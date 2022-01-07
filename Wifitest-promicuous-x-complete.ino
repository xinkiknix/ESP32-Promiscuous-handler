/*
   Working promiscuous WIFI solution version RTOS for ESP32
   Sending complete received message PROBE_REQ and PROBE_RES payload (max length 264 bytes) for processing
   Queue length of 100 works fine (meaning a delay of 100 message between receipt end handling can be handled without information loss)
   During tests more than 10 messages where handled
   Messages are stored in map and later filed to file "/MapData.txt" on internal flash unique MAC address destination and MAC address sender are written regularly 
   together with number of times this combination was seen since last storage to file
   File can be retrieved from flash using SPIFF FTP_Server SW to be installed on the ESP32
*/
#include "freertos/FreeRTOS.h"
#include <stdint.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include <ESP32Time.h>  //https://gith/ub.com/fbiego/ESP32Time/blob/main/examples/esp32_time/esp32_time.ino
#include <WiFi.h>
#include "MyMap.h"
//#include "pins_arduino.h"

#define ONBOARD_LED 2  //LED_BUILTIN

#define SSID "Livebox-0C3D"
#define PASSWORD "66EF9091C8E6960FC2527488A3"

//#define __DEBUG__

#ifdef __DEBUG__
#define DEBUG(...) Serial.print(__VA_ARGS__)
#define DEBUGF(...) Serial.printf(__VA_ARGS__)
#define DEBUGLN(...) Serial.println(__VA_ARGS__)
#else
#define DEBUG(...)
#define DEBUGF(...)
#define DEBUGLN(...)
#endif

#define INTERRUPT_ATTR IRAM_ATTR

#define WIFI_CHANNEL_SWITCH_INTERVAL (500)
#define WIFI_CHANNEL_MAX (13)
#define PKT_SIZE 264
#define QUEUE_SIZE 100

ESP32Time rtc;
char fileName[] = "/Mapdata.csv";
MyMap addrMap(fileName);


static wifi_country_t wifi_country = { .cc = "FR", .schan = 1, .nchan = WIFI_CHANNEL_MAX };  //Most recent esp32 library struct
/*
  MAC header frame control
  Use uint16_t to force the compiler to limit the struct to 16bit, 32 bit compiler will otherwise pad the struct to 32 bit.
*/
typedef struct {
  uint16_t protocol : 2;
  uint16_t type : 2;
  uint16_t subtype : 4;
  uint16_t to_ds : 1;
  uint16_t from_ds : 1;
  uint16_t more_frag : 1;
  uint16_t retry : 1;
  uint16_t pwr_mgmt : 1;
  uint16_t more_data : 1;
  uint16_t wep : 1;
  uint16_t strict : 1;
} wifi_header_frame_control_t;

/*
   MAC header
*/
typedef struct {
  wifi_header_frame_control_t frame_ctrl;
  uint16_t duration_id : 16;
  uint8_t addr1[6];             // receiver address
  uint8_t addr2[6];             // sender address
  uint8_t addr3[6];             // filtering address
  unsigned sequence_ctrl : 16;  //The Sequence Number field is a 12-bit , The Fragment Number field is a 4-bit field indicating the number of each fragment of an MSDU or MMPDU.
  uint8_t addr4[6];             // optional
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

/*
   https://mrncciew.com/2014/10/27/cwap-802-11-probe-requestresponse/
*/
typedef struct {
  uint16_t timestamp : 16;
  //unsigned interval : 4;
  uint16_t capability : 16;
  uint8_t tag_number : 8;
  uint8_t tag_length : 8;
  char ssid[0];
  uint8_t rates[1];
} wifi_mgmt_probe_res_t;

typedef struct {
  uint8_t tag_number : 8;
  uint8_t tag_length : 8;
  char ssid[0];
  uint8_t rates[1];
} wifi_mgmt_probe_req_t;

typedef enum {
  ASSOCIATION_REQ,
  ASSOCIATION_RES,
  REASSOCIATION_REQ,
  REASSOCIATION_RES,
  PROBE_REQ,
  PROBE_RES,
  NU1,  // ......................
  NU2,  // 0110, 0111 not used
  BEACON,
  ATIM,
  DISASSOCIATION,
  AUTHENTICATION,
  DEAUTHENTICATION,
  ACTION,
  ACTION_NACK,
} wifi_mgmt_subtypes_t;
#ifdef __DEBUG__
//CTRL_SUBTYPE
typedef enum {
  //RESERVED,
  TACK = 1,
  BEAMFORMING_REPORT_POLL,
  VHT_HE_NDP_ANNOUNCEMENT,
  CONTROL_FRAME_EXTENSION,
  CONTROL_WRAPPER,
  BLOCK_ACK_REQ,
  BLOCK_ACK,
  PS_POLL,
  RTS,
  CTS,
  ACK,
  CF_END,
  CF_END_CF_ACK
} wifi_ctrl_subtypes_t;

//DATA_SUBTYPE
typedef enum {
  DATA,
  // RESERVED,
  // RESERVED,
  // RESERVED,
  NO_DATA = 4,
  //RESERVED,
  //RESERVED,
  //RESERVED,
  QOS_DATA = 8,
  QOS_DATA_CF_ACK,
  QOS_DATA_CF_POLL,
  QOS_DATA_CF_ACK_CF_POLL,
  QOS_NULL_NO_DATA,
  //RESERVED,
  QOS_CF_POLL_NO_DATA = 14,
  QOS_CF_ACK_CF_POLL_NO_DATA
} wifi_data_subtypes_t;

//EXT_SUBYTPE
typedef enum {
  DMG_BEACON,
  S1G_BEACON
  //RESERVED
} wifi_ext_subtypes_t;



const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type) {
  switch (type) {
    case WIFI_PKT_MGMT: return "MGMT";
    case WIFI_PKT_DATA: return "DATA";
    case WIFI_PKT_CTRL: return "CTRL";
    default:
    case WIFI_PKT_MISC: return "MISC";
  }
}

const char *wifi_pkt_type2str(wifi_promiscuous_pkt_type_t type, uint16_t subtype) {
  switch (type) {
    case WIFI_PKT_MGMT:
      switch ((wifi_mgmt_subtypes_t)subtype) {
        case ASSOCIATION_REQ: return "ASSOCIATION_REQ";
        case ASSOCIATION_RES: return "ASSOCIATION_RES";
        case REASSOCIATION_REQ: return "REASSOCIATION_REQ";
        case REASSOCIATION_RES: return "REASSOCIATION_RES";
        case PROBE_REQ: return "PROBE_REQ";
        case PROBE_RES: return "PROBE_RES";
        case NU1: return "NU1";
        case NU2: return "NU2";
        case BEACON: return "BEACON";
        case ATIM: return "ATIM";
        case DISASSOCIATION: return "DISASSOCIATION";
        case AUTHENTICATION: return "AUTHENTICATION";
        case DEAUTHENTICATION: return "DEAUTHENTICATION";
        case ACTION: return "ACTION";
        case ACTION_NACK: return "ACTION_NACK";
        default:
          return " ";
      };
    case WIFI_PKT_DATA:
      switch ((wifi_data_subtypes_t)subtype) {
        case DATA: return "DATA";
        case NO_DATA: return "NO DATA";
        case QOS_DATA: return "QOS DATA";
        case QOS_DATA_CF_ACK: return "QOS DATA";
        case QOS_DATA_CF_POLL: return "QOS_DATA_CF_ACK";
        case QOS_DATA_CF_ACK_CF_POLL: return "QOS_DATA_CF_ACK_CF_POLL";
        case QOS_NULL_NO_DATA: return "QOS_NULL_NO_DATA";
        case QOS_CF_POLL_NO_DATA: return "QOS_CF_POLL_NO_DATA";
        case QOS_CF_ACK_CF_POLL_NO_DATA: return "QOS_CF_ACK_CF_POLL_NO_DATA";
        default: return " ";
      };
    case WIFI_PKT_CTRL:
      switch ((wifi_ctrl_subtypes_t)subtype) {
        case TACK: return "TACK";
        case BEAMFORMING_REPORT_POLL: return "BEAMFORMING_REPORT_POLL";
        case VHT_HE_NDP_ANNOUNCEMENT: return "VHT_HE_NDP_ANNOUNCEMENT";
        case CONTROL_FRAME_EXTENSION: return "CONTROL_FRAME_EXTENSION";
        case CONTROL_WRAPPER: return "CONTROL_WRAPPER";
        case BLOCK_ACK_REQ: return "BLOCK_ACK_REQ";
        case BLOCK_ACK: return "BLOCK_ACK";
        case PS_POLL: return "PS_POLL";
        case RTS: return "RTS";
        case CTS: return "CTS";
        case ACK: return "ACK";
        case CF_END: return "CF_END";
        case CF_END_CF_ACK: return "CF_END_CF_ACK";
        default:
          return "";
      };
    case WIFI_PKT_MISC:
      switch ((wifi_ext_subtypes_t)subtype) {
        case DMG_BEACON: return "DMG_BEACON";
        case S1G_BEACON: return "S1G_BEACON";
        default:
          return "";
      };
    default:
      return "";
  }
}
#endif
esp_err_t event_handler(void *ctx, system_event_t *event) {
  return ESP_OK;
}
/*
* Initialize ESP32, promiscuous mode and RTC
* A filter is set to limit interception to MGMT packages only
*/
void wifi_sniffer_init(void) {
  nvs_flash_init();
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country)); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_start());
  setRtcTimefromNTP();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  //https://github.com/pycom/pycom-esp-idf/blob/master/components/esp32/include/esp_wifi_types.h
  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
}


/*
Define queue for communication between sniffer and message processing, allows for much larger number of messages to be processed
*/
const QueueHandle_t IEEE_Queue = xQueueCreate(QUEUE_SIZE, PKT_SIZE);

/*
Callback function for package handling from wifi process
Received buffer is mapped to appropriate format(s) en sub components to be able to use required fields (e.i.frame_ctrl->subtype and rx_ctrl.sig_len)
Only PROBE_RES and PROBE_REQ are handled and ppkt->rx_ctrl.sig_len number of bytes are put on the queue
Since buff is just a pointer and most fields are defined a of length 1 in the struct a copy of the whole payload part needs to be passed and not the ppkt->payload reference
memcpy is used because the message can contain "\0" chars.
*/
void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
  const wifi_header_frame_control_t *frame_ctrl = (wifi_header_frame_control_t *)&hdr->frame_ctrl;

  if (frame_ctrl->subtype == PROBE_RES || frame_ctrl->subtype == PROBE_REQ) {
    Serial.print("!");
#ifdef __DEBUG__
    uint8_t ch1;
    wifi_second_chan_t ch2;
    esp_wifi_get_channel(&ch1, &ch2);
    DEBUGF("%02d", ch1);
#endif
    char prom_pkt[PKT_SIZE];
    memset(prom_pkt, '\0', PKT_SIZE);
    memcpy(prom_pkt, (char *)ipkt, ppkt->rx_ctrl.sig_len > PKT_SIZE ? PKT_SIZE : ppkt->rx_ctrl.sig_len);  //memcpy !!! strncopy stops after '\0'!!!!
    if (uxQueueSpacesAvailable(IEEE_Queue) > 0) {
      DEBUGLN("Sending");
      xQueueSend(IEEE_Queue, &prom_pkt, portMAX_DELAY);
      DEBUGLN("Sent");
    } else {
      DEBUGLN("no space");
    }
  } else {
    Serial.print(".");
  }
  DEBUGLN("sent off for handling");
}

/*
* Asynchronous Task handles messages received on a queue 
* Received message is mapped to appropriate format(s) en sub components to be able to use required fields (e.i.frame_ctrl->subtype and rx_ctrl.sig_len)
* Mac Address 1 and Mac Address 2 are put into a unordered_map<string, int> map
* When sufficient messages have been retrieved the map will be stored to file preceded by timestamp. Map will be emptied during storage process
*/
void handle(void *pvParameters) {
  // const wifi_ieee80211_packet_t *ipkt;
  char prom_pkt[PKT_SIZE];
  char timeDate[26];
  unsigned long CurrentTime;
  unsigned long StartTime = millis();
  DEBUGLN("Handler started");
  for (;;) {
    DEBUGLN("Waiting");
    if (IEEE_Queue != NULL) {
      DEBUGLN("Handling message");
      DEBUGLN(uxQueueMessagesWaiting(IEEE_Queue));
      if (xQueueReceive(IEEE_Queue, &prom_pkt, portMAX_DELAY)) {
        const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)prom_pkt;
        const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
        const wifi_mgmt_probe_res_t *probe_res_frame = (wifi_mgmt_probe_res_t *)&ipkt->payload;  //it is a request or response
        const wifi_mgmt_probe_req_t *probe_req_frame = (wifi_mgmt_probe_req_t *)&ipkt->payload;
        const wifi_header_frame_control_t frame_ctrl = (wifi_header_frame_control_t)hdr->frame_ctrl;
        // only (frame_ctrl->subtype == PROBE_RES || frame_ctrl->subtype == PROBE_REQ) subtypes are received
        rtc.getTimeDate().toCharArray(timeDate, 26);
        char Adr[80];  //size sufficient for complete message
        char Adr1[9], Adr2[9];
        char tpe1[2], tpe2[2];
        MacAddrType(hdr->addr1).toCharArray(tpe1, 2);
        strcat(Adr, tpe1);
        strcat(Adr, ",");  //add separator
        if (tpe1[0] == 'B') {
          strcat(Adr, "ff");
        } else {
          OUI(hdr->addr1).toCharArray(Adr1, 9);
          strcat(Adr, Adr1);
        }
        strcat(Adr, ",");  //add separator
        MacAddrType(hdr->addr2).toCharArray(tpe2, 2);
        strcat(Adr, tpe2);
        strcat(Adr, ",");  //add separator
        OUI(hdr->addr2).toCharArray(Adr2, 9);
        strcat(Adr, Adr2);
        char ssid[32] = { 0 };
        if (frame_ctrl.subtype == PROBE_RES) {
          if (probe_res_frame->tag_length >= 32) {
            strncpy(ssid, probe_res_frame->ssid, 31);
          } else {
            strncpy(ssid, probe_res_frame->ssid, probe_res_frame->tag_length);
          }
        } else  //if(frame_ctrl.subtype == PROBE_REQ)
        {
          if (probe_req_frame->tag_length >= 32) {
            strncpy(ssid, probe_req_frame->ssid, 31);
          } else {
            strncpy(ssid, probe_req_frame->ssid, probe_req_frame->tag_length);
          }
        }
        strcat(Adr, ",");  //add separator
        if (isAscci(ssid)) {
          strcat(Adr, ssid);  //add separator
        }
        addrMap.addToMap(Adr);
        DEBUGLN(addrMap.size());
        CurrentTime = millis();
        if ((addrMap.size() >= 20 || (CurrentTime - StartTime) >= 30 * 60 * 1000) || addrMap.size() >= 50 || (CurrentTime - StartTime) >= 60 * 60 * 1000) {  // (20 items and 10 mins) or 50 items or 30 mins
          addrMap.storeMap(timeDate);
          StartTime = CurrentTime;
        }

#ifdef __DEBUG__  // print message content to Serial
        DEBUGF("\r\nTs: %06u-%s | Dest %s Addr:%17s| Snd %s Addr:%17s | %u(%-2u) | %-6s | %-10s ",
               rtc.getMicros(),
               timeDate,
               MacAddrType(hdr->addr1),
               Adr1,
               MacAddrType(hdr->addr2),
               Adr2,
               frame_ctrl.type,
               frame_ctrl.subtype,
               wifi_sniffer_packet_type2str((wifi_promiscuous_pkt_type_t)frame_ctrl.type),
               wifi_pkt_type2str((wifi_promiscuous_pkt_type_t)frame_ctrl.type, frame_ctrl.subtype));
        char ssid[32] = { 0 };
        if (probe_req_frame->tag_length >= 32) {
          strncpy(ssid, probe_req_frame->ssid, 31);
        } else {
          strncpy(ssid, probe_req_frame->ssid, probe_req_frame->tag_length);
        }
        DEBUGF(", tag num %02d, tag length %03d %s, TS %jd\r\n", probe_req_frame->tag_number, probe_req_frame->tag_length, ssid, probe_req_frame->timestamp);  //timestamp representation is not correct!!!!
        vTaskDelay(200);
      }
#endif
      DEBUGLN("package arrived!");
    } else {
      DEBUGLN(" timeout");  // wait a bit
      vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
    }
    DEBUGLN("\n processed");
  }
  else {
    DEBUGLN("error in queue reading");
  }
}
vTaskDelete(NULL);
}

void setup() {
  time_t tm;
  Serial.begin(500000);
  if (!Serial.available()) {
    delay(100);  // wait for serial port to connect.
  }
  Serial.println(__FILE__);
  pinMode(ONBOARD_LED, OUTPUT);
  // Serial.setDebugOutput(true);
  xTaskCreatePinnedToCore(
    handle,         /* Task function. */
    "Handler Task", /* name of task. */
    10000,          /* Stack size of task */
    NULL,           /* parameter of the task */
    1,              /* priority of the task */
    NULL,           /* Task handle to keep track of created task */
    1);
  xTaskCreate(
    switchChannel,  /* Task function. */
    "Channel Task", /* name of task. */
    10000,          /* Stack size of task */
    NULL,           /* parameter of the task */
    1,              /* priority of the task */
    NULL);          /* Task handle to keep track of created task */
  wifi_sniffer_init();
  digitalWrite(ONBOARD_LED, LOW);
}

void switchChannel(void *pvParameters) {
  uint8_t channel = 1;
  for (;;) {
    DEBUGF("\nScanning channel %02d\n", channel);
    digitalWrite(ONBOARD_LED, channel <= 6 ? LOW : HIGH);
    vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    channel = (channel % WIFI_CHANNEL_MAX) + 1;
    DEBUGF("in the loop :%d", channel);
  }
  vTaskDelete(NULL);
}

// the loop function does nothing
void loop() {
}
/*
* convert Addresstype to string: if byte 7 of the first byte is set the address is a fake address created to hide the real (sender) address for privacy reasons
* otherwise the address is from a globally (IEEE) administered address block
* FF:FF:FF.... addresses are Broadcast addresses
*/
String MacAddrType(const uint8_t addr[6]) {
  String AdressType = (bitRead(addr[0], 6) ? "L" : "G");
  if (addr[0] == 0xff && addr[1] == 0xff) { AdressType = "B"; };
  return AdressType;
}

/*
* Return the Macaddress in stringformat ':' saparated
*
*/
String MacAddress(const uint8_t addr[6]) {
  char stringAddr[18];
  sprintf(stringAddr, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
  return stringAddr;
}


/*
* Return the OUI in stringformat ':' saparated
*
*/
String OUI(const uint8_t addr[6]) {
  char stringAddr[18];
  sprintf(stringAddr, "%02x:%02x:%02x", addr[0], addr[1], addr[2]);
  return stringAddr;
}

/*
* Set internal Real Time Clock to time received from ntp Server
* failure to connect will use compile time as starting time
*/
void setRtcTimefromNTP() {
  const char *ntpServer = "pool.ntp.org";
  WiFi.begin(SSID, PASSWORD);
  int count = 0;
  while (WiFi.status() != WL_CONNECTED && count++ <= 10) {
    delay(500);
    DEBUG(".");
  }
  if (count < 10) {
    DEBUGLN(" CONNECTED");
    const long gmtOffset_sec = 3600;
    const int daylightOffset_sec = 3600;
    configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
    struct tm timeinfo;
    if (getLocalTime(&timeinfo)) {
      rtc.setTime(timeinfo.tm_sec, timeinfo.tm_min, timeinfo.tm_hour, timeinfo.tm_mday, timeinfo.tm_mon + 1, timeinfo.tm_year + 1900);
    }
  } else {
    time_when_compiled();
    DEBUGLN("NTP failed, compile time set");
  }
}

/*
* set rtc clock to compile time and date
*
*/
void time_when_compiled() {
  const char *date = __DATE__;
  const char *time = __TIME__;
  char s_month[5];
  int month, day, year, hour, minute, second;
  static const char month_names[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
  sscanf(date, "%s %d %d", s_month, &day, &year);
  sscanf(time, "%2d%*c%2d%*c%2d", &hour, &minute, &second);
  month = (strstr(month_names, s_month) - month_names) / 3 + 1;
  rtc.setTime(second, minute, hour, day, month, year);
}

const bool isAscci(char aString[]) {
  for (int i = 0; i < strlen(aString); i++) {
    if ((int)aString[i] > 128 || (int)aString[i] < 40) {
      return false;
    }
  }
  return true;
}
