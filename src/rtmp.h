
/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief  RTMP (Adobe's Flash client) support
 * 
 * \author Philippe Sultan <philippe.sultan@inria.fr>
 *
 * \ingroup channel_drivers
 */


#define CLIENT_TYPE_FLASH   1
#define CLIENT_TYPE_ANDROID 2
#define CLIENT_TYPE_IOS     3



#define JITTER_SIZE       160

#define RTMP_FEATURE_HTTP	  0x01
#define RTMP_FEATURE_ENC	  0x02
#define RTMP_FEATURE_SSL	  0x04
#define RTMP_FEATURE_MFP	  0x08
#define RTMP_FEATURE_WRITE	0x10
#define RTMP_FEATURE_HTTP2	0x20

#define RTMP_INCOMING           0
#define RTMP_OUTGOING           1

#define RTMPBUFSIZE				512
#define RTMP_BLOCK_SIZE         1536
//#define RTMP_RECV_BUFSIZE     2*RTMP_BLOCK_SIZE + 1   /* should match with RTMP server */
#define RTMP_RECV_BUFSIZE       271360
#define RTMP_DEFAULT_PORT       1935
#define RTMP_WINDOW_SIZE    131072
#define RTMP_CHUNK_SIZE         128
//#define RTMP_MAX_BODYSIZE     16777215    /* 0xFFFFFF */
//#define RTMP_MAX_BODYSIZE       65535       /* 0xFFFF */
//#define RTMP_MAX_BODYSIZE       1048575       /* 0xFFFFF */
#define RTMP_MAX_BODYSIZE       200       /* 0xFFFFF */
#define RTMP_MAX_CHANNELS       64
#define RTMP_STREAM_CHANNEL_RANGE   5
#define RTMP_MAX_STREAMS        12  

#define RTMP_EXTENDEDTIMESTAMP_SIZE 4

#define RTMP_CHANNEL_SYSTEM       2
#define RTMP_CHANNEL_CONNECT        3
#define RTMP_CHANNEL_DATA       0
#define RTMP_CHANNEL_PUBLISH        4
#define RTMP_CHANNEL_LOCAL        5
#define RTMP_CHANNEL_VIDEO        6
#define RTMP_CHANNEL_UNKNOWN        3
#define RTMP_CHANNEL_CONTROL        4

#define RTMP_PING_DEFAULTBODYSIZE   6
#define RTMP_PING_TYPE_CLEAR        0x01        /* clear stream */
#define RTMP_PING_TYPE_PLAY     0x02        /* clear playing buffer */
#define RTMP_PING_TYPE_TIME     0x03        /* buffer time in milliseconds */
#define RTMP_PING_TYPE_RESET        0x04        /* reset stream */
#define RTMP_PING_TYPE_PING     0x06
#define RTMP_PING_TYPE_PONG     0x07


#define RTMP_TYPE_CHUNK_SIZE        0x01
#define RTMP_TYPE_BYTES_READ        0x03
#define RTMP_TYPE_PING          0x04
#define RTMP_TYPE_SERVER_BANDWIDTH  0x05
#define RTMP_TYPE_CLIENT_BANDWIDTH  0x06 
#define RTMP_TYPE_AUDIO_DATA        0x08
#define RTMP_TYPE_VIDEO_DATA        0x09
#define RTMP_TYPE_FLEX_STREAM_SEND  0x0F
#define RTMP_TYPE_FLEX_SHARED_OBJECT    0x10
#define RTMP_TYPE_FLEX_MESSAGE      0x11
#define RTMP_TYPE_NOTIFY        0x12
#define RTMP_TYPE_SHARED_OBJECT     0x13
#define RTMP_TYPE_INVOKE        0x14
#define RTMP_TYPE_UNKNOWN       0x15


#define AMF_TYPE_NUMBER         0x00
#define AMF_TYPE_BOOLEAN        0x01
#define AMF_TYPE_STRING         0x02
#define AMF_TYPE_OBJECT         0x03
#define AMF_TYPE_MOVIECLIP      0x04
#define AMF_TYPE_NULL           0x05
#define AMF_TYPE_UNDEFINED      0x06
#define AMF_TYPE_REFERENCE      0x07
#define AMF_TYPE_MIXED_ARRAY        0x08
#define AMF_TYPE_OBJECT_END     0x09
#define AMF_TYPE_ARRAY          0x0A
#define AMF_TYPE_DATE           0x0B
#define AMF_TYPE_LONG_STRING        0x0C
#define AMF_TYPE_UNSUPPORTED        0x0D
#define AMF_TYPE_RECORDSET      0x0E
#define AMF_TYPE_XML            0x0F
#define AMF_TYPE_CLASS_OBJECT       0x10
#define AMF_TYPE_AMF3_OBJECT        0x11

#define AMF_BOOLEAN_FALSE       "\0"
#define AMF_BOOLEAN_TRUE        "\1"

#define RTMP_AUDIO_CODEC_LINEAR 0x1
#define RTMP_AUDIO_CODEC_ALAW   0x80
#define RTMP_AUDIO_CODEC_MULAW  0x100
#define RTMP_AUDIO_CODEC_SPEEX  0x800
#define RTMP_AUDIO_CODEC_SUPPORTED  (RTMP_AUDIO_CODEC_LINEAR | RTMP_AUDIO_CODEC_ALAW | RTMP_AUDIO_CODEC_MULAW | RTMP_AUDIO_CODEC_SPEEX)

#define RTMP_VIDEO_CODEC_SORENSON   0x4
#define RTMP_VIDEO_CODEC_H264       0x80
#define RTMP_VIDEO_CODEC_SUPPORTED  RTMP_VIDEO_CODEC_SORENSON | RTMP_VIDEO_CODEC_H264


#define FLV_AUDIO_CODEC_ADPCM                   1
#define FLV_AUDIO_CODEC_MP3                     2
#define FLV_AUDIO_CODEC_PCMS16le                3
#define FLV_AUDIO_CODEC_NELLYMOSER_16KHZ_MONO   4
#define FLV_AUDIO_CODEC_NELLYMOSER_8KHZ_MONO    5
#define FLV_AUDIO_CODEC_NELLYMOSER              6
#define FLV_AUDIO_CODEC_G711_ALAW               7
#define FLV_AUDIO_CODEC_G711_MULAW              8
#define FLV_AUDIO_CODEC_ASTERISK_SLIN           9
#define FLV_AUDIO_CODEC_AAC                     10
#define FLV_AUDIO_CODEC_SPEEX                   11
#define FLV_AUDIO_CODEC_MP3_8KHZ                14
#define FLV_AUDIO_CODEC_DEVICE_SPECIFIC         15


#define ADMIN_CMD_GETQOS        "getqos:"
#define ADMIN_CMD_GETQOS_LG         7
#define ADMIN_CMD_GETVERSION    "getversion:"
#define ADMIN_CMD_GETVERSION_LG     11
#define ADMIN_CMD_PING          "ping:"
#define ADMIN_CMD_PING_LG           5

#define ADMIN_RESP_GETQOS       "respGetQos:"
#define ADMIN_RESP_GETQOS_LG        11
#define ADMIN_RESP_GETCFG       "respGetCfg:"
#define ADMIN_RESP_GETCFG_LG        11
#define ADMIN_RESP_GETVERSION   "respGetVersion:"
#define ADMIN_RESP_GETVERSION_LG        15
#define ADMIN_RESP_PONG         "pong:"
#define ADMIN_RESP_PONG_LG        5


struct rtmp_channel {
    uint8_t channelid;      /* the RTMP channel id (64 bits long) */
    uint8_t hdrlen[2];
    uint32_t timestamp[2];
    uint32_t bodylen[2];
    uint8_t type[2];
    uint32_t streamid[2];       /* the stream this channel is part of */

    int isactive;           /* is this channel active? */
};

struct rtmp_message {
    uint8_t hdrlen;         /* 1,2,4 or 12 */
    uint8_t channelid;      /* less than 64 */
    uint32_t timestamp;     /* three bytes long */
    uint32_t timestampdelta;        /* three bytes long */
    uint32_t bodyalloc;      /* three bytes long */
    uint32_t bodysize;      /* three bytes long */
    uint8_t type;
    uint32_t streamid;      /* four bytes long */
    void *body;         /* bytes after header */

    int bytesread;          /* the number of parsed bytes */
};

struct amf_hdr {
    uint8_t hdrlen;         /* 1,2,4 or 12 */
    uint8_t type;
    uint8_t objectid;       /* less than 64 */
};

struct amf_basic_object {
    uint8_t type;
    uint16_t length;        /* used if the object is a string */
    char *property;
    void *value;
    struct amf_basic_object *next;
};

struct amf_object {
    struct amf_basic_object *bobject;
    unsigned int size;
};

enum rtmp_state {
    RTMP_DISCONNECTING,
    RTMP_DISCONNECTED,
    RTMP_CONNECTING,
    RTMP_HANDSHAKE_OK,
    RTMP_CONNECTED
};

enum rtmp_reply {
    RTMP_REPLY_RESULT,

    RTMP_REPLY_CONNECT,
    RTMP_REPLY_INITSTREAM,
    RTMP_REPLY_RELEASESTREAM,
    RTMP_REPLY_CREATESTREAM,
    RTMP_REPLY_DELETESTREAM,
    RTMP_REPLY_INVITE,
    RTMP_REPLY_ACCEPT,
    RTMP_REPLY_REJECT,
    RTMP_REPLY_BYE,

    RTMP_REPLY_PUBLISH,
    RTMP_REPLY_PLAY,
    RTMP_REPLY_CLOSESTREAM,

    RTMP_REPLY_DTMF,
    RTMP_REPLY_TEXT,

    RTMP_NOREPLY,
};

enum rtmp_pipe {
    RTMP_PIPE_NULL,
    RTMP_PIPE_MARK,
    RTMP_PIPE_AUDIO_NELLYMOSER,
    RTMP_PIPE_AUDIO_SPEEX,
    RTMP_PIPE_AUDIO_SLINEAR,
    RTMP_PIPE_AUDIO_ULAW,
    RTMP_PIPE_AUDIO_ALAW,
    RTMP_PIPE_VIDEO_SORENSON,
    RTMP_PIPE_VIDEO_SORENSON_MARK,
    RTMP_PIPE_VIDEO_H264,
    RTMP_PIPE_VIDEO_H264_MARK,
    RTMP_PIPE_DTMF,
    RTMP_PIPE_TEXT,
    RTMP_PIPE_EVENT,
};

enum amf_parser {
    AMF_PARSE_TYPE,
    AMF_PARSE_STRINGLEN,
    AMF_PARSE_STRINGVAL,
    AMF_PARSE_DOUBLE_RESULT,
    AMF_PARSE_PROPERTY_LEVEL,
    AMF_PARSE_PROPERTY_CODE,
    AMF_PARSE_PROPERTY_DESCRIPTION,
    AMF_PARSE_STRING_VALUE,
    AMF_PARSE_NUMBER,
    AMF_PARSE_BOOLEAN,

    AMF_PARSE_ID,
    AMF_PARSE_APP,
    AMF_PARSE_FLASHVER,
    AMF_PARSE_SWFURL,
    AMF_PARSE_TCURL,
    AMF_PARSE_FPAD,
    AMF_PARSE_CAPABILITIES,
    AMF_PARSE_AUDIOCODECS,
    AMF_PARSE_VIDEOCODECS,
    AMF_PARSE_VIDEOFUNCTION,
    AMF_PARSE_PAGEURL,      
    AMF_PARSE_OBJECTENCODING,       

    AMF_PARSE_RESULT,       

    AMF_PARSE_CREATESTREAM,     
    AMF_PARSE_DELETESTREAM,     

    AMF_PARSE_INVITE,       
    AMF_PARSE_ACCEPT,       
    AMF_PARSE_REJECT,       
    AMF_PARSE_BYE,      

    AMF_PARSE_PUBLISH,      
    AMF_PARSE_PLAY,     
    AMF_PARSE_CLOSESTREAM,      
};
