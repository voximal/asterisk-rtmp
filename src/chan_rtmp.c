/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do ²not directly contact
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
 * \brief  RTMP (Adobe's Flash Player and Flash Server client) support
 *
 * \author Borja SIXTO <borja.sixto@ulex.fr>
 *
 * \ingroup channel_drivers
 */

/*** MODULEINFO
    <depend>avcodec</depend>
 ***/

#warning
#warning "CVS $Revision: 1.323 $"
#warning


#define  VERSION_RTMP         1
#define  SUBVERSION_RTMP      0


#include <sys/socket.h>
#include <linux/sockios.h>
//#include <arpa/inet.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/signal.h>
#include <regex.h>
#include <poll.h>
#include <errno.h>

#ifdef RTMP_FLV
#include <libavcodec/avcodec.h>
#endif

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/dh.h>

#if 0
#include <curl/curl.h>
#ifndef LIBCURL_VERSION
#define LIBCURL_VERSION forced
#endif
#endif

#include <GeoIP.h>
#include <GeoIPCity.h>

//#undef SSL
//#undef SSL_CTX

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 1.323 $")

#include "asterisk/astobj2.h"
#include "asterisk/lock.h"
#include "asterisk/channel.h"
#include "asterisk/config.h"
#include "asterisk/module.h"
#include "asterisk/pbx.h"
#include "asterisk/utils.h"
#include "asterisk/strings.h"
#include "asterisk/app.h"
#include "asterisk/io.h"
#include "asterisk/cli.h"
#include "asterisk/tcptls.h"
#include "asterisk/frame.h"
#include "asterisk/paths.h"
#include "asterisk/callerid.h"
#include "asterisk/musiconhold.h"
#include "asterisk/causes.h"
#include "asterisk/stringfields.h"
#include "asterisk/manager.h"
#include "asterisk/netsock.h"
#include "asterisk/acl.h"
#include "asterisk/sched.h"

#include <version_macros.h>


#include "flvtools.h"
/* Forcing NUM Version ? */
#if ASTERISK_VERSION_NUM_FORCE
#define ASTERISK_VERSION_NUM ASTERISK_VERSION_NUM_FORCE
#warning "Compilation Force ASTERISK_VERSION_NUM"
#endif
#ifndef FALSE
#define FALSE    0
#endif
#ifndef TRUE
#define TRUE     1
#endif

/* Disable SSL */
#define DO_SSL

#ifndef AVMEDIA_TYPE_AUDIO
//#warning "AVMEDIA_TYPE_AUDIO CODEC_TYPE_AUDIO not define!"
#define AVMEDIA_TYPE_AUDIO CODEC_TYPE_AUDIO
#endif

#include "rtmp.h"
#include "rtmpe.h"


#define PKT_PAYLOAD     2000
#define PKT_SIZE        (sizeof(struct ast_frame) + AST_FRIENDLY_OFFSET + PKT_PAYLOAD)
#define PKT_OFFSET      (sizeof(struct ast_frame) + AST_FRIENDLY_OFFSET)
#if ASTERISK_VERSION_NUM>10600
#define AST_FRAME_GET_BUFFER(fr)        ((unsigned char*)((fr)->data.ptr))
#else
#define AST_FRAME_GET_BUFFER(fr)        ((unsigned char*)((fr)->data))
#endif
#define BUFFER_OUTPUTFRAME  800000
#define MAX_RULES  100
#undef _CHECK_CNX_RTMP_
struct rtmp_client;
struct rtmp_threadinfo;
struct rtmp_user;


/* Structure for RTMP peer data, we place calls to peers if registred  or fixed IP address (host) */
struct rtmp_user
{
        char name[80];
        AST_DECLARE_STRING_FIELDS(AST_STRING_FIELD(secret);
        AST_STRING_FIELD(context);
        /* Suggested caller id if registering */
        AST_STRING_FIELD(cid_num); AST_STRING_FIELD(cid_name););
        int multipleusers;
        int lastuniqueuser;

        /* Qualification */
        int callno;                 /*!< Call number of POKE request */
        uint16_t maxcallno;         /*!< Max call number limit for this user.  Set on registration */

        struct rtmp_client *client;
};

struct rtmp_client
{
        int id;
        ast_mutex_t lock;
        enum rtmp_state state;

        int fd;

        int protocol;

        struct rtmp_channel *streams[RTMP_MAX_CHANNELS];

        // Reference for timestamp
        time_t date;

        int firstaudio;
        struct timeval timestart;
        uint32_t timestamp;
        uint32_t timestamplast;

        time_t callstart;
        time_t callanswer;
        time_t callstop;

        char flashver[80];
        char name[80];
        char param[80];
        char address[80];
        int port;
        char cellid[80];
        char *country;
        float latitude, longitude;

        // NetStreams
        double publishstream;
        double playstream;
        double playstream2;

        int publishing;
        int playing;
        int playing2;

        int autoanswer;
        int mute;
        int echo;

        int outgoing_chunksize;
        int incoming_chunksize;

        int outgoing_windowsize;
        int incoming_windowsize;

        uint32_t outgoing_bytescount;
        uint32_t incoming_bytescount;

        struct timeval timecalc;
        uint32_t outgoing_timebytescount;
        uint32_t incoming_timebytescount;
        uint32_t outgoing_bandwidth;
        uint32_t incoming_bandwidth;
        uint32_t incoming_calls;
        uint32_t outgoing_calls;
        uint32_t outgoing_images;
        uint32_t incoming_images;

        uint32_t outgoing_video;
        uint32_t outgoing_audio;
        uint32_t outgoing_videolost;
        uint32_t outgoing_audiolost;

        uint32_t incoming_video;
        uint32_t incoming_audio;
        uint32_t incoming_videolost;
        uint32_t incoming_audiolost;

        uint32_t burst_max;
        uint32_t burst_counter;
        uint32_t burst_count;

        uint32_t overwrites_max;
        uint32_t overwrites_count;

        uint32_t lastack;

        int txseq;
        int cseq;

        // To receive video MRCP chunks
        uint8_t *buffer;
        uint32_t bufferSize;
        uint32_t bufferLen;

        uint8_t *chunks_buffer;
        uint32_t chunks_buffersize;
        uint32_t chunks_bufferoffset;

        struct rtmp_threadinfo *threadinfo;
        struct rtmp_user *user;
        struct rtmp_pvt *pvt;

        int acodec_setted;          // flag to not erase previous setting
        INITIALIZE_CLIENT_AUDIOCODEC;

        int clientType;
        //  have the swfUrl for flash phone

        // To debug the streams
        FILE *incoming_audiofile;
        FILE *outgoing_audiofile;
        FILE *incoming_videofile;
        FILE *outgoing_videofile;

        // file descriptor for flv
        stFLV_data in_flv;
        stFLV_data out_flv;
        stFLV_data out_flv_spy;

        int havePictureInSize;      // Last incoming picture size
        int pictureIn_width;
        int pictureIn_heigth;
        int havePictureOutSize;     // Last outgoing picture size
        int pictureOut_width;
        int pictureOut_heigth;

#ifdef _CHECK_CNX_RTMP_
        int wdog_startCheck;
        struct timeval wdog_lastModifTime;
        uint32_t wdog_prev_isalive;
        uint32_t wdog_isalive;
#endif
        struct ast_tcptls_session_instance *tcptls_session;
        MDH *dh;
        RC4_handle rc4keyIn;
        RC4_handle rc4keyOut;

};

/*! \brief argument for the 'show channels|subscriptions' callback. */
struct __show_chan_arg
{
        int fd;
        int subscriptions;
        int numchans;               /* return value */
};

/*! \brief The RTMP socket definition */
struct rtmp_socket
{
        int fd;                     /*!< Filed descriptor, the actual socket */
        struct ast_tcptls_session_instance *tcptls_session; /* If tcp or tls, a socket manager */
};

/**
 * This structure stores information about an RTMP connection :
 * - the number of streams (FLEX NetStream objects) that form the Asterisk
 *   channel. A minimum of 2 streams are used per Asterisk channel to
 *   receive/send data from/to the RTMP server.
 * - the name of the stream that Asterisk will publish to the RTMP server
 * - the name of the stream that Asterisk will retrieve from the RTMP server.
 *   If numstreams is higher than 2, Asterisk will ask the RTMP server to play
 *   streams named 'readstream-0', 'readstream-1', etc.
 */
struct rtmp_pvt
{
        struct ast_channel *owner;
        int mode;

#ifdef RTMP_FFMPEG
        AVCodec *encoder;
        AVCodec *decoder;
        AVCodecContext *encoding_context;
        AVCodecContext *decoding_context;
        ReSampleContext *tortmp_resample_context;
        ReSampleContext *fromrtmp_resample_context;
#endif
        unsigned int rtmpinputrate; /* default : 11000 Hz */
        unsigned int astinputrate;  /* default : 8000 Hz */
        int16_t decoding_jitter[JITTER_SIZE * 2];
        int decoding_jitter_length;


        /* Each stream is a member of a group of at least 2 streams :
         * - the first stream carries data to be published to the RTMP server
         * - each subsequent stream handles data (audio/video) coming
         *   from the RTMP server
         *
         * numstreams contains the number of streams contained in the group
         */
        uint32_t streamid;
        //uint32_t streamid2;
        int numstreams;
        int readstream_index;
        char readstream[AST_MAX_EXTENSION];
        char writestream[AST_MAX_EXTENSION];

        /* \brief Pipe file descriptor handles array.
         * Read from pipe[0], write to pipe[1]
         */
        int pipe[2];
        int pipe2[2];
        int schedid;

        uint8_t audiobuffer[2000];  // buff in case of rcv less than codec packet
        int audiolength;

        struct timeval tv;
        long samples;
        long duration;
        long last;

        struct rtmp_client *client;
        struct rtmp_socket socket;  /*!< The socket used for this dialog */
};

struct rtmp_rule
{
        char name[80];
        char number[AST_MAX_EXTENSION];
        char dest[AST_MAX_EXTENSION];
};

static int version = VERSION_RTMP;
static int subversion = SUBVERSION_RTMP;

static uint8_t buffer_black[] =
{ 0x12, 0x00, 0x00, 0x84, 0x00, 0x08, 0x08, 0x14, 0x26, 0x16, 0x16, 0x18,
        0x18, 0xF4, 0xF4 };
//static uint8_t buffer_white[] = { 0x12, 0x00, 0x00, 0x84, 0x00, 0x08, 0x08, 0x14, 0x26, 0x16, 0x16, 0x18, 0x18, 0xF4, 0xF4 };

// Original: static struct ast_sched_thread *sched;
INITIALIZE_SCHED;

static struct sockaddr_in rtmpserver;
static char rtmpserverstr[256];
static char application[50];
static int autochunksize = 0;
static int autousers = 0;
static int multipleusers = 0;
static int lastuniqueuser = 0;
static int hangupusers = 1;
static char context[AST_MAX_EXTENSION] = "default";
static char redirect[1000] = "";
static char httpurl[1000] = "";
static char realtimename[50] = ""; //rtmpusers";
static int debug = 0;
static int dumptimings = 0;
static int dumpstats = 0;
static int videosupport = 0;
static int textsupport = 0;
static int nospeexsilence = 0;
static int reserved = 1;
static int record_raw = 0;
static int record_flv = 0;
static int spy_picture = 0;


static int chunksbuffer = 20;
static int audiotimestamp = 0;
static int videotimestamp = 0;
static int functionthreaded = 1;
static int events = 0;
static int tcpbuffer = 0;
static int maxaudiobuffer = 40000;
static int maxvideobuffer = 10000;
static int maxaudiopipe = 60000;
static int maxvideopipe = 60000;
static int maxoverwrites = 0;
static int tcpkeepalive = 0;
static int tcpnodelay = 0;
static int antiburst = 0;
static int maxsilence = 500;
// Flag to use new parsing for connect msg
static int mSupportCnxParseOldVersion = 0;

static struct ast_tls_config rtmp_tls_cfg;
static struct ast_tls_config default_tls_cfg;

static int rtmfpenable = 0;


#ifdef GEOIP_H
static GeoIP *gi = NULL;
#endif

static struct ast_jb_conf default_jbconf = {
        .flags = 0,
        .max_size = (-1),
        .resync_threshold = (-1),
        .impl = "",
        .target_extra = (-1),
};
static struct ast_jb_conf global_jbconf;

static const char tdesc[] = "RTMP driver";
static const char config_file[] = "rtmp.conf";


#ifdef LOW_MEMORY
static int hash_connections_size = 17;
static int hash_rtmpmessages_size = 17;
static int hash_dialog_size = 17;
#else
static int hash_connections_size = 563;
static int hash_rtmpmessages_size = 563;
static int hash_dialog_size = 563;
#endif

#ifdef LOW_MEMORY
#define HASH_USER_SIZE 17
#else
#define HASH_USER_SIZE 563
#endif


static struct ao2_container *users;
static struct ao2_container *connections;

#define rtmp_pvt_lock(x) ao2_lock(x)
#define rtmp_pvt_trylock(x) ao2_trylock(x)
#define rtmp_pvt_unlock(x) ao2_unlock(x)

#define DEFAULT_RTMP_PORT    1935 /* From RFC 3261 (former 2543) */
#define DEFAULT_RTMPS_PORT   443

static int rtmpport = DEFAULT_RTMP_PORT;
static int bindport = -1;
static int bindport2 = -1;
static int bindport3 = -1;
static struct sockaddr_in bindaddr; /* The address we bind to */
static struct sockaddr_in bindaddr2;  /* The address we bind to */
static int rtmpudpsock = -1;    /* UDP listening socket */
static int test_losspct = 0;

static struct
{
        unsigned int tos;
        unsigned int cos;
} qos =
{
        0, 0};

static pthread_t netthreadid = AST_PTHREADT_NULL;

static char applicationlocal[50]; // For RTMP connect

static struct rtmp_rule rtmp_rules[MAX_RULES];


AST_MUTEX_DEFINE_STATIC(rtmplock);  /*!< Protect the interface list (of rtmp_pvt's) */

/* This is the thread for the monitor which checks for input on the channels
   which are not currently in use.  */
#ifdef _CHECK_CNX_RTMP_
static pthread_t monitor_thread = AST_PTHREADT_NULL;
#endif


#define STATS_MAX 13
static int stats[STATS_MAX];
static char stats_name[STATS_MAX][40] = {
        "Sessions connected ",
        "Sessions peak      ",
        "Sessions binded    ",
        "Sessions error     ",
        "Sessions denied    ",
        "Sessions calls     ",
        "Sessions requests  ",
        "Sessions answers   ",
        "Sessions hangups   ",
        "Texts              ",
        "DTMF               ",
        "Functions          ",
        "Events             ",
};
#define STATS_COUNT           0
#define STATS_PEAK            1
#define STATS_BIND            2
#define STATS_ERROR_OPEN      3
#define STATS_DENIED          4
#define STATS_CALLS           5
#define STATS_REQUESTS        6
#define STATS_ANSWERS         7
#define STATS_HANGUPS         8
#define STATS_TEXTS           9
#define STATS_DTMFS           10
#define STATS_FUNCTIONS       11
#define STATS_EVENTS          12


static void *_rtmp_tcp_helper_thread(struct rtmp_pvt *pvt,
        struct ast_tcptls_session_instance *tcptls_session);
static void *rtmp_tcp_worker_fn(void *data);



/*! \brief The TCP server definition */
static struct ast_tcptls_session_args rtmp_tcp_desc = {
        .accept_fd = -1,
        .master = AST_PTHREADT_NULL,
        .tls_cfg = NULL,
        .poll_timeout = -1,
        .name = "rtmp tcp server",
        //.accept_fn = rtmp_tcp_server_root,
        .accept_fn = ast_tcptls_server_root,
        .worker_fn = rtmp_tcp_worker_fn,
};

static struct ast_tcptls_session_args rtmp_tls_desc = {
        .accept_fd = -1,
        .master = AST_PTHREADT_NULL,
        .tls_cfg = NULL,
        .poll_timeout = -1,
        .name = "rtmp tcp server 2",
        //.accept_fn = rtmp_tcp_server_root,
        .accept_fn = ast_tcptls_server_root,
        .worker_fn = rtmp_tcp_worker_fn,
};


/*! \brief Definition of a thread that handles a socket */
struct rtmp_threadinfo
{
        int stop;
        pthread_t threadid;
        struct ast_tcptls_session_instance *tcptls_session;

        struct rtmp_client *client;
};

enum rtmfp_thread_iostate
{
    RTMFP_IOSTATE_IDLE,
    RTMFP_IOSTATE_READY,
    RTMFP_IOSTATE_PROCESSING,
    RTMFP_IOSTATE_SCHEDREADY,
};

enum rtmfp_thread_type
{
    RTMFP_THREAD_TYPE_POOL,
    RTMFP_THREAD_TYPE_DYNAMIC,
};

struct rtmfp_pkt_buf
{
        AST_LIST_ENTRY(rtmfp_pkt_buf) entry;
        size_t len;
        unsigned char buf[1];
};

struct rtmfp_thread
{
        AST_LIST_ENTRY(rtmfp_thread) list;
        enum rtmfp_thread_type type;
        enum rtmfp_thread_iostate iostate;
#ifdef SCHED_MULTITHREADED
        void (*schedfunc) (const void *);
        const void *scheddata;
#endif
#ifdef DEBUG_SCHED_MULTITHREAD
        char curfunc[80];
#endif
        int actions;
        pthread_t threadid;
        int threadnum;
        struct sockaddr_in iosin;
        unsigned char readbuf[4096];
        unsigned char *buf;
        ssize_t buf_len;
        size_t buf_size;
        int iofd;
        time_t checktime;
        ast_mutex_t lock;
        ast_cond_t cond;
        ast_mutex_t init_lock;
        ast_cond_t init_cond;
        /*! if this thread is processing a full frame,
     some information about that frame will be stored
     here, so we can avoid dispatching any more full
     frames for that callno to other threads */
        struct
        {
                unsigned short callno;
                struct sockaddr_in sin;
                unsigned char type;
                unsigned char csub;
        } ffinfo;
        /*! Queued up full frames for processing.  If more full frames arrive for
         *  a call which this thread is already processing a full frame for, they
         *  are queued up here. */
        AST_LIST_HEAD_NOLOCK(, rtmfp_pkt_buf) full_frames;
        unsigned char stop;
};

/* Thread lists */
static AST_LIST_HEAD_STATIC(rtmfp_list, rtmfp_thread);

static void *rtmfp_process_thread(void *data);

static int rtmfp_max_thread_count = 200;
static int rtmfp_thread_count = 0;

static void signal_condition(ast_mutex_t * lock, ast_cond_t * cond)
{
    ast_mutex_lock(lock);
    ast_cond_signal(cond);
    ast_mutex_unlock(lock);
}


/*! \brief  The table of TCP threads */
static struct ao2_container *threadt;


#define RTMP_VERBOSE(client,str, ...)       {\
        if (debug) \
        { \
            if ((void*)client == NULL)\
            ast_verbose(str,  ## __VA_ARGS__ );\
            else\
            ast_verbose("RTMP/%p : " str, (void*)client, ## __VA_ARGS__ );\
        } \
}

#define I6LOG(lvl,client,str, ...)      {\
        if (debug) \
        { \
            if ((void*)client == NULL)\
            ast_log(lvl, str,  ## __VA_ARGS__ );\
            else\
            ast_log(lvl, "RTMP/%p : " str, (void*)client, ## __VA_ARGS__ );\
        } \
}

#define I6DEBUG(lvl,client,str, ...)    { \
        if (debug) \
        { \
            if ((void*)client == NULL)\
            ast_debug(lvl, str,  ## __VA_ARGS__ );\
            else\
            ast_debug(lvl, "RTMP/%p : " str, (void*)client, ## __VA_ARGS__ ); \
            /* printf("RTMP/%p : " str, (void*)client, ## __VA_ARGS__ ); */\
        } \
}

#ifdef RTMP_FFMPEG
/*
 * Macro defines for FLV recorder
         if (client && client->pvt && client->pvt->client && client->pvt->client->name && strcmp(client->name,client->pvt->client->name) )\
            sprintf(filename, "/tmp/RTMP-%p_sd_%s_to_%s_%s.flv", client, (client->outgoing_calls + client->incoming_calls), client->name,client->pvt->client->name, direction ); \

 */
#define FLV_SET_FILENAME(filename, direction)  {\
        if (ast_config_AST_MONITOR_DIR != NULL){\
            ast_mkdir(ast_config_AST_MONITOR_DIR, 0777); \
        }\
        if (client && client->name) {\
            if (client && client->pvt && client->pvt->owner && GET_CHAN_EXTEN(client->pvt->owner)  )\
            if (ast_config_AST_MONITOR_DIR != NULL)\
            sprintf(filename, "%s/RTMP-%p_%s_%s_to_%s_%s.flv", ast_config_AST_MONITOR_DIR, client, GET_CHAN_UNIQUEID(client->pvt->owner), client->name, GET_CHAN_EXTEN(client->pvt->owner), direction ); \
            else\
            sprintf(filename, "/tmp/RTMP-%p_%s_%s_to_%s_%s.flv", client, GET_CHAN_UNIQUEID(client->pvt->owner), client->name, GET_CHAN_EXTEN(client->pvt->owner), direction ); \
            else\
            if (ast_config_AST_MONITOR_DIR != NULL)\
            sprintf(filename, "%s/RTMP-%p_%s_%s_%s.flv", ast_config_AST_MONITOR_DIR, client, GET_CHAN_UNIQUEID(client->pvt->owner), client->name, direction ); \
            else\
            sprintf(filename, "/tmp/RTMP-%s_%s_%s.flv",GET_CHAN_UNIQUEID(client->pvt->owner), client->name, direction ); \
        }\
        else {\
            if (ast_config_AST_MONITOR_DIR != NULL)\
            sprintf(filename, "%s/RTMP-%p_%s_%s.flv", ast_config_AST_MONITOR_DIR, client, GET_CHAN_UNIQUEID(client->pvt->owner), direction); \
            else\
            sprintf(filename, "/tmp/RTMP-%p_%s_%s.flv", client, GET_CHAN_UNIQUEID(client->pvt->owner), direction); \
        }\
}

/*
 * Ctx name and filename are inverted because what receive by astersik is send by client
 * so it's the out the client but the in for asterisk
 *  => INPUT ctx for asterisk create an output filename
 *  => OUTPUT ctx for asterisk create an input filename
 */
#define INIT_FLV_INPUT(client) { \
        char filename[100]; \
        FLV_SET_FILENAME(filename, "out");\
        if ( FLV_init(&(client->in_flv), 1, 0, 0, client->audiocodec, FLV_FRAME_KEY, filename) != FLV_OK ) { \
            RTMP_VERBOSE(client, "Record FLV init failed\n"); \
        } \
        else {\
            I6DEBUG(4,client, "Record FLV input file ok: %s\n", filename); \
        }\
}

#define INIT_FLV_OUTPUT(client) { \
        char filename[100]; \
        FLV_SET_FILENAME(filename, "in");\
        if ( FLV_init(&(client->out_flv), 1, 0, 0, client->audiocodec, FLV_FRAME_KEY, filename) != FLV_OK ) { \
            RTMP_VERBOSE(client, "Record FLV init failed\n"); \
        } \
        else {\
            I6DEBUG(4,client, "Record FLV output file ok: %s\n", filename); \
        }\
}

/*
 * Macro to init spy data
 */
#define FLV_SPY_SET_FILENAME(filename)  {\
        if (client && client->name) {\
            if (ast_config_AST_MONITOR_DIR != NULL)\
            sprintf(filename, "%s/spy/RTMP-spy-%s.flv", ast_config_AST_MONITOR_DIR, client->name); \
            else\
            sprintf(filename, "/tmp/RTMP-spy-%p-%s.flv", client, client->name ); \
        }\
        else {\
            if (ast_config_AST_MONITOR_DIR != NULL)\
            sprintf(filename, "%s/RTMP-spy-%p.flv", ast_config_AST_MONITOR_DIR, client); \
            else\
            sprintf(filename, "/tmp/RTMP-spy-%p.flv", client); \
        }\
}

#define INIT_FLV_SPY(client) { \
        char filename[100]; \
        FLV_SPY_SET_FILENAME(filename);\
        if ( FLV_init(&(client->out_flv_spy), 1, 0, 0, client->audiocodec, FLV_FRAME_KEY, filename) != FLV_OK ) {\
            RTMP_VERBOSE(client, "Spy FLV init failed\n");\
        }\
        else {\
            I6DEBUG(4,client, "Spy FLV output file ok: %s\n", filename);\
        }\
}
#endif


ast_mutex_t streamslock;

//static struct ast_channel *rtmp_request(const char *type, int format, const struct ast_channel *requestor, void *data, int *cause);

#if ASTERISK_VERSION_NUM < AST_8
static struct ast_channel *rtmp_request(const char *type, int format_cap,
        void *data, int *cause);
static int rtmp_call(struct ast_channel *ast, char *dest, int timeout);
#elif ASTERISK_VERSION_NUM >= AST_8 && ASTERISK_VERSION_NUM < AST_11
static struct ast_channel *rtmp_request(const char *type, format_t format_cap,
        const struct ast_channel *requestor, void *data, int *cause);
static int rtmp_call(struct ast_channel *ast, char *dest, int timeout);
#elif ASTERISK_VERSION_NUM >= AST_11  && ASTERISK_VERSION_NUM < AST_12
static struct ast_channel *rtmp_request(const char *type,
        struct ast_format_cap *format_cap, const struct ast_channel *requestor,
        const char *data, int *cause);
static int rtmp_call(struct ast_channel *ast, const char *dest, int timeout);
#elif ASTERISK_VERSION_NUM >= AST_12
static struct ast_channel *rtmp_request(const char *type,
        struct ast_format_cap *format_cap, const struct ast_channel *requestor,
        const char *data, int *cause);
static int rtmp_call(struct ast_channel *ast, const char *dest, int timeout);
#endif
static void rtmp_destroy_fn(void *p);
static void rtmp_destroy(struct rtmp_pvt *p);
static void rtmpmessage_destroy_fn(void *p);
static void rtmpmessage_destroy(struct rtmp_message *rtmp);
static int rtmp_hangup(struct ast_channel *ast);
static int rtmp_answer(struct ast_channel *ast);
static struct ast_frame *rtmp_read(struct ast_channel *ast);
static int rtmp_write(struct ast_channel *ast, struct ast_frame *frame);
static int rtmp_indicate(struct ast_channel *chan, int condition,
        const void *data, size_t datalen);
static int rtmp_devicestate(void *data);
static int rtmp_senddigit_begin(struct ast_channel *ast, char digit);
static int rtmp_senddigit_end(struct ast_channel *ast, char digit,
        unsigned int duration);
static int rtmp_sendtext(struct ast_channel *ast, const char *text);
static int rtmp_sendhtml(struct ast_channel *ast, int subclass,
        const char *data, int datalen);
//static enum ast_bridge_result rtmp_bridge(struct ast_channel *c0, struct ast_channel *c1, int flags, struct ast_frame **fo, struct ast_channel **rc, int timeoutms);


static int rtmp_handshake(struct rtmp_client *client);
static int rtmp_server_process(struct rtmp_threadinfo *me);
//static void* rtmp_client_process(void *data);
static void rtmp_function_process(struct rtmp_client *client, char *input);
static int check_handshake_reply(void *buffer, size_t size);
static int rtmp_send_pong(struct rtmp_client *client,
        struct rtmp_message *rtmp);
static int rtmp_send_ping(struct rtmp_client *client);
static int rtmp_send_chunksize(struct rtmp_client *client,
        uint32_t newchunksize);
static int rtmp_send_acknowledgement(struct rtmp_client *client,
        uint32_t bytesread);
static int rtmp_send_buffertime(struct rtmp_client *client, uint32_t streamid);
static int rtmp_send_createstream(struct rtmp_client *client, double streamid);
static int rtmp_send_closestream(struct rtmp_client *client, double streamid);
static int rtmp_send_play(struct rtmp_client *client, uint32_t streamid,
        char *name);
static int rtmp_send_publish(struct rtmp_client *client, uint32_t streamid,
        char *name);
static int rtmp_send_invited(struct rtmp_client *client, char *callerid);
static int rtmp_send_spyed(struct rtmp_client *client, char *callerid);
static int rtmp_send_autoanswer(struct rtmp_client *client, char *callerid);
static int rtmp_send_bye(struct rtmp_client *client);
static int rtmp_send_text(struct rtmp_client *client, const char *text);
static int rtmp_send_dtmf(struct rtmp_client *client, const char digit);
static int rtmp_send_admin(struct rtmp_client *client, const char *text);
static int rtmp_send_function(struct rtmp_client *client, const char *text);
static int rtmp_send_event(struct rtmp_client *client, const char *text);
static int rtmp_send_registered(struct rtmp_client *client, const char *text);
static int rtmp_send_unregistered(struct rtmp_client *client, const char *text);
static int rtmp_send_result_connect(struct rtmp_client *client,
        uint32_t streamid, double connectionid, char *level, char *code,
        char *description);
static int rtmp_send_result_createstream(struct rtmp_client *client,
        uint32_t streamid, double connectionid, double result);
static int rtmp_send_result_invite(struct rtmp_client *client,
        uint32_t streamid, double connectionid, char *result, char *description);
static int rtmp_send_result_accepted(struct rtmp_client *client,
        uint32_t streamid, double connectionid, char *result, char *description);
static int rtmp_send_result_rejected(struct rtmp_client *client,
        uint32_t streamid, double connectionid, char *result, char *description);
static int rtmp_send_result_cancelled(struct rtmp_client *client,
        uint32_t streamid, double connectionid, char *result, char *description);
static int rtmp_send_result_publish(struct rtmp_client *client,
        uint32_t channelid, uint32_t streamid, double connectionid,
        char *description);
static int rtmp_send_result_play(struct rtmp_client *client, uint32_t channelid,
        uint32_t streamid, double connectionid, char *description);
static int rtmp_send_result_bye(struct rtmp_client *client, uint32_t streamid,
        double connectionid, char *result, char *description);
static int rtmp_send_audio(struct rtmp_client *client, struct rtmp_pvt *p,
        struct ast_frame *frame);
static int rtmp_send_video(struct rtmp_client *client, struct rtmp_pvt *p,
        struct ast_frame *frame);
static int rtmp_send_clear(struct rtmp_client *client);
static int amf_add_bobject(struct amf_object *object, uint8_t type,
        char *property, void *value);
static int amf_destroy_object(struct amf_object *object);
static char *rtmp_build_invoke(struct rtmp_message *rtmp, char *method,
        double connectionid, struct amf_object *amf, char *options, void *boolean,
        char *newoptions);
static char *rtmp_build_result_connect(struct rtmp_message *rtmp, char *method,
        double connectionid, struct amf_object *amf);
static char *rtmp_build_result_createstream(struct rtmp_message *rtmp,
        char *method, double connectionid, double result);
static char *rtmp_build_result_message(struct rtmp_message *rtmp, char *method,
        double connectionid, char *description);
static char *rtmp_build_request_message(struct rtmp_message *rtmp, char *method,
        double connectionid, char *description);
static char *rtmp_build_request_message2(struct rtmp_message *rtmp,
        char *method, double connectionid, char *description, char *extra);
static char *rtmp_build_audio_pcm(struct rtmp_message *rtmp, void *samples,
        int datalen);
static char *rtmp_build_audio_reserved(struct rtmp_message *rtmp, void *samples,
        int datalen);
static char *rtmp_build_audio_ulaw(struct rtmp_message *rtmp, void *samples,
        int datalen);
static char *rtmp_build_audio_alaw(struct rtmp_message *rtmp, void *samples,
        int datalen);
static char *rtmp_build_audio_speex(struct rtmp_message *rtmp, void *samples,
        int datalen);
static char *rtmp_build_video(struct rtmp_message *rtmp, void *samples,
        int datalen);
static int rtmp_set_header(uint8_t * header, struct rtmp_message *rtmp,
        int hdrlen);
static int rtmp_set_boolean(void *message, void *value);
static int rtmp_set_property(void *message, char *string);
static int rtmp_set_string(void *message, char *string, size_t length);
static int rtmp_set_number(void *message, double *number);
static int rtmp_set_null(void *message);
static int rtmp_set_undefined(void *message);
static int rtmp_set_object(void *message, struct amf_object *amf);
static int rtmp_set_array(void *message, struct amf_object *amf);
static int amf_numberlen(double *number);
static int amf_booleanlen(void *boolean);
static int amf_strlen(char *string);
static int amf_objlen(struct amf_object *object);
static int amf_arraylen(struct amf_object *object);
static int amf_objcount(struct amf_object *object);
static int SendTcp(struct rtmp_client *client, uint8_t * data,int length);
static int rtmp_send_data(struct rtmp_client *client, uint8_t * data,int length);
static int rtmp_receive_line(struct rtmp_client *client, char *data,int length);
static int rtmp_receive_data(struct rtmp_client *client, uint8_t * data,int length, int timeout);
static int rtmp_send_message(struct rtmp_client *client, uint8_t * prefix,
        uint8_t * message, size_t bodysize, int iType);
static int rtmp_send_message_direct(struct rtmp_client *client,
        uint8_t * prefix, uint8_t * message, size_t bodysize);
static int rtmp_set_outgoing_channelinfo(struct rtmp_client *client,
        struct rtmp_message *rtmp, uint8_t next_hdrlen);
static int rtmp_set_incoming_channelinfo(struct rtmp_client *client,
        void *buffer, int hdrlen, int channelid);
static int rtmp_get_current_hdrlen(struct rtmp_client *client,
        uint8_t channelid);
static int rtmp_get_current_timestamp(struct rtmp_client *client,
        uint8_t channelid);
static int rtmp_get_current_bodylen(struct rtmp_client *client,
        uint8_t channelid);
static int rtmp_get_current_type(struct rtmp_client *client, uint8_t channelid);
static int rtmp_get_current_streamid(struct rtmp_client *client,
        uint8_t channelid);
static int rtmp_get_header_length(uint8_t * header);
static int rtmp_get_channelid(uint8_t * header);
static int rtmp_get_streamid(uint8_t * header);
static int rtmp_get_bodylen(struct rtmp_client *client, uint8_t * header,
        struct rtmp_message *rtmp, int direction);
static int rtmp_parse_header(struct rtmp_message *rtmp, void *buffer);
static int rtmp_handle_system_message(struct rtmp_client *client,
        struct rtmp_message *rtmp);
static int rtmp_handle_connect_message(struct rtmp_client *client,
        struct rtmp_message *rtmp);
static int rtmp_handle_notify_message(struct rtmp_client *client,
        struct rtmp_message *rtmp);
static int rtmp_handle_control_message(struct rtmp_client *client,
        struct rtmp_message *rtmp);
static int rtmp_handle_audio_packet(struct rtmp_client *client,
        struct rtmp_message *rtmp);
static int rtmp_handle_video_packet(struct rtmp_client *client,
        struct rtmp_message *rtmp);
static int rtmp_handle_notify_packet(struct rtmp_client *client,
        struct rtmp_message *rtmp);
static int rtmp_handle_null_packet(struct rtmp_client *client);
static int amf_parse_reply(double *result, char *level, char *code,
        char *description, char *amf, size_t len);
static int amf_parse_connect(double *result, char *level, char *code,
        char *description, char *amf, size_t len, int *audioCodecDetected,
        char *flashVer, char *tcurl);
static int amf_parse_connect_message(double *result, char *level, char *code,
        char *description, char *amf, size_t len, int *audioCodecDetected,
        char *flashVer, char *tcurl);
static int amf_parse_control(double *id, char *name, char *amf, size_t len);
static int amf_parse_command(char *command, char *text, char *amf, char *dstId,
        size_t len);
static int amf_get_type(char *buf);
static int amf_get_property(char *string, void *buffer, size_t length);
static int amf_get_property_connect(char *string, void *buffer, size_t length);
static int amf_get_property_control(char *string, void *buffer, size_t length);
static int amf_get_string(char *string, void *buffer, size_t length);
static int amf_get_number(double *number, void *amf);
static int activate_channels(struct rtmp_client *client, int channelid,
        int range);
static int desactivate_channels(struct rtmp_client *client, int channelid,
        int range);

static struct rtmp_client *rtmp_find_connection(const char *name);
static int rtmp_find_rule(char *src, char *caller, char *called, char *dest,
        char *parameters);

static int reload(void);

static char *rtmp_do_reload(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_do_debug(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_show_version(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_show_configuration(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_show_routing(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_show_jitter(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_show_channels(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_show_connections(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_show_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_close_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_close_connections(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_send_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_admin_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_dtmf_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_event_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_set_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_show_users(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char *rtmp_show_statistics(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a);
static char * getUsedRtmpProtocolName(struct rtmp_client *client);


static char type[] = "RTMP";
static struct ast_channel_tech rtmp_tech = {
        .type = type,
        .description = tdesc,
        // .capabilities =  ... We declare this value at the start of the function configure_module
        .properties = AST_CHAN_TP_WANTSJITTER | AST_CHAN_TP_CREATESJITTER,
        .requester = rtmp_request,
        .send_digit_begin = rtmp_senddigit_begin,
        .send_digit_end = rtmp_senddigit_end,
        .send_text = rtmp_sendtext,
        .send_html = rtmp_sendhtml,
        .call = rtmp_call,
        .hangup = rtmp_hangup,
        .answer = rtmp_answer,
        .read = rtmp_read,
        .write = rtmp_write,
        .write_video = rtmp_write,
        //.bridge = rtmp_bridge,
        .indicate = rtmp_indicate,
        //.devicestate = rtmp_devicestate,
};
//

static struct ast_cli_entry rtmp_cli[] = {
        AST_CLI_DEFINE(rtmp_do_reload, "Reload RTMP configuration"),
        AST_CLI_DEFINE(rtmp_do_debug, "Enable/Disable RTMP debugging"),
        AST_CLI_DEFINE(rtmp_show_version, "Show RTMP module version"),
        AST_CLI_DEFINE(rtmp_show_configuration, "Show RTMP configuration"),
        AST_CLI_DEFINE(rtmp_show_routing, "Show RTMP routing"),
        AST_CLI_DEFINE(rtmp_show_jitter, "Show RTMP jitter configuration"),
        AST_CLI_DEFINE(rtmp_show_channels, "Show RTMP channels"),
        AST_CLI_DEFINE(rtmp_show_connections, "Show RTMP connections"),
        AST_CLI_DEFINE(rtmp_show_connection, "Show RTMP connection"),
        AST_CLI_DEFINE(rtmp_close_connection, "Close RTMP connection"),
        AST_CLI_DEFINE(rtmp_close_connections, "Close RTMP connections"),
        AST_CLI_DEFINE(rtmp_send_connection, "Send a text to RTMP connection"),
        AST_CLI_DEFINE(rtmp_admin_connection, "Send an ADMIN cmd to RTMP connection"),
        AST_CLI_DEFINE(rtmp_dtmf_connection, "Send a DTMF to RTMP connection"),
        AST_CLI_DEFINE(rtmp_event_connection, "Send an event to RTMP connection"),
        AST_CLI_DEFINE(rtmp_set_connection, "Configure RTMP connection"),
        AST_CLI_DEFINE(rtmp_show_users, "Show RTMP users"),
        AST_CLI_DEFINE(rtmp_show_statistics, "Show RTMP statistics"),
};



/*******************************************************************************
 *
 *                            START CODE
 *
 ******************************************************************************/


/*
void I6_log( int dbgLevel, const char *fmt, ...)
{
    va_list list;
    va_start(list, fmt);

    if ((int)level <= verbose)
    {
        vfprintf(stderr, fmt, list);
    }

    va_end(list);
}
 */

#if 1
static void dump_buffer_hex(const char *text, void *data, int size)
{
    /* dumps size bytes of *data to stdout. Looks like:
     * [0000] 75 6E 6B 6E 6F 77 6E 20
     *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
     * (in a single line of course)
     */

    if (debug < 2)
        return;

    unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[4] = { 0 };
    char addrstr[10] = { 0 };
    char hexstr[16 * 3 + 5] = { 0 };
    char charstr[16 * 1 + 5] = { 0 };

    ast_debug(9, "%s : (%d bytes)\n", text, size);

    for (n = 1; n <= size; n++)
    {
        if (n % 16 == 1)
        {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4x",
                    ((unsigned int)p - (unsigned int)data));
        }

        c = *p;
        if (isalnum(c) == 0)
        {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr) - strlen(hexstr) - 1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr) - strlen(charstr) - 1);

        if (n % 16 == 0)
        {
            /* line completed */
            ast_debug(9, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
        else if (n % 8 == 0)
        {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr) - strlen(hexstr) - 1);
            strncat(charstr, " ", sizeof(charstr) - strlen(charstr) - 1);
        }
        p++;                        /* next byte */
    }

    if (strlen(hexstr) > 0)
    {
        /* print rest of buffer if not empty */
        ast_debug(9, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}
#endif                          /* jyg */


/*
 * Function : getUsedRtmpProtocolName
 * In       : client context
 * Out      : NA
 * Return   : Protocol name
 * Purpose  : Return protocol name selected for client
 */
static char * getUsedRtmpProtocolName(struct rtmp_client *client)
{
    if (client->protocol && RTMP_FEATURE_ENC)
        return "rtmpe";
    else if (client->protocol && RTMP_FEATURE_SSL)
        return "rtmps";
    else
        return "rtmp";
}


#undef _SEND_TCP_NONBLOCK_
#ifdef _SEND_TCP_NONBLOCK_
#define SENDTCP(fd, buf, len, flag) sendNonBlock(fd, buf, len, flag)
#else
#define SENDTCP(fd, buf, len, flag) send(fd, buf, len, flag)
#endif

static int sendNonBlock(int fd, void *buf, size_t len, int flags)
{
    int loop = 3;
    int res = -1;

    I6DEBUG(10, NULL, "sendNonBlock %do\n", len);
    while ((loop > 0) && (res < 0))
    {
        res = send(fd, buf, len, flags);
        if (res < 0)
        {
            I6DEBUG(3, NULL, "send %d/%do failed errno: (%d)%s.\n", res, len, errno,strerror(errno));
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)){
                // Manage our retry
                loop--;
                usleep(10000);
            }
            else
                loop = 0;
        }
    }

    I6DEBUG(10, NULL, "sent %d/%d\n", res, len);
    return res;
}



#ifdef LIBCURL_VERSION
static size_t curl_write_str(void *ptr, size_t size, size_t nmemb, void *data)
{
    register int realsize = size * nmemb;
    struct ast_str **pstr = (struct ast_str **)data;

    ast_debug(3, "Called with data=%p, str=%p, realsize=%d, len=%zu, used=%zu\n",
            data, *pstr, realsize, ast_str_size(*pstr), ast_str_strlen(*pstr));

    ast_str_append_substr(pstr, 0, ptr, realsize);

    ast_debug(3, "Now, len=%zu, used=%zu\n", ast_str_size(*pstr),
            ast_str_strlen(*pstr));

    return realsize;
}

static int http_request(char *server, char *caller, char *called,
        char *response, char *extra)
{
    CURL *curl;
    CURLcode res;
    long errcode = 0;

    char *request = NULL;
    char *params = NULL;

    struct ast_str *str = NULL;

    if (!httpurl[0])
        return -1;

    str = (struct ast_str *)ast_str_create(100);

    request = ast_calloc(1, 1024);
    if (request == NULL)
    {
        ast_free(str);
        return -1;
    }

    params = ast_calloc(1, 400);
    if (params == NULL)
    {
        ast_free(str);
        ast_free(request);
        return -1;
    }

    curl = curl_easy_init();

    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "ChannelRTMP");
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_str);
        curl_easy_setopt(curl, CURLOPT_FILE, (void *)&str);

        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);

        if (extra && extra[0])
            sprintf(params, "server=%s&caller=%s&called=%s&%s", server, caller,
                    called, extra);
        else
            sprintf(params, "server=%s&caller=%s&called=%s", server, caller, called);

        sprintf(request, "%s?%s", httpurl, params);

    if (debug)
        ast_verbose(VERBOSE_PREFIX_2 "HTTP request URL = %s\n", request);

        curl_easy_setopt(curl, CURLOPT_URL, request);

        res = curl_easy_perform(curl);

        if (CURLE_OK == res)
        {
            char *ct;
            /* ask for the content-type */
            /* http://curl.haxx.se/libcurl/c/curl_easy_getinfo.html */
            res = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);

            if ((CURLE_OK == res) && ct)
                if (debug)
                    ast_verbose(VERBOSE_PREFIX_2 "Content-Type: %s\n", ct);

            res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &errcode);

            if (CURLE_OK == res)
                if (debug)
                    ast_verbose(VERBOSE_PREFIX_2 "HTTP Code: %ld\n", errcode);
        }
        else
        {
            if (debug)
                ast_verbose(VERBOSE_PREFIX_2 "ERROR: %ld\n", errcode);
        }

        if (debug)
            ast_verbose(VERBOSE_PREFIX_2 "Content: \"%s\"\n", ast_str_buffer(str));

        if (response)
            strncpy(response, ast_str_buffer(str), 200);

        /* always cleanup */
        curl_easy_cleanup(curl);
    }


    ast_free(str);

    ast_free(params);
    ast_free(request);

    if (errcode == 200)
        return 0;
    else
        return -1;
}
#else
static int http_request(char *server, char *caller, char *called,
        char *response, char *extra)
{
    if (!httpurl[0])
    return -1;

    ast_log(LOG_WARNING, "Without CURL, no request enabled\n");

    return -1;
}
#endif

static int user_hash_cb(const void *obj, const int flags)
{
    const struct rtmp_user *user = obj;

    return ast_str_hash(user->name);
}

static int user_cmp_cb(void *obj, void *arg, int flags)
{
    struct rtmp_user *user = obj, *user2 = arg;

    return !strcmp(user->name, user2->name) ? CMP_MATCH | CMP_STOP : 0;
}

static int threadt_hash_cb(const void *obj, const int flags)
{
    const struct rtmp_threadinfo *th = obj;

    if (!th && th->tcptls_session)
    {
        struct in_addr temp_addr;
        TCPTLS_SESSION_ADDRESS(th->tcptls_session->remote_address,
                temp_addr.s_addr);
        return temp_addr.s_addr;
    }
    else
        return -1;
}

static int threadt_cmp_cb(void *obj, void *arg, int flags)
{
    struct rtmp_threadinfo *th = obj, *th2 = arg;

    return (th->tcptls_session == th2->tcptls_session) ? CMP_MATCH | CMP_STOP : 0;
}

/*! \brief
 * when we create or delete references, make sure to use these
 * functions so we keep track of the refcounts.
 */
#ifdef REF_DEBUG
#define rtmpmessage_ref(arg1,arg2) rtmpmessage_ref_debug((arg1),(arg2), __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define rtmpmessage_unref(arg1,arg2) rtmpmessage_unref_debug((arg1),(arg2), __FILE__, __LINE__, __PRETTY_FUNCTION__)
static struct rtmp_message *rtmpmessage_ref_debug(struct rtmp_message *p,
        char *tag, char *file, int line, const char *func)
{
        if (p)
            _ao2_ref_debug(p, 1, tag, file, line, func);
        else
            ast_log(LOG_ERROR, "Attempt to Ref a null pointer\n");
        return p;
}
static struct rtmp_message *rtmpmessage_unref_debug(struct rtmp_message *p,
        char *tag, char *file, int line, const char *func)
{
        if (p)
            _ao2_ref_debug(p, -1, tag, file, line, func);
        return NULL;
}
#else
static struct rtmp_message *rtmpmessage_ref(struct rtmp_message *p, char *tag)
{
        if (p)
            ao2_ref(p, 1);
        else
            ast_log(LOG_ERROR, "Attempt to Ref a null pointer\n");
        return p;
}
static struct rtmp_rtmpmessage *rtmpmessage_unref(struct rtmp_message *p,
        char *tag)
{
        if (p)
            ao2_ref(p, -1);
        return NULL;
}
#endif





#define AES_KEY_SIZE 0x20

uint8_t g_dh1024p[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

DH *dh = NULL;

static void generateKeyPair(void)
{
    unsigned char publicKey[128];
    unsigned char privateKey[128];
    //char P[128]; //this is set to a static 128-byte value, omitting for brevity
    unsigned long G = 2;

    if (dh)
        DH_free(dh);

    dh = DH_new();
    dh->p = BN_new();
    dh->g = BN_new();

    BN_set_word(dh->g, G);
    BN_bin2bn(g_dh1024p, 128, dh->p);
    if (DH_generate_key(dh))
    {
        BN_bn2bin(dh->pub_key, publicKey);
        BN_bn2bin(dh->priv_key, privateKey);
    }

    {
        char tmp[1024];
        sprintf(tmp, "AES (public)");
        dump_buffer_hex(tmp, publicKey, 128);
    }


    {
        char tmp[1024];
        sprintf(tmp, "AES (private)");
        dump_buffer_hex(tmp, privateKey, 128);
    }

}

static void computeSharedSecret(char *far_key, size_t far_key_size)
{
    char shared_secret[128];
    BIGNUM *bn_far_key = BN_bin2bn((const uint8_t *)far_key, far_key_size, NULL);
    DH_compute_key((unsigned char *)shared_secret, bn_far_key, dh);

    BN_free(bn_far_key);

    {
        char tmp[1024];
        sprintf(tmp, "AES (shared secret)");
        dump_buffer_hex(tmp, shared_secret, 128);
    }
}

static void computeAsymetricKeys(char *shared_secret, size_t shared_secret_size,
        char *initiator_nonce, size_t initiator_nonce_size,
        char *responder_nonce, size_t responder_nonce_size)
{
    uint8_t md1[AES_KEY_SIZE];
    uint8_t md2[AES_KEY_SIZE];

    // doing HMAC-SHA256 of one side
    HMAC(EVP_sha256(), responder_nonce, responder_nonce_size,
            (const uint8_t *)initiator_nonce, initiator_nonce_size, md1, NULL);
    // doing HMAC-SHA256 of the other side
    HMAC(EVP_sha256(), initiator_nonce, initiator_nonce_size,
            (const uint8_t *)responder_nonce, responder_nonce_size, md2, NULL);

    char decrypt_key[128];
    char encrypt_key[128];

    // now doing HMAC-sha256 of both result with the shared secret DH key
    HMAC(EVP_sha256(), shared_secret, shared_secret_size, md1, AES_KEY_SIZE,
            (uint8_t *) decrypt_key, NULL);
    HMAC(EVP_sha256(), shared_secret, shared_secret_size, md2, AES_KEY_SIZE,
            (uint8_t *) encrypt_key, NULL);
}

static void decryptBuffer(char *pkt_data, size_t pkt_length, char *key_data,
        uint32_t offset)
{
    AES_KEY aes_decrypt_key;
    AES_set_decrypt_key((const uint8_t *)key_data, 128, &aes_decrypt_key);

    uint8_t init_vector[128];
    memset(init_vector, 0, sizeof(init_vector));
    AES_cbc_encrypt((const uint8_t *)&pkt_data[offset],
            (uint8_t *) & pkt_data[offset], pkt_length - offset, &aes_decrypt_key,
            init_vector, AES_DECRYPT);
}

static uint32_t paddingLength(uint32_t size)
{
    uint32_t paddingBytesLength = (0xFFFFFFFF - size + 5) & 0x0F;

    return paddingBytesLength;
}

static void encryptBuffer(char *pkt_data, size_t pkt_length, char *key_data,
        uint32_t offset)
{
    AES_KEY aes_encrypt_key;
    AES_set_encrypt_key((const uint8_t *)key_data, 128, &aes_encrypt_key);
    uint8_t init_vector[128];
    memset(init_vector, 0, sizeof(init_vector));
    AES_cbc_encrypt((const uint8_t *)&pkt_data[offset],
            (uint8_t *) & pkt_data[offset], pkt_length - offset, &aes_encrypt_key,
            init_vector, AES_ENCRYPT);
}


static unsigned char get_n_bits_at(unsigned char *data, int n, int bit)
{
    int byte = bit / 8;           /* byte containing first bit */
    int rem = 8 - (bit % 8);      /* remaining bits in first byte */
    unsigned char ret = 0;

    if (n <= 0 || n > 8)
        return 0;

    if (rem < n)
    {
        ret = (data[byte] << (n - rem));
        ret |= (data[byte + 1] >> (8 - n + rem));
    }
    else
    {
        ret = (data[byte] >> (rem - n));
    }

    return (ret & (0xff >> (8 - n)));
}

static int speex_get_wb_sz_at(unsigned char *data, int len, int bit)
{
    static int SpeexWBSubModeSz[] = {
            0, 36, 112, 192,
            352, 0, 0, 0
    };
    int off = bit;
    unsigned char c;

    /* skip up to two wideband frames */
    if (((len * 8 - off) >= 5) && get_n_bits_at(data, 1, off))
    {
        c = get_n_bits_at(data, 3, off + 1);
        off += SpeexWBSubModeSz[c];

        if (((len * 8 - off) >= 5) && get_n_bits_at(data, 1, off))
        {
            c = get_n_bits_at(data, 3, off + 1);
            off += SpeexWBSubModeSz[c];

            if (((len * 8 - off) >= 5) && get_n_bits_at(data, 1, off))
            {
                ast_log(LOG_WARNING,
                        "Encountered corrupt speex frame; too many wideband frames in a row.\n");
                return -1;
            }
        }

    }
    return off - bit;
}

static int speex_samples(unsigned char *data, int len)
{
    static int SpeexSubModeSz[] = {
            5, 43, 119, 160,
            220, 300, 364, 492,
            79, 0, 0, 0,
            0, 0, 0, 0
    };
    static int SpeexInBandSz[] = {
            1, 1, 4, 4,
            4, 4, 4, 4,
            8, 8, 16, 16,
            32, 32, 64, 64
    };
    int bit = 0;
    int cnt = 0;
    int off;
    unsigned char c;

    while ((len * 8 - bit) >= 5)
    {
        /* skip wideband frames */
        off = speex_get_wb_sz_at(data, len, bit);
        if (off < 0)
        {
            ast_log(LOG_WARNING,
                    "Had error while reading wideband frames for speex samples\n");
            break;
        }
        bit += off;

        if ((len * 8 - bit) < 5)
        {
            //ast_log(LOG_WARNING, "Not enough bits remaining after wide band for speex samples.\n");
            break;
        }

        /* get control bits */
        c = get_n_bits_at(data, 5, bit);
        bit += 5;

        if (c == 15)
        {
            /* terminator */
            break;
        }
        else if (c == 14)
        {
            /* in-band signal; next 4 bits contain signal id */
            c = get_n_bits_at(data, 4, bit);
            bit += 4;
            bit += SpeexInBandSz[c];
        }
        else if (c == 13)
        {
            /* user in-band; next 5 bits contain msg len */
            c = get_n_bits_at(data, 5, bit);
            bit += 5;
            bit += c * 8;
        }
        else if (c > 8)
        {
            /* unknown */
            break;
        }
        else
        {
            /* skip number bits for submode (less the 5 control bits) */
            bit += SpeexSubModeSz[c] - 5;
            cnt += 160;               /* new frame */
        }
    }
    return cnt;
}

static inline struct rtmp_user *user_unref(struct rtmp_user *user)
{
        ao2_ref(user, -1);
        return NULL;
}


static void user_destructor(void *obj)
{
    struct rtmp_user *user = obj;

    I6DEBUG(3, NULL, "Destroy user context %p.\n", user);

    ast_string_field_free_memory(user);
}

/*! \brief Create user structure based on configuration */
static struct rtmp_user *build_user(char *name, struct ast_variable *v,
        struct ast_variable *alt, int temponly)
{
        struct rtmp_user *user = NULL;
        int found = 0;
        int firstpass = 1;
        struct rtmp_user tmp_user;

        ast_copy_string(tmp_user.name, name, sizeof(tmp_user.name));
        user =
                ao2_t_find(users, &tmp_user, OBJ_POINTER | OBJ_UNLINK,
                        "find and unlink user from users table");

        if (user)
        {
            found++;
            firstpass = 0;
        }
        else if ((user = ao2_t_alloc(sizeof(*user), user_destructor, "Allocate user")))
        {
            if (ast_string_field_init(user, 128))
            {
                user = user_unref(user);
            }
        }

        if (user)
        {
            if (firstpass)
            {
                if (!found)
                {
                    ast_copy_string(user->name, name, sizeof(user->name));
                }
                user->maxcallno = 0;
                user->client = NULL;
                ast_string_field_set(user, secret, "");
                ast_string_field_set(user, context, "");
                ast_string_field_set(user, cid_name, "");
                ast_string_field_set(user, cid_num, "");
                user->multipleusers = -1;
                user->lastuniqueuser = -1;
            }

            if (!v)
            {
                v = alt;
                alt = NULL;
            }
            while (v)
            {
                if (!strcasecmp(v->name, "secret"))
                {
                    ast_string_field_set(user, secret, v->value);
                    //          } else if (!strcasecmp(v->name, "mailbox")) {
                    //              ast_string_field_set(user, mailbox, v->value);
                }
                else if (!strcasecmp(v->name, "context"))
                {
                }
                else if (!strcasecmp(v->name, "callerid"))
                {
                    if (!ast_strlen_zero(v->value))
                    {
                        char name2[80];
                        char num2[80];
                        ast_callerid_split(v->value, name2, sizeof(name2), num2,
                                sizeof(num2));
                        ast_string_field_set(user, cid_name, name2);
                        ast_string_field_set(user, cid_num, num2);
                    }
                    else
                    {
                        ast_string_field_set(user, cid_name, "");
                        ast_string_field_set(user, cid_num, "");
                    }
                }
                else if (!strcasecmp(v->name, "fullname"))
                {
                    ast_string_field_set(user, cid_name, S_OR(v->value, ""));
                }
                else if (!strcasecmp(v->name, "cid_number"))
                {
                    ast_string_field_set(user, cid_num, S_OR(v->value, ""));
                }
                else if (!strcasecmp(v->name, "multipleusers"))
                {
                    if (!strcmp(v->value, "global"))
                    user->multipleusers = -1;
                    else
                    user->multipleusers = ast_true(v->value) ? 1 : 0;
                }
                else if (!strcasecmp(v->name, "lastuniqueuser"))
                {
                    if (!strcmp(v->value, "global"))
                    user->lastuniqueuser = -1;
                    else
                    user->lastuniqueuser = ast_true(v->value) ? 1 : 0;
                }
                v = v->next;
                if (!v)
                {
                    v = alt;
                    alt = NULL;
                }
            }
        }

        return user;
}

/*! \brief Update user object in realtime storage
    If the Asterisk system name is set in asterisk.conf, we will use
    that name and store that in the "regserver" field in the sipusers
    table to facilitate multi-server setups.
 */
static void realtime_update_user(const char *username, struct sockaddr_in *sin,
        const char *useragent)
{
    char port[10] = "0";
    char ipaddr[INET_ADDRSTRLEN] = "0.0.0.0";
    char regseconds[20];

    const char *sysname = ast_config_AST_SYSTEM_NAME;

    time_t nowtime = time(NULL);

    if ((username == NULL) || (!*username))
        return;

    int realtime;

    if (!realtimename[0])
        return;

    realtime = ast_check_realtime(realtimename);
    if (!realtime)
        return;

    snprintf(regseconds, sizeof(regseconds), "%d", (int)nowtime); /* Expiration time */
    if (sin)
    {
        char buf[100];
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        ast_copy_string(ipaddr, buf, sizeof(ipaddr));
    }
    if (sin)
        snprintf(port, sizeof(port), "%d", ntohs(sin->sin_port));

    //ast_log(LOG_ERROR, "Realtime : %s %s %s %s\n", username, regseconds, ipaddr, port);

    if (useragent)
        ast_update_realtime(realtimename,
                "name", username,
                "regseconds", regseconds,
                "ipaddr", ipaddr, "port", port, "regserver", sysname,
                //"defaultuser", defaultuser,
                "useragent", useragent, SENTINEL);
    else
        ast_update_realtime(realtimename,
                "name", username,
                "regseconds", regseconds, "ipaddr", ipaddr, "port", port, SENTINEL);

    return;
}

/*!
 * \note This function calls reg_source_db -> iax2_poke_user -> find_callno,
 *       so do not call this with a pvt lock held.
 */
static struct rtmp_user *realtime_user(const char *username,
        struct sockaddr_in *sin)
{
        struct ast_variable *var = NULL;
        struct ast_variable *tmp;
        struct rtmp_user *user = NULL;
        time_t regseconds = 0;
        //int dynamic = 0;

        if (username)
        {
            var = ast_load_realtime(realtimename, "name", username, "host", "dynamic",
                                    SENTINEL);
            if (!var && sin)
            {
                char buf[100];
                inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
                var =
                        ast_load_realtime(realtimename, "name", username, "host",
                                buf, SENTINEL);
            }
        }

        if (!var && username)
        {                             /* Last ditch effort */
            var = ast_load_realtime(realtimename, "name", username, SENTINEL);
            /*!\note
             * If this one loaded something, then we need to ensure that the host
             * field matched.  The only reason why we can't have this as a criteria
             * is because we only have the IP address and the host field might be
             * set as a name (and the reverse PTR might not match).
             */
            if (var && sin)
            {
                for (tmp = var; tmp; tmp = tmp->next)
                {
                    if (!strcasecmp(tmp->name, "host"))
                    {
                        struct ast_hostent ahp;
                        struct hostent *hp;
                        if (!(hp = ast_gethostbyname(tmp->value, &ahp)) ||
                                (memcmp(hp->h_addr, &sin->sin_addr, sizeof(hp->h_addr))))
                        {
                            /* No match */
                            ast_variables_destroy(var);
                            var = NULL;
                        }
                        break;
                    }
                }
            }
        }

        if (!var)
        {
            ast_log(LOG_NOTICE, "Realtime username %s not found!\n", username);
            return NULL;
        }

        user = build_user((char *)username, var, NULL, 0);

        if (!user)
        {
            ast_log(LOG_WARNING, "Unable to build realtime username %s!\n", username);

            ast_variables_destroy(var);
            return NULL;
        }

        for (tmp = var; tmp; tmp = tmp->next)
        {
            /* Make sure it's not a user only... */
            if (!strcasecmp(tmp->name, "type"))
            {
                if (debug)
                    ast_verbose(VERBOSE_PREFIX_2 "Realtime user %s : type=%s.\n", username,
                            tmp->value);
                if (strcasecmp(tmp->value, "friend") && strcasecmp(tmp->value, "user"))
                {
                    /* Whoops, we weren't supposed to exist! */
                    user = user_unref(user);
                    break;
                }
            }
            else if (!strcasecmp(tmp->name, "regseconds"))
            {
                ast_get_time_t(tmp->value, &regseconds, 0, NULL);
            }
            else if (!strcasecmp(tmp->name, "host"))
            {
                //if (!strcasecmp(tmp->value, "dynamic"))
                //    dynamic = 1;
            }
            else if (!strcasecmp(tmp->name, "secret"))
            {
                ast_string_field_set(user, secret, tmp->value);
                if (debug)
                    ast_verbose(VERBOSE_PREFIX_2 "Realtime user %s : password=%s.\n",
                            username, tmp->value);
            }
            else if (!strcasecmp(tmp->name, "context"))
            {
                ast_string_field_set(user, context, tmp->value);
                if (debug)
                    ast_verbose(VERBOSE_PREFIX_2 "Realtime user %s : context=%s.\n",
                            username, tmp->value);
            }
        }

        ast_variables_destroy(var);

        if (debug)
            ast_verbose(VERBOSE_PREFIX_2 "Realtime user %s added.\n", username);

        return user;
}

/*!
 * \note This funtion find the rule (for redirect).
 */
static int rtmp_find_rule(char *src, char *caller, char *called, char *dest,
        char *parameters)
{
    int index;

    if (caller == NULL)
        return 0;

    if (httpurl[0])
    {
        if (http_request(src, caller, called, dest, parameters) == 0)
        {
            if (debug)
                ast_verbose(VERBOSE_PREFIX_2 "Remote rule found : %s!\n", dest);

            if (!strcmp(dest, "OK"))
                return 0;
            else if (!strcmp(dest, "ERROR"))
                return -1;
            else
                return 1;
        }
    }
    else
        for (index = 0; index < MAX_RULES; index++)
        {
            int match;

            match = 0;

            // Check caller with number
            if ((caller != NULL) && (*caller != 0) &&
                    (rtmp_rules[index].number[0] != 0))
            {
                int numberlen = strlen(rtmp_rules[index].number);
                int callerlen = strlen(caller);

                // Exact
                if (!match)
                    if (!strcmp(caller, rtmp_rules[index].number))
                    {
                        match = 1;
                    }

                // Prefix
                if (!match)
                    if (rtmp_rules[index].number[0] == '*')
                        if (callerlen >= (numberlen - 1))
                            if (!strcmp(caller + (callerlen - numberlen) + 1,
                                    rtmp_rules[index].number + 1))
                            {
                                match = 1;
                            }

                // Sufix
                if (!match)
                    if (rtmp_rules[index].number[numberlen - 1] == '*')
                        if (callerlen >= (numberlen - 1))
                            if (!strncmp(caller, rtmp_rules[index].number, numberlen - 1))
                            {
                                match = 1;
                            }

                // Asterisk Dialplan pattern
                if (!match)
                    if (rtmp_rules[index].number[0] == '_')
                        if (ast_extension_match(rtmp_rules[index].number, caller))
                        {
                            match = 1;
                        }

                // Remote number
                if (!match)
                    if (rtmp_rules[index].number[0] == '@')
                        if ((called != NULL) && (*called != 0))
                        {
                            if (!strcmp(called, rtmp_rules[index].number))
                            {
                                match = 1;
                            }

                            if (!match)
                                if (rtmp_rules[index].number[1] == '_')
                                    if (ast_extension_match((rtmp_rules[index].number) + 1,
                                            called))
                                    {
                                        match = 1;
                                    }
                        }

                if (match)
                {
                    if (debug)
                        ast_verbose(VERBOSE_PREFIX_2
                                "Rule %s found (account%d, number %s)!\n",
                                rtmp_rules[index].name, index, rtmp_rules[index].number);

                    strcpy(dest, rtmp_rules[index].dest);
                    return 1;
                }
            }
        }

    return 0;
}

/*!
 * \note This funtion calls realtime_user -> reg_source_db -> iax2_poke_user -> find_callno,
 *       so do not call it with a pvt lock held.
 */
static struct rtmp_user *rtmp_find_user(const char *name, int realtime)
{
        struct rtmp_user *user = NULL;
        struct rtmp_user tmp_user;

        ast_copy_string(tmp_user.name, name, sizeof(tmp_user.name));
        user = ao2_find(users, &tmp_user, OBJ_POINTER);

        /* Now go for realtime if applicable */
        if (!user && realtime)
            user = realtime_user(name, NULL);

        return user;
}

static void rtmp_tcptls_client_args_destructor(void *obj)
{
    struct ast_tcptls_session_args *args = obj;

    //ast_log(LOG_ERROR, "rtmp_tcptls_client_args_destructor\n");

    if (args->tls_cfg)
    {
        ast_free(args->tls_cfg->certfile);
        ast_free(args->tls_cfg->cipher);
        ast_free(args->tls_cfg->cafile);
        ast_free(args->tls_cfg->capath);
    }
    ast_free(args->tls_cfg);
    ast_free((char *)args->name);
}

static void rtmp_threadinfo_destructor(void *obj)
{
    struct rtmp_threadinfo *th = obj;

    //ast_log(LOG_ERROR, "rtmp_threadinfo_destructor\n");

    if (th->tcptls_session)
    {
        ao2_t_ref(th->tcptls_session, -1,
                "remove tcptls_session for rtmp_threadinfo object");
        th->tcptls_session = NULL;
    }
}

/*! \brief creates a rtmp_threadinfo object and links it into the threadt table. */
static struct rtmp_threadinfo *rtmp_threadinfo_create(struct
        ast_tcptls_session_instance *tcptls_session)
{
        struct rtmp_threadinfo *th;

        if (!tcptls_session ||
                !(th = ao2_t_alloc(sizeof(*th), rtmp_threadinfo_destructor, "Alloc thread info")))
        {
            return NULL;
        }

        th->tcptls_session = tcptls_session;
        th->client = NULL;

        ao2_t_link(threadt, th, "Adding new tcptls helper thread");
        return th;
}


#if 1 // TODO JYG merge ??
static void session_instance_destructor(void *obj)
{
#if ASTERISK_VERSION_NUM < AST_11
    struct ast_tcptls_session_instance *i = obj;
    ast_mutex_destroy(&i->lock);
#endif
}


#ifdef DO_SSL
static HOOK_T ssl_read(void *cookie, char *buf, LEN_T len)
{
    int i = SSL_read(cookie, buf, len - 1);
#if 0
    if (i >= 0)
        buf[i] = '\0';
    ast_verb(0, "ssl read size %d returns %d <%s>\n", (int)len, i, buf);
#endif
    return i;
}

static HOOK_T ssl_write(void *cookie, const char *buf, LEN_T len)
{
#if 0
    char *s = alloca(len + 1);
    strncpy(s, buf, len);
    s[len] = '\0';
    ast_verb(0, "ssl write size %d <%s>\n", (int)len, s);
#endif
    return SSL_write(cookie, buf, len);
}

static int ssl_close(void *cookie)
{
    close(SSL_get_fd(cookie));
    SSL_shutdown(cookie);
    SSL_free(cookie);
    return 0;
}
#endif                          /* DO_SSL */

/*! \brief
 * creates a FILE * from the fd passed by the accept thread.
 * This operation is potentially expensive (certificate verification),
 * so we do it in the child thread context.
 *
 * \note must decrement ref count before returning NULL on error
 */
static void *handle_tcptls_connection(void *data)
{
    struct ast_tcptls_session_instance *tcptls_session = data;
#ifdef DO_SSL
    int (*ssl_setup) (SSL *) =
            (tcptls_session->client) ? SSL_connect : SSL_accept;
    int ret;
    char err[256];
#endif

    /*
     * open a FILE * as appropriate.
     */
    if (!tcptls_session->parent->tls_cfg)
    {
        if ((tcptls_session->f = fdopen(tcptls_session->fd, "w+")))
        {
            if (setvbuf(tcptls_session->f, NULL, _IONBF, 0))
            {
                fclose(tcptls_session->f);
                tcptls_session->f = NULL;
            }
        }
    }
#ifdef DO_SSL
    else if ((tcptls_session->ssl =
            SSL_new(tcptls_session->parent->tls_cfg->ssl_ctx)))
    {
        SSL_set_fd(tcptls_session->ssl, tcptls_session->fd);
        if ((ret = ssl_setup(tcptls_session->ssl)) <= 0)
        {
            ast_verb(2, "Problem setting up ssl connection: %s\n",
                    ERR_error_string(ERR_get_error(), err));
        }
        else
        {
#if defined(HAVE_FUNOPEN)       /* the BSD interface */
            tcptls_session->f =
                    funopen(tcptls_session->ssl, ssl_read, ssl_write, NULL, ssl_close);

#elif defined(HAVE_FOPENCOOKIE) /* the glibc/linux interface */
            static const cookie_io_functions_t cookie_funcs = {
                    ssl_read, ssl_write, NULL, ssl_close
            };
            tcptls_session->f = fopencookie(tcptls_session->ssl, "w+", cookie_funcs);
#else
            /* could add other methods here */
            ast_debug(2, "no tcptls_session->f methods attempted!");
#endif
            if ((tcptls_session->client &&
                    !ast_test_flag(&tcptls_session->parent->tls_cfg->flags,
                            AST_SSL_DONT_VERIFY_SERVER)) ||
                            (!tcptls_session->client && ast_test_flag(&tcptls_session->parent->tls_cfg->flags,
                                    AST_SSL_VERIFY_CLIENT)))
            {
                X509 *peer;
                long res;
                peer = SSL_get_peer_certificate(tcptls_session->ssl);
                if (!peer)
                    ast_log(LOG_WARNING, "No peer SSL certificate\n");
                res = SSL_get_verify_result(tcptls_session->ssl);
                if (res != X509_V_OK)
                    ast_log(LOG_ERROR, "Certificate did not verify: %s\n",
                            X509_verify_cert_error_string(res));
                if (!ast_test_flag(&tcptls_session->parent->tls_cfg->flags,
                        AST_SSL_IGNORE_COMMON_NAME))
                {
                    ASN1_STRING *str;
                    unsigned char *str2;
                    X509_NAME *name = X509_get_subject_name(peer);
                    int pos = (-1);
                    int found = 0;

                    for (;;)
                    {
                        /* Walk the certificate to check all available "Common Name" */
                        /* XXX Probably should do a gethostbyname on the hostname and compare that as well */
                        pos = X509_NAME_get_index_by_NID(name, NID_commonName, pos);
                        if (pos < 0)
                            break;
                        str = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, pos));
                        ASN1_STRING_to_UTF8(&str2, str);
                        if (str2)
                        {
                            if (!strcasecmp(tcptls_session->parent->hostname, (char *)str2))
                                found = 1;
                            ast_debug(3, "SSL Common Name compare s1='%s' s2='%s'\n",
                                    tcptls_session->parent->hostname, str2);
                            OPENSSL_free(str2);
                        }
                        if (found)
                            break;
                    }
                    if (!found)
                    {
                        ast_log(LOG_ERROR, "Certificate common name did not match (%s)\n",
                                tcptls_session->parent->hostname);
                        if (peer)
                            X509_free(peer);
                        close(tcptls_session->fd);
                        fclose(tcptls_session->f);
                        ao2_ref(tcptls_session, -1);
                        return NULL;
                    }
                }
                if (peer)
                    X509_free(peer);
            }
        }
        if (!tcptls_session->f)     /* no success opening descriptor stacking */
            SSL_free(tcptls_session->ssl);
    }
#endif                          /* DO_SSL */

    if (!tcptls_session->f)
    {
        close(tcptls_session->fd);
        ast_log(LOG_WARNING, "FILE * open failed!\n");
#ifndef DO_SSL
        if (tcptls_session->parent->tls_cfg)
        {
            ast_log(LOG_WARNING,
                    "Attempted a TLS connection without OpenSSL support.  This will not work!\n");
        }
#endif
        ao2_ref(tcptls_session, -1);
        return NULL;
    }

    if (tcptls_session && tcptls_session->parent->worker_fn)
        return tcptls_session->parent->worker_fn(tcptls_session);
    else
        return tcptls_session;
}


/*! \brief RTMP TCP connection handler */
static void *rtmp_tcp_server_root(void *data)
{
    struct ast_tcptls_session_args *desc = data;
    int fd;
    struct sockaddr_in sin;
    socklen_t sinlen;
    struct ast_tcptls_session_instance *tcptls_session;
    pthread_t launched;
    //int flags;


    for (;;)
    {
        int i, flags;

        if (desc->periodic_fn)
            desc->periodic_fn(desc);
        i = ast_wait_for_input(desc->accept_fd, desc->poll_timeout);
        if (i <= 0)
            continue;
        sinlen = sizeof(sin);
        fd = accept(desc->accept_fd, (struct sockaddr *)&sin, &sinlen);
        if (fd < 0)
        {
            if ((errno != EAGAIN) && (errno != EINTR))
                ast_log(LOG_WARNING, "Accept failed: %s\n", strerror(errno));
            continue;
        }
#ifdef _SEND_TCP_NONBLOCK_
        //fd = accept4(desc->accept_fd, (struct sockaddr *)&sin, &sinlen, SOCK_NONBLOCK);
        fcntl(desc->accept_fd, F_SETFL, O_NONBLOCK);
#endif

        tcptls_session =
                ao2_alloc(sizeof(*tcptls_session), session_instance_destructor);
        if (!tcptls_session)
        {
            ast_log(LOG_WARNING, "No memory for new session: %s\n", strerror(errno));
            close(fd);
            continue;
        }

        #if ASTERISK_VERSION_NUM < AST_11
        ast_mutex_init(&tcptls_session->lock);
        #endif

        flags = fcntl(fd, F_GETFL);
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        tcptls_session->fd = fd;
        tcptls_session->parent = desc;
        memcpy(&tcptls_session->remote_address, &sin,
                sizeof(tcptls_session->remote_address));

        tcptls_session->client = 0;

        /* This thread is now the only place that controls the single ref to tcptls_session */
        if (ast_pthread_create_detached_background(&launched, NULL,
                handle_tcptls_connection, tcptls_session))
        {
            ast_log(LOG_WARNING, "Unable to launch helper thread: %s\n",
                    strerror(errno));
            close(tcptls_session->fd);
            ao2_ref(tcptls_session, -1);
        }
    }
    return NULL;
}
#endif


/*! \brief RTMP TCP connection handler */
static void *rtmp_tcp_worker_fn(void *data)
{
    struct ast_tcptls_session_instance *tcptls_session = data;

    return _rtmp_tcp_helper_thread(NULL, tcptls_session);
}

/*! \brief RTMP TCP thread management function */
static void *_rtmp_tcp_helper_thread(struct rtmp_pvt *pvt,
        struct ast_tcptls_session_instance *tcptls_session)
{
    //int flags;
    struct rtmp_threadinfo *me = NULL;

    if (debug)
        ast_debug(2, "Starting thread\n");


    {
        if (!(me = rtmp_threadinfo_create(tcptls_session)))
        {
            goto cleanup;
        }
    }

    me->tcptls_session = tcptls_session;
    me->threadid = pthread_self();

    //flags = 1;

    if (debug)
        ast_debug(2, "Starting thread id %ld server\n", me->threadid);
    if (debug && me->tcptls_session != NULL && me->tcptls_session->parent != NULL && me->tcptls_session->parent->name != NULL)
        ast_debug(2, "    server '%s'\n", me->tcptls_session->parent->name);

    if (debug)
        ast_debug(2, "Starting thread server process\n");

    rtmp_server_process(me);

    if (debug)
        ast_debug(2, "Shutting down thread server\n");

    cleanup:

    if (tcptls_session)
    {
        TCPTLS_LOCK(tcptls_session);

        if (tcptls_session->f)
        {
            if (debug)
                ast_debug(2, "Stop thread fclose %p\n", tcptls_session->f);
            //fclose(tcptls_session->f);
            tcptls_session->f = NULL;
        }
        if (tcptls_session->fd != (-1))
        {
            if (debug)
                ast_debug(2, "Stop thread close %d\n", tcptls_session->fd);
            //close(tcptls_session->fd);
            tcptls_session->fd = (-1);
        }
        tcptls_session->parent = NULL;

        TCPTLS_UNLOCK(tcptls_session);

        ao2_ref(tcptls_session, -1);
        tcptls_session = NULL;
        me->tcptls_session = NULL;
    }

    I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
    ast_mutex_lock(&rtmplock);
    I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n")

    if (me)
    {
        ao2_t_unlink(threadt, me,
                "Removing tcptls helper thread, thread is closing");
        ao2_t_ref(me, -1, "Removing tcp_helper_threads threadinfo ref");
    }

    ast_mutex_unlock(&rtmplock);
    I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");

    if (debug)
        ast_debug(2, "end of thread server\n");

    return NULL;
}

static int socket_read(int *id, int fd, short events, void *cbdata);

static void *network_thread(void *ignore)
{
    for (;;)
    {
        pthread_testcancel();

        socket_read(NULL, rtmpudpsock, 0, NULL);
    }
    return NULL;
}

/* Function to clean up process thread if it is cancelled */
static void rtmfp_process_thread_cleanup(void *data)
{
    struct rtmfp_thread *thread = data;
    ast_mutex_destroy(&thread->lock);
    ast_cond_destroy(&thread->cond);
    ast_mutex_destroy(&thread->init_lock);
    ast_cond_destroy(&thread->init_cond);
    ast_free(thread);
    //ast_atomic_dec_and_test(&iaxactivethreadcount);
}

/*
 * JYG Monitor Thread
 * Check if RTMP connection are still alive
 */
#ifdef _CHECK_CNX_RTMP_
static void *monitor_process_thread(void *data)
{
    ast_debug(6, "MonitorClient: starting check");

    for (;;)
    {
        struct rtmp_threadinfo *th;
        struct ao2_iterator i;
        struct timeval now;

        // on s'endort un peu avec select
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        select(0, NULL, NULL, NULL, &timeout);

        // Parse all RTMP connection
        I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
        ast_mutex_lock(&rtmplock);
        I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n");

        i = ao2_iterator_init(threadt, 0);
        while ((th =
                ao2_t_iterator_next(&i,
                        "iterate through tcp threads for 'monitor_rtmp'")))
        {
            if (th->client)
            {
                ast_debug(6, "MonitorClient: Check connection client RTMP/0x%X '%s'\n",
                        th->client->name);
                now = ast_tvnow();
                if (th->client->wdog_startCheck)
                {
                    if (th->client->wdog_isalive == th->client->wdog_prev_isalive)
                    {
                        int res = ast_tvdiff_ms(now, th->client->wdog_lastModifTime);
                        if (res > 15000)    // WATCH_TIMEOUT 15 s
                        {
                            ast_log(LOG_WARNING,
                                    "MonitorClient: MonitorClient: Connection is lock RTMP/0x%X\n",
                                    th->client);
                            if (th->client->fd != -1)
                            {
                                ast_log(LOG_WARNING,
                                        "MonitorClient: Close connection RTMP/0x%X\n", th->client);
                                //close(th->client->fd);
                            }
                        }
                    }
                    else
                    {
                        th->client->wdog_startCheck = 0;
                        th->client->wdog_lastModifTime = now;
                        th->client->wdog_prev_isalive = th->client->wdog_isalive;
                        ast_debug(2,
                                "MonitorClient: Connection release check for client RTMP/0x%X\n",
                                th->client);
                    }
                }
                else
                {
                    if (th->client->wdog_isalive == th->client->wdog_prev_isalive)
                    {
                        th->client->wdog_lastModifTime = now;
                        th->client->wdog_startCheck = 1;
                        ast_debug(2,
                                "MonitorClient: Connection seams to be lock for client RTMP/0x%X\n",
                                th->client);
                    }
                    else
                    {
                        th->client->wdog_lastModifTime = now;
                        th->client->wdog_prev_isalive = th->client->wdog_isalive;
                    }
                }
            }
        }
        ao2_iterator_destroy(&i);

        ast_mutex_unlock(&rtmplock);
        I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
    }
}
#endif


static void *rtmfp_process_thread(void *data)
{
    struct rtmfp_thread *thread = data;
    struct timeval wait;
    struct timespec ts;
    int first_time = 1;
    int old_state;

    //ast_atomic_fetchadd_int(&iaxactivethreadcount, 1);

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state);
    pthread_cleanup_push(rtmfp_process_thread_cleanup, data);

    for (;;)
    {
        /* Wait for something to signal us to be awake */
        I6DEBUG(10, NULL, "Mutex lock 'thread'.\n");
        ast_mutex_lock(&thread->lock);
        I6DEBUG(10, NULL, "Mutex locked 'thread'.\n");

        if (thread->stop)
        {
            I6DEBUG(10, NULL, "Mutex unlock 'thread'.\n");
            ast_mutex_unlock(&thread->lock);
            break;
        }

        /* Flag that we're ready to accept signals */
        if (first_time)
        {
            signal_condition(&thread->init_lock, &thread->init_cond);
            first_time = 0;
        }

        if (1)
        {
            /* Wait to be signalled or time out */
            wait = ast_tvadd(ast_tvnow(), ast_samp2tv(30000, 1000));
            ts.tv_sec = wait.tv_sec;
            ts.tv_nsec = wait.tv_usec * 1000;
            if (ast_cond_timedwait(&thread->cond, &thread->lock, &ts) == ETIMEDOUT)
            {
                /* This thread was never put back into the available dynamic
                 * thread list, so just go away. */
                if (thread->stop)
                {
                    I6DEBUG(10, NULL, "Mutex unlock 'thread'.\n");
                    ast_mutex_unlock(&thread->lock);
                    break;
                }

                ast_log(LOG_WARNING, "Thread timeout 1\n");

                /* Someone grabbed our thread *right* after we timed out.
                 * Wait for them to set us up with something to do and signal
                 * us to continue. */
                wait = ast_tvadd(ast_tvnow(), ast_samp2tv(30000, 1000));
                ts.tv_sec = wait.tv_sec;
                ts.tv_nsec = wait.tv_usec * 1000;
                if (ast_cond_timedwait(&thread->cond, &thread->lock, &ts) == ETIMEDOUT)
                {
                    ast_log(LOG_WARNING, "Thread timeout 1\n");

                    I6DEBUG(10, NULL, "Mutex unlock 'thread'.\n");
                    ast_mutex_unlock(&thread->lock);
                    break;

                }
            }
        }
        else
        {
            ast_cond_wait(&thread->cond, &thread->lock);
        }

        I6DEBUG(10, NULL, "Mutex unlock 'thread'.\n");
        ast_mutex_unlock(&thread->lock);

        if (thread->stop)
        {
            break;
        }

        time(&thread->checktime);
    }

    pthread_cleanup_pop(1);

    return NULL;
}

static int socket_read(int *id, int fd, short events, void *cbdata)
{
    struct rtmfp_thread *thread = NULL;

    socklen_t len;
    int buf_len;

    struct sockaddr_in iosin;
    unsigned char readbuf[4096];
    unsigned char *buffer = NULL;

    ast_log(LOG_WARNING, "Start READ frame\n");

    len = sizeof(iosin);
    buf_len =
            recvfrom(fd, &readbuf, sizeof(readbuf), 0, (struct sockaddr *)&iosin, &len);

    ast_log(LOG_WARNING, "READ frame\n");

    if (buf_len < 0)
    {
        if (errno != ECONNREFUSED && errno != EAGAIN)
            ast_log(LOG_WARNING, "Error: %s\n", strerror(errno));
        //handle_error();
        return 1;
    }

    if (test_losspct &&
            ((100.0 * ast_random() / (RAND_MAX + 1.0)) < test_losspct))
    {                             /* simulate random loss condition */
        return 1;
    }

    AST_LIST_LOCK(&rtmfp_list);
    AST_LIST_TRAVERSE(&rtmfp_list, thread, list)
    {
        if (!inaddrcmp(&thread->ffinfo.sin, &iosin))
            break;
    }

    if (!thread)
    {
        /* If we can't create a new dynamic thread for any reason, return no thread at all */
        if (rtmfp_thread_count >= rtmfp_max_thread_count ||
                !(thread = ast_calloc(1, sizeof(*thread))))
        {
            AST_LIST_UNLOCK(&rtmfp_list);
            return 0;
        }

        /* Set default values */
        ast_atomic_fetchadd_int(&rtmfp_thread_count, 1);
        //thread->threadnum = ast_atomic_fetchadd_int(&iaxdynamicthreadnum, 1);

        /* Initialize lock and condition */
        ast_mutex_init(&thread->lock);
        ast_cond_init(&thread->cond, NULL);
        ast_mutex_init(&thread->init_lock);
        ast_cond_init(&thread->init_cond, NULL);
        ast_mutex_lock(&thread->init_lock);

        /* Create thread and send it on it's way */
        if (ast_pthread_create_background(&thread->threadid, NULL,
                rtmfp_process_thread, thread))
        {
            ast_cond_destroy(&thread->cond);
            ast_mutex_destroy(&thread->lock);
            ast_mutex_unlock(&thread->init_lock);
            ast_cond_destroy(&thread->init_cond);
            ast_mutex_destroy(&thread->init_lock);
            ast_free(thread);

            AST_LIST_UNLOCK(&rtmfp_list);
            return 0;
        }

        /* this thread is not processing a full frame (since it is idle),
       so ensure that the field for the full frame call number is empty */
        memset(&thread->ffinfo, 0, sizeof(thread->ffinfo));

        /* Wait for the thread to be ready before returning it to the caller */
        ast_cond_wait(&thread->init_cond, &thread->init_lock);

        /* Done with init_lock */
        ast_mutex_unlock(&thread->init_lock);

        /* this thread is going to process this frame, so mark it */
        memcpy(&thread->ffinfo.sin, &iosin, len);
        //thread->ffinfo.type = fh->type;
        //thread->ffinfo.csub = fh->csub;
        AST_LIST_INSERT_HEAD(&rtmfp_list, thread, list);
    }

    AST_LIST_UNLOCK(&rtmfp_list);

    if (!(buffer = ast_calloc(1, buf_len)))
    {
        return 0;
    }

    ast_mutex_lock(&thread->lock);

    AST_LIST_INSERT_TAIL(&thread->full_frames, (void *)buffer, entry);

    ast_mutex_unlock(&thread->lock);

    signal_condition(&thread->lock, &thread->cond);

    return 1;
}


/*!
 * \note Use the stream id
 */
static int connections_hash_cb(const void *obj, const int flags)
{
    const struct rtmp_pvt *pvt = obj;

    if (debug)
    {
        if (pvt->client)
        {
            I6DEBUG(7, pvt->client, "pvt->streamid = %d\n", pvt->streamid);
        }
        else
            ast_debug(7, "pvt->streamid = %d\n", pvt->streamid);
    }
    return pvt->streamid;
}

/*!
 * \note Use the stream id
 */
static int connections_cmp_cb(void *obj, void *arg, int flags)
{
    int res = 0;
    struct rtmp_pvt *pvt = obj, *pvt2 = arg;

    if (debug)
    {
        if (pvt->client)
        {
            I6DEBUG(7, pvt->client,
                    "pvt->streamid = %d - pvt2->streamid = %d - pvt->numstreams = %d\n",
                    pvt->streamid, pvt2->streamid, pvt->numstreams);
        }
        else
            ast_debug(7,
                    "pvt->streamid = %d - pvt2->streamid = %d - pvt->numstreams = %d\n",
                    pvt->streamid, pvt2->streamid, pvt->numstreams);
    }
    /* match if streamid <= id < streamid + range */
    if (pvt2->streamid >= pvt->streamid &&
            pvt2->streamid < pvt->streamid + pvt->numstreams)
    {
        res = CMP_MATCH | CMP_STOP;
    }

    return res;
}

/*!
 * \note Use the channel id
 */
static int rtmpmessages_hash_cb(const void *obj, const int flags)
{
    const struct rtmp_message *pvt = obj;

    if (debug)
        ast_debug(10, "pvt->channelid = %d\n", pvt->channelid);
    return pvt->channelid;
}

/*!
 * \note Use the stream id
 */
static int rtmpmessages_cmp_cb(void *obj, void *arg, int flags)
{
    int res = 0;
    struct rtmp_message *pvt = obj, *pvt2 = arg;

    if (pvt && pvt2)
        if (pvt2->channelid == pvt->channelid)
        {
            res = CMP_MATCH | CMP_STOP;
        }

    return res;
}


static int rtmp_sched(const void *data)
{
    struct rtmp_pvt *p = (void *)data;
    struct rtmp_client *client = NULL;

    uint8_t pipetype;
    uint8_t buf[2000];
    uint32_t length;
    int res;

    int wait_read;
    struct timeval tv;

    if (p)
        client = p->client;

    tv = ast_tvnow();
    wait_read = ast_tvdiff_ms(tv, p->tv);

    I6DEBUG(8, client, "Wait read = %d.\n", wait_read);

    if (p->schedid == (-1))
    {
        return 0;
    }

    do
    {
        ioctl(p->pipe[0], FIONREAD, &length);
        if (length == 0)
        {
            return 1;
        }

        // Get the type
        res = read(p->pipe[0], (void *)&pipetype, 1);
        if (res == (-1))
        {
            return 0;
        }

        //ast_log(LOG_WARNING, "RTMP SCHED TYPE %d\n", pipetype);

        switch (pipetype)
        {
            case RTMP_PIPE_NULL:
                I6DEBUG(8, client, "Pipe NULL received.\n");
                res = write(p->pipe2[1], (void *)&pipetype, 1);
                break;
            case RTMP_PIPE_MARK:
                I6DEBUG(8, client, "Pipe MARK received.\n");
                //write(p->pipe2[1], (void*)&pipetype, 1);
                break;
            case RTMP_PIPE_AUDIO_NELLYMOSER:
            case RTMP_PIPE_AUDIO_SPEEX:
            case RTMP_PIPE_AUDIO_SLINEAR:
            case RTMP_PIPE_AUDIO_ULAW:
            case RTMP_PIPE_AUDIO_ALAW:
            case RTMP_PIPE_VIDEO_SORENSON:
            case RTMP_PIPE_VIDEO_SORENSON_MARK:
            case RTMP_PIPE_TEXT:
                I6DEBUG(8, client, "Pipe MEDIA received.\n");
                res = write(p->pipe2[1], (void *)&pipetype, 1);

                res = read(p->pipe[0], (void *)&length, 4);
                if (res != 4)
                {
                    ast_log(LOG_ERROR, "Failed to read audio length frame %d.\n", res);
                    return 0;
                }
                if (length > 2000)
                {
                    ast_log(LOG_ERROR, "Failed to read audio length=%d.\n", length);
                    return 0;
                }

                res = write(p->pipe2[1], (void *)&length, 4);

                res = read(p->pipe[0], buf, length);

                if (res != length)
                {
                    ast_log(LOG_ERROR, "Failed to read audio frame.\n");
                    return 0;
                }

                res = write(p->pipe2[1], buf, length);

                break;
            case RTMP_PIPE_DTMF:
                I6DEBUG(8, client, "Pipe DTMF received.\n");

                res = write(p->pipe2[1], (void *)&pipetype, 1);

                res = read(p->pipe[0], buf, 1);
                res = write(p->pipe2[1], buf, 1);
                break;
            case RTMP_PIPE_EVENT:
                I6DEBUG(8, client, "Pipe EVENT received.\n");

                res = write(p->pipe2[1], (void *)&pipetype, 1);

                res = read(p->pipe[0], buf, 1);
                res = write(p->pipe2[1], buf, 1);
                break;
            default:
                break;
        }
    }
    while (pipetype != RTMP_PIPE_MARK);


    return 1;
}

#if ASTERISK_VERSION_NUM < AST_11
static int rtmp_call(struct ast_channel *ast, char *dest, int timeout)
#else
static int rtmp_call(struct ast_channel *ast, const char *dest, int timeout)
#endif
{
    char buf[RTMPBUFSIZE];
    struct rtmp_pvt *p;
    int res = (-1);
    struct rtmp_client *client = NULL;

    if ((GET_CHAN_STATE(ast) != AST_STATE_DOWN) &&
            (GET_CHAN_STATE(ast) != AST_STATE_RESERVED))
    {
        ast_log(LOG_WARNING, "Channel is already in use (%s)?\n",
                GET_CHAN_NAME(ast));
        return -1;
    }

    p = GET_CHAN_TECH_PVT(ast);

    if (p)
        client = p->client;

    if (debug)
        I6LOG(LOG_DEBUG, client, "rtmp_call set format %s (native format %s)\n",
                GET_FORMAT_NAME(client->audiocodec), ast_getformatname_multiple(buf,
                        RTMPBUFSIZE, GET_CHAN_NATIVEFORMATS(ast)));

    SET_CHAN_READFORMAT(ast, client->audiocodec);
    SET_CHAN_WRITEFORMAT(ast, client->audiocodec);

    if (!p)
    {
        if (debug)
            I6DEBUG(3, client, "tech_pvt is NULL\n");
    }
    else
    {
        if (debug)
            I6DEBUG(3, client, "p->owner->name : \%s\n", GET_CHAN_NAME(p->owner));
    }

    if ((GET_CHAN_STATE(ast) != AST_STATE_DOWN) &&
            (GET_CHAN_STATE(ast) != AST_STATE_RESERVED))
    {
        I6LOG(LOG_WARNING, client, "rtmp_call called on %s, neither down nor reserved\n", GET_CHAN_NAME(ast));
        return -1;
    }


    /* When we call, it just works, really, there's no destination...  Just
     ring the phone and wait for someone to answer */
    if (debug)
        I6DEBUG(3, client, "Calling %s on %s\n", dest, GET_CHAN_CALLERID_NUMBER(ast));


    //res = rtmp_send_invited(client, "asterisk");
    if (client->autoanswer == 2)
    {
        RTMP_VERBOSE(client, "<* message/spyed(%s)\n", GET_CHAN_CALLERID_NUMBER(ast));
        if (GET_CHAN_CALLERID_NUMBER(ast))
            res = rtmp_send_spyed(client, GET_CHAN_CALLERID_NUMBER(ast));
        else
            res = rtmp_send_spyed(client, "");
    }
    else if (client->autoanswer == 1)
    {
        RTMP_VERBOSE(client, "<* message/autoanswer(%s)\n", GET_CHAN_CALLERID_NUMBER(ast));
        if (GET_CHAN_CALLERID_NUMBER(ast))
            res = rtmp_send_autoanswer(client, GET_CHAN_CALLERID_NUMBER(ast));
        else
            res = rtmp_send_autoanswer(client, "");
    }
    else
    {
        RTMP_VERBOSE(client, "<* message/invited(%s)\n", GET_CHAN_CALLERID_NUMBER(ast));
        if (GET_CHAN_CALLERID_NUMBER(ast))
            res = rtmp_send_invited(client, GET_CHAN_CALLERID_NUMBER(ast));
        else
            res = rtmp_send_invited(client, "");

        ast_indicate(ast, AST_CONTROL_ANSWER);
        ast_setstate(ast, AST_STATE_RING);
    }

    res = res;

    return 0;
}

static void rtmp_destroy_fn(void *p)
{
    rtmp_destroy(p);
}

static void rtmp_destroy(struct rtmp_pvt *p)
{
    I6DEBUG(3, NULL, "Destroy PVT context.\n");

    if (p->schedid != (-1))
    {
        DELETE_SCHED(sched, p->schedid);
        p->schedid = (-1);
    }

    I6DEBUG(3, NULL, "Close the PIPEs.\n");

    close(p->pipe[0]);
    p->pipe[0] = (-1);
    close(p->pipe[1]);
    p->pipe[1] = (-1);

    if (p->pipe2[0] != (-1))
    {
        close(p->pipe2[0]);
        p->pipe2[0] = (-1);
        close(p->pipe2[1]);
        p->pipe2[1] = (-1);
    }

#ifdef RTMP_FFMPEG
    if (p->encoding_context)
    {
        avcodec_close(p->encoding_context);
    }

    if (p->decoding_context)
    {
        avcodec_close(p->decoding_context);
    }

    if (p->tortmp_resample_context)
    {
        audio_resample_close(p->tortmp_resample_context);
    }
    if (p->fromrtmp_resample_context)
    {
        audio_resample_close(p->fromrtmp_resample_context);
    }
#endif
}

static void rtmpmessage_destroy_fn(void *p)
{
    rtmpmessage_destroy(p);
}

static void rtmpmessage_destroy(struct rtmp_message *rtmp)
{
    ast_free(rtmp->body);
}

/** \brief Allocate a new RTMP stream
 * A new RTMP stream consists of 5 RTMP channels
 */
static struct rtmp_pvt *rtmp_alloc(char *writestream, char *readstream,
        char *readnum)
{
        struct rtmp_pvt *p;
        int rnum = 0;

        if (!readnum)
        {
            rnum = 1;
        }
        else
        {
            rnum = atoi(readnum);
        }

        if (!(p = ao2_t_alloc(sizeof(*p), rtmp_destroy_fn, "allocate an pvt struct")))
            return NULL;

        p->numstreams = 1 + rnum;
        p->readstream_index = 0;
#ifdef RTMP_FFMPEG
        p->encoder = NULL;
        p->decoder = NULL;
        p->encoding_context = NULL;
        p->decoding_context = NULL;
#endif
        p->rtmpinputrate = 11000;
        p->astinputrate = 8000;
        p->client = NULL;

        p->mode = 0;

        p->last = 0;
        p->duration = 0;
        p->samples = 0;

        if (antiburst)
            p->schedid = AST_SCHED_ADD(sched, 20, rtmp_sched, p);
        else
            p->schedid = (-1);


        /* the outputrate value of this context matches with the sampling
         * rate of the RTMP packets that come in to Asterisk. On the other
         * hand, the inputrate value of this context matches with the
         * sampling rate of the packets that come in to Asterisk from the
         * opposite Asterisk channel (eg : RTP packets).
         * Other values are taken from the examples given in FFMPEG.
         * The function prototype is :
         * ReSampleContext *av_audio_resample_init(int output_channels, int input_channels,
         *                                 int output_rate, int input_rate,
         *                         enum SampleFormat sample_fmt_out,
         *                                     enum SampleFormat sample_fmt_in,
         *                                     int filter_length, int log2_phase_count,
         *                                     int linear, double cutoff)
         */
        /*
     p->tortmp_resample_context = av_audio_resample_init(
     1, 1,
     p->rtmpinputrate, p->astinputrate,
     SAMPLE_FMT_S16, SAMPLE_FMT_S16,
     16, 10, 1, 0.8);
     p->fromrtmp_resample_context = av_audio_resample_init(
     1, 1,
     p->astinputrate, p->rtmpinputrate,
     SAMPLE_FMT_S16, SAMPLE_FMT_S16,
     16, 10, 1, 0.8);
         */

#ifdef RTMP_FFMPEG
        p->tortmp_resample_context = NULL;
        p->fromrtmp_resample_context = NULL;
#endif

        strncpy(p->readstream, readstream, AST_MAX_EXTENSION);
        strncpy(p->writestream, writestream, AST_MAX_EXTENSION);

        /* add to active RTMP streams list */

        I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
        ast_mutex_lock(&rtmplock);
        I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n");

        ao2_t_link(connections, p, "link pvt into RTMP streams table");

        I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
        ast_mutex_unlock(&rtmplock);

        return p;
}

static int rtmp_hangup(struct ast_channel *ast)
{
    struct rtmp_pvt *p = GET_CHAN_TECH_PVT(ast);
    struct rtmp_client *client = NULL;
    int res = 0;

    //I6LOG(LOG_NOTICE, client, "RTMP Hangup %s.\n", GET_CHAN_NAME(ast));

    if (!p)
    {
        I6LOG(LOG_WARNING, client, "Asked to hangup channel %s not connected.\n", GET_CHAN_NAME(ast));
        return 0;
    }

    client = p->client;

    if (client == NULL)
    {
        I6LOG(LOG_WARNING, client, "Channel %s must have a client.\n", GET_CHAN_NAME(ast));
        return 0;
    }

    ast_mutex_lock(&client->lock);

    I6DEBUG(3, client, "rtmp_hangup(%s)\n", GET_CHAN_NAME(ast));

#ifdef RTMP_FFMPEG
    if (client->in_flv.fd)
    {
        I6DEBUG(3, client, "Close FLV incoming file\n");
        FLV_close(&client->in_flv, ast_tvdiff_ms(ast_tvnow(), client->timestart),
                client->pictureIn_width, client->pictureIn_heigth);
    }
    if (client->out_flv.fd)
    {
        I6DEBUG(3, client, "Close FLV outgoing file\n");
        FLV_close(&client->out_flv, ast_tvdiff_ms(ast_tvnow(), client->timestart),
                client->pictureOut_width, client->pictureOut_heigth);
    }
#endif

    if (p->schedid != (-1))
    {
        DELETE_SCHED(sched, p->schedid);
        p->schedid = (-1);
    }

    client->havePictureInSize = 0;
    client->havePictureOutSize = 0;

    time(&client->callstop);
    client->firstaudio = 0;

    {
        if (client->fd != (-1))
        {
            if (GET_CHAN_STATE(ast) == AST_STATE_UP)
            {
                if (!p->mode)
                {
                    RTMP_VERBOSE(client, "<* message/bye()\n");
                    rtmp_send_bye(client);
                }
                else
                {
                    /*
             int i;
             for (i = 0; i < p->numstreams; i++)
             {
             rtmp_send_closestream(p->client, p->streamid + i);
             }
                     */
                }
            }
            else
            {
                if (!p->mode)
                {
                    if (GET_CHAN_STATE(ast) == AST_STATE_UP)
                    {
                        if (GET_CHAN_CALLERID_NAME(ast))
                        {
                            RTMP_VERBOSE(client, "<* message/cancelled()\n");

                            res = rtmp_send_result_cancelled(client, 0, 2.0, (char *)ast_cause2str(GET_CHAN_HANGUPCAUSE(ast)), GET_CHAN_CALLERID_NAME(ast));
                        }
                        else
                        {
                            RTMP_VERBOSE(client, "<* message/bye()\n");

                            rtmp_send_bye(client);
                        }
                    }
                    else
                    {
                        RTMP_VERBOSE(client, "<* message/cancelled()\n");

                        res = rtmp_send_result_cancelled(client, 0, 2.0, (char *)ast_cause2str(GET_CHAN_HANGUPCAUSE(ast)), GET_CHAN_CALLERID_NAME(ast));
                    }
                }
            }

            client->pvt = NULL;

            if (p->mode)
            {
                if (debug)
                    I6DEBUG(3, client, "Close TCP connection\n");

                if (client->fd != (-1))
                    close(client->fd);
                client->fd = (-1);
            }
        }

        stats[STATS_HANGUPS]++;
    }

    //if (GET_CHAN_STATE(ast) != AST_STATE_DOWN)
    ast_setstate(ast, AST_STATE_DOWN);

    // Do be transfer to the Pvt context
    if (client->outgoing_audiofile)
    {
        fclose(client->outgoing_audiofile);
        client->outgoing_audiofile = NULL;
    }
    if (client->incoming_audiofile)
    {
        fclose(client->incoming_audiofile);
        client->incoming_audiofile = NULL;
    }
    if (client->outgoing_videofile)
    {
        fclose(client->outgoing_videofile);
        client->outgoing_videofile = NULL;
    }
    if (client->incoming_videofile)
    {
        fclose(client->incoming_videofile);
        client->incoming_videofile = NULL;
    }

    // Free PVT context but before
    if (p)
    {
        I6DEBUG(3, client, "Free the PVT context from hangup\n");

        //ast_channel_lock(ast);
        ast_channel_set_fd(ast, 0, -1);
        SET_CHAN_TECH_PVT(ast, NULL);
        //ast_channel_unlock(ast);

        p->client = NULL;
        p->owner = NULL;

        client->pvt = NULL; // This free the client

        ao2_t_unlink(connections, p, "Unlink pvt out to connections table");
        ao2_t_ref(p, -1, "Unref and free rtmp_pvt");
    }

    ast_mutex_unlock(&client->lock);

    I6DEBUG(3, client, "End of hangup hangup\n");

    res = res;

    return 0;
}

static int rtmp_answer(struct ast_channel *ast)
{
    int res = 0;
    struct rtmp_pvt *p = GET_CHAN_TECH_PVT(ast);
    struct rtmp_client *client = NULL;

    I6DEBUG(3, client, "rtmp_answer(%s)\n", GET_CHAN_NAME(ast));

    if (p)
    {
        client = p->client;
        if (!client)
        {
            return -1;
        }
        ast_mutex_lock(&client->lock);
    }
    else
        return -1;

    if (GET_CHAN_STATE(ast) != AST_STATE_UP)
    {
        ast_setstate(ast, AST_STATE_UP);
        if (option_debug)
            I6DEBUG(1, client, "rtmp_answer(%s)\n", GET_CHAN_NAME(ast));

        RTMP_VERBOSE(client, "<* message/accepted\n");

        if (!p->mode)
            res = rtmp_send_result_accepted(client, 0, 2.0, "accepted", NULL);

        res = 0;

        stats[STATS_ANSWERS]++;
    }

    time(&client->callanswer);

    ast_mutex_unlock(&client->lock);

    return res;
}



static struct ast_frame *rtmp_read(struct ast_channel *ast)
{
        struct rtmp_pvt *p = GET_CHAN_TECH_PVT(ast);
        struct rtmp_client *client = p->client;

        int res;
        uint8_t pipetype;
        uint8_t *buf = NULL;
        uint32_t length;

        struct timeval tv;
        struct timeval tv_read;
        int wait = 0;
        int wait_read = 0;

        uint8_t *frameBuffer;
        struct ast_frame *f = NULL;
        int pipe = (-1);

        I6DEBUG(3, client, "rtmp_read(%s)\n", GET_CHAN_NAME(ast));

        if (!p)
            return NULL;

        if (p->pipe2[0] != (-1))
            pipe = p->pipe2[0];
        else
            pipe = p->pipe[0];

        if (pipe == (-1))
        {
            return NULL;
        }

        if (!(frameBuffer = ast_calloc_cache(1, PKT_SIZE)))
        {
            return NULL;
        }

        f = (struct ast_frame *)frameBuffer;
        f->mallocd_hdr_len = PKT_SIZE;

        f->frametype = AST_FRAME_NULL;
        f->src = "RTMP";
        f->mallocd = 1;
        f->delivery.tv_sec = 0;
        f->delivery.tv_usec = 0;
        f->delivery = ast_tv(0, 0);
        f->samples = 0;
        f->datalen = 0;
        f->data.ptr = NULL;

        /* Set frame data */
        AST_FRAME_SET_BUFFER(f, f, PKT_OFFSET, 0);

        tv_read = ast_tvnow();

        if (0)
            if ((rand() % 100) < 5)
            {
                struct timeval tv;
                int usec = 400 * 1000;
                tv.tv_sec = usec / 1000000L;
                tv.tv_usec = usec % 1000000L;

                if (dumptimings)
                    ast_log(LOG_ERROR, "Added TEST wait %dms\n", 400);

                select(0, 0, 0, 0, &tv);
            }



        if (GET_CHAN_FDNO(ast) == 0)
        {
            int size;
            ioctl(pipe, FIONREAD, &size);
            I6DEBUG(10, client, "Datas on PIPE (read) : %d\n", size);

            res = read(pipe, (void *)&pipetype, 1);
        }
        else
        {
            ast_free(frameBuffer);
            return NULL;
        }

        switch (pipetype)
        {
            case RTMP_PIPE_NULL:
                if (debug)
                    I6DEBUG(7, p->client, "Return NULL frame !!! \n");

                ast_free(frameBuffer);
                return NULL;
                break;

            case RTMP_PIPE_AUDIO_NELLYMOSER:
            case RTMP_PIPE_AUDIO_SPEEX:
            case RTMP_PIPE_AUDIO_SLINEAR:
            case RTMP_PIPE_AUDIO_ULAW:
            case RTMP_PIPE_AUDIO_ALAW:
                res = read(pipe, (void *)&length, 4);

                if (res != 4)
                {
                    ast_log(LOG_ERROR, "Failed to read audio length frame from channel %s\n", GET_CHAN_NAME(ast));
                    ast_free(frameBuffer);
                    return NULL;

                }
                if (length > 2000)
                {
                    ast_free(frameBuffer);
                    return NULL;
                }
                buf = ((unsigned char *)((f)->data.ptr));
                if (!buf)
                {
                    ast_free(frameBuffer);
                    return NULL;
                }

                res = read(pipe, buf, length);

                if (res != length)
                {
                    ast_log(LOG_ERROR, "Failed to read audio frame from channel %s\n", GET_CHAN_NAME(ast));
                    ast_free(frameBuffer);
                    return NULL;
                }

                f->frametype = AST_FRAME_VOICE;
                f->datalen = res;

                if (pipetype == RTMP_PIPE_AUDIO_SPEEX)
                {
                    SET_FRAME_SUBCLASS_FORMAT(f, AST_FORMAT_SPEEX);

                    f->samples = speex_samples(f->data.ptr, f->datalen);
                }
                else if (pipetype == RTMP_PIPE_AUDIO_ULAW)
                {
                    SET_FRAME_SUBCLASS_FORMAT(f, AST_FORMAT_ULAW);

                    f->samples = 160;
                }
                else if (pipetype == RTMP_PIPE_AUDIO_ALAW)
                {
                    SET_FRAME_SUBCLASS_FORMAT(f, AST_FORMAT_ALAW);

                    f->samples = 160;
                }
                else
                {
                    SET_FRAME_SUBCLASS_FORMAT(f, AST_FORMAT_SLINEAR);

                    f->samples = 160;
                }

                if (debug)
                    I6DEBUG(2, p->client, "Read %d bytes as an audio frame on %s\n", res, GET_CHAN_NAME(ast));

                tv = ast_tvnow();
                wait_read = ast_tvdiff_ms(tv, tv_read);

                if (debug)
                    I6DEBUG(2, p->client, "Wait read = %d\n", wait_read);

                if (p->samples == 0)
                {
                    p->tv = ast_tvnow();
                }

                p->last = p->duration;
                p->duration = ast_tvdiff_ms(tv, p->tv);
                p->samples += f->samples;

                if ((p->samples / 8) < (p->duration))
                {
                    if (dumptimings)
                        ast_log(LOG_ERROR, "Audio samples < duration : %ld, %ld\n ",
                                p->samples / 8, p->duration);
                    p->samples = ((p->duration / 20) * 160) + 160;
                    if (dumptimings)
                        ast_log(LOG_ERROR, "Audio samples correction delay %ld\n ",
                                p->samples / 8);
                }

                if (antiburst)
                    if ((p->samples / 8) > (p->duration + antiburst))
                    {
                        if (client->burst_max < ((p->samples / 8) - p->duration))
                            client->burst_max = ((p->samples / 8) - p->duration);

                        client->burst_counter++;

                        //p->samples = ((p->duration/20)*160);

                        if (dumptimings)
                            ast_log(LOG_ERROR, "Audio samples > duration : %ld, %ld + %d\n ",
                                    p->samples / 8, p->duration, antiburst);

                        wait = (p->samples / 8) - (p->duration + antiburst);

                        if (debug)
                            I6DEBUG(2, p->client, "Wait = %d\n", wait);
                    }

                if (antiburst)
                {
                    if ((p->samples / 8) > (p->duration + 20))
                    {
                        client->burst_count++;

                        if (client->burst_count > 50)
                        {
                            //p->samples = ((p->duration/20)*160);

                            //if (dumptimings)
                            //ast_log(LOG_ERROR, "Audio samples correction burst %ld\n ", p->samples/8);
                        }

                    }
                    else
                        client->burst_count = 0;
                }


                if (dumptimings)
                    ast_log(LOG_ERROR,
                            "Audio frame : wait read %d : samples %d / samples %ld : %ld, duration %ld, delta %ld\n ",
                            wait_read, f->samples, p->samples, p->samples / 8, p->duration,
                            (p->samples / 8) - p->duration);

                return f;

                break;
            case RTMP_PIPE_VIDEO_SORENSON:
            case RTMP_PIPE_VIDEO_SORENSON_MARK:
                res = read(pipe, (void *)&length, 4);

                if (res != 4)
                {
                    I6LOG(LOG_ERROR, p->client, "Failed to read video length frame from channel %s\n", GET_CHAN_NAME(ast));
                    ast_free(frameBuffer);
                    return NULL;
                }
                if (length > 2000)
                {
                    ast_free(frameBuffer);
                    return NULL;
                }
                buf = AST_FRAME_GET_BUFFER(f);
                if (!buf)
                {
                    ast_free(frameBuffer);
                    return NULL;
                }

                res = read(pipe, buf, length);

                if (res != length)
                {
                    I6LOG(LOG_ERROR, p->client, "Failed to read video frame from channel %s\n", GET_CHAN_NAME(ast));
                    ast_free(frameBuffer);
                    return NULL;
                }

                if (!videosupport)
                {
                    I6LOG(LOG_WARNING, p->client, "Video support disabled, frame skipped from channel %s\n", GET_CHAN_NAME(ast));
                    ast_free(frameBuffer);
                    return NULL;
                }

                f->frametype = AST_FRAME_VIDEO;
                if (pipetype == RTMP_PIPE_VIDEO_SORENSON_MARK)
                {
                    SET_FRAME_SUBCLASS_FORMAT_AND_VIDEOMARK(f, AST_FORMAT_H263);
                }
                else
                {
                    SET_FRAME_SUBCLASS_FORMAT(f, AST_FORMAT_H263);
                }

                f->samples = 0;
                f->datalen = res;

                I6DEBUG(7, p->client, "Read %d bytes as a video frame on %s\n", res, GET_CHAN_NAME(ast));

                if (client->echo)
                {
                    ast_mutex_lock(&client->lock);
                    rtmp_send_video(client, p, f);
                    ast_mutex_unlock(&client->lock);
                }

                return f;
                break;
            case RTMP_PIPE_DTMF:
                buf = AST_FRAME_GET_BUFFER(f);

                res = read(pipe, buf, 1);

                I6DEBUG(7, p->client, "Send DTMF begin %d\n", buf[0]);


                if (res != 1)
                {
                    I6LOG(LOG_ERROR, p->client, "Failed to read text/dtmf frame from channel %s %d\n", GET_CHAN_NAME(ast), res);
                    ast_free(frameBuffer);
                    return NULL;
                }

                if (buf[0] & 0x80)
                {
                    SET_FRAME_SUBCLASS_INTEGER(f, buf[0] & 0x7f);
                    f->frametype = AST_FRAME_DTMF_BEGIN;
                    f->len = 250;

                    //ast_log(LOG_ERROR, "Sent dtmf BEGIN %c !!!\n", f->subclass);
                }
                else
                {
                    SET_FRAME_SUBCLASS_INTEGER(f, buf[0] & 0x7f);
                    f->frametype = AST_FRAME_DTMF_END;
                    f->len = 100;

                    //ast_log(LOG_ERROR, "Sent dtmf END %c !!!\n", f->subclass);
                }

                return f;
                break;
            case RTMP_PIPE_TEXT:
                res = read(pipe, (void *)&length, 4);
                if (res != 4)
                {
                    I6LOG(LOG_ERROR, p->client, "Failed to read text length frame from channel %s\n", GET_CHAN_NAME(ast));
                    ast_free(frameBuffer);
                    return NULL;
                }

                if (length > 255)
                {
                    ast_free(frameBuffer);
                    return NULL;
                }

                buf = AST_FRAME_GET_BUFFER(f);
                if (!buf)
                {
                    ast_free(frameBuffer);
                    return NULL;
                }
                res = read(pipe, buf, length);
                if (res != length)
                {
                    I6LOG(LOG_ERROR, p->client, "Failed to read video frame from channel %s\n", GET_CHAN_NAME(ast));
                    ast_free(frameBuffer);
                    return NULL;
                }

                if (!textsupport)
                {
                    I6LOG(LOG_WARNING, p->client, "Text support disabled, frame skipped from channel %s\n", GET_CHAN_NAME(ast));
                    return NULL;
                }

                f->frametype = AST_FRAME_TEXT;
                FRAME_SUBCLASS_FORMAT_CLEAR(f);
                f->samples = 0;
                buf[res] = 0;
                f->datalen = res + 1;

                if (debug)
                    I6DEBUG(7, p->client, "Read %d bytes as a text frame on %s\n", res, GET_CHAN_NAME(ast));

                return f;
                break;

            case RTMP_PIPE_EVENT:
                buf = AST_FRAME_GET_BUFFER(f);

                res = read(pipe, buf, 1);

                I6DEBUG(7, p->client, "Send EVENT begin %d\n", buf[0]);

                if (res != 1)
                {
                    I6LOG(LOG_ERROR, p->client, "Failed to read event frame from channel %s %d\n", GET_CHAN_NAME(ast), res);
                    ast_free(frameBuffer);
                    return NULL;
                }

                if (buf[0] == 'v')
                {
                    ast_indicate(ast, AST_CONTROL_VIDUPDATE);

                    //ast_log(LOG_ERROR, "Sent event VIDUPDATE %c !!!\n", f->subclass);
                }

                return f;
                break;

            default:
                break;
        }

        ast_free(frameBuffer);

        return NULL;
}


static int rtmp_write(struct ast_channel *ast, struct ast_frame *frame)
{
    struct rtmp_pvt *p = NULL;

    struct rtmp_client *client = NULL;

    int res = (-1);

    I6DEBUG(3, client, "rtmp_write(%s)\n", GET_CHAN_NAME(ast));

    p = GET_CHAN_TECH_PVT(ast);
    if (p)
    {
        client = p->client;
    }

    if (client == NULL)
    {
        ast_log(LOG_WARNING, "Client NULL !\n");
        return -1;
    }

    if (client->fd == (-1))
    {
        I6LOG(LOG_DEBUG, client, "Write with connection closed !\n");
        return -1;
    }

    ast_mutex_lock(&client->lock);

    I6DEBUG(5, client, "rtmp_write( frame->frametype = %d)\n",
            frame->frametype);

    if (frame->frametype == AST_FRAME_CONTROL)
    {
        /* Depending on the event */
        switch (GET_FRAME_CONTROL_TYPE(frame))
        {
            case AST_CONTROL_RINGING:
                break;
            case AST_CONTROL_BUSY:
                RTMP_VERBOSE(client, "<* message/cancelled()\n");

                rtmp_send_result_cancelled(client, 0, 2.0, (char *)ast_cause2str(GET_CHAN_HANGUPCAUSE(ast)), GET_CHAN_CALLERID_NAME(ast));
                break;
            case AST_CONTROL_CONGESTION:
                RTMP_VERBOSE(client, "<* message/cancelled()\n");

                rtmp_send_result_cancelled(client, 0, 2.0, (char *)ast_cause2str(GET_CHAN_HANGUPCAUSE(ast)), GET_CHAN_CALLERID_NAME(ast));
                break;
        }

        ast_mutex_unlock(&client->lock);
        return -1;
    }

    if (frame->frametype != AST_FRAME_VOICE &&
            frame->frametype != AST_FRAME_VIDEO)
    {
        I6LOG(LOG_WARNING, client, "Don't know what to do with  frame type '%d'\n",
                frame->frametype);

        ast_mutex_unlock(&client->lock);

        return 0;
    }

    if (client->playing)
        if (frame->frametype == AST_FRAME_VOICE)
        {
            if (FORMAT_FORCE_TO_OLD_BITFIELD(client->audiocodec) == 0)
            {
                ast_mutex_unlock(&client->lock);

                return 0;
            }

            if (!(COMPARE_VARFORMAT_IDFORMAT(GET_FRAME_SUBCLASS_FORMAT(frame), AST_FORMAT_SLINEAR))
                    && !(COMPARE_VARFORMAT_IDFORMAT(GET_FRAME_SUBCLASS_FORMAT(frame), AST_FORMAT_SPEEX))
                    && !(COMPARE_VARFORMAT_IDFORMAT(GET_FRAME_SUBCLASS_FORMAT(frame), AST_FORMAT_ULAW))
                    && !(COMPARE_VARFORMAT_IDFORMAT(GET_FRAME_SUBCLASS_FORMAT(frame),
                            AST_FORMAT_ALAW)))
            {
                I6LOG(LOG_WARNING, client, "Cannot handle frames in %s format\n", GET_FORMAT_NAME(GET_FRAME_SUBCLASS_FORMAT(frame)));
                {
                    ast_mutex_unlock(&client->lock);

                    return 0;
                }
            }
        }

    if ((client->playing) || (client->playing2))
        if (frame->frametype == AST_FRAME_VIDEO)
        {
            if (!(COMPARE_VARFORMAT_IDFORMAT(GET_FRAME_SUBCLASS_FORMAT(frame),
                    AST_FORMAT_H263)))
            {
                I6LOG(LOG_DEBUG, client, "Cannot handle video frames in %s format\n", GET_FORMAT_NAME(GET_FRAME_SUBCLASS_FORMAT(frame)));

                ast_mutex_unlock(&client->lock);

                return 0;
            }
        }

    if (GET_CHAN_STATE(ast) == AST_STATE_DOWN)
    {
        /* Don't try tos end audio on-hook */
        I6LOG(LOG_DEBUG, client, "Channel is not UP!\n");

        ast_mutex_unlock(&client->lock);

        return 0;
    }

    if (frame->frametype == AST_FRAME_VOICE)
    {
        if ((client->mute == 1) || (client->mute == 3))
        {
            ast_mutex_unlock(&client->lock);

            return 0;
        }

        I6DEBUG(5, client, "Call rtmp_send_audio()\n");

        if ((client->playing) || (client->playing2))
        {
            res = rtmp_send_audio(client, p, frame);
        }
    }

    if (frame->frametype == AST_FRAME_VIDEO)
    {
        if (client->mute > 1)
        {
            ast_mutex_unlock(&client->lock);
            return 0;
        }

        if (videosupport)
        {
            uint32_t *header = (uint32_t *) frame->data.ptr;

            if (*header == 0x504d5452)  // "RTMP"
            {
                I6DEBUG(5, client, "Call rtmp_send_video()\n");

                if (!client->echo)
                    res = rtmp_send_video(client, p, frame);
                else
                    I6LOG(LOG_WARNING, client, "Skipped frame (echo)!\n");
            }
            else
            {
                I6LOG(LOG_WARNING, client, "Skipped frame (type=%x)!\n",
                        frame->frametype);
            }
        }
        else
        {
            I6LOG(LOG_WARNING, client,
                    "Skipped video frame (videosupport disabled)!\n");
        }
    }

    ast_mutex_unlock(&client->lock);

    res = res;

    return 0;
}

static int rtmp_indicate(struct ast_channel *chan, int condition,
        const void *data, size_t datalen)
{
    struct rtmp_pvt *p = GET_CHAN_TECH_PVT(chan);
    struct rtmp_client *client = p->client;

    int res = 0;

    I6DEBUG(3, client, "rtmp_indicate(%s)", GET_CHAN_NAME(chan));

    switch (condition)
    {
        case AST_CONTROL_HOLD:
            ast_moh_start(chan, data, NULL);
            break;
        case AST_CONTROL_UNHOLD:
            ast_moh_stop(chan);
            break;
        case AST_CONTROL_BUSY:
            ast_softhangup_nolock(chan, AST_SOFTHANGUP_DEV);
            break;
        case AST_CONTROL_CONGESTION:
            ast_softhangup_nolock(chan, AST_SOFTHANGUP_DEV);
            break;
        case AST_CONTROL_VIDUPDATE:
            I6DEBUG(0, client, "Receive Video Update !\n");
            ast_mutex_lock(&client->lock);
            rtmp_send_event(client, "videoupdate");
            ast_mutex_unlock(&client->lock);
            break;
        default:
            I6DEBUG(3, client, "Don't know how to indicate condition '%d'\n", condition);
            res = (-1);
    }

    return res;
}

static int rtmp_devicestate(void *data)
{
    char *host;
    char *tmp;
    //struct sip_peer *p;

    int res = AST_DEVICE_INVALID;

    I6DEBUG(3, NULL, "rtmp_devicestate(%s)", (char*)data);

    /* make sure data is not null. Maybe unnecessary, but better be safe */
    host = ast_strdupa(data ? data : "");
    if ((tmp = strchr(host, '@')))
        host = tmp + 1;

    ast_debug(3, "Checking device state for peer %s\n", host);

#if 0
    if ((p = find_peer(host, NULL, FALSE, FINDALLDEVICES, TRUE, 0)))
    {
        if (p->addr.sin_addr.s_addr || p->defaddr.sin_addr.s_addr)
        {
            /* we have an address for the peer */

            /* Check status in this order
         - Hold
         - Ringing
         - Busy (enforced only by call limit)
         - Inuse (we have a call)
         - Unreachable (qualify)
         If we don't find any of these state, report AST_DEVICE_NOT_INUSE
         for registered devices */

            if (p->onHold)
                /* First check for hold or ring states */
                res = AST_DEVICE_ONHOLD;
            else if (p->inRinging)
            {
                if (p->inRinging == p->inUse)
                    res = AST_DEVICE_RINGING;
                else
                    res = AST_DEVICE_RINGINUSE;
            }
            else if (p->call_limit && (p->inUse == p->call_limit))
                /* check call limit */
                res = AST_DEVICE_BUSY;
            else if (p->call_limit && p->busy_level && p->inUse >= p->busy_level)
                /* We're forcing busy before we've reached the call limit */
                res = AST_DEVICE_BUSY;
            else if (p->call_limit && p->inUse)
                /* Not busy, but we do have a call */
                res = AST_DEVICE_INUSE;
            else if (p->maxms && ((p->lastms > p->maxms) || (p->lastms < 0)))
                /* We don't have a call. Are we reachable at all? Requires qualify= */
                res = AST_DEVICE_UNAVAILABLE;
            else                      /* Default reply if we're registered and have no other data */
                res = AST_DEVICE_NOT_INUSE;
        }
        else
        {
            /* there is no address, it's unavailable */
            res = AST_DEVICE_UNAVAILABLE;
        }
        unref_peer(p,
                "unref_peer, from sip_devicestate, release ref from find_peer");
    }
    else
    {
        res = AST_DEVICE_UNKNOWN;
    }
#endif

    return res;
}

static int rtmp_senddigit_begin(struct ast_channel *ast, char digit)
{
    struct rtmp_pvt *p = GET_CHAN_TECH_PVT(ast);
    struct rtmp_client *client = p->client;

    int res = 0;

    I6DEBUG(3, client, "rtmp_senddigit_begin(%s)\n", GET_CHAN_NAME(ast));

    if (client == NULL)
    {
        ast_log(LOG_WARNING, "Client NULL !\n");
        return -1;
    }


    if (debug)
        I6DEBUG(5, client, "rtmp_senddigit_begin(digit = %c)\n", digit);

    if (textsupport)
    {
        ast_mutex_lock(&client->lock);
        rtmp_send_dtmf(client, digit);
        ast_mutex_unlock(&client->lock);

    }
    else if (debug)
        I6LOG(LOG_DEBUG, client, "Text support disabled!\n");

    return res;
}

static int rtmp_senddigit_end(struct ast_channel *ast, char digit,
        unsigned int duration)
{
    struct rtmp_pvt *p = GET_CHAN_TECH_PVT(ast);
    struct rtmp_client *client = p->client;

    int res = 0;

    I6DEBUG(3, client, "rtmp_senddigit_end(%s)", GET_CHAN_NAME(ast));

    if (client == NULL)
    {
        ast_log(LOG_WARNING, "Client NULL !\n");
        return -1;
    }

    return res;
}

static int rtmp_sendtext(struct ast_channel *ast, const char *text)
{
    struct rtmp_pvt *p = GET_CHAN_TECH_PVT(ast);
    struct rtmp_client *client = p->client;

    int res = 0;

    I6DEBUG(3, client, "rtmp_sendtext(%s)", GET_CHAN_NAME(ast));

    if (client == NULL)
    {
        ast_log(LOG_WARNING, "Client NULL !\n");
        return -1;
    }

    if (debug)
        I6DEBUG(3, client, "rtmp_sendtext(text = %s)\n", text);

    if (textsupport)
    {
        ast_mutex_lock(&client->lock);

        rtmp_send_text(client, text);

        ast_mutex_unlock(&client->lock);
    }
    else if (debug)
        I6DEBUG(1, client, "Text support disabled!\n");

    return res;
}

static int rtmp_sendhtml(struct ast_channel *ast, int subclass,
        const char *data, int datalen)
{
    struct rtmp_pvt *p = GET_CHAN_TECH_PVT(ast);
    struct rtmp_client *client = p->client;

    int res = 0;

    I6DEBUG(3, client, "rtmp_sendhtml(%s)", GET_CHAN_NAME(ast));

    if (client == NULL)
    {
        ast_log(LOG_WARNING, "Client NULL !\n");
        return -1;
    }

    if (debug)
        I6DEBUG(3, client, "rtmp_sendhtml(data = %s)\n", data);

    if (textsupport)
    {
        ast_mutex_lock(&client->lock);

        rtmp_send_text(client, data);

        ast_mutex_unlock(&client->lock);
    }
    else if (debug)
        I6DEBUG(1, client, "Text support disabled!\n");

    return res;
}

#if 0
static enum ast_bridge_result rtmp_bridge(struct ast_channel *c0,
        struct ast_channel *c1, int flags, struct ast_frame **fo,
        struct ast_channel **rc, int timeoutms)
{
    return 0;
}
#endif

static struct ast_channel *rtmp_new(struct rtmp_pvt *i, int state,
        const char *linkedid, char *exten, char *param)
{
        static int counter=0;
        char format[100];
        struct ast_channel *tmp;

        sprintf(format, "RTMP/%%p_%d", counter++);

        I6DEBUG(3, i->client, "rtmp_new for %s\n", exten);
        I6DEBUG(3, i->client, "channel allocation... %s\n", exten);

        if (i->client->user && i->client->user->context[0])
        {
            tmp = ALLOCATE_CHANNEL(1, state, 0, i->client->name, NULL, exten, i->client->user->context, linkedid, 0, format, i->client);
        }
        else
        {
            tmp = ALLOCATE_CHANNEL(1, state, 0, i->client->name, NULL, exten, context, linkedid, 0, format, i->client);
        }
        if (!tmp)
        {
            ast_log(LOG_WARNING, "Unable to allocate channel structure\n");
            return NULL;
        }

        if (debug)
            I6DEBUG(3, i->client, "channel allocated for %s\n", exten);

        if (pipe(i->pipe) < 0)
        {
            ast_log(LOG_ERROR, "Pipe failed\n");
            return NULL;
        }

        if (i->schedid != (-1))
        {
            if (pipe(i->pipe2) < 0)
            {
                ast_log(LOG_ERROR, "Pipe2 failed\n");
                i->pipe2[0] = (-1);
                i->pipe2[1] = (-1);
            }
        }
        else
        {
            i->pipe2[0] = (-1);
            i->pipe2[1] = (-1);
        }

        if (i->pipe2[0] != (-1))
            ast_channel_set_fd(tmp, 0, i->pipe2[0]);
        else
            ast_channel_set_fd(tmp, 0, i->pipe[0]);

        SET_CHAN_TECH(tmp, &rtmp_tech);

        if (i->client != NULL)
        {
            if (videosupport)
            {
                SET_CHAN_NATIVEFORMATS2_ASTFORMAT_AND_IDFORMAT(tmp, i->client->audiocodec,
                        AST_FORMAT_H263);
            }
            else
            {
                SET_CHAN_NATIVEFORMATS1(tmp, i->client->audiocodec);
            }
            //
            if (debug)
            {
                char tmp_nativeformats_buffer[512];
                GET_FORMAT_NAME_MULTIPLE(tmp_nativeformats_buffer,
                        sizeof(tmp_nativeformats_buffer), GET_CHAN_NATIVEFORMATS(tmp));
                I6DEBUG(3, i->client, "rtmp_new set format %s (native format %s)\n", GET_FORMAT_NAME(i->client->audiocodec), tmp_nativeformats_buffer);
            }

            SET_CHAN_READFORMAT(tmp, i->client->audiocodec);
            SET_CHAN_WRITEFORMAT(tmp, i->client->audiocodec);

        }
        else
        {
            ast_log(LOG_DEBUG, "client for channel is NULL, cannot get audiocodec");
        }

        if (state == AST_STATE_RING)
        {
            SET_CHAN_RINGS(tmp, 1);
        }

        SET_CHAN_ADSICPE(tmp, AST_ADSI_UNAVAILABLE);

        SET_CHAN_TECH_PVT(tmp, i);

        if (!ast_strlen_zero(i->client->name))
        {
            SET_CHAN_CALLERID_NUMBER(tmp, ast_strdup(i->client->name));
            SET_CHAN_CALLERID_ANI(tmp, ast_strdup(i->client->name));
        }
        else
        {
            SET_CHAN_CALLERID_ANI(tmp, ast_strdup("?"));
        }

        SET_CHAN_CALLERID_DNID(tmp, ast_strdup(exten));

        if ((i->client->user) && (i->client->user->context[0]))
        {
            SET_CHAN_CONTEXT(tmp, i->client->user->context);
        }
        else
        {
            SET_CHAN_CONTEXT(tmp, context);
        }

        SET_CHAN_EXTEN(tmp, exten);
        SET_CHAN_PRIORITY(tmp, 1);

        SET_CHAN_LANGUAGE_RETURN_BOOL(tmp, "");
#if ASTERISK_VERSION_NUM >= AST_11
        struct ast_callid *callid = ast_channel_callid(tmp);
        if (!callid)
        {
            callid = ast_create_callid();
            if (callid)
                ast_channel_callid_set(tmp, callid);
        }
#endif

        if (param)
            if (param[0])
            {
                if (debug)
                    RTMP_VERBOSE(i->client, "Set variable VOXIMAL_PARAM=%s\n", param);

                //pbx_builtin_setvar_helper(chan, "__RTMPINVITE", flashver);
                pbx_builtin_setvar_helper(tmp, "__VOXIMAL_PARAM", param);
            }

        // Set jitter
        ast_jb_configure(tmp, &global_jbconf);

        i->owner = tmp;

        if (!((COMPARE_VARFORMAT_IDFORMAT(i->client->audiocodec, AST_FORMAT_SPEEX)) ||
                (COMPARE_VARFORMAT_IDFORMAT(i->client->audiocodec, AST_FORMAT_ALAW)) ||
                (COMPARE_VARFORMAT_IDFORMAT(i->client->audiocodec, AST_FORMAT_ULAW)) ||
                (COMPARE_VARFORMAT_IDFORMAT(i->client->audiocodec, AST_FORMAT_SLINEAR))))
        {
#ifdef RTMP_FFMPEG
            I6DEBUG(3, i->client, "Use encoder audio codec not supported\n");

            i->encoder = avcodec_find_encoder(CODEC_ID_ADPCM_SWF);

            if (!i->encoder)
            {
                if (debug)
                    I6DEBUG(3, i->client, "Codec not found\n");
                ast_hangup(tmp);
            }

            i->encoding_context = avcodec_alloc_context2(AVMEDIA_TYPE_AUDIO);
            if (i->encoding_context != NULL)
            {
                i->encoding_context->codec_id = CODEC_ID_ADPCM_SWF;
                i->encoding_context->codec_type = AVMEDIA_TYPE_AUDIO;
                i->encoding_context->channels = 1;
                i->encoding_context->sample_rate = 11025;
            }
            if (avcodec_open(i->encoding_context, i->encoder) < 0)
            {
                if (debug)
                    I6DEBUG(3, i->client, "Could not open codec\n");
                ast_hangup(tmp);
            }

            i->decoder = avcodec_find_decoder(CODEC_ID_NELLYMOSER);
            if (!i->decoder)
            {
                ast_log(LOG_WARNING, "Codec not found\n");
                ast_hangup(tmp);
            }
            //i->decoding_context = avcodec_alloc_context2(CODEC_ID_NELLYMOSER);
            i->decoding_context = avcodec_alloc_context2(AVMEDIA_TYPE_AUDIO);
            if (i->decoding_context != NULL)
            {
                i->decoding_context->codec_id = CODEC_ID_NELLYMOSER;
                i->decoding_context->codec_type = AVMEDIA_TYPE_AUDIO;
                i->decoding_context->channels = 1;
                i->decoding_context->sample_rate = 8000;
                i->decoding_context->bits_per_coded_sample = 16;
            }

            if (avcodec_open(i->decoding_context, i->decoder) < 0)
            {
                ast_log(LOG_WARNING, "Could not open codec\n");
                ast_hangup(tmp);
            }
            i->decoding_jitter_length = 0;
#else
            if (debug)
            I6DEBUG(3, i->client, "Codec not found (no FFMPEG)\n");
            ast_hangup(tmp);
#endif
        }

        i->audiolength = 0;

        i->client->outgoing_images = 0;
        i->client->incoming_images = 0;

        i->client->callanswer = 0;
        i->client->callstart = 0;
        i->client->callstop = 0;
        time(&i->client->callstart);

        i->client->outgoing_audiofile = NULL;
        i->client->incoming_audiofile = NULL;
        i->client->outgoing_videofile = NULL;
        i->client->incoming_videofile = NULL;

        i->client->in_flv.fd = 0;
        i->client->out_flv.fd = 0;
        i->client->havePictureInSize = 0;
        i->client->havePictureOutSize = 0;

#if ASTERISK_VERSION_NUM >= AST_12
        ast_channel_unlock(tmp);
#endif
        if (state != AST_STATE_DOWN && ast_pbx_start(tmp))
        {
            ast_log(LOG_WARNING, "Unable to start PBX on %s\n", GET_CHAN_NAME(tmp));
            SET_CHAN_HANGUPCAUSE(tmp, AST_CAUSE_SWITCH_CONGESTION);
            ast_hangup(tmp);
            i->owner = NULL;
            tmp = NULL;
        }


        return tmp;
}


//static struct ast_channel *rtmp_request(const char *type, int format, const struct ast_channel *requestor, void *data, int *cause)
#if ASTERISK_VERSION_NUM < AST_8
static struct ast_channel *rtmp_request(const char *type, int format_cap,
        void *data, int *cause)
#elif ASTERISK_VERSION_NUM >= AST_8 && ASTERISK_VERSION_NUM < AST_11
static struct ast_channel *rtmp_request(const char *type, format_t format_cap,
        const struct ast_channel *requestor, void *data, int *cause)
#elif ASTERISK_VERSION_NUM >= AST_11  && ASTERISK_VERSION_NUM < AST_12
static struct ast_channel *rtmp_request(const char *type,
        struct ast_format_cap *format_cap, const struct ast_channel *requestor,
        const char *data, int *cause)
#elif ASTERISK_VERSION_NUM >= AST_12
static struct ast_channel *rtmp_request(const char *type,
        struct ast_format_cap *format_cap, const struct ast_channel *requestor,
        const char *data, int *cause)
#endif
{
        INITIALIZE_OLDFORMAT;
        struct rtmp_pvt *p;
        struct ast_channel *tmp = NULL;
        struct rtmp_client *client = NULL;

        I6DEBUG(3, client, "RTMP request for = %s\n", (char *)data);

        client = rtmp_find_connection(data);
        if (client == NULL)
        {
            I6DEBUG(3, client, "No RTMP client = %s\n", (char *)data);
            *cause = AST_CAUSE_SUBSCRIBER_ABSENT;
            return NULL;
        }

        I6LOG(LOG_DEBUG, client, "Request for %s\n", (char *)data);

        if (client->pvt != NULL)
        {
            if (debug)
                I6DEBUG(3, client, "RTMP client busy = %s\n", (char *)data);

            *cause = AST_CAUSE_USER_BUSY;

            ast_mutex_unlock(&client->lock);
            return NULL;
        }

        stats[STATS_REQUESTS]++;

        //p = rtmp_alloc(args.writestream, args.readstream, ast_strlen_zero(args.readnum) ? NULL : args.readnum);
        p = rtmp_alloc("", "", NULL);
        if (p == NULL)
        {
            if (debug)
                I6DEBUG(3, client, "Cannot allocate RTMP client = %s\n", (char *)data);

            *cause = AST_CAUSE_FAILURE;
            ast_mutex_unlock(&client->lock);

            return NULL;
        }

        p->client = client;

        I6DEBUG(1, client, "%s client found, connected to ast channel \n",
                (char *)data);

        COPY_FORMAT_CAP(oldformat, format_cap);
        CLEAR_CAP_AND_SET_FORMAT(format_cap, client->audiocodec);
        char oldformat_buffer[512];
        GET_FORMAT_NAME_MULTIPLE(oldformat_buffer, sizeof(oldformat_buffer),
                oldformat);
        if (CHECK_CAP_EMPTY(format_cap))
        {
            if (debug)
                I6DEBUG(1, client, "Asked to get a channel of unsupported format '%s' force to %s)\n", oldformat_buffer, GET_FORMAT_NAME(client->audiocodec));

        }

        {
            //tmp = rtmp_new(p, AST_STATE_DOWN, requestor ? requestor->linkedid : NULL);
            tmp = rtmp_new(p, AST_STATE_DOWN, NULL, "s", NULL);
            if (!tmp)
            {
                if (debug)
                    I6LOG(LOG_DEBUG, client, "Cannot create a new RTMP client = %s\n",
                            (char *)data);

                ast_mutex_lock(&rtmplock);

                ao2_t_unlink(connections, p, "Unlink pvt out to connections table");
                ao2_t_ref(p, -1, "Unref and free rtmp_pvt");

                ast_mutex_unlock(&rtmplock);

                ast_mutex_unlock(&client->lock);

                return NULL;
            }
            else
            {
                ast_channel_lock(tmp);

                if (videosupport)
                {
                    SET_CHAN_NATIVEFORMATS2_ASTFORMAT_AND_IDFORMAT(tmp, client->audiocodec,
                            AST_FORMAT_H263);
                }
                else
                {
                    SET_CHAN_NATIVEFORMATS1(tmp, client->audiocodec);
                }

                if (debug)
                {
                    char tmp_nativeformats_buffer[512];
                    GET_FORMAT_NAME_MULTIPLE(tmp_nativeformats_buffer,
                            sizeof(tmp_nativeformats_buffer), GET_CHAN_NATIVEFORMATS(tmp));
                    I6DEBUG(3, client, "rtmp_new set format %s (native format %s)\n", GET_FORMAT_NAME(client->audiocodec), tmp_nativeformats_buffer);
                }

                SET_CHAN_READFORMAT(tmp, client->audiocodec);
                SET_CHAN_WRITEFORMAT(tmp, client->audiocodec);

                I6DEBUG(3, client, "Connect the PVT context\n");

                p->owner = tmp;
                client->pvt = p;
                client->outgoing_calls++;

                ast_mutex_unlock(&client->lock);
                ast_channel_unlock(tmp);

                I6DEBUG(5, client, "Channel state %d ok\n", GET_CHAN_STATE(tmp));
                I6DEBUG(5, client, "Request for %s ok\n", (char *)data);
            }
        }

        return tmp;
}

#ifdef _USE_RTMPT_
/*
 * http_getCmdSess
 * Parse HTTP POST request to find HTTP cmd and session ID.
 *
 * Request ex :
         POST /open/1 HTTP/1.1
         Content-Type: application/x-fcs
         User-Agent: Shockwave Flash
         Host: localhost:1939
         Content-Length: 1
         Connection: Keep-Alive
         Cache-Control: no-cache

        POST /idle/55a6414ef2609e1a9ec5bf33b4a69a5/0 HTTP/1.1
        Content-Type: application/x-fcs
        User-Agent: Shockwave Flash
        Host: localhost:1939
        Content-Length: 1
        Connection: Keep-Alive
        Cache-Control: no-cache
 */

static int http_getCmdSess(struct rtmp_client *client, char *request, char *cmd, char *sessId)
{
    char *firstSlash;
    char *secondSlash;
    char *thirdSlash;
    char *http1;

    I6DEBUG(9, client, "http_getCmdSess: parse request\n");
    // get first '/'
    firstSlash = strchr(request, '/');
    if (firstSlash) {
        // get second '/'
        secondSlash = strchr(firstSlash+1, '/');
        if (secondSlash) {
            int lg = secondSlash - firstSlash - 1;
            memcpy(cmd, firstSlash+1, lg);
            I6DEBUG(4, client, "lgcmd=%d : cmd='%s'\n", lg,cmd);

            // Search sessID
            /* First search HTTP/1.1 because we can have :
             *    POST /open/1 HTTP/1.1   or
             *    POST /idle/55a6414ef2609e1a9ec5bf33b4a69a5/0 HTTP/1.1
             */
            http1 = strstr(secondSlash+1, "HTTP/1.1");
            thirdSlash = strchr(secondSlash+1, '/');
            if (thirdSlash < http1) {
                // There is a request number
                lg = thirdSlash - secondSlash -1 ;
                memcpy(sessId, secondSlash+1, lg);
                I6DEBUG(4, client, "lgsess=%d : sess='%s'\n", lg, sessId);
            }
            else {
                // There is a request number
                lg = (http1-1) - secondSlash -1 ;
                memcpy(sessId, secondSlash+1, lg);
                I6DEBUG(4, client, "lgsess=%d : sess='%s'\n", lg, sessId);
            }
        }
        else {
            I6DEBUG(4, client, "second '/' not found");
            return -1;
        }
    }
    else {
        I6DEBUG(4, client, "first '/' not found");
        return -1;
    }
    return 0;
}


static int http_getDataLength(struct rtmp_client *client, char *request, int *pLg)
{
    char *ptr;
    char *end;

    I6DEBUG(9, client, "http_getDataLength: parse request\n");
    ptr = strstr(request, "Content-Length");
    if (ptr != NULL) {
        ptr += 16; // sizeof("Content-Length: ");
        end = strstr(ptr, "\n");
        if (end != NULL) {
            int size = end - ptr -1 ;
            char lgstr[20];
            memcpy(lgstr, ptr, size);
            *pLg = atoi(lgstr);
            I6DEBUG(4, client, "lg=%d : lgstr='%s' -> %Xh\n", size, lgstr, *pLg);
        }
        else {
            I6DEBUG(0, client, "Failed to found end of 'Content-Length'\n");
            return -1;
        }
    }
    else {
        I6DEBUG(0, client, "Failed to found 'Content-Length'\n");
        return -1;
    }
    return 0;
}

static int rtmp_try_rtmpt(struct rtmp_client *client)
{
    int res;
    uint32_t uptime;
    int i, *ip;
    uint8_t serverbuf[RTMP_BLOCK_SIZE + 4];
    uint8_t *serversig = serverbuf + 1;
    uint8_t clientsig[RTMP_BLOCK_SIZE+1];
    //int offalg = 0;
    int dhposServer = 0;
    int digestPosServer = 0;
    RC4_handle keyIn = 0;
    RC4_handle keyOut = 0;
    //getoff *getdh = NULL, *getdig = NULL;
    int encore =1;
    char strSessId[20];

    I6DEBUG(4, client, "start rtmp_try_rtmpt\n");

    while ( ((res = rtmp_receive_data(client, (uint8_t *)clientsig, RTMP_BLOCK_SIZE , 5000)) >= 0) && encore) {
        I6DEBUG(9, client, "rtmp_try_rtmpt: recv %d\n",res);
        if (res) {
            if (debug) {
                char tmp[1024];
                sprintf(tmp, "RTMP/%p ", client);
                dump_buffer_hex(tmp,clientsig, res);
                I6DEBUG(0, client, "req: \n%s\n",clientsig);
            }

            // Check if POST HTTP
            if (!strncmp(clientsig, "POST ", 5)) {
                char cmd[20]    = {0};
                char rcvSessId[20] = {0};

                snprintf(strSessId, sizeof(strSessId), "%08x", client);

                if (http_getCmdSess(client, clientsig, cmd, rcvSessId) == -1) {
                    ast_log(LOG_ERROR, "Failed to parse HTTP request\n%s\n",clientsig);
                    return -1;
                }
                if (!strncmp(cmd, "open", 4)) {
                    char hbuf[512];
                    int hlen = snprintf(hbuf, sizeof(hbuf), "HTTP/1.1 200 OK\n"
                      "Cache-Control: no-cache\n"
                      "Content-Length: 9\n"
                      "Content-Type: application/x-fcs\n"
                      "Connection: Keep-Alive\n\n"
                      "%08x\n", client);

                    I6DEBUG(4, client, "Send 200 OK\n%s",hbuf);
                    if (rtmp_send_data(client, hbuf, hlen) != hlen) {
                        ast_log(LOG_ERROR, "Could not initiate handshake.\n");
                        return -1;
                    }
                }
                else if (!strncmp(cmd, "close", 5)) {
                    char hbuf[512];
                    int hlen = snprintf(hbuf, sizeof(hbuf), "HTTP/1.1 200 OK\n"
                      "Cache-Control: no-cache\n"
                      "Content-Length: 1\n"
                      "Content-Type: application/x-fcs\n"
                      "Connection: Keep-Alive\n\n");

                    I6DEBUG(4, client, "Send 200 OK\n%s",hbuf);
                    if (rtmp_send_data(client, hbuf, hlen) != hlen) {
                        ast_log(LOG_ERROR, "Could not initiate handshake.\n");
                        return -1;
                    }
                    encore = 0;
                }
                else if (!strncmp(cmd, "idle", 4)) {
                    char hbuf[512];

                    // Check session ID
                    I6DEBUG(4, client, "sessid: local '%s' - rem '%s'\n", strSessId, rcvSessId);
                    if (!strncmp(strSessId, rcvSessId, sizeof(strSessId))) {
                        int hlen = snprintf(hbuf, sizeof(hbuf), "WRITE\nHTTP/1.1 200 OK\n"
                          "Cache-Control: no-cache\n"
                          "Content-Length: 1\n"
                          "Content-Type: application/x-fcs\n"
                          "Connection: Keep-Alive\n\n");

                        I6DEBUG(4, client, "Send 200 OK\n%s",hbuf);
                        if (rtmp_send_data(client, hbuf, hlen) != hlen) {
                            ast_log(LOG_ERROR, "Could not initiate handshake.\n");
                            return -1;
                        }
                    }
                    else {
                        ast_log(LOG_ERROR, "Bad received sessionid %s != %s\n", rcvSessId, strSessId);
                        return -1;
                    }
                }
                else if (!strncmp(cmd, "send", 4)) {
                    char hbuf[512];
                    int contentLg;

                    // Check session ID
                    I6DEBUG(4, client, "sessid: local '%s' - rem '%s'\n", strSessId, rcvSessId);
                    if (1) { /////////////////////////////////////////  !strncmp(strSessId, rcvSessId, sizeof(strSessId))) {
                        // Get length
                        if (http_getDataLength(client, clientsig, &contentLg) == -1) {
                            ast_log(LOG_ERROR, "Failed to get contentlength\n");
                            return -1;
                        }
                        I6DEBUG(4, client, "Content-length=%d\n", contentLg);

                        int hlen = snprintf(hbuf, sizeof(hbuf), "WRITE\nHTTP/1.1 200 OK\n"
                          "Cache-Control: no-cache\n"
                          "Content-Length: 1\n"
                          "Content-Type: application/x-fcs\n"
                          "Connection: Keep-Alive\n\n");

                        I6DEBUG(4, client, "Send 200 OK\n%s",hbuf);
                        if (rtmp_send_data(client, hbuf, hlen) != hlen) {
                            ast_log(LOG_ERROR, "Could not initiate handshake.\n");
                            return -1;
                        }
                    }
                    else {
                        ast_log(LOG_ERROR, "Bad received sessionid %s != %s\n", rcvSessId, strSessId);
                        return -1;
                    }
                }
                else {
                    ast_log(LOG_ERROR, "Unsupported HTTP cmd %s\n", cmd);
                    return -1;
                }
            }
            else {
                I6DEBUG(0, client, "Not POST HTTP\n");
                return -1;
            }
        }
    }


    return -1;
}
#endif // #ifdef _USE_RTMPT_

static int rtmp_handshake(struct rtmp_client *client)
{
    int  encrypted = 0;
    int  FP9HandShake = 0;
    int  offalgo = 0;
    char type;
    int res;
    uint32_t uptime;
    int i, *ip;
    uint8_t serverbuf[RTMP_BLOCK_SIZE + 4];
    uint8_t *serversig = serverbuf + 1;
    uint8_t clientsig[RTMP_BLOCK_SIZE+1];
    //int offalg = 0;
    int dhposServer = 0;
    int digestPosServer = 0;
    RC4_handle keyIn = 0;
    RC4_handle keyOut = 0;
    //getoff *getdh = NULL, *getdig = NULL;

    I6DEBUG(4, client, "start handshake\n");

    /* Read Type */
    res = rtmp_receive_data(client, (uint8_t *)&type, 1, 5000);
    if (res != 1) {
        I6LOG(LOG_ERROR, client, "rtmp_handshake: Failed to get first byte. Rcv %d\n", res);
        return -1;
    }
    I6DEBUG(9, client, "handshake: recv type %d\n",type);

    /* Read 1st Handshake */
    res = rtmp_receive_data(client, (uint8_t *)clientsig, RTMP_BLOCK_SIZE , 5000);
    I6DEBUG(9, client, "handshake: recv 1st handshake lg %d\n",res);
    if (debug) {
        char tmp[1024];
        sprintf(tmp, "RTMP/%p handshake 1/2", client);
        dump_buffer_hex(tmp,clientsig, RTMP_BLOCK_SIZE); // 16);
    }

    if (type == 3) {
        encrypted = 0;
        I6DEBUG(2, client, "handshake type %d (not encrypted)\n",type);
    }
    else if (type == 6 || type == 8)
    {
        offalgo      = 1;
        encrypted    = 1;
        FP9HandShake = 1;
        client->protocol |= RTMP_FEATURE_ENC;
        /* use FP10 if client is capable */
        if (clientsig[4] == 128)
            type = 8;
        I6DEBUG(2, client, "handshake: type %d (encrypted)\n", type);
    }
    else
    {
        I6LOG(LOG_ERROR, client, "handshake: unknown type %d\n", type);
        return -1;
    }

    if (!FP9HandShake && clientsig[4]) {
        FP9HandShake = 1;
        I6DEBUG(4, client, "handshake: FP9 detected  %Xh(%d)\n", clientsig[4], clientsig[4]);
    }

    serverbuf[0] = type;

    uptime = htonl((uint32_t)time(NULL));
    memcpy(serversig, &uptime, 4);

    if (FP9HandShake) {
        /* Server version */
        serversig[4] = 3;
        serversig[5] = 5;
        serversig[6] = 1;
        serversig[7] = 1;
    }
    else {
        memset(&serversig[4], 0, 4);
    }
    /* generate random data */
#ifdef _DEBUG_
    memset(serversig+8, 0, RTMP_BLOCK_SIZE-8);
#else
    ip = (int32_t *)(serversig+8);
    for (i = 2; i < RTMP_BLOCK_SIZE/4; i++)
        *ip++ = rand();
#endif

    /* set handshake digest */
    if (FP9HandShake)
    {
        if (encrypted)
        {
            I6DEBUG(9, client, "handshake: generate Diffie-Hellmann parameters\n");
            /* generate Diffie-Hellmann parameters */
            client->dh = DHInit(1024);
            if (!client->dh)
            {
                I6LOG(LOG_ERROR, client, "handshake: Couldn't initialize Diffie-Hellmann!\n");
                return -1;
            }

            I6DEBUG(9, client, "handshake: DH key\n");
            dhposServer = getDhPos(offalgo, serversig, RTMP_BLOCK_SIZE);
            I6DEBUG(4, client, "handshake: DH pubkey position: %d (algo %d)\n", dhposServer, offalgo);
            if (!DHGenerateKey(client->dh))
            {
                I6LOG(LOG_ERROR, client, "handshake: Couldn't generate Diffie-Hellmann public key!\n");
                return -1;
            }

            I6DEBUG(9, client, "handshake: DH public key\n");
            if (!DHGetPublicKey(client->dh, (uint8_t *) &serversig[dhposServer], 128))
            {
                I6LOG(LOG_ERROR, client, "handshake: Couldn't write public key!\n");
                return -1;
            }
        }
        I6DEBUG(9, client, "handshake: FP9 calculate handshake return\n");

        digestPosServer = getDigestPos(offalgo, serversig, RTMP_BLOCK_SIZE);   /* reuse this value in verification */
        I6DEBUG(4, client, "handshake: Server digest offset: %d (algo %d)\n",  digestPosServer, offalgo);

        calculate_digest(digestPosServer, serversig, GENUINE_FMSKEY, 36,&serversig[digestPosServer]);
        if (debug) {
            char tmp[1024];
            sprintf(tmp, "RTMP/%p handshake: Initial server digest:", client);
            dump_buffer_hex(tmp, serversig + digestPosServer, SHA256_DIGEST_LENGTH);
        }
    }

    /* write server type + time  */
    I6DEBUG(4, client, "handshake: sending server info\n");
    if (rtmp_send_data(client, serverbuf, RTMP_BLOCK_SIZE + 1) != RTMP_BLOCK_SIZE + 1)
    {
        ast_log(LOG_ERROR, "Could not initiate handshake.\n");
        return -1;
    }

    /* decode client response */
    memcpy(&uptime, clientsig, 4);
    uptime = ntohl(uptime);

    I6DEBUG(4, client, "handshake: Client Uptime : %d\n",uptime);
    I6DEBUG(4, client, "handshake: Player Version: %d.%d.%d.%d\n",
            clientsig[4],clientsig[5], clientsig[6], clientsig[7]);

#if 1
    if (FP9HandShake)
    {
        uint8_t digestResp[SHA256_DIGEST_LENGTH];
        uint8_t *signatureResp = NULL;
        int digestPosClient;

        /* we have to use this signature now to find the correct algorithms for getting the digest and DH positions */
        if ((digestPosClient = verify_digest(offalgo, clientsig)) == -1)
        {
            ast_log(LOG_ERROR, "Couldn't verify the client digest\n");
            return -1;
        }
        I6DEBUG(4, client, "handshake: use digest position client %d\n",digestPosClient);

#if 0
        /* generate SWFVerification token (SHA256 HMAC hash of decompressed SWF, key are the last 32 bytes of the server handshake) */
        if (client->SWFSize)
        {
            const char swfVerify[] = { 0x01, 0x01 };
            char *vend = r->Link.SWFVerificationResponse+sizeof(r->Link.SWFVerificationResponse);
            memcpy(r->Link.SWFVerificationResponse, swfVerify, 2);
            AMF_EncodeInt32(&r->Link.SWFVerificationResponse[2], vend, r->Link.SWFSize);
            AMF_EncodeInt32(&r->Link.SWFVerificationResponse[6], vend, r->Link.SWFSize);
            HMACsha256(r->Link.SWFHash, SHA256_DIGEST_LENGTH,
                    &serversig[RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH],
                    SHA256_DIGEST_LENGTH,
                    (uint8_t *)&r->Link.SWFVerificationResponse[10]);
        }
#endif

        /* do Diffie-Hellmann Key exchange for encrypted RTMP */
        if (encrypted)
        {
            int dhposClient, len;
            /* compute secret key */
            uint8_t secretKey[128] = { 0 };

            dhposClient = getDhPos(offalgo, clientsig, RTMP_BLOCK_SIZE);
            I6DEBUG(4, client, "handshake: Client DH public key offset: %d\n", dhposClient);
            len = DHComputeSharedSecretKey(client->dh, (uint8_t *) &clientsig[dhposClient], 128, secretKey);
            if (len < 0)
            {
                ast_log(LOG_ERROR, "handshake:  Wrong secret key position!\n");
                return -1;
            }
            if (debug) {
                char tmp[1024];
                sprintf(tmp, "RTMP/%p handshake: Secret key", client);
                dump_buffer_hex(tmp, secretKey, 128);
            }

            InitRC4Encryption(secretKey,
                    (uint8_t *) &clientsig[dhposClient],
                    (uint8_t *) &serversig[dhposServer],
                    &keyIn, &keyOut);
        }


        /* calculate response now */
        signatureResp = clientsig + RTMP_BLOCK_SIZE - SHA256_DIGEST_LENGTH;

        verify_HMAC(&clientsig[digestPosClient], SHA256_DIGEST_LENGTH,
                NULL, GENUINE_FMSKEY, 0, digestResp);
        verify_HMAC(clientsig, RTMP_BLOCK_SIZE - SHA256_DIGEST_LENGTH,
                digestResp, 0, SHA256_DIGEST_LENGTH, signatureResp);
#ifdef FP10
        if (type == 8 )
        {
            uint8_t *dptr = digestResp;
            uint8_t *sig = signatureResp;
            /* encrypt signatureResp */
            for (i=0; i<SHA256_DIGEST_LENGTH; i+=8)
                rtmpe8_sig(sig+i, sig+i, dptr[i] % 15);
        }
#endif
        /* some info output */
        if (debug) {
            char tmp[1024];
            sprintf(tmp, "RTMP/%p handshake: Calculated digest key from secure key and server digest:", client);
            dump_buffer_hex(tmp, digestResp, SHA256_DIGEST_LENGTH);
            sprintf(tmp, "RTMP/%p handshake: Server signature calculated:", client);
            dump_buffer_hex(tmp, signatureResp, SHA256_DIGEST_LENGTH);
        }
    }
#endif

    I6DEBUG(4, client, "handshake: sending handshake resp (1/2)\n");
    if (rtmp_send_data(client, clientsig, RTMP_BLOCK_SIZE) != RTMP_BLOCK_SIZE)
    {
        ast_log(LOG_ERROR, "Could not initiate handshake (send 1/2).\n");
        return -1;
    }

    /*
     * 2nd part of handshake
     */
    res = rtmp_receive_data(client, clientsig, RTMP_BLOCK_SIZE , 5000);
    if (res != RTMP_BLOCK_SIZE) {
        ast_log(LOG_ERROR, "Could not initiate handshake (send 2/2): rcv %d/%d.\n", res,RTMP_BLOCK_SIZE);
        return -1;
    }
    /*if (debug) {
      char tmp[1024];
      sprintf(tmp, "RTMP/%p handshake 2/2", client);
      dump_buffer_hex(tmp,clientsig, RTMP_BLOCK_SIZE);
    } */

    if (FP9HandShake)
    {
        uint8_t signature[SHA256_DIGEST_LENGTH];
        uint8_t digest[SHA256_DIGEST_LENGTH];

        if (debug) {
            char tmp[1024];
            sprintf(tmp, "RTMP/%p handshake:  Client sent signature:", client);
            dump_buffer_hex(tmp, &clientsig[RTMP_BLOCK_SIZE - SHA256_DIGEST_LENGTH], SHA256_DIGEST_LENGTH);
        }

        /* verify client response */
        verify_HMAC(&serversig[digestPosServer], SHA256_DIGEST_LENGTH,
                NULL, GENUINE_FPSKEY, 0, digest);
        verify_HMAC(clientsig, RTMP_BLOCK_SIZE - SHA256_DIGEST_LENGTH,
                digest, 0, SHA256_DIGEST_LENGTH, signature);
#ifdef FP10
        if (type == 8 )
        {
            uint8_t *dptr = digest;
            uint8_t *sig = signature;
            /* encrypt signatureResp */
            for (i=0; i<SHA256_DIGEST_LENGTH; i+=8)
                rtmpe8_sig(sig+i, sig+i, dptr[i] % 15);
        }
#endif

        /* show some information */
        if (debug) {
            char tmp[1024];
            sprintf(tmp, "RTMP/%p handshake: Digest key:", client);
            dump_buffer_hex(tmp, digest, SHA256_DIGEST_LENGTH);
            sprintf(tmp, "RTMP/%p handshake: Signature calculated:", client);
            dump_buffer_hex(tmp,signature , SHA256_DIGEST_LENGTH);
        }

        if (memcmp(signature, &clientsig[RTMP_BLOCK_SIZE - SHA256_DIGEST_LENGTH],
                SHA256_DIGEST_LENGTH) != 0)
        {
            ast_log(LOG_ERROR, "handshake: Client not genuine Adobe!\n");
            return -1;
        }
        else {
            I6DEBUG(4, client, "handshake: Genuine Adobe Flash Player\n");
        }

        if (encrypted)
        {
            char buff[RTMP_BLOCK_SIZE];
            /* set keys for encryption from now on */
            client->rc4keyIn  = keyIn;
            client->rc4keyOut = keyOut;

            /* update the keystreams */
            if (client->rc4keyIn)
            {
                RC4_encrypt(client->rc4keyIn, RTMP_BLOCK_SIZE, (uint8_t *) buff);
            }

            if (client->rc4keyOut) {
                RC4_encrypt(client->rc4keyOut, RTMP_BLOCK_SIZE, (uint8_t *) buff);
            }
        }
    }
    else
    {
        if (memcmp(serversig, clientsig, RTMP_BLOCK_SIZE) != 0) {
            I6DEBUG(0, client, "handshake: client signature does not match!");
        }
    }
    I6DEBUG(4, client, "handshake: finished\n");
    return 0;
}


/*--- rtmp_server_process: Read data from RTMP socket ---*/
/*    Successful messages is connected to RTMP call and forwarded to handle_request() */
//static int rtmpsock_read(int *id, int fd, short events, void *ignore)
static int rtmp_server_process(struct rtmp_threadinfo *me)
{
    struct ast_tcptls_session_instance *tcptls_session = me->tcptls_session;
    int result = 0;
    int res = (-1);
    uint8_t *buffer = NULL;
    struct ao2_container *rtmpmessages = NULL;
    struct ao2_iterator aux;
    struct rtmp_message *rtmp = NULL;
    struct rtmp_client *client = NULL;
    int i;
    struct timeval now;
    struct timeval lastaudio;

    /* initialize the RTMP messages container */
    rtmpmessages =
            ao2_t_container_alloc(hash_rtmpmessages_size, rtmpmessages_hash_cb,
                    rtmpmessages_cmp_cb, "allocate RTMP messages");

    /* set the first byte to 0x03, fill the rest with zeros */



    // Alloc a new client.
    client = ast_calloc(1, sizeof(*client));
    if (!client)
    {
        ast_log(LOG_ERROR, "Failed to allocate client!\n");
        return AST_MODULE_LOAD_FAILURE;
    }
    I6DEBUG(0, client, "Starting a new server thread.\n");


    client->protocol = 0;

    client->name[0] = 0;
    client->flashver[0] = 0;
    client->cellid[0] = 0;
    client->param[0] = 0;

    {
        struct in_addr temp_addr;
        TCPTLS_SESSION_ADDRESS(tcptls_session->remote_address, temp_addr.s_addr);
        inet_ntop(AF_INET, &temp_addr, client->address, 80);
        client->port = TCPTLS_SESSION_PORT(tcptls_session->remote_address);
    }

    client->country = NULL;
    client->latitude = 0.0;
    client->longitude = 0.0;

    client->state = RTMP_DISCONNECTED;

    /* initialize our array of streams to zero */
    for (i = 0; i < RTMP_MAX_CHANNELS; i++)
    {
        client->streams[i] = ast_malloc(sizeof(struct rtmp_channel));
        memset(client->streams[i], '\0', sizeof(struct rtmp_channel));
    }

    client->threadinfo = me;
    client->user = NULL;

    client->outgoing_chunksize = RTMP_CHUNK_SIZE;
    client->incoming_chunksize = RTMP_CHUNK_SIZE;

    client->outgoing_windowsize = RTMP_WINDOW_SIZE;
    client->incoming_windowsize = RTMP_WINDOW_SIZE;

    client->outgoing_bytescount = 0;
    client->incoming_bytescount = 0;

    client->outgoing_timebytescount = 0;
    client->incoming_timebytescount = 0;

    client->lastack = 0;

    client->publishstream = (-1.0);
    client->playstream = (-1.0);
    client->playstream2 = (-1.0);

    client->publishing = 0;
    client->playing = 0;
    client->playing2 = 0;

    client->autoanswer = 0;
    client->mute = 0;
    client->echo = 0;

    client->firstaudio = 0;
    time(&client->date);
    client->timestart = ast_tvnow();
    client->timecalc = client->timestart;
    client->timestamp = 0;
    client->timestamplast = 0;

    client->callstart = 0;
    client->callanswer = 0;
    client->callstop = 0;

    client->pvt = NULL;
    client->state = RTMP_CONNECTING;
    client->fd = tcptls_session->fd;
    // JYG ???????????       tcptls_session->fd = -1;

    FORMAT_CLEAR(client->audiocodec);
    client->acodec_setted = 0;

    client->incoming_calls = 0;
    client->outgoing_calls = 0;

    client->incoming_images = 0;
    client->outgoing_images = 0;

    client->outgoing_audio = 0;
    client->outgoing_video = 0;

    client->outgoing_audiolost = 0;
    client->outgoing_videolost = 0;

    client->incoming_audio = 0;
    client->incoming_video = 0;

    client->incoming_audiolost = 0;
    client->incoming_videolost = 0;

    client->burst_max = 0;
    client->burst_counter = 0;
    client->burst_count = 0;

    client->overwrites_max = maxoverwrites;
    client->overwrites_count = 0;

    ast_mutex_init(&client->lock);

    /* Malloc output frame */
    client->cseq = 0;
    client->bufferSize = BUFFER_OUTPUTFRAME;
    client->bufferLen = 0;
    client->buffer = (uint8_t *) ast_malloc(client->bufferSize);

    client->chunks_buffer = NULL;
    client->chunks_buffersize = 0;
    client->chunks_bufferoffset = 0;

    client->tcptls_session = tcptls_session;
    client->rc4keyIn  = NULL;
    client->rc4keyOut = NULL;

    lastaudio.tv_sec = 0;
    lastaudio.tv_usec = 0;

    if (!client->buffer)
    {
        I6LOG(LOG_ERROR, client, "Unable to alloc Video RTMP buffer\n");
        goto cleanup;
    }

    if (client->fd == (-1))
    {
        I6LOG(LOG_ERROR, client, "Unable to build socket\n");
        goto cleanup;
    }

    buffer = ast_malloc(RTMP_RECV_BUFSIZE);
    if (!buffer)
    {
        I6LOG(LOG_ERROR, client, "Unable to alloc buffer\n");
        goto cleanup;
    }

    I6DEBUG(4, client, "Starting process me=%ph\n",&me);
    me->client = client;

    /* Set the option active */
    if (tcpbuffer)
        if (setsockopt(client->fd, SOL_SOCKET, SO_RCVBUF, &tcpbuffer,
                sizeof(tcpbuffer)))
        {
            ast_log(LOG_WARNING,
                    "Failed to configure RTMP SO_RCVBUF connection from TCP listening sock %d : %s\n",
                    client->fd, strerror(errno));
        }

    if (tcpbuffer)
        if (setsockopt(client->fd, SOL_SOCKET, SO_SNDBUF, &tcpbuffer,
                sizeof(tcpbuffer)))
        {
            ast_log(LOG_WARNING,
                    "Failed to configure RTMP SO_SNDBUF connection from TCP listening sock %d : %s\n",
                    client->fd, strerror(errno));
        }

    // Set KEEPALIVE
    if (tcpkeepalive)
    {
        int optval = 1;

        /* Set the option active */
        if (setsockopt(client->fd, SOL_SOCKET, SO_KEEPALIVE, &optval,
                sizeof(optval)))
        {
            ast_log(LOG_WARNING,
                    "Failed to configure RTMP KEEPALIVE connection from TCP listening sock %d : %s\n",
                    client->fd, strerror(errno));
        }

        optval = tcpkeepalive;
        if (setsockopt(client->fd, SOL_TCP, TCP_KEEPIDLE, (void *)&optval,
                sizeof(optval)) < 0)
        {
            ast_log(LOG_WARNING,
                    "Failed to configure RTMP KEEPALIVE connection from TCP listening sock %d : %s\n",
                    client->fd, strerror(errno));
        }

        optval = 3;
        if (setsockopt(client->fd, SOL_TCP, TCP_KEEPCNT, (void *)&optval,
                sizeof(optval)) < 0)
        {
            ast_log(LOG_WARNING,
                    "Failed to configure RTMP KEEPALIVE connection from TCP listening sock %d : %s\n",
                    client->fd, strerror(errno));
        }

        optval = tcpkeepalive;
        if (setsockopt(client->fd, SOL_TCP, TCP_KEEPINTVL, (void *)&optval,
                sizeof(optval)) < 0)
        {
            ast_log(LOG_WARNING,
                    "Failed to configure RTMP TCP_KEEPINTVL connection from TCP listening sock %d : %s\n",
                    client->fd, strerror(errno));
        }
    }

    // Set NODELAY
    if (tcpnodelay)
    {
        int optval = 1;

        /* Set the option active */
        if (setsockopt(client->fd, SOL_SOCKET, TCP_NODELAY, &optval,
                sizeof(optval)))
        {
            ast_log(LOG_WARNING,
                    "Failed to configure RTMP TCP_NODELAY connection from TCP listening sock %d : %s\n",
                    client->fd, strerror(errno));
        }
    }

    if (tcptls_session->ssl)
    {
        I6DEBUG(2, client, "Initialize SSL new session.\n");
        client->protocol |= RTMP_FEATURE_SSL;
        #ifdef _USE_RTMPT_
        if (rtmp_try_rtmpt(client)) {
            ast_log(LOG_ERROR, "rtmp_try_rtmpt failed\n");
            stats[STATS_DENIED]++;
            goto cleanup;
        }
        #endif //#ifdef _USE_RTMPT_
    }
    else
    {
        I6DEBUG(2, client, "Initialize new session.\n");
    }
    if (rtmp_handshake(client)) {
        ast_log(LOG_ERROR, "handshake failed\n");
        stats[STATS_DENIED]++;
        goto cleanup;
    }




    result++;

    //ast_log(LOG_ERROR, "LOCK\n");
    I6DEBUG(10, client, "Mutex lock 'rtmplock'.\n");
    ast_mutex_lock(&rtmplock);
    I6DEBUG(10, client, "Mutex locked 'rtmplock'.\n");
    stats[STATS_BIND]++;
    client->id = stats[STATS_BIND];

    I6DEBUG(10, client, "Mutex unlock 'rtmplock'.\n");
    ast_mutex_unlock(&rtmplock);

    stats[STATS_COUNT]++;
    if (stats[STATS_PEAK] < stats[STATS_COUNT])
        stats[STATS_PEAK] = stats[STATS_COUNT];

    /* mark main RTMP channels (0 to 3) as active */
    activate_channels(client, 0, 0);

    //ast_debug(0, "Send connect message\n");

    /* send connect message and wait for reply */
    client->state = RTMP_CONNECTED;

    if (debug)
        I6DEBUG(2, client, "Session connected.\n");

    memset(buffer, '\0', RTMP_RECV_BUFSIZE);

    // JYG-Watch-dog
#if 0
    //res = ast_tvdiff_ms(now, lastaudio);
    now = ast_tvnow();
    wdog_lastsend = now;
    // Send watch-dog msg
    rtmp_send_ping(client);
#endif

#ifdef _CHECK_CNX_RTMP_
    now = ast_tvnow();
    client->wdog_isalive = 0;
    client->wdog_prev_isalive = 0xFFFFFFFF;
    client->wdog_lastModifTime = now;
    client->wdog_startCheck = 0;
#endif

    res=0;
    while ((client->fd != (-1)) && (res != (-1)))
    {
        int buflen = 0;
        int channelid = 0;
        struct rtmp_message mtmp;
        int newmessage = 0;

        I6DEBUG(7, client, "Waiting new message.\n");

        /* receive first byte to get header length and channel id */
        res = rtmp_receive_data(client, buffer, 1, 200);
#ifdef _CHECK_CNX_RTMP_
        client->wdog_isalive++;
#endif

        now = ast_tvnow();

        if (res == (-1))
        {
            I6DEBUG(2, client, "RTMP socket closed\n");

            if (client->fd != (-1))
                close(client->fd);
            client->fd = (-1);

            stats[STATS_COUNT]--;

            goto cleanup;
        }

        // Send if buffered chunks
        if (client->chunks_buffer)
        {
            ast_mutex_lock(&client->lock);
            rtmp_send_data(client, NULL, 0);
            ast_mutex_unlock(&client->lock);
        }

        // Check watch-dog
#if 0                           // JYG Watch-dog
        if (client->wdog_wait_pong)
        {
            res = ast_tvdiff_ms(now, wdog_lastsend);
            if (res > 15000)          // WATCH_TIMEOUT 15 s
            {
                I6LOG(LOG_WARNING, client, "Watch-dog timeout. Close connection '%s'\n",
                        client->name);

                if (client->fd = (-1))
                    client->fd);
                    client->fd = (-1);
                    stats[STATS_COUNT]--;
                    goto cleanup;
            }
        }
        else
        {
            // check if we need to send PING
            res = ast_tvdiff_ms(now, wdog_lastsend);
            if (res > 30000)          // WATCH_FREQ 30 s
            {
                wdog_lastsend = now;
                rtmp_send_ping(client);
            }
        }
#endif


        if (res == 0)
        {
            if (client->pvt != NULL)
            {
                if (client->pvt->owner != NULL)
                    if (TEST_FLAG(client->pvt->owner, AST_FLAG_EMULATE_DTMF))
                    {
                        I6DEBUG(4, client, "RTMP socket timeout\n");
                        rtmp_handle_null_packet(client);
                    }
            }

            lastaudio = now;

            ast_mutex_unlock(&client->lock);

            continue;
        }

        res = ast_tvdiff_ms(now, lastaudio);
        if (res > maxsilence)
        {
            I6DEBUG(4, client, "Audio silence detected !\n");

            if (client->pvt != NULL)
            {
                if (client->pvt->owner != NULL)
                    if (TEST_FLAG(client->pvt->owner, AST_FLAG_EMULATE_DTMF))
                    {
                        if (debug)
                            I6DEBUG(4, client, "RTMP send NULL packet\n");

                        rtmp_handle_null_packet(client);
                    }
            }
            lastaudio = now;
        }

        I6DEBUG(7, client, "RTMP first=%02x\n", buffer[0]);
        I6DEBUG(4, client, "New RTMP message received\n");

        channelid = rtmp_get_channelid(buffer);
        I6DEBUG(7, client, "channelid = %d\n", channelid);

        mtmp.channelid = channelid;
        rtmp =
                ao2_t_find(rtmpmessages, &mtmp, OBJ_POINTER, "ao2 find in rtmpmessages");
        if (!rtmp)
        {
            I6DEBUG(3, client, "Allocate message id = %d\n", mtmp.channelid);
            //ast_log(LOG_ERROR, "Allocate message id = %d\n", mtmp.channelid);

            newmessage = 1;
            /* need to build a new message and insert it in our list */
            if (!(rtmp =
                    ao2_t_alloc(sizeof(*rtmp), rtmpmessage_destroy_fn,
                            "allocate RTMP message struct")))
            {

                stats[STATS_COUNT]--;

                rtmpmessage_unref(rtmp,
                        "release reference on RTMP message, should be destroyed now");
                goto cleanup;
            }
            rtmp->body = ast_malloc(RTMP_MAX_BODYSIZE);
            if (!rtmp->body)
            {
                stats[STATS_COUNT]--;

                rtmpmessage_unref(rtmp,
                        "release reference on RTMP message, should be destroyed now");
                goto cleanup;
            }
            memset(rtmp->body, '\0', RTMP_MAX_BODYSIZE);
            rtmp->bodyalloc = RTMP_MAX_BODYSIZE;
            rtmp->bodysize = 0;
        }
        else
        {
            I6DEBUG(3, client, "Found message id = %d\n", mtmp.channelid);
        }

        rtmp->channelid = rtmp_get_channelid(buffer);
        rtmp->hdrlen = rtmp_get_header_length(buffer);

        if (debug)
            I6DEBUG(6, client, "RTMP channelid=%d, header length=%d\n",
                    rtmp->channelid, rtmp->hdrlen);

        /* retrieve the remaining header bytes */
        if (rtmp->hdrlen > 1)
        {
            if (debug)
                I6DEBUG(4, client, "Retrieve the remaining header\n");
            //res = recv(client->fd, buffer, rtmp->hdrlen - 1, 0);
            res = rtmp_receive_data(client, buffer + 1, rtmp->hdrlen - 1, 5000);
            //res = recv(client->fd, buffer+1, rtmp->hdrlen - 1, MSG_WAITALL);
            //res=ast_tcptls_server_read2(tcptls_session, buffer, rtmp->hdrlen - 1);
            if (res == (-1))
            {
                ast_log(LOG_ERROR, "Connection closed !\n");

                stats[STATS_COUNT]--;

                rtmpmessage_unref(rtmp,
                        "release reference on RTMP message, should be destroyed now");
                goto cleanup;
            }

            if (res != (rtmp->hdrlen - 1))
            {
                ast_log(LOG_ERROR, "Connection mute !\n");

                stats[STATS_COUNT]--;

                rtmpmessage_unref(rtmp,
                        "release reference on RTMP message, should be destroyed now");
                goto cleanup;
            }

            rtmp_parse_header(rtmp, buffer + 1);
            rtmp_set_incoming_channelinfo(client, buffer + 1, rtmp->hdrlen,
                    rtmp->channelid);

            {
                char tmp[1024];
                sprintf(tmp, "RTMP/%p receive (header)", client);
                dump_buffer_hex(tmp, buffer, rtmp->hdrlen);
            }
        }
        else
        {
            char tmp[1024];
            sprintf(tmp, "RTMP/%p receive (header)", client);
            dump_buffer_hex(tmp, buffer, rtmp->hdrlen);
        }

        {
            rtmp->bodysize = rtmp_get_bodylen(client, buffer + 1, rtmp, RTMP_INCOMING);
            if (rtmp->bodysize > rtmp->bodyalloc)
            {
                if (rtmp->bodysize > 1622016)
                    I6LOG(LOG_WARNING, client, "Bodysize too long %d\n", rtmp->bodysize);

                I6DEBUG(3, client, "RTMP body reallocate with size %d\n",
                        rtmp->bodysize);

                rtmp->body = ast_realloc(rtmp->body, rtmp->bodysize);
                rtmp->bodyalloc = rtmp->bodysize;
                rtmp->bytesread = 0;
            }
        }

        I6DEBUG(7, client, "RTMP bodysize=%d, bytesread=%d type=%d\n",
                rtmp->bodysize, rtmp->bytesread, rtmp->type);

        if (rtmp->bodysize <= client->incoming_chunksize)
        {
            buflen = rtmp->bodysize;
        }
        else
        {
            if (rtmp->bodysize - rtmp->bytesread <= client->incoming_chunksize)
            {
                buflen = rtmp->bodysize - rtmp->bytesread;
            }
            else
            {
                buflen = client->incoming_chunksize;
            }
        }


        if (!rtmp->bodysize)
        {
            /* message has no body */
            if (!newmessage)
            {
                I6DEBUG(7, client, "Deleting RTMP message from list\n");
                ao2_t_unlink(rtmpmessages, rtmp,
                        "unlinking RTMP message via ao2_unlink");
            }
            rtmpmessage_unref(rtmp,
                    "release reference on RTMP message, should be destroyed now");
            continue;
        }

        /* retrieve the body parts */
        if (debug)
            I6DEBUG(4, client, "Retrieve the body parts %d\n", buflen);
        res = rtmp_receive_data(client, buffer, buflen, 5000);
        //res = recv(client->fd, buffer, buflen, MSG_WAITALL);
        //res=ast_tcptls_server_read2(tcptls_session, buffer, buflen);

        if (res == 0)
        {
      ast_log(LOG_ERROR, "RECV ERROR : Receive 0, or timeout!\n");

      stats[STATS_COUNT]--;

            rtmpmessage_unref(rtmp,
                    "release reference on RTMP message, should be destroyed now");
      goto cleanup;
    }
        else
            if (res == (-1))
            {
                //ast_log(LOG_ERROR, "Connection closed !\n");
                if (debug)
                    I6DEBUG(3, client, "Connection closed !\n");

                stats[STATS_COUNT]--;

                rtmpmessage_unref(rtmp,
                        "release reference on RTMP message, should be destroyed now");
                goto cleanup;
            }
            else
                if (res != buflen)
                {
                    ast_log(LOG_ERROR, "RECV ERROR : client %p, buflen %d != res %d !\n",
                            client, buflen, res);

                    stats[STATS_COUNT]--;

                    rtmpmessage_unref(rtmp,
                            "release reference on RTMP message, should be destroyed now");
                    goto cleanup;
                }

        {
            char tmp[1024];
            sprintf(tmp, "RTMP/%p receice (body part)", client);
            dump_buffer_hex(tmp, buffer, res);
        }

        if (buflen > rtmp->bodysize)
        {
            ast_log(LOG_ERROR, "MEMCPY ERROR : client %p, buflen %d > rtmp->bodysize %d !\n",
                    client, buflen, rtmp->bodysize);
            //exit(-1);

            stats[STATS_COUNT]--;

            rtmpmessage_unref(rtmp,
                    "release reference on RTMP message, should be destroyed now");
            goto cleanup;
        }

        if (buflen + rtmp->bytesread > rtmp->bodysize)
        {
            ast_log(LOG_ERROR, "MEMCPY ERROR : client %p, rtmp->bytesread %d + buflen %d > rtmp->bodysize %d!\n",
                    client, rtmp->bytesread, buflen, rtmp->bodysize);
            //exit(-1);

            stats[STATS_COUNT]--;

            rtmpmessage_unref(rtmp,
                    "release reference on RTMP message, should be destroyed now");
            goto cleanup;
        }

        // JYG mem
        // Check memory before
        if ((rtmp->bytesread + buflen) > rtmp->bodysize)
        {
            I6DEBUG(2, client, "Rcv lg buffer too long %d : bytesread %d bodysize=%d\n",
                    buflen, rtmp->bytesread, rtmp->bodysize);
            buflen = rtmp->bodysize - rtmp->bytesread ;
            //continue;
        }

        // CORE
        memcpy(rtmp->body + rtmp->bytesread, buffer, buflen);
        rtmp->bytesread += buflen;
        //ast_debug(0, "rtmp->bytesread = %d\n", rtmp->bytesread);

        if (rtmp->bytesread < rtmp->bodysize)
        {
            /* message has been partially retrieved, release
             * reference and link it to the messages list if it
             * was not found */
            if (newmessage)
            {
                I6DEBUG(5, client, "Inserted new RTMP message into list\n");
                ao2_t_link(rtmpmessages, rtmp, "link into RTMP messages table");
            }
            rtmpmessage_unref(rtmp, "Released a reference (rtmp_message)");
            continue;
        }

        {
            char tmp[1024];
            sprintf(tmp, "RTMP/%p receice (body)", client);
            dump_buffer_hex(tmp, rtmp->body, rtmp->bodysize);

        }

        I6DEBUG(7, client, "dbgjyg: me=0x%ph\n",me);
        if (debug)
            I6DEBUG(7, client, "RTMP bodysize=%d, bytesread=%d (complete)\n",
                    rtmp->bodysize, rtmp->bytesread);

        if (!client->streams[rtmp->channelid])
        {
            ast_log(LOG_WARNING,
                    "Ignoring message received on inactive RTMP channel %d\n",
                    rtmp->channelid);
            rtmpmessage_unref(rtmp, "Released a reference (rtmp_message)");
            continue;
        }

        /* message has been completely retrieved, process it */

        I6DEBUG(1,client, ">* channel/%d timestamp=%d, channelid=%d, type=0x%02X, streamid=%d, size=%d\n",
                rtmp->channelid, rtmp->timestamp, rtmp->channelid, rtmp->type, rtmp->streamid, rtmp->bodysize);

        if (rtmp->channelid < 4)
        {
            ast_mutex_lock(&client->lock);

            /* handle system messages here */
            switch (rtmp->channelid)
            {
                case 0:
                    break;
                case 1:
                    break;
                case RTMP_CHANNEL_SYSTEM:
                    I6DEBUG(1, client, "RTMP message SYSTEM\n");
                    rtmp_handle_system_message(client, rtmp);
                    break;
                case RTMP_CHANNEL_CONNECT:
                    I6DEBUG(1, client, "RTMP message CONNECT\n");
                    rtmp_handle_connect_message(client, rtmp);
                    break;
            }

            ast_mutex_unlock(&client->lock);


            /* release the reference on this message, which should be
             * destroyed by Asterisk */
            if (!newmessage)
            {
                //rtmpmessage_ref(rtmp, "Let's bump the count in the unlink so it doesn't accidentally become dead before we are done");

                if (debug)
                    I6DEBUG(5, client, "Deleting RTMP message from list\n");
                ao2_t_unlink(rtmpmessages, rtmp,
                        "unlinking RTMP message via ao2_unlink");
                //rtmpmessage_unref(rtmp, "Dereferecing RTMP message after it has been unlinked");
            }
            rtmpmessage_unref(rtmp,
                    "release reference on RTMP message, should be destroyed now");

            continue;
        }

        I6DEBUG(3, client, "TYPE %d CHANNEL %d\n",
                client->streams[rtmp->channelid]->type[RTMP_INCOMING],
                (rtmp->channelid) % RTMP_STREAM_CHANNEL_RANGE);



        switch (client->streams[rtmp->channelid]->type[RTMP_INCOMING])
        {
            case RTMP_TYPE_PING:
                I6DEBUG(3, client, "Received PING message for channel with id %d\n",
                        rtmp->channelid);
                break;

            case RTMP_TYPE_AUDIO_DATA:
                I6DEBUG(3, client, "Received AUDIO message for channel with id %d\n",
                        rtmp->channelid);
                rtmp_handle_audio_packet(client, rtmp);
                lastaudio = now;
                break;

            case RTMP_TYPE_VIDEO_DATA:
                if (debug)
                    I6DEBUG(3, client, "Received VIDEO message for channel with id %d\n",
                            rtmp->channelid);
                if (videosupport)
                    rtmp_handle_video_packet(client, rtmp);
                else
                    ast_log(LOG_WARNING,
                            "Video support disabled, message skipped from channel\n");
                break;

            case RTMP_TYPE_NOTIFY:
                I6DEBUG(5, client, "Received NOTIFY message for channel with id %d\n",
                        rtmp->channelid);
                rtmp_handle_notify_packet(client, rtmp);
                break;

            case RTMP_TYPE_INVOKE:
                I6DEBUG(5, client, "Received INVOKE message for channel with id %d\n",
                        rtmp->channelid);
                ast_mutex_lock(&client->lock);
                rtmp_handle_control_message(client, rtmp);
                ast_mutex_unlock(&client->lock);
                break;
        }

        /* release the reference on this message, which should be
         * destroyed by Asterisk */
        if (!newmessage)
        {
            //rtmpmessage_ref(rtmp, "Let's bump the count in the unlink so it doesn't accidentally become dead before we are done");

            I6DEBUG(5, client, "Deleting RTMP message from list\n");
            ao2_t_unlink(rtmpmessages, rtmp, "unlinking RTMP message via ao2_unlink");
            //rtmpmessage_unref(rtmp, "Dereferecing RTMP message after it has been unlinked");
        }
        rtmpmessage_unref(rtmp,
                "release reference on RTMP message, should be destroyed now");
    }

    stats[STATS_COUNT]--;

    cleanup:
    I6DEBUG(4, client, "Cleanup server.\n");
    ast_mutex_lock(&rtmplock);
    me->client = NULL;
    ast_mutex_unlock(&rtmplock);

    // Try to hangup the Asterisk
    ast_mutex_lock(&client->lock);

    if (client->name[0])
    {
        http_request("", client->name, "", NULL, NULL);

        if (result == 1)
            ast_verbose(VERBOSE_PREFIX_3 "Unregistered RTMP/%p '%s' (%s)\n", client,
                    client->name, getUsedRtmpProtocolName(client));

        if (events)
        {
            struct in_addr temp_addr;
            TCPTLS_SESSION_ADDRESS(client->threadinfo->tcptls_session->remote_address,
                    temp_addr.s_addr);
            manager_event(EVENT_FLAG_SYSTEM, "Registry",
                    "ChannelType: RTMP\r\nUsername: %s\r\nDomain: %s:%d\r\nStatus: %s\r\n",
                    client->name, client->address, client->port,
                    "Unregistered");
        }
    }

    client->publishing = 0;
    client->playing = 0;
    client->playing2 = 0;

    result++;

    if (dumpstats)
    {
        struct tm *tmvalue;
        time_t now;

        int duration;
        int duration2;

        int numBytes = (-1);

        time(&now);

        duration = 0;
        duration2 = 0;

        if (client->callstop)
        {
            duration = client->callstop - client->callstart;
            if (client->callanswer)
                duration2 = client->callstop - client->callanswer;
        }
        else
        {
            if (client->callstart)
                duration = now - client->callstart;
            if (client->callanswer)
                duration2 = now - client->callanswer;
        }

        ast_log(LOG_NOTICE, "  ID:                     RTMP/%p\n", client);
        ast_log(LOG_NOTICE, "  Name:                   %s\n", client->name);
        ast_log(LOG_NOTICE, "  User:                   %s\n",
                (client->user ? " " : "*"));

        tmvalue = localtime(&client->date);
        ast_log(LOG_NOTICE,
                "  Date:                   %04d/%02d/%02d %02d:%02d:%02d\n",
                tmvalue->tm_year + 1900, tmvalue->tm_mon + 1, tmvalue->tm_mday,
                tmvalue->tm_hour, tmvalue->tm_min, tmvalue->tm_sec);

        ioctl(client->fd, SIOCOUTQ, &numBytes);

        char formatbuf[256];
        strcpy(formatbuf, GET_FORMAT_NAME(client->audiocodec));

        ast_log(LOG_NOTICE, "  Codec Capability:       %s\n", formatbuf);

        //ast_log(LOG_NOTICE, "  Format:                 %s\n", formatbuf);

        ast_log(LOG_NOTICE, "  Addr->IP:               %s Port %d\n",  client->address, client->port);
        ast_log(LOG_NOTICE, "  Streams IDs:            P=%f, A=%f, V=%f\n",
                client->publishstream, client->playstream, client->playstream2);
        ast_log(LOG_NOTICE, "  Streams status:         P=%d, A=%d, V=%d\n",
                client->publishing, client->playing, client->playing2);
        ast_log(LOG_NOTICE, "  Counters:               I=%d, O=%d in bytes\n",
                client->incoming_bytescount, client->outgoing_bytescount);
        ast_log(LOG_NOTICE, "  Bandwidth:              I=%d, O=%d in bytes/s\n",
                client->incoming_bandwidth, client->outgoing_bandwidth);
        ast_log(LOG_NOTICE, "  Calls counters:         I=%d, O=%d\n",
                client->incoming_calls, client->outgoing_calls);
        ast_log(LOG_NOTICE, "  Image frames:           I=%d, O=%d\n",
                client->incoming_images, client->outgoing_images);
        if (duration)
            ast_log(LOG_NOTICE, "  Frames per seconde:     I=%dfps, O=%dfps\n",
                    client->incoming_images / duration, client->outgoing_images / duration);
        ast_log(LOG_NOTICE, "  Incoming lost packets:  A=%d/%d, V=%d/%d\n",
                client->incoming_audiolost, client->incoming_audio,
                client->incoming_videolost, client->incoming_video);
        ast_log(LOG_NOTICE, "  Outgoing lost packets:  A=%d/%d, V=%d/%d\n",
                client->outgoing_audiolost, client->outgoing_audio,
                client->outgoing_videolost, client->outgoing_video);
        ast_log(LOG_NOTICE, "  Burst packets:          M=%d, C=%d\n",
                client->burst_max, client->burst_counter);
        if (client->pvt)
            ast_log(LOG_NOTICE, "  Status:                 %s\n",
                    (client->pvt ? "CALL" : "HANGUP"));
        ast_log(LOG_NOTICE, "  Duration:               %d(+%d)s\n", duration2,
                duration - duration2);

        if (client->pvt)
            ast_log(LOG_NOTICE, "  Mode:                   %s\n",
                    (client->pvt->mode ? "direct" : "signaling"));
        ast_log(LOG_NOTICE, "  Buffer:                 %d/%d A=%d, V=%d\n",
                numBytes, tcpbuffer, maxaudiobuffer, maxvideobuffer);
        ast_log(LOG_NOTICE, "  Pipe:                   %d/%d A=%d, V=%d\n", 0, 0,
                maxaudiopipe, maxvideopipe);
        ast_log(LOG_NOTICE, "  Socket FD:              %d\n", client->fd);
    }

    // Close TCPconnection
    if (client->fd != (-1))
    {
        close(client->fd);
        client->fd = (-1);
    }

    // Disconnect user
    if (client->user)
    {
        client->user->client = NULL;
        client->user = NULL;
    }

    // Wait Hangup and channel free
    if (client->pvt)
    {
        int maxloop = 10; // for 5 seconds
        int hangupsend = 0;

        while ((client->pvt) && maxloop)
        {
            struct timeval tv;

            ast_mutex_unlock(&client->lock);

            I6DEBUG(3, client, "Wait channel release.\n");

            /* Calculate sleep time */
            memset(&tv, 0, sizeof(tv));
            tv.tv_sec = 0;
            tv.tv_usec = 500000;

            /* Sleep wait hangup */
            select(0, 0, 0, 0, &tv);

            ast_mutex_lock(&client->lock);

            if (client->pvt)
            {
                I6DEBUG(2, client, "Trying to hangup the channel.\n");
                //ast_log(LOG_WARNING, "Trying to hangup the channel\n");

                if (!hangupsend)
                {
                    I6DEBUG(2, client, "try Send Hangup %s\n", GET_CHAN_NAME(client->pvt->owner));

                    if (!ast_channel_trylock(client->pvt->owner))
                    {
                        I6DEBUG(2, client, "Send Hangup %s\n", GET_CHAN_NAME(client->pvt->owner));
                        ast_queue_hangup(client->pvt->owner);
                        ast_channel_unlock(client->pvt->owner);
                        hangupsend = 1;
                    }
                }
                maxloop--;
            }
        }

        if (!maxloop)
            ast_log(LOG_WARNING, "RTMP close client without clean hangup\n");

        client->pvt = NULL;

        I6DEBUG(2, client, "RTMP channel closed.\n");
    }

    RTMP_VERBOSE(client, "Connection closed.\n");

    I6DEBUG(3, client, "RTMP Message in container = %d\n", ao2_container_count(rtmpmessages));

    /* Free the RTMP messages list */
    aux = ao2_iterator_init(rtmpmessages, 0);
    while ((rtmp = ao2_t_iterator_next(&aux, "iterate thru RTMP messages")))
    {
        rtmpmessage_unref(rtmp, "toss RTMP message ptr from iterator_next");
    }
    ao2_iterator_destroy(&aux);

    ao2_t_callback(rtmpmessages, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE, NULL, NULL, "Unallocate rtmp messages");
    ao2_t_ref(rtmpmessages, -1, "Unref rtmp messages");

    if (debug)
        I6DEBUG(5, client, "Freeing allocations.\n");


    if (buffer)
        ast_free(buffer);

    if (client->buffer)
        ast_free(client->buffer);

    if (client->chunks_buffer)
    {
        ast_free(client->chunks_buffer);
    }

    client->chunks_buffer = NULL;

    if (client->address)
    {
        // thread free this context.
        //ast_free(client->address);
    }

    I6DEBUG(10, client, "Mutex unlock 'client'.\n");
    ast_mutex_unlock(&client->lock);

    ast_mutex_destroy(&client->lock);
    I6DEBUG(10, client, "Mutex destroy 'client'.\n");

    if (client->name[0])
        realtime_update_user(client->name, NULL, NULL);

    for (i = 0; i < RTMP_MAX_CHANNELS; i++)
    {
        ast_free(client->streams[i]);
    }

    ast_free(client);
    client = NULL;

    if (debug)
        ast_debug(5, "Server terminated.\n");

    return result;
}

static int check_handshake_reply(void *buffer, size_t size)
{
    int res = (-1);
    uint8_t handshake[2 * RTMP_BLOCK_SIZE + 1];

    /* expected reply */
    memset(&handshake, 0x00, 2 * RTMP_BLOCK_SIZE + 1);
    handshake[0] = 0x03;
    handshake[4] = 0x01;

    if (!memcmp(handshake, buffer, 2 * RTMP_BLOCK_SIZE))
    {
        /* skip last byte because its value is not always the same! */
        if (debug)
            ast_debug(3, "Handshake test passed, buffer size = %d\n", (int)size);
        res = RTMP_HANDSHAKE_OK;
    }

    return res;
}


/** \brief Send PONG message back to server
 * \param rtmp the received PING message
 * \note body size is the same in both directions
 *
 */
static int rtmp_send_pong(struct rtmp_client *client, struct rtmp_message *rtmp)
{
    int res = (-1);
    void *message = NULL;
    void *aux = NULL;
    uint16_t pingtype = htons(RTMP_PING_TYPE_PONG);
    struct rtmp_message *pong = NULL;
    int hdrlen = 0;
    int msglen = 0;
    int current_bodylen = 0;
    int current_type = 0;
    uint32_t pingtimestamp = 0;

    I6DEBUG(7, client, "Sending PING message (timestamp = %d)\n", pingtimestamp);

    RTMP_VERBOSE(client, "<* message/pong(%d)\n", pingtimestamp);

    pong = ast_calloc(1, sizeof(*pong));
    if (!pong)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }
    /* populate our PONG packet */
    pong->channelid = RTMP_CHANNEL_SYSTEM;
    pong->bodysize = RTMP_PING_DEFAULTBODYSIZE;
    pong->type = RTMP_TYPE_PING;
    pong->streamid = 0;
    pong->timestamp = 0;

    current_bodylen = rtmp_get_current_bodylen(client, rtmp->channelid);
    current_type = rtmp_get_current_type(client, rtmp->channelid);
    rtmp_get_current_timestamp(client, rtmp->channelid);
    rtmp_get_current_streamid(client, rtmp->channelid);


    if (pong->type != current_type || pong->bodysize != current_bodylen)
    {
        hdrlen = 12;
    }
    else
    {
        hdrlen = 1;
    }

    pong->hdrlen = hdrlen;
    msglen = hdrlen + RTMP_PING_DEFAULTBODYSIZE;

    message = ast_calloc(1, msglen);
    if (!message)
    {
        res = (-1);
        goto safeout;
    }

    aux = message;
    res = rtmp_set_header(aux, pong, hdrlen);
    if (!res)
    {
        ast_log(LOG_ERROR, "Error while setting header\n");
        return res;
    }

    aux += res;
    /* set ping type (2 bytes long) */
    memcpy(aux, &pingtype, 2);
    aux += 2;

    /* set timestamp (4 bytes long) */
    memcpy(aux, rtmp->body + 2, 4);

    res = rtmp_send_message(client, NULL, message, pong->bodysize, rtmp->type);

    safeout:
    ast_free(pong);
    ast_free(message);
    return res;
}

#if 0
/** \brief Send PING message to client
 * \param rtmp the received PING message
 * \note body size is the same in both directions
 *
 */
static int rtmp_send_ping(struct rtmp_client *client)
{
    int res = (-1);
    void *message = NULL;
    void *aux = NULL;
    uint16_t pingtype = htons(RTMP_PING_TYPE_PING);
    struct rtmp_message *ping = NULL;
    int hdrlen = 0;
    int msglen = 0;
    int current_bodylen = 0;
    int current_type = 0;
    uint32_t pingtimestamp = 0;

    I6DEBUG(7, client, "Sending PING message (timestamp = %d)\n", pingtimestamp);

    RTMP_VERBOSE(client, "<* message/ping(%d)\n", pingtimestamp);

    ping = ast_calloc(1, sizeof(*ping));
    if (!ping)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }
    /* populate our PING packet */
    ping->channelid = RTMP_CHANNEL_SYSTEM;
    ping->bodysize = RTMP_PING_DEFAULTBODYSIZE;
    ping->type = RTMP_TYPE_PING;
    ping->streamid = 0;
    ping->timestamp = 0;

    /*current_bodylen = rtmp_get_current_bodylen(client, rtmp->channelid);
     current_type = rtmp_get_current_type(client, rtmp->channelid);
     rtmp_get_current_timestamp(client, rtmp->channelid);
     rtmp_get_current_streamid(client, rtmp->channelid);

     if (pong->type != current_type || pong->bodysize != current_bodylen) {
     hdrlen = 12;
     } else {
     hdrlen = 1;
     }
     */
    hdrlen = 12;

    ping->hdrlen = hdrlen;
    msglen = hdrlen + RTMP_PING_DEFAULTBODYSIZE;

    message = ast_calloc(1, msglen);
    if (!message)
    {
        res = (-1);
        goto safeout;
    }

    aux = message;
    res = rtmp_set_header(aux, ping, hdrlen);
    if (!res)
    {
        ast_log(LOG_ERROR, "Error while setting header\n");
        return res;
    }

    aux += res;
    /* set ping type (2 bytes long) */
    memcpy(aux, &pingtype, 2);
    aux += 2;

    /* set timestamp (4 bytes long) */
    //memcpy(aux, rtmp->body + 2, 4);

    res =
            rtmp_send_message(client, NULL, message, ping->bodysize, RTMP_TYPE_PING);
    client->wdog_wait_pong = 1;

    safeout:
    ast_free(ping);
    ast_free(message);
    return res;
}
#endif



/** \brief Send CHUNKSIZE message to server
 */
static int rtmp_send_chunksize(struct rtmp_client *client,
        uint32_t newchunksize)
{
    int res = (-1);
    void *message = NULL;
    void *aux = NULL;
    struct rtmp_message *rtmp = NULL;
    int hdrlen = 0;
    int msglen = 0;
    int current_bodysize = 0;
    int current_type = 0;
    int current_streamid = 0;
    int current_timestamp = 0;

    RTMP_VERBOSE(client, "<* message/chunksize(%d)\n", newchunksize);

    newchunksize = htonl(newchunksize);

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }
    /* populate our packet */
    rtmp->channelid = RTMP_CHANNEL_SYSTEM;
    rtmp->bodysize = sizeof(newchunksize);
    rtmp->type = RTMP_TYPE_CHUNK_SIZE;
    rtmp->streamid = 0;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;

    current_bodysize = rtmp_get_current_bodylen(client, rtmp->channelid);
    current_type = rtmp_get_current_type(client, rtmp->channelid);
    current_timestamp = rtmp_get_current_timestamp(client, rtmp->channelid);
    current_streamid = rtmp_get_current_streamid(client, rtmp->channelid);

    if (rtmp->streamid != current_streamid)
    {
        hdrlen = 12;
    }
    else if (rtmp->type != current_type || rtmp->bodysize != current_bodysize)
    {
        hdrlen = 8;
    }
    else if (rtmp->timestamp != current_timestamp)
    {
        hdrlen = 4;
    }
    else
    {
        hdrlen = 1;
    }

    rtmp->hdrlen = hdrlen;
    msglen = hdrlen + rtmp->bodysize;

    message = ast_calloc(1, msglen);
    if (!message)
    {
        res = (-1);
        goto safeout;
    }

    aux = message;
    res = rtmp_set_header(aux, rtmp, hdrlen);
    if (!res)
    {
        I6LOG(LOG_ERROR, client, "Error while setting header\n");
        return res;
    }

    aux += res;

    /* set chunksize (4 bytes long, low-endian) */
    memcpy(aux, &newchunksize, sizeof(newchunksize));

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}


/** \brief Send ACKNOWLEDGEMENT message to server
 */
static int rtmp_send_acknowledgement(struct rtmp_client *client,
        uint32_t bytesread)
{
    int res = (-1);
    void *message = NULL;
    void *aux = NULL;
    struct rtmp_message *rtmp = NULL;
    int hdrlen = 0;
    int msglen = 0;
    int current_bodysize = 0;
    int current_type = 0;
    int current_streamid = 0;
    int current_timestamp = 0;

    RTMP_VERBOSE(client, "<* message/acknowledgement(%d)\n", bytesread);

    client->lastack = bytesread;

    bytesread = htonl(bytesread);

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }
    /* populate our packet */
    rtmp->channelid = RTMP_CHANNEL_SYSTEM;
    rtmp->bodysize = sizeof(bytesread);
    rtmp->type = RTMP_TYPE_BYTES_READ;
    rtmp->streamid = 0;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;

    current_bodysize = rtmp_get_current_bodylen(client, rtmp->channelid);
    current_type = rtmp_get_current_type(client, rtmp->channelid);
    current_timestamp = rtmp_get_current_timestamp(client, rtmp->channelid);
    current_streamid = rtmp_get_current_streamid(client, rtmp->channelid);

    if (rtmp->streamid != current_streamid)
    {
        hdrlen = 12;
    }
    else if (rtmp->type != current_type || rtmp->bodysize != current_bodysize)
    {
        hdrlen = 8;
    }
    else if (rtmp->timestamp != current_timestamp)
    {
        hdrlen = 4;
    }
    else
    {
        hdrlen = 1;
    }

    rtmp->hdrlen = hdrlen;
    msglen = hdrlen + rtmp->bodysize + RTMP_EXTENDEDTIMESTAMP_SIZE;

    message = ast_calloc(1, msglen);
    if (!message)
    {
        res = (-1);
        goto safeout;
    }

    aux = message;
    res = rtmp_set_header(aux, rtmp, hdrlen);
    if (!res)
    {
        ast_log(LOG_ERROR, "Error while setting header\n");
        return res;
    }

    aux += res;

    /* set chunksize (4 bytes long, low-endian) */
    memcpy(aux, &bytesread, sizeof(bytesread));

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send buffer time to server */
static int rtmp_send_buffertime(struct rtmp_client *client, uint32_t streamid)
{
    int res = (-1);
    uint8_t *message = NULL;
    uint8_t *aux = NULL;
    uint16_t pingtype = htons(RTMP_PING_TYPE_TIME);
    struct rtmp_message buffertime;
    int hdrlen = 0;
    int msglen = 0;

    /* populate our PING packet */
    buffertime.channelid = RTMP_CHANNEL_SYSTEM;
    buffertime.bodysize = 2 + 4 + 4;
    buffertime.type = RTMP_TYPE_PING;
    buffertime.streamid = streamid;
    buffertime.timestamp = 0;
    buffertime.timestampdelta = 0;

    hdrlen = 12;
    msglen = hdrlen + buffertime.bodysize;

    message = ast_calloc(1, msglen);
    if (!message)
    {
        return -1;
    }

    aux = message;
    res = rtmp_set_header(message, &buffertime, hdrlen);
    if (!res)
    {
        ast_log(LOG_ERROR, "Error while setting header\n");
        return res;
    }

    aux += res;
    /* set ping type (2 bytes long) */
    memcpy(aux, &pingtype, 2);
    aux += 2;

    /* set timestamp (4 bytes long) */
    memcpy(aux, &buffertime.streamid, 4);
    aux += 4;

    /* set buffer time to zero */
    memset(aux, '\0', 4);

    res = rtmp_set_outgoing_channelinfo(client, &buffertime, 8);

    res = rtmp_send_data(client, message, msglen);
    //res = send(client->fd, message, msglen, 0);


    return res;
}

#if 0
/* \brief Send a message to create a new stream
 *
 * The Action Script function prototype is :
 * createstream(double ClientStream, NULL)
 */
static int rtmp_send_createstream(struct rtmp_client *client, double streamid)
{
    int res = (-1);
    struct rtmp_message *rtmp = NULL;
    void *message = NULL;
    void *aux = NULL;
    char *method = "createStream";

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_createstream\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 8-byte header, the connection object is implicit */
    rtmp->hdrlen = 8;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    /* string header length (1 + 2) + string length
     * + double header length (1) + double length (8)
     * + NULL packet length (1) */
    rtmp->bodysize = 1 + 2 + strlen(method) + 1 + 8 + 1;

    message = ast_calloc(1, rtmp->hdrlen + rtmp->bodysize);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    aux = message;
    res = rtmp_set_header(message, rtmp, 8);
    if (!res)
    {
        goto safeout;
    }
    aux += res;

    res = rtmp_set_string(aux, method, strlen(method));
    if (!res)
    {
        goto safeout;
    }
    aux += res;

    res = rtmp_set_number(aux, &streamid);
    if (!res)
    {
        goto safeout;
    }
    aux += res;

    res = rtmp_set_null(aux);

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}
#endif

#if 0
/* \brief Send a message to delete stream
 * The Action Script function prototype is : i
 * closestream(double 0, NULL, double ClientStream)
 */
static int rtmp_send_closestream(struct rtmp_client *client, double streamid)
{
    int res = (-1);
    struct rtmp_message *rtmp = NULL;
    void *message = NULL;
    void *aux = NULL;
    char *method = "closeStream";
    double zero = 0.0;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_closestream\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 8-byte header, the connection object is implicit */
    rtmp->hdrlen = 8;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONTROL;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;

    /* string header length (1 + 2) + string length
     * + double header length (1) + double length (8)
     * + NULL packet length (1)
     * + double header length (1) + double length (8) */
    rtmp->bodysize = 1 + 2 + strlen(method) + 1 + 8 + 1;

    message = ast_calloc(1, rtmp->hdrlen + rtmp->bodysize);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    aux = message;
    res = rtmp_set_header(message, rtmp, 8);
    if (!res)
    {
        goto safeout;
    }
    aux += res;

    res = rtmp_set_string(aux, method, strlen(method));
    if (!res)
    {
        goto safeout;
    }
    aux += res;

    res = rtmp_set_number(aux, &zero);
    if (!res)
    {
        goto safeout;
    }
    aux += res;

    res = rtmp_set_null(aux);

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}
#endif

/** \brief Send instructions to play a stream
 *
 * We send the following messages in sequence :
 * - Invoke("receiveAudio", 0, NULL, TRUE)
 * - PING(streamid, buffertime)
 * - Invoke("receiveVideo", 0, NULL, FALSE)
 * - Invoke("play", 0, NULL, "name")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_play(struct rtmp_client *client, uint32_t streamid,
        char *name)
{
    int res = (-1);
    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_play\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONTROL;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = streamid;

    rtmp_get_current_hdrlen(client, rtmp->channelid);

    message =
            rtmp_build_invoke(rtmp, "receiveAudio", streamid, NULL, NULL,
                    AMF_BOOLEAN_TRUE, NULL);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }
    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);
    ast_free(message);
    message = NULL;

    res = rtmp_send_buffertime(client, streamid);

    message =
            rtmp_build_invoke(rtmp, "receiveVideo", streamid, NULL, NULL,
                    AMF_BOOLEAN_FALSE, NULL);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }
    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);
    ast_free(message);
    message = NULL;

    message = rtmp_build_invoke(rtmp, "play", streamid, NULL, name, NULL, NULL);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }
    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);
    ast_verbose("Sending play request for stream with id %d and name %s\n",
            streamid, name);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_publish(struct rtmp_client *client, uint32_t streamid,
        char *name)
{
    int res = (-1);
    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_publish\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONTROL;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = streamid;

    message =
            rtmp_build_invoke(rtmp, "publish", streamid, NULL, name, NULL, "live");
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);
    ast_verbose("Sending publish request for stream with id %d and name %s\n",
            streamid, name);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_invited(struct rtmp_client *client, char *callerid)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_invited\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = 0;

    message =
            rtmp_build_request_message2(rtmp, "invited", 0, callerid, "callerid");
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_autoanswer(struct rtmp_client *client, char *callerid)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_autoanswer\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = 0;

    message =
            rtmp_build_request_message2(rtmp, "autoanswer", 0, callerid, "callerid");
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_spyed(struct rtmp_client *client, char *callerid)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_spyed\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = 0;

    message = rtmp_build_request_message2(rtmp, "spyed", 0, callerid, "callerid");
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_bye(struct rtmp_client *client)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_bye\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = 0;

    message = rtmp_build_request_message(rtmp, "bye", 0, NULL);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_text(struct rtmp_client *client, const char *text)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    stats[STATS_TEXTS]++;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_text\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = 0;

    message = rtmp_build_request_message2(rtmp, "send", 0, "text", (char *)text);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    RTMP_VERBOSE(client, "<* message/send(text,%s)\n", text);

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}


/** \brief Send response of function request
 *
 *
 */
static int rtmp_send_function(struct rtmp_client *client, const char *text)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_function\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = 0;

    message =
            rtmp_build_request_message2(rtmp, "send", 0, "function", (char *)text);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }
    /*RTMP_VERBOSE( */
    I6DEBUG(1, client, "<* message/send(function,%s)\n", text);

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send response of function request
 *
 *
 */
static int rtmp_send_event(struct rtmp_client *client, const char *text)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_event\n");

    stats[STATS_EVENTS]++;

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = 0;

    message = rtmp_build_request_message2(rtmp, "send", 0, "event", (char *)text);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    RTMP_VERBOSE(client, "<* message/send(event,%s)\n", text);

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send response of function request
 *
 *
 */
static int rtmp_send_registered(struct rtmp_client *client, const char *text)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_registered\n");

    stats[STATS_EVENTS]++;

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = 0;

    message =
            rtmp_build_request_message2(rtmp, "send", 0, "registered", (char *)text);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    RTMP_VERBOSE(client, "<* message/send(registered,%s)\n", text);

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send response of function request
 *
 *
 */
static int rtmp_send_unregistered(struct rtmp_client *client, const char *text)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_unregistered\n");

    stats[STATS_EVENTS]++;

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = 0;

    message =
            rtmp_build_request_message2(rtmp, "send", 0, "unregistered", (char *)text);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    RTMP_VERBOSE(client, "<* message/send(unregistered,%s)\n", text);

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_dtmf(struct rtmp_client *client, char digit)
{
    int res = (-1);
    char text[2] = "?";

    text[0] = digit;

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_dtmf\n");

    stats[STATS_DTMFS]++;

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = 0;

    message = rtmp_build_request_message2(rtmp, "send", 0, "dtmf", text);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    RTMP_VERBOSE(client, "<* message/send(dtmf,%c)\n", digit);

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}
/** \brief Send admin cmd
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_admin(struct rtmp_client *client, const char *text)
{
    int res = (-1);
    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_admin\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = 0;

    message = rtmp_build_request_message2(rtmp, "send", 0, "admin", (char *)text);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    RTMP_VERBOSE(client, "<* message/send(admin,%s)\n", text);

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_result_connect(struct rtmp_client *client,
        uint32_t streamid, double connectionid, char *level, char *code,
        char *description)
{
    int res = (-1);
    struct amf_object *object = NULL;

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    double objectencoding = 0.0;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_reply\n");

    object = ast_calloc(1, sizeof(*object));
    if (!object)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    if (debug)
        I6DEBUG(3, client, "streamid = %d\n", streamid);

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = streamid;

    object->size = 0;

    /* Populate the AMF object
     * In the case of the Response method, the AMF object must contain
     * the following basic objects :
     * - app : the application identifier to connect to
     * - swfUul : referrer to the SWF file
     * Property names are case sensitive */
    //amf_add_bobject(object, AMF_TYPE_NULL, "", NULL);
    amf_add_bobject(object, AMF_TYPE_STRING, "description", description);
    amf_add_bobject(object, AMF_TYPE_STRING, "code", code);
    amf_add_bobject(object, AMF_TYPE_NUMBER, "objectEncoding", &objectencoding);
    amf_add_bobject(object, AMF_TYPE_NULL, "details", NULL);
    amf_add_bobject(object, AMF_TYPE_STRING, "level", level);
    //amf_add_bobject(object, AMF_TYPE_STRING, "", "");

    message = rtmp_build_result_connect(rtmp, "_result", connectionid, object);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);
    if (debug)
        I6DEBUG(3, client,
                "Sending response request for stream with id %d and name %s\n", streamid,
                "level");

    safeout:
    amf_destroy_object(object);
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_result_createstream(struct rtmp_client *client,
        uint32_t streamid, double connectionid, double result)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_reply\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    if (debug)
        I6DEBUG(3, client, "streamid = %d\n", streamid);

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = streamid;

    if (result >= 0)
        message =
                rtmp_build_result_createstream(rtmp, "_result", connectionid, result);
    else
        message =
                rtmp_build_result_createstream(rtmp, "_error", connectionid, result);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);
    if (debug)
        I6DEBUG(3, client,
                "Sending response request for stream with id %d and name %s\n", streamid,
                "level");

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_result_invite(struct rtmp_client *client,
        uint32_t streamid, double connectionid, char *result, char *description)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_reply\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    if (debug)
        I6DEBUG(3, client, "streamid = %d\n", streamid);

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = streamid;

    if (result)
        message =
                rtmp_build_result_message(rtmp, result, connectionid, description);
    else
        message = rtmp_build_result_message(rtmp, "_result", connectionid, NULL);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);
    if (debug)
        I6DEBUG(3, client,
                "Sending response request for stream with id %d and name %s\n", streamid,
                "level");

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_result_accepted(struct rtmp_client *client,
        uint32_t streamid, double connectionid, char *result, char *description)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_reply streamid = %d\n", streamid);

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }


    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = streamid;

    if (result)
        message =
                rtmp_build_request_message(rtmp, result, connectionid, description);
    else
        message = rtmp_build_request_message(rtmp, "_result", connectionid, NULL);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);
    if (debug)
        I6DEBUG(3, client,
                "Sending response request for stream with id %d and name %s\n", streamid,
                "level");

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}


/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_result_rejected(struct rtmp_client *client,
        uint32_t streamid, double connectionid, char *result, char *description)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_result_rejected  streamid = %d\n",
                streamid);

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = streamid;

    if (result)
        message =
                rtmp_build_request_message(rtmp, "rejected", connectionid, result);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);
    if (debug)
        I6DEBUG(3, client,
                "Sending response request for stream with id %d and name %s\n", streamid,
                "level");

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_result_cancelled(struct rtmp_client *client,
        uint32_t streamid, double connectionid, char *result, char *callerid)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_result_cancelled\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        I6LOG(LOG_ERROR, client, "Memory allocation failure\n");
        return res;
    }

    if (debug)
        I6DEBUG(3, client, "streamid = %d\n", streamid);

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = streamid;

    if (result)
        //message = rtmp_build_request_message(rtmp, "cancelled", connectionid, result);
        message =
                rtmp_build_request_message2(rtmp, "cancelled", 0, callerid, "callerid");

    if (!message)
    {
        I6LOG(LOG_ERROR, client, "Could not set buffer\n");
        goto safeout;
    }

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);
    if (debug)
        I6DEBUG(3, client,
                "Sending response request for stream with id %d and name %s\n", streamid,
                "level");

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_result_publish(struct rtmp_client *client,
        uint32_t channelid, uint32_t streamid, double connectionid, char *description)
{
    int res = (-1);
    struct amf_object *object = NULL;

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_reply streamid = %d\n", streamid);


    object = ast_calloc(1, sizeof(*object));
    if (!object)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = channelid;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = streamid;

    object->size = 0;

    /* Populate the AMF object
     * In the case of the Response method, the AMF object must contain
     * the following basic objects :
     * - app : the application identifier to connect to
     * - swfUul : referrer to the SWF file
     * Property names are case sensitive */
    //amf_add_bobject(object, AMF_TYPE_NULL, "", NULL);
    amf_add_bobject(object, AMF_TYPE_STRING, "description", description);
    amf_add_bobject(object, AMF_TYPE_STRING, "code", "NetStream.Publish.Start");
    amf_add_bobject(object, AMF_TYPE_NULL, "details", NULL);
    amf_add_bobject(object, AMF_TYPE_STRING, "level", "status");
    //amf_add_bobject(object, AMF_TYPE_STRING, "", "");

    message = rtmp_build_result_connect(rtmp, "onStatus", connectionid, object);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    I6DEBUG(1, client, "<* message/onStatus(Publish.start)(%d,(%d,%d),%d)\n",
            rtmp->timestamp, rtmp->channelid, rtmp->streamid, rtmp->bodysize);

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);
    if (debug)
        I6DEBUG(3, client,
                "Sending response request for stream with id %d and name %s\n", streamid,
                "level");

    safeout:
    amf_destroy_object(object);
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_result_play(struct rtmp_client *client, uint32_t channelid,
        uint32_t streamid, double connectionid, char *description)
{
    int res = (-1);
    struct amf_object *object = NULL;

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_reply\n");

    object = ast_calloc(1, sizeof(*object));
    if (!object)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = channelid;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = streamid;

    object->size = 0;

    /* Populate the AMF object
     * In the case of the Response method, the AMF object must contain
     * the following basic objects :
     * - app : the application identifier to connect to
     * - swfUul : referrer to the SWF file
     * Property names are case sensitive */
    amf_add_bobject(object, AMF_TYPE_STRING, "description", description);
    amf_add_bobject(object, AMF_TYPE_STRING, "code", "NetStream.Play.Start");
    amf_add_bobject(object, AMF_TYPE_NULL, "details", NULL);
    amf_add_bobject(object, AMF_TYPE_STRING, "level", "status");

    message = rtmp_build_result_connect(rtmp, "onStatus", connectionid, object);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    I6DEBUG(1, client, "<* message/onStatus(Play.start)(%d,(%d,%d),%d)\n",
            rtmp->timestamp, rtmp->channelid, rtmp->streamid, rtmp->bodysize);

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);
    if (debug)
        I6DEBUG(3, client,
                "Sending response request for stream with id %d and name %s\n", streamid,
                "level");

    safeout:
    amf_destroy_object(object);
    ast_free(rtmp);
    ast_free(message);
    return res;
}

/** \brief Send instructions to publish a stream
 *
 * We send the following messages in sequence :
 * - Invoke("publish", 0, NULL, "filename", "live")
 *
 * Invoke messages are sent over the control channel of the given stream
 */
static int rtmp_send_result_bye(struct rtmp_client *client, uint32_t streamid,
        double connectionid, char *result, char *description)
{
    int res = (-1);

    struct rtmp_message *rtmp = NULL;
    void *message = NULL;

    if (debug)
        I6DEBUG(3, client, "In rtmp_send_reply streamid = %d\n", streamid);

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }


    /* send a 12-byte header */
    rtmp->hdrlen = 12;
    rtmp->type = RTMP_TYPE_INVOKE;
    rtmp->channelid = RTMP_CHANNEL_CONNECT;
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;

    rtmp->streamid = streamid;
    if (result)
        message =
                rtmp_build_request_message(rtmp, result, connectionid, description);
    else
        message = rtmp_build_request_message(rtmp, "_result", connectionid, NULL);
    if (!message)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    res = rtmp_send_message(client, NULL, message, rtmp->bodysize, rtmp->type);
    if (debug)
        I6DEBUG(3, client,
                "Sending response request for stream with id %d and name %s\n", streamid,
                "level");

    safeout:
    ast_free(rtmp);
    ast_free(message);
    return res;
}


/** \brief Send audio packet
 */
static int rtmp_send_audio(struct rtmp_client *client, struct rtmp_pvt *p,
        struct ast_frame *frame)
{
    int res = (-1);
    struct rtmp_message *rtmp = NULL;
    void *packet = NULL;
    uint8_t *input = NULL;        /* data from remote Assterisk channel */
    short *rawsamples = NULL;     /* resampled data */
    uint8_t *samples = NULL;      /* encoded data */
    int len = 0, inputlen;

    client->outgoing_audio++;

    if (client->chunks_buffer)
    {
        I6DEBUG(3, client, "Chunks in queue !\n");
    }

    I6DEBUG(3, client,
            "In rtmp_send_audio: subclass %s audiocodec %s datalen %d\n",
            GET_FORMAT_NAME(GET_FRAME_SUBCLASS_FORMAT(frame)),
            GET_FORMAT_NAME(client->audiocodec), frame->datalen);


    if (client->playstream == (-1.0))
    {
        I6DEBUG(3, client, "No playstream\n");
        return -1;
    }

    if (p)
        if (!p->mode)
            if (!client->playing)
            {
                I6DEBUG(3, client, "No playstream\n");
                return -1;
            }

    if (!(COMPARE_VARFORMAT_VARFORMAT(GET_FRAME_SUBCLASS_FORMAT(frame),
            client->audiocodec)))
    {
        RTMP_VERBOSE(client, "Invalid audio frame codec (%s <> %s) !\n", GET_FORMAT_NAME(GET_FRAME_SUBCLASS_FORMAT(frame)), GET_FORMAT_NAME(client->audiocodec));

        /*
       if (p->owner)
       {
       //ast_log(LOG_ERROR, "SET FORMAT !\n");
       //ast_set_read_format(p->owner, frame->subclass);
       //ast_set_read_format(p->owner, client->audiocodec);
       }
       else
       RTMP_VERBOSE(client, "No owner !\n");
         */

        /*
       if (p->owner)
       {
       ast_log(LOG_ERROR, "SET FORMAT !\n");
       ast_set_write_format(p->owner, frame->subclass);
       ast_set_write_format(p->owner, client->audiocodec);
       }
       else
       RTMP_VERBOSE(client, "No owner !\n");
         */

        return 0;
    }
    else
    {
        I6DEBUG(7, client, "send_audio: subclass %sh codec %sh\n", GET_FORMAT_NAME(GET_FRAME_SUBCLASS_FORMAT(frame)), GET_FORMAT_NAME(client->audiocodec));
    }

    if (nospeexsilence)
        if ((frame->datalen == 6) || (nospeexsilence == 2))
        {
            //if (debug)
            //RTMP_VERBOSE(client,"Speex slience skipped\n");
            return 0;
        }

    if (maxaudiobuffer)
    {
        int numBytes = 0;
        if (ioctl(client->fd, SIOCOUTQ, &numBytes) < 0)
        {
        }

        if (numBytes > maxaudiobuffer)
            //if ((rand() %100) > 50)
        {
            RTMP_VERBOSE(client, "RTMP Buffer TCP Overflow for audio =%d\n",
                    numBytes);

            client->bufferLen = 0;
            client->outgoing_audiolost++;

            client->overwrites_count++;

            if (client->overwrites_max)
            if (client->overwrites_count > client->overwrites_max)
            {
              ast_log(LOG_ERROR, "WRITE ERROR : client %p, close connection!\n", client);

              if (client->fd != (-1))
              close(client->fd);
              client->fd = (-1);
            }

            return 0;
        }
    }

    client->overwrites_count = 0;

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return -1;
    }

    /* properly set the RTMP header
     * \note body size is set within the rtmp_build family functions */
    rtmp->type = RTMP_TYPE_AUDIO_DATA;
    if (!p->mode)
    {
        if ((client->publishstream == (-1.0)) && (client->playstream != (-1.0)))
            rtmp->channelid = RTMP_CHANNEL_PUBLISH;
        else
            rtmp->channelid = RTMP_CHANNEL_LOCAL;
    }

    if (p->mode)
        rtmp->channelid = 4;

    //rtmp->channelid = 0;
    //rtmp->channelid = 4;
    //res = rtmp_set_outgoing_channelinfo(client, rtmp, hdrlen);
    /*
     rtmp->hdrlen = rtmp_get_current_hdrlen(client, rtmp->channelid);
     if (!rtmp->hdrlen) {
     rtmp->hdrlen = 12;
     }
     */

    //rtmp->timestamp = rtmp_get_current_timestamp(client, rtmp->channelid);
    //rtmp->timestamp += 20;

    if (!client->firstaudio)
    {
        client->timestart = ast_tvnow();
        client->firstaudio = 1;
        //ast_log(LOG_ERROR, "first packet\n");
    }

    if (audiotimestamp == 1)
    {
        rtmp->timestamp = ast_tvdiff_ms(ast_tvnow(), client->timestart);
    }
    else if (audiotimestamp == 2)
    {
        rtmp->timestamp = 0;
        rtmp->timestampdelta =
                rtmp->timestamp - rtmp_get_current_timestamp(client, rtmp->channelid);
    }
    else
    {
        //rtmp->timestampdelta = 20;
        //rtmp->timestampdelta = rtmp->timestamp - rtmp_get_current_timestamp(client, rtmp->channelid);
        rtmp->timestamp = 0;
        rtmp->timestampdelta = 20;
    }

    rtmp->bodysize = frame->datalen + 1;
    rtmp->streamid = p->streamid;
    if ((client->publishstream == (-1.0)) && (client->playstream != (-1.0)))
        rtmp->streamid = 1;
    else
        rtmp->streamid = 2;

    //rtmp->hdrlen = 12;
    if (rtmp->streamid != rtmp_get_current_streamid(client, rtmp->channelid))
    {
        rtmp->hdrlen = 12;
    }
    else
        if (rtmp->type != rtmp_get_current_type(client, rtmp->channelid)
                || rtmp->bodysize != rtmp_get_current_bodylen(client, rtmp->channelid))
        {
            rtmp->hdrlen = 8;
        }
        else
            if (rtmp->timestamp != rtmp_get_current_timestamp(client, rtmp->channelid))
            {
                rtmp->hdrlen = 4;
            }
            else
                rtmp->hdrlen = 1;

    if (COMPARE_VARFORMAT_IDFORMAT(GET_FRAME_SUBCLASS_FORMAT(frame), AST_FORMAT_SPEEX))
    {
        rtmp->timestampdelta = speex_samples(frame->data.ptr, frame->datalen) / 8;
        rtmp->timestamp = (ast_tvdiff_ms(ast_tvnow(), client->timestart));

        client->timestamp += rtmp->timestampdelta;

        if ((rtmp->timestamp < client->timestamp + 100) &&
                (client->timestamp < client->timestamplast + 1000))
        {
            //RTMP_VERBOSE(client,"TIME! delta=%d rtmp=%d client=%d last=%d\n", rtmp->timestampdelta, rtmp->timestamp, client->timestamp, client->timestamplast);

            client->timestamplast = rtmp->timestamp;
            rtmp->timestamp = 0;
            rtmp->timestampdelta = 20;
        }
        else
        {
            //RTMP_VERBOSE(client,"TIME  delta=%d rtmp=%d client=%d\n", rtmp->timestampdelta, rtmp->timestamp, client->timestamp);

            rtmp->timestampdelta = 0;
            //rtmp->timestamp = 0; // TST

            client->timestamp = rtmp->timestamp;
            client->timestamplast = rtmp->timestamp;

            //client->timestart = ast_tvnow(); //TST
        }

        if (record_raw)
        {
            if (!client->outgoing_audiofile)
            {
                char filename[100];
                sprintf(filename, "/tmp/RTMP%p_%d_outgoingaudio_speex.raw", client,
                        (client->outgoing_calls + client->incoming_calls));
                client->outgoing_audiofile = fopen(filename, "wb");
            }

            if (client->outgoing_audiofile)
            {
                fwrite(frame->data.ptr, 1, frame->datalen, client->outgoing_audiofile);
            }
        }
        if (record_flv && frame->datalen != 0)
        {
#ifdef RTMP_FFMPEG
            if (client->out_flv.fd == 0)
            {
                INIT_FLV_OUTPUT(client);
            }
            if (FLV_writePkt(&client->out_flv, FLV_TYPE_AUDIO, client->timestamp,
                    frame->datalen, frame->data.ptr) != FLV_OK)
            {
                ast_log(LOG_ERROR, "Cannot write outgoing flv file !\n");
            }
#else
            {
                ast_log(LOG_ERROR, "Cannot write outgoing flv file (no FFMPEG)!\n");
            }
#endif
        }

        packet = rtmp_build_audio_speex(rtmp, frame->data.ptr, frame->datalen);


        if (autochunksize)
            if (client->outgoing_chunksize < rtmp->bodysize + 1)
            {
                int maxloop = 500;

                while (client->chunks_buffer)
                {
                    int res;

                    res = rtmp_send_data(client, NULL, 0);
                    if (res == -1)
                        goto safeout;

                    if (!res)
                    {
                        maxloop--;
                        if (!maxloop)
                        {
                            I6LOG(LOG_WARNING, client, "Fail to send datas after waiting loop (chunks)!\n");
                            goto safeout;
                        }

                        //ast_mutex_unlock(&client->lock);
                        usleep(10000);
                        //ast_mutex_lock(&client->lock);
                    }
                }

                /* don't write media frame, send new chunksize instead */
                res = rtmp_send_chunksize(client, rtmp->bodysize + 1);
                client->outgoing_chunksize = rtmp->bodysize + 1;
                //goto safeout;

                RTMP_VERBOSE(client, "SET CHUNK SIZE %d\n", client->outgoing_chunksize);
            }

        if (!packet)
        {
            ast_log(LOG_ERROR, "Could not set buffer\n");
            goto safeout;
        }

        I6DEBUG(1, client, "<* message/audio_speex(%d|%d,(%d,%d),%d)\n",
                rtmp->timestamp, rtmp->timestampdelta, rtmp->channelid, rtmp->streamid,
                rtmp->bodysize);
    }
    else if (COMPARE_VARFORMAT_IDFORMAT(GET_FRAME_SUBCLASS_FORMAT(frame), AST_FORMAT_ULAW))
    {
        //rtmp->timestampdelta = ast_codec_get_samples(frame) / 8;
#if 0
        rtmp->timestampdelta = (frame->datalen) / 8;
        rtmp->timestamp = (ast_tvdiff_ms(ast_tvnow(), client->timestart));

        client->timestamp += rtmp->timestampdelta;

        if ((rtmp->timestamp < client->timestamp + 100) &&
                (client->timestamp < client->timestamplast + 1000))
        {
            rtmp->timestamp = 0;
            rtmp->timestampdelta = 20;
        }
        else
        {
            rtmp->timestampdelta = 0;
            //rtmp->timestamp = 0; // TST

            client->timestamp = rtmp->timestamp;
            client->timestamplast = rtmp->timestamp;

            //client->timestart = ast_tvnow(); //TST
        }
#endif

        if (audiotimestamp == 1)
        {
            rtmp->timestamp = ast_tvdiff_ms(ast_tvnow(), client->timestart);
            rtmp->timestampdelta =
                    rtmp->timestamp - rtmp_get_current_timestamp(client, rtmp->channelid);
            rtmp->timestampdelta = 0;
        }
        else if (audiotimestamp == 2)
        {
            //rtmp->timestamp = ast_tvdiff_ms(ast_tvnow(), client->timestart);
            rtmp->timestamp = 0;
            rtmp->timestampdelta =
                    rtmp->timestamp - rtmp_get_current_timestamp(client, rtmp->channelid);
        }
        else
        {
            rtmp->timestamp = 0;
            rtmp->timestampdelta = 0;
        }


        if (record_raw)
        {
            if (!client->outgoing_audiofile)
            {
                char filename[100];
                sprintf(filename, "/tmp/RTMP%p_%d_outgoingaudio_ulaw.raw", client,
                        (client->outgoing_calls + client->incoming_calls));
                client->outgoing_audiofile = fopen(filename, "wb");
            }

            if (client->outgoing_audiofile)
                fwrite(frame->data.ptr, 1, frame->datalen, client->outgoing_audiofile);
            else
                ast_log(LOG_ERROR, "Cannot write outgoing audio ulaw file !\n");
        }
        if (record_flv && frame->datalen != 0)
        {
#ifdef RTMP_FFMPEG
            if (client->out_flv.fd == 0)
            {
                INIT_FLV_OUTPUT(client);
            }
            if (FLV_writePkt(&client->out_flv, FLV_TYPE_AUDIO, client->timestamp,
                    frame->datalen, frame->data.ptr) != FLV_OK)
            {
                ast_log(LOG_ERROR, "Cannot write outgoing flv file !\n");
            }
#else
            {
                ast_log(LOG_ERROR, "Cannot write outgoing flv file (no FFMPEG) !\n");
            }
#endif
        }

        inputlen = frame->datalen;
        rawsamples = ast_malloc(inputlen);

        memcpy(rawsamples, frame->data.ptr, inputlen);
        len = inputlen;

        if (autochunksize)
            if (client->outgoing_chunksize < len + 1)
            {
                /* don't write media frame, send new chunksize instead */
                res = rtmp_send_chunksize(client, len + 1);
                client->outgoing_chunksize = len + 1;

                RTMP_VERBOSE(client, "SET CHUNK SIZE %d\n", client->outgoing_chunksize);
            }
        packet = rtmp_build_audio_ulaw(rtmp, rawsamples, len);

        //ast_free(rawsamples);

        if (!packet)
        {
            ast_log(LOG_ERROR, "Could not set buffer\n");
            goto safeout;
        }

        I6DEBUG(1, client, "<* message/audio_ulaw(%d,(%d,%d),%d)\n",
                rtmp->timestamp, rtmp->channelid, rtmp->streamid, rtmp->bodysize);
    }
    else if (COMPARE_VARFORMAT_IDFORMAT(GET_FRAME_SUBCLASS_FORMAT(frame), AST_FORMAT_ALAW))
    {
        //rtmp->timestampdelta = ast_codec_get_samples(frame) / 8;
        rtmp->timestampdelta = (frame->datalen) / 8;
        rtmp->timestamp = (ast_tvdiff_ms(ast_tvnow(), client->timestart));

        client->timestamp += rtmp->timestampdelta;

        if ((rtmp->timestamp < client->timestamp + 100) &&
                (client->timestamp < client->timestamplast + 1000))
        {
            rtmp->timestamp = 0;
            rtmp->timestampdelta = 20;
        }
        else
        {
            rtmp->timestampdelta = 0;
            //rtmp->timestamp = 0; // TST

            client->timestamp = rtmp->timestamp;
            client->timestamplast = rtmp->timestamp;

            //client->timestart = ast_tvnow(); //TST
        }

        if (record_raw)
        {
            if (!client->outgoing_audiofile)
            {
                char filename[100];
                sprintf(filename, "/tmp/RTMP%p_%d_outgoingaudio_alaw.raw", client,
                        (client->outgoing_calls + client->incoming_calls));
                client->outgoing_audiofile = fopen(filename, "wb");
            }

            if (client->outgoing_audiofile)
                fwrite(frame->data.ptr, 1, frame->datalen, client->outgoing_audiofile);
            else
                ast_log(LOG_ERROR, "Cannot write outgoing audio alaw file !\n");
        }
        if (record_flv && frame->datalen != 0)
        {
#ifdef RTMP_FFMPEG
            if (client->out_flv.fd == 0)
            {
                INIT_FLV_OUTPUT(client);
            }
            if (FLV_writePkt(&client->out_flv, FLV_TYPE_AUDIO, client->timestamp,
                    frame->datalen, frame->data.ptr) != FLV_OK)
            {
                ast_log(LOG_ERROR, "Cannot write outgoing flv file !\n");
            }
#else
            {
                ast_log(LOG_ERROR, "Cannot write outgoing flv file (no FFMPEG) !\n");
            }
#endif
        }

        inputlen = frame->datalen;
        rawsamples = ast_malloc(inputlen);

        memcpy(rawsamples, frame->data.ptr, inputlen);
        len = inputlen;

        if (autochunksize)
            if (client->outgoing_chunksize < len + 1)
            {
                /* don't write media frame, send new chunksize instead */
                res = rtmp_send_chunksize(client, len + 1);
                client->outgoing_chunksize = len + 1;

                RTMP_VERBOSE(client, "SET CHUNK SIZE %d\n", client->outgoing_chunksize);
            }
        packet = rtmp_build_audio_alaw(rtmp, rawsamples, len);

        //ast_free(rawsamples);

        if (!packet)
        {
            ast_log(LOG_ERROR, "Could not set buffer\n");
            goto safeout;
        }

        I6DEBUG(1, client, "<* message/audio_alaw(%d|%d,(%d,%d),%d)\n",
                rtmp->timestamp, rtmp->timestampdelta, rtmp->channelid, rtmp->streamid,
                rtmp->bodysize);
    }
    else if (reserved)
    {
        //rtmp->timestampdelta = ast_codec_get_samples(frame) / 8;
        rtmp->timestampdelta = (frame->datalen / 2) / 8;
        rtmp->timestamp = (ast_tvdiff_ms(ast_tvnow(), client->timestart));

        client->timestamp += rtmp->timestampdelta;

        if ((rtmp->timestamp < client->timestamp + 100) &&
                (client->timestamp < client->timestamplast + 1000))
        {
            rtmp->timestamp = 0;
            rtmp->timestampdelta = 20;
        }
        else
        {
            rtmp->timestampdelta = 0;
            //rtmp->timestamp = 0; // TST

            client->timestamp = rtmp->timestamp;
            client->timestamplast = rtmp->timestamp;

            //client->timestart = ast_tvnow(); //TST
        }

        if (record_raw)
        {
            if (!client->outgoing_audiofile)
            {
                char filename[100];
                sprintf(filename, "/tmp/RTMP%p_%d_outgoingaudio_slinear.raw", client,
                        (client->outgoing_calls + client->incoming_calls));
                client->outgoing_audiofile = fopen(filename, "wb");
            }

            if (client->outgoing_audiofile)
                fwrite(frame->data.ptr, 1, frame->datalen, client->outgoing_audiofile);
            else
                ast_log(LOG_ERROR, "Cannot write outgoing audio slinear file !\n");
        }
        if (record_flv && frame->datalen != 0)
        {
#ifdef RTMP_FFMPEG
            if (client->out_flv.fd == 0)
            {
                INIT_FLV_OUTPUT(client);
            }
            if (FLV_writePkt(&client->out_flv, FLV_TYPE_AUDIO, client->timestamp,
                    frame->datalen, frame->data.ptr) != FLV_OK)
            {
                ast_log(LOG_ERROR, "Cannot write outgoing flv file !\n");
            }
#else
            {
                ast_log(LOG_ERROR, "Cannot write outgoing flv file (no FFMPEG) !\n");
            }
#endif
        }

        inputlen = frame->datalen;

        if (debug)
            I6DEBUG(7, client, "inputlen samples = %d\n", inputlen / 2);

        if (autochunksize)
            if (client->outgoing_chunksize < inputlen + 1)
            {
                /* don't write media frame, send new chunksize instead */
                res = rtmp_send_chunksize(client, inputlen + 1);
                client->outgoing_chunksize = inputlen + 1;

                RTMP_VERBOSE(client, "SET CHUNK SIZE %d\n", client->outgoing_chunksize);
            }

        packet = rtmp_build_audio_reserved(rtmp, frame->data.ptr, inputlen);

        if (!packet)
        {
            ast_log(LOG_ERROR, "Could not set buffer\n");
            goto safeout;
        }

        I6DEBUG(1, client, "<* message/audio_slinear(%d,(%d,%d),%d)\n",
                rtmp->timestamp, rtmp->channelid, rtmp->streamid, rtmp->bodysize);
    }
    else
    {
        //rtmp->timestampdelta = ast_codec_get_samples(frame) / 8;
        rtmp->timestampdelta = (frame->datalen / 2) / 8;
        rtmp->timestamp = (ast_tvdiff_ms(ast_tvnow(), client->timestart));

        client->timestamp += rtmp->timestampdelta;

        if ((rtmp->timestamp < client->timestamp + 100) &&
                (client->timestamp < client->timestamplast + 1000))
        {
            rtmp->timestamp = 0;
            rtmp->timestampdelta = 20;
        }
        else
        {
            rtmp->timestampdelta = 0;
            //rtmp->timestamp = 0; // TST

            client->timestamp = rtmp->timestamp;
            client->timestamplast = rtmp->timestamp;

            //client->timestart = ast_tvnow(); //TST
        }

        if (record_raw)
        {
            if (!client->outgoing_audiofile)
            {
                char filename[100];
                sprintf(filename, "/tmp/RTMP%p_%d_outgoingaudio_pcms16le.raw", client,
                        (client->outgoing_calls + client->incoming_calls));
                client->outgoing_audiofile = fopen(filename, "wb");
            }

            if (client->outgoing_audiofile)
                fwrite(frame->data.ptr, 1, frame->datalen, client->outgoing_audiofile);
            else
                ast_log(LOG_ERROR, "Cannot write outgoing audio pcms16le file !\n");
        }

        if (record_flv && frame->datalen != 0)
        {
#ifdef RTMP_FFMPEG
            if (client->out_flv.fd == 0)
            {
                INIT_FLV_OUTPUT(client);
            }
            if (FLV_writePkt(&client->out_flv, FLV_TYPE_AUDIO, client->timestamp,
                    frame->datalen, frame->data.ptr) != FLV_OK)
            {
                ast_log(LOG_ERROR, "Cannot write outgoing flv file !\n");
            }
#else
            {
                ast_log(LOG_ERROR, "Cannot write outgoing flv file (no FFMPEG) !\n");
            }
#endif
        }

        inputlen = frame->datalen;
        rawsamples = ast_malloc(inputlen);

        /* Frames coming from Asterisk contain data sampled at 8 kHz. We need
         * to resample them to match with the values expected by the remote
         * FLEX clients : 5.5, 11 or 22 kHz
         */

        /*
       len = audio_resample(p->tortmp_resample_context, rawsamples, (short *)input, inputlen/2);
       if (debug)
       I6DEBUG(7, client, "rawsamples number = %d (in %d)\n", len, inputlen/2);
         */

        memcpy(rawsamples, frame->data.ptr, inputlen);
        len = inputlen / 2;

        if (autochunksize)
            if (client->outgoing_chunksize < len * 2 + 1)
            {
                /* don't write media frame, send new chunksize instead */
                res = rtmp_send_chunksize(client, len * 2 + 1);
                client->outgoing_chunksize = len * 2 + 1;

                RTMP_VERBOSE(client, "SET CHUNK SIZE %d\n", client->outgoing_chunksize);
            }
        packet = rtmp_build_audio_pcm(rtmp, rawsamples, len * 2);

        //ast_free(rawsamples);

        if (!packet)
        {
            ast_log(LOG_ERROR, "Could not set buffer\n");
            goto safeout;
        }

        I6DEBUG(1, client, "<* message/audio_slinear(%d|%d,(%d,%d),%d)\n",
                rtmp->timestamp, rtmp->timestampdelta, rtmp->channelid, rtmp->streamid,
                rtmp->bodysize);
    }


    I6DEBUG(1,client, "<* channel/%d timestamp=%d, channelid=%d, type=0x%02X, streamid=%d, size=%d\n",
            rtmp->channelid, rtmp->timestamp, rtmp->channelid, rtmp->type, rtmp->streamid, rtmp->bodysize);

    //res = rtmp_send_message_direct(client, NULL, packet, rtmp->bodysize);
    res = rtmp_send_message(client, NULL, packet, rtmp->bodysize, rtmp->type);


    safeout:
    if (rawsamples)
        ast_free(rawsamples);
    if (samples)
        ast_free(samples);
    if (input)
        ast_free(input);

    ast_free(rtmp);
    ast_free(packet);
    return res;
}

/** \brief Send video packet
 */
static int rtmp_send_video(struct rtmp_client *client, struct rtmp_pvt *p,
        struct ast_frame *frame)
{
    int res = (-1);
    struct rtmp_message *rtmp = NULL;
    void *packet = NULL;
    uint8_t *input = NULL;        /* data from remote Assterisk channel */
    short *rawsamples = NULL;     /* resampled data */
    uint8_t *samples = NULL;      /* encoded data */
    uint32_t rxseq = 0;
    uint16_t cseq = 0;
    unsigned char info = 0;
    unsigned char codecid = 0;
    unsigned char frametype = 0;

    client->outgoing_video++;

    if ((client->playstream2 == (-1.0)) && (client->playstream == (-1.0)))
    {
        I6DEBUG(3, client, "No playstream\n");
        return -1;
    }

    if (p)
        if (!p->mode)
            if ((!client->playing) && (!client->playing2))
            {
                I6DEBUG(3, client, "No playstream\n");
                return -1;
            }


    rxseq = ntohl(*(uint32_t *) ((frame->data.ptr) + 4));
    cseq = ntohs(*(uint16_t *) ((frame->data.ptr) + 8));

    if (debug)
        I6DEBUG(7, client, "rxseq=%d, cseq=%d\n", rxseq, cseq);

    if (cseq == 0)
    {
        info = (*(char *)((frame->data.ptr) + 24));
        codecid = ((info & 0x0f));
        frametype = ((info & 0xf0) >> 4);

        if (debug)
            I6DEBUG(5, client, "codecid=%d, frametype=%d\n", codecid, frametype);
    }

    if (cseq != 0)
        if (client->bufferLen == 0)
        {
            I6LOG(LOG_DEBUG, client, "Synchro error (cseq!=0).\n");
            client->cseq = 0;
            return 0;
        }

    if (client->cseq != cseq)
    {
        I6LOG(LOG_DEBUG, client, "Synchro error (cseq!=next).\n");
        client->cseq = 0;
        client->bufferLen = 0;
        return 0;
    }

    /* Just copy */
    if (cseq == 0)
    {
        client->cseq = 1;
        if ((client->bufferLen + frame->datalen - 24) < client->bufferSize)
        {
            memcpy(client->buffer + client->bufferLen, frame->data.ptr + 24,
                    frame->datalen - 24);
            client->bufferLen += frame->datalen - 24;
        }
        else
        {
            ast_log(LOG_ERROR, "Overflow in the video buffer\n");
        }
    }
    else
    {
        client->cseq = cseq + 1;
        if ((client->bufferLen + frame->datalen - 10) < client->bufferSize)
        {
            memcpy(client->buffer + client->bufferLen, frame->data.ptr + 10,
                    frame->datalen - 10);
            client->bufferLen += frame->datalen - 10;
        }
        else
        {
            ast_log(LOG_ERROR, "Overflow in the video buffer\n");
        }
    }
    /* Return added */

    if (!CHECK_FRAME_SUBCLASS_VIDEOMARK(frame))
        return 0;

    client->cseq = 0;
    client->outgoing_images++;

    if (maxvideobuffer)
    {
        int numBytes = 0;
        if (ioctl(client->fd, SIOCOUTQ, &numBytes) < 0)
        {
        }
        //ast_verbose("RTMP Buffer TCP before video =%d for %d\n", numBytes, client->bufferLen);

        if (numBytes > maxvideobuffer)
            //if ((rand() %100) > 50)
            if ((numBytes + client->bufferLen) > maxvideobuffer)
            {
                RTMP_VERBOSE(client, "RTMP Buffer TCP Overflow for video =%d\n",
                        numBytes);

                client->bufferLen = 0;
                client->outgoing_videolost++;

                client->overwrites_count++;

                if (client->overwrites_max)
                if (client->overwrites_count > client->overwrites_max)
                {
                  ast_log(LOG_ERROR, "WRITE ERROR : client %p, close connection!\n", client);

                  if (client->fd != (-1))
                    close(client->fd);
                  client->fd = (-1);
                }

                return 0;
            }
    }

    client->overwrites_count = 0;

#ifdef RTMP_FFMPEG
    frametype = FLV_getPictureType( (uint8_t *) (client->buffer + 1)) ;
    I6DEBUG(8, client, "frametype=%d(%s)\n", frametype, frametype==FLV_FRAME_KEY?"KEY":"INTER" );
#endif

    if (record_raw)
    {
        if (!client->outgoing_videofile)
        {
            char filename[100];
            sprintf(filename, "/tmp/RTMP%p_%d_outgoingaudio_video.raw", client,
                    (client->outgoing_calls + client->incoming_calls));
            client->outgoing_videofile = fopen(filename, "wb");
        }

        if (client->outgoing_videofile)
            fwrite(client->buffer, 1, client->bufferLen, client->outgoing_videofile);
        else
            ast_log(LOG_ERROR, "Cannot write outgoing video file !\n");
    }

    // Get picture size
    if (client && client->havePictureOutSize == 0)
    {
#ifdef RTMP_FFMPEG
        FLV_getPictureSize(&(client->pictureOut_width),
                &(client->pictureOut_heigth), (uint8_t *) (client->buffer + 1));
        if (client->pictureOut_width > 2 && client->pictureOut_heigth > 2)
        {
            I6DEBUG(3, client, "FLV get picture size from frame %dx%d\n",
                    client->pictureOut_width, client->pictureOut_heigth);
            client->havePictureOutSize = 1;
        }
        else
        {
            I6DEBUG(3, client, "bad image size %dx%d\n", client->pictureOut_width,
                    client->pictureOut_heigth);
        }
#else
        {
            client->pictureOut_width = 1;
            client->pictureOut_heigth = 1;
            client->havePictureOutSize = 0;
            I6DEBUG(3, client, "bad image size %dx%d (no FFMPEG)\n", client->pictureOut_width,
                    client->pictureOut_heigth);
        }
#endif
    }

    if (record_flv && client->bufferLen != 0)
    {
#ifdef RTMP_FFMPEG
        if (client->out_flv.fd == 0)
        {
            INIT_FLV_OUTPUT(client);
        }
        /*
         * buffer + 1 => because video tag code is already added in frame !
         *      => switch it. It will be add in FLV module
         */
        if (FLV_writePkt(&client->out_flv, FLV_TYPE_VIDEO, client->timestamp,
                (client->bufferLen - 1), (uint8_t *) (client->buffer + 1)) != FLV_OK)
        {
            //frame->datalen-25, (uint8_t*)(frame->data.ptr+25) ) != FLV_OK){
            //client->bufferLen-offset, (uint8_t*)(client->buffer+offset) ) != FLV_OK){
            ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file !\n");
        }
#else
        {
            ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file (no FFMPEG) !\n");
        }
#endif
    }
    /* JYG test Anew spy */
    if (spy_picture==1 && client->bufferLen != 0 && frametype == 1 )
    {
#ifdef RTMP_FFMPEG
        I6DEBUG(1,client, "Spy frame\n");

        INIT_FLV_SPY(client);
        if (FLV_writePkt(&client->out_flv_spy, FLV_TYPE_VIDEO, client->timestamp,
                (client->bufferLen - 1), (uint8_t *) (client->buffer + 1)) != FLV_OK)
        {
            ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file !\n");
        }
        I6DEBUG(3, client, "Close FLV outgoing file\n");
        FLV_close(&client->out_flv_spy, ast_tvdiff_ms(ast_tvnow(), client->timestart),
                client->pictureOut_width, client->pictureOut_heigth);
#else
        {
            ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file (no FFMPEG) !\n");
        }
#endif
    }
    else {
        I6DEBUG(3, client, "spy_picture=%d bufferLen=%d frametype=%d\n",spy_picture, client->bufferLen, frametype);
    }


    if (debug)
        I6DEBUG(3, client, "frame MARK In rtmp_send_video\n");

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return -1;
    }

    /* properly set the RTMP header
     * \note body size is set within the rtmp_build family functions */
    rtmp->type = RTMP_TYPE_VIDEO_DATA;

    if ((client->playstream2 == (-1.0)) && (client->playstream != (-1.0)))
        rtmp->channelid = RTMP_CHANNEL_PUBLISH;
    else
        rtmp->channelid = RTMP_CHANNEL_VIDEO;

    if (client->pvt)
        if (client->pvt->mode)
        {
            if ((client->playstream2 == (-1.0)) && (client->playstream != (-1.0)))
                rtmp->channelid = 4;
            else
                rtmp->channelid = 5;
        }

    if (videotimestamp == 1)
    {
        rtmp->timestamp = ast_tvdiff_ms(ast_tvnow(), client->timestart);
        rtmp->timestampdelta =
                rtmp->timestamp - rtmp_get_current_timestamp(client, rtmp->channelid);
        rtmp->timestampdelta = 0;
    }
    else if (videotimestamp == 2)
    {
        rtmp->timestamp = ast_tvdiff_ms(ast_tvnow(), client->timestart);
        rtmp->timestamp = 0;
        rtmp->timestampdelta =
                rtmp->timestamp - rtmp_get_current_timestamp(client, rtmp->channelid);
    }
    else
    {
        rtmp->timestamp = 0;
        rtmp->timestampdelta = 0;
    }

    //rtmp->timestamp = 0;
    //rtmp->timestampdelta = 0;

    rtmp->streamid = p->streamid;
    if ((client->playstream2 == (-1.0)) && (client->playstream != (-1.0)))
        rtmp->streamid = 2;
    else
        rtmp->streamid = 3;

    if (p->mode)
    {
        if ((client->playstream2 == (-1.0)) && (client->playstream != (-1.0)))
            rtmp->streamid = 1;
        else
            rtmp->streamid = 2;
    }

    if (rtmp->streamid != rtmp_get_current_streamid(client, rtmp->channelid))
    {
        rtmp->hdrlen = 12;
    }
    else
        if (rtmp->type != rtmp_get_current_type(client, rtmp->channelid)
                || rtmp->bodysize != rtmp_get_current_bodylen(client, rtmp->channelid))
        {
            rtmp->hdrlen = 8;
        }
        else
            if (rtmp->timestamp != rtmp_get_current_timestamp(client, rtmp->channelid))
            {
                rtmp->hdrlen = 4;
            }
            else
                rtmp->hdrlen = 4;

    /* now build an audio packet with encoded data */
    packet = rtmp_build_video(rtmp, client->buffer, client->bufferLen); // input, inputlen);
    client->bufferLen = 0;
    if (!packet)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    I6DEBUG(1,client, "<* channel/%d timestamp=%d, channelid=%d, type=0x%02X, streamid=%d, size=%d\n",
            rtmp->channelid, rtmp->timestamp, rtmp->channelid, rtmp->type, rtmp->streamid, rtmp->bodysize);

    I6DEBUG(1, client, "<* message/video_sorenson(%d,(%d,%d),%d)\n",
            rtmp->timestamp, rtmp->channelid, rtmp->streamid, rtmp->bodysize);

    res = rtmp_send_message(client, NULL, packet, rtmp->bodysize, rtmp->type);

    safeout:
    ast_free(rawsamples);
    ast_free(samples);
    ast_free(input);
    ast_free(rtmp);
    ast_free(packet);
    return res;
}

/** \brief Send video packet
 */
static int rtmp_send_clear(struct rtmp_client *client)
{
    int res = (-1);
    struct rtmp_message *rtmp = NULL;
    void *packet = NULL;

    I6DEBUG(3, client, "Send clear video.\n");

    if ((client->playstream2 == (-1.0)) && (client->playstream == (-1.0)))
    {
        I6DEBUG(3, client, "No playstream\n");
        return -1;
    }

    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return res;
    }

    /* properly set the RTMP header
     * \note body size is set within the rtmp_build family functions */
    rtmp->type = RTMP_TYPE_VIDEO_DATA;

    if ((client->playstream2 == (-1.0)) && (client->playstream != (-1.0)))
        rtmp->channelid = RTMP_CHANNEL_PUBLISH;
    else
        rtmp->channelid = RTMP_CHANNEL_VIDEO;

    if (client->pvt)
        if (client->pvt->mode)
        {
            if ((client->playstream2 == (-1.0)) && (client->playstream != (-1.0)))
                rtmp->channelid = 4;
            else
                rtmp->channelid = 5;
        }

    if (videotimestamp == 1)
    {
        rtmp->timestamp = ast_tvdiff_ms(ast_tvnow(), client->timestart);
        rtmp->timestampdelta =
                rtmp->timestamp - rtmp_get_current_timestamp(client, rtmp->channelid);
        rtmp->timestampdelta = 0;
    }
    else if (videotimestamp == 2)
    {
        rtmp->timestamp = ast_tvdiff_ms(ast_tvnow(), client->timestart);
        rtmp->timestamp = 0;
        rtmp->timestampdelta =
                rtmp->timestamp - rtmp_get_current_timestamp(client, rtmp->channelid);
    }
    else
    {
        rtmp->timestamp = 0;
        rtmp->timestampdelta = 0;
    }

    rtmp->streamid = 0;
    if ((client->playstream2 == (-1.0)) && (client->playstream != (-1.0)))
        rtmp->streamid = 2;
    else
        rtmp->streamid = 3;

    if (rtmp->streamid != rtmp_get_current_streamid(client, rtmp->channelid))
    {
        rtmp->hdrlen = 12;
    }
    else
        if (rtmp->type != rtmp_get_current_type(client, rtmp->channelid)
                || rtmp->bodysize != rtmp_get_current_bodylen(client, rtmp->channelid))
        {
            rtmp->hdrlen = 8;
        }
        else
            if (rtmp->timestamp != rtmp_get_current_timestamp(client, rtmp->channelid))
            {
                rtmp->hdrlen = 4;
            }
            else
                rtmp->hdrlen = 4;

    /* now build an audio packet with encoded data */
    packet = rtmp_build_video(rtmp, buffer_black, sizeof(buffer_black));
    client->bufferLen = 0;
    if (!packet)
    {
        ast_log(LOG_ERROR, "Could not set buffer\n");
        goto safeout;
    }

    I6DEBUG(1, client, "<* message/video_sorenson(%d,(%d,%d),%d)\n",
            rtmp->timestamp, rtmp->channelid, rtmp->streamid, rtmp->bodysize);

    res = rtmp_send_message(client, NULL, packet, rtmp->bodysize, rtmp->type);

    // Need to wait before
    usleep(10000);

    safeout:
    ast_free(rtmp);
    ast_free(packet);
    return res;
}

static int amf_add_bobject(struct amf_object *object, uint8_t type,
        char *property, void *value)
{
    int res = (-1);
    struct amf_basic_object *aux = NULL;
    struct amf_basic_object *bottom = NULL;

    aux = ast_calloc(1, sizeof(struct amf_basic_object) + 1);
    if (!aux)
    {
        return res;
    }

    if (!object || !property)
    {
        ast_log(LOG_ERROR, "Wrong object assignment\n");
        return res;
    }

    aux->type = type;
    aux->property = ast_calloc(1, strlen(property) + 1);
    memcpy(aux->property, property, strlen(property));
    switch (aux->type)
    {
        case AMF_TYPE_NUMBER:
            /* type + double length */
            aux->length = 1 + 8;
            aux->value = ast_calloc(1, sizeof(double));
            memcpy(aux->value, value, sizeof(double));
            break;
        case AMF_TYPE_BOOLEAN:
            /* type + boolean length */
            aux->length = 1 + 1;
            aux->value = ast_calloc(1, 1);
            memcpy(aux->value, value, 1);
            break;
        case AMF_TYPE_STRING:
            /* type + string length + computed string length */
            aux->length = 1 + 2 + strlen((char *)value);
            aux->value = ast_calloc(1, strlen((char *)value));
            memcpy(aux->value, value, strlen((char *)value));
            break;
        case AMF_TYPE_NULL:
            /* type */
            aux->length = 1;
            aux->value = NULL;
            break;
        default:
            if (debug)
                ast_debug(5, "Unknown AMF type : %d\n", aux->type);
            return res;
    }

    aux->next = NULL;

    /* string length + computed property string length */
    object->size += 2 + strlen(aux->property);
    object->size += aux->length;

    /* insert object at the end of list */
    bottom = object->bobject;
    if (!bottom)
    {
        /* list is empty */
        object->bobject = aux;
        return 1;
    }
    while (bottom->next)
    {
        bottom = bottom->next;
    }
    bottom->next = aux;

    return 1;
}

static int amf_destroy_object(struct amf_object *object)
{
    int res = 0;
    struct amf_basic_object *aux = NULL;
    struct amf_basic_object *auxold = NULL;

    aux = object->bobject;
    while (aux)
    {
        if (aux->value)
            ast_free(aux->value);
        ast_free(aux->property);
        auxold = aux;
        aux = aux->next;
        ast_free(auxold);
    }

    ast_free(object);

    return res;
}

static char *rtmp_build_invoke(struct rtmp_message *rtmp, char *method,
        double connectionid, struct amf_object *amf, char *options, void *boolean,
        char *newoptions)
{
    int res = (-1);
    void *buf = NULL;
    void *message = NULL;         /* serialized RTMP header + body */

    if (debug)
        ast_debug(3, "In rtmp_build_invoke\n");
    rtmp->bodysize =
            amf_strlen(method) + amf_numberlen(&connectionid) + amf_objlen(amf) +
            amf_strlen(options) + amf_booleanlen(boolean) + amf_strlen(newoptions);

    message = ast_calloc(1, rtmp->hdrlen + rtmp->bodysize);
    if (!message)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return NULL;
    }

    buf = message;

    /* copy header */
    res = rtmp_set_header(buf, rtmp, rtmp->hdrlen);
    if (!res)
    {
        ast_log(LOG_WARNING, "Cannot set RTMP header\n");
        ast_free(message);
        return NULL;
    }

    if (rtmp->hdrlen != res){
        ast_log(LOG_WARNING, "Bad header lg %d!=%d\n", rtmp->hdrlen, res);
        ast_free(message);
        return NULL;

    }

    buf += res;

    /* copy the method string */
    res = rtmp_set_string(buf, method, strlen(method));
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the connection id */
    res = rtmp_set_number(buf, &connectionid);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the AMF object */
    res = rtmp_set_object(buf, amf);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy an optional string (the filename in play/publish request) */
    res = rtmp_set_string(buf, options, options ? strlen(options) : 0);
    if (res < 0)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the boolean parameter */
    res = rtmp_set_boolean(buf, boolean);
    if (res < 0)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy an optional string (the live/record_raw option in publish
     * requests) */
    res = rtmp_set_string(buf, newoptions, newoptions ? strlen(newoptions) : 0);
    if (res < 0)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    return message;
}

static char *rtmp_build_result_connect(struct rtmp_message *rtmp, char *method,
        double connectionid, struct amf_object *amf)
{
    int res = (-1);
    uint8_t *buf = NULL;
    void *message = NULL;         /* serialized RTMP header + body */

    if (debug)
        ast_debug(3, "In rtmp_build_result\n");


    rtmp->bodysize =
            amf_strlen(method) + amf_numberlen(&connectionid) + amf_arraylen(amf);

    message = ast_calloc(1, rtmp->hdrlen + rtmp->bodysize);
    if (!message)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return NULL;
    }

    buf = message;

    /* copy header */
    res = rtmp_set_header(buf, rtmp, rtmp->hdrlen);
    if (!res)
    {
        ast_log(LOG_WARNING, "Cannot set RTMP header\n");
        ast_free(message);
        return NULL;
    }

    if (rtmp->hdrlen != res){
        ast_log(LOG_WARNING, "Bad header lg %d!=%d\n", rtmp->hdrlen, res);
        ast_free(message);
        return NULL;
    }

    buf += res;

    /* copy the method string */
    res = rtmp_set_string(buf, method, strlen(method));
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the connection id */
    res = rtmp_set_number(buf, &connectionid);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the connection id */
    res = rtmp_set_null(buf);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the AMF object */
    //res = rtmp_set_array(buf, amf);
    res = rtmp_set_object(buf, amf);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    return message;
}

static char *rtmp_build_result_createstream(struct rtmp_message *rtmp,
        char *method, double connectionid, double result)
{
    int res = (-1);
    uint8_t *buf = NULL;
    void *message = NULL;         /* serialized RTMP header + body */

    if (debug)
        ast_debug(3, "In rtmp_build_result\n");
    if (result == (-1.0))
        rtmp->bodysize = amf_strlen(method) + amf_numberlen(&connectionid) + 1 + 1;
    else
        rtmp->bodysize =
                amf_strlen(method) + amf_numberlen(&connectionid) +
                amf_numberlen(&result) + 1;

    message = ast_calloc(1, rtmp->hdrlen + rtmp->bodysize);
    if (!message)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return NULL;
    }

    buf = message;

    /* copy header */
    res = rtmp_set_header(buf, rtmp, rtmp->hdrlen);
    if (!res)
    {
        ast_log(LOG_WARNING, "Cannot set RTMP header\n");
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the method string */
    res = rtmp_set_string(buf, method, strlen(method));
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the connection id */
    res = rtmp_set_number(buf, &connectionid);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the connection id */
    res = rtmp_set_null(buf);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the result */
    if (result == (-1.0))
        res = rtmp_set_null(buf);
    else
        res = rtmp_set_number(buf, &result);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    return message;
}

static char *rtmp_build_result_message(struct rtmp_message *rtmp, char *method,
        double connectionid, char *description)
{
    int res = (-1);
    uint8_t *buf = NULL;
    void *message = NULL;         /* serialized RTMP header + body */

    if (debug)
        ast_debug(3, "In rtmp_build_result\n");
    if (description)
        rtmp->bodysize =
                amf_strlen(method) + amf_numberlen(&connectionid) + 1 +
                amf_strlen(description);
    else
        rtmp->bodysize = amf_strlen(method) + amf_numberlen(&connectionid) + 1;

    message = ast_calloc(1, rtmp->hdrlen + rtmp->bodysize + 1);
    if (!message)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return NULL;
    }

    buf = message;

    /* copy header */
    res = rtmp_set_header(buf, rtmp, rtmp->hdrlen);
    if (!res)
    {
        ast_log(LOG_WARNING, "Cannot set RTMP header\n");
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the method string */
    res = rtmp_set_string(buf, method, strlen(method));
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the connection id */
    res = rtmp_set_number(buf, &connectionid);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the connection id */
    res = rtmp_set_null(buf);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    if (description)
    {
        /* copy the method string */
        res = rtmp_set_string(buf, description, strlen(description));
        if (!res)
        {
            ast_free(message);
            return NULL;
        }    buf += res;
    }
    else
    {
        res = rtmp_set_undefined(buf);
        if (!res)
        {
            ast_free(message);
            return NULL;
        }
        buf += res;
    }

    return message;
}

static char *rtmp_build_request_message(struct rtmp_message *rtmp, char *method,
        double connectionid, char *description)
{
    int res = (-1);
    uint8_t *buf = NULL;
    void *message = NULL;         /* serialized RTMP header + body */

    if (debug)
        ast_debug(3, "In rtmp_build_result\n");
    if (description)
        rtmp->bodysize =
                amf_strlen(method) + amf_numberlen(&connectionid) + 1 +
                amf_strlen(description);
    else
        rtmp->bodysize = amf_strlen(method) + amf_numberlen(&connectionid) + 1;

    message = ast_calloc(1, rtmp->hdrlen + rtmp->bodysize);
    if (!message)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return NULL;
    }

    buf = message;

    /* copy header */
    res = rtmp_set_header(buf, rtmp, rtmp->hdrlen);
    if (!res)
    {
        ast_log(LOG_WARNING, "Cannot set RTMP header\n");
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the method string */
    res = rtmp_set_string(buf, method, strlen(method));
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the connection id */
    res = rtmp_set_number(buf, &connectionid);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the connection id */
    res = rtmp_set_null(buf);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    if (description)
    {
        /* copy the method string */
        res = rtmp_set_string(buf, description, strlen(description));
        if (!res)
        {
            ast_free(message);
            return NULL;
        }
        buf += res;
    }

    return message;
}

static char *rtmp_build_request_message2(struct rtmp_message *rtmp,
        char *method, double connectionid, char *description, char *extra)
{
    int res = (-1);
    uint8_t *buf = NULL;
    void *message = NULL;         /* serialized RTMP header + body */

    if (debug)
        ast_debug(3, "In rtmp_build_request_message2\n");

    rtmp->bodysize = amf_strlen(method) + amf_numberlen(&connectionid) + 1;
    if (description)
        rtmp->bodysize += amf_strlen(description);

    if (extra)
        rtmp->bodysize += amf_strlen(extra);

    message = ast_calloc(1, rtmp->hdrlen + rtmp->bodysize);
    if (!message)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return NULL;
    }

    buf = message;

    /* copy header */
    res = rtmp_set_header(buf, rtmp, rtmp->hdrlen);
    if (!res)
    {
        ast_log(LOG_WARNING, "Cannot set RTMP header\n");
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the method string */
    res = rtmp_set_string(buf, method, strlen(method));
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the connection id */
    res = rtmp_set_number(buf, &connectionid);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* copy the connection id */
    res = rtmp_set_null(buf);
    if (!res)
    {
        ast_free(message);
        return NULL;
    }
    buf += res;

    if (description)
    {
        /* copy the method string */
        res = rtmp_set_string(buf, description, strlen(description));
        if (!res)
        {
            ast_free(message);
            return NULL;
        }
        buf += res;
    }

    if (extra)
    {
        /* copy the method string */
        res = rtmp_set_string(buf, extra, strlen(extra));
        if (!res)
        {
            ast_free(message);
            return NULL;
        }
        buf += res;
    }

    return message;
}

static char *rtmp_build_audio_reserved(struct rtmp_message *rtmp, void *samples,
        int datalen)
{
    int res = (-1);
    void *buf = NULL;
    void *message = NULL;         /* serialized RTMP header + body */
    uint8_t firstbyte = 0x92;     /* audio description :
                                   - 6  : raw data at 11 kHz
                                   - 22 : ADPCM at 11 kHz */

    if (debug)
        ast_debug(7, "In rtmp_build_audio\n");
    rtmp->bodysize = 1 + datalen; /* first byte contains audio description */

    message = ast_calloc(1, rtmp->hdrlen + rtmp->bodysize);
    if (!message)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return NULL;
    }

    buf = message;

    /* copy header */
    res = rtmp_set_header(buf, rtmp, rtmp->hdrlen);
    if (!res)
    {
        ast_log(LOG_WARNING, "Cannot set RTMP header\n");
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* set sound information
     * The first byte is not a media packet,
     * it contains the following codec information :
     *  soundType   (byte & 0x01) >> 0  0: mono, 1: stereo
     *  soundSize   (byte & 0x02) >> 1  0: 8-bit, 1: 16-bit
     *  soundRate   (byte & 0x0c) >> 2  0: 5.5 kHz, 1: 11 kHz, 2: 22 kHz, 3: 44 kHz
     *  soundFormat (byte & 0xf0) >> 4  0: Uncompressed, 1: ADPCM, 2: MP3, 5: Nellymoser 8kHz mono, 6: Nellymoser, 11: Speex
     * */
    *(uint8_t *) buf = firstbyte;
    buf++;

    /* copy samples */
    memcpy(buf, samples, datalen);

    return message;
}

static char *rtmp_build_audio_ulaw(struct rtmp_message *rtmp, void *samples,
        int datalen)
{
    int res = (-1);
    void *buf = NULL;
    void *message = NULL;         /* serialized RTMP header + body */
    uint8_t firstbyte = 0x80;     /* audio description :
                                   - 6  : raw data at 11 kHz
                                   - 22 : ADPCM at 11 kHz */

    if (debug)
        ast_debug(7, "In rtmp_build_audio\n");
    rtmp->bodysize = 1 + datalen; /* first byte contains audio description */

    message = ast_calloc(1, rtmp->hdrlen + rtmp->bodysize);
    if (!message)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return NULL;
    }

    buf = message;

    /* copy header */
    res = rtmp_set_header(buf, rtmp, rtmp->hdrlen);
    if (!res)
    {
        ast_log(LOG_WARNING, "Cannot set RTMP header\n");
        ast_free(message);
        return NULL;
    }

    if (rtmp->hdrlen != res){
        ast_log(LOG_WARNING, "Bad header lg %d!=%d\n", rtmp->hdrlen, res);
        ast_free(message);
        return NULL;
    }

    buf += res;

    /* set sound information
     * The first byte is not a media packet,
     * it contains the following codec information :
     *  soundType   (byte & 0x01) >> 0  0: mono, 1: stereo
     *  soundSize   (byte & 0x02) >> 1  0: 8-bit, 1: 16-bit
     *  soundRate   (byte & 0x0c) >> 2  0: 5.5 kHz, 1: 11 kHz, 2: 22 kHz, 3: 44 kHz
     *  soundFormat (byte & 0xf0) >> 4  0: Uncompressed, 1: ADPCM, 2: MP3, 5: Nellymoser 8kHz mono, 6: Nellymoser, 11: Speex
     * */
    *(uint8_t *) buf = firstbyte;
    buf++;

    /* copy samples */
    memcpy(buf, samples, datalen);

    return message;
}

static char *rtmp_build_audio_alaw(struct rtmp_message *rtmp, void *samples,
        int datalen)
{
    int res = (-1);
    void *buf = NULL;
    void *message = NULL;         /* serialized RTMP header + body */
    uint8_t firstbyte = 0x70;     /* audio description :
                                   - 6  : raw data at 11 kHz
                                   - 22 : ADPCM at 11 kHz */

    if (debug)
        ast_debug(7, "In rtmp_build_audio\n");
    rtmp->bodysize = 1 + datalen; /* first byte contains audio description */

    message = ast_calloc(1, rtmp->hdrlen + rtmp->bodysize);
    if (!message)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return NULL;
    }

    buf = message;

    /* copy header */
    res = rtmp_set_header(buf, rtmp, rtmp->hdrlen);
    if (!res)
    {
        ast_log(LOG_WARNING, "Cannot set RTMP header\n");
        ast_free(message);
        return NULL;
    }

    if (rtmp->hdrlen != res){
        ast_log(LOG_WARNING, "Bad header lg %d!=%d\n", rtmp->hdrlen, res);
        ast_free(message);
        return NULL;
    }

    buf += res;

    /* set sound information
     * The first byte is not a media packet,
     * it contains the following codec information :
     *  soundType   (byte & 0x01) >> 0  0: mono, 1: stereo
     *  soundSize   (byte & 0x02) >> 1  0: 8-bit, 1: 16-bit
     *  soundRate   (byte & 0x0c) >> 2  0: 5.5 kHz, 1: 11 kHz, 2: 22 kHz, 3: 44 kHz
     *  soundFormat (byte & 0xf0) >> 4  0: Uncompressed, 1: ADPCM, 2: MP3, 5: Nellymoser 8kHz mono, 6: Nellymoser, 11: Speex
     * */
    *(uint8_t *) buf = firstbyte;
    buf++;

    /* copy samples */
    memcpy(buf, samples, datalen);

    return message;
}

static char *rtmp_build_audio_pcm(struct rtmp_message *rtmp, void *samples,
        int datalen)
{
    int res = (-1);
    void *buf = NULL;
    void *message = NULL;         /* serialized RTMP header + body */
    uint8_t firstbyte = 6;        /* audio description :
                                   - 6  : raw data at 11 kHz
                                   - 22 : ADPCM at 11 kHz */

    if (debug)
        ast_debug(7, "In rtmp_build_audio\n");
    rtmp->bodysize = 1 + datalen; /* first byte contains audio description */

    message = ast_calloc(1, rtmp->hdrlen + rtmp->bodysize);
    if (!message)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return NULL;
    }

    if (rtmp->hdrlen != res){
        ast_log(LOG_WARNING, "Bad header lg %d!=%d\n", rtmp->hdrlen, res);
        ast_free(message);
        return NULL;
    }

    buf = message;

    /* copy header */
    res = rtmp_set_header(buf, rtmp, rtmp->hdrlen);
    if (!res)
    {
        ast_log(LOG_WARNING, "Cannot set RTMP header\n");
        ast_free(message);
        return NULL;
    }
    buf += res;

    /* set sound information
     * The first byte is not a media packet,
     * it contains the following codec information :
     *  soundType   (byte & 0x01) >> 0  0: mono, 1: stereo
     *  soundSize   (byte & 0x02) >> 1  0: 8-bit, 1: 16-bit
     *  soundRate   (byte & 0x0c) >> 2  0: 5.5 kHz, 1: 11 kHz, 2: 22 kHz, 3: 44 kHz
     *  soundFormat (byte & 0xf0) >> 4  0: Uncompressed, 1: ADPCM, 2: MP3, 5: Nellymoser 8kHz mono, 6: Nellymoser, 11: Speex
     * */
    *(uint8_t *) buf = firstbyte;
    buf++;

    /* copy samples */
    memcpy(buf, samples, datalen);

    return message;
}

static char *rtmp_build_audio_speex(struct rtmp_message *rtmp, void *samples,
        int datalen)
{
    int res = (-1);
    void *buf = NULL;
    void *message = NULL;         /* serialized RTMP header + body */
    uint8_t firstbyte = 0xB2;     // 11:Speex 0:na 1:snd16

    if (debug)
        ast_debug(3, "In rtmp_build_audio SPEEX\n");
    rtmp->bodysize = 1 + datalen; /* first byte contains audio description */

    message =
            ast_calloc(1, rtmp->hdrlen + rtmp->bodysize + RTMP_EXTENDEDTIMESTAMP_SIZE + 4 ); // Valgrind
    if (!message)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return NULL;
    }

    buf = message;

    /* copy header */
    res = rtmp_set_header(buf, rtmp, rtmp->hdrlen);
    if (!res)
    {
        ast_log(LOG_WARNING, "Cannot set RTMP header\n");
        ast_free(message);
        return NULL;
    }

    if (rtmp->hdrlen != res){
        ast_log(LOG_WARNING, "Bad header lg %d!=%d\n", rtmp->hdrlen, res);
        ast_free(message);
        return NULL;
    }

    buf += res;

    /* set sound information
     * The first byte is not a media packet,
     * it contains the following codec information :
     *  soundType   (byte & 0x01) >> 0  0: mono, 1: stereo
     *  soundSize   (byte & 0x02) >> 1  0: 8-bit, 1: 16-bit
     *  soundRate   (byte & 0x0c) >> 2  0: 5.5 kHz, 1: 11 kHz, 2: 22 kHz, 3: 44 kHz
     *  soundFormat (byte & 0xf0) >> 4  0: Uncompressed, 1: ADPCM, 2: MP3, 5: Nellymoser 8kHz mono, 6: Nellymoser, 11: Speex
     * */
    *(uint8_t *) buf = firstbyte;
    buf++;

    /* copy samples */
    memcpy(buf, samples, datalen);

    return message;
}

static char *rtmp_build_video(struct rtmp_message *rtmp, void *samples,
        int datalen)
{
    int res = (-1);
    void *buf = NULL;
    void *message = NULL;         /* serialized RTMP header + body */

    if (debug)
        ast_debug(3, "In rtmp_build_video\n");
    rtmp->bodysize = datalen + 0; /* first byte contains audio description */

    message =
            ast_calloc(1, rtmp->hdrlen + rtmp->bodysize + RTMP_EXTENDEDTIMESTAMP_SIZE);
    if (!message)
    {
        ast_log(LOG_ERROR, "Memory allocation failure\n");
        return NULL;
    }

    buf = message;

    /* copy header */
    res = rtmp_set_header(buf, rtmp, rtmp->hdrlen);
    if (!res)
    {
        ast_log(LOG_WARNING, "Cannot set RTMP header\n");
        ast_free(message);
        return NULL;
    }

    if (rtmp->hdrlen != res){
        ast_log(LOG_WARNING, "Bad header lg %d!=%d\n", rtmp->hdrlen, res);
        ast_free(message);
        return NULL;
    }

    buf += res;

    //*(uint8_t *)buf = firstbyte;
    //buf++;

    /* copy samples */
    memcpy(buf, samples, datalen);

    return message;
}

static int rtmp_set_header(uint8_t * header, struct rtmp_message *rtmp,
        int hdrlen)
{
    int res = (-1);
    uint8_t *aux = header;
    uint32_t bodylen;
    uint32_t timestamp;
    uint32_t streamid;
    void *tmp = NULL;

    if (!header)
    {
        ast_log(LOG_WARNING, "Cannot set RTMP header\n");
        return res;
    }

    switch (hdrlen)
    {
        case 1:
            /* the first two bits are 11 (type 3) */
            *aux = (rtmp->channelid & 0x3F) | 0xC0;
            return 1;
        case 4:
            /* the first two bits are 10 (type 2) */
            *aux++ = (rtmp->channelid & 0x3F) | 0x80;
            memcpy(aux, "\0\0\0", 3);
            if (rtmp->timestampdelta)
            {
                timestamp = htonl(rtmp->timestampdelta);
                tmp = &timestamp;
                memcpy(aux, tmp + 1, 3);
            }
            return 4;
        case 8:
            /* the first two bits are 01 (type 1) */
            *aux++ = (rtmp->channelid & 0x3F) | 0x40;
            memcpy(aux, "\0\0\0", 3);
            if (rtmp->timestampdelta)
            {
                timestamp = htonl(rtmp->timestampdelta);
                tmp = &timestamp;
                memcpy(aux, tmp + 1, 3);
            }
            aux += 3;

            /* set body size in network byte order as a 3-bytes
             * field */
            bodylen = htonl(rtmp->bodysize);
            tmp = &bodylen;
            memcpy(aux, tmp + 1, 3);
            aux += 3;

            memcpy(aux++, &rtmp->type, 1);
            return 8;
        case 12:
            //
            // http://wiki.gnashdev.org/RTMP_Messages_Decoded
            //
            /* the first two bits are 00 (type 0) */
            *aux++ = rtmp->channelid & 0x3F;
            if (rtmp->timestamp < 0x00FFFFFF)
            {
                timestamp = htonl(rtmp->timestampdelta);
                tmp = &timestamp;
                memcpy(aux, tmp + 1, 3);
            }
            else
            {
                timestamp = htonl(0x00FFFFFF);
                tmp = &timestamp;
                memcpy(aux, tmp + 1, 3);
            }
            aux += 3;

            /* set body size in network byte order as a 3-bytes
             * field */
            bodylen = htonl(rtmp->bodysize);
            tmp = &bodylen;
            memcpy(aux, tmp + 1, 3);
            aux += 3;

            /* set RTMP packet type */
            memcpy(aux++, &rtmp->type, 1);

            /* set netsream (or connection) identifier */
            //streamid = htonl(rtmp->streamid);
            streamid = rtmp->streamid;
            tmp = &streamid;
            memcpy(aux, tmp, 4);
            aux += 4;

            if (rtmp->timestamp < 0x00FFFFFF)
                return 12;
            else
            {
                ast_log(LOG_WARNING, "Extended timestamp : %d\n", rtmp->timestamp);

                timestamp = htonl(rtmp->timestamp);
                tmp = &timestamp;
                memcpy(aux, tmp, 4);
                aux += 4;
                return 16;
            }
        default:
            ast_log(LOG_WARNING, "Unknown RTMP header length : %d\n", hdrlen);
            return res;
    }
}

static int rtmp_set_boolean(void *message, void *value)
{
    int res = (-1);
    char *buf = NULL;

    if (!message)
    {
        ast_log(LOG_WARNING, "Cannot set AMF boolean\n");
        return -1;
    }

    if (!value)
    {
        return 0;
    }

    buf = message;
    if (debug)
        ast_debug(7, "Setting first byte\n");
    *buf++ = AMF_TYPE_BOOLEAN;
    memcpy(buf, value, 1);

    res = amf_booleanlen(value);
    return res;
}

static int rtmp_set_property(void *message, char *string)
{
    int res = (-1);
    char *buf = NULL;
    unsigned short len;

    if (!string || !message)
    {
        ast_log(LOG_WARNING, "Cannot set AMF object property\n");
        return 0;
    }
    len = htons(strlen(string));
    buf = message;
    memcpy(buf, &len, 2);
    buf += 2;
    if (debug)
        ast_debug(7, "Copying property\n");

    memcpy(buf, string, strlen(string));

    res = strlen(string) + 2;
    return res;
}

/** \brief Set string in an AMF message
 *
 * \note value in struct can be anything (not necessary a string), we need the
 * value length because string can be not terminated by '\0'. This also
 * prevents us from applying strlen like functions to string.
 */
static int rtmp_set_string(void *message, char *string, size_t length)
{
    int res = (-1);
    char *buf = NULL;
    unsigned short len;

    if (!message)
    {
        ast_log(LOG_WARNING, "Cannot set AMF string\n");
        return -1;
    }

    if (!string)
    {
        return 0;
    }

    len = htons(length);
    buf = message;
    if (debug)
        ast_debug(3, "Setting first byte\n");
    *buf++ = AMF_TYPE_STRING;
    memcpy(buf, &len, 2);
    buf += 2;
    if (debug)
    {
        char string2[1024];

        strncpy(string2, string, length);
        if (length<1024)
        {
            strncpy(string2, string, length);
            string2[length]=0;
        }
        else
        {
            strncpy(string2, string, 1023);
            string2[1023]=0;
        }

        ast_debug(3, "Copying string : %s - length : %d\n", string2,
                (int)length);
    }

    memcpy(buf, string, length);

    res = 1 + 2 + length;
    return res;
}

static int rtmp_set_number(void *message, double *number)
{
    int res = (-1);
    char *buf = NULL;
    int i;
    char *aux = (char *)number + sizeof(double) - 1;

    //unsigned char *ptr = number;

    if (!message)
    {
        ast_log(LOG_WARNING, "Cannot set AMF number\n");
        return 0;
    }

    //ptr = (unsigned char*)number;
    //if (debug)
    //I6DEBUG(7, client, "Double value : %02x%02x%02x%02x%02x%02x%02x%02x",
    //  *(ptr++), *(ptr++),*(ptr++),*(ptr++),
    //  *(ptr++), *(ptr++),*(ptr++),*(ptr++));

    if (debug)
        ast_debug(7, "Double value : %f\n", *number);

    buf = message;
    *buf++ = AMF_TYPE_NUMBER;
    /* copy the content of number in network byte order.
     * FIXME : do that if needed only */
    for (i = 0; i < sizeof(double); i++)
    {
        //memcpy(buf++, aux--, 1);
        *buf++ = *aux--;
    }

    //ptr = (unsigned char*)message;
    //ptr++;
    //if (debug)
    //I6DEBUG(7, client, "Double value : %02x%02x%02x%02x%02x%02x%02x%02x",
    //  *(ptr++), *(ptr++),*(ptr++),*(ptr++),
    //  *(ptr++), *(ptr++),*(ptr++),*(ptr++));

    res = amf_numberlen(number);
    return res;
}

static int rtmp_set_null(void *message)
{
    int res = (-1);
    char *buf = NULL;

    if (!message)
    {
        ast_log(LOG_WARNING, "Cannot set AMF NULL\n");
        return 0;
    }

    buf = message;
    *buf++ = AMF_TYPE_NULL;
    res = 1;

    return res;
}

static int rtmp_set_undefined(void *message)
{
    int res = (-1);
    char *buf = NULL;

    if (!message)
    {
        ast_log(LOG_WARNING, "Cannot set AMF UNDEFINED\n");
        return 0;
    }

    buf = message;
    *buf++ = AMF_TYPE_UNDEFINED;
    res = 1;

    return res;
}

static int rtmp_set_object(void *message, struct amf_object *amf)
{
    int res = (-1);
    char *buf = NULL;
    struct amf_basic_object *bobject = NULL;
    double aux;
    int tmp = 0;

    if (!message)
    {
        ast_log(LOG_WARNING, "Cannot set AMF object\n");
        return res;
    }

    buf = message;

    if (!amf)
    {
        /* set a NULL object if amf is NULL */
        *buf = AMF_TYPE_NULL;
        return 1;
    }

    bobject = amf->bobject;
    *buf++ = AMF_TYPE_OBJECT;
    tmp++;
    if (debug)
        ast_debug(7, "Setting basic objects\n");
    while (bobject)
    {
        /* append object property string and value */
        res = rtmp_set_property(buf, bobject->property);
        buf += res;
        tmp += res;
        if (debug)
            ast_debug(7, "property : %s, length : %d, res = %d, expected res = %d\n",
                    bobject->property, (int)strlen(bobject->property), res,
                    2 + (int)strlen(bobject->property));
        switch (bobject->type)
        {
            case AMF_TYPE_NUMBER:
                memcpy(&aux, bobject->value, sizeof(double));
                res = rtmp_set_number(buf, &aux);
                buf += res;
                tmp += res;
                if (debug)
                    ast_debug(7, "Inserted NUMBER. res = %d, expected res = %d\n", res,
                            9);
                break;
            case AMF_TYPE_BOOLEAN:
                res = rtmp_set_boolean(buf, bobject->value);
                buf += res;
                tmp += res;
                if (debug)
                    ast_debug(7, "Inserted BOOLEAN. res = %d, expected res = %d\n", res,
                            2);
                break;
            case AMF_TYPE_STRING:
                res =
                        rtmp_set_string(buf, (char *)bobject->value, bobject->length - 1 - 2);
                buf += res;
                tmp += res;
                if (debug)
                    ast_debug(7, "Inserted STRING : %s. res = %d, expected res = %d\n",
                            (char *)bobject->value, res, bobject->length);
                break;
            case AMF_TYPE_NULL:
                res = rtmp_set_null(buf);
                buf += res;
                tmp += res;
                if (debug)
                    ast_debug(7, "Inserted NULL. res = %d, expected res = %d\n", res, 2);
                break;
            default:
                ast_log(LOG_WARNING, "Unknown AMF type : %d\n", bobject->type);
                return -1;

        }
        bobject = bobject->next;
    }

    /* append AMF object ending sequence */
    memset(buf, '\0', 2);
    buf += 2;
    tmp += 2;
    *buf++ = AMF_TYPE_OBJECT_END;
    tmp++;
    if (debug)
        ast_debug(7, "Object size = %d, 1 + amf->size + 3 = %d, tmp = %d\n",
                buf - (char *)message, 1 + (int)amf->size + 3, tmp);
    if (debug)
        ast_debug(7, "buf - 1 : %u\n", *(buf - 1));
    if (debug)
        ast_debug(7, "buf - 2 : %u\n", *(buf - 2));
    if (debug)
        ast_debug(7, "buf - 3 : %u\n", *(buf - 3));

    /* start byte + actual object length + ending sequence */
    res = amf_objlen(amf);
    return res;
}

static int rtmp_set_array(void *message, struct amf_object *amf)
{
    int res = (-1);
    char *buf = NULL;
    struct amf_basic_object *bobject = NULL;
    double aux;
    int tmp = 0;
    uint32_t len;

    if (!message)
    {
        ast_log(LOG_WARNING, "Cannot set AMF array\n");
        return res;
    }

    buf = message;

    if (!amf)
    {
        /* set a NULL object if amf is NULL */
        *buf = AMF_TYPE_NULL;
        return 1;
    }

    bobject = amf->bobject;
    *buf++ = AMF_TYPE_MIXED_ARRAY;
    tmp++;
    len = htonl(amf_objcount(amf));
    if (debug)
        ast_debug(7, "Setting length\n");
    memcpy(buf, &len, 4);
    buf += 4;
    if (debug)
        ast_debug(7, "Setting basic objects\n");
    while (bobject)
    {
        /* append object property string and value */
        res = rtmp_set_property(buf, bobject->property);
        buf += res;
        tmp += res;
        if (debug)
            ast_debug(7, "property : %s, length : %d, res = %d, expected res = %d\n",
                    bobject->property, (int)strlen(bobject->property), res,
                    2 + (int)strlen(bobject->property));
        switch (bobject->type)
        {
            case AMF_TYPE_NUMBER:
                memcpy(&aux, bobject->value, sizeof(double));
                res = rtmp_set_number(buf, &aux);
                buf += res;
                tmp += res;
                if (debug)
                    ast_debug(7, "Inserted NUMBER. res = %d, expected res = %d\n", res,
                            9);
                break;
            case AMF_TYPE_BOOLEAN:
                res = rtmp_set_boolean(buf, bobject->value);
                buf += res;
                tmp += res;
                if (debug)
                    ast_debug(7, "Inserted BOOLEAN. res = %d, expected res = %d\n", res,
                            2);
                break;
            case AMF_TYPE_STRING:
                res =
                        rtmp_set_string(buf, (char *)bobject->value, bobject->length - 1 - 2);
                buf += res;
                tmp += res;
                if (debug)
                    ast_debug(7, "Inserted STRING : %s. res = %d, expected res = %d\n",
                            (char *)bobject->value, res, bobject->length);
                break;
            case AMF_TYPE_NULL:
                res = rtmp_set_null(buf);
                buf += res;
                tmp += res;
                if (debug)
                    ast_debug(7, "Inserted NULL. res = %d, expected res = %d\n", res, 2);
                break;
            default:
                ast_log(LOG_WARNING, "Unknown AMF type : %d\n", bobject->type);
                return -1;

        }
        bobject = bobject->next;
    }

    /* append AMF object ending sequence */
    memset(buf, '\0', 2);
    buf += 2;
    tmp += 2;
    *buf++ = AMF_TYPE_OBJECT_END;
    tmp++;
    if (debug)
    {
        ast_debug(7, "Object size = %d, 1 + amf->size + 3 = %d, tmp = %d\n",
                buf - (char *)message, 1 + (int)amf->size + 3, tmp);
        ast_debug(7, "buf - 1 : %u\n", *(buf - 1));
        ast_debug(7, "buf - 2 : %u\n", *(buf - 2));
        ast_debug(7, "buf - 3 : %u\n", *(buf - 3));
    }

    /* start byte + actual object length + ending sequence */
    res = amf_arraylen(amf);
    return res;
}

/** \brief Return the length of an AMF encoded boolean */
static int amf_numberlen(double *number)
{
    return number ? 1 + sizeof(double) : 0;
}

/** \brief Return the length of an AMF encoded boolean */
static int amf_booleanlen(void *boolean)
{
    return boolean ? 1 + 1 : 0;
}

/** \brief Return the length of an AMF encoded string */
static int amf_strlen(char *string)
{
    return string ? 1 + 2 + strlen(string) : 0;
}

/** \brief Return the length of an AMF encoded object
 * We return 1 if object is NULL because the inserted symbol in this case
 * is AMF_TYPE_NULL
 * */
static int amf_objlen(struct amf_object *object)
{
    return object ? 1 + 3 + object->size : 1;
}

static int amf_arraylen(struct amf_object *object)
{
    // JYG Why +4 ???
    //return object ? 1 + 3 + 4 + 1 + object->size : 1;
    return object ? 1 + 3 + 1 + object->size : 1;
}

static int amf_objcount(struct amf_object *object)
{
    int res = 0;
    struct amf_basic_object *aux = NULL;

    aux = object->bobject;
    while (aux)
    {
        res++;
        aux = aux->next;
    }

    return res;
}


static int rtmp_receive_line(struct rtmp_client *client, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;

    if (client == NULL)
        return -1;

    if (client->fd == (-1))
        return -1;

    while ((i < size - 1) && (c != '\n'))
    {
        n = recv(client->fd, &c, 1, 0);
        /* DEBUG printf("%02X\n", c); */
        if (n > 0)
        {
            if (c == '\r')
            {
                n = recv(client->fd, &c, 1, MSG_PEEK);
                /* DEBUG printf("%02X\n", c); */
                if ((n > 0) && (c == '\n'))
                    recv(client->fd, &c, 1, 0);
                else
                    c = '\n';
            }
            buf[i] = c;
            i++;
        }
        else
            c = '\n';
    }
    buf[i] = '\0';

    return (i);
}

static int rtmp_receive_data(struct rtmp_client *client, uint8_t * data,
        int length, int timeout)
{
    int result;
    struct pollfd fds[1];
    uint8_t * ptr = data;
    int readen = 0;

    if (client == NULL)
        return -1;

    if (client->fd == (-1))
        return -1;

    // Calculat the bandwidth
    if (ast_tvdiff_ms(ast_tvnow(), client->timecalc) > 10000)
    {
        client->incoming_bandwidth =
                (client->incoming_bytescount - client->incoming_timebytescount) / 10;
        client->outgoing_bandwidth =
                (client->outgoing_bytescount - client->outgoing_timebytescount) / 10;
        client->incoming_timebytescount = client->incoming_bytescount;
        client->outgoing_timebytescount = client->outgoing_bytescount;

        client->timecalc = ast_tvnow();
    }

    I6DEBUG(9, client, "rtmp_receive_data : req %d bytes\n", length);
    //I6DEBUG(9, client, " %02X %02X %02X %02X    %c %c %c %c\n", ptr[0],ptr[1],ptr[2],ptr[3], ptr[0],ptr[1],ptr[2],ptr[3]);

    result = 0;
    while (readen != length)
    {
        fds[0].fd = client->fd;
        fds[0].events = POLLIN | POLLERR;
        fds[0].revents = 1;

        result = poll(fds, 1, timeout);

        I6DEBUG(9, client, "rtmp_receive_data : poll result=%d\n", result);

        if (result == 0) {
            I6DEBUG(8, client, "rtmp_receive_data : poll timeout (%d)\n", timeout);
            return 0;
        }
        else if (result < 0) {
            ast_log(LOG_ERROR, "Pool error %d\n", errno);
            return -1;
        }

        if (result > 0)
        {
            I6DEBUG(9, client, "rtmp_receive_data : wait for %d/%d\n", (length-readen), length);
            if ((client->tcptls_session != NULL) && (client->tcptls_session->ssl != NULL)) {
                result = SSL_read(client->tcptls_session->ssl, ptr, (length-readen));
                I6DEBUG(9, client, "rtmp_receive_data: TCP/SSL read %d/%d\n",result, (length-readen));
            }
            else {
                result = recv(client->fd, ptr, (length-readen), MSG_DONTWAIT);
                I6DEBUG(9, client, "rtmp_receive_data: TCP read %d/%d\n",result, (length-readen));
            }

            //result = ast_tcptls_server_read(client->threadinfo->tcptls_session, ptr, (length-readen));
            if (result < 0)
            {
                char err[256];
                if ((client->tcptls_session != NULL) && (client->tcptls_session->ssl != NULL)) {
                    I6DEBUG(0, client, "rtmp_receive_data SSL_read failed (%d): %s\n",SSL_get_error(client->tcptls_session->ssl, result),ERR_error_string(ERR_get_error(), err));
                }
                else {
                    I6DEBUG(0, client, "rtmp_receive_data recv failed (%d):(%d) %s\n", result, errno, strerror(errno));
                }
                return -1;
            }
            else if (result == 0) {
                I6DEBUG(8, client, "rtmp_receive_data : read 0!\n");
                return -1;
            }
            I6DEBUG(9, client, "rtmp_receive_data : recv %do\n", result);

            if (result > 0)
            {
                if ((client->protocol && RTMP_FEATURE_ENC) &&
                    (client->rc4keyIn != NULL))
                {
                    I6DEBUG(9, client, "rtmp_receive_data : decrypt %do\n", result);
                    RC4_encrypt(client->rc4keyIn, result, ptr);
                }
                client->incoming_bytescount += result;
                ptr+=result;
                readen+=result;
                I6DEBUG(9, client, "rtmp_receive_data : readlen %d\n", readen);
                if ((client->tcptls_session != NULL) && (client->tcptls_session->ssl != NULL)) {
                    break;
                }
            }
        }
    }

    ast_mutex_lock(&client->lock);

    // Send the acknowledgement
    if (client->incoming_bytescount >
            (client->lastack + client->incoming_windowsize))
    {
        rtmp_send_acknowledgement(client, client->incoming_bytescount);
    }
    ast_mutex_unlock(&client->lock);

    return readen;
}

/*
 * SendTcp send over TCP with ecryption or not and using ssl if necessary
 */
static int SendTcp(struct rtmp_client *client, uint8_t * data,int length)
{
    int mallocEnc = 0;
    int result = 0;
    uint8_t *encrypted = NULL;
    uint8_t *ptr = data;
    if ((client->protocol && RTMP_FEATURE_ENC) && (client->rc4keyOut != NULL))
    {
        char buf[RTMP_BLOCK_SIZE];
        I6DEBUG(9, client, "rtmp_send_data : encrypt\n");

        if (length > sizeof(buf))   {
            encrypted = (char *)malloc(length);
            if (encrypted == NULL) {
                I6LOG(LOG_WARNING, client, "RTMP/TCP ecnrypted: allocation failed!\n");
                return -1;
            }
            mallocEnc = 1;
        }
        else
            encrypted = (char *)buf;
        ptr = encrypted;
        RC4_encrypt2(client->rc4keyOut, length, data, ptr);
    }

    if ((client->tcptls_session != NULL) && (client->tcptls_session->ssl != NULL)){
        result = SSL_write(client->tcptls_session->ssl, ptr, length);
        I6DEBUG(9, client, "rtmp_send_data: TCP/SSL write %d/%d\n", result, length);
    }
    else {
        result = send(client->fd, ptr, length, 0);
        I6DEBUG(9, client, "rtmp_send_data: TCP write %d/%d\n", result, length);
    }

    if (mallocEnc && (client->protocol && RTMP_FEATURE_ENC) && (client->rc4keyOut != NULL) )
        free(encrypted);

    return result;
}

static int rtmp_send_data(struct rtmp_client *client, uint8_t * data, int length)
{
    int result = 0;
    int numBytes = 0;             // TCP out internal buffer

    if (client == NULL)
        return -1;

    // Calculat the bandwidth
    if (ast_tvdiff_ms(ast_tvnow(), client->timecalc) > 10000)
    {
        client->incoming_bandwidth =
                (client->incoming_bytescount - client->incoming_timebytescount) / 10;
        client->outgoing_bandwidth =
                (client->outgoing_bytescount - client->outgoing_timebytescount) / 10;
        client->incoming_timebytescount = client->incoming_bytescount;
        client->outgoing_timebytescount = client->outgoing_bytescount;

        client->timecalc = ast_tvnow();
    }

    if (client->protocol & RTMP_FEATURE_HTTP)
    {
        length = 0;
    }

    /*
    {
      char c;
      errno = 0;
      if  (recv(client->fd, &c, 1, MSG_PEEK | MSG_DONTWAIT)==(-1))
      {
        I6DEBUG(3, client, "Connection closed.\n");
        return -1;
      }
    }
     */

    // Check if TCP buffer overflow
    if (tcpbuffer)
    {
        if (ioctl(client->fd, SIOCOUTQ, &numBytes) < 0){
            I6DEBUG(3, client, "ioctl error\n");
        }

        I6DEBUG(3, client, "RTMP Buffer TCP OUT =%d\n", numBytes);

        if (client->chunks_buffer)
        {
            if (numBytes + length + (client->outgoing_chunksize + 1) * chunksbuffer > tcpbuffer)
            {
                // No more space for buffering
                I6DEBUG(3, client, "RTMP/TCP Overwrite (%d+%d+%d>%d).\n", numBytes,
                        length, (client->outgoing_chunksize + 1) * chunksbuffer, tcpbuffer);

                client->overwrites_count++;

                if (client->overwrites_max)
                if (client->overwrites_count > client->overwrites_max)
                {
                  ast_log(LOG_ERROR, "WRITE ERROR : client %p, close connection!\n", client);

                  if (client->fd != (-1))
                    close(client->fd);
                  client->fd = (-1);
                }

                return 0;
            }
        }
        else if (numBytes + length > tcpbuffer)
        {
            I6LOG(LOG_WARNING, client, "RTMP/TCP Overwrite (%d+%d>%d).\n", numBytes,
                    length, tcpbuffer);

            client->overwrites_count++;

            if (client->overwrites_max)
            if (client->overwrites_count > client->overwrites_max)
            {
              ast_log(LOG_ERROR, "WRITE ERROR : client %p, close connection!\n", client);

              if (client->fd != (-1))
                close(client->fd);
              client->fd = (-1);
            }

            return 0;
        }
    }

    client->overwrites_count = 0;

    if (debug)
        I6DEBUG(7, client, "rtmp_send_data len %d (bufoff %d buffsize %d)\n",
                length, client->chunks_bufferoffset, client->chunks_buffersize);

    if (client->chunks_buffer)
    {
        int chunksize = (client->outgoing_chunksize + 1) * chunksbuffer;

        I6DEBUG(7, client, "All chunks not send: chunksize %d  (%d / %d)\n",
                chunksize, client->chunks_bufferoffset, client->chunks_buffersize);

        if (client->chunks_buffersize <= (client->chunks_bufferoffset + chunksize))
        {
            void *ptr = client->chunks_buffer;

            if (ptr != NULL)
            {
                chunksize = (client->chunks_buffersize - client->chunks_bufferoffset);

                result = SendTcp(client, client->chunks_buffer + client->chunks_bufferoffset,chunksize);

                if (result != chunksize)
                {
                    I6LOG(LOG_WARNING, client, "RTMP/TCP Write error (%d!=%d).\n", result,
                            chunksize);

                    client->chunks_buffer = NULL;
                    client->chunks_buffersize = 0;

                    ast_free(ptr);

                    return -1;
                }
                else
                    I6DEBUG(7, client, "rtmp_send_data: %d bytes wrote (all chunks sent)\n",
                            result);

                {
                    char tmp[1024];
                    sprintf(tmp, "RTMP/%p send (chunks)", client);
                    dump_buffer_hex(tmp,
                            client->chunks_buffer + client->chunks_bufferoffset, chunksize);
                }

                client->chunks_buffer = NULL;
                client->chunks_buffersize = 0;

                ast_free(ptr);
            }
            else
                I6LOG(LOG_WARNING, client, "RTMP/TCP Chucks buffer invalid!\n");
        }
        else
        {
            void *ptr = client->chunks_buffer;

            result = SendTcp(client, client->chunks_buffer + client->chunks_bufferoffset,chunksize);

            if (result != chunksize)
            {
                {
                    char tmp[1024];
                    sprintf(tmp, "RTMP/%p send (chunks)", client);
                    dump_buffer_hex(tmp,
                            client->chunks_buffer + client->chunks_bufferoffset, chunksize);
                }

                I6LOG(LOG_WARNING, client, "RTMP/TCP Write error (%d!=%d).\n", result,
                        chunksize);
                client->chunks_buffer = NULL;
                client->chunks_buffersize = 0;
                ast_free(ptr);
                length = 0;

                if (client->fd != (-1))
                    close(client->fd);
                client->fd = (-1);
            }
            else
            {
                client->chunks_bufferoffset += chunksize;
                I6DEBUG(7, client,
                        "rtmp_send_data: %do wrote (bufoff=%d / bufsize %d)\n", result,
                        client->chunks_bufferoffset, client->chunks_buffersize);

                if (length > 0)
                {
                    I6DEBUG(7, client,
                            "All chunks are not sent, but we have data to send %d !!\n",
                            length);
                }
            }
        }
    }
    else
    {
        /*
         * We need to start the buffering of chunk, so save info
         * It's not done by caller because of the critial section
         */
        if (client->chunks_buffersize != 0)
            if (length)
            {
                client->chunks_bufferoffset = length;
                client->chunks_buffer = data;
                //ast_log(LOG_ERROR, "client = %p, data = %p, length=%d.\n", client, data, length);
                client->chunks_buffer = ast_calloc(1,client->chunks_buffersize);
                memcpy(client->chunks_buffer, data, client->chunks_buffersize);
                I6DEBUG(7, client,
                        "rtmp_send_data: chunk started: bufoff=%d / bufsize %d\n",
                        client->chunks_bufferoffset, client->chunks_buffersize);
            }
    }

    if (length > 0)
    {
        result = SendTcp(client, data, length);
        if (result != length)
        {
            I6LOG(LOG_WARNING, client, "RTMP/TCP Write error (%d!=%d).\n", result,
                    length);

            if (client->fd != (-1))
                close(client->fd);
            client->fd = (-1);
        }
        else
            I6DEBUG(7, client, "rtmp_send_data: %do wrote\n", result);
    }

    if (result > 0)
        client->outgoing_bytescount += result;

    return result;
}

static int rtmp_send_message(struct rtmp_client *client, uint8_t * prefix,
        uint8_t * message, size_t bodysize, int iType)
{
    int res = 0;
    int hdrlen = 0;
    uint8_t channelid = 0;
    uint8_t *body = NULL;
    uint8_t *buffer = NULL;
    uint8_t *aux = NULL;
    struct rtmp_message *rtmp = NULL;
    int chunks = 0;
    int buflen = 0;
    int i;
    int offset = 0;

    if (!client || !message)
    {
        ast_log(LOG_ERROR, "Cannot send message\n");
        return -1;
    }

    if (client->outgoing_chunksize == 0)
    {
        ast_log(LOG_ERROR, "chunksize NULL!\n");
        return -1;
    }

    // Alloc the message
    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        res = (-1);
        goto safeout;
    }

    // Fill the headers
    hdrlen = rtmp_get_header_length(message);
    channelid = rtmp_get_channelid(message);
    chunks =
            (int)(bodysize % client->outgoing_chunksize ==
                    0) ? bodysize / client->outgoing_chunksize : bodysize /
                            client->outgoing_chunksize + 1;
    body = message + hdrlen;

    rtmp->hdrlen = hdrlen;
    rtmp->channelid = channelid;
    rtmp->bodysize = bodysize;
    /* TODO : process timestamp */
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;
    rtmp->streamid = rtmp_get_streamid(message);

    // Debug messages
    if (debug)
    {
        if (iType == RTMP_TYPE_VIDEO_DATA)
        {
            I6DEBUG(6, client, "send_message VIDEO chid %d hdrlrn %d lg %d (%d)\n",
                    rtmp->channelid, rtmp->hdrlen, rtmp->bodysize,
                    client->outgoing_chunksize);
        }
        else if (iType == RTMP_TYPE_AUDIO_DATA)
        {
            I6DEBUG(6, client, "send_message AUDIO chid %d hdrlrn %d lg %d (%d)\n",
                    rtmp->channelid, rtmp->hdrlen, rtmp->bodysize,
                    client->outgoing_chunksize);
        }
        else
        {
            I6DEBUG(6, client, "send_message type %d chid %d hdrlrn %d lg %d (%d)\n",
                    rtmp->type, rtmp->channelid, rtmp->hdrlen, rtmp->bodysize,
                    client->outgoing_chunksize);
        }
    }

    // Single not chunked message
    if ((chunks == 1))
    {
        // !! de base l'audio est chunke !!!  || (iType == RTMP_TYPE_AUDIO_DATA )) {
        if (iType == RTMP_TYPE_VIDEO_DATA)
            if (client->chunks_buffer)
            {
                I6DEBUG(3, client, "Not pushed all the last chunks (%d / %d) !\n",
                        client->chunks_bufferoffset, client->chunks_buffersize);

                int maxloop = 500;

                while (client->chunks_buffer)
                {
                    int res;

                    res = rtmp_send_data(client, NULL, 0);
                    if (res == -1)
                        goto safeout;

                    if (!res)
                    {
                        I6DEBUG(7, client, "Fail 2 %d!\n", maxloop);
                        //ast_log(LOG_ERROR, "Fail 2 !\n");
                        maxloop--;
                        if (!maxloop)
                        {
                            I6LOG(LOG_WARNING, client, "Fail to send datas after waiting loop (video chunks)!\n");
                            goto safeout;
                        }
                        ast_mutex_unlock(&client->lock);
                        usleep(10000);
                        ast_mutex_lock(&client->lock);
                    }
                }
            }

        I6DEBUG(7, client,
                "Sent one chunk: hdrlen=%d, chid=%d, bodysize=%d, chunkbuff=%s\n", hdrlen,
                channelid, bodysize, client->chunks_buffer ? "yes" : "no");

        /* we can send the whole message in a single chunk */
        res = rtmp_set_outgoing_channelinfo(client, rtmp, hdrlen);
        if (!res)
        {
            ast_log(LOG_WARNING, "could not update outgoing stream information\n");
        }

        // Send Control Messages
        if ((iType != RTMP_TYPE_VIDEO_DATA) && ((iType != RTMP_TYPE_AUDIO_DATA)))
        {
            int maxloop = 500;

            while(!(res=rtmp_send_data(client, message, hdrlen + bodysize)))
            {
                res = rtmp_send_data(client, NULL, 0);
                if (res == -1)
                    goto safeout;

                if (!res)
                {
                    I6DEBUG(7, client, "Fail 3 %d!\n", maxloop);


                    maxloop--;
                    if (!maxloop)
                    {
                        close(client->fd);
                        client->fd = (-1);

                        res = -1;
                        I6LOG(LOG_ERROR, client, "Fail to send datas after waiting loop (control message)!\n");
                        goto safeout;
                    }

                    //ast_mutex_unlock(&client->lock);
                    usleep(10000);
                    //ast_mutex_lock(&client->lock);
                }
            };
        }
        else
        {
            // Message can be lost
            res = rtmp_send_data(client, message, hdrlen + bodysize);
        }

        if (res)
        {
            char tmp[1024];
            sprintf(tmp, "RTMP/%p send", client);
            dump_buffer_hex(tmp, message, hdrlen + bodysize);

        }
        else
        {
            char tmp[1024];
            sprintf(tmp, "RTMP/%p NOT send", client);
            dump_buffer_hex(tmp, message, hdrlen + bodysize);
        }

        goto safeout;
    }

    /* reserve space for buffer to send :
     * header + number of 1-byte headers to insert + bodysize */
    if (prefix)
    {
        buflen = RTMP_BLOCK_SIZE + hdrlen + (chunks - 1) * 1 + (int)bodysize;
    }
    else
    {
        buflen = hdrlen + (chunks - 1) * 1 + bodysize;
    }

    I6DEBUG(7, client,
            "Sending message, hdrlen=%d, channelid=%d, chunks=%d, bodysize=%d, buflen=%d, chunkbuff=%s\n",
            hdrlen, channelid, chunks, bodysize, buflen,
            client->chunks_buffer ? "yes" : "no");

    buffer = ast_calloc(1, buflen);
    if (!buffer)
    {
        res = (-1);
        goto safeout;
    }
    memset(buffer, '\0', buflen);

    if (prefix)
    {
        memcpy(buffer, prefix, RTMP_BLOCK_SIZE);
        aux = buffer + RTMP_BLOCK_SIZE;
    }
    else
    {
        aux = buffer;
    }

    /* copy header */
    memcpy(aux, message, hdrlen);
    aux += hdrlen;

    offset =
            hdrlen + chunksbuffer * (client->outgoing_chunksize) + chunksbuffer - 1;

    for (i = 0; i < chunks; i++)
    {
        /* copy body, insert 1-byte header between 128-bytes chunks */
        int chunksize =
                (i ==
                        chunks -
                        1) ? bodysize % client->outgoing_chunksize : client->outgoing_chunksize;
        res = rtmp_set_outgoing_channelinfo(client, rtmp, hdrlen);
        if (!res)
        {
            ast_log(LOG_WARNING, "could not update outgoing stream information\n");
        }
        memcpy(aux, body + i * client->outgoing_chunksize, chunksize);
        if (debug)
            I6DEBUG(8, client, "Copying %d bytes chunk %d/%d\n", chunksize, i, chunks);

        aux += chunksize;
        if (i < chunks - 1)
        {
            if (debug)
                I6DEBUG(8, client, "Inserting header : %Xh\n", 0xC0 | channelid);
            memset(aux++, 0xC0 | channelid, 1);
        }
        hdrlen = 1;
    }

    //if ((rtmp->type == RTMP_TYPE_VIDEO_DATA ) && (client->chunks_buffer))
    if (client->chunks_buffer)
    {
        I6DEBUG(3, client, "Not pushed all the last chunks (%d / %d) !\n",
                client->chunks_bufferoffset, client->chunks_buffersize);

        int maxloop = 500;

        while (client->chunks_buffer)
        {
            res = rtmp_send_data(client, NULL, 0);
            if (res == -1)
                goto safeout;

            if (!res)
            {
                usleep(10000);
                maxloop--;
                if (!maxloop)
                {
                    I6LOG(LOG_ERROR, client, "Fail to send datas after waiting loop (control message)!\n");
                    goto safeout;
                }
                ast_mutex_unlock(&client->lock);
                usleep(10000);
                ast_mutex_lock(&client->lock);
            }
        }
    }

    /* JUST TO ENABLE BLUSENS !!! FFPHONE can't really chunks
     if (chunksbuffer && (chunks > chunksbuffer) && (!client->chunks_buffer))
     */
    if ((client->playstream2 != (-1.0)) && (chunks > chunksbuffer) &&
            (!client->chunks_buffer))
    {
        {
            char tmp[1024];
            sprintf(tmp, "RTMP/%p Full DUMP !!!", client);
            dump_buffer_hex(tmp, buffer, buflen);
        }

        I6DEBUG(7, client, "send %d of bufsize %d (chunks %d)\n", offset, buflen,
                chunks);

        if (client->chunks_buffersize !=0)
            ast_log(LOG_ERROR, "chunks_buffersize not 0!\n");

        client->chunks_buffersize = buflen;

        res = rtmp_send_data(client, buffer, offset);
        if (res == offset)
        {
            char tmp[1024];
            sprintf(tmp, "RTMP/%p send (first chunks)", client);
            dump_buffer_hex(tmp, buffer, offset);
        }
        else
        {
            ast_log(LOG_ERROR, "Cannot send chunked packets (overwrite TCP 1st chunks) res=%d!=%d\n", res, offset);
            client->chunks_buffersize = 0;
            client->chunks_bufferoffset = 0;
        }

        I6DEBUG(7, client, "chunk rest: off %d bufsize %d\n",
                client->chunks_bufferoffset, client->chunks_buffersize);
    }
    else
    {
        res = rtmp_send_data(client, buffer, buflen);
        if (res == buflen)
        {
            char tmp[1024];
            sprintf(tmp, "RTMP/%p send (first chunks)", client);
            dump_buffer_hex(tmp, buffer, buflen);
        }
        else
        {
            ast_log(LOG_ERROR, "Cannot send chunked packets (overwrite TCP 1st chunks) res=%d!=%d\n", res, buflen);
        }
    }

    safeout:
    if (rtmp)
        ast_free(rtmp);
    if (buffer)
        ast_free(buffer);
    if (debug)
        I6DEBUG(7, client, "Returning, res = %d, buflen = %d\n", res, buflen);
    return res;
}


static int rtmp_send_message_direct(struct rtmp_client *client,
        uint8_t * prefix, uint8_t * message, size_t bodysize)
{
    int res = 0;
    int hdrlen = 0;
    uint8_t channelid = 0;
    uint32_t streamid = 0;
    uint8_t *body = NULL;
    uint8_t *buffer = NULL;
    uint8_t *aux = NULL;
    struct rtmp_message *rtmp = NULL;
    int chunks = 0;
    int buflen = 0;

    if (!client || !message)
    {
        ast_log(LOG_ERROR, "Cannot send message\n");
        return -1;
    }

    if (prefix)
    {
        buflen = RTMP_BLOCK_SIZE + hdrlen + 1 + (int)bodysize;
    }
    else
    {
        buflen = hdrlen + 1 + bodysize;
    }

    buffer = ast_calloc(1, buflen);
    if (!buffer)
    {
        res = (-1);
        goto safeout;
    }
    rtmp = ast_calloc(1, sizeof(*rtmp));
    if (!rtmp)
    {
        res = (-1);
        goto safeout;
    }

    if (debug)
        I6DEBUG(7, client, "chunk ?, %d, %d = %d\n", bodysize,
                client->outgoing_chunksize, (bodysize % client->outgoing_chunksize == 0));

    hdrlen = rtmp_get_header_length(message);
    channelid = rtmp_get_channelid(message);
    streamid = rtmp_get_streamid(message);
    ast_verbose("Get stream ID = %d", streamid);
    chunks =
            (int)(bodysize % client->outgoing_chunksize ==
                    0) ? bodysize / client->outgoing_chunksize : bodysize /
                            client->outgoing_chunksize + 1;
    body = message + hdrlen;

    memset(buffer, '\0', buflen);
    if (debug)
        I6DEBUG(7, client,
                "Sending message, hdrlen = %d, channelid = %d, chunks = %d, bodysize = %d, buflen = %d\n",
                hdrlen, channelid, chunks, bodysize, buflen);

    rtmp->hdrlen = hdrlen;
    rtmp->channelid = channelid;
    rtmp->streamid = streamid;
    rtmp->bodysize = bodysize;
    /* TODO : process timestamp */
    rtmp->timestamp = 0;
    rtmp->timestampdelta = 0;


    /* reserve space for buffer to send :
     * header + number of 1-byte headers to insert + bodysize */
    if (prefix)
    {
        buflen = RTMP_BLOCK_SIZE + hdrlen + (chunks - 1) * 1 + (int)bodysize;
    }
    else
    {
        buflen = hdrlen + (chunks - 1) * 1 + bodysize;
    }
    buffer = ast_calloc(1, buflen);
    if (!buffer)
    {
        res = (-1);
        goto safeout;
    }
    memset(buffer, '\0', buflen);
    if (debug)
        I6DEBUG(7, client,
                "Sending message, hdrlen = %d, channelid = %d, chunks = %d, bodysize = %d, buflen = %d\n",
                hdrlen, channelid, chunks, bodysize, buflen);

    if (prefix)
    {
        memcpy(buffer, prefix, RTMP_BLOCK_SIZE);
        aux = buffer + RTMP_BLOCK_SIZE;
    }
    else
    {
        aux = buffer;
    }

    res = rtmp_set_outgoing_channelinfo(client, rtmp, hdrlen);

    {
        /* we can send the whole message in a single chunk */
        //res = rtmp_set_outgoing_channelinfo(client, rtmp, hdrlen);
        memcpy(buffer, message, hdrlen + bodysize);
        res = rtmp_send_data(client, buffer, hdrlen + bodysize);
        //res = send(client->fd, buffer, hdrlen + bodysize, 0);
        {
            char tmp[1024];
            sprintf(tmp, "RTMP/%p send", client);
            dump_buffer_hex(tmp, buffer, hdrlen + bodysize);
        }
        if (debug)
            I6DEBUG(7, client, "Sent one chunk of data (%d bytes)\n", res);
        goto safeout;
    }

    safeout:
    ast_free(rtmp);
    ast_free(buffer);
    if (debug)
        I6DEBUG(7, client, "Returning, res = %d, buflen = %d\n", res, buflen);
    return res;
}

/**
 * \brief Update outgoing channel information
 *
 * This function must be called each time we send RTMP messages.
 */
static int rtmp_set_outgoing_channelinfo(struct rtmp_client *client,
        struct rtmp_message *rtmp, uint8_t next_hdrlen)
{
    switch (rtmp->hdrlen)
    {
        case 1:
            /* nothing to do */
            break;
        case 4:
            /* update the stream array */
            client->streams[rtmp->channelid]->timestamp[RTMP_OUTGOING] =
                    rtmp->timestamp;
            break;
        case 8:
            /* update the stream array */
            client->streams[rtmp->channelid]->timestamp[RTMP_OUTGOING] =
                    rtmp->timestamp;
            client->streams[rtmp->channelid]->bodylen[RTMP_OUTGOING] = rtmp->bodysize;
            client->streams[rtmp->channelid]->type[RTMP_OUTGOING] = rtmp->type;
            break;
        case 12:
        case 0:
            /* update the stream array */
            client->streams[rtmp->channelid]->timestamp[RTMP_OUTGOING] =
                    rtmp->timestamp;
            client->streams[rtmp->channelid]->bodylen[RTMP_OUTGOING] = rtmp->bodysize;
            client->streams[rtmp->channelid]->type[RTMP_OUTGOING] = rtmp->type;
            client->streams[rtmp->channelid]->streamid[RTMP_OUTGOING] =
                    rtmp->streamid;
            break;
    }

    client->streams[rtmp->channelid]->hdrlen[RTMP_OUTGOING] = next_hdrlen;

    return 1;
}

/**  \brief Update incoming channel information */
static int rtmp_set_incoming_channelinfo(struct rtmp_client *client,
        void *buffer, int hdrlen, int channelid)
{
    int res = (-1);
    char *aux = NULL;
    uint32_t timestamp = 0;
    uint32_t bodysize = 0;
    uint8_t type = 0;
    uint32_t streamid = 0;
    void *p = NULL;

    aux = buffer;
    if (debug)
        I6DEBUG(7, client, "Updating information for incoming channel %d\n",
                channelid);
    if (debug)
        I6DEBUG(7, client, "streams[%d] is %s\n", channelid,
                client->streams[channelid] ? "NOT NULL" : "NULL");

    if (!client->streams[channelid])
    {
        return -1;
    }
    switch (hdrlen)
    {
        case 1:
            /* nothing to do */
            break;
        case 4:
            /* timestamp is transmitted in 3 three bytes */
            p = (void *)&timestamp + 1;
            memcpy(p, aux, 3);
            timestamp = ntohl(timestamp);

            /* update the stream array */
            client->streams[channelid]->timestamp[RTMP_INCOMING] = timestamp;
            break;
        case 8:
            /* timestamp is transmitted in 3 three bytes */
            p = (void *)&timestamp + 1;
            memcpy(p, aux, 3);
            timestamp = ntohl(timestamp);
            aux += 3;
            p = (void *)&bodysize + 1;
            memcpy(p, aux, 3);
            bodysize = ntohl(bodysize);
            aux += 3;
            type = (uint8_t) * aux;

            /* update the stream array */
            client->streams[channelid]->timestamp[RTMP_INCOMING] = timestamp;
            client->streams[channelid]->bodylen[RTMP_INCOMING] = bodysize;
            client->streams[channelid]->type[RTMP_INCOMING] = type;
            if (debug)
                I6DEBUG(7, client, "streams[channelid]->bodylen[RTMP_INCOMING] = %d\n",
                        client->streams[channelid]->bodylen[RTMP_INCOMING]);
            break;
        case 12:
            /* timestamp is transmitted in 3 three bytes */
            p = (void *)&timestamp + 1;
            memcpy(p, aux, 3);
            timestamp = ntohl(timestamp);
            aux += 3;
            p = (void *)&bodysize + 1;
            memcpy(p, aux, 3);
            bodysize = ntohl(bodysize);
            aux += 3;
            type = (uint8_t) * aux;
            aux++;
            memcpy(&streamid, aux, 4);
            /* this parameter is sent in reversed network byte order! */
            //streamid = ntohl(streamid);

            /* update the stream array */
            client->streams[channelid]->timestamp[RTMP_INCOMING] = timestamp;
            client->streams[channelid]->bodylen[RTMP_INCOMING] = bodysize;
            client->streams[channelid]->type[RTMP_INCOMING] = type;
            client->streams[channelid]->streamid[RTMP_INCOMING] = streamid;
            if (debug)
                I6DEBUG(7, client, "streams[channelid]->bodylen[RTMP_INCOMING] = %d\n",
                        client->streams[channelid]->bodylen[RTMP_INCOMING]);
            break;
    }

    res = hdrlen;
    return res;
}
/** \brief Return the header length for a given channel id */
static int rtmp_get_current_hdrlen(struct rtmp_client *client,
        uint8_t channelid)
{
    return client->streams[channelid]->hdrlen[RTMP_OUTGOING];
}

/** \brief Return the timestamp for a given channel id */
static int rtmp_get_current_timestamp(struct rtmp_client *client,
        uint8_t channelid)
{
    return client->streams[channelid]->timestamp[RTMP_OUTGOING];
}

/** \brief Return the body length for a given channel id */
static int rtmp_get_current_bodylen(struct rtmp_client *client,
        uint8_t channelid)
{
    return client->streams[channelid]->bodylen[RTMP_OUTGOING];
}

/** \brief Return the RTMP packet type for a given channel id */
static int rtmp_get_current_type(struct rtmp_client *client, uint8_t channelid)
{
    return client->streams[channelid]->type[RTMP_OUTGOING];
}

/** \brief Return the RTMP stream identifier for a given channel id */
static int rtmp_get_current_streamid(struct rtmp_client *client,
        uint8_t channelid)
{
    return client->streams[channelid]->streamid[RTMP_OUTGOING];
}

static int rtmp_get_header_length(uint8_t * header)
{
    int res = (-1);
    if (!header)
    {
        if (debug)
            ast_debug(7, "Header is NULL\n");
        return res;
    }
    switch (header[0] & 0xC0)
    {
        case 0xC0:
            /* 11 000000 */
            return 1;
            break;
        case 0x80:
            /* 10 000000 */
            return 4;
            break;
        case 0x40:
            /* 01 000000 */
            return 8;
            break;
        case 0x00:
            /* 00 000000 */
            return 12;
            break;
    }

    return res;
}

static int rtmp_get_channelid(uint8_t * header)
{
    int res = (-1);

    if (!header)
    {
        if (debug)
            ast_debug(7, "Header is NULL\n");
        return res;
    }

    res = header[0] & 0x3F;

    return res;
}

static int rtmp_get_streamid(uint8_t * header)
{
    int res = 0;
    uint8_t *aux = NULL;
    uint32_t tmp = 0;
    /* body size is transmitted over 3 bytes, and tmp is 4-bytes long
     * so we'll copy the 3-bytes integer to the end of tmp */
    //void *p = (void *)&tmp + 1;

    aux = header;

    if (!header)
    {
        if (debug)
            ast_debug(7, "Header is NULL\n");
        return res;
    }

    switch (header[0] & 0xC0)
    {
        case 0x00:
            aux++;
            aux += 3;
            aux += 3;
            aux++;
            memcpy(&tmp, aux, 4);
            res = tmp;
            if (debug)
                ast_debug(7, "streamid=%d (%04X)\n", res, tmp);
            break;
    }

    return res;
}

/** \brief Get RTMP packet's body length
 *
 * Return the value contained in the header if it exists, otherwise return
 * the last value that matches with the channel id
 */
static int rtmp_get_bodylen(struct rtmp_client *client, uint8_t * header,
        struct rtmp_message *rtmp, int direction)
{
    int res = (-1);
    uint32_t size = 0;
    uint8_t *aux = NULL;
    /* body size is transmitted over 3 bytes, and tmp is 4-bytes long
     * so we'll copy the 3-bytes integer to the end of tmp */
    void *p = (void *)&size + 1;

    if (!header || !rtmp)
    {
        return res;
    }

    if (rtmp->hdrlen < 8)
    {
        if (client->streams[rtmp->channelid])
        {
            res = client->streams[rtmp->channelid]->bodylen[direction];
        }
        else
        {
            ast_log(LOG_WARNING,
                    "Channel not found, cannot return packet's length\n");
        }
    }
    else
    {
        aux = header + 3;
        memcpy(p, aux, 3);
        size = ntohl(size);
        res = size;
    }

    return res;
}

/** \brief Parse incoming RTMP header
 *
 * Set the fields of the rtmp_message structure
 *
 * \return The channel identifier for this RTMP message
 */
static int rtmp_parse_header(struct rtmp_message *rtmp, void *buffer)
{
    int res = (-1);
    char *aux = NULL;
    uint32_t tmp = 0;
    /* body size is transmitted over 3 bytes, and tmp is 4-bytes long
     * so we'll copy the 3-bytes integer to the end of tmp */
    void *p = (void *)&tmp + 1;

    aux = buffer;

    if (debug)
        ast_debug(7, "rtmp->channelid = %d\n", rtmp->channelid);
    switch (rtmp->hdrlen)
    {
        case 1:
            break;
        case 4:
            memcpy(p, aux, 3);
            rtmp->timestamp = ntohl(tmp);
            if (debug)
                ast_debug(7, "timestamp=%d (%04X)\n", rtmp->timestamp, tmp);
            break;
        case 8:
            memcpy(p, aux, 3);
            rtmp->timestamp = ntohl(tmp);
            if (debug)
                ast_debug(7, "timestamp=%d (%04X)\n", rtmp->timestamp, tmp);
            aux += 3;
            memcpy(p, aux, 3);
            rtmp->bodysize = ntohl(tmp);
            if (debug)
                ast_debug(7, "bodysize=%d (%04X)\n", rtmp->bodysize, tmp);
            aux += 3;
            rtmp->type = (uint8_t) * (aux);
            if (debug)
                ast_debug(7, "type=%d (%02X)\n", rtmp->type, rtmp->type);
            break;
        case 12:
            //memcpy(&rtmp->timestamp, aux + 1, 3);
            memcpy(p, aux, 3);
            rtmp->timestamp = ntohl(tmp);
            if (debug)
                ast_debug(7, "timestamp=%d (%04X)\n", rtmp->timestamp, tmp);
            aux += 3;
            memcpy(p, aux, 3);
            rtmp->bodysize = ntohl(tmp);
            if (debug)
                ast_debug(7, "bodysize=%d (%04X)\n", rtmp->bodysize, tmp);
            aux += 3;
            rtmp->type = (uint8_t) * (aux);
            if (debug)
                ast_debug(7, "type=%d (%02X)\n", rtmp->type, rtmp->type);
            aux++;
            memcpy(&tmp, aux, 4);
            //rtmp->streamid = ntohl(tmp);
            rtmp->streamid = tmp;
            if (debug)
                ast_debug(7, "streamid=%d (%04X)\n", rtmp->streamid, tmp);
            break;

    }

    if (debug)
        ast_debug(7, "rtmp->streamid = %d\n", rtmp->streamid);

    return res;
}

/** \brief Handle system messages
 *
 * Reply to PING messages
 * \note AMF body length of packet to build is the same as the one we receive
 * from the server
 */
static int rtmp_handle_system_message(struct rtmp_client *client,
        struct rtmp_message *rtmp)
{
    int res = (-1);
    uint16_t pingtype = 0;
    uint32_t pingtimestamp = 0;

    switch (client->streams[rtmp->channelid]->type[RTMP_INCOMING])
    {
        uint32_t temp = 0;
        case RTMP_TYPE_CHUNK_SIZE:
            RTMP_VERBOSE(client, ">* message/chunksize()\n");
            memcpy(&temp, rtmp->body, sizeof(temp));
            if (debug)
                I6DEBUG(7, client,
                        "Handling CHUNKSIZE message. Chunk size changed from %d to %d\n",
                        client->incoming_chunksize, ntohl(temp));
            client->incoming_chunksize = ntohl(temp);
            break;

        case RTMP_TYPE_BYTES_READ:
            memcpy(&temp, rtmp->body, sizeof(temp));
            temp = ntohl(temp);

            RTMP_VERBOSE(client, ">* message/acknowledgement(%d)\n", temp);

            //res = rtmp_send_acknowledgement(client, temp);
            break;

        case RTMP_TYPE_PING:
            memcpy(&pingtype, rtmp->body, 2);
            pingtype = ntohs(pingtype);
            memcpy(&pingtimestamp, rtmp->body, 4);
            pingtimestamp = ntohl(pingtimestamp);

            //I6DEBUG(7, client,"Handling PING message (ping type = %d)\n", pingtype);
            I6DEBUG(7, client, "Handling PING message (timestamp = %d)\n",
                    pingtimestamp);

            //ast_verbose(">* message/ping(%d)\n", pingtype);
            RTMP_VERBOSE(client, ">* message/ping(%d, %d)\n", pingtype,
                    pingtimestamp);

            switch (pingtype)
            {
                case RTMP_PING_TYPE_PING:
                    res = rtmp_send_pong(client, rtmp);
                    break;
                default:
                    break;
            }
            //res = rtmp_send_pong(client, rtmp);

            break;
                default:
                    if (debug)
                        I6DEBUG(7, client, "Unknown system message with type %d\n", rtmp->type);
    }
    return res;
}

/** \brief Handle connection messages
 *
 * Retrieve server result to our connection requests
 */
static int rtmp_handle_connect_message(struct rtmp_client *client,
        struct rtmp_message *rtmp)
{
    int res = (-1);
    char *amf = NULL;
    double result = 0.0;
    struct rtmp_pvt *p = NULL;
    /* the value reserved for string space is arbitrary */
    char flashver[256] = "";
    char tcurl[256] = "";
    char caller[256] = "";
    char passwd[256] = "";
    char called[256] = "";
    int channelid;
    struct rtmp_user *user = NULL;
    char *callerid = NULL;
    char *secret = NULL;
    char *exten = NULL;
    char *param = NULL;
    int audioCodecDetected = 0;
    char server[256] = "";
    char parameters[256] = "";
    struct rtmp_client *client2 = NULL;

    if (!client)
    {
        return res;
    }

    memset(flashver, '\0', 256);
    memset(tcurl, '\0', 256);
    memset(caller, '\0', 256);
    memset(passwd, '\0', 256);
    memset(called, '\0', 256);

    memset(server, '\0', 256);

    /* get a local copy of the RTMP body */
    amf = ast_malloc(rtmp->bodysize);
    if (!amf)
    {
        return res;
    }
    memcpy(amf, rtmp->body, rtmp->bodysize);

    //    amf_parse_connect(double *id, char *user, char *password, char *name, char *amf, size_t len, int *audioCodecDetected) {
    res =
            amf_parse_connect(&result, caller, passwd, called, amf, rtmp->bodysize,
                    &audioCodecDetected, flashver, tcurl);

    if (debug)
    {
        I6DEBUG(3, client, "Received RTMP CMDMSG message from server :\n");
        I6DEBUG(3, client, "         res          : %d\n", res);
        I6DEBUG(3, client, "         result       : %f\n", result);
        I6DEBUG(3, client, "         caller       : %s\n",
                ast_strlen_zero(caller) ? "N/A" : caller);
        I6DEBUG(3, client, "         password     : %s\n",
                ast_strlen_zero(passwd) ? "N/A" : passwd);
        I6DEBUG(3, client, "         called       : %s\n",
                ast_strlen_zero(called) ? "N/A" : called);
        I6DEBUG(3, client, "         flashver     : %s\n",
                ast_strlen_zero(flashver) ? "N/A" : flashver);
        I6DEBUG(3, client, "         tcurl        : %s\n",
                ast_strlen_zero(tcurl) ? "N/A" : tcurl);

    }

    /* handle_connect est appelée plusieurs fois => on set le codec audio & client
     type la première fois sur le msg connect */


    if (!client->acodec_setted)
    {
        client->acodec_setted = 1;
        I6DEBUG(3, client, "         AudioCodec   : %X\n", audioCodecDetected);
        if (audioCodecDetected & RTMP_AUDIO_CODEC_SPEEX)
        {
            SET_FORMAT_FROMID_TOVAR(client->audiocodec, AST_FORMAT_SPEEX);

            I6DEBUG(3, client, "         acodec       : SPEEX\n");
        }
        else if (audioCodecDetected & RTMP_AUDIO_CODEC_MULAW)
        {
            SET_FORMAT_FROMID_TOVAR(client->audiocodec, AST_FORMAT_ULAW);

            I6DEBUG(3, client, "         acodec       : ULAW\n");
        }
        else if (audioCodecDetected & RTMP_AUDIO_CODEC_ALAW)
        {
            SET_FORMAT_FROMID_TOVAR(client->audiocodec, AST_FORMAT_ALAW);

            I6DEBUG(3, client, "         acodec       : ALAW\n");
        }
        else
        {
            SET_FORMAT_FROMID_TOVAR(client->audiocodec, AST_FORMAT_SLINEAR);

            I6DEBUG(3, client, "         acodec       : SLINEAR\n");
        }

        // Set Client type
        if (strstr(flashver, "ANDROID") != NULL)
        {
            client->clientType = CLIENT_TYPE_ANDROID;
        }
        else if (strstr(flashver, "IOS") != NULL)
        {
            client->clientType = CLIENT_TYPE_IOS;
        }
        else
        {
            client->clientType = CLIENT_TYPE_FLASH;
        }
    }

    I6DEBUG(7, client, "res = %d\n", res);

    switch (res)
    {
        case RTMP_REPLY_RESULT:
            channelid = rtmp->channelid;

            I6DEBUG(3, client, "streamid = %d :\n", rtmp->streamid);
            RTMP_VERBOSE(client, ">* connect/request(%s,%s,%s)\n", caller, passwd,
                    called);

            break;

        case RTMP_REPLY_CONNECT:
            channelid = rtmp->channelid;
#ifdef GEOIP_H
            GeoIPRecord *gir;
#endif


            // rtmp://borja.voximal.org/72.52.201.107_487/11800/publish

            if (!strncmp(caller, "@id", 3))
            {
                sprintf(caller, "%d", client->id);
            }
            else if (!strncmp(caller, "@number", 7))
            {
                sprintf(caller, "%08d", client->id % 100000000);
            }
            else if (!strncmp(caller, "@channel", 8))
            {
                sprintf(caller, "RTMP/%p", client);
            }
            else
                exten = strchr(caller, '@');

            if (exten)
            {
                callerid = caller;
                *(exten++) = 0;
                if (debug)
                    ast_debug(6, "caller=%s exten=%s\n", caller, exten);
            }
            else
            {
                callerid = strchr(caller, '/');
                if (callerid)
                {
                    exten = caller;
                    *(callerid++) = 0;
                    param = strchr(callerid, '/');
                    if (param)
                    {
                        *(param++) = 0;
                    }
                    else
                    {
                        param = callerid;
                        callerid = caller;
                    }
                }
                else
                    callerid = caller;
                if (debug)
                    ast_debug(6, "caller=%s callerid=%s\n", caller, callerid);
            }

            // First the field password
            if (!ast_strlen_zero(passwd))
            {
                secret = passwd;
            }
            else
                // After search : in the filename
                if ((secret = strchr(callerid, ':')))
                {
                    *secret++ = '\0';
                }
                else
                    // No password
                {
                    secret = "";
                }

            //RTMP_VERBOSE(client, ">* secret %s\n", secret);

            client->publishstream = (-1.0);
            client->playstream = (-1.0);
            client->playstream2 = (-1.0);

            strncpy(client->flashver, flashver, sizeof(client->flashver));

#ifdef GEOIP_H
            client->country = NULL;
            client->latitude = 0, 0;
            client->longitude = 0.0;

            if (gi)
            {
                gir = GeoIP_record_by_name(gi, (const char *)client->address);

                if (gir)
                {
                    client->country = gir->country_code;
                    client->latitude = gir->latitude;
                    client->longitude = gir->longitude;

                    if (debug)
                    {
                        ast_log(LOG_NOTICE, "Localisation : IP:%s loc:%f,%f country:%s\n",
                                client->address, client->latitude, client->longitude,
                                client->country);
                    }
                    GeoIPRecord_delete(gir);
                }
            }

            sprintf(parameters,
                    "location=loc:%f,%f&latitude=%f&longitude=%f&country=%s&ip=%s&version=%s",
                    client->latitude, client->longitude, client->latitude,
                    client->longitude, client->country, client->address,
                    client->flashver);

            {
                char *ptr;

                while ((ptr = strchr(parameters, ' ')) != NULL)
                    *ptr = '_';
            }
#else
            sprintf(parameters, "ip=%s&flashver=%s", client->address), client->flashver);
#endif
            if (debug)
                ast_debug(6, "parameters=%s\n", parameters);

            // Static redirect
            if (redirect[0])
            {
                RTMP_VERBOSE(client, ">* connect/connect(redirect,%s,%s,%s)\n", caller,
                        passwd, called);

                /* first stream in the group is reserved for publication */
                res =
                        rtmp_send_result_connect(client, rtmp->streamid, result, "status",
                                "NetConnection.Connect.Redirected", redirect);

                ast_verbose(VERBOSE_PREFIX_3
                        "Redirect RTMP '%s' at %s port %d, to %s\n", client->name,
                        client->address, client->port, redirect);
                //
                if (client->fd != (-1))
                    close(client->fd);
                client->fd = (-1);

                goto cleanup;
            }

            // Redirect rule
            if ((rtmp_find_rule(tcurl, callerid, called, server, parameters)))
            {
                RTMP_VERBOSE(client, ">* connect/connect(redirect,%s,%s,%s)\n", caller,
                        passwd, called);

                /* first stream in the group is reserved for publication */
                res =
                        rtmp_send_result_connect(client, rtmp->streamid, result, "status",
                                "NetConnection.Connect.Redirected", server);

                ast_verbose(VERBOSE_PREFIX_3
                        "Redirect RTMP '%s' at %s port %d, to %s\n", callerid,
                        client->address, client->port, server);

                ast_copy_string(client->name, callerid, sizeof(client->name));

                if (client->fd != (-1))
                    close(client->fd);
                client->fd = (-1);

                goto cleanup;
            }

            // Find user
            if (callerid)
            {
                if (debug)
                    ast_debug(9, "check caller '%s'\n", callerid);

                if (realtimename[0])
                    user = rtmp_find_user(callerid, 1);
                else
                    user = rtmp_find_user(callerid, 0);

                if (user)
                {
                    //client->user = user;
                }
                else
                {
                    if (debug)
                        ast_debug(9, "no user %s\n", callerid);
                }
            }
            else
            user = NULL;

            ast_verbose(VERBOSE_PREFIX_3 "Lastuniqueuser General : %d\n", lastuniqueuser);
            if (user)
            ast_verbose(VERBOSE_PREFIX_3 "Lastuniqueuser user : %d\n", user->lastuniqueuser);

            // Eject users connected
            if ( ((((user &&  user->lastuniqueuser==-1) || !user)  && lastuniqueuser) || (user && user->lastuniqueuser==1))
                  && callerid[0])
            {
                if (debug)
                    ast_debug(9, "check if '%s' already connected\n", callerid);


                while ((client2 = rtmp_find_connection(callerid)))
                {
                    if (!hangupusers && client2->pvt)
                    {
                        RTMP_VERBOSE(client, ">* connect/connect(reject,%s,%s,%s)\n",
                                caller, passwd, called);

                        /* first stream in the group is reserved for publication */
                        res =
                                rtmp_send_result_connect(client, rtmp->streamid, result, "status",
                                        "NetConnection.Connect.Rejected", "Cannot hangup.");

                        ast_verbose(VERBOSE_PREFIX_3
                                "Refused RTMP hangup '%s' at %s port %d\n", client->name,
                                client->address,
                                client->port);

                        if (events)
                        {
                            manager_event(EVENT_FLAG_SYSTEM, "Registry",
                                    "ChannelType: RTMP\r\nUsername: %s\r\nDomain: %s:%d\r\nStatus: %s\r\n",
                                    client->name, client->address,
                                    client->port, "Rejected");
                        }

                        if (client->fd != (-1))
                            close(client->fd);
                        client->fd = (-1);

                        ast_mutex_unlock(&client2->lock);

                        goto cleanup;
                    }
                    else
                    {
                        RTMP_VERBOSE(client, "Ejected connection %p for %s.\n", client2, callerid);
                        I6DEBUG(1, client2, "Ejected connection for %s.\n", callerid);

                        ast_verbose(VERBOSE_PREFIX_3 "Ejected RTMP '%s' at %s port %d\n",
                                client->name,
                                client->address,
                                client->port);

                        if (client2->fd != (-1))
                            close(client2->fd);
                        client2->fd = (-1);

                        ast_mutex_unlock(&client2->lock);
                    }
                }

                client2 = NULL;
            }

            ast_verbose(VERBOSE_PREFIX_3 "Multiusers General : %d\n", multipleusers);
            if (user)
            ast_verbose(VERBOSE_PREFIX_3 "Multiusers user : %d\n", user->multipleusers);

            // Reject if not multipleusers
            if (( (((user &&  user->multipleusers==-1) || !user)  && !multipleusers) || (user && user->multipleusers==0))
              && (client2=rtmp_find_connection(callerid)))
            {
                ast_mutex_unlock(&client2->lock);

                RTMP_VERBOSE(client,
                        ">* connect/connect(reject,%s,%s,%s) - Duplicate user\n", caller,
                        passwd, tcurl);

                /* first stream in the group is reserved for publication */
                res =
                        rtmp_send_result_connect(client, rtmp->streamid, result, "status",
                                "NetConnection.Connect.Rejected", "Duplicate user.");

                ast_verbose(VERBOSE_PREFIX_3 "Refused RTMP '%s'(%s) at %s port %d\n",
                        client->name, caller, client->address, client->port);

                if (events)
                {
                    manager_event(EVENT_FLAG_SYSTEM, "Registry",
                            "ChannelType: RTMP\r\nUsername: %s\r\nDomain: %s:%d\r\nStatus: %s\r\n",
                            client->name, client->address, client->port, "Rejected");
                }

                if (client->fd != (-1))
                    close(client->fd);
                client->fd = (-1);

                goto cleanup;
            }

            // Set name and user
            if (callerid)
            {

                ast_copy_string(client->name, callerid, sizeof(client->name));

                if (user)
                {
                    client->user = user;

                    //if (user->secret[0])
                    {
                        if (debug)
                            ast_debug(9, "check password '%s' ? '%s'\n", user->secret,
                                    secret);

                        if (!user->secret[0] || !strcmp(user->secret, secret))
                        {
                            RTMP_VERBOSE(client,
                                    ">* connect/connect(success,%s,%s,%s;%s,%s,%s)\n", caller,
                                    passwd, called, exten, callerid, param);

                            /* first stream in the group is reserved for publication */
                            res =
                                    rtmp_send_result_connect(client, rtmp->streamid, result,
                                            "status", "NetConnection.Connect.Success",
                                            "Connection succeeded.");

                            user->client = client;

                            ast_verbose(VERBOSE_PREFIX_3
                                    "Registered RTMP/%p user '%s' at %s port %d (%s)\n", client,
                                    client->name, client->address, client->port, getUsedRtmpProtocolName(client));

                            if (events)
                            {
                                manager_event(EVENT_FLAG_SYSTEM, "Registry",
                                        "ChannelType: RTMP\r\nUsername: %s\r\nDomain: %s:%d\r\nStatus: %s\r\n",
                                        client->name, client->address, client->port, "Registered");
                            }

                            if (client->name[0])
                            {
                                struct sockaddr_in *ptr_tmp_add_in =
                                        malloc(sizeof(struct sockaddr_in));
                                TCPTLS_SESSION_ADDRESS_FORCE_SOCKADDR_IN(client->threadinfo->
                                        tcptls_session->remote_address, ptr_tmp_add_in);
                                realtime_update_user(client->name, ptr_tmp_add_in,
                                        "UserAgent Flash/default");
                                //free(ptr_tmp_add_in);
                            }
                        }
                        else
                        {
                            RTMP_VERBOSE(client, ">* connect/connect(reject,%s,%s,%s)\n",
                                    caller, passwd, called);

                            /* first stream in the group is reserved for publication */
                            res =
                                    rtmp_send_result_connect(client, rtmp->streamid, result,
                                            "status", "NetConnection.Connect.Rejected", "Bad password.");

                            ast_verbose(VERBOSE_PREFIX_3
                                    "Refused RTMP password '%s' at %s port %d\n", client->name,
                                    client->address, client->port);

                            if (events)
                            {
                                manager_event(EVENT_FLAG_SYSTEM, "Registry",
                                        "ChannelType: RTMP\r\nUsername: %s\r\nDomain: %s:%d\r\nStatus: %s\r\n",
                                        client->name, client->address, client->port, "No Authentication");
                            }

                            if (client->fd != (-1))
                                close(client->fd);
                            client->fd = (-1);

                            goto cleanup;
                        }
                    }
                }

            }

            // Auto users
            if (!client->user)
            {
                if (autousers)
                {
                    RTMP_VERBOSE(client,
                            ">* connect/connect(success,%s,%s,%s;%s,%s,%s, %s)\n", caller,
                            passwd, called, exten, callerid, param,
                            GET_FORMAT_NAME(client->audiocodec));
                    //
                    /* first stream in the group is reserved for publication */
                    res = rtmp_send_result_connect(client, rtmp->streamid, result, "status",
                                    "NetConnection.Connect.Success", "Connection succeeded.");

                    ast_verbose(VERBOSE_PREFIX_3
                            "Registered RTMP/%p '%s' at %s port %d (%s)\n", client, client->name,
                            client->address, client->port, getUsedRtmpProtocolName(client));

                    if (events)
                    {
                        manager_event(EVENT_FLAG_SYSTEM, "Registry",
                                "ChannelType: RTMP\r\nUsername: %s\r\nDomain: %s:%d\r\nStatus: %s\r\n",
                                client->name, client->address, client->port, "Registered");
                    }
                    if (client->name[0])
                    {
                        struct sockaddr_in tmp_add_in;
                        struct sockaddr_in *ptr_tmp_add_in = &tmp_add_in;
                        TCPTLS_SESSION_ADDRESS_FORCE_SOCKADDR_IN(client->threadinfo->
                                tcptls_session->remote_address, ptr_tmp_add_in);
                        realtime_update_user(client->name, ptr_tmp_add_in,
                                "UserAgent Flash/default");
                    }
                }
                else
                    // Reject
                {
                    RTMP_VERBOSE(client,
                            ">* connect/connect(reject,%s,%s,%s) - Unknow user\n", caller,
                            passwd, caller);

                    if (events)
                    {
                        manager_event(EVENT_FLAG_SYSTEM, "Registry",
                                "ChannelType: RTMP\r\nUsername: %s\r\nDomain: %s:%d\r\nStatus: %s\r\n",
                                client->name, client->address, client->port, "Rejected");
                    }

                    /* first stream in the group is reserved for publication */
                    res =
                            rtmp_send_result_connect(client, rtmp->streamid, result, "status",
                                    "NetConnection.Connect.Rejected", "Unknow user.");

                    ast_verbose(VERBOSE_PREFIX_3 "Refused RTMP '%s'(%s) at %s port %d\n",
                            client->name, caller, client->address, client->port);

                    goto cleanup;
                }
            }

            if (exten)
            {
                if (debug)
                    I6DEBUG(3, client, "Connection with extension %s\n", exten);

                p = rtmp_alloc("", "", NULL);
                p->mode = 1;

                p->client = client;
                if (p)
                {
                    struct ast_channel *tmp = NULL;

                    I6DEBUG(10, client, "Mutex lock 'client'.\n");
                    ast_mutex_lock(&client->lock);
                    I6DEBUG(10, client, "Mutex locked 'client'.\n");

                    tmp = rtmp_new(p, AST_STATE_RINGING, NULL, exten, param);
                    if (!tmp)
                    {
                        //ast_log(LOG_ERROR, "connections unlink %p\n", p);
                        I6DEBUG(10, client, "Mutex lock 'rtmplock'.\n");
                        ast_mutex_lock(&rtmplock);
                        I6DEBUG(10, client, "Mutex locked 'rtmplock'.\n");

                        ao2_t_unlink(connections, p, "Unlink pvt out to connections table");
                        ao2_t_ref(p, -1, "Unref and free rtmp_pvt");

                        I6DEBUG(10, client, "Mutex unlock 'rtmplock'.\n");
                        ast_mutex_unlock(&rtmplock);

                        ast_log(LOG_WARNING, "Cannot allocate an RTMP channel!\n");
                    }
                    else
                    {
                        if (GET_CHAN_STATE(tmp) != AST_STATE_DOWN)
                        {

                            if (debug)
                                I6DEBUG(3, client, "Connect the PVT context\n");

                            p->owner = tmp;
                            client->pvt = p;
                            p->client = client;
                            client->incoming_calls++;
                        }
                    }

                    I6DEBUG(10, client, "Mutex unlock 'client'.\n");
                    ast_mutex_unlock(&client->lock);
                }

            }
            break;


case RTMP_REPLY_CREATESTREAM:
    channelid = rtmp->channelid;
    /* first stream in the group is reserved for publication */
    if (client->publishstream == (-1.0))
    {
        client->publishstream = 1.0;
        res =
                rtmp_send_result_createstream(client, rtmp->streamid, result,
                        client->publishstream);

        RTMP_VERBOSE(client, ">* connect/createstream(%f) 1st publish\n",
                client->publishstream);
    }
    else if (client->playstream == (-1.0))
    {
        client->playstream = 2.0;
        res =
                rtmp_send_result_createstream(client, rtmp->streamid, result,
                        client->playstream);

        RTMP_VERBOSE(client, ">* connect/createstream(%f) 2nd playaudio\n",
                client->playstream);
    }
    else if (client->playstream2 == (-1.0))
    {
        if (videosupport)
            client->playstream2 = 3.0;
        res =
                rtmp_send_result_createstream(client, rtmp->streamid, result,
                        client->playstream2);

        RTMP_VERBOSE(client, ">* connect/createstream(%f) 3th playvideo\n",
                client->playstream2);
    }
    break;

case RTMP_REPLY_DELETESTREAM:
    ast_mutex_lock(&client->lock);

    if (client->pvt)
    {
        int maxloop = 20;

        while ( (GET_CHAN_STATE(client->pvt->owner) != AST_STATE_DOWN) && maxloop)
        {
            if (!ast_channel_trylock(client->pvt->owner))
            {
                ast_queue_hangup(client->pvt->owner);
                ast_channel_unlock(client->pvt->owner);
                break;
            }
            else
            {
                ast_mutex_unlock(&client->lock);
                usleep(10000);
                ast_mutex_lock(&client->lock);
                if (client->pvt == NULL)
                    break;
            }
            maxloop--;
            if (!maxloop)
                res = -1;
        }
    }

    channelid = rtmp->channelid;
    /* first stream in the group is reserved for publication */
    RTMP_VERBOSE(client, ">* connect/deletestream(%d,%f)\n", rtmp->streamid,
            result);

    if (result == client->playstream)
        client->playstream = (-1);

    if (result == client->playstream2)
        client->playstream2 = (-1);

    if (result == client->publishstream)
        client->publishstream = (-1);

    ast_mutex_unlock(&client->lock);

    break;


case RTMP_REPLY_INVITE:
    channelid = rtmp->channelid;
    if (debug)
    {
        /*
           if (tcurl)
           {
           RTMP_VERBOSE(client, ">* message/invite(%s,%s,%s)\n", caller, passwd, called);
           }
           else */
        {
            // Le parametre de l'invite est dans la variable passwd
            if (passwd[0])
            {
                RTMP_VERBOSE(client, ">* message/invite(%s,%s)\n", caller, passwd);
                // Parse invite param to get cellid if exist

                if (!strncmp(passwd, "cellid:", 7))
                {
                    // Get cellid
                    strcpy(client->cellid, passwd + 7);
                    I6DEBUG(3, client, "Found cellid : %s\n", client->cellid);
                }
                else
                {
                    strcpy(client->param, flashver);
                    I6DEBUG(3, client, "Found parameter : %s\n", client->param);
                }
            }
            else
            {
                RTMP_VERBOSE(client, ">* message/invite(%s)\n", caller);
            }
        }
        if (debug)
        {
            I6DEBUG(3, client, "audiocodec %s\n", GET_FORMAT_NAME(client->audiocodec));
        }
    }

    if (client->pvt == NULL)
    {
        stats[STATS_CALLS]++;

        res = rtmp_send_result_invite(client, 0, result, NULL, NULL);
        //res = rtmp_send_result_invite(client, rtmp->streamid, 2.0, "accepted", NULL);
        p = rtmp_alloc("", "", NULL);

        p->client = client;

        if (p)
        {
            struct ast_channel *tmp = NULL;

            tmp = rtmp_new(p, AST_STATE_RING, NULL, caller, passwd);
            if (!tmp)
            {
                //ast_log(LOG_ERROR, "connections unlink %p\n", p);
                I6DEBUG(10, client, "Mutex lock 'rtmplock'.\n");
                ast_mutex_lock(&rtmplock);
                I6DEBUG(10, client, "Mutex locked 'rtmplock'.\n");
                ao2_t_unlink(connections, p, "Unlink pvt out to connections table");
                ao2_t_ref(p, -1, "Unref and free rtmp_pvt");

                I6DEBUG(10, client, "Mutex unlock 'rtmplock'.\n");
                ast_mutex_unlock(&rtmplock);
            }
            else
            {
                ast_channel_lock(tmp);
                I6DEBUG(10, client, "Mutex lock 'client'.\n");
                ast_mutex_lock(&client->lock);
                I6DEBUG(10, client, "Mutex locked 'client'.\n");

                if (GET_CHAN_STATE(tmp) != AST_STATE_DOWN)
                {
                    if (debug)
                    {
                        I6DEBUG(3, client, "Connect the PVT context with audiocodec %s\n", GET_FORMAT_NAME(client->audiocodec));
                    }
                    p->owner = tmp;
                    client->pvt = p;
                    p->client = client;

                    client->incoming_calls++;

                    if (debug)
                    {
                        char tmp_nativeformats_buffer[512];
                        GET_FORMAT_NAME_MULTIPLE(tmp_nativeformats_buffer,
                                sizeof(tmp_nativeformats_buffer),
                                GET_CHAN_NATIVEFORMATS(tmp));
                        I6DEBUG(3, client, "rtmp_handle_connect: set format %s (native format %s)\n", GET_FORMAT_NAME(client->audiocodec), tmp_nativeformats_buffer);
                    }

                    SET_CHAN_READFORMAT(tmp, client->audiocodec);
                    SET_CHAN_WRITEFORMAT(tmp, client->audiocodec);
                    //

                    ast_indicate(tmp, AST_CONTROL_RINGING);
                }
                else
                {
                    if (debug)
                        I6DEBUG(3, client, "PVT context not set, state down\n");

                }

                ast_channel_unlock(tmp);

                I6DEBUG(10, client, "Mutex unlock 'client'.\n");
                ast_mutex_unlock(&client->lock);
            }
        }
    }
    else
    {
        res =
                rtmp_send_result_invite(client, rtmp->streamid, 2.0, "rejected",
                        "busy");

        RTMP_VERBOSE(client, "<* message/rejected(busy)\n");
        if (client->pvt->owner)
        {
            //ast_queue_hangup(client->pvt->owner);
        }
    }

    //res = rtmp_send_result_invite(client, rtmp->streamid, 2.0, "accepted", NULL);

    break;

case RTMP_REPLY_ACCEPT:

    RTMP_VERBOSE(client, ">* message/accept()\n");

    if (client->pvt)
    {
        int maxloop = 20;

        while ( (GET_CHAN_STATE(client->pvt->owner) != AST_STATE_UP) && maxloop)
        {
            if (!ast_channel_trylock(client->pvt->owner))
            {
                ast_setstate(client->pvt->owner, AST_STATE_UP);
                ast_channel_unlock(client->pvt->owner);
                break;
            }
            else
            {
                ast_mutex_unlock(&client->lock);
                usleep(10000);
                ast_mutex_lock(&client->lock);
                if (client->pvt == NULL)
                    break;
            }
            maxloop--;
            if (!maxloop)
                res = -1;
        }
    }

    channelid = rtmp->channelid;
    res = rtmp_send_result_bye(client, rtmp->streamid, result, NULL, NULL);

    RTMP_VERBOSE(client, "<* message/accept()\n");

    ast_queue_control(client->pvt->owner, AST_CONTROL_ANSWER);

    break;

case RTMP_REPLY_REJECT:
    RTMP_VERBOSE(client, ">* message/reject()\n");

    if (client->pvt)
    {
        int maxloop = 20;

        while ( (GET_CHAN_STATE(client->pvt->owner) != AST_STATE_DOWN) && maxloop)
        {
            if (!ast_channel_trylock(client->pvt->owner))
            {
                ast_queue_hangup(client->pvt->owner);
                ast_channel_unlock(client->pvt->owner);
                break;
            }
            else
            {
                ast_mutex_unlock(&client->lock);
                usleep(10000);
                ast_mutex_lock(&client->lock);
                if (client->pvt == NULL)
                    break;
            }
            maxloop--;
            if (!maxloop)
                res = -1;
        }
    }

    break;

case RTMP_REPLY_BYE:
    RTMP_VERBOSE(client, ">* message/bye()\n");

    if (client->pvt)
    {
        if (GET_CHAN_STATE(client->pvt->owner) != AST_STATE_DOWN)
        {
            int maxloop = 20;

            while ( (GET_CHAN_STATE(client->pvt->owner) != AST_STATE_DOWN) && maxloop)
            {
                if (!ast_channel_trylock(client->pvt->owner))
                {
                    ast_queue_hangup(client->pvt->owner);
                    ast_channel_unlock(client->pvt->owner);
                    break;
                }
                else
                {
                    ast_mutex_unlock(&client->lock);
                    usleep(10000);
                    ast_mutex_lock(&client->lock);
                    if (client->pvt == NULL)
                        break;
                }
                maxloop--;
                if (!maxloop)
                    res = -1;
            }
        }
    }

    channelid = rtmp->channelid;
    /*
      res = rtmp_send_result_bye(client, rtmp->streamid, result, NULL, NULL);
      RTMP_VERBOSE(client, "<* message/bye()\n");
     */

    break;

case RTMP_NOREPLY:
    break;
default:
    RTMP_VERBOSE(client, "Unsupported ret for parse connect %Xh\n", res);
    break;
    }

    cleanup:
    ast_free(amf);
    return res;
}


/** \brief Handle notify messages
 *
 * Retrieve server result to our control requests
 */
static int rtmp_handle_notify_message(struct rtmp_client *client,
        struct rtmp_message *rtmp)
{
    int res = (-1);
    char *amf = NULL;
    double result = 0.0;
    /* the value reserved for string space is arbitrary */
    char name[256] = "";
    //char readstream_index[3];         /* "-xx" */
    //char readstream_name[AST_MAX_EXTENSION];

    memset(name, '\0', 256);

    /* get a local copy of the RTMP body */
    amf = ast_malloc(rtmp->bodysize);
    if (!amf)
    {
        return res;
    }
    memcpy(amf, rtmp->body, rtmp->bodysize);

    res = amf_parse_control(&result, name, amf, rtmp->bodysize);

    if (debug)
    {
        ast_debug(0, "Received RTMP message from server :\n");
        ast_debug(0, "         res          : %d\n", res);
        ast_debug(0, "         result       : %f\n", result);
        ast_debug(0, "         description  : %s\n",
                ast_strlen_zero(name) ? "N/A" : name);
    }
    switch (res)
    {
        default:
            RTMP_VERBOSE(client, ">* ? %d\n", res);
            //res = rtmp_send_result_bye(client, rtmp->streamid, result, NULL, NULL);

            break;
    }

    //safeout:
    ast_free(amf);
    return res;
}


/** \brief Handle control messages
 *
 * Retrieve server result to our control requests
 */
static int rtmp_handle_control_message(struct rtmp_client *client,
        struct rtmp_message *rtmp)
{
    int res = (-1);
    char *amf = NULL;
    double result = 0.0;
    /* the value reserved for string space is arbitrary */
    char name[256] = "";
    //char readstream_index[3];         /* "-xx" */
    //char readstream_name[AST_MAX_EXTENSION];
    int channelid;

    memset(name, '\0', 256);

    /* get a local copy of the RTMP body */
    amf = ast_malloc(rtmp->bodysize);
    if (!amf)
    {
        return res;
    }
    memcpy(amf, rtmp->body, rtmp->bodysize);

    res = amf_parse_control(&result, name, amf, rtmp->bodysize);

    if (debug)
    {
        I6DEBUG(3, client, "Received RTMP message from server :\n");
        I6DEBUG(3, client, "         res          : %d\n", res);
        I6DEBUG(3, client, "         result       : %f\n", result);
        I6DEBUG(3, client, "         description  : %s\n",
                ast_strlen_zero(name) ? "N/A" : name);
    }
    switch (res)
    {
        case RTMP_REPLY_PUBLISH:
            channelid = rtmp->channelid;

            I6DEBUG(3, client, "steamid = %d :\n", rtmp->streamid);

            RTMP_VERBOSE(client, ">* control/publish()\n");

            if (client->publishstream == (-1.0))
                client->publishstream = 1.0;

            I6DEBUG(3, client, "publishstream = %f :\n", client->publishstream);

            /* first stream in the group is reserved for publication */
            res =
                    rtmp_send_result_publish(client, RTMP_CHANNEL_PUBLISH, rtmp->streamid,
                            result, "");

            client->publishing = 1;

            break;
        case RTMP_REPLY_PLAY:
            channelid = rtmp->channelid;

            I6DEBUG(3, client, "steamid = %d :\n", rtmp->streamid);
            I6DEBUG(3, client, "channelid = %d :\n", rtmp->channelid);

            RTMP_VERBOSE(client, ">* control/play(%s)\n", name);

            /* first stream in the group is reserved for publication */

            /*
         if (channelid==14)
         channelid = RTMP_CHANNEL_LOCAL;
         else
         channelid = RTMP_CHANNEL_VIDEO;

         if (client->pvt)
         if (client->pvt->mode)
         channelid = rtmp->channelid;
             */

            //client->pvt->streamid = rtmp->streamid;

            res =
                    rtmp_send_result_play(client, channelid, rtmp->streamid, result, name);

            if ((client->publishstream != (-1.0)) && (client->playstream == (-1.0)))
            {
                client->playstream = client->publishstream;
                client->publishstream = (-1.0);
            }

            I6DEBUG(3, client, "playstream = %f :\n", client->playstream);
            I6DEBUG(3, client, "publishstream = %f :\n", client->publishstream);

            if ((channelid == RTMP_CHANNEL_LOCAL) || (channelid == 14))
                client->playing = 1;
            else if (channelid == RTMP_CHANNEL_VIDEO)
                client->playing2 = 1;
            else if (name[0] && (!strcmp(name, "video")))
                client->playing2 = 1;
            else
                client->playing = 1;

            I6DEBUG(3, client, "playing = %d :\n", client->playing);
            I6DEBUG(3, client, "playing2 = %d :\n", client->playing2);

            client->streams[channelid]->streamid[RTMP_OUTGOING] = (-1);

            if (name[0])
                if (!strcmp(name, "video"))
                {
                    if (client->pvt) {
                        //RTMP_VERBOSE(client, "----- DON'T SEND CLEAR VIDEO PKT\n");
                        rtmp_send_clear(client);
                    }

                    if (client->pvt)
                    {
                        I6DEBUG(3, client, "Send Video Update !\n");
                        {
                            int maxloop = 20;

                            while ( (GET_CHAN_STATE(client->pvt->owner) == AST_STATE_UP) && maxloop)
                            {
                                if (!ast_channel_trylock(client->pvt->owner))
                                {
                                    ast_queue_control(client->pvt->owner, AST_CONTROL_VIDUPDATE);
                                    ast_channel_unlock(client->pvt->owner);
                                    break;
                                }
                                else
                                {
                                    ast_mutex_unlock(&client->lock);
                                    usleep(10000);
                                    ast_mutex_lock(&client->lock);
                                    if (client->pvt == NULL)
                                        break;
                                }
                                maxloop--;
                                if (!maxloop)
                                    res = -1;
                            }
                        }
                    }
                }

            break;
        case RTMP_REPLY_CLOSESTREAM:
            channelid = rtmp->channelid;

            if (debug)
                ast_debug(0, "steamid = %d :\n", rtmp->streamid);

            RTMP_VERBOSE(client, ">* control/closestream()\n");

            break;
        default:
            RTMP_VERBOSE(client, ">* ? %d\n", res);

            break;
    }

    //safeout:
    ast_free(amf);
    return res;
}

/** \brief Handle audio packets
 */
static int rtmp_handle_audio_packet(struct rtmp_client *client,
        struct rtmp_message *rtmp)
{
    int res = (-1);
    struct rtmp_pvt *tmp = NULL;
    int len = 0;
    uint32_t length = 0;
    uint8_t pipetype;
    uint8_t *input = NULL;
    uint8_t *rawsamples = NULL;
    uint8_t *firstbyte = NULL;
    uint8_t *samples = NULL;
    int rawsampleslen;
    int inputchannels = 0, inputrate = 0, sample_fmt_in = 0;  //, sample_fmt_out = 0;
    //int16_t audio_buf[AVCODEC_MAX_AUDIO_FRAME_SIZE];
    ///int16_t audio_buf[(AVCODEC_MAX_AUDIO_FRAME_SIZE * 3) / 2];
    int16_t audio_buf[1000];
    int pipesize;

    if (!rtmp->bodysize)
    {
        I6LOG(LOG_WARNING, client, "Audio RTMP packet null!\n");
        goto safeout;
    }

    tmp = client->pvt;
    if (tmp == NULL)
    {
        I6DEBUG(0, client,
                "No Asterisk tech channel that matches with RTMP channel %d\n",
                rtmp->channelid);
        res = (-1);
        goto safeout;
    }

    client->incoming_audio++;

    firstbyte = rtmp->body;
#ifdef RTMP_FFMPEG
    rawsampleslen = AVCODEC_MAX_AUDIO_FRAME_SIZE;
#else
    rawsampleslen = 192000;
#endif
    if (!tmp->owner)
    {
        I6DEBUG(0, client,
                "No Asterisk channel that matches with RTMP channel %d\n",
                rtmp->channelid);
        res = (-1);
        goto safeout;
    }

    if (maxaudiopipe)
    {
        ioctl(tmp->pipe[0], FIONREAD, &pipesize);
        if (pipesize > maxaudiopipe)
        {
            client->incoming_audiolost++;

            I6DEBUG(0, client, "Max audio pipe reach : %d\n", pipesize);
            res = (-1);
            goto safeout;
        }
    }

    I6DEBUG(7, client, "firsbyte = %02x\n", *firstbyte);

    input = ast_malloc(rtmp->bodysize - 1);
    memcpy(input, rtmp->body + 1, rtmp->bodysize - 1);

    if ((*firstbyte & 0x01) >> 0 == 1)
    {
        inputchannels = 2;          /* stereo */
    }
    else
    {
        inputchannels = 1;          /* mono */
    }

    if ((*firstbyte & 0x02) >> 1 == 1)
    {
        sample_fmt_in = 16;
    }
    else
    {
        sample_fmt_in = 8;
    }

    if (debug)
        I6DEBUG(7, client, "Audio type : %s\n",
                (*firstbyte & 0x01) >> 0 ? "stereo" : "mono");
    if (debug)
        I6DEBUG(7, client, "Sample size : %s\n",
                (*firstbyte & 0x02) >> 1 ? "16-bit" : "8-bit");

    switch ((*firstbyte & 0x0c) >> 2)
    {
        case 0:
            if (debug)
                I6DEBUG(7, client, "Sampling rate : 5,5 kHz\n");
            inputrate = 5500;
            break;
        case 1:
            if (debug)
                I6DEBUG(7, client, "Sampling rate : 11 kHz\n");
            inputrate = 11000;
            break;
        case 2:
            if (debug)
                I6DEBUG(7, client, "Sampling rate : 22 kHz\n");
            inputrate = 22000;
            break;
        case 3:
            if (debug)
                I6DEBUG(7, client, "Sampling rate : 44 kHz\n");
            inputrate = 44000;
            break;
        default:
            inputrate = 44000;
    }

    switch ((*firstbyte & 0xf0) >> 4)
    {
        case 0:
            I6DEBUG(7, client, "Format : Uncompressed\n");
            break;
        case FLV_AUDIO_CODEC_ADPCM:  //1
            I6DEBUG(7, client, "Format : ADPCM\n");
            break;
        case FLV_AUDIO_CODEC_MP3:  //2
            I6DEBUG(7, client, "Format : MP3\n");
            break;
        case FLV_AUDIO_CODEC_PCMS16le: //3:
            I6DEBUG(7, client, "Format : PCMS16le\n");
            break;
        case FLV_AUDIO_CODEC_NELLYMOSER_8KHZ_MONO: //5:
            I6DEBUG(7, client, "Format : Nellymoser 8 kHz mono\n");
            /* overwrite input rate */
            //inputrate = 8000;
            break;
        case FLV_AUDIO_CODEC_NELLYMOSER: // 6:
            I6DEBUG(7, client, "Format : Nellymoser\n");
            break;
        case FLV_AUDIO_CODEC_G711_ALAW:  //7:
            I6DEBUG(7, client, "Format : ALAW\n");
            break;
        case FLV_AUDIO_CODEC_G711_MULAW: //8:
            I6DEBUG(7, client, "Format : MULAW\n");
            break;
        case FLV_AUDIO_CODEC_ASTERISK_SLIN: //9:
            I6DEBUG(7, client,
                    "Format : Reserved (slinear, PCM 16bit 8 kHz mono)\n");
            /* overwrite input rate */
            inputrate = 8000;
            break;
        case FLV_AUDIO_CODEC_SPEEX:  //11:
            I6DEBUG(7, client, "Format : Speex\n");
            break;
        default:
            I6DEBUG(7, client, "Unknown format : %d\n", (*firstbyte & 0xf0) >> 4);
            break;
    }

    if (tmp->schedid != (-1))
    {
        pipetype = RTMP_PIPE_MARK;

        I6DEBUG(7, client, "Send MARK pipe.\n");

        len = write(tmp->pipe[1], (void *)&pipetype, 1);
        if (len == (-1))
        {
            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
            res=(-1);
            goto safeout;
        }
    }

    {
        int size;
        ioctl(tmp->pipe[1], FIONREAD, &size);
        I6DEBUG(10, client, "Datas on PIPE (write) : %d\n", size);
    }

    if (((*firstbyte & 0xf0) >> 4) == FLV_AUDIO_CODEC_SPEEX)  // 11)
    {
        length = rtmp->bodysize - 1;

        if (debug)
            I6DEBUG(1, client, ">* message/audio_speex(%d|%d,(%d,%d),%d)\n",
                    rtmp->timestamp, rtmp->timestampdelta, rtmp->channelid, rtmp->streamid,
                    rtmp->bodysize);

        if (COMPARE_VARFORMAT_IDFORMAT(client->audiocodec, AST_FORMAT_SPEEX))
        {
            if (nospeexsilence && length == 6)
            {
                RTMP_VERBOSE(client, "Speex slience skipped\n");
                //return 0;
            }
            else if (length != 0)
            {
                if (record_raw)
                {
                    if (!client->incoming_audiofile)
                    {
                        char filename[100];
                        sprintf(filename, "/tmp/RTMP%p_%d_incomingaudio_speex.raw", client,
                                (client->outgoing_calls + client->incoming_calls));
                        client->incoming_audiofile = fopen(filename, "wb");
                        I6DEBUG(4, client, "File %s created\n", filename);
                    }

                    if (client->incoming_audiofile)
                    {
                        fwrite(input, 1, length, client->incoming_audiofile);
                        I6DEBUG(4, client, "%d in bytes written\n", length);
                    }
                    else
                        ast_log(LOG_ERROR, "Cannot write incoming audio ulaw file !\n");
                }
                if (record_flv && length != 0)
                {
#if RTMP_FFMPEG
                    if (client->in_flv.fd == 0)
                    {
                        INIT_FLV_INPUT(client);
                    }
                    if (FLV_writePkt(&client->in_flv, FLV_TYPE_AUDIO, client->timestamp,
                            length, (uint8_t *) input) != FLV_OK)
                    {
                        ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file !\n");
                    }
#else
                    {
                        ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file (no FFMPEG)!\n");
                    }
#endif
                }
                pipetype = RTMP_PIPE_AUDIO_SPEEX;
                len = write(tmp->pipe[1], (void *)&pipetype, 1);
                if (len == (-1))
                {
                    ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                    res=(-1);
                    goto safeout;
                }
                len = write(tmp->pipe[1], (void *)&length, 4);
                if (len == (-1))
                {
                    ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                    res=(-1);
                    goto safeout;
                }
                len = write(tmp->pipe[1], input, length);
                if (len == (-1))
                {
                    ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                    res=(-1);
                    goto safeout;
                }

                if (len != length)
                    I6LOG(LOG_WARNING, client, "Cannot write SPEEX to PIPE (%d!=%d)!\n",
                            len, length);
            }
        }
        else
        {
            I6LOG(LOG_WARNING, client, "rcv speex codec from msg, but channel not configured with speex (%s)\n", GET_FORMAT_NAME(client->audiocodec));
        }

        goto safeout;
    }
    else if (((*firstbyte & 0xf0) >> 4) == FLV_AUDIO_CODEC_G711_ALAW) //7)
    {
        length = rtmp->bodysize - 1;

        if (debug)
            I6DEBUG(1, client, ">* message/audio_alaw(%d|%d,(%d,%d),%d)\n",
                    rtmp->timestamp, rtmp->timestampdelta, rtmp->channelid, rtmp->streamid,
                    rtmp->bodysize);

        if (COMPARE_VARFORMAT_IDFORMAT(client->audiocodec, AST_FORMAT_ALAW))
        {
            if (length != 0)
            {
                if (record_raw)
                {
                    if (!client->incoming_audiofile)
                    {
                        char filename[100];
                        sprintf(filename, "/tmp/RTMP%p_%d_incomingaudio_alaw.raw", client,
                                (client->outgoing_calls + client->incoming_calls));
                        client->incoming_audiofile = fopen(filename, "wb");
                    }

                    if (client->incoming_audiofile)
                        fwrite(input, 1, length, client->incoming_audiofile);
                    else
                        ast_log(LOG_ERROR, "Cannot write incoming audio ALAW file !\n");
                }
                if (record_flv && length != 0)
                {
#ifdef RTMP_FFMPEG
                    if (client->in_flv.fd == 0)
                    {
                        INIT_FLV_INPUT(client);
                    }
                    if (FLV_writePkt(&client->in_flv, FLV_TYPE_AUDIO, client->timestamp,
                            length, (uint8_t *) input) != FLV_OK)
                    {
                      ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file !\n");
                    }
#else
                    {
                      ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file (no FFMPEG) !\n");
                    }
#endif
                }

                // Rcv lg is correct for codec => not buffered
                if ((length == 160) && !tmp->audiolength)
                {
                    pipetype = RTMP_PIPE_AUDIO_ALAW;
                    len = write(tmp->pipe[1], (void *)&pipetype, 1);
                    if (len == (-1))
                    {
                        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                        res=(-1);
                        goto safeout;
                    }
                    len = write(tmp->pipe[1], (void *)&length, 4);
                    if (len == (-1))
                    {
                        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                        res=(-1);
                        goto safeout;
                    }
                    len = write(tmp->pipe[1], input, length);
                    if (len == (-1))
                    {
                        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                        res=(-1);
                        goto safeout;
                    }

                    if (len != length)
                        I6LOG(LOG_WARNING, client, "Cannot write ALAW to PIPE (%d!=%d)!\n",
                                len, length);

                }
                else
                {
                    int lgToCopie;
                    int offset;

                    I6DEBUG(7, client, "buffered ALAW packet:\n");

                    // Calculate size of paste
                    lgToCopie = 160 - tmp->audiolength;
                    if (lgToCopie > length)
                    {
                        lgToCopie = length;
                    }

                    // Add lentgh in buff
                    memcpy(tmp->audiobuffer + tmp->audiolength, input, lgToCopie);
                    tmp->audiolength += lgToCopie;
                    I6DEBUG(7, client,
                            "save %do in tmp buff from %d rcv. Size tmpBuff %d\n", lgToCopie,
                            length, tmp->audiolength);

                    // Check if we add to write tmp Buff in pipe
                    offset = 0;
                    while (tmp->audiolength >= 160)
                    {
                        int fixedlength = 160;

                        pipetype = RTMP_PIPE_AUDIO_ALAW;
                        len = write(tmp->pipe[1], (void *)&pipetype, 1);
                        if (len == (-1))
                        {
                            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                            res=(-1);
                            goto safeout;
                        }
                        len = write(tmp->pipe[1], (void *)&fixedlength, 4);
                        if (len == (-1))
                        {
                            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                            res=(-1);
                            goto safeout;
                        }
                        len = write(tmp->pipe[1], tmp->audiobuffer + offset, fixedlength);
                        if (len == (-1))
                        {
                            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                            res=(-1);
                            goto safeout;
                        }

                        if (len != fixedlength)
                            I6LOG(LOG_WARNING, client,
                                    "Cannot write ALAW to PIPE (%d!=%d)!\n", len, fixedlength);

                        I6DEBUG(7, client, "Write %do from tmpBuff\n", fixedlength);
                        tmp->audiolength = tmp->audiolength - 160;
                        offset += fixedlength;

                        memset(tmp->audiobuffer, 0, fixedlength);
                    }

                    if (tmp->audiolength)
                    {
                        memcpy(tmp->audiobuffer, tmp->audiobuffer + offset,
                                tmp->audiolength);
                    }
                }
            }
        }
        else
        {
            I6LOG(LOG_WARNING, client, "rcv ALAW codec from msg, but channel not configured with ALAW (%s)\n", GET_FORMAT_NAME(client->audiocodec));
        }

        goto safeout;
    }
    else if (((*firstbyte & 0xf0) >> 4) == FLV_AUDIO_CODEC_G711_MULAW)  // 8)
    {
        length = rtmp->bodysize - 1;

        if (debug)
            I6DEBUG(1, client, ">* message/audio_ulaw(%d|%d,(%d,%d),%d)\n",
                    rtmp->timestamp, rtmp->timestampdelta, rtmp->channelid, rtmp->streamid,
                    rtmp->bodysize);

        if (COMPARE_VARFORMAT_IDFORMAT(client->audiocodec, AST_FORMAT_ULAW))
        {
            if (length != 0)
            {
                if (record_raw)
                {
                    if (!client->incoming_audiofile)
                    {
                        char filename[100];
                        sprintf(filename, "/tmp/RTMP%p_%d_incomingaudio_ulaw.raw", client,
                                (client->outgoing_calls + client->incoming_calls));
                        client->incoming_audiofile = fopen(filename, "wb");
                    }

                    if (client->incoming_audiofile)
                        fwrite(input, 1, length, client->incoming_audiofile);
                    else
                        ast_log(LOG_ERROR, "Cannot write incoming audio ulaw file !\n");
                }
                if (record_flv && length != 0)
                {
#ifdef RTMP_FFMPEG
                    if (client->in_flv.fd == 0)
                    {
                        INIT_FLV_INPUT(client);
                    }
                    if (FLV_writePkt(&client->in_flv, FLV_TYPE_AUDIO, client->timestamp,
                            length, (uint8_t *) input) != FLV_OK)
                    {
                        ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file !\n");
                    }
#else
                    {
                        ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file (no FFMPEG)!\n");
                    }
#endif
                }

                // Rcv lg is correct for codec => not buffered
                if ((length == 160) && !tmp->audiolength)
                {
                    pipetype = RTMP_PIPE_AUDIO_ULAW;
                    len = write(tmp->pipe[1], (void *)&pipetype, 1);
                    if (len == (-1))
                    {
                        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                        res=(-1);
                        goto safeout;
                    }
                    len = write(tmp->pipe[1], (void *)&length, 4);
                    if (len == (-1))
                    {
                        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                        res=(-1);
                        goto safeout;
                    }
                    len = write(tmp->pipe[1], input, length);
                    if (len == (-1))
                    {
                        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                        res=(-1);
                        goto safeout;
                    }

                    if (len != length)
                        I6LOG(LOG_WARNING, client, "Cannot write ULAW to PIPE (%d!=%d)!\n",
                                len, length);
                }
                else if (length)
                {
                    int offset;

                    I6DEBUG(7, client, "buffered ULAW packet:\n");

                    I6LOG(LOG_WARNING, client, "DBG length=%d, buffer=%d\n", length,
                            tmp->audiolength);

                    // Add lentgh in buff
                    memcpy(tmp->audiobuffer + tmp->audiolength, input, length);
                    tmp->audiolength += length;
                    I6DEBUG(7, client, "save buff from %d rcv. Size tmpBuff %d\n",
                            length, tmp->audiolength);

                    I6LOG(LOG_WARNING, client, "DBG new buffer=%d\n", tmp->audiolength);

                    // Check if we add to write tmp Buff in pipe
                    offset = 0;
                    while (tmp->audiolength >= 160)
                    {
                        int fixedlength = 160;

                        pipetype = RTMP_PIPE_AUDIO_ULAW;
                        len = write(tmp->pipe[1], (void *)&pipetype, 1);
                        if (len == (-1))
                        {
                            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                            res=(-1);
                            goto safeout;
                        }
                        len = write(tmp->pipe[1], (void *)&fixedlength, 4);
                        if (len == (-1))
                        {
                            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                            res=(-1);
                            goto safeout;
                        }
                        len = write(tmp->pipe[1], tmp->audiobuffer + offset, fixedlength);
                        if (len == (-1))
                        {
                            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                            res=(-1);
                            goto safeout;
                        }

                        if (len != fixedlength)
                            I6LOG(LOG_WARNING, client,
                                    "Cannot write ULAW to PIPE (%d!=%d)!\n", len, fixedlength);

                        I6DEBUG(7, client, "Write %do from tmpBuff\n", fixedlength);
                        tmp->audiolength = tmp->audiolength - 160;
                        offset += fixedlength;

                        I6LOG(LOG_WARNING, client, "DBG write 160, buffer=%d\n",
                                tmp->audiolength);
                        //memset(tmp->audiobuffer, 0, fixedlength);
                    }

                    I6LOG(LOG_WARNING, client, "DBG end buffer=%d\n", tmp->audiolength);

                    if (tmp->audiolength)
                    {
                        memcpy(tmp->audiobuffer, tmp->audiobuffer + offset,
                                tmp->audiolength);
                    }
                }
            }
        }
        else
        {
            I6LOG(LOG_WARNING, client, "rcv ULAW codec from msg, but channel not configured with ULAW (%s)\n", GET_FORMAT_NAME(client->audiocodec));
        }

        goto safeout;
    }
    else if (((*firstbyte & 0xf0) >> 4) == FLV_AUDIO_CODEC_ASTERISK_SLIN)  //9)
    {
        length = rtmp->bodysize - 1;

        if (debug)
            I6DEBUG(1, client, ">* message/audio_slinear(%d|%d,(%d,%d),%d)\n",
                    rtmp->timestamp, rtmp->timestampdelta, rtmp->channelid, rtmp->streamid,
                    rtmp->bodysize);

        if (COMPARE_VARFORMAT_IDFORMAT(client->audiocodec, AST_FORMAT_SLINEAR))
        {
            if (length != 0)
            {
                if (record_raw)
                {
                    if (!client->incoming_audiofile)
                    {
                        char filename[100];
                        sprintf(filename, "/tmp/RTMP%p_%d_incomingaudio_slinear.raw",
                                client, (client->outgoing_calls + client->incoming_calls));
                        client->incoming_audiofile = fopen(filename, "wb");
                    }

                    if (client->incoming_audiofile)
                        fwrite(input, 1, length, client->incoming_audiofile);
                    else
                        ast_log(LOG_ERROR, "Cannot write incoming audio slinear file !\n");
                }
                if (record_flv && length != 0)
                {
#ifdef RTMP_FFMPEG
                    if (client->in_flv.fd == 0)
                    {
                        INIT_FLV_INPUT(client);
                    }
                    if (FLV_writePkt(&client->in_flv, FLV_TYPE_AUDIO, client->timestamp,
                            length, (uint8_t *) input) != FLV_OK)
                    {
                        ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file !\n");
                    }
#else
                    {
                        ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file (no FFMPEG) !\n");
                    }
#endif
                }

                // Rcv lg is correct for codec => not buffered
                if ((length >= 320) && !tmp->audiolength)
                {
                    pipetype = RTMP_PIPE_AUDIO_SLINEAR;
                    len = write(tmp->pipe[1], (void *)&pipetype, 1);
                    if (len == (-1))
                    {
                        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                        res=(-1);
                        goto safeout;
                    }
                    len = write(tmp->pipe[1], (void *)&length, 4);
                    if (len == (-1))
                    {
                        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                        res=(-1);
                        goto safeout;
                    }
                    len = write(tmp->pipe[1], input, length);
                    if (len == (-1))
                    {
                        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                        res=(-1);
                        goto safeout;
                    }

                    if (len != length)
                        I6LOG(LOG_WARNING, client,
                                "Cannot write SLINEAR to PIPE (%d!=%d)!\n", len, length);
                }
                else
                {
                    int lgToCopie;

                    I6DEBUG(7, client, "buffered linear packet:\n");

                    // Calculate size of paste
                    lgToCopie = 320 - tmp->audiolength;
                    if (lgToCopie > length)
                    {
                        lgToCopie = length;
                    }

                    // Add lentgh in buff
                    memcpy(tmp->audiobuffer + tmp->audiolength, input, lgToCopie);
                    tmp->audiolength += lgToCopie;
                    I6DEBUG(7, client,
                            "save %do in tmp buff from %d rcv. Size tmpBuff %d\n", lgToCopie,
                            length, tmp->audiolength);

                    // Check if we add to write tmp Buff in pipe
                    if (tmp->audiolength >= 320)
                    {
                        int fixedlength = 320;
                        pipetype = RTMP_PIPE_AUDIO_SLINEAR;
                        len = write(tmp->pipe[1], (void *)&pipetype, 1);
                        if (len == (-1))
                        {
                            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                            res=(-1);
                            goto safeout;
                        }
                        len = write(tmp->pipe[1], (void *)&fixedlength, 4);
                        if (len == (-1))
                        {
                            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                            res=(-1);
                            goto safeout;
                        }
                        len = write(tmp->pipe[1], tmp->audiobuffer, fixedlength);
                        if (len == (-1))
                        {
                            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                            res=(-1);
                            goto safeout;
                        }

                        if (len != fixedlength)
                            I6LOG(LOG_WARNING, client,
                                    "Cannot write SLINEAR to PIPE (%d!=%d)!\n", len, fixedlength);

                        I6DEBUG(7, client, "Write %do from tmpBuff\n", fixedlength);
                        tmp->audiolength = 0;
                        memset(tmp->audiobuffer, 0, fixedlength);
                    }

                    // save the rest of the input buff in tmp buff
                    if (length > lgToCopie)
                    {
                        memcpy(tmp->audiobuffer, input + lgToCopie, length - lgToCopie);
                        tmp->audiolength += (length - lgToCopie);
                        I6DEBUG(7, client,
                                "save rest %do in tmp buff from %d rcv. Size tmpBuff %d",
                                length - lgToCopie, length, tmp->audiolength);
                    }
                }
            }
        }
        else
        {
            I6LOG(LOG_WARNING, client, "rcv linear codec from msg, but channel not configured with linear (%s)\n", GET_FORMAT_NAME(client->audiocodec));
        }

        goto safeout;
    }
    else if (((*firstbyte & 0xf0) >> 4) == FLV_AUDIO_CODEC_PCMS16le)  //3)
    {
        length = rtmp->bodysize - 1;

        if (debug)
            I6DEBUG(1, client, ">* message/audio_slinear(%d|%d,(%d,%d),%d)\n",
                    rtmp->timestamp, rtmp->timestampdelta, rtmp->channelid, rtmp->streamid,
                    rtmp->bodysize);

        if (COMPARE_VARFORMAT_IDFORMAT(client->audiocodec, AST_FORMAT_SLINEAR))
        {
            if (length != 0)
            {
                // Rcv lg is correct for codec => not buffered
                if ((length >= 320) && !tmp->audiolength)
                {
                    pipetype = RTMP_PIPE_AUDIO_SLINEAR;
                    len = write(tmp->pipe[1], (void *)&pipetype, 1);
                    if (len == (-1))
                    {
                        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                        res=(-1);
                        goto safeout;
                    }
                    len = write(tmp->pipe[1], (void *)&length, 4);
                    if (len == (-1))
                    {
                        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                        res=(-1);
                        goto safeout;
                    }
                    len = write(tmp->pipe[1], input, length);
                    if (len == (-1))
                    {
                        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                        res=(-1);
                        goto safeout;
                    }

                    if (len != length)
                        I6LOG(LOG_WARNING, client,
                                "Cannot write SLINEAR to PIPE (%d!=%d)!\n", len, length);
                    I6DEBUG(7, client, "Write %do from tmpBuff\n", length);
                }
                else
                {
                    int lgToCopie;

                    I6DEBUG(7, client, "buffered linear packet:\n");

                    // Calculate size of paste
                    lgToCopie = 320 - tmp->audiolength;
                    if (lgToCopie > length)
                    {
                        lgToCopie = length;
                    }

                    // Add lentgh in buff
                    memcpy(tmp->audiobuffer + tmp->audiolength, input, lgToCopie);
                    tmp->audiolength += lgToCopie;
                    I6DEBUG(7, client,
                            "save %do in tmp buff from %d rcv. Size tmpBuff %d\n", lgToCopie,
                            length, tmp->audiolength);

                    // Check if we add to write tmp Buff in pipe
                    if (tmp->audiolength >= 320)
                    {
                        int fixedlength = 320;
                        pipetype = RTMP_PIPE_AUDIO_SLINEAR;
                        len = write(tmp->pipe[1], (void *)&pipetype, 1);
                        if (len == (-1))
                        {
                            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                            res=(-1);
                            goto safeout;
                        }
                        len = write(tmp->pipe[1], (void *)&fixedlength, 4);
                        if (len == (-1))
                        {
                            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                            res=(-1);
                            goto safeout;
                        }
                        len = write(tmp->pipe[1], tmp->audiobuffer, fixedlength);
                        if (len == (-1))
                        {
                            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                            res=(-1);
                            goto safeout;
                        }

                        if (len != fixedlength)
                            I6LOG(LOG_WARNING, client,
                                    "Cannot write SLINEAR to PIPE (%d!=%d)!\n", len, fixedlength);

                        I6DEBUG(7, client, "Write %do from tmpBuff\n", fixedlength);
                        tmp->audiolength = 0;
                        memset(tmp->audiobuffer, 0, fixedlength);
                    }

                    // save the rest of the input buff in tmp buff
                    if (length > lgToCopie)
                    {
                        memcpy(tmp->audiobuffer, input + lgToCopie, length - lgToCopie);
                        tmp->audiolength += (length - lgToCopie);
                        I6DEBUG(7, client,
                                "save rest %do in tmp buff from %d rcv. Size tmpBuff %d",
                                length - lgToCopie, length, tmp->audiolength);
                    }
                }
            }
        }
        else
        {
            I6LOG(LOG_WARNING, client, "rcv linear codec from msg, but channel not configured with linear (%s)\n", GET_FORMAT_NAME(client->audiocodec));
        }

        goto safeout;
    }

    /* decode audio packet
     * The first byte is not a media packet,
     * it contains the following codec information :
     *  soundType   (byte & 0x01) >> 0  0: mono, 1: stereo
     *  soundSize   (byte & 0x02) >> 1  0: 8-bit, 1: 16-bit
     *  soundRate   (byte & 0x0c) >> 2  0: 5.5 kHz, 1: 11 kHz, 2: 22 kHz, 3: 44 kHz
     *  soundFormat (byte & 0xf0) >> 4  0: Uncompressed, 1: ADPCM, 2: MP3, 5: Nellymoser 8kHz mono, 6: Nellymoser, 11: Speex
     * */
    I6DEBUG(3, client, "bodysize-1 = %d, firstbyte=0x%02X\n", rtmp->bodysize - 1,
            *firstbyte);

    I6LOG(LOG_WARNING, client, "Audio packets discarded\n");
    goto safeout;

#ifdef RTMP_FFMPEG

    //len = avcodec_decode_audio2(tmp->decoding_context, (int16_t *)rawsamples, &rawsampleslen, input, rtmp->bodysize - 1);
    {
        AVPacket avpkt;

        av_init_packet(&avpkt);
        avpkt.data = input;
        avpkt.size = (rtmp->bodysize - 1);

        rawsamples = ast_malloc(rawsampleslen);
        samples = ast_malloc(1024);

        //len = avcodec_decode_audio3(tmp->decoding_context, (int16_t *)&audio_buf[tmp->decoding_jitter_length], &rawsampleslen, &avpkt);
        len =
                avcodec_decode_audio3(tmp->decoding_context, (int16_t *) rawsamples,
                        &rawsampleslen, &avpkt);
    }
    I6DEBUG(5, client, "RAW len = %d\n", len);
    I6DEBUG(5, client, "rawsampleslen= %d\n", rawsampleslen);
#if 0
    if (inputrate != tmp->rtmpinputrate)
    {
        /* incoming audio packets are not sampled at the expected rate
         * so let's reinitialize the sampling context */
        if (!tmp->fromrtmp_resample_context)
        {
            ast_log(LOG_DEBUG, "No sampling context found\n");
            res = (-1);
            goto safeout;
        }
        audio_resample_close(tmp->fromrtmp_resample_context);
        ast_log(LOG_NOTICE, "Changed incoming sample rate from %d Hz to %d Hz\n",
                tmp->rtmpinputrate, inputrate);
        tmp->rtmpinputrate = inputrate;
        tmp->fromrtmp_resample_context = av_audio_resample_init(1, 1, /* One channel in both ways */
                tmp->astinputrate, tmp->rtmpinputrate,
                SAMPLE_FMT_S16, SAMPLE_FMT_S16, 16, 10, 1, 0.8);
    }
    len =
            audio_resample(tmp->fromrtmp_resample_context, (short *)samples,
                    (short *)rawsamples, rawsampleslen / 2);
#endif
    //len = write(tmp->pipe[1], samples, len * 2);
#if 1
    if (tmp->decoding_jitter_length)
        memcpy(audio_buf, tmp->decoding_jitter, tmp->decoding_jitter_length);
    len = (rawsampleslen + tmp->decoding_jitter_length);
    tmp->decoding_jitter_length = len % JITTER_SIZE;
    len = len - tmp->decoding_jitter_length;
    if (tmp->decoding_jitter_length)
        memcpy(tmp->decoding_jitter, &audio_buf[len], tmp->decoding_jitter_length);
    if (tmp->decoding_jitter_length)
        memset(tmp->decoding_jitter, '\0', tmp->decoding_jitter_length);
    I6DEBUG(3, client, "jitter = %d\n", tmp->decoding_jitter_length);
#endif
    pipetype = RTMP_PIPE_AUDIO_NELLYMOSER;
    len = write(tmp->pipe[1], (void *)&pipetype, 1);
    if (len == (-1))
    {
        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
        res=(-1);
        goto safeout;
    }
    len = write(tmp->pipe[1], audio_buf, len);
    if (len == (-1))
    {
        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
        res=(-1);
        goto safeout;
    }
    len = write(tmp->pipe[1], audio_buf, rawsampleslen);
    if (len == (-1))
    {
        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
        res=(-1);
        goto safeout;
    }

    if (len != rawsampleslen)
        I6LOG(LOG_WARNING, client, "Cannot write Nellymoser to PIPE (%d!=%d)!\n",
                len, rawsampleslen);
#endif

    safeout:
    if (input)
        ast_free(input);
    if (rawsamples)
        ast_free(rawsamples);
    if (samples)
        ast_free(samples);

    return res;
}

/** \brief Handle video packets
 */
static int rtmp_handle_video_packet(struct rtmp_client *client,
        struct rtmp_message *rtmp)
{
    int res = (-1);
    struct rtmp_pvt *tmp = NULL;
    int len = 0;
    uint8_t pipetype = RTMP_PIPE_VIDEO_SORENSON;
    uint8_t *firstbyte = NULL;
    uint32_t length = 0;

    uint8_t frameBuffer[2000];
    uint8_t *frameData = frameBuffer;

    unsigned char Sorenson_header[30] = { 0 };

    uint16_t cseq = 0;
    uint32_t txseq = client->txseq;

    //uint8_t *data = rtmp->body;
    uint8_t *data = rtmp->body + 1;
    uint8_t *test = rtmp->body;
    //uint32_t size = rtmp->bodysize;
    uint32_t size = rtmp->bodysize - 1;

    uint32_t msgtype = 9;
    uint32_t msgsize = size;
    uint32_t msgtime = 9000;      //((90000/vtc->fps) * vtc->txseq) / 1000;

    int maxsize = 1000;
    int position = maxsize - 25;

    int pipesize;

    tmp = client->pvt;

    if (tmp == NULL)
    {
        if (debug)
            I6DEBUG(0, client,
                    "No Asterisk channel that matches with RTMP channel %d\n",
                    rtmp->channelid);
        res = (-1);
        goto safeout;
    }

    client->incoming_video++;

    firstbyte = rtmp->body;
    if (debug)
        I6DEBUG(7, client, "firsbyte = %02Xh\n", *firstbyte);

    if (debug)
    {
        if (((*firstbyte)&0xF0)>>4 == FLV_FRAMETYPE_KEY){
            I6DEBUG(9, client, "complete frame (keyframe) size %d\n", size);
        }
    }

    if (!tmp->owner)
    {
        if (debug)
            ast_log(LOG_DEBUG,
                    "No Asterisk channel that matches with RTMP channel %d\n",
                    rtmp->channelid);
        res = (-1);
        goto safeout;
    }

    if (maxvideopipe)
    {
        ioctl(tmp->pipe[0], FIONREAD, &pipesize);

        if (pipesize > maxvideopipe)
        {
            client->incoming_videolost++;

            I6DEBUG(0, client, "Max video buffer reach : %d\n", pipesize);
            res = (-1);
            goto safeout;
        }
    }

    if (debug)
        I6DEBUG(1, client, ">* message/video_sorenson(%d|%d,(%d,%d),%d)\n",
                rtmp->timestamp, rtmp->timestampdelta, rtmp->channelid, rtmp->streamid,
                rtmp->bodysize);

    client->incoming_images++;

    /* Construct payload header.
     Set videosize and the temporal reference to that of the frame */
    Sorenson_header[0] = 'R';
    Sorenson_header[1] = 'T';
    Sorenson_header[2] = 'M';
    Sorenson_header[3] = 'P';

    *((uint32_t *) (&Sorenson_header[4])) = htonl(txseq);
    *((uint16_t *) (&Sorenson_header[8])) = htons(cseq);
    *((uint16_t *) (&Sorenson_header[10])) = htons((uint16_t) size + 13);

    *((uint32_t *) (&Sorenson_header[12])) = htonl(msgtype);
    *((uint32_t *) (&Sorenson_header[16])) = htonl(msgsize + 1);
    *((uint32_t *) (&Sorenson_header[20])) = htonl(msgtime);

    if (txseq > 10)
        Sorenson_header[24] = 0x22;
    else
        Sorenson_header[24] = 0x12;

    Sorenson_header[24] = *test;

    if (debug)
        I6DEBUG(5, client,
                "Sorenson header 1 [0x%.2x,0x%.2x,0x%.2x,0x%.2x, 0x%.2x,0x%.2x,0x%.2x,0x%.2x]\n",
                Sorenson_header[0], Sorenson_header[1], Sorenson_header[2],
                Sorenson_header[3], Sorenson_header[4], Sorenson_header[5],
                Sorenson_header[6], Sorenson_header[7]);
    if (debug)
        I6DEBUG(5, client,
                "Sorenson header 2 [0x%.2x,0x%.2x,0x%.2x,0x%.2x, 0x%.2x,0x%.2x,0x%.2x,0x%.2x]\n",
                Sorenson_header[8], Sorenson_header[9], Sorenson_header[10],
                Sorenson_header[11], Sorenson_header[12], Sorenson_header[13],
                Sorenson_header[14], Sorenson_header[15]);
    if (debug)
        I6DEBUG(5, client,
                "Sorenson header 3 [0x%.2x,0x%.2x,0x%.2x,0x%.2x, 0x%.2x,0x%.2x,0x%.2x,0x%.2x]\n",
                Sorenson_header[16], Sorenson_header[17], Sorenson_header[18],
                Sorenson_header[19], Sorenson_header[20], Sorenson_header[21],
                Sorenson_header[22], Sorenson_header[23]);
    if (debug)
        I6DEBUG(5, client, "Sorenson header 4 [0x%.2x]\n", Sorenson_header[24]);

    if (size < (maxsize - 25))
        maxsize = 0;

    /* Set frame len */
    if (maxsize)
        length = maxsize;
    else
        length = size + 25;

    /* Set header */
    memcpy(frameData, Sorenson_header, 25);
    /* Copy */
    if (maxsize)
        memcpy(frameData + 25, data, maxsize - 25);
    else
        memcpy(frameData + 25, data, size);

    if (maxsize)
        pipetype = RTMP_PIPE_VIDEO_SORENSON;
    else
        pipetype = RTMP_PIPE_VIDEO_SORENSON_MARK;

    len = write(tmp->pipe[1], (void *)&pipetype, 1);
    if (len == (-1))
    {
        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
        res=(-1);
        goto safeout;
    }
    len = write(tmp->pipe[1], (void *)&length, 4);
    if (len == (-1))
    {
        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
        res=(-1);
        goto safeout;
    }
    len = write(tmp->pipe[1], frameData, length);
    if (len == (-1))
    {
        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
        res=(-1);
        goto safeout;
    }

    if (len != length)
    {
        I6LOG(LOG_WARNING, client, "Cannot write packet to PIPE (%d!=%d)!\n", len,
                length);
    }

    // Get picture size
    if (client && client->pvt)
    {
        if (client->havePictureInSize == 0)
        {
#ifdef RTMP_FFMPEG
            FLV_getPictureSize(&(client->pictureIn_width),
                    &(client->pictureIn_heigth), (uint8_t *) data);
            if (client->pictureIn_width > 2 && client->pictureIn_heigth > 2)
            {
                I6DEBUG(3, client, "FLV get picture size from frame %dx%d\n",
                        client->pictureIn_width, client->pictureIn_heigth);
                client->havePictureInSize = 1;
            }
            else
            {
                I6DEBUG(3, client, "bad image size %dx%d\n", client->pictureIn_width,
                        client->pictureIn_heigth);
            }
#else
            {
                client->pictureIn_width = 1;
                client->pictureIn_heigth = 1;
                client->havePictureInSize = 0;
                I6DEBUG(3, client, "bad image size %dx%d (no FFMPEG)\n", client->pictureIn_width,
                        client->pictureIn_heigth);
            }
#endif
        }


    }

    if (record_flv && size != 0)
    {
#ifdef RTMP_FFMPEG
        if (client->in_flv.fd == 0)
        {
            INIT_FLV_INPUT(client);
        }

        //if (FLV_writePkt(&client->in_flv, FLV_TYPE_VIDEO, client->timestamp, length, (uint8_t*)frameData) != FLV_OK){
        if (FLV_writePkt(&client->in_flv, FLV_TYPE_VIDEO, client->timestamp, size,
                (uint8_t *) data) != FLV_OK)
        {
            ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file !\n");
        }
#else
        {
            ast_log(LOG_ERROR, "Cannot write incoming pkt to flv file (no FFMPEG)!\n");
        }
#endif
    }

    while (position < size)
    {
        int len = size - position;
        uint8_t *ptr = data + position;

        cseq++;
        if (debug)
            I6DEBUG(7, client, "cseq = %d\n", cseq);
        *((uint16_t *) (&Sorenson_header[8])) = htons(cseq);

        if (debug)
            I6DEBUG(7, client,
                    "Sorenson header 1 [0x%.2x,0x%.2x,0x%.2x,0x%.2x, 0x%.2x,0x%.2x,0x%.2x,0x%.2x]\n",
                    Sorenson_header[0], Sorenson_header[1], Sorenson_header[2],
                    Sorenson_header[3], Sorenson_header[4], Sorenson_header[5],
                    Sorenson_header[6], Sorenson_header[7]);
        if (debug)
            I6DEBUG(7, client,
                    "Sorenson header 2 [0x%.2x,0x%.2x,0x%.2x,0x%.2x, 0x%.2x,0x%.2x,0x%.2x,0x%.2x]\n",
                    Sorenson_header[8], Sorenson_header[9], Sorenson_header[10],
                    Sorenson_header[11], Sorenson_header[12], Sorenson_header[13],
                    Sorenson_header[14], Sorenson_header[15]);
        if (debug)
            I6DEBUG(7, client,
                    "Sorenson header 3 [0x%.2x,0x%.2x,0x%.2x,0x%.2x, 0x%.2x,0x%.2x,0x%.2x,0x%.2x]\n",
                    Sorenson_header[16], Sorenson_header[17], Sorenson_header[18],
                    Sorenson_header[19], Sorenson_header[20], Sorenson_header[21],
                    Sorenson_header[22], Sorenson_header[23]);
        if (debug)
            I6DEBUG(7, client, "Sorenson header 4 [0x%.2x]\n", Sorenson_header[24]);

        /* Set header */
        memcpy(frameData, Sorenson_header, 10);

        if (len > (maxsize - 10))
        {
            position += (maxsize - 10);
            len = maxsize - 10;
        }
        else
        {
            position = size;
            pipetype = RTMP_PIPE_VIDEO_SORENSON_MARK;
        }

        memcpy(frameData + 10, ptr, len);

        length = len + 10;

        I6DEBUG(3, client, "Write video frame [%d]\n", length);

        if (tmp->pipe[1] != -1)
        {
            len = write(tmp->pipe[1], (void *)&pipetype, 1);
            if (len == (-1))
            {
                ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                res=(-1);
                goto safeout;
            }
            len = write(tmp->pipe[1], (void *)&length, 4);
            if (len == (-1))
            {
                ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                res=(-1);
                goto safeout;
            }
            len = write(tmp->pipe[1], frameData, length);
            if (len == (-1))
            {
                ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                res=(-1);
                goto safeout;
            }

            I6DEBUG(3, client, "Writen video frame [%d]\n", len);
        }
        else
            len = 0;

        if (len != length)
        {
            I6LOG(LOG_WARNING, client, "Cannot write packet to PIPE (%d!=%d)!2\n",
                    len, length);
        }
    }

    client->txseq++;

    safeout:

    return res;
}


static void rtmp_function_process(struct rtmp_client *client, char *input)
{
    char result[1024] = { "" };
    char params[1024];
    char *pParams, *ptr;
    char *ptrReq, *ptrEndReq;
    int len;

    I6DEBUG(8, client, "notify: function (%d)%s\n", strlen(input), input);

    /*
     * Cmd format : [<headertxt>]|<cmd>(param1, param2, ...)|cmd2(p1, p2 ...)|...
     */

    /* check headertxt
     *   headertxt|cmd(...)
     *    | before (
     */
    ptr = strchr(input, '|');
    pParams = strchr(input, '(');
    if (ptr && (ptr != input) && (pParams > ptr))
    {
        len = ptr - input;
        if (len > 1024) {
            I6DEBUG(1, client, " notify too long %d > max\n",len);
            len = 1022;
        }
        // write header text in response
        memcpy(result, input, len);
        result[len] = '|';
        result[len + 1] = '\0';
        I6DEBUG(8, client, " prepare result: %s\n", result);

        ptrReq = ptr + 1;
    }
    else
    {
        ptrReq = input;
    }

    ptrEndReq = input + strlen(input);

    // Loop on cmd
    while (ptrReq < ptrEndReq)
    {
        // Search eof cmd ')'
        if ((ptr = strchr(ptrReq, ')')))
        {
            char localResult[128] = { "" };

            len = ptr + 1 - ptrReq;
            if (len > 1024) {
                I6DEBUG(1, client, " notify too long %d > max\n",len);
                len = 1022;
            }
            memcpy(params, ptrReq, len);
            params[len] = '\0';

            // check if it's a get or set
            //  <cmd>(params,..)==<setvalue>

            // point after ')'
            ptrReq = ptr + 1;
            if (!strncmp(ptrReq, "==", 2))
            {
                char setvalue[128];

                // decale for ==
                ptrReq += 2;

                // Get setvalue
                if ((ptr = strchr(ptrReq, '|')))
                {
                    len = ptr - ptrReq;
                    if (len > 128) {
                        I6DEBUG(1, client, " notify params too long %d > max\n",len);
                        len = 127;
                    }
                    memcpy(setvalue, ptrReq, len);
                    setvalue[len] = '\0';
                    ptrReq = ptr;
                }
                else
                {
                    len = ptrEndReq - ptrReq;
                    if (len > 128) {
                        I6DEBUG(1, client, " notify params too long %d > max\n",len);
                        len = 127;
                    }
                    memcpy(setvalue, ptrReq, len);
                    setvalue[len] = '\0';
                    ptrReq = ptrEndReq;
                }

                I6DEBUG(8, client, " cmd set value %s for %s\n", setvalue, params);
                if (ast_func_write(NULL, params, setvalue) >= 0)
                    strcat(result, "OK");
                else
                    strcat(result, "failed");
            }
            else
            {
                I6DEBUG(8, client, " cmd get value of %s\n", params);
                //ast_func_read(NULL, params, localResult, sizeof(localResult));
                //if (strlen(localResult) > 0)
                if (ast_func_read(NULL, params, localResult, sizeof(localResult)) >= 0)
                {
                    I6DEBUG(8, client, "  result: %s\n", localResult);
                    strcat(result, localResult);
                }
                else
                {
                    strcat(result, "failed");
                }
            }
        }
        else
        {
            I6DEBUG(8, client, "don't found ')' !\n");
            strcat(result, "failed");
        }

        // Search net cmd
        if ((ptr = strchr(ptrReq, '|')))
        {
            ptrReq = ptr + 1;
            strcat(result, "|");
        }
        else
        {
            break;
        }
    }                             // eof loop cmd


    I6DEBUG(8, client, " result of all cmd: %s\n", result);
    ast_mutex_lock(&client->lock);
    rtmp_send_function(client, result);
    ast_mutex_unlock(&client->lock);

    return;
}

struct fast_request_helper
{
        char input[1024];
        struct rtmp_client *client;
};

static void *fast_request(void *data)
{
    struct fast_request_helper *helper = data;

    I6DEBUG(8, NULL, "Begin the thread.\n");

    if (helper)
    {
        struct rtmp_threadinfo *th;
        struct ao2_iterator i;

        I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
        ast_mutex_lock(&rtmplock);
        I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n");

        i = ao2_iterator_init(threadt, 0);
        while ((th =
                ao2_t_iterator_next(&i,
                        "iterate through tcp threads for 'rtmp fast request ...'")))
        {

            if (th->client == helper->client)
            {
                I6DEBUG(8, helper->client, "Found client in the request thread.\n");

                rtmp_function_process(helper->client, helper->input);
                ao2_t_ref(th, -1, "decrement ref from iterator");
                break;
            }
            ao2_t_ref(th, -1, "decrement ref from iterator");
        }
        ao2_iterator_destroy(&i);

        I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
        ast_mutex_unlock(&rtmplock);

        ast_free(helper);
    }

    I6DEBUG(8, NULL, "End the thread.\n");

    return NULL;
}

/** \brief Handle text packets
 */
static int rtmp_handle_notify_packet(struct rtmp_client *client,
        struct rtmp_message *rtmp)
{
    int res = (-1);
    char *amf = NULL;
    struct rtmp_pvt *tmp = NULL;
    int len = 0;
    uint8_t pipetype = RTMP_PIPE_TEXT;
    char command[256];
    char input[256];
    char dstId[256];
    uint32_t length = 0;
    //uint32_t size = rtmp->bodysize - 1;

    tmp = client->pvt;

    /*  JYG
     if (tmp == NULL)
     {
     ast_log(LOG_WARNING, "No Asterisk channel that matches with RTMP channel %d\n", rtmp->channelid);
     goto safeout;
     }

     if (!tmp->owner) {
     ast_log(LOG_WARNING, "No Asterisk channel that matches with RTMP channel %d\n", rtmp->channelid);
     res = (-1);
     goto safeout;
     }
     */
    /* get a local copy of the RTMP body */
    amf = ast_malloc(rtmp->bodysize);
    if (!amf)
    {
        return res;
    }
    memcpy(amf, rtmp->body, rtmp->bodysize);

    res = amf_parse_command(command, input, amf, dstId, rtmp->bodysize);

    if (!strcmp(command, "function"))
    {
        I6DEBUG(1, client, ">* message/notify(%s,%s)\n", command, input);
    }
    else
    {
        RTMP_VERBOSE(client, ">* message/notify(%s,%s)\n", command, input);
    }

    //memcpy(input, "1", 1);

    if (!strcmp(command, "dtmf"))
    {
        stats[STATS_DTMFS]++;

        pipetype = RTMP_PIPE_DTMF;
        length = 1;
        input[0] |= 0x80;
        I6DEBUG(8, client, "Send Start DTMF.\n");
        len = write(tmp->pipe[1], (void *)&pipetype, 1);
        if (len == (-1))
        {
            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
            res=(-1);
            goto safeout;
        }
        len = write(tmp->pipe[1], input, 1);
        if (len == (-1))
        {
            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
            res=(-1);
            goto safeout;
        }
        input[0] &= 0x7F;
        I6DEBUG(8, client, "Send End DTMF.\n");
        len = write(tmp->pipe[1], (void *)&pipetype, 1);
        if (len == (-1))
        {
            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
            res=(-1);
            goto safeout;
        }
        len = write(tmp->pipe[1], input, 1);
        if (len == (-1))
        {
            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
            res=(-1);
            goto safeout;
        }
    }
    else if (!strcmp(command, "text"))
    {
        stats[STATS_TEXTS]++;

        /* Send text directly to connected user if the dstId is the same that connected user
       or if dst id is empty
         */
        len = strlen(dstId);
        if ((tmp != NULL) &&
                ((!strncasecmp(tmp->client->name, dstId, len)) || (strlen(dstId) == 0)))
        {
            I6DEBUG(6, client, "Notify packet to %s\n", tmp->client->name);
            if (!tmp->owner)
            {
                ast_log(LOG_WARNING,
                        "No Asterisk channel that matches with RTMP channel %d\n",
                        rtmp->channelid);
                res = (-1);
                goto safeout;
            }

            pipetype = RTMP_PIPE_TEXT;
            length = strlen(input);
            len = write(tmp->pipe[1], (void *)&pipetype, 1);
            if (len == (-1))
            {
                ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                res=(-1);
                goto safeout;
            }
            len = write(tmp->pipe[1], (void *)&length, 4);
            if (len == (-1))
            {
                ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                res=(-1);
                goto safeout;
            }
            len = write(tmp->pipe[1], input, length);
            if (len == (-1))
            {
                ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
                res=(-1);
                goto safeout;
            }
        }
        else
        {
            struct rtmp_threadinfo *th;
            size_t len;
            struct ao2_iterator i;
            char tmp[20];

            I6DEBUG(6, client, "Search client id %s for text msg\n", dstId);

            /* Search rtmp ctx for dst user Id */
            ast_mutex_lock(&rtmplock);

            i = ao2_iterator_init(threadt, 0);
            while ((th =
                    ao2_t_iterator_next(&i,
                            "iterate through tcp threads for 'rtmp show connection'")))
            {
                if (th->client)
                {
                    sprintf(tmp, "RTMP/%p", th->client);
                    len = strlen(dstId);
                    if (len > 0)
                    {
                        if (!strncasecmp(th->client->name, dstId, len))
                        {
                            ast_mutex_lock(&th->client->lock);

                            I6DEBUG(6, client, "Notify packet to %s (dstId %s thd %p)\n",
                                    th->client->name, dstId, th->client);
                            rtmp_send_text(th->client, input);

                            ast_mutex_unlock(&th->client->lock);
                        }
                    }
                    else
                    {
                        ast_log(LOG_WARNING, "No userId to send text msg\n");
                    }
                }
                ao2_t_ref(th, -1, "Unref threadinfo");
            }
            ao2_iterator_destroy(&i);

            ast_mutex_unlock(&rtmplock);
        }
    }
    else if (!strcmp(command, "event"))
    {
        stats[STATS_EVENTS]++;

        pipetype = RTMP_PIPE_EVENT;
        length = 1;
        I6DEBUG(8, client, "Send EVENT.\n");
        len = write(tmp->pipe[1], (void *)&pipetype, 1);
        if (len == (-1))
        {
            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
            res=(-1);
            goto safeout;
        }
        len = write(tmp->pipe[1], input, 1);
        if (len == (-1))
        {
            ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
            res=(-1);
            goto safeout;
        }
    }
    else if (!strcmp(command, "function"))
    {
        stats[STATS_FUNCTIONS]++;

        if (functionthreaded)
        {
            pthread_t th;
            struct fast_request_helper *fast = ast_calloc(1, sizeof(*fast));

            fast->client = client;
            strncpy(fast->input, input, 1024);

            I6DEBUG(8, client, "Start the thread.\n");

#if ASTERISK_VERSION_NUM >= AST_6
            if (ast_pthread_create_detached(&th, NULL, fast_request, fast))
            {
                ast_free(fast);
                ast_log(LOG_WARNING, "Unable to create the thread.\n");
            }
            else
            {
                res = 0;
            }
#else
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);


            if (ast_pthread_create(&th, &attr, fast_request, fast))
            {
                ast_free(fast);
                ast_log(LOG_WARNING, "Unable to create the thread.\n");
            }

            pthread_attr_destroy(&attr);
#endif
        }
        else
        {
            rtmp_function_process(client, input);
        }
    }
    else if (!strcmp(command, "admin"))
    {
        //char string[PATH_MAX];
        I6DEBUG(1, client, "Admin response from %s\n", client->name);
        //sprintf(string, "  %s: %s\n", client->name, input);
        //ast_console_puts(string);

        if (!strncmp(input, ADMIN_RESP_GETQOS, ADMIN_RESP_GETQOS_LG))
        {
            ast_verbose("  %s: %s\n", client->name, input + ADMIN_RESP_GETQOS_LG);
        }
        else if (!strncmp(input, ADMIN_RESP_GETCFG, ADMIN_RESP_GETCFG_LG))
        {
            ast_verbose("  %s: %s\n", client->name, input + ADMIN_RESP_GETCFG_LG);
        }
        else if (!strncmp(input, ADMIN_CMD_GETVERSION, ADMIN_CMD_GETVERSION_LG))
        {
            rtmp_send_admin(client, "respGetVersion:$Revision: 1.323 $");
        }
        else if (!strncmp(input, ADMIN_CMD_PING, ADMIN_CMD_PING_LG))
        {
            rtmp_send_admin(client, ADMIN_RESP_PONG);
        }
        else
        {
            ast_verbose("Unsupported ADMIN response from %s: %s\n", client->name,
                    input);
        }
    }
    else if (!strcmp(command, "error"))
    {
        ast_log(LOG_ERROR, "RTMP Error : %s %s.\n", client->name, input);
        //ast_verbose("RTMP Error :%s: %s.\n", client->name, input);
    }
    else if (!strcmp(command, "warning"))
    {
        ast_log(LOG_WARNING, "RTMP Warning : %s %s.\n", client->name, input);
        //ast_verbose("RTMP Warning :%s: %s.\n", client->name, input);
    }
    else if (!strcmp(command, "cdr"))
    {
        /* Set CDR user field for channel (stored in CDR)
       int ast_cdr_setuserfield(struct ast_channel *chan, const char *userfield);
       Append to CDR user field for channel (stored in CDR)
       int ast_cdr_appenduserfield(struct ast_channel *chan, const char *userfield);
         */
        if (tmp != NULL && tmp->owner != NULL)
        {
            //ast_cdr_appenduserfield(tmp->owner, input);  Marcos: test_AST12
            I6DEBUG(1, client, "CDR from %s: %s\n", client->name, input);
        }
        else
        {
            I6DEBUG(1, client, "CDR cannot be sent.\n");
        }
    }
    else if (!strcmp(command, "add"))
    {
        if (events)
            manager_event(EVENT_FLAG_SYSTEM, "Registry",
                    "ChannelType: RTMP\r\nName: %s\r\nContact: %s\r\nAction: Add\r\n",
                    client->name, input);
    }
    else if (!strcmp(command, "remove"))
    {
        if (events)
            manager_event(EVENT_FLAG_SYSTEM, "Registry",
                    "ChannelType: RTMP\r\nName: %s\r\nContact: %s\r\nAction: Remove\r\n",
                    client->name, input);
    }
    else
    {
    }

    safeout:
    ast_free(amf);

    return res;
}


/** \brief Handle null packets
 */
static int rtmp_handle_null_packet(struct rtmp_client *client)
{
    int res = (-1);
    struct rtmp_pvt *tmp = NULL;
    int len = 0;
    uint8_t pipetype = RTMP_PIPE_NULL;
    uint32_t length = 0;

    tmp = client->pvt;
    if (tmp == NULL)
    {
        ast_log(LOG_WARNING,
                "No Asterisk channel that matches with RTMP channel %d\n", -1);
        goto safeout;
    }

    if (!tmp->owner)
    {
        ast_log(LOG_WARNING,
                "No Asterisk channel that matches with RTMP channel %d\n", -1);
        res = (-1);
        goto safeout;
    }

    I6DEBUG(7, client, "Send NULL pipe.\n");

    pipetype = RTMP_PIPE_NULL;
    length = 1;
    len = write(tmp->pipe[1], (void *)&pipetype, 1);
    if (len == (-1))
    {
        ast_log(LOG_ERROR, "PIPE WRITE ERROR : client %p, !\n", client);
        res=(-1);
        goto safeout;
    }

    safeout:

    return res;
}


/** \brief Parse AMF reply from server
 */
static int amf_parse_reply(double *result, char *level, char *code,
        char *description, char *amf, size_t len)
{
    int res = (-1);
    char *aux = NULL;
    int count = 0;
    int context = AMF_PARSE_TYPE;
    uint16_t wordlen;
    char string[256];
    memset(string, '\0', 256);

    if (!amf)
    {
        ast_log(LOG_WARNING, "Failed to parse AMF message\n");
        return res;
    }

    aux = amf;

    while (count < len)
    {
        if (debug)
            ast_debug(4, "context = %d %d %d\n", context, count, len);
        switch (context)
        {
            case AMF_PARSE_TYPE:
                context = amf_get_type(aux);
                aux++;
                count++;
                break;
            case AMF_PARSE_STRINGLEN:
                /* string length is 2-bytes long */
                memcpy(&wordlen, aux, sizeof(uint16_t));
                wordlen = htons(wordlen);
                if (debug)
                    ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                if (wordlen > (len - count))
                {
                    ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                    return -1;
                }
                aux += 2;
                count += 2;
                context = AMF_PARSE_STRINGVAL;
                break;
            case AMF_PARSE_STRINGVAL:
                context = amf_get_string(string, aux, wordlen);
                if (debug)
                    ast_debug(4, "string : %s\n", string);
                aux += wordlen;
                count += wordlen;
                break;
            case AMF_PARSE_DOUBLE_RESULT:
                aux++;
                count++;
                context = amf_get_number(result, aux);
                aux += sizeof(double);
                count += sizeof(double);
                break;
            case AMF_PARSE_PROPERTY_LEVEL:
                /* skip AMF type byte */
                aux++;
                count++;
                memcpy(&wordlen, aux, sizeof(uint16_t));
                wordlen = htons(wordlen);
                if (debug)
                    ast_debug(4, "wordlen (property level) = %d\n", wordlen);
                if (wordlen > (len - count))
                {
                    ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                    return -1;
                }
                aux += 2;
                count += 2;
                amf_get_string(level, aux, wordlen);
                aux += wordlen;
                count += wordlen;
                /* next object is a property or an object
                 * end */
                context = AMF_PARSE_STRINGLEN;
                break;
            case AMF_PARSE_PROPERTY_CODE:
                /* skip AMF type byte */
                aux++;
                count++;
                memcpy(&wordlen, aux, sizeof(uint16_t));
                wordlen = htons(wordlen);
                if (debug)
                    ast_debug(4, " wordlen (property code) = %d\n", wordlen);
                if (wordlen > (len - count))
                {
                    ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                    return -1;
                }
                aux += 2;
                count += 2;
                amf_get_string(code, aux, wordlen);
                aux += wordlen;
                count += wordlen;
                /* next object is a property or an object
                 * end */
                context = AMF_PARSE_STRINGLEN;
                break;
            case AMF_PARSE_PROPERTY_DESCRIPTION:
                /* skip AMF type byte */
                aux++;
                count++;
                memcpy(&wordlen, aux, sizeof(uint16_t));
                wordlen = htons(wordlen);
                if (debug)
                    ast_debug(4, "wordlen (property description) = %d\n", wordlen);
                if (wordlen > (len - count))
                {
                    ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                    return -1;
                }
                aux += 2;
                count += 2;
                amf_get_string(description, aux, wordlen);
                aux += wordlen;
                count += wordlen;
                /* next object is a property or an object
                 * end */
                context = AMF_PARSE_STRINGLEN;
                break;
            default:
                if (debug)
                    ast_debug(4, "In default, context = %d\n", context);
                count++;
        }
    }

    if (!strcmp(level, "status"))
    {
        res = RTMP_REPLY_CONNECT;
    }
    else if (*result != 0)
    {
        res = RTMP_REPLY_CREATESTREAM;
    }
    if (debug)
    {
        ast_debug(4, "result = %lf\n", *result);
        ast_debug(4, "level= %s\n", level);
        ast_debug(4, "code= %s\n", code);
        ast_debug(4, "description= %s\n", description);
    }

    return res;
}

static char * getAmfTypeName(int type)
{
    static char nameType[AMF_TYPE_AMF3_OBJECT+1][20] = {"NUMBER",
            "BOOLEAN",
            "STRING",
            "OBJECT",
            "MOVIECLIP",   //      0x04
            "NULL",        //      0x05
            "UNDEFINED",   //      0x06
            "REFERENCE",   //      0x07
            "MIXED_ARRAY", //      0x08
            "OBJECT_END",  //      0x09
            "ARRAY",       //      0x0A
            "DATE",        //      0x0B
            "LONG_STRING", //      0x0C
            "UNSUPPORTED", //      0x0D
            "RECORDSET",   //      0x0E
            "XML",         //      0x0F
            "CLASS_OBJECT",//      0x10
            "AMF3_OBJECT", //      0x11
            "Unknown"};

    if (type < 0 || type > AMF_TYPE_AMF3_OBJECT) {
        return nameType[AMF_TYPE_AMF3_OBJECT+1];
    }
    else {
        return nameType[type];
    }
}


#define SIZE_MAX_VALUE  1000

/** \brief Parse AMF reply from server
 *
 *  +----------------+---------+---------------------------------------+
 *  | Field Name     | Type    | Description                           |
 *  +--------------- +---------+---------------------------------------+
 *  | Command Name   | String  | Name of the command. Set to “connect”.|
 *  +----------------+---------+---------------------------------------+
 *  | Transaction ID | Number  | Always set to 1.                      |
 *  +----------------+---------+---------------------------------------+
 *  | Command Object | Object  | Command information object which has  |
 *  |                |         | the name-value pairs.                 |
 *  +----------------+---------+---------------------------------------+
 *  | Optional User  | Object  | Any optional information              |
 *  | Arguements     |         |                                       |
 *  +----------------+---------+---------------------------------------+
 */
static int amf_parse_connect_message(double *id, char *user, char *password,
        char *name, char *amf, size_t len, int *audioCodecDetected, char *flashVer,
        char *tcurl)
{
    int res = (-1);
    char *aux = NULL;
    int count = 0;
    int context = AMF_PARSE_TYPE;
    uint16_t wordlen = 0;
    char string[SIZE_MAX_VALUE];
    char objectValue[SIZE_MAX_VALUE];
    double result;
    int detectFlashPhone = 0;
    int paramNum = 0;
    int oldVersDetected = 0;

    memset(string, '\0', 256);

    if (!amf)
    {
        ast_log(LOG_WARNING, "Failed to parse AMF message\n");
        return res;
    }
    ast_debug(5, "Parsing 'connect' command object\n");
    aux = amf;
    res = RTMP_REPLY_CONNECT;
    //ast_debug(4, "%02X %02X %02X %02X %02X %02X %02X %02X\n", *aux,*(aux+1),*(aux+2),*(aux+3),*(aux+4),*(aux+5),*(aux+6),*(aux+7));

    /*
    // Get CMD
    context = amf_get_type(aux);
    aux++;count++;
    if (context == AMF_PARSE_STRINGVAL) {
        amf_get_property_connect(string, aux, wordlen);
        ast_debug(4, "Command : %s\n", string);
        if (strcmp(string, "connect")) {
            ast_debug(0, "It's should be 'connect' => '%s' !!\n", string);
        }
        aux += wordlen;
        count += wordlen;
     */
    // Get TRansaction ID
    context = amf_get_type(aux);
    aux++;
    count++;
    context = amf_get_number(id, aux);
    if (debug)
        ast_debug(4, "Id : %lf\n", *id);
    aux += sizeof(double);
    count += sizeof(double);

    // Get Start of object
    if (*aux == 0x3)
    {
        aux++;
        count++;
        if (debug)
            ast_debug(4, "Start parsing command object\n");

        /* Parse object
         *  Object is compose by :
         *      Key (string)    |       value
         *        16bits size   |  type (8bits) + (lg) + value
         */
        while (count < len)
        {
            memset(objectValue, '\0', SIZE_MAX_VALUE);
            memset(string, '\0', SIZE_MAX_VALUE);

            // Get KEY length
            wordlen = 0;
            memcpy(&wordlen, aux, sizeof(uint16_t));
            wordlen = htons(wordlen);
            if (debug)
                ast_debug(4, "key size = %d (count %d/%d)\n", wordlen, count, len);
            aux += 2;
            count += 2;

            if (mSupportCnxParseOldVersion)
            {
                /*
                 * Workaround to support old&new parsing !
                 *
                 * New client version
                 *  [00c0]   00 00 00 00 0E 6F 62 6A   65 63 74 45 6E 63 6F 64   .....obj ectEncod
                 *  [00d0]   69 6E 67 00 00 00 80 3F   10 00 00 00 17 00 09 02   ing..... ........
                 *  [00e0]   00 07 67 61 6C 61 78 79   33 02 00 07 61 7A 65 72   ..galaxy 3...azer
                 *
                 * OLD client version
                 *  [00c0]   00 00 00 00 0E 6F 62 6A   65 63 74 45 6E 63 6F 64   .....obj ectEncod
                 *  [00d0]   69 6E 67 00 00 00 00 00   00 00 00 00 17 00 09 02   ing..... ........
                 *  [00e0]   00 07 67 61 6C 61 78 79   33 02 00 07 61 7A 65 72   ..galaxy 3...azer
                 */
                if (debug) ast_debug(9, "wdlen=%d rest=%d, aux: %02X %02X %02X %02X\n",
                        wordlen, (len-count), aux[0], aux[1], aux[2], aux[3]);
                if (wordlen > (len-count) && aux[0]==9 && aux[1]==2)
                {
                    wordlen=0;
                    oldVersDetected = 1;
                    ast_log(LOG_WARNING, "old version connect detected\n");
                }
            }
            // Check if it's the end
            if (wordlen != 0)
            {
                // Get KEY value
                amf_get_property_connect(string, aux, wordlen);
                if (debug)
                    ast_debug(4, "object key : (%d)%s\n", wordlen, string);
                aux += wordlen;
                count += wordlen;

                // Get Value type
                context = *aux;
                aux++;
                count++;
                if (debug)
                    ast_debug(4, "object type : %d (%s)\n", context, getAmfTypeName(context));


                // Workaround to support old&new parsing !
                if (mSupportCnxParseOldVersion)
                {
                    // Erase aux in case!
                    if (debug) ast_debug(2, "wdlen=%d rest=%d, aux: %02X %02X\n",
                            wordlen, (len-count), aux[10], aux[11]);
                    // 9=END tag 2=string
                    if (!strncmp(string, "objectEncoding", 14) && context != 0 && aux[10]==9 && aux[11]==2 )
                    {
                        context = AMF_TYPE_NUMBER;
                        oldVersDetected = 1;
                        ast_log(LOG_WARNING, "old version connect detected\n");
                    }
                }

                switch (context)
                {
                    case AMF_TYPE_STRING:
                        wordlen = 0;
                        memcpy(&wordlen, aux, sizeof(uint16_t));
                        wordlen = htons(wordlen);
                        if (debug)
                            ast_debug(5, "object size = %d\n", wordlen);
                        aux += 2;
                        count += 2;
                        if (wordlen > 0)
                        {
                            amf_get_property_connect(objectValue, aux, wordlen);
                            if (debug)
                                ast_debug(4, "object value (str) : %s\n", objectValue);
                            aux += wordlen;
                            count += wordlen;
                        }
                        break;
                    case AMF_TYPE_NUMBER:
                        //memcpy(&wordlen, aux, sizeof(uint16_t));
                        amf_get_number(&result, aux);
                        if (debug)
                            ast_debug(4, "object value (num)  : %lf\n", result);
                        aux += sizeof(double);
                        count += sizeof(double);
                        break;
                    case AMF_TYPE_BOOLEAN:
                        if (debug)
                            ast_debug(4, "object value (bool) : %d\n", *aux);
                        aux++;
                        count++;
                        break;
                    case AMF_TYPE_NULL:
                        if (debug)
                            ast_debug(4, "object null\n");
                        break;
                    case AMF_TYPE_UNDEFINED:
                        if (debug)
                            ast_debug(4, "object undefined\n");
                        break;
                    default:
                        ast_log(LOG_WARNING, "Unsupported type %Xh\n", context);
                        break;
                }                       //eof switch

                // Treat key
                if (!strncmp(string, "audioCodecs", strlen("audioCodecs")))
                {
                    if (((int)result) & RTMP_AUDIO_CODEC_SUPPORTED)
                    {
                        *audioCodecDetected = (int)result;
                        if (debug)
                            ast_debug(4, "  set audioCodecDetected to %Xh\n",
                                    *audioCodecDetected);
                    }
                }
                else if (!strncmp(string, "flashVer", strlen("flashVer")))
                {
                    strncpy(flashVer, objectValue, wordlen);
                    if (debug)
                        ast_debug(4, "  flashver : %s\n", flashVer);
                }
                else if (!strncmp(string, "tcUrl", strlen("tcUrl")))
                {
                    strncpy(tcurl, objectValue, wordlen);
                    if (debug)
                        ast_debug(4, "  url : %s\n", tcurl);
                }
                else if (!strncmp(string, "swfUrl", strlen("swfUrl")))
                {
                    // Fix SPEEX for FlashPhone
                    // We consider that a FlashPhone has a swf name
                    if (strlen(objectValue) != 0)
                    {
                        detectFlashPhone = 1;
                    }
                }

            }
            else
            {
                if (debug)
                    ast_debug(4, "key size null\n");
                // Check the end tag
                if (*aux == 0x09)
                {
                    if (debug)
                        ast_debug(4, "tag END\n");
                    break;
                }
            }                         // eof key size null
        }                           // eof of while
    }
    else
    {
        ast_log(LOG_WARNING,
                "CONNECT badly formatted. We should have 03h instead of %02Xh\n", *aux);
        res = -1;
    }
    /*    }
    else
    {
        ast_debug(0, "CONNECT badly formatted. It should start with %02Xh type instead of %02Xh", AMF_PARSE_STRINGVAL, context);
        res=-1;
    } */

    if (res >= 0)
    {
        // Check if we have PARAMS: USER / PASSWORD / NAME
        paramNum = 0;
        aux++;
        count++;
        if (debug)  ast_debug(4, "Parse 'connect' params\n");
        while (count < len)
        {
            int haveParam = 0;

            // Get Value type
            context = *aux;
            aux++;
            count++;
            paramNum++;
            if (debug) ast_debug(9, "treat param %d context %Xh count %d\n", paramNum, context, count);
            switch (context)
            {
                case AMF_TYPE_STRING:
                    wordlen = 0;
                    memcpy(&wordlen, aux, sizeof(uint16_t));
                    wordlen = htons(wordlen);
                    if (debug)
                        ast_debug(4, "param %d size = %d\n", paramNum, wordlen);
                    aux += 2;
                    count += 2;
                    if (wordlen > 0)
                    {
                        amf_get_property_connect(objectValue, aux, wordlen);
                        if (debug)
                            ast_debug(4, "param %d (str) : %s\n", paramNum, objectValue);
                        aux += wordlen;
                        count += wordlen;
                        haveParam = 1;
                    }
                    break;
                case AMF_TYPE_NUMBER:
                    ast_debug(9, "dbgyg:NUMBER oldVersDetect=%d aux[1]=%Xh\n", oldVersDetected, aux[1]);
                    if ((count+sizeof(double) > len) ||
                            (oldVersDetected && aux[1]==9) )
                    {
                        aux++;
                        count++;
                    }
                    else {
                        //memcpy(&wordlen, aux, sizeof(uint16_t));
                        amf_get_number(&result, aux);
                        if (debug)
                            ast_debug(4, "param %d value (num)  : %lf\n", paramNum, result);
                        aux += sizeof(double);
                        count += sizeof(double);
                        haveParam = 1;
                    }
                    break;
                case AMF_TYPE_BOOLEAN:
                    if (debug)
                        ast_debug(4, "param %d value (bool) : %d\n", paramNum, *aux);
                    aux++;
                    count++;
                    haveParam = 1;
                    break;
                case AMF_TYPE_NULL:
                    if (debug)
                        ast_debug(4, "End frame: count %d len %d\n", count, len);
                    break;
                default:
                    ast_log(LOG_WARNING, "Unsupported type %Xh for param %d\n", context,
                            paramNum);
                    break;
            } //eof switch

            // If we have a param, aff
            if (haveParam)
            {
                switch (paramNum)
                {
                    case 1:              // First param is USER
                        strncpy(user, objectValue, wordlen);
                        break;
                    case 2:              // Second param is PASSWORD
                        strncpy(password, objectValue, wordlen);
                        break;
                    case 3:              // Third param is Display NAME
                        strncpy(name, objectValue, wordlen);
                        break;
                }
            }
        }//Eof while count

        if (detectFlashPhone)
        {
            // JYG: c'est un flash phone => on set le flag pour savoir le type de codec a sauvegarder
            *audioCodecDetected = RTMP_AUDIO_CODEC_SPEEX;
            if (debug)
                ast_debug(4,
                        "FlashPhone detected => set audioCodecDetected to SPEEX (%d)\n",
                        *audioCodecDetected);
        }
    } // eof res>0
    return res;


}



/** \brief Parse AMF reply from server
 */
static int amf_parse_connect(double *id, char *user, char *password, char *name,
        char *amf, size_t len, int *audioCodecDetected, char *flashVer, char *tcurl)
{
    int res = (-1);
    char *aux = NULL;
    int count = 0;
    int context = AMF_PARSE_TYPE;
    uint16_t wordlen = 0;
    char string[1000];
    double result;

    memset(string, '\0', 256);

    if (!amf)
    {
        ast_log(LOG_WARNING, "Failed to parse AMF message\n");
        return res;
    }

    aux = amf;

    res = RTMP_REPLY_CONNECT;

    while (count < len)
    {
        if (debug)
            ast_debug(8, "context = %d %d %d\n", context, count, len);
        switch (context)
        {
            case AMF_PARSE_TYPE:
                context = amf_get_type(aux);
                aux++;
                count++;
                break;
            case AMF_PARSE_STRINGLEN:
                /* string length is 2-bytes long */
                wordlen = 0;
                memcpy(&wordlen, aux, sizeof(uint16_t));
                wordlen = htons(wordlen);
                if (debug)
                    ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                aux += 2;
                count += 2;
                context = AMF_PARSE_STRINGVAL;
                break;
            case AMF_PARSE_STRINGVAL:
                context = amf_get_property_connect(string, aux, wordlen);
                if (debug)
                    ast_debug(4, "string : %s\n", string);

                /*
                 * JYG: Le parsing du connect est route dans une autre fct - l'actuel n'est pas bon
                 *      Mais cette mm fct est utilisee pour parser d'autre message => on garde ce parsing pour l'instant
                 */
                if (!strcmp(string, "connect"))
                {
                    aux += wordlen;
                    count += wordlen;
                    // len - TLV
                    res =
                            amf_parse_connect_message(id, user, password, name, aux,
                                    len - wordlen - 3, audioCodecDetected, flashVer, tcurl);
                    return res;
                }
                else if (!strcmp(string, "initStream"))
                    res = RTMP_NOREPLY;
                else if (!strcmp(string, "releaseStream"))
                    res = RTMP_NOREPLY;
                else if (!strcmp(string, "FCPublish"))
                    res = RTMP_NOREPLY;
                else if (!strcmp(string, "FCUnpublish"))
                    res = RTMP_NOREPLY;
                aux += wordlen;
                count += wordlen;
                break;
            case AMF_PARSE_NUMBER:
                context = amf_get_number(id, aux);
                if (debug)
                    ast_debug(4, "id : %lf\n", *id);
                aux += sizeof(double);
                count += sizeof(double);
                break;
            case AMF_PARSE_APP:
                context = amf_get_type(aux);
                aux++;
                count++;
                wordlen = 0;
                memcpy(&wordlen, aux, sizeof(uint16_t));
                wordlen = htons(wordlen);
                if (debug)
                    ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                if (wordlen > (len - count))
                {
                    ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                    return -1;
                }
                aux += 2;
                count += 2;
                context = amf_get_string(user, aux, wordlen);
                if (debug)
                    ast_debug(4, "app : %s\n", string);
                aux += wordlen;
                count += wordlen;
                context = AMF_PARSE_STRINGLEN;
                break;
            case AMF_PARSE_FLASHVER:
                context = amf_get_type(aux);
                aux++;
                count++;
                wordlen = 0;
                memcpy(&wordlen, aux, sizeof(uint16_t));
                wordlen = htons(wordlen);
                if (debug)
                    ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                if (wordlen > (len - count))
                {
                    ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                    return -1;
                }
                aux += 2;
                count += 2;
                context = amf_get_string(flashVer, aux, wordlen);
                if (debug)
                    ast_debug(4, "FlashVer : %s\n", flashVer);
                aux += wordlen;
                count += wordlen;
                context = AMF_PARSE_STRINGLEN;
                break;
            case AMF_PARSE_SWFURL:
                context = *aux;         //amf_get_type(aux);
                aux++;
                count++;
                if (context == AMF_TYPE_STRING)
                {
                    wordlen = 0;
                    memcpy(&wordlen, aux, sizeof(uint16_t));
                    wordlen = htons(wordlen);
                    if (debug)
                        ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                    if (wordlen > (len - count))
                    {
                        ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                        return -1;
                    }
                    aux += 2;
                    count += 2;
                    context = amf_get_string(string, aux, wordlen);
                    if (debug)
                        ast_debug(4, "SWFURL : %s\n", string);
                    aux += wordlen;
                    count += wordlen;
                }
                context = AMF_PARSE_STRINGLEN;
                // JYG: c'est un flash phone => on set le flag pour savoir le type de codec a sauvegarder
                *audioCodecDetected = RTMP_AUDIO_CODEC_SPEEX;
                if (debug)
                    ast_debug(4, "swfUrl found => set audioCodecDetected to SPEEX (%d)\n",
                            *audioCodecDetected);

                break;
            case AMF_PARSE_TCURL:
                context = amf_get_type(aux);
                aux++;
                count++;
                wordlen = 0;
                memcpy(&wordlen, aux, sizeof(uint16_t));
                wordlen = htons(wordlen);
                if (debug)
                    ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                if (wordlen > (len - count))
                {
                    ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                    return -1;
                }
                aux += 2;
                count += 2;
                context = amf_get_string(tcurl, aux, wordlen);
                if (debug)
                    ast_debug(4, "TCURL : %s\n", tcurl);
                aux += wordlen;
                count += wordlen;
                context = AMF_PARSE_STRINGLEN;
                break;
            case AMF_PARSE_FPAD:
                context = amf_get_type(aux);
                aux++;
                count++;
                //memcpy(&wordlen, aux, sizeof(uint16_t));
                wordlen = *aux;
                if (debug)
                    ast_debug(4, "fpad (boolean) = %d\n", wordlen);
                aux++;
                count++;
                context = AMF_PARSE_STRINGLEN;
                break;
            case AMF_PARSE_CAPABILITIES:
                context = amf_get_type(aux);
                aux++;
                count++;
                wordlen = 0;
                memcpy(&wordlen, aux, sizeof(uint16_t));
                context = amf_get_number(&result, aux);
                if (debug)
                    ast_debug(4, "capabilities : %lf\n", result);
                aux += sizeof(double);
                count += sizeof(double);
                context = AMF_PARSE_STRINGLEN;
                break;
            case AMF_PARSE_AUDIOCODECS:
                context = amf_get_type(aux);        aux++;
                count++;
                wordlen = 0;
                memcpy(&wordlen, aux, sizeof(uint16_t));
                context = amf_get_number(&result, aux);
                if (debug)
                    ast_debug(4, "audiocodec : %lf\n", result);
                {
                    int value = (int)result;
                    if (value & RTMP_AUDIO_CODEC_SUPPORTED)
                    {
                        *audioCodecDetected = value;
                        if (debug)
                            ast_debug(4, "set audioCodecDetected to %Xh\n",
                                    *audioCodecDetected);
                    }
                }

                aux += sizeof(double);
                count += sizeof(double);
                context = AMF_PARSE_STRINGLEN;
                break;
            case AMF_PARSE_VIDEOCODECS:
                context = amf_get_type(aux);
                aux++;
                count++;
                wordlen = 0;
                memcpy(&wordlen, aux, sizeof(uint16_t));
                context = amf_get_number(&result, aux);
                if (debug)
                    ast_debug(4, "videocodecs : %lf\n", result);
                aux += sizeof(double);
                count += sizeof(double);
                context = AMF_PARSE_STRINGLEN;
                break;
            case AMF_PARSE_VIDEOFUNCTION:
                context = amf_get_type(aux);
                aux++;
                count++;
                memcpy(&wordlen, aux, sizeof(uint16_t));
                context = amf_get_number(&result, aux);
                if (debug)
                    ast_debug(4, "videoFunction : %lf\n", result);
                aux += sizeof(double);
                count += sizeof(double);
                context = AMF_PARSE_STRINGLEN;
                break;
            case AMF_PARSE_PAGEURL:
                context = *aux;         //amf_get_type(aux);
                aux++;
                count++;
                if (context == AMF_TYPE_STRING)
                {
                    memcpy(&wordlen, aux, sizeof(uint16_t));
                    wordlen = htons(wordlen);
                    if (debug)
                        ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                    if (wordlen > (len - count))
                    {
                        ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                        return -1;
                    }
                    aux += 2;
                    count += 2;
                    if (wordlen < sizeof(string))
                        context = amf_get_string(string, aux, wordlen);
                    if (debug)
                        ast_debug(4, "AMF_PARSE_TCURL : %s\n", string);
                    aux += wordlen;
                    count += wordlen;
                }
                context = AMF_PARSE_STRINGLEN;
                break;
            case AMF_PARSE_OBJECTENCODING:
                //context = amf_get_type(aux);
                if (debug)
                    ast_debug(4, "objectEncoding : \n");
                //aux++;
                //count++;
                aux += 12;
                count += 12;

                context = amf_get_type(aux);
                aux++;
                count++;

                ast_debug(4, "Parse user context %d\n", context);

                if (context == AMF_PARSE_STRINGLEN)
                {
                    ast_debug(4, "Parse user\n");

                    memcpy(&wordlen, aux, sizeof(uint16_t));
                    wordlen = htons(wordlen);
                    if (debug)
                        ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                    if (wordlen > (len - count))
                    {
                        ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                        return -1;
                    }
                    aux += 2;
                    count += 2;
                    context = amf_get_string(user, aux, wordlen);
                    if (debug)
                        ast_debug(4, "user : %s\n", user);
                    aux += wordlen;
                    count += wordlen;
                }

                context = amf_get_type(aux);
                aux++;
                count++;

                ast_debug(4, "Parse password context %d\n", context);

                if (context == AMF_PARSE_STRINGLEN)
                {
                    ast_debug(4, "Parse password\n");

                    memcpy(&wordlen, aux, sizeof(uint16_t));
                    wordlen = htons(wordlen);
                    if (debug)
                        ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                    if (wordlen > (len - count))
                    {
                        ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                        return -1;
                    }
                    aux += 2;
                    count += 2;
                    context = amf_get_string(password, aux, wordlen);
                    if (debug)
                        ast_debug(4, "password : %s\n", password);
                    aux += wordlen;
                    count += wordlen;
                }

                context = amf_get_type(aux);
                aux++;
                count++;
                // JYG check if we have a string which contain name
                if (context == AMF_PARSE_STRINGLEN)
                {
                    ast_debug(4, "Parse name\n");


                    memcpy(&wordlen, aux, sizeof(uint16_t));
                    wordlen = htons(wordlen);
                    if (debug)
                        ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                    if (wordlen > (len - count))
                    {
                        ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                        return -1;
                    }
                    aux += 2;
                    count += 2;
                    context = amf_get_string(name, aux, wordlen);
                    if (debug)
                        ast_debug(4, "name : %s\n", name);
                    aux += wordlen;
                    count += wordlen;

                    context = AMF_PARSE_STRINGLEN;
                }

                res = RTMP_REPLY_CONNECT;
                break;

            case AMF_PARSE_RESULT:
                context = amf_get_type(aux);
                if (debug)
                    ast_debug(6, "context : %d\n", context);
                aux++;
                count++;
                //memcpy(&wordlen, aux, sizeof(uint16_t));
                context = amf_get_number(&result, aux);
                if (debug)
                    ast_debug(4, "double : %f\n", result);
                *id = result;
                aux += sizeof(double);
                count += sizeof(double);
                context = AMF_PARSE_STRINGLEN;

                res = RTMP_REPLY_RESULT;
                count = len;
                break;

            case AMF_PARSE_CREATESTREAM:
                context = amf_get_type(aux);
                if (debug)
                    ast_debug(6, "context : %d\n", context);
                aux++;
                count++;
                //memcpy(&wordlen, aux, sizeof(uint16_t));
                context = amf_get_number(&result, aux);
                if (debug)
                    ast_debug(4, "connectid : %f\n", result);
                *id = result;
                aux += sizeof(double);
                count += sizeof(double);
                context = AMF_PARSE_STRINGLEN;

                res = RTMP_REPLY_CREATESTREAM;
                count = count + (len - count);
                aux = aux + (len - count);
                break;

            case AMF_PARSE_DELETESTREAM:
                context = amf_get_type(aux);
                if (debug)
                    ast_debug(6, "context : %d\n", context);
                aux++;
                count++;
                //memcpy(&wordlen, aux, sizeof(uint16_t));
                context = amf_get_number(&result, aux);
                if (debug)
                    ast_debug(4, "connectid : %f\n", result);
                *id = result;
                aux += sizeof(double);
                count += sizeof(double);

                context = amf_get_type(aux);
                if (debug)
                    ast_debug(6, "context : %d\n", context);
                aux++;
                count++;

                context = amf_get_number(&result, aux);
                if (debug)
                    ast_debug(4, "streamid : %f\n", result);
                *id = result;
                aux += sizeof(double);
                count += sizeof(double);

                context = AMF_PARSE_STRINGLEN;

                res = RTMP_REPLY_DELETESTREAM;
                count = count + (len - count);
                aux = aux + (len - count);
                break;

            case AMF_PARSE_INVITE:
                context = amf_get_type(aux);
                if (debug)
                    ast_debug(6, "context : %d\n", context);
                aux++;
                count++;
                context = amf_get_number(&result, aux);
                if (debug)
                    ast_debug(4, "connectid : %f\n", result);
                *id = result;
                aux += sizeof(double);
                count += sizeof(double);

                context = amf_get_type(aux);
                aux++;
                count++;

                context = amf_get_type(aux);
                aux++;
                count++;
                memcpy(&wordlen, aux, sizeof(uint16_t));
                wordlen = htons(wordlen);
                if (debug)
                    ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                if (wordlen > (len - count))
                {
                    ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                    return -1;
                }
                aux += 2;
                count += 2;
                context = amf_get_string(user, aux, wordlen);
                if (debug)
                    ast_debug(4, "number called : %s\n", user);
                aux += wordlen;
                count += wordlen;

                if (count < len)
                {
                    context = amf_get_type(aux);
                    aux++;
                    count++;
                    if (context == AMF_PARSE_STRINGLEN)
                    {
                        memcpy(&wordlen, aux, sizeof(uint16_t));
                        wordlen = htons(wordlen);
                        if (debug)
                            ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                        if (wordlen > (len - count))
                        {
                            ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen,
                                    len - count);
                            return -1;
                        }
                        aux += 2;
                        count += 2;
                        context = amf_get_string(password, aux, wordlen);
                        if (debug)
                            ast_debug(4, "param : %s\n", password);
                        aux += wordlen;
                        count += wordlen;
                    }
                    else if (context == AMF_PARSE_TYPE)
                    {
                    }
                    else
                    {
                        ast_log(LOG_WARNING, "bad type %d\n", context);
                        return -1;
                    }
                }

                res = RTMP_REPLY_INVITE;
                count = count + (len - count);
                aux = aux + (len - count);
                break;

            case AMF_PARSE_ACCEPT:
                context = amf_get_type(aux);
                if (debug)
                    ast_debug(6, "context : %d\n", context);
                aux++;
                count++;
                context = amf_get_number(&result, aux);
                if (debug)
                    ast_debug(4, "connectid : %f\n", result);
                *id = result;
                aux += sizeof(double);
                count += sizeof(double);

                context = amf_get_type(aux);
                aux++;
                count++;

                res = RTMP_REPLY_ACCEPT;
                count = count + (len - count);
                aux = aux + (len - count);
                break;

            case AMF_PARSE_REJECT:
                context = amf_get_type(aux);
                if (debug)
                    ast_debug(6, "context : %d\n", context);
                aux++;
                count++;
                context = amf_get_number(&result, aux);
                if (debug)
                    ast_debug(4, "connectid : %f\n", result);
                *id = result;
                aux += sizeof(double);
                count += sizeof(double);

                context = amf_get_type(aux);
                aux++;
                count++;

                res = RTMP_REPLY_REJECT;
                count = count + (len - count);
                aux = aux + (len - count);
                break;

            case AMF_PARSE_BYE:
                context = amf_get_type(aux);
                if (debug)
                    ast_debug(6, "context : %d\n", context);
                aux++;
                count++;
                context = amf_get_number(&result, aux);
                if (debug)
                    ast_debug(4, "connectid : %f\n", result);
                *id = result;
                aux += sizeof(double);
                count += sizeof(double);

                context = amf_get_type(aux);
                aux++;
                count++;

                res = RTMP_REPLY_BYE;
                count = count + (len - count);
                aux = aux + (len - count);
                break;

            default:
                if (debug)
                    ast_debug(6, "In default, context = %d\n", context);
                count++;
        }
    }

    //if (!strcmp(level, "status")) {
    //  res = RTMP_REPLY_CONNECT;
    //} else if (*result != 0) {
    //  res = RTMP_REPLY_CREATESTREAM;
    //}


    //ast_debug(4, "user= %s\n", user);
    //ast_debug(4, "password= %s\n", password);
    //ast_debug(4, "name= %s\n", name);

    return res;
}

/** \brief Parse AMF reply from server
 */
static int amf_parse_control(double *id, char *name, char *amf, size_t len)
{
    int res = (-1);
    char *aux = NULL;
    int count = 0;
    int context = AMF_PARSE_TYPE;
    uint16_t wordlen = 0;
    char string[256];
    double result;

    memset(string, '\0', 256);


    if (!amf)
    {
        ast_log(LOG_WARNING, "Failed to parse AMF message\n");
        return res;
    }

    aux = amf;

    res = RTMP_REPLY_PUBLISH;

    while (count < len)
    {
        if (debug)
            ast_debug(8, "context = %d %d %d\n", context, count, len);
        switch (context)
        {
            case AMF_PARSE_TYPE:
                context = amf_get_type(aux);
                aux++;
                count++;
                break;
            case AMF_PARSE_STRINGLEN:
                /* string length is 2-bytes long */
                memcpy(&wordlen, aux, sizeof(uint16_t));
                wordlen = htons(wordlen);
                if (debug)
                    ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                aux += 2;
                count += 2;
                context = AMF_PARSE_STRINGVAL;
                break;
            case AMF_PARSE_STRINGVAL:
                context = amf_get_property_control(string, aux, wordlen);
                if (debug)
                    ast_debug(4, "string : %s\n", string);
                aux += wordlen;
                count += wordlen;
                break;
            case AMF_PARSE_NUMBER:
                context = amf_get_number(id, aux);
                if (debug)
                    ast_debug(4, "id : %lf\n", *id);
                aux += sizeof(double);
                count += sizeof(double);
                break;
            case AMF_PARSE_PUBLISH:
                context = amf_get_type(aux);
                I6DEBUG(3, NULL, "context : %d\n", context);
                aux++;
                count++;
                context = amf_get_number(&result, aux);
                I6DEBUG(3, NULL, "connectid : %f\n", result);
                *id = result;
                aux += sizeof(double);
                count += sizeof(double);
                context = AMF_PARSE_STRINGLEN;

                context = amf_get_type(aux);  // NULL
                aux++;
                count++;

                context = amf_get_type(aux);
                aux++;
                count++;
                memcpy(&wordlen, aux, sizeof(uint16_t));
                wordlen = htons(wordlen);
                I6DEBUG(3, NULL, "wordlen (stringlen) = %d\n", wordlen);
                if (wordlen > (len - count))
                {
                    ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                    return -1;
                }
                aux += 2;
                count += 2;
                context = amf_get_string(name, aux, wordlen);
                I6DEBUG(3, NULL, "name : %s\n", name);
                aux += wordlen;
                count += wordlen;

                res = RTMP_REPLY_PUBLISH;
                count = count + (len - count);
                aux = aux + (len - count);
                break;

            case AMF_PARSE_PLAY:
                context = amf_get_type(aux);
                I6DEBUG(3, NULL, "context : %d\n", context);
                aux++;
                count++;
                context = amf_get_number(&result, aux);
                I6DEBUG(3, NULL, "connectid : %f\n", result);
                *id = result;
                aux += sizeof(double);
                count += sizeof(double);
                context = AMF_PARSE_STRINGLEN;

                context = amf_get_type(aux);  // NULL
                aux++;
                count++;

                context = amf_get_type(aux);
                aux++;
                count++;
                // JYG check if we have a string which contain name
                if (context == AMF_PARSE_STRINGLEN)
                {
                    memcpy(&wordlen, aux, sizeof(uint16_t));
                    wordlen = htons(wordlen);
                    I6DEBUG(3, NULL, "wordlen (stringlen) = %d\n", wordlen);
                    if (wordlen > (len - count))
                    {
                        ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                        return -1;
                    }
                    aux += 2;
                    count += 2;
                    context = amf_get_string(name, aux, wordlen);
                    I6DEBUG(3, NULL, "name : %s\n", name);
                    aux += wordlen;
                    count += wordlen;
                }

                res = RTMP_REPLY_PLAY;
                count = count + (len - count);
                aux = aux + (len - count);
                break;

            case AMF_PARSE_CLOSESTREAM:
                res = RTMP_REPLY_CLOSESTREAM;
                count = len;
                break;

            default:
                I6DEBUG(3, NULL, "In default, context = %d\n", context);
                count++;
        }
    }

    return res;
}

/** \brief Parse AMF reply from server
 */
static int amf_parse_command(char *command, char *text, char *amf, char *dstId,
        size_t len)
{
    int res = (-1);
    char *aux = NULL;
    int count = 0;
    int context = AMF_PARSE_TYPE;
    uint16_t wordlen;

    if (!amf)
    {
        ast_log(LOG_WARNING, "Failed to parse AMF message\n");
        return res;
    }

    *command = 0;
    *text = 0;
    *dstId = 0;

    aux = amf;

    res = RTMP_REPLY_DTMF;

    context = amf_get_type(aux);
    aux++;
    count++;

    memcpy(&wordlen, aux, sizeof(uint16_t));
    wordlen = htons(wordlen);
    if (debug)
        ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
    if (wordlen > len)
    {
        ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len);
        return -1;
    }
    aux += 2;
    count += 2;

    context = amf_get_string(command, aux, wordlen);
    if (debug)
        ast_debug(4, "command : %s\n", command);
    aux += wordlen;
    count += wordlen;

    if (count < len)
    {
        context = amf_get_type(aux);
        aux++;
        count++;
        if (context == AMF_PARSE_STRINGLEN)
        {
            memcpy(&wordlen, aux, sizeof(uint16_t));
            wordlen = htons(wordlen);
            if (debug)
                ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
            if (wordlen > (len - count))
            {
                ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                return -1;
            }
            aux += 2;
            count += 2;

            context = amf_get_string(text, aux, wordlen);
            aux += wordlen;
            count += wordlen;
        }

        // Check for dst in case of text (tchat)
        if (!strcmp(command, "text") && (count < len))
        {
            context = amf_get_type(aux);
            aux++;
            count++;

            if (context == AMF_PARSE_STRINGLEN)
            {
                memcpy(&wordlen, aux, sizeof(uint16_t));
                wordlen = htons(wordlen);
                if (debug)
                    ast_debug(4, "wordlen (stringlen) = %d\n", wordlen);
                if (wordlen > (len - count))
                {
                    ast_log(LOG_WARNING, "bad wordlen %d > %d\n", wordlen, len - count);
                    return -1;
                }
                aux += 2;
                count += 2;

                context = amf_get_string(dstId, aux, wordlen);
                aux += wordlen;
                count += wordlen;
            }
        }
    }
    else
    {
        if (debug)
            ast_debug(4, "No parameter!\n");
        *text = 0;
    }

    return res;
}

static int amf_get_type(char *buf)
{
    int res = (-1);
    uint8_t aux = (uint8_t) * buf;

    switch (aux)
    {
        case AMF_TYPE_BOOLEAN:
            res = AMF_PARSE_BOOLEAN;
            break;
        case AMF_TYPE_NUMBER:
            res = AMF_PARSE_NUMBER;
            break;
        case AMF_TYPE_STRING:
        case AMF_TYPE_OBJECT:
            res = AMF_PARSE_STRINGLEN;
            break;
        case AMF_TYPE_NULL:
            res = AMF_PARSE_TYPE;
            break;
        case AMF_TYPE_UNDEFINED:
            res = (-1);
            break;
        default:
            ast_log(LOG_WARNING, "Unknown type %d\n", aux);
            res = (-1);
    }
    if (debug)
        ast_debug(5, "type = %d\n", aux);

    return res;
}

static int amf_get_string(char *string, void *buffer, size_t length)
{
    int res = (-1);
    char aux[length+1];

    memset(aux, '\0', length+1);
    memcpy(aux, buffer, length);

    if (!strncmp(aux, "_result", strlen("_result")))
    {
        res = AMF_PARSE_DOUBLE_RESULT;
        ast_copy_string(string, "_result", strlen("_result") + 1);
        if (debug)
            ast_debug(6, "Found string _result\n");

    }
    else if (!strncmp(aux, "level", strlen("level")))
    {
        res = AMF_PARSE_PROPERTY_LEVEL;
        ast_copy_string(string, "level", strlen("level") + 1);
        if (debug)
            ast_debug(6, "Found string level\n");

    }
    else if (!strncmp(aux, "code", strlen("code")))
    {
        res = AMF_PARSE_PROPERTY_CODE;
        ast_copy_string(string, "code", strlen("code") + 1);
        if (debug)
            ast_debug(6, "Found string code\n");

    }
    else if (!strncmp(aux, "description", strlen("description")))
    {
        res = AMF_PARSE_PROPERTY_DESCRIPTION;
        ast_copy_string(string, "description", strlen("description") + 1);
        if (debug)
            ast_debug(6, "Found string description\n");

    }
    else if (!strncmp(aux, "connect", strlen("connect")))
    {
        res = AMF_PARSE_PROPERTY_DESCRIPTION;
        ast_copy_string(string, "connect", strlen("connect") + 1);
        if (debug)
            ast_debug(6, "Found string connect\n");
    }
    else if (!strncmp(aux, "onStatus", strlen("onStatus")))
    {
        res = AMF_PARSE_DOUBLE_RESULT;
        ast_copy_string(string, "onStatus", strlen("onStatus") + 1);
        if (debug)
            ast_debug(6, "Found string onStatus\n");
    }
    else
    {
        res = AMF_PARSE_STRING_VALUE;
        if (length)
        {
            ast_copy_string(string, aux, length + 1);
            if (debug)
                ast_debug(6, "Found %s\n", string);
        }
        else
        {
            if (debug)
                ast_debug(6, "Found empty string\n");
        }
    }

    return res;
}

static int amf_get_property(char *string, void *buffer, size_t length)
{
    int res = (-1);
    char aux[length];

    memset(aux, '\0', length);
    memcpy(aux, buffer, length);

    if (!strncmp(aux, "_result", strlen("_result")))
    {
        res = AMF_PARSE_DOUBLE_RESULT;
        ast_copy_string(string, "_result", strlen("_result") + 1);
        if (debug)
            ast_debug(6, "Found string _result\n");

    }
    else if (!strncmp(aux, "level", strlen("level")))
    {
        res = AMF_PARSE_PROPERTY_LEVEL;
        ast_copy_string(string, "level", strlen("level") + 1);
        if (debug)
            ast_debug(6, "Found string level\n");

    }
    else if (!strncmp(aux, "code", strlen("code")))
    {
        res = AMF_PARSE_PROPERTY_CODE;
        ast_copy_string(string, "code", strlen("code") + 1);
        if (debug)
            ast_debug(6, "Found string code\n");

    }
    else if (!strncmp(aux, "description", strlen("description")))
    {
        res = AMF_PARSE_PROPERTY_DESCRIPTION;
        ast_copy_string(string, "description", strlen("description") + 1);
        if (debug)
            ast_debug(6, "Found string description\n");

    }
    else if (!strncmp(aux, "connect", strlen("connect")))
    {
        res = AMF_PARSE_PROPERTY_DESCRIPTION;
        ast_copy_string(string, "connect", strlen("connect") + 1);
        if (debug)
            ast_debug(6, "Found string connect\n");
    }
    else
    {
        res = AMF_PARSE_STRING_VALUE;
        if (length)
        {
            ast_copy_string(string, aux, length + 1);
            if (debug)
                ast_debug(6, "Found %s\n", aux);
        }
        else
        {
            if (debug)
                ast_debug(6, "Found empty string\n");
        }
    }

    return res;
}

static int amf_get_property_connect(char *string, void *buffer, size_t length)
{
    int res = (-1);
    char aux[length+1];

    memset(aux, '\0', length+1);
    memcpy(aux, buffer, length);

    if (!strncmp(aux, "_result", strlen("_result")))
    {
        res = AMF_PARSE_RESULT;
        ast_copy_string(string, "_result", strlen("_result") + 1);
        if (debug)
            ast_debug(6, "Found string _result\n");
    }
    else if (!strncmp(aux, "createStream", strlen("createStream")))
    {
        res = AMF_PARSE_CREATESTREAM;
        ast_copy_string(string, "createStream", strlen("createStream") + 1);
        if (debug)
            ast_debug(6, "Found string createStream\n");
    }
    else if (!strncmp(aux, "deleteStream", strlen("deleteStream")))
    {
        res = AMF_PARSE_DELETESTREAM;
        ast_copy_string(string, "deleteStream", strlen("deleteStream") + 1);
        if (debug)
            ast_debug(6, "Found string deleteStream\n");
    }
    else if (!strncmp(aux, "invite", strlen("invite")))
    {
        res = AMF_PARSE_INVITE;
        ast_copy_string(string, "invite", strlen("invite") + 1);
        if (debug)
            ast_debug(6, "Found string invite\n");
    }
    else if (!strncmp(aux, "accept", strlen("accept")))
    {
        res = AMF_PARSE_ACCEPT;
        ast_copy_string(string, "accept", strlen("accept") + 1);
        if (debug)
            ast_debug(6, "Found string  accept\n");
    }
    else if (!strncmp(aux, "reject", strlen("reject")))
    {
        res = AMF_PARSE_REJECT;
        ast_copy_string(string, "reject", strlen("reject") + 1);
        if (debug)
            ast_debug(6, "Found string reject\n");
    }
    else if (!strncmp(aux, "bye", strlen("bye")))
    {
        res = AMF_PARSE_BYE;
        ast_copy_string(string, "bye", strlen("bye") + 1);
        if (debug)
            ast_debug(6, "Found string bye\n");
    }
    else if (!strncmp(aux, "app", strlen("app")))
    {
        res = AMF_PARSE_APP;
        ast_copy_string(string, "app", strlen("app") + 1);
        if (debug)
            ast_debug(6, "Found string app\n");
    }
    else if (!strncmp(aux, "flashVer", strlen("flashVer")))
    {
        res = AMF_PARSE_FLASHVER;
        ast_copy_string(string, "flashVer", strlen("flashVer") + 1);
        if (debug)
            ast_debug(6, "Found string flashVer\n");
    }
    else if (!strncmp(aux, "swfUrl", strlen("swfUrl")))
    {
        res = AMF_PARSE_SWFURL;
        ast_copy_string(string, "swfUrl", strlen("swfUrl") + 1);
        if (debug)
            ast_debug(6, "Found string swfUrl\n");
    }
    else if (!strncmp(aux, "tcUrl", strlen("tcUrl")))
    {
        res = AMF_PARSE_TCURL;
        ast_copy_string(string, "tcUrl", strlen("tcUrl") + 1);
        if (debug)
            ast_debug(6, "Found string tcUrl\n");
    }
    else if (!strncmp(aux, "fpad", strlen("fpad")))
    {
        res = AMF_PARSE_FPAD;
        ast_copy_string(string, "fpad", strlen("fpad") + 1);
        if (debug)
            ast_debug(6, "Found string fpad\n");
    }
    else if (!strncmp(aux, "capabilities", strlen("capabilities")))
    {
        res = AMF_PARSE_CAPABILITIES;
        ast_copy_string(string, "capabilities", strlen("capabilities") + 1);
        if (debug)
            ast_debug(6, "Found string capabilities\n");
    }
    else if (!strncmp(aux, "audioCodecs", strlen("audioCodecs")))
    {
        res = AMF_PARSE_AUDIOCODECS;
        ast_copy_string(string, "audioCodecs", strlen("audioCodecs") + 1);
        if (debug)
            ast_debug(6, "Found string audioCodecs\n");
    }
    else if (!strncmp(aux, "videoCodecs", strlen("videoCodecs")))
    {
        res = AMF_PARSE_VIDEOCODECS;
        ast_copy_string(string, "videoCodecs", strlen("videoCodecs") + 1);
        if (debug)
            ast_debug(2, "Found string videoCodecs\n");
    }
    else if (!strncmp(aux, "videoFunction", strlen("videoFunction")))
    {
        res = AMF_PARSE_VIDEOFUNCTION;
        ast_copy_string(string, "videoFunction", strlen("videoFunction") + 1);
        if (debug)
            ast_debug(6, "Found string videoFunction\n");
    }
    else if (!strncmp(aux, "pageUrl", strlen("pageUrl")))
    {
        res = AMF_PARSE_PAGEURL;
        ast_copy_string(string, "pageUrl", strlen("pageUrl") + 1);
        if (debug)
            ast_debug(6, "Found string pageUrl\n");
    }
    else if (!strncmp(aux, "objectEncoding", strlen("objectEncoding")))
    {
        res = AMF_PARSE_OBJECTENCODING;
        ast_copy_string(string, "objectEncoding", strlen("objectEncoding") + 1);
        if (debug)
            ast_debug(6, "Found string objectEncoding\n");
    }
    else if (!strncmp(aux, "connect", strlen("connect")))
    {
        res = AMF_PARSE_TYPE;
        ast_copy_string(string, "connect", strlen("connect") + 1);
        if (debug)
            ast_debug(6, "Found string connect\n");
    }
    else
    {
        res = AMF_PARSE_STRING_VALUE;
        if (length)
        {
            ast_copy_string(string, aux, length + 1);
            if (debug)
                ast_debug(6, "Found %s\n", aux);
        }
        else
        {
            if (debug)
                ast_debug(6, "Found empty string\n");
        }
    }

    return res;
}

static int amf_get_property_control(char *string, void *buffer, size_t length)
{
    int res = (-1);
    char aux[length+1];

    memset(aux, '\0', length+1);
    memcpy(aux, buffer, length);

    if (!strncmp(aux, "publish", strlen("publish")))
    {
        res = AMF_PARSE_PUBLISH;
        ast_copy_string(string, "publish", strlen("publish") + 1);
        if (debug)
            ast_debug(2, "Found string publish\n");
    }
    else if (!strncmp(aux, "play", strlen("play")))
    {
        res = AMF_PARSE_PLAY;
        ast_copy_string(string, "play", strlen("play") + 1);
        if (debug)
            ast_debug(2, "Found string play\n");
    }
    else if (!strncmp(aux, "closeStream", strlen("closeStream")))
    {
        res = AMF_PARSE_CLOSESTREAM;
        ast_copy_string(string, "closeStream", strlen("closeStream") + 1);
        if (debug)
            ast_debug(2, "Found string closeStream\n");
    }
    else
    {
        res = AMF_PARSE_STRING_VALUE;
        if (length)
        {
            ast_copy_string(string, aux, length + 1);
            if (debug)
                ast_debug(2, "Found %s\n", aux);
        }
        else
        {
            if (debug)
                ast_debug(2, "Found empty string\n");
        }
    }

    return res;
}

static int amf_get_number(double *number, void *amf)
{
    int res = (-1);
    int i;
    unsigned char *aux = (unsigned char *)number;
    unsigned char *src = amf + sizeof(double) - 1;
    //unsigned char *src = amf;

    if (!amf || !number)
    {
        ast_log(LOG_WARNING, "Cannot get AMF number\n");
        return 0;
    }

    /* copy the content of number in network byte order.
     * FIXME : do that if needed only */
    for (i = 0; i < sizeof(double); i++)
    {
        if (debug)
            ast_debug(8, "amf_get_number: Inserted %d (%02x)\n", *src, *src);
        memcpy(aux++, src--, 1);
        //memcpy(aux++, src++, 1);
    }

    if (debug)
        ast_debug(6, "number = %f\n", *number);

    /* reset parser */
    res = AMF_PARSE_TYPE;

    return res;
}

static int activate_channels(struct rtmp_client *client, int channelid,
        int range)
{
    int i;

    I6DEBUG(10, client, "Mutex lock 'streamlock'.\n");
    ast_mutex_lock(&streamslock);
    I6DEBUG(10, client, "Mutex locked 'streamlock'.\n");

    /* main RTMP channels (0 to 3) */
    if (channelid < 4)
    {
        client->streams[0]->isactive = 1;
        client->streams[1]->isactive = 1;
        client->streams[2]->isactive = 1;
        client->streams[3]->isactive = 1;
    }

    /* other RTMP channels */
    for (i = 0; i < range; i += 5)
    {
        client->streams[channelid + i + 0]->isactive = 1;
        client->streams[channelid + i + 1]->isactive = 1;
        client->streams[channelid + i + 2]->isactive = 1;
        client->streams[channelid + i + 3]->isactive = 1;
        client->streams[channelid + i + 4]->isactive = 1;
    }

    I6DEBUG(10, client, "Mutex unlock 'streamlock'.\n");
    ast_mutex_unlock(&streamslock);

    return 1;
}

static int desactivate_channels(struct rtmp_client *client, int channelid,
        int range)
{
    int i;

    I6DEBUG(10, client, "Mutex lock 'streamlock'.\n");
    ast_mutex_lock(&streamslock);
    I6DEBUG(10, client, "Mutex locked 'streamlock'.\n");

    /* main RTMP channels (0 to 3) */
    if (channelid < 4)
    {
        client->streams[0]->isactive = 0;
        client->streams[1]->isactive = 0;
        client->streams[2]->isactive = 0;
        client->streams[3]->isactive = 0;
    }

    /* other RTMP channels */
    for (i = 0; i < range; i += 5)
    {
        client->streams[channelid + i + 0]->isactive = 0;
        client->streams[channelid + i + 1]->isactive = 0;
        client->streams[channelid + i + 2]->isactive = 0;
        client->streams[channelid + i + 3]->isactive = 0;
        client->streams[channelid + i + 4]->isactive = 0;
    }

    I6DEBUG(10, client, "Mutex unlock 'streamlock'.\n");
    ast_mutex_unlock(&streamslock);

    return 1;
}

/*! \brief Find a name */
struct rtmp_client *rtmp_find_connection(const char *name)
{
        struct rtmp_threadinfo *th;
        struct ao2_iterator i;

        I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
        ast_mutex_lock(&rtmplock);
        I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n");

        i = ao2_iterator_init(threadt, 0);
        while ((th =
                ao2_t_iterator_next(&i,
                        "iterate through tcp threads for 'rtmp show ...'")))
        {
            if (th->client)
            {
                if (th->client->fd != (-1))
                    if (!strcmp(th->client->name, name))
                    {
                        ao2_t_ref(th, -1, "decrement ref from iterator");
                        ao2_iterator_destroy(&i);

                        ast_mutex_lock(&th->client->lock);

                        I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
                        ast_mutex_unlock(&rtmplock);
                        return th->client;
                    }
            }

            ao2_t_ref(th, -1, "decrement ref from iterator");
        }
        ao2_iterator_destroy(&i);

        I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
        ast_mutex_unlock(&rtmplock);

        return NULL;
}

static char *complete_rtmpuser(const char *line, const char *word, int pos,
        int state)
{
    int which = 0;
    struct rtmp_threadinfo *th;
    char *c = NULL;
    int wordlen = strlen(word);
    struct ao2_iterator i;
    char tmp[20];

    //ast_log(LOG_WARNING, "1 %s\n", word);

    if (word == NULL)
    {
        return NULL;
    }

    if (*word == 0)
    {
        return NULL;
    }

    if (pos != 3)
    {
        return NULL;
    }

    I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
    ast_mutex_lock(&rtmplock);
    I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n");

    i = ao2_iterator_init(threadt, 0);
    while ((th = ao2_t_iterator_next(&i, "iterate thru tcp thread")))
    {

        //ast_log(LOG_WARNING, ".\n");

        rtmp_pvt_lock(th);
        if (!strncasecmp(word, th->client->name, wordlen) && ++which > state)
        {
            c = ast_strdup(th->client->name);
            ao2_t_ref(th, -1, "Unref threadinfo");
            rtmp_pvt_unlock(th);
            //threads_unref(th, "drop ref in iterator loop break");
            break;
        }
        rtmp_pvt_unlock(th);
        //dialog_unref(th, "drop ref in iterator loop");

        ao2_t_ref(th, -1, "Unref threadinfo");
    }
    ao2_iterator_destroy(&i);

    if (c == NULL)
    {
        i = ao2_iterator_init(threadt, 0);
        while ((th = ao2_t_iterator_next(&i, "iterate thru tcp thread")))
        {

            //ast_log(LOG_WARNING, ".\n");

            rtmp_pvt_lock(th);

            sprintf(tmp, "RTMP/%p", th->client);
            //ast_log(LOG_WARNING, "! %s\n", tmp);

            if (!strncasecmp(word, tmp, wordlen) && ++which > state)
            {
                c = ast_strdup(tmp);
                rtmp_pvt_unlock(th);
                ao2_t_ref(th, -1, "Unref threadinfo");
                //threads_unref(th, "drop ref in iterator loop break");
                break;
            }
            rtmp_pvt_unlock(th);
            //dialog_unref(th, "drop ref in iterator loop");
            ao2_t_ref(th, -1, "Unref threadinfo");
        }
        ao2_iterator_destroy(&i);
    }

    I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
    ast_mutex_unlock(&rtmplock);

    return c;
}

/*! \brief return Yes or No depending on the argument.
 * This is used in many places in CLI command, having a function to generate
 * this helps maintaining a consistent output (and possibly emitting the
 * output in other languages, at some point).
 */
static const char *cli_yesno(int x)
{
    return x ? "Yes" : "No";
}

extern const char *ast_build_hostname;
extern const char *ast_build_kernel;
extern const char *ast_build_machine;
extern const char *ast_build_os;
extern const char *ast_build_date;
extern const char *ast_build_user;

/*! \brief CLI command "rtmp show version" */
static char *rtmp_show_version(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{

    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp show version";
            e->usage =
                    "Usage: rtmp show version\n" "       Dump the RTMP module version.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    if (a->argc != 3)
        return CLI_SHOWUSAGE;

    ast_cli(a->fd, "Version       : V%d.%d\n", version, subversion);

    ast_cli(a->fd, " CVS Revision : %s\n", "$Revision: 1.323 $");
#ifdef __TIMESTAMP__
    ast_cli(a->fd, " Source file  : %s\n", __TIMESTAMP__);
#endif
    ast_cli(a->fd, " Compilation  : %s\n", __DATE__);
    ast_cli(a->fd, "              : %s\n", __TIME__);

    ast_cli(a->fd, "Build with    :\n");

    ast_cli(a->fd, " Gcc          : V%d.%d\n", __GNUC__, __GNUC_MINOR__);
    ast_cli(a->fd, " Arch         : %d bits\n", __WORDSIZE);

#ifdef  __x86_64__
    ast_cli(a->fd, " Target       : %s\n", "x86_64");
#else
    ast_cli(a->fd, " Target       : %s\n", "i686");
#endif
#ifdef ASTERISK_VERSION
    ast_cli(a->fd, " Asterisk     : V%s\n", ASTERISK_VERSION);
#else
    ast_cli(a->fd, " Asterisk     : V%s\n", ast_get_version());
#endif

    ast_cli(a->fd, "              : by %s@%s\n",
            ast_build_user, ast_build_hostname);
    ast_cli(a->fd, "              : on %s/%s %s\n",
            ast_build_machine, ast_build_os, ast_build_date);

    generateKeyPair();

    return CLI_SUCCESS;
}

/*! \brief CLI command "rtmp show configuration" */
static char *rtmp_show_configuration(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    int realtimeusers = 0;

    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp show configuration";
            e->usage =
                    "Usage: rtmp show configuration\n"
                    "       Dump the RTMP module configuration.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    if (a->argc != 3)
        return CLI_SHOWUSAGE;

    if (realtimename[0])
        realtimeusers = ast_check_realtime(realtimename);


    //ast_cli(a->fd, "Port               : %d\n", rtmpport);
    //ast_cli(a->fd, "Application        : %s\n", application);

    ast_cli(a->fd, "Server name        : %s\n", rtmpserverstr);
    struct in_addr temp_addr;
    char buf[100];
    TCPTLS_SESSION_ADDRESS(rtmp_tcp_desc.local_address, temp_addr.s_addr);
    inet_ntop(AF_INET, &temp_addr, buf, sizeof(buf));

    ast_cli(a->fd, "Bind address       : %s:%d\n", buf,
            bindport);
    //
    if (bindport2 > 0)
    {
        TCPTLS_SESSION_ADDRESS(rtmp_tcp_desc.local_address, temp_addr.s_addr);
        inet_ntop(AF_INET, &temp_addr, buf, sizeof(buf));
        ast_cli(a->fd, "Bind address 2     : %s:%d\n", buf,
                bindport2);
    }

    if (rtmfpenable)
        ast_cli(a->fd, "RTMFP protocol     : %s\n", cli_yesno(videosupport));

    if (httpurl[0])
        ast_cli(a->fd, "HTTP URL           : %s\n", httpurl);

    ast_cli(a->fd, "Context            : %s\n", context);

    ast_cli(a->fd, "Video              : %s\n", cli_yesno(videosupport));
    ast_cli(a->fd, "Text               : %s\n", cli_yesno(textsupport));
    ast_cli(a->fd, "No Speex slience   : %s\n", cli_yesno(nospeexsilence));

    ast_cli(a->fd, "RTMP realtime      : %s (%s)\n", cli_yesno(realtimeusers),
            realtimename);

    ast_cli(a->fd, "Auto users         : %s\n", cli_yesno(autousers));
    ast_cli(a->fd, "Muliple users      : %s\n", cli_yesno(multipleusers));
    ast_cli(a->fd, "Last unique user   : %s\n", cli_yesno(lastuniqueuser));
    ast_cli(a->fd, "Hangup users       : %s\n", cli_yesno(hangupusers));

    ast_cli(a->fd, "TCP buffer         : %d\n", tcpbuffer);
    ast_cli(a->fd, "Max audio buffer   : %d\n", maxaudiobuffer);
    ast_cli(a->fd, "Max video buffer   : %d\n", maxvideobuffer);
    ast_cli(a->fd, "Max audio pipe     : %d\n", maxaudiopipe);
    ast_cli(a->fd, "Max video pipe     : %d\n", maxvideopipe);
    ast_cli(a->fd, "Chunks buffer      : %d\n", chunksbuffer);
    ast_cli(a->fd, "TCP Keepalive      : %d\n", tcpkeepalive);
    ast_cli(a->fd, "TCP NoDelay        : %s\n", cli_yesno(tcpnodelay));
    ast_cli(a->fd, "Antiburst          : %d\n", antiburst);
    ast_cli(a->fd, "Record FLV         : %s\n", cli_yesno(record_flv));
    ast_cli(a->fd, "Spy picture        : %s\n", cli_yesno(spy_picture));

    ast_cli(a->fd, "Debug level        : %d\n", debug);
    ast_cli(a->fd, "Support old parsing: %s\n", cli_yesno(mSupportCnxParseOldVersion));

    return CLI_SUCCESS;
}

/*! \brief CLI command "rtmp show routing" */
static char *rtmp_show_routing(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    int fd = a->fd;
    int index;
    int found = 0;


    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp show routing";
            e->usage =
                    "Usage: rtmp show routing\n"
                    "       Dump the RTMP module routing configuration.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    if (a->argc != 3)
        return CLI_SHOWUSAGE;

    if (httpurl[0])
    {
        char response[200];

        if (!http_request(rtmpserverstr, NULL, NULL, response, NULL))
        {
            found = 1;

            ast_cli(fd, "Rule HTTP\n");
            ast_cli(fd, " Response         : %s\n", response);
        }
    }
    else
        for (index = 0; index < MAX_RULES; index++)
        {
            if (rtmp_rules[index].name[0] != 0)
            {
                found = 1;
                ast_cli(fd, "Rule %d\n", index);
                ast_cli(fd, " Name             : %s\n", rtmp_rules[index].name);
                ast_cli(fd, " Number           : %s\n", rtmp_rules[index].number);
                ast_cli(fd, " Destination      : %s\n", rtmp_rules[index].dest);
            }
        }

    if (!found)
        ast_cli(fd, "No routing rules configured !\n");

    return CLI_SUCCESS;
}

/*! \brief CLI command "rtmp show jitter" */
static char *rtmp_show_jitter(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp show jitter";
            e->usage =
                    "Usage: rtmp show jitter\n"
                    "       Dump the RTMP module jitter configuration.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    if (a->argc != 3)
        return CLI_SHOWUSAGE;

    ast_cli(a->fd, "  Jitterbuffer enabled  : %s\n",
            cli_yesno(ast_test_flag(&global_jbconf, AST_JB_ENABLED)));
    ast_cli(a->fd, "  Jitterbuffer forced   : %s\n",
            cli_yesno(ast_test_flag(&global_jbconf, AST_JB_FORCED)));
    ast_cli(a->fd, "  Jitterbuffer max size : %ld\n", global_jbconf.max_size);
    ast_cli(a->fd, "  Jitterbuffer resync   : %ld\n",
            global_jbconf.resync_threshold);
    ast_cli(a->fd, "  Jitterbuffer impl     : %s\n", global_jbconf.impl);
    ast_cli(a->fd, "  Jitterbuffer log      : %s\n",
            cli_yesno(ast_test_flag(&global_jbconf, AST_JB_LOG)));

    return CLI_SUCCESS;
}

/*! \brief CLI command "rtmp show channels" */
static char *rtmp_show_channels(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    struct rtmp_threadinfo *th;
    struct ao2_iterator i;
    int count = 0;

#define FORMAT2 "%-20s %-20.20s %-6.6s %-5.5s %-20.20s\n"
#define FORMAT  "RTMP/%-15p %-20.20s %-6d %-4.4s %s%-20.20s\n"

    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp show channels";
            e->usage =
                    "Usage: rtmp show channels\n"
                    "       Lists all active RTMP channels.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    if (a->argc != 3)
        return CLI_SHOWUSAGE;


    I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
    ast_mutex_lock(&rtmplock);
    I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n");

    i = ao2_iterator_init(threadt, 0);
    while ((th =
            ao2_t_iterator_next(&i,
                    "iterate through tcp threads for 'rtmp show connections'")))
    {
        if (th->client)
            if (th->client->pvt)
            {
                if (!count)
                    ast_cli(a->fd, FORMAT2, "Channel", "Host", "Port", "Type", "Name");

                ast_cli(a->fd, FORMAT, th->client, th->client->address, th->client->port,
                        (th->tcptls_session->client ? "S" : "C"),
                        (th->client->user ? " " : "*"), th->client->name);
                //
                count++;
            }
        ao2_t_ref(th, -1, "decrement ref from iterator");
    }
    ao2_iterator_destroy(&i);

    I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
    ast_mutex_unlock(&rtmplock);

    ast_cli(a->fd, "%d active RTMP dialogs\n", count);

    return CLI_SUCCESS;
#undef FORMAT
#undef FORMAT2
}

/*! \brief CLI command "rtmp show connections" */
static char *rtmp_show_connections(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    struct rtmp_threadinfo *th;
    struct ao2_iterator i;

    char *country = NULL;
    float latitude = 0.0, longitude = 0.0;

    //         channel  host   port    type  proto  name
#define FORMAT2 "%-18s %-17.17s %-6.6s %-4.4s %-5.5s %s\n"
#define FORMAT  "RTMP/%-13p %-17.17s %-6d %-4.4s %-5.5s %s%s %s (%s loc:%f,%f)\n"
    // format name: [@]<name> [*] ([?/<country] loc:latitude, longitude)
    //                 @=user registered
    //                 *=tcp connected

    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp show connections";
            e->usage =
                    "Usage: rtmp show connections\n"
                    "       Lists all active RTMP sessions.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    if (a->argc != 3)
        return CLI_SHOWUSAGE;

    I6DEBUG(1, NULL, "CLI cmd: show connections\n");
    I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
    ast_mutex_lock(&rtmplock);
    I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n");

    ast_cli(a->fd, FORMAT2, "Channel", "Host", "Port", "Type", "Proto", "Name");
    i = ao2_iterator_init(threadt, 0);
    while ((th =
            ao2_t_iterator_next(&i,
                    "iterate through tcp threads for 'rtmp show connections'")))
    {
        if (th->client)
        {
            country = th->client->country;
            latitude = th->client->latitude;
            longitude = th->client->longitude;

            ast_cli(a->fd, FORMAT, th->client, th->client->address, th->client->port,
                    (th->tcptls_session->client ? "S" : "C"),
                    getUsedRtmpProtocolName(th->client),
                    (th->client->user ? "@" : " "), th->client->name,
                    (th->client->fd == (-1) ? " " : "*"), (country ? country : "?"),
                    latitude, longitude);
            //
        }

        ao2_t_ref(th, -1, "decrement ref from iterator");
    }
    ao2_iterator_destroy(&i);

    I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
    ast_mutex_unlock(&rtmplock);

    return CLI_SUCCESS;
#undef FORMAT
#undef FORMAT2
}

/*! \brief CLI command "rtmp show connection" */
static char *rtmp_show_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    struct rtmp_threadinfo *th;
    size_t len;
    int found = 0;
    struct ao2_iterator i;
    char tmp[40];
    struct tm *tmvalue;
    time_t now;

    int duration;
    int duration2;

    time(&now);

    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp show connection";
            e->usage =
                    "Usage: rtmp show connection <user|RTMP/id>\n"
                    "       Provides detailed status on a given RTMP connection (identified by RTMP id).\n";
            return NULL;
        case CLI_GENERATE:
            return complete_rtmpuser(a->line, a->word, a->pos, a->n);
    }

    if (a->argc != 4)
        return CLI_SHOWUSAGE;
    len = strlen(a->argv[3]);

    I6DEBUG(1, NULL, "CLI cmd: show connection %s\n", a->argv[3]);
    I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
    ast_mutex_lock(&rtmplock);
    I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n");

    i = ao2_iterator_init(threadt, 0);
    while ((th =
            ao2_t_iterator_next(&i,
                    "iterate through tcp threads for 'rtmp show connection'")))
    {
        if (th->client)
        {
            int numBytes = (-1);
            int pipesize = (-1);

            I6DEBUG(7, th->client, "CLI cmd: show connection %s\n", a->argv[3]);

            sprintf(tmp, "RTMP/%p", th->client);

            if ((!strncasecmp(th->client->name, a->argv[3], len)) ||
                    (!strncasecmp(tmp, a->argv[3], len)))
            {

                duration = 0;
                duration2 = 0;

                if (th->client->callstop)
                {
                    duration = th->client->callstop - th->client->callstart;
                    if (th->client->callanswer)
                        duration2 = th->client->callstop - th->client->callanswer;
                }
                else
                {
                    if (th->client->callstart)
                        duration = now - th->client->callstart;
                    if (th->client->callanswer)
                        duration2 = now - th->client->callanswer;
                }

                char formatbuf[256];
                ast_cli(a->fd, "\n");
                ast_cli(a->fd, "  ID:                     RTMP/%p\n", th->client);
                ast_cli(a->fd, "  Name:                   %s\n", th->client->name);
                ast_cli(a->fd, "  User:                   %s\n",
                        (th->client->user ? " " : "*"));

                ast_cli(a->fd, "  Flash version:          %s\n", th->client->flashver);

                if (th->client->clientType == CLIENT_TYPE_ANDROID)
                    ast_cli(a->fd, "  Type:                   ANDROID\n");
                else if (th->client->clientType == CLIENT_TYPE_IOS)
                    ast_cli(a->fd, "  Type:                   IOS\n");
                else
                    ast_cli(a->fd, "  Type:                   FLASH\n");

                ast_cli(a->fd, "  Protocol:               %s\n", getUsedRtmpProtocolName(th->client));

                tmvalue = localtime(&th->client->date);
                ast_cli(a->fd,
                        "  Date:                   %04d/%02d/%02d %02d:%02d:%02d\n",
                        tmvalue->tm_year + 1900, tmvalue->tm_mon + 1, tmvalue->tm_mday,
                        tmvalue->tm_hour, tmvalue->tm_min, tmvalue->tm_sec);

                if (th->client->cellid && strlen(th->client->cellid) != 0)
                    ast_cli(a->fd, "  Cellid:                 %s\n", th->client->cellid);
                else
                    ast_cli(a->fd, "  Cellid:                 none\n");
                if (th->client->param && strlen(th->client->param) != 0)
                    ast_cli(a->fd, "  Param:                  %s\n", th->client->param);
                else
                    ast_cli(a->fd, "  Param:                  none\n");

                ast_cli(a->fd, "  Localisation:           loc:%f,%f\n",
                        th->client->latitude, th->client->longitude);

                if (th->client->country)
                    ast_cli(a->fd, "  Country:                %s\n", th->client->country);
                else
                    ast_cli(a->fd, "  Country:                ?\n");

                ioctl(th->client->fd, SIOCOUTQ, &numBytes);
                if (th->client->pvt)
                    ioctl(th->client->pvt->pipe[0], FIONREAD, &pipesize);


                strcpy(formatbuf, GET_FORMAT_NAME(th->client->audiocodec));

                ast_cli(a->fd, "  Codec Capability:       %s\n", formatbuf);

                //ast_cli(a->fd, "  Format:                 %s\n",
                //  GET_FORMAT_NAME(th->client->audiocodec));

                ast_cli(a->fd, "  Address IP:             %s Port %d\n",
                        th->client->address, th->client->port);
                //
                ast_cli(a->fd, "  Streams IDs:            P=%f, A=%f, V=%f\n",
                        th->client->publishstream, th->client->playstream,
                        th->client->playstream2);
                ast_cli(a->fd, "  Streams status:         P=%d, A=%d, V=%d\n",
                        th->client->publishing, th->client->playing, th->client->playing2);
                ast_cli(a->fd, "  Counters:               I=%d, O=%d in bytes\n",
                        th->client->incoming_bytescount, th->client->outgoing_bytescount);
                ast_cli(a->fd, "  Bandwidth:              I=%d, O=%d in bytes/s\n",
                        th->client->incoming_bandwidth, th->client->outgoing_bandwidth);
                ast_cli(a->fd, "  Calls counters:         I=%d, O=%d\n",
                        th->client->incoming_calls, th->client->outgoing_calls);
                ast_cli(a->fd, "  Image frames:           I=%d, O=%d\n",
                        th->client->incoming_images, th->client->outgoing_images);
                if (duration)
                    ast_cli(a->fd, "  Frames per seconde:     I=%dfps, O=%dfps\n",
                            th->client->incoming_images / duration,
                            th->client->outgoing_images / duration);
                ast_cli(a->fd, "  Incoming lost packets:  A=%d/%d, V=%d/%d\n",
                        th->client->incoming_audiolost, th->client->incoming_audio,
                        th->client->incoming_videolost, th->client->incoming_video);
                ast_cli(a->fd, "  Outgoing lost packets:  A=%d/%d, V=%d/%d\n",
                        th->client->outgoing_audiolost, th->client->outgoing_audio,
                        th->client->outgoing_videolost, th->client->outgoing_video);
                ast_cli(a->fd, "  Burst packets:          M=%d, C=%d\n",
                        th->client->burst_max, th->client->burst_counter);
                ast_cli(a->fd, "  Status:                 %s\n",
                        (th->client->pvt ? "CALL" : "HANGUP"));
                ast_cli(a->fd, "  Duration:               %d(+%d)s\n", duration2,
                        duration - duration2);
                ast_cli(a->fd, "  Last IN picture size    %dx%d\n",
                        th->client->pictureIn_width, th->client->pictureIn_heigth);
                ast_cli(a->fd, "  Last OUT picture size   %dx%d\n",
                        th->client->pictureOut_width, th->client->pictureOut_heigth);

                if (th->client->pvt)
                    ast_cli(a->fd, "  Mode:                   %s\n",
                            (th->client->pvt->mode ? "direct" : "signaling"));
                ast_cli(a->fd, "  Buffer:                 %d/%d A=%d, V=%d\n", numBytes,
                        tcpbuffer, maxaudiobuffer, maxvideobuffer);
                ast_cli(a->fd, "  Pipe:                   %d/%d A=%d, V=%d\n", pipesize,
                        0, maxaudiopipe, maxvideopipe);
                ast_cli(a->fd, "  Socket FD:              %d\n", th->client->fd);

                ast_cli(a->fd, "\n\n");

                found++;
            }
        }

        ao2_t_ref(th, -1, "decrement ref from iterator");
    }
    ao2_iterator_destroy(&i);

    I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
    ast_mutex_unlock(&rtmplock);

    if (!found)
        ast_cli(a->fd, "No such RTMP connection starting with '%s'\n", a->argv[3]);

    return CLI_SUCCESS;
}

/*! \brief CLI command "rtmp show connection" */
static char *rtmp_close_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    struct rtmp_threadinfo *th;
    size_t len;
    int found = 0;
    struct ao2_iterator i;
    char tmp[20];

    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp close connection";
            e->usage =
                    "Usage: rtmp close connection <user>\n"
                    "       Close a given RTMP connection (identified by RTMP id).\n";
            return NULL;
        case CLI_GENERATE:
            return complete_rtmpuser(a->line, a->word, a->pos, a->n);
    }

    if (a->argc != 4)
        return CLI_SHOWUSAGE;
    len = strlen(a->argv[3]);
    I6DEBUG(1, NULL, "CLI cmd: close connection %s\n", a->argv[3]);


    ast_mutex_lock(&rtmplock);

    i = ao2_iterator_init(threadt, 0);
    while ((th =
            ao2_t_iterator_next(&i,
                    "iterate through tcp threads for 'rtmp show connection'")))
    {
        if (th->client)
        {
            sprintf(tmp, "RTMP/%p", th->client);

            if ((!strncasecmp(th->client->name, a->argv[3], len)) ||
                    (!strncasecmp(tmp, a->argv[3], len)))
            {
                ast_mutex_lock(&th->client->lock);

                if (th->client->fd != (-1))
                    close(th->client->fd);
                th->client->fd = (-1);

                ast_mutex_unlock(&th->client->lock);

                found++;
            }
        }
    }
    ao2_iterator_destroy(&i);

    ast_mutex_unlock(&rtmplock);

    if (!found)
        ast_cli(a->fd, "No such RTMP connection starting with '%s'\n", a->argv[3]);

    return CLI_SUCCESS;
}

/*! \brief CLI command "rtmp show connection" */
static char *rtmp_close_connections(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    struct rtmp_threadinfo *th;
    int found = 0;
    struct ao2_iterator i;

    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp close connections";
            e->usage =
                    "Usage: rtmp close connections\n"
                    "       Close all the RTMP connections.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    if (a->argc != 3)
        return CLI_SHOWUSAGE;

    I6DEBUG(1, NULL, "CLI cmd: close connection\n");

    ast_mutex_lock(&rtmplock);

    i = ao2_iterator_init(threadt, 0);
    while ((th =
            ao2_t_iterator_next(&i,
                    "iterate through tcp threads for 'rtmp show connection'")))
    {
        if (th->client)
        {
            ast_mutex_lock(&th->client->lock);

            if (th->client->fd != (-1))
                close(th->client->fd);
            th->client->fd = (-1);

            ast_mutex_unlock(&th->client->lock);

            found++;
        }
    }
    ao2_iterator_destroy(&i);

    ast_mutex_unlock(&rtmplock);

    if (!found)
        ast_cli(a->fd, "No such RTMP connection starting with '%s'\n", a->argv[3]);

    return CLI_SUCCESS;
}

/*! \brief CLI command "rtmp show connection" */
static char *rtmp_send_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    struct rtmp_threadinfo *th;
    size_t len;
    int found = 0;
    struct ao2_iterator i;
    char tmp[20];

    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp send connection";
            e->usage =
                    "Usage: rtmp send connection <user> <text>\n"
                    "       Send a text to an RTMP connection (identified by RTMP id).\n";
            return NULL;
        case CLI_GENERATE:
            return complete_rtmpuser(a->line, a->word, a->pos, a->n);
    }

    if (a->argc != 5)
        return CLI_SHOWUSAGE;
    len = strlen(a->argv[3]);
    I6DEBUG(1, NULL, "CLI cmd: send connection %s\n", a->argv[3]);

    ast_mutex_lock(&rtmplock);

    i = ao2_iterator_init(threadt, 0);
    while ((th =
            ao2_t_iterator_next(&i,
                    "iterate through tcp threads for 'rtmp show connection'")))
    {
        if (th->client)
        {
            ast_mutex_lock(&th->client->lock);

            sprintf(tmp, "RTMP/%p", th->client);

            if ((!strncasecmp(th->client->name, a->argv[3], len)) ||
                    (!strncasecmp(tmp, a->argv[3], len)))
            {
                rtmp_send_text(th->client, a->argv[4]);

                found++;
            }

            ast_mutex_unlock(&th->client->lock);
        }
        ao2_t_ref(th, -1, "Unref threadinfo");
    }
    ao2_iterator_destroy(&i);

    ast_mutex_unlock(&rtmplock);

    if (!found)
        ast_cli(a->fd, "No such RTMP connection starting with '%s'\n", a->argv[3]);

    return CLI_SUCCESS;
}

/*! \brief CLI command "rtmp admin connection" */
static char *rtmp_admin_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    struct rtmp_threadinfo *th;
    size_t len;
    int found = 0;
    struct ao2_iterator i;
    char tmp[20];
    char i6cmd[100];

    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp admin connection";
            e->usage =
                    "Usage: rtmp admin connection <user> <cmd>\n"
                    "       Send an admin CMD to an RTMP connection (identified by RTMP id).\n";
            return NULL;
        case CLI_GENERATE:
            return complete_rtmpuser(a->line, a->word, a->pos, a->n);
    }

    if (a->argc < 5)
        return CLI_SHOWUSAGE;
    len = strlen(a->argv[3]);

    // Create admin cmd: cmd line between @@
    if (a->argv[4])
    {
        sprintf(i6cmd, "%s:", a->argv[4]);
    }
    /*
     * Concat args :
     *   CLI> rtmp admin connection rtmp1 setcfg watchdog 20
     *   => send cmd setcfg:watchdog:20
     */
    if (a->argc > 5)
    {
        int i;
        for (i = 5; i < a->argc; i++)
        {
            strcat((char *)i6cmd, a->argv[i]);
            if (i < a->argc - 1)
            {
                strcat((char *)i6cmd, ":");
            }
        }
    }
    I6DEBUG(1, NULL, "CLI cmd: admin connection %s : %s\n", a->argv[3], i6cmd);

    ast_mutex_lock(&rtmplock);

    i = ao2_iterator_init(threadt, 0);
    while ((th =
            ao2_t_iterator_next(&i,
                    "iterate through tcp threads for 'rtmp admin connection'")))
    {
        if (th->client)
        {
            ast_mutex_lock(&th->client->lock);

            sprintf(tmp, "RTMP/%p", th->client);

            if ((!strncasecmp(th->client->name, a->argv[3], len)) ||
                    (!strncasecmp(tmp, a->argv[3], len)))
            {
                rtmp_send_admin(th->client, i6cmd /*a->argv[4] */ );
                found++;
            }

            ast_mutex_unlock(&th->client->lock);
        }
        ao2_t_ref(th, -1, "Unref threadinfo");
    }
    ao2_iterator_destroy(&i);

    ast_mutex_unlock(&rtmplock);

    if (!found)
        ast_cli(a->fd, "No such RTMP connection starting with '%s'\n", a->argv[3]);

    return CLI_SUCCESS;
}

/*! \brief CLI command "rtmp send dtmf connection" */
static char *rtmp_dtmf_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    struct rtmp_threadinfo *th;
    size_t len;
    int found = 0;
    struct ao2_iterator i;
    char tmp[20];

    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp dtmf connection";
            e->usage =
                    "Usage: rtmp dtmf connection <user> <key>\n"
                    "       Send a dtmf to an RTMP connection (identified by RTMP id).\n";
            return NULL;
        case CLI_GENERATE:
            return complete_rtmpuser(a->line, a->word, a->pos, a->n);
    }

    if (a->argc != 5)
        return CLI_SHOWUSAGE;
    len = strlen(a->argv[3]);
    I6DEBUG(1, NULL, "CLI cmd: dtmf connection %s\n", a->argv[3]);

    ast_mutex_lock(&rtmplock);

    i = ao2_iterator_init(threadt, 0);
    while ((th =
            ao2_t_iterator_next(&i,
                    "iterate through tcp threads for 'rtmp dtmf connection'")))
    {
        if (th->client)
        {
            ast_mutex_lock(&th->client->lock);

            sprintf(tmp, "RTMP/%p", th->client);

            if ((!strncasecmp(th->client->name, a->argv[3], len)) ||
                    (!strncasecmp(tmp, a->argv[3], len)))
            {
                rtmp_send_dtmf(th->client, a->argv[4][0]);
                found++;
            }

            ast_mutex_unlock(&th->client->lock);
        }
        ao2_t_ref(th, -1, "Unref threadinfo");
    }
    ao2_iterator_destroy(&i);

    ast_mutex_unlock(&rtmplock);

    if (!found)
        ast_cli(a->fd, "No such RTMP connection starting with '%s'\n", a->argv[3]);

    return CLI_SUCCESS;
}

/*! \brief CLI command "rtmp event connection" */
static char *rtmp_event_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    struct rtmp_threadinfo *th;
    size_t len;
    int found = 0;
    struct ao2_iterator i;
    char tmp[20];

    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp event connection";
            e->usage =
                    "Usage: rtmp event connection <user> <key>\n"
                    "       Send an event to an RTMP connection (identified by RTMP id).\n";
            return NULL;
        case CLI_GENERATE:
            return complete_rtmpuser(a->line, a->word, a->pos, a->n);
    }

    if (a->argc != 5)
        return CLI_SHOWUSAGE;
    len = strlen(a->argv[3]);
    I6DEBUG(1, NULL, "CLI cmd: event connection %s\n", a->argv[3]);

    I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
    ast_mutex_lock(&rtmplock);
    I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n");

    i = ao2_iterator_init(threadt, 0);
    while ((th =
            ao2_t_iterator_next(&i,
                    "iterate through tcp threads for 'rtmp event connection'")))
    {
        if (th->client)
        {
            ast_mutex_lock(&th->client->lock);

            sprintf(tmp, "RTMP/%p", th->client);

            if ((!strncasecmp(th->client->name, a->argv[3], len)) ||
                    (!strncasecmp(tmp, a->argv[3], len)))
            {
                rtmp_send_event(th->client, a->argv[4]);
                found++;
            }

            ast_mutex_unlock(&th->client->lock);
        }
        ao2_t_ref(th, -1, "Unref threadinfo");
    }
    ao2_iterator_destroy(&i);

    I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
    ast_mutex_unlock(&rtmplock);

    if (!found)
        ast_cli(a->fd, "No such RTMP connection starting with '%s'\n", a->argv[3]);

    return CLI_SUCCESS;
}
/*! \brief CLI command "rtmp show connection" */
static char *rtmp_set_connection(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    struct rtmp_threadinfo *th;
    size_t len;
    int found = 0;
    struct ao2_iterator i;
    char tmp[20];

    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp set connection";
            e->usage =
                    "Usage: rtmp set connection <user> <action>\n"
                    "       Configure an RTMP connection (identified by RTMP id).\n";
            return NULL;
        case CLI_GENERATE:
            return complete_rtmpuser(a->line, a->word, a->pos, a->n);
    }

    if (a->argc < 4)
        return CLI_SHOWUSAGE;
    I6DEBUG(1, NULL, "CLI cmd: set connection %s\n", a->argv[3]);
    len = strlen(a->argv[3]);

    I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
    ast_mutex_lock(&rtmplock);
    I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n");

    i = ao2_iterator_init(threadt, 0);
    while ((th =
            ao2_t_iterator_next(&i,
                    "iterate through tcp threads for 'rtmp show connection'")))
    {
        if (th->client)
        {
            ast_mutex_lock(&th->client->lock);

            sprintf(tmp, "RTMP/%p", th->client);

            if ((!strncasecmp(th->client->name, a->argv[3], len)) ||
                    (!strncasecmp(tmp, a->argv[3], len)))
            {
                I6DEBUG(1, th->client, "CLI cmd: set connection %s %s %s\n",
                        a->argv[3], a->argv[4], a->argv[5]);

                if ((!strcasecmp(a->argv[4], "autoanswer")) && (a->argc > 5) &&
                        (!strcasecmp(a->argv[5], "spy")))
                {
                    ast_cli(a->fd, "Enable auto answer / spy mode.\n");
                    th->client->autoanswer = 2;
                }
                else if ((!strcasecmp(a->argv[4], "autoanswer")) && (a->argc > 5) &&
                        (!strcasecmp(a->argv[5], "yes")))
                {
                    ast_cli(a->fd, "Enable auto answer.\n");
                    th->client->autoanswer = 1;
                }
                else if ((!strcasecmp(a->argv[4], "autoanswer")) && (a->argc > 5) &&
                        (!strcasecmp(a->argv[5], "no")))
                {
                    ast_cli(a->fd, "Disable auto answer.\n");
                    th->client->autoanswer = 0;
                }
                else if ((!strcasecmp(a->argv[4], "echo")) && (a->argc > 5) &&
                        (!strcasecmp(a->argv[5], "yes")))
                {
                    ast_cli(a->fd, "Enable echo.\n");
                    th->client->echo = 1;
                }
                else if ((!strcasecmp(a->argv[4], "echo")) && (a->argc > 5) &&
                        (!strcasecmp(a->argv[5], "no")))
                {
                    ast_cli(a->fd, "Disable echo.\n");
                    th->client->echo = 0;
                }
                else if ((!strcasecmp(a->argv[4], "mute")) && (a->argc == 5))
                {
                    ast_cli(a->fd, "Muted audio and video.\n");
                    th->client->mute = 3;
                }
                else if ((!strcasecmp(a->argv[4], "unmute")) && (a->argc == 5))
                {
                    ast_cli(a->fd, "Unuted audio and video.\n");
                    th->client->mute = 0;
                }
                else if ((!strcasecmp(a->argv[4], "mute")) && (a->argc > 5) &&
                        (!strcasecmp(a->argv[5], "video")))
                {
                    ast_cli(a->fd, "Muted audio and video.\n");
                    th->client->mute = 2;
                }
                else if ((!strcasecmp(a->argv[4], "mute")) && (a->argc > 5) &&
                        (!strcasecmp(a->argv[5], "audio")))
                {
                    ast_cli(a->fd, "Mute audio.\n");
                    th->client->mute = 1;
                }
                else
                {
                    ast_cli(a->fd, "Command not found.\n");
                }

                ast_mutex_unlock(&th->client->lock);

                found++;
            }
        }
        ao2_t_ref(th, -1, "Unref threadinfo");
    }
    ao2_iterator_destroy(&i);

    I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
    ast_mutex_unlock(&rtmplock);

    if (!found)
        ast_cli(a->fd, "No such RTMP connection starting with '%s'\n", a->argv[3]);

    return CLI_SUCCESS;
}

/*! \brief Execute rtmp show users command */
//static int __rtmp_show_users(int manager, int fd, struct mansession *s, int argc, char *argv[])
#if ASTERISK_VERSION_NUM < AST_8
static int __rtmp_show_users(int manager, int fd, int argc, char *argv[])
#elif ASTERISK_VERSION_NUM >= AST_8 && ASTERISK_VERSION_NUM < AST_11
static int __rtmp_show_users(int manager, int fd, int argc,
        const char *const argv[])
#elif ASTERISK_VERSION_NUM >= AST_11  && ASTERISK_VERSION_NUM < AST_12
static int __rtmp_show_users(int manager, int fd, int argc,
        const char *const argv[])
#else
static int __rtmp_show_users(int manager, int fd, int argc,
        const char *const argv[])
#endif
{
    regex_t regexbuf;
    int havepattern = 0;
    int total_users = 0;
    int online_users = 0;
    int offline_users = 0;
    struct ao2_iterator i;

#define FORMAT2 "%-15.15s  %-15.15s %-8s %-10s%s"
#define FORMAT "%-15.15s  %-15.15s %-8d %-10s%s"

    struct rtmp_user *user = NULL;
    char name[256];
    int registeredonly = 0;
    char *term = manager ? "\r\n" : "\n";
    switch (argc)
    {
        case 6:
            if (!strcasecmp(argv[3], "registered"))
                registeredonly = 1;
            else
                return RESULT_SHOWUSAGE;
            if (!strcasecmp(argv[4], "like"))
            {
                if (regcomp(&regexbuf, argv[5], REG_EXTENDED | REG_NOSUB))
                    return RESULT_SHOWUSAGE;
                havepattern = 1;
            }
            else
                return RESULT_SHOWUSAGE;
            break;
        case 5:
            if (!strcasecmp(argv[3], "like"))
            {
                if (regcomp(&regexbuf, argv[4], REG_EXTENDED | REG_NOSUB))
                    return RESULT_SHOWUSAGE;
                havepattern = 1;
            }
            else
                return RESULT_SHOWUSAGE;
            break;
        case 4:
            if (!strcasecmp(argv[3], "registered"))
                registeredonly = 1;
            else
                return RESULT_SHOWUSAGE;
            break;
        case 3:
            break;
        default:
            return RESULT_SHOWUSAGE;
    }


    ast_cli(fd, FORMAT2, "Name", "Host", "Port", "Status", term);

    i = ao2_iterator_init(users, 0);
    for (user = ao2_iterator_next(&i); user;
            user_unref(user), user = ao2_iterator_next(&i))
    {

        //if (registeredonly && !user->addr.sin_addr.s_addr)
        //  continue;

        if (havepattern && regexec(&regexbuf, user->name, 0, NULL, 0))
            continue;

        ast_copy_string(name, user->name, sizeof(name));

        if (user->client)
        {
            ast_cli(fd, FORMAT, name,
                    user->client->address, user->client->port,
                    "status", term);
            //
        }
        else
            ast_cli(fd, FORMAT, name, "(Unspecified)", 0, "status", term);

        total_users++;
    }
    ao2_iterator_destroy(&i);

    ast_cli(fd, "%d rtmp users [%d online, %d offline]%s", total_users,
            online_users, offline_users, term);

    if (havepattern)
        regfree(&regexbuf);

    return RESULT_SUCCESS;
#undef FORMAT
#undef FORMAT2
}

/*! \brief  CLI Show users command */
static char *rtmp_show_users(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp show users";
            e->usage =
                    "Usage: rtmp show users [registered] [like <pattern>]\n"
                    "       Lists all known RTMP users.\n"
                    "       Optional 'registered' argument lists only users with known addresses.\n"
                    "       Optional regular expression pattern is used to filter the user list.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    //switch (__rtmp_show_users(0, a->fd, NULL, a->argc, a->argv)) {
    switch (__rtmp_show_users(0, a->fd, a->argc, a->argv))
    {
        case RESULT_SHOWUSAGE:
            return CLI_SHOWUSAGE;
        case RESULT_FAILURE:
            return CLI_FAILURE;
        default:
            return CLI_SUCCESS;
    }
}

// Show statistics
static char *rtmp_show_statistics(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    int fd = a->fd;
    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp show statistics";
            e->usage =
                    "Usage: rtmp show statistics\n"
                    "       Provides a dump statistics on the RTMP channel.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }
    if (a->argc > 3)
        return CLI_SHOWUSAGE;

    int index;

    for (index = 0; index < STATS_MAX; index++)
        ast_cli(fd, "%s : %d\n", stats_name[index], stats[index]);

    return CLI_SUCCESS;
}

/*! \brief CLI command "rtmp reload" */
static char *rtmp_do_reload(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    switch (cmd)
    {
        case CLI_INIT:
            e->command = "rtmp reload";
            e->usage = "Usage: rtmp reload\n" "       Reload rtmp channel driver.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }
    I6DEBUG(1, NULL, "CLI cmd: reload\n");

    reload();

    return CLI_SUCCESS;
}

/*! \brief Turn on RTMP debugging (CLI command) */
static char *rtmp_do_debug(struct ast_cli_entry *e, int cmd,
        struct ast_cli_args *a)
{
    int oldrtmpdebug = debug;
    char *what;

    if (cmd == CLI_INIT)
    {
        e->command = "rtmp set debug {on|off|dump|full}";
        e->usage =
                "Usage: rtmp set debug {off|on|dump}\n"
                "       Globally disables dumping of RTMP packets,\n"
                "       or enables it either globally\n";
        return NULL;
    }
    else if (cmd == CLI_GENERATE)
    {
        if (a->pos == 4)
            return NULL;
    }

    what = a->argv[e->args - 1];  /* guaranteed to exist */
    if (a->argc == e->args)
    {                             /* on/off/dump */
        if (!strcasecmp(what, "on"))
        {
            debug = 1;
            ast_cli(a->fd, "RTMP Debugging %senabled\n", oldrtmpdebug ? "re-" : "");
            return CLI_SUCCESS;
        }
        else if (!strcasecmp(what, "dump"))
        {
            debug = 2;
            ast_cli(a->fd, "RTMP Debugging %senabled\n", oldrtmpdebug ? "re-" : "");
            return CLI_SUCCESS;
        }
        else if (!strcasecmp(what, "full"))
        {
            debug = 10;
            ast_cli(a->fd, "RTMP Debugging %senabled\n", oldrtmpdebug ? "re-" : "");
            return CLI_SUCCESS;
        }
        else if (!strcasecmp(what, "off"))
        {
            debug = 0;
            ast_cli(a->fd, "RTMP Debugging Disabled\n");
            return CLI_SUCCESS;
        }
    }

    return CLI_SHOWUSAGE;         /* default, failure */
}

/*! \brief  ${RTMPYUSER()} Dialplan function - reads user data */
static int function_rtmpuser(struct ast_channel *chan, const char *cmd,
        char *data, char *buf, size_t len)
{
    struct rtmp_user *user;
    char *colname;

    *buf = 0;

    if ((colname = strchr(data, ':')))
    {                             /*! \todo Will be deprecated after 1.4 */
        static int deprecation_warning = 0;
        *colname++ = '\0';
        if (deprecation_warning++ % 10 == 0)
            ast_log(LOG_WARNING,
                    "RTMPUSER(): usage of ':' to separate arguments is deprecated.  Please use ',' instead.\n");
    }
    else if ((colname = strchr(data, ',')))
        *colname++ = '\0';
    else
        colname = "ip";

    ast_mutex_lock(&rtmplock);

    if (!(user = rtmp_find_user(data, 0)))
    {
        ast_mutex_unlock(&rtmplock);
        return -1;
    }

    if (!strcasecmp(colname, "ip"))
    {
        ast_copy_string(buf, user->client ? user->client->address : "", len);
        //
    }

#if 0
    else if (!strcasecmp(colname, "port"))
    {
        snprintf(buf, len, "%d", ntohs(user->addr.sin_port));
    }
    else if (!strcasecmp(colname, "status"))
    {
        user_status(user, buf, len);
    }
    else if (!strcasecmp(colname, "language"))
    {
        ast_copy_string(buf, user->language, len);
    }
    else if (!strcasecmp(colname, "regexten"))
    {
        ast_copy_string(buf, user->regexten, len);
    }
    else if (!strcasecmp(colname, "limit"))
    {
        snprintf(buf, len, "%d", user->call_limit);
    }
    else if (!strcasecmp(colname, "busylevel"))
    {
        snprintf(buf, len, "%d", user->busy_level);
    }
    else if (!strcasecmp(colname, "curcalls"))
    {
        snprintf(buf, len, "%d", user->inUse);
    }
    else if (!strcasecmp(colname, "accountcode"))
    {
        ast_copy_string(buf, user->accountcode, len);
    }
    else if (!strcasecmp(colname, "callgroup"))
    {
        ast_print_group(buf, len, user->callgroup);
    }
    else if (!strcasecmp(colname, "pickupgroup"))
    {
        ast_print_group(buf, len, user->pickupgroup);
    }
    else if (!strcasecmp(colname, "useragent"))
    {
        ast_copy_string(buf, user->useragent, len);
    }
    else if (!strcasecmp(colname, "mailbox"))
    {
        struct ast_str *mailbox_str = ast_str_alloca(512);
        user_mailboxes_to_str(&mailbox_str, user);
        ast_copy_string(buf, mailbox_str->str, len);
    }
    else if (!strcasecmp(colname, "context"))
    {
        ast_copy_string(buf, user->context, len);
    }
    else if (!strcasecmp(colname, "expire"))
    {
        snprintf(buf, len, "%d", user->expire);
    }
    else if (!strcasecmp(colname, "dynamic"))
    {
        ast_copy_string(buf, user->host_dynamic ? "yes" : "no", len);
    }
    else if (!strcasecmp(colname, "callerid_name"))
    {
        ast_copy_string(buf, user->cid_name, len);
    }
    else if (!strcasecmp(colname, "callerid_num"))
    {
        ast_copy_string(buf, user->cid_num, len);
    }
    else if (!strcasecmp(colname, "codecs"))
    {
        ast_getformatname_multiple(buf, len - 1, user->capability);
    }
    else if (!strncasecmp(colname, "chanvar[", 8))
    {
        char *chanvar = colname + 8;
        struct ast_variable *v;

        chanvar = strsep(&chanvar, "]");
        for (v = user->chanvars; v; v = v->next)
            if (!strcasecmp(v->name, chanvar))
                ast_copy_string(buf, v->value, len);
    }
    else if (!strncasecmp(colname, "codec[", 6))
    {
        char *codecnum;
        int codec = 0;

        codecnum = colname + 6;     /* move past the '[' */
        codecnum = strsep(&codecnum, "]");  /* trim trailing ']' if any */
        if ((codec = ast_codec_pref_index(&user->prefs, atoi(codecnum))))
        {
            ast_copy_string(buf, ast_getformatname(codec), len);
        }
        else
        {
            buf[0] = '\0';
        }
    }
    else
    {
        buf[0] = '\0';
    }

#endif

    ast_mutex_unlock(&rtmplock);

    return 0;
}

/*! \brief Structure to declare a dialplan function: RTMPuser */
struct ast_custom_function rtmpuser_function = {
        .name = "RTMPUSER",
        .synopsis = "Gets RTMP user information",
        .syntax = "RTMPUSER(<username>[,item])",
        .read = function_rtmpuser,
        .desc = "Valid items are:\n" "- ip (default)          The IP address.\n"
                /*
       "- port                  The port number\n"
       "- mailbox               The configured mailbox.\n"
       "- context               The configured context.\n"
       "- expire                The epoch time of the next expire.\n"
       "- dynamic               Is it dynamic? (yes/no).\n"
       "- callerid_name         The configured Caller ID name.\n"
       "- callerid_num          The configured Caller ID number.\n"
       "- callgroup             The configured Callgroup.\n"
       "- pickupgroup           The configured Pickupgroup.\n"
       "- codecs                The configured codecs.\n"
       "- status                Status (if qualify=yes).\n"
       "- regexten              Registration extension\n"
       "- limit                 Call limit (call-limit)\n"
       "- busylevel             Configured call level for signalling busy\n"
       "- curcalls              Current amount of calls \n"
       "                        Only available if call-limit is set\n"
       "- language              Default language for user\n"
       "- accountcode           Account code for this user\n"
       "- useragent             Current user agent id for user\n"
       "- chanvar[name]         A channel variable configured with setvar for this user.\n"
       "- codec[x]              Preferred codec index number 'x' (beginning with zero).\n"
                 */
                "\n"
};

/*! \brief  ${RTMPCLIENT()} Dialplan function - reads user data */
static int func_rtmpconnection_read(struct ast_channel *chan, const char *cmd,
        char *data, char *buf, size_t len)
{
    struct rtmp_pvt *p = NULL;
    struct rtmp_client *client = NULL;
    char *colname;
    char addr[20];

    *buf = 0;

    ast_debug(8, "RTMPCONNECTION(): %s\n", data);

    if (chan != NULL)
    {
        p = GET_CHAN_TECH_PVT(chan);
    }

    if ((colname = strchr(data, ':')))
    {                             /*! \todo Will be deprecated after 1.4 */
        static int deprecation_warning = 0;
        *colname++ = '\0';
        if (deprecation_warning++ % 10 == 0)
            ast_log(LOG_WARNING,
                    "RTMPCONNECTION(): usage of ':' to separate arguments is deprecated.  Please use ',' instead.\n");
    }
    else if ((colname = strchr(data, ',')))
        *colname++ = '\0';
    else
        colname = "";

    if ((colname[0] == 0) && (chan != NULL))
    {
        if (GET_CHAN_TECH(chan) == &rtmp_tech)
            if (p)
                client = p->client;

        /*
       if (client==NULL)
       if (chan->caller.id.number.valid)
       if (chan->caller.id.number.str != NULL)
       {
       client = rtmp_find_connection(chan->caller.id.number.str);
       } */

        if (client == NULL)
            return -1;

        ast_mutex_lock(&client->lock);
    }
    else if (!(client = rtmp_find_connection(colname)))
    {
        ast_debug(2, "RTMPCONNECTION(): no client found for %s\n", colname);
        return -1;
    }

    ast_debug(8, "RTMPCONNECTION(): execute cmd %s for client %s\n", data,
            client->name);

    if (!strcasecmp(data, "ip"))
    {
        ast_copy_string(buf, client->threadinfo ? client->address : "", len);
    }
    else if (!strcasecmp(data, "country"))
    {
        ast_copy_string(buf, client->country ? client->country : "", len);
    }
    else if (!strcasecmp(data, "loc"))
    {
        sprintf(buf, "loc:%f,%f", client->latitude, client->longitude);
    }
    else if (!strcasecmp(data, "latitude"))
    {
        sprintf(buf, "%f", client->latitude);
    }
    else if (!strcasecmp(data, "longitude"))
    {
        sprintf(buf, "%f", client->longitude);
    }
    else if (!strcasecmp(data, "addr"))
    {
        // Use PHP function ip2long/long2ip
        // online : http://www.mydnstools.info/ip2long

        if (client->threadinfo)
        {
            struct in_addr temp_addr;
            TCPTLS_SESSION_ADDRESS(client->threadinfo->tcptls_session->remote_address,
                    temp_addr.s_addr);
            uint32_t *value = (void *)&temp_addr;
            //
            sprintf(addr, "%u", htonl(*value));
        }
        ast_copy_string(buf, client->threadinfo ? addr : "", len);
    }
    else if (!strcasecmp(data, "channel"))
    {
        ast_copy_string(buf, client->pvt ? GET_CHAN_NAME(client->pvt->owner) : "", len);
    }
    else if (!strcasecmp(data, "status"))
    {
        ast_copy_string(buf, client->pvt ? "CALL" : "HANGUP", len);
    }
    else if (!strcasecmp(data, "param"))
    {
        ast_copy_string(buf, client->param, len);
    }

    ast_mutex_unlock(&client->lock);

    return 0;
}


/*! \brief  ${RTMPCONNECTION()} Dialplan function - reads user data */
static int func_rtmpconnection_write(struct ast_channel *chan, const char *cmd,
        char *data, const char *value)
{
    struct rtmp_pvt *p = NULL;
    struct rtmp_client *client = NULL;
    char *colname;

    ast_debug(8, "RTMPCONNECTION(): %s\n", data);

    if (chan != NULL)
    {
        p = GET_CHAN_TECH_PVT(chan);
    }

    if ((colname = strchr(data, ':')))
    {
        static int deprecation_warning = 0;
        *colname++ = '\0';
        if (deprecation_warning++ % 10 == 0)
            ast_log(LOG_WARNING,
                    "RTMPCONNECTION(): usage of ':' to separate arguments is deprecated.  Please use ',' instead.\n");
    }
    else if ((colname = strchr(data, ',')))
        *colname++ = '\0';
    else
        colname = "";

    if ((colname[0] == 0) && (chan != NULL))
    {
        if (GET_CHAN_TECH(chan) == &rtmp_tech)
            if (p)
                client = p->client;

        /*
       if (client==NULL)
       if (chan->caller.id.number.valid)
       if (chan->caller.id.number.str != NULL)
       {
       client = rtmp_find_connection(chan->caller.id.number.str);
       } */

        if (client == NULL)
            return -1;

        ast_mutex_lock(&client->lock);
    }
    else if (!(client = rtmp_find_connection(colname)))
    {
        ast_debug(1, "RTMPCONNECTION(): no client found for %s\n", colname);
        return -1;
    }

    ast_debug(8, "RTMPCONNECTION(): execute cmd %s for client %s\n", data,
            client->name);

    if (!strcasecmp(data, "event"))
    {
        rtmp_send_event(client, value);
    }

    ast_mutex_unlock(&client->lock);

    return 0;
}


/*! \brief Structure to declare a dialplan function: RTMPCONNECTION */
struct ast_custom_function rtmpconnection_function = {
        .name = "RTMPCONNECTION",
        .synopsis = "Gets/set RTMP connection status",
        .syntax = "RTMPCONNECTION(item,[connection])",
        .read = func_rtmpconnection_read,
        .write = func_rtmpconnection_write,
        .desc = "Valid items are:\n"
                "R/O  ip (default)          The IP address.\n"
                "R/O  channel               The channel name.\n"
                "R/O  status                The connection status.\n"
                "R/W    event                 Send an event to the connection.\n" "\n"
};


static int manager_rtmpsend(struct mansession *s, const struct message *m)
{
    const char *name = astman_get_header(m, "Connection");
    const char *type = astman_get_header(m, "Type");
    const char *data = astman_get_header(m, "Data");
    struct ast_variable *vars = astman_get_variables(m);
    struct rtmp_client *client = NULL;

    if (ast_strlen_zero(name))
    {
        astman_send_error(s, m, "RTMPSend requires a connection name");
        return 0;
    }

    if (ast_strlen_zero(type))
    {
        astman_send_error(s, m, "RTMPSend requires a type");
        return 0;
    }

    if (ast_strlen_zero(data))
    {
        astman_send_error(s, m, "RTMPSend requires a data (string)");
        return 0;
    }

    if (debug)
        I6DEBUG(3, client, "RTMP request for = %s\n", (char *)data);

    client = rtmp_find_connection(name);

    if (client)
    {
        astman_send_ack(s, m, "Message Sent");
        ast_mutex_unlock(&client->lock);
    }
    else
    {
        astman_send_error(s, m, "Unable to send message");
    }

    ast_variables_destroy(vars);
    return 0;
}

static char mandescr_rtmpsend[] =
        "Description: Sends a RTMP message\n"
        "All parameters for this event must be specified in the body of this request\n"
        "Variables: \n"
        "  *Name: <name>              Connection to receive the message. Required.\n"
        "  *Type: <type>              Types : 'dtmf', 'text', 'event', 'up', 'down'. Required\n"
        "  *Data: <digit|text|name>   String value. Required.\n"
        "  ActionID: <id>             Action ID for this transaction. Will be returned.\n";


static int configure_module(void)
{
    struct ast_config *cfg = NULL;
    struct ast_variable *v;
    struct ast_flags config_flags = { 0 };
    struct ast_hostent ahp;
    struct hostent *hp;
    char *cat;
    const char *utype;
    struct rtmp_user *user;
    struct ast_variable *var;
    char *tmp;
    int index;
    char rule[30];
    const char *tosval;

    ALLOCATE_CAPABILITIES(rtmp_tech.capabilities);
    ADD_CAPABILITIES4(rtmp_tech.capabilities, AST_FORMAT_SPEEX,
            AST_FORMAT_SLINEAR, AST_FORMAT_ULAW, AST_FORMAT_ALAW);

    default_tls_cfg.enabled = 0;  /* Default: Disable TLS */

    if (default_tls_cfg.certfile)
        ast_free(default_tls_cfg.certfile);
    if (default_tls_cfg.cipher)
        ast_free(default_tls_cfg.cipher);
    if (default_tls_cfg.cafile)
        ast_free(default_tls_cfg.cafile);
    if (default_tls_cfg.capath)
        ast_free(default_tls_cfg.capath);

    default_tls_cfg.certfile = ast_strdup(AST_CERTFILE);  /*XXX Not sure if this is useful */
    default_tls_cfg.cipher = ast_strdup("");
    default_tls_cfg.cafile = ast_strdup("");
    default_tls_cfg.capath = ast_strdup("");

    /* load config file */
    if (!(cfg = ast_config_load(config_file, config_flags)))
    {
        return -1;
    }

    memset(&bindaddr, 0, sizeof(bindaddr));
    memset(&bindaddr2, 0, sizeof(bindaddr2));


    /* Copy the default jb config over global_jbconf */
    memcpy(&global_jbconf, &default_jbconf, sizeof(struct ast_jb_conf));

    v = ast_variable_browse(cfg, "general");

    /* Seed initial tos value */
    tosval = ast_variable_retrieve(cfg, "general", "tos");
    if (tosval)
    {
        if (ast_str2tos(tosval, &qos.tos))
            ast_log(LOG_WARNING, "Invalid tos value, refer to QoS documentation\n");
    }
    /* Seed initial cos value */
    tosval = ast_variable_retrieve(cfg, "general", "cos");
    if (tosval)
    {
        if (ast_str2cos(tosval, &qos.cos))
            ast_log(LOG_WARNING, "Invalid cos value, refer to QoS documentation\n");
    }

    for (; v; v = v->next)
    {
        /* handle jb conf */
        if (!ast_jb_read_conf(&global_jbconf, v->name, v->value))
            continue;
        else if (!strcasecmp(v->name, "server"))
            ast_copy_string(rtmpserverstr, v->value, sizeof(rtmpserverstr));
        else if (!strcasecmp(v->name, "port"))
            rtmpport = atoi(v->value);
        else if (!strcasecmp(v->name, "application"))
            ast_copy_string(application, v->value, sizeof(application));
        else if (!strcasecmp(v->name, "bindaddr"))
        {
            if (!(hp = ast_gethostbyname(v->value, &ahp)))
            {
                ast_log(LOG_WARNING, "Invalid address: %s\n", v->value);
            }
            else
            {
                bindaddr.sin_family = AF_INET;
                memcpy(&bindaddr.sin_addr, hp->h_addr, sizeof(bindaddr.sin_addr));
            }
        }
        else if (!strcasecmp(v->name, "bindaddr2"))
        {
            if (!(hp = ast_gethostbyname(v->value, &ahp)))
            {
                ast_log(LOG_WARNING, "Invalid address: %s\n", v->value);
            }
            else
            {
                bindaddr2.sin_family = AF_INET;
                memcpy(&bindaddr2.sin_addr, hp->h_addr, sizeof(bindaddr2.sin_addr));
            }
        }
        else if (!strcasecmp(v->name, "bindport"))
        {
            if (sscanf(v->value, "%d", &bindport) == 1)
            {
                bindaddr.sin_port = htons(bindport);
                if (bindaddr2.sin_port == 0)
                    bindaddr2.sin_port = htons(bindport);
            }
            else
            {
                ast_log(LOG_WARNING, "Invalid port number '%s' at line %d of %s\n",
                        v->value, v->lineno, config_file);
            }
        }
        else if (!strcasecmp(v->name, "bindport2"))
        {
            if (sscanf(v->value, "%d", &bindport2) == 1)
            {
                bindaddr2.sin_port = htons(bindport2);
            }
            else
            {
                ast_log(LOG_WARNING, "Invalid port number '%s' at line %d of %s\n",
                        v->value, v->lineno, config_file);
            }
        }
        else if (!strcasecmp(v->name, "bindport3"))
        {
            if (sscanf(v->value, "%d", &bindport3) == 1)
            {
                //bindaddr3.sin_port = htons(bindport3);
            }
            else
            {
                ast_log(LOG_WARNING, "Invalid port number '%s' at line %d of %s\n",
                        v->value, v->lineno, config_file);
            }
        }
        else if (!strcasecmp(v->name, "applicationlocal"))
            ast_copy_string(applicationlocal, v->value, sizeof(applicationlocal));
        else if (!strcasecmp(v->name, "context"))
            ast_copy_string(context, v->value, sizeof(context));
        else if (!strcasecmp(v->name, "redirect"))
            ast_copy_string(redirect, v->value, sizeof(redirect));
        else if (!strcasecmp(v->name, "httpurl"))
            ast_copy_string(httpurl, v->value, sizeof(httpurl));
        else if (!strcasecmp(v->name, "realtime"))
        {
            if (!strcasecmp(v->value, "yes"))
                ast_copy_string(realtimename, "rtmpusers", sizeof(realtimename));
            else if (!strcasecmp(v->value, "no"))
                realtimename[0] = 0;
            else
                ast_copy_string(realtimename, v->value, sizeof(realtimename));
        }
        else if (!strcasecmp(v->name, "tcpbuffer"))
        {
            int value;

            value = atoi(v->value);
            if (value < 0)
                value = 0;

            tcpbuffer = value;
        }
        else if (!strcasecmp(v->name, "maxaudiobuffer"))
        {
            int value;

            value = atoi(v->value);
            if (value < 0)
                value = 0;

            maxaudiobuffer = value;
        }
        else if (!strcasecmp(v->name, "maxvideobuffer"))
        {
            int value;

            value = atoi(v->value);
            if (value < 0)
                value = 0;

            maxvideobuffer = value;
        }
        else if (!strcasecmp(v->name, "maxaudiopipe"))
        {
            int value;

            value = atoi(v->value);
            if (value < 0)
                value = 0;

            maxaudiopipe = value;
        }
        else if (!strcasecmp(v->name, "maxvideopipe"))
        {
            int value;

            value = atoi(v->value);
            if (value < 0)
                value = 0;

            maxvideopipe = value;
        }
        else if (!strcasecmp(v->name, "autochunksize"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                autochunksize = 1;
            }
            else
            {
                autochunksize = 0;
            }
        }
        else if (!strcasecmp(v->name, "tcpkeepalive"))
        {
            int value;

            value = atoi(v->value);
            if (value < 0)
                value = 0;

            tcpkeepalive = value;
        }
        else if (!strcasecmp(v->name, "tcpnodelay"))
        {
            if (!strcasecmp(v->value, "yes"))
                tcpnodelay = 1;
            else
                tcpnodelay = 0;
        }
        else if (!strcasecmp(v->name, "antiburst"))
        {
            int value;

            if (!strcasecmp(v->value, "yes"))
            {
                antiburst = 600;
            }
            else
            {
                value = atoi(v->value);
                if (value < 0)
                    value = 0;

                antiburst = value;
            }
        }
        else if (!strcasecmp(v->name, "maxsilence"))
        {
            int value;

            value = atoi(v->value);
            if (value < 0)
                value = 0;

            maxsilence = value;
        }
        else if (!strcasecmp(v->name, "autousers"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                autousers = 1;
            }
            else
            {
                autousers = 0;
            }
        }
        else if (!strcasecmp(v->name, "multipleusers"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                multipleusers = 1;
            }
            else
            {
                multipleusers = 0;
            }
        }
        else if (!strcasecmp(v->name, "lastuniqueuser"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                lastuniqueuser = 1;
            }
            else
            {
                lastuniqueuser = 0;
            }
        }
        else if (!strcasecmp(v->name, "hangupusers"))
        {
            if (!strcasecmp(v->value, "no"))
            {
                hangupusers = 0;
            }
            else
            {
                hangupusers = 1;
            }
        }
        else if (!strcasecmp(v->name, "videosupport"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                videosupport = 1;
                ADD_CAPABILITIES1(rtmp_tech.capabilities, AST_FORMAT_H263);
            }
            else
            {
                videosupport = 0;
            }
        }
        else if (!strcasecmp(v->name, "textsupport"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                textsupport = 1;
            }
            else
            {
                textsupport = 0;
            }
        }
        else if (!strcasecmp(v->name, "nospeexsilence"))
        {
            if (!strcasecmp(v->value, "force"))
            {
                nospeexsilence = 2;
            }
            else if (!strcasecmp(v->value, "yes"))
            {
                nospeexsilence = 1;
            }
            else
            {
                nospeexsilence = 0;
            }
        }
        else if (!strcasecmp(v->name, "reserved"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                reserved = 1;
            }
            else
            {
                reserved = 0;
            }
        }
        else if (!strcasecmp(v->name, "recordraw"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                record_raw = 1;
            }
            else
            {
                record_raw = 0;
            }
        }
        else if (!strcasecmp(v->name, "record"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                record_flv = 1;
            }
            else
            {
                record_flv = 0;
            }
        }
        else if (!strcasecmp(v->name, "spy_picture"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                char path[PATH_MAX] = {"/var/spool/asterisk/monitor/spy"};

                spy_picture = 1;
                // Create dir
                if (ast_config_AST_MONITOR_DIR != NULL) {
                    sprintf(path, "%s/spy", ast_config_AST_MONITOR_DIR);
                }
                ast_verbose( "Create folder : %s (if needed)\n",path);
                ast_mkdir(path, 0777);
            }
            else
            {
                spy_picture = 0;
            }
        }
        else if (!strcasecmp(v->name, "supportparsing_oldcnx"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                mSupportCnxParseOldVersion = 1;
            }
            else
            {
                mSupportCnxParseOldVersion = 0;
            }
        }
        else if (!strcasecmp(v->name, "chunksbuffer"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                chunksbuffer = 10;
            }
            else
            {
                int value;

                value = atoi(v->value);
                if (value < 0)
                    value = 0;

                chunksbuffer = value;
            }
        }
        else if (!strcasecmp(v->name, "audiotimestamp"))
        {
            if (!strcasecmp(v->value, "absolute"))
            {
                audiotimestamp = 1;
            }
            else if (!strcasecmp(v->value, "relative"))
            {
                audiotimestamp = 2;
            }
            else if (!strcasecmp(v->value, "none"))
            {
                audiotimestamp = 0;
            }
            else
            {
                audiotimestamp = 0;
            }
        }
        else if (!strcasecmp(v->name, "videotimestamp"))
        {
            if (!strcasecmp(v->value, "absolute"))
            {
                videotimestamp = 1;
            }
            else if (!strcasecmp(v->value, "relative"))
            {
                videotimestamp = 2;
            }
            else if (!strcasecmp(v->value, "none"))
            {
                videotimestamp = 0;
            }
            else
            {
                videotimestamp = 0;
            }
        }
        else if (!strcasecmp(v->name, "functionthreaded"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                functionthreaded = 1;
            }
            else
            {
                functionthreaded = 0;
            }
        }
        else if (!strcasecmp(v->name, "debug"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                debug = 1;
            }
            else if (!strcasecmp(v->value, "dump"))
            {
                debug = 1;
            }
            else
            {
                int value;

                value = atoi(v->value);
                if (value < 0)
                    value = 0;

                debug = value;
            }
        }
        else if (!strcasecmp(v->name, "dumptimings"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                dumptimings = 1;
            }
            else
            {
                dumptimings = 0;
            }
        }
        else if (!strcasecmp(v->name, "dumpstats"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                dumpstats = 1;
            }
            else if (!strcasecmp(v->value, "dump"))
            {
                dumpstats = 1;
            }
            else
            {
                int value;

                value = atoi(v->value);
                if (value < 0)
                    value = 0;

                dumpstats = value;
            }
        }
        else if (!strcasecmp(v->name, "events"))
        {
            if (!strcasecmp(v->value, "yes"))
            {
                events = 1;
            }
            else
            {
                events = 0;
            }
        }
        else if (!strcasecmp(v->name, "tlsenable"))
        {
            default_tls_cfg.enabled = ast_true(v->value) ? TRUE : FALSE;
        }
        else if (!strcasecmp(v->name, "tlscertfile"))
        {
            ast_free(default_tls_cfg.certfile);
            default_tls_cfg.certfile = ast_strdup(v->value);
        }
        else if (!strcasecmp(v->name, "tlscipher"))
        {
            ast_free(default_tls_cfg.cipher);
            default_tls_cfg.cipher = ast_strdup(v->value);
        }
        else if (!strcasecmp(v->name, "tlscafile"))
        {
            ast_free(default_tls_cfg.cafile);
            default_tls_cfg.cafile = ast_strdup(v->value);
        }
        else if (!strcasecmp(v->name, "tlscapath"))
        {
            ast_free(default_tls_cfg.capath);
            default_tls_cfg.capath = ast_strdup(v->value);
        }
        else if (!strcasecmp(v->name, "tlsverifyclient"))
        {
            ast_set2_flag(&default_tls_cfg.flags, ast_true(v->value),
                    AST_SSL_VERIFY_CLIENT);
        }
        else if (!strcasecmp(v->name, "tlsdontverifyserver"))
        {
            ast_set2_flag(&default_tls_cfg.flags, ast_true(v->value),
                    AST_SSL_DONT_VERIFY_SERVER);
        }
        else if (!strcasecmp(v->name, "rtmfpenable"))
        {
            rtmfpenable = ast_true(v->value) ? TRUE : FALSE;
        }
        else if (!strcasecmp(v->name, "maxoverwrite"))
        {
            int value;

            value = atoi(v->value);
            if (value < 0)
                value = 0;

            maxoverwrites = value;
        }

    }


    cat = NULL;
    while ((cat = ast_category_browse(cfg, cat)))
    {
        if (strcasecmp(cat, "general"))
        {
            utype = ast_variable_retrieve(cfg, cat, "type");
            if (utype)
            {
                if (!strcasecmp(utype, "user") || !strcasecmp(utype, "user") ||
                        !strcasecmp(utype, "friend"))
                {
                    user = build_user(cat, ast_variable_browse(cfg, cat), NULL, 0);
                    if (user)
                    {
                        ao2_t_link(users, user, "Adding new user");
                    }
                }
                else if (strcasecmp(utype, "user"))
                {
                    ast_log(LOG_WARNING, "Unknown type '%s' for '%s' in %s\n", utype, cat,
                            config_file);
                }
            }
            else
                ast_log(LOG_WARNING, "Section '%s' lacks type\n", cat);
        }
    }

    for (index = 0; index < MAX_RULES; index++)
    {
        sprintf(rule, "rule%d", index);
        var = (void *)ast_variable_browse(cfg, rule);
        if (!var)
        {
            rtmp_rules[index].number[0] = 0;
            rtmp_rules[index].number[0] = 0;
        }
        else
        {
            tmp = (void *)ast_variable_retrieve(cfg, rule, "name");
            if (tmp)
            {
                strcpy(rtmp_rules[index].name, tmp);
            }
            else
            {
                rtmp_rules[index].name[0] = 0;
            }

            tmp = (void *)ast_variable_retrieve(cfg, rule, "number");
            if (tmp)
            {
                strcpy(rtmp_rules[index].number, tmp);
            }
            else
            {
                rtmp_rules[index].number[0] = 0;
            }

            tmp = (void *)ast_variable_retrieve(cfg, rule, "dest");
            if (tmp)
            {
                strcpy(rtmp_rules[index].dest, tmp);
            }
            else
            {
                rtmp_rules[index].dest[0] = 0;
            }
        }
    }

    ast_config_destroy(cfg);

#ifdef GEOIP_H
    if (gi)
    {
        GeoIP_delete(gi);
        gi = GeoIP_open("/usr/lib/asteriskrtmp/GeoIPCity.dat", GEOIP_INDEX_CACHE);

        if (gi == NULL)
        {
            ast_log(LOG_NOTICE, "Cannot load GeoIP database file.\n");
        }
    }
#endif

    return 0;
}

static int load_module(void)
{
    char buf[100];

    I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
    ast_mutex_lock(&rtmplock);
    I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n");

    ast_verbose("RTMP channel loading...\n");

    threadt =
            ao2_t_container_alloc(hash_dialog_size, threadt_hash_cb, threadt_cmp_cb,
                    "Allocate threadt table.");

    users =
            ao2_t_container_alloc(HASH_USER_SIZE, user_hash_cb, user_cmp_cb,
                    "Allocate users table.");

    connections =
            ao2_t_container_alloc(hash_connections_size, connections_hash_cb,
                    connections_cmp_cb,
                    "Allocate RTMP channels");

    bindport = DEFAULT_RTMP_PORT;
    bindport2 = (-1);
    bindport3 = (-1);

    memset(&bindaddr, 0, sizeof(bindaddr));
    bindaddr.sin_family = AF_INET;
    bindaddr.sin_addr.s_addr = INADDR_ANY;
    bindaddr.sin_port = htons(bindport);

    if (default_tls_cfg.certfile)
        ast_free(default_tls_cfg.certfile);
    if (default_tls_cfg.cipher)
        ast_free(default_tls_cfg.cipher);
    if (default_tls_cfg.cafile)
        ast_free(default_tls_cfg.cafile);
    if (default_tls_cfg.capath)
        ast_free(default_tls_cfg.capath);

    default_tls_cfg.certfile = ast_strdup(AST_CERTFILE);
    default_tls_cfg.cipher = ast_strdup("");
    default_tls_cfg.cafile = ast_strdup("");
    default_tls_cfg.capath = ast_strdup("");

    rtmpserverstr[0] = 0;

    if (configure_module())
    {
        ast_log(LOG_WARNING, "Unable to load config %s\n", config_file);
        return AST_MODULE_LOAD_DECLINE;
    }

    if (!(sched = SCHED_CREATE))
    {
        ast_log(LOG_ERROR, "Failed to create scheduler thread\n");
        return AST_MODULE_LOAD_FAILURE;
    }

    // Reset the statistics
    {
        int i;
        for (i = 0; i < STATS_MAX; i++)
            stats[i] = 0;
    }

#ifdef RTMP_FFMPEG
    /* must be called before using avcodec lib */
    avcodec_init();

    /* register all the codecs */
    avcodec_register_all();
#endif

    /* Make sure we can register our channel type */
    if (ast_channel_register(&rtmp_tech))
    {
        ast_log(LOG_ERROR, "Unable to register channel class %s\n", type);
        return -1;
    }

    ast_cli_register_multiple(rtmp_cli, ARRAY_LEN(rtmp_cli));

    ast_custom_function_register(&rtmpuser_function);
    ast_custom_function_register(&rtmpconnection_function);
    AST_MANAGER_REGISTER2("RTMPSend", EVENT_FLAG_SYSTEM, manager_rtmpsend, NULL,
            "Send a RTMP message", mandescr_rtmpsend);

    ast_mutex_init(&streamslock);

    memset(&rtmpserver, 0, sizeof(rtmpserver));
    rtmpserver.sin_family = AF_INET;

    if (!rtmpserverstr[0])
    rtmpserver.sin_addr.s_addr = INADDR_ANY;
    else
    rtmpserver.sin_addr.s_addr = inet_addr(rtmpserverstr);

    rtmpserver.sin_port = htons(bindport);

    /* Start TCP server */
    memset(&rtmp_tcp_desc.local_address, 0, sizeof(rtmp_tcp_desc.local_address));
    SET_ADDRESS_LENGTH(rtmp_tcp_desc.local_address.len);

    if (bindaddr.sin_family == AF_INET)
    {
        memcpy(&rtmp_tcp_desc.local_address, &bindaddr, sizeof(bindaddr));
        SET_TCPTLS_SESSION_PORT(rtmp_tcp_desc.local_address, bindport);
    }
    else
    {
        SET_TCPTLS_SESSION_PORT(rtmp_tcp_desc.local_address, bindport);
        SET_TCPTLS_SESSION_FAMILY(rtmp_tcp_desc.local_address, AF_INET);
    }

    struct in_addr temp_addr;

    TCPTLS_SESSION_ADDRESS(rtmp_tcp_desc.local_address, temp_addr.s_addr);
    inet_ntop(AF_INET, &temp_addr, buf, sizeof(buf));
    ast_verb(2, "RTMP is Listening on %s:%d\n",
            buf, TCPTLS_SESSION_PORT(rtmp_tcp_desc.local_address));
    //
    ast_tcptls_server_start(&rtmp_tcp_desc);

    if (bindaddr2.sin_family == AF_INET || (bindport != bindport2))
    {
        memset(&rtmp_tls_desc.local_address, 0, sizeof(rtmp_tls_desc.local_address));
        memset(&rtmp_tls_desc.old_address,   0, sizeof(rtmp_tls_desc.old_address));

        if (bindaddr2.sin_family == AF_INET)
        {
            ast_verb(2, "Use second port %d\n", bindport2);
            memcpy(&rtmp_tls_desc.local_address, &bindaddr2, sizeof(bindaddr2));
        }
        else
        {
            ast_verb(2, "Set TLS port %d\n", bindport2);
            /*ast_log(LOG_VERBOSE, "dbgjyg: INET=%Xh family=%Xh addrlen=%d\n", AF_INET, rtmp_tls_desc.local_address.ss.ss_family, rtmp_tls_desc.local_address.len);*/
            SET_TCPTLS_SESSION_FAMILY(rtmp_tls_desc.local_address, AF_INET);
            SET_ADDRESS_LENGTH(rtmp_tls_desc.local_address.len);

            /* !!!!!!!!!!!!
               A TESTER il fallait htons avec 1.6 et pas pour 1.8 !!!!
             */
            SET_TCPTLS_SESSION_PORT(rtmp_tls_desc.local_address, bindport2);
        }

        /* Start TLS server if needed */
        if (default_tls_cfg.enabled)
        {
            ast_verb(2, "RTMP TLS/SSL mode enabled.\n");
            rtmp_tls_desc.tls_cfg = &rtmp_tls_cfg;
            memcpy(rtmp_tls_desc.tls_cfg, &default_tls_cfg, sizeof(default_tls_cfg));

            if (ast_ssl_setup(rtmp_tls_desc.tls_cfg))
            {
                ast_tcptls_server_start(&rtmp_tls_desc);
                if (default_tls_cfg.enabled && rtmp_tls_desc.accept_fd == (-1))
                {
                    ast_log(LOG_ERROR,
                            "RTMP TLS Server start failed. Not listening on TLS socket.\n");
                    rtmp_tls_desc.tls_cfg = NULL;
                }
                else {
                    TCPTLS_SESSION_ADDRESS(rtmp_tls_desc.local_address, temp_addr.s_addr);
                    inet_ntop(AF_INET, &temp_addr, buf, sizeof(buf));
                    ast_verb(2, "RTMP  Listening on %s:%d (bis)\n", buf,
                            TCPTLS_SESSION_PORT(rtmp_tls_desc.local_address));
                }
            }
            else
            {
                ast_log(LOG_WARNING, "RTMP TLS server did not load because of errors.\n");
                if (!rtmp_tls_desc.tls_cfg->enabled) {
                    ast_log(LOG_VERBOSE,
                            "RTMP TLS was disabled!\n");
                }
                rtmp_tls_desc.tls_cfg = NULL;
            }

        }
        else
        {
            rtmp_tls_desc.tls_cfg = NULL;
            ast_tcptls_server_start(&rtmp_tls_desc);
            ast_verb(2, "RTMP is Listening on %s:%d (bis)\n", buf,
                    TCPTLS_SESSION_PORT(rtmp_tls_desc.local_address));
        }

    }

    if (rtmfpenable)
    {
        struct sockaddr_in sin;
        int res;

        rtmpudpsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (rtmpudpsock < 0)
        {
            ast_log(LOG_ERROR, "Unable to create network socket: %s\n",
                    strerror(errno));
        }
        else
        {
            const int reuseFlag = 1;

            if (setsockopt(rtmpudpsock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuseFlag,
                    sizeof reuseFlag) < 0)
            {
                ast_log(LOG_WARNING, "Error setting SO_REUSEADDR on sockfd '%d'\n",
                        rtmpudpsock);
            }

            memset(&sin, 0, sizeof(sin));
            //sin.sin_family = AF_INET;
            //sin.sin_port = htons(bindport3);
            //inet_aton(v->value, &sin.sin_addr);
            memcpy(&sin, &bindaddr, sizeof(bindaddr));
            if (bindport3 > 0)
                sin.sin_port = htons(bindport3);

            res = bind(rtmpudpsock, &sin, sizeof(struct sockaddr_in));
            if (res < 0)
            {
                ast_log(LOG_ERROR, "Can't bind: %s\n", strerror(errno));
                close(rtmpudpsock);
                rtmpudpsock = (-1);
            }
            else
            {
                ast_netsock_set_qos(rtmpudpsock, qos.tos, qos.cos, "RTMFP");

                ast_enable_packet_fragmentation(rtmpudpsock);

                inet_ntop(AF_INET, &sin.sin_addr, buf, sizeof(buf));

                ast_verb(2, "RTMFP Listening on %s:%d\n",
                        buf, ntohs(sin.sin_port));

                ast_pthread_create_background(&netthreadid, NULL, network_thread, NULL);
            }
        }
    }

    ast_realtime_require_field(realtimename,
            "name", RQ_CHAR, 80,
            "secret", RQ_CHAR, 80,
            "ipaddr", RQ_CHAR, 15,
            "port", RQ_UINTEGER2, 5,
            "regseconds", RQ_INTEGER4, 11,
            "defaultuser", RQ_CHAR, 10,
            "fullcontact", RQ_CHAR, 35,
            "regserver", RQ_CHAR, 20,
            "useragent", RQ_CHAR, 20, "lastms", RQ_INTEGER4, 11, SENTINEL);

#ifdef GEOIP_H
    if (gi == NULL)
        gi = GeoIP_open("/usr/lib/asteriskrtmp/GeoIPCity.dat", GEOIP_INDEX_CACHE);

    if (gi == NULL)
    {
        ast_log(LOG_ERROR, "Error opening database GeoIP\n");
    }
#endif

    // Create to check TCP connection
#ifdef _CHECK_CNX_RTMP_
    ast_pthread_create_background(&monitor_thread, NULL, monitor_process_thread,
            NULL);
#endif


    I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
    ast_mutex_unlock(&rtmplock);

    return AST_MODULE_LOAD_SUCCESS;
}

/*! \brief Reload module */
static int reload(void)
{
    I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
    ast_mutex_lock(&rtmplock);
    I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n");

    configure_module();
    //ast_sched_dump(sched);

    I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
    ast_mutex_unlock(&rtmplock);

    return 0;
}

static int unload_module(void)
{
    struct ao2_iterator aux;
    struct rtmp_pvt *p;
    struct rtmp_threadinfo *th;
    struct ao2_iterator i;

    I6DEBUG(10, NULL, "Mutex lock 'rtmplock'.\n");
    ast_mutex_lock(&rtmplock);
    I6DEBUG(10, NULL, "Mutex locked 'rtmplock'.\n");

#ifdef GEOIP_H
    if (gi)
        GeoIP_delete(gi);
#endif

    // Close monitor thread
#ifdef _CHECK_CNX_RTMP_
    pthread_kill(monitor_thread, SIGURG);
    pthread_join(monitor_thread, NULL);
#endif

    //ast_sched_dump(sched->context);

    ast_cli_unregister_multiple(rtmp_cli, ARRAY_LEN(rtmp_cli));

    /* First, take us out of the channel loop */
    ast_channel_unregister(&rtmp_tech);

    /* Kill TCP/TLS server threads */
    if (rtmp_tcp_desc.master)
        ast_tcptls_server_stop(&rtmp_tcp_desc);

    /* Kill TCP/TLS server threads */
    if (rtmp_tls_desc.master)
        ast_tcptls_server_stop(&rtmp_tls_desc);

    if (netthreadid != AST_PTHREADT_NULL)
    {
        //AST_LIST_LOCK(&frame_queue);
        pthread_cancel(netthreadid);
        //AST_LIST_UNLOCK(&frame_queue);
        pthread_join(netthreadid, NULL);
    }

    if (default_tls_cfg.certfile)
        ast_free(default_tls_cfg.certfile);
    if (default_tls_cfg.cipher)
        ast_free(default_tls_cfg.cipher);
    if (default_tls_cfg.cafile)
        ast_free(default_tls_cfg.cafile);
    if (default_tls_cfg.capath)
        ast_free(default_tls_cfg.capath);

    /* Kill all existing TCP/TLS threads */
    i = ao2_iterator_init(threadt, 0);
    while ((th =
            ao2_t_iterator_next(&i,
                    "iterate through tcp threads for 'rtmp show tcp'")))
    {
        pthread_t thread = th->threadid;
        th->stop = 1;
        pthread_kill(thread, SIGURG);
        pthread_join(thread, NULL);
        ao2_t_ref(th, -1, "decrement ref from iterator");
    }
    ao2_iterator_destroy(&i);

    /* Close all streams if they have an owner */
    aux = ao2_iterator_init(connections, 0);
    while ((p = ao2_t_iterator_next(&aux, "iterate thru RTMP streams")))
    {
        if (p->owner)
            ast_softhangup(p->owner, AST_SOFTHANGUP_APPUNLOAD);
        ao2_t_ref(p, -1, "toss RTMP stream ptr from iterator_next");
    }
    ao2_iterator_destroy(&aux);

    /* Destroy all users */
    aux = ao2_iterator_init(users, 0);
    while ((p = ao2_t_iterator_next(&aux, "iterate thru RTMP users")))
    {
        ao2_t_ref(p, -1, "Destroying user");
    }
    ao2_iterator_destroy(&aux);

    ao2_t_callback(connections, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE, NULL, NULL, "Unallocate connections");
    ao2_t_ref(connections, -1, "Destroying connections");

    ao2_t_callback(users, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE, NULL, NULL, "Unallocate users");
    ao2_t_ref(users, -1,  "Destroying users");

    ao2_t_callback(threadt, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE, NULL, NULL, "Unallocate threadt");
    ao2_t_ref(threadt, -1, "Destroying threadt");

    ast_custom_function_unregister(&rtmpuser_function);
    ast_custom_function_unregister(&rtmpconnection_function);

    if (realtimename[0])
        ast_unload_realtime(realtimename);

    if (sched)
    {
        SCHED_DESTROY(sched);
    }

    I6DEBUG(10, NULL, "Mutex unlock 'rtmplock'.\n");
    ast_mutex_unlock(&rtmplock);

    return 0;
}

#undef AST_BUILDOPT_SUM
#define AST_BUILDOPT_SUM ""

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT,
                "RTMP Channel Driver",.load = load_module,.unload = unload_module,.reload =
                reload,);