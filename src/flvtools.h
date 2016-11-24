/*! \file
 *
 * \brief  Tools to manage FLV format file managment
 *
 * \author JYG <jyg@ulex.fr>
 *
 */




#ifndef _FLVTOOLS_H_
#define _FLVTOOLS_H_

#include "asterisk.h"
#include "asterisk/frame.h"
#include "asterisk/utils.h"
#include "asterisk/paths.h"

/*** Marcos Rev02 ***/
#define AST_4           10400
#define AST_6           10600
#define AST_6_1         10601
#define AST_8           10800
#define AST_11			110000
#define AST_12			120000

/********************/

/*
 * Define for FLV file structure
 */
#define FLV_HEADER_SIZE     9
#define FLV_HEADER_TAG_SIZE 11
#define FLV_SIZE_DOUBLE     9   // type+64bits

/*
 * FLV define
 */

#define FLV_TYPE_AUDIO  0x08
#define FLV_TYPE_VIDEO  0x09
#define FLV_TYPE_META   0x12

#define FLV_SAMPLESIZE_8BITS    8
#define FLV_SAMPLESIZE_16BITS   16


/* offsets for packed values */
#define FLV_AUDIO_SAMPLESSIZE_OFFSET 1
#define FLV_AUDIO_SAMPLERATE_OFFSET  2
#define FLV_AUDIO_CODECID_OFFSET     4

#define FLV_VIDEO_FRAMETYPE_OFFSET   4

/* bitmasks to isolate specific values */
#define FLV_AUDIO_CHANNEL_MASK    0x01
#define FLV_AUDIO_SAMPLESIZE_MASK 0x02
#define FLV_AUDIO_SAMPLERATE_MASK 0x0c
#define FLV_AUDIO_CODECID_MASK    0xf0

#define FLV_VIDEO_CODECID_MASK    0x0f
#define FLV_VIDEO_FRAMETYPE_MASK  0xf0



enum {
    FLV_HEADER_FLAG_HASVIDEO = 1,
    FLV_HEADER_FLAG_HASAUDIO = 4,
};


enum {
    FLV_MONO   = 0,
    FLV_STEREO = 1,
};

enum {
    FLV_SAMPLESSIZE_8BIT  = 0,
    FLV_SAMPLESSIZE_16BIT = 1 << FLV_AUDIO_SAMPLESSIZE_OFFSET,
};

enum {
    FLV_SAMPLERATE_SPECIAL = 0, /**< signifies 5512Hz and 8000Hz in the case of NELLYMOSER */
    FLV_SAMPLERATE_11025HZ = 1 << FLV_AUDIO_SAMPLERATE_OFFSET,
    FLV_SAMPLERATE_22050HZ = 2 << FLV_AUDIO_SAMPLERATE_OFFSET,
    FLV_SAMPLERATE_44100HZ = 3 << FLV_AUDIO_SAMPLERATE_OFFSET,
};

enum {
    FLV_CODECID_PCM                  = 0,
    FLV_CODECID_ADPCM                = 1 << FLV_AUDIO_CODECID_OFFSET,
    FLV_CODECID_MP3                  = 2 << FLV_AUDIO_CODECID_OFFSET,
    FLV_CODECID_PCM_LE               = 3 << FLV_AUDIO_CODECID_OFFSET,
    FLV_CODECID_NELLYMOSER_16KHZ_MONO = 4 << FLV_AUDIO_CODECID_OFFSET,
    FLV_CODECID_NELLYMOSER_8KHZ_MONO = 5 << FLV_AUDIO_CODECID_OFFSET,
    FLV_CODECID_NELLYMOSER           = 6 << FLV_AUDIO_CODECID_OFFSET,
    FLV_CODECID_G711_ALAW            = 7 << FLV_AUDIO_CODECID_OFFSET,
    FLV_CODECID_G711_ULAW            = 8 << FLV_AUDIO_CODECID_OFFSET,
    FLV_CODECID_RESERVED             = 9 << FLV_AUDIO_CODECID_OFFSET,
    FLV_CODECID_AAC                  = 10<< FLV_AUDIO_CODECID_OFFSET,
    FLV_CODECID_SPEEX                = 11<< FLV_AUDIO_CODECID_OFFSET,
};

enum {
    FLV_CODECID_H263    = 2,
    FLV_CODECID_SCREEN  = 3,
    FLV_CODECID_VP6     = 4,
    FLV_CODECID_VP6A    = 5,
    FLV_CODECID_SCREEN2 = 6,
    FLV_CODECID_H264    = 7,
};

enum {
    FLV_FRAME_KEY        = 1 << FLV_VIDEO_FRAMETYPE_OFFSET,
    FLV_FRAME_INTER      = 2 << FLV_VIDEO_FRAMETYPE_OFFSET,
    FLV_FRAME_DISP_INTER = 3 << FLV_VIDEO_FRAMETYPE_OFFSET,
};
enum {
    FLV_FRAMETYPE_KEY        = 1, // keyframe (for AVC, a seekable frame)
    FLV_FRAMETYPE_INTER,          // inter frame (for AVC, a nonseekable frame)
    FLV_FRAMETYPE_DISP_INTER,     // disposable inter frame (H.263 only)
    FLV_FRAMETYPE_GENERATED_KEY,  // generated keyframe (reserved for server use only)
    FLV_FRAMETYPE_VIDEOINFO,      // video info/command frame
};


typedef enum {
    AMF_DATA_TYPE_NUMBER      = 0x00,
    AMF_DATA_TYPE_BOOL        = 0x01,
    AMF_DATA_TYPE_STRING      = 0x02,
    AMF_DATA_TYPE_OBJECT      = 0x03,
    AMF_DATA_TYPE_NULL        = 0x05,
    AMF_DATA_TYPE_UNDEFINED   = 0x06,
    AMF_DATA_TYPE_REFERENCE   = 0x07,
    AMF_DATA_TYPE_MIXEDARRAY  = 0x08,
    AMF_DATA_TYPE_OBJECT_END  = 0x09,
    AMF_DATA_TYPE_ARRAY       = 0x0a,
    AMF_DATA_TYPE_DATE        = 0x0b,
    AMF_DATA_TYPE_LONG_STRING = 0x0c,
    AMF_DATA_TYPE_UNSUPPORTED = 0x0d,
} AMFDataType;


// Return code
typedef enum {
    FLV_ERROR_FD = -100,
    FLV_ERROR_WRITING,
    FLV_ERROR_WRITING_HDR,
    FLV_ERROR_DATA,
    FLV_ERROR_BAD_TYPE,
    FLV_ERROR_BAD_AUDIO_CODECID,
    FLV_ERROR_BAD_SAMPLERATE,
    FLV_ERROR_FILENAME,

    FLV_ERROR = -1,
    FLV_OK = 0,
    FLV_ERROR_LAST
} eFlvReturnCode;


/*
 * Data structure needed by FLV module
 */
typedef struct {
    int fd; // file descriptor for file
    uint8_t audio_tag;
    uint8_t video_tag;
    uint8_t meta_tag;
    int fileSizeOffset;
    int filesize;
    int durationOffset;
    int audioDataSize;
    int sampleRate;
    int sampleSize;
    int vcodec;
    int acodec;
    int stereo;
    int pictureSizeGetted;
    int widthOffset;
    int heigthOffset;
} stFLV_data;

#ifdef RTMP_FFMPEG
/*
 * Prototyp definition
 */
#if ASTERISK_VERSION_NUM < AST_11
eFlvReturnCode FLV_init(stFLV_data *pCtx, int channels, int sampleSize, int sampleRate, int codec,
                        int videoFrameType, char *pFilename);
#else
eFlvReturnCode FLV_init(stFLV_data *pCtx, int channels, int sampleSize, int sampleRate, struct ast_format codec,
                        int videoFrameType, char *pFilename);
#endif
eFlvReturnCode FLV_close(stFLV_data *pCtx, long iDuration, int iWidth, int iHeigth);
eFlvReturnCode FLV_writeHeader(stFLV_data *pCtx);
eFlvReturnCode FLV_writePkt(stFLV_data *pCtx, int type, int timestamp, int len, uint8_t *pData);
eFlvReturnCode FLV_getPictureSize(int *pWidth, int *pHeight, uint8_t *pData) ;
int FLV_getPictureType(uint8_t *pData) ;

int writeBmpImage(FILE *fp, unsigned char *buff, int len, int width, int height) ;
void put_jpeg_yuv420p_file(FILE *fp, unsigned char *image[3], int width, int height, int quality);
#endif

#endif // _FLVTOOLS_H_

