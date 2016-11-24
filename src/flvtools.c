/*! \file
 *
 * \brief  Tools to manage FLV format file managment
 *
 * \author JYG <jyg@ulex.fr>
 *
 */

#ifdef RTMP_FFMPEG

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <libavcodec/avcodec.h>
//#include <libavutil/internal.h>
//#include <libavcodec/get_bits.h>

#include "flvtools.h"

/*** Marcos Rev02 ***/
#define AST_4           10400
#define AST_6           10600
#define AST_6_1         10601
#define AST_8           10800
#define AST_11			110000
#define AST_12			120000

/********************/



/*
 * Static Global variable
 */



/*
 * Static prototype
 */
 #if ASTERISK_VERSION_NUM < AST_11
static uint8_t getVideoFlags(stFLV_data *pCtx, int codecid, int frameType);
static uint8_t getAudioFlags(stFLV_data *pCtx, int channels, int sampleSize, int sampleRate, int codecid);
#else
static uint8_t getVideoFlags(stFLV_data *pCtx, struct ast_format codecid, int frameType);
static uint8_t getAudioFlags(stFLV_data *pCtx, int channels, int sampleSize, int sampleRate, struct ast_format codecid);
#endif
static uint8_t getTag(stFLV_data *pCtx, int type);
//static int64_t av_dbl2int(double d);
static void FLV_writeHeaderMetaData(stFLV_data *pCtx);





/*
 * Macro defines
 */
#define WR_8(p, val)    *(p)++ = val;
#define WR_16(p, val)   {WR_8(p, (val >> 8));WR_8(p, val);}
#define WR_24(p, val)   {WR_16(p, (val >> 8));WR_8(p, val);}
#define WR_32(p, val)   {WR_8(p, (val >> 24));  \
                        WR_8(p, (val >> 16));  \
                        WR_8(p, (val >> 8));\
                        WR_8(p, (val));}

#define WR_64(p, val)  WR_32(p, (uint32_t)(val >> 32)); WR_32(p, (uint32_t)(val & 0xffffffff));


#define AMF_STRING(p, string) {\
    size_t len = strlen(string);\
    WR_16(p, len);\
    memcpy(p, string, len);\
    p+=len;\
}

#define AMF_DOUBLE(p, value) {\
    WR_8(p, AMF_DATA_TYPE_NUMBER);\
    WR_64(p, av_dbl2int(value));\
}

#define AMF_BOOL(p, value) {\
    WR_8(p, AMF_DATA_TYPE_BOOL);\
    WR_8(p, !!value);\
}







/*! \fn int FLV_init(int channels, int sampleSize, int sampleRate, int codec)
 *  \brief save packet info to create header tags
 *  \param channels channels number 0=mono 1=stereo
 *  \param sampleSize sample size 8 or 16 bits
 *  \param sampleRate sample rate in Hz
 *  \param codec audio and video codec used
 *  \param videoFrameType video frame type keyframe, inter frame, disposable inter frame
 *  \param pFilename record filename
 */
 // Marcos Rev95: Difference header
#if ASTERISK_VERSION_NUM < AST_11
eFlvReturnCode FLV_init(stFLV_data *pCtx,
                        int channels, int sampleSize, int sampleRate, int codec, int videoFrameType,
                        char *pFilename)
#else
eFlvReturnCode FLV_init(stFLV_data *pCtx,
                        int channels, int sampleSize, int sampleRate, struct ast_format codec, int videoFrameType,
                        char *pFilename)
#endif
{
    if (pCtx == NULL){
        ast_log(LOG_ERROR, "FLV ctx NULL!\n");
        return FLV_ERROR_FD;
    }

    if (pFilename == NULL)
    {
        ast_log(LOG_ERROR, "filename NULL!\n");
        return FLV_ERROR_FILENAME;
    }

    if (pCtx->fd != 0)
    {
        ast_log(LOG_ERROR, "WARNING: fd not null!\n");
    }

    ast_debug(6, " ch %d splSize %d splRate %d codec %s frmType %d file %s\n",
              channels, sampleSize, sampleRate, GET_FORMAT_NAME(codec), videoFrameType, pFilename); // Marcos Rev96: show format name instead of hexadecimal value

    // Open file
    if ( (pCtx->fd = open(pFilename, O_CREAT|O_WRONLY|O_TRUNC, 0664)) <= 0) {
        ast_log(LOG_ERROR, "Cannot create file %s : %s\n", pFilename, strerror(errno));
        return FLV_ERROR_WRITING_HDR;
    }
    else {
        ast_debug(3, "Record FLV file %s fd %d\n", pFilename, pCtx->fd);

        // Initialize context
        if ((sampleSize == 0) || (sampleRate == 0))
        {
            if (COMPARE_VARFORMAT_IDFORMAT(codec, AST_FORMAT_SPEEX)) { // Marcos Rev97, Original codec & AST_FORMAT_SPEEX
                if (!sampleSize)
                    sampleSize = FLV_SAMPLESIZE_16BITS;
                if (!sampleRate)
                    sampleRate = 11025;
            }
            else {
                if (!sampleSize)
                    sampleSize = FLV_SAMPLESIZE_8BITS;
                if (!sampleRate)
                    sampleRate = 8000;
            }
            ast_debug(3, "Force sample size %d sample rate %d\n", sampleSize, sampleRate);
        }
        pCtx->filesize      = 0;
        pCtx->audioDataSize = 0;
        pCtx->sampleRate    = sampleRate;
        pCtx->sampleSize    = sampleSize;
        pCtx->stereo        = channels==2?1:0;
        pCtx->pictureSizeGetted = 0;

        if ((pCtx->audio_tag = getAudioFlags(pCtx, channels, sampleSize, sampleRate, codec)) < 0)
            return pCtx->audio_tag;

        if ((pCtx->video_tag = getVideoFlags(pCtx, codec, videoFrameType)) < 0)
            return pCtx->video_tag;

        // Create header
        if (FLV_writeHeader(pCtx) != FLV_OK){
            ast_log(LOG_ERROR, "Failed to write header flv file %s\n", pFilename);
            close(pCtx->fd);
            pCtx->fd = 0;
            return FLV_ERROR_WRITING_HDR;
        }
        else {
            ast_debug(3, "FLV: tag audio 0x%X video 0x%02X\n", pCtx->audio_tag, pCtx->video_tag);
            return FLV_OK;
        }
    }



}

/*! \fn int FLV_close()
 *  \brief ended file
 */
eFlvReturnCode FLV_close(stFLV_data *pCtx, long iDuration, int iWidth, int iHeigth)
{
    if ((pCtx == NULL) || (pCtx->fd <= 0)) {
        ast_log(LOG_ERROR, "bad ctx\n");
        return FLV_ERROR_FD;
    }

    // Write file size if non null
    if (pCtx->filesize > 0)
    {
        char buffer[10];
        char *p=buffer;

        lseek(pCtx->fd, pCtx->fileSizeOffset, SEEK_SET);
        AMF_DOUBLE(p, pCtx->filesize);
        if (write(pCtx->fd, buffer, FLV_SIZE_DOUBLE)  < 0) {
            ast_log(LOG_ERROR, "FLV_close: Failed to write filesize %s\n", strerror(errno));
            return FLV_ERROR_WRITING;
        }
        ast_debug(3, "FLV: filesize %d written\n", pCtx->filesize);
    }

    if (pCtx->audioDataSize > 0)
    {
        char buffer[10];
        char *p=buffer;
        int duration=0;

        if (iDuration != 0) // pCtx->sampleRate != 0)
        {
            //duration = pCtx->audioDataSize / pCtx->sampleRate;
            //duration = ast_tvdiff_ms(ast_tvnow(), client->timestart) / 1000;
            duration = (iDuration/1000)+1;
            lseek(pCtx->fd, pCtx->durationOffset, SEEK_SET);
            AMF_DOUBLE(p, duration);
            if (write(pCtx->fd, buffer, FLV_SIZE_DOUBLE)  < 0) {
                ast_log(LOG_ERROR, "FLV_close: Failed to write filesize %s\n", strerror(errno));
                return FLV_ERROR_WRITING;
            }
            ast_debug(3, "FLV: duration %d written\n", duration);
        }
    }
    if (iWidth != 0)
    {
        char buffer[10];
        char *p=buffer;

        lseek(pCtx->fd, pCtx->widthOffset, SEEK_SET);
        AMF_DOUBLE(p, iWidth);
        if (write(pCtx->fd, buffer, FLV_SIZE_DOUBLE)  < 0) {
            ast_log(LOG_ERROR, "FLV_close: Failed to write width %s\n", strerror(errno));
            return FLV_ERROR_WRITING;
        }
    }
    if (iHeigth != 0)
    {
        char buffer[10];
        char *p=buffer;

        lseek(pCtx->fd, pCtx->heigthOffset, SEEK_SET);
        AMF_DOUBLE(p, iHeigth);
        if (write(pCtx->fd, buffer, FLV_SIZE_DOUBLE)  < 0) {
            ast_log(LOG_ERROR, "FLV_close: Failed to write heigth %s\n", strerror(errno));
            return FLV_ERROR_WRITING;
        }
    }
    ast_debug(3, "FLV: picture size %dx%d written\n", iWidth, iHeigth);

    close(pCtx->fd);
    pCtx->fd = 0;
    pCtx->pictureSizeGetted = 0;


    return FLV_OK;
}


/*! \fn int FLV_writeHeader(stFLV_data *pCtx)
 *  \brief Writes header info in FLV file with filedescriptor \a pCtx->fd.
 *  \param pCtx->fd The descriptor to write to.
 */
eFlvReturnCode FLV_writeHeader(stFLV_data *pCtx)
{
    char header[FLV_HEADER_SIZE] = {0};
    uint32_t size = 0;

    if ((pCtx == NULL) || (pCtx->fd <= 0)) {
        ast_log(LOG_ERROR, "FLV_writeHeader: bad ctx\n");
        return FLV_ERROR_FD;
    }

    /*
     * FLV header is compose like this :
     *      3 bytes : signature "FLV"
     *      uint8   : Version = 1
     *      uint8   : Flag : bitmask: 4 is audio, 1 is video (5=audio+video)
     *      uint32  : offset : size of header => 9
     */
    header[0] = 'F';
    header[1] = 'L';
    header[2] = 'V';
    header[3] = 0x01;    // Version
    header[4] = 0x05;    // We always create audio & video stream
    header[8] = 0x09;

    // Write header
    if (write(pCtx->fd, header, FLV_HEADER_SIZE)  < 0) {
        ast_log(LOG_ERROR, "FLV_writeHeader: Failed to write header %s\n", strerror(errno));
        return FLV_ERROR_WRITING;
    }
    pCtx->filesize += FLV_HEADER_SIZE;

    // Write first tag size to 0
    size = 0;
    if (write(pCtx->fd, (char*)&size, sizeof(uint32_t))  < 0) {
        ast_log(LOG_ERROR, "FLV_writeHeader: Failed to write size in header %s\n", strerror(errno));
        return FLV_ERROR_WRITING;
    }
    pCtx->filesize += sizeof(uint32_t);

    // Need to add META-DATA for file info
    FLV_writeHeaderMetaData(pCtx);

    return FLV_OK;
}

/*! \fn int FLV_writePkt(stFLV_data *pCtx, int type, int len, char *pData)
 *  \brief Writes packet data in FLV file with filedescriptor \a pCtx->fd.
 *  \param pCtx->fd The descriptor to write to.
 *  \param type stream type of data.
 *  \param len data len.
 *  \param pData packet data.
 */
eFlvReturnCode FLV_writePkt(stFLV_data *pCtx, int type, int timestamp, int len, uint8_t *pData)
{
    uint8_t tagHdr[FLV_HEADER_TAG_SIZE+1];// +1 for first pkt byte
    uint8_t *p = tagHdr;
    int hdrSize=0;

    if ((pCtx == NULL) || (pCtx->fd <= 0)) {
        ast_log(LOG_ERROR, "FLV_writePkt: bad ctx\n");
        return FLV_ERROR_FD;
    }
    if (len <= 0) {
        ast_log(LOG_ERROR, "FLV_writePkt: bad data length\n");
        return FLV_ERROR_DATA;
    }
    if ((type != FLV_TYPE_AUDIO) && (type != FLV_TYPE_VIDEO) && (type != FLV_TYPE_META)) {
        ast_log(LOG_ERROR, "FLV_writePkt: bad type %d \n", type);
        return FLV_ERROR_BAD_TYPE;
    }



    /*
     * Create TAG
     */
    WR_8 (p, type);
    if ((type == FLV_TYPE_AUDIO) || (type == FLV_TYPE_VIDEO) ){
        WR_24(p, (len+1));            // length + tag
    }
    else {
        WR_24(p, len);
    }
    WR_24(p, timestamp);          // timestamp
    if (timestamp > 0xFFFFFF) {
        WR_8(p, (timestamp & 0xFF000000)>>24);
    }
    else {
        WR_8(p, 0);
    }
    WR_24(p, 0);                  // streamid

    // The first byte of an audio&video tag is specific
    if ((type == FLV_TYPE_AUDIO) || (type == FLV_TYPE_VIDEO) )
    {
        WR_8(p, getTag(pCtx, type));  // first byte
        hdrSize = FLV_HEADER_TAG_SIZE+1;
    }
    else
        hdrSize = FLV_HEADER_TAG_SIZE;


    // Write header tag + specific tag for audio&video
    if (write(pCtx->fd, tagHdr, hdrSize)  < 0) {
        ast_log(LOG_ERROR, "Failed to write tag %s\n", strerror(errno));
        return FLV_ERROR_WRITING;
    }
    pCtx->filesize += hdrSize;
    //ast_debug(6, " wrote %d bytes for header tag %s\n", FLV_HEADER_TAG_SIZE+1, type==FLV_TYPE_AUDIO?"audio":"video");

    // Write data
    if (write(pCtx->fd, pData, len)  < 0) {
        ast_log(LOG_ERROR, "Failed to write data %s\n", strerror(errno));
        return FLV_ERROR_WRITING;
    }
    pCtx->filesize += len;
    if (type == FLV_TYPE_VIDEO)
        pCtx->audioDataSize += len;
    ///ast_debug(6, " wrote %d data len for data %s\n", len, type==FLV_TYPE_AUDIO?"audio":"video");

    // write previous size
    p = tagHdr;
    WR_32(p, (len+hdrSize));

    if (write(pCtx->fd, tagHdr, 4) < 0) {
        ast_log(LOG_ERROR, "Failed to size %s\n", strerror(errno));
        return FLV_ERROR_WRITING;
    }
    pCtx->filesize += 4;
    //ast_debug(6, " wrote %d datasize for tag %s\n", (len+FLV_HEADER_TAG_SIZE+1), type==FLV_TYPE_AUDIO?"audio":"video");

    ast_debug(3, "FLV: %d bytes %s written timestamp %d (tag 0x%02X size %d) in fd %d\n",
              len, type==FLV_TYPE_AUDIO?"audio":"video", timestamp, getTag(pCtx, type),
              len+FLV_HEADER_TAG_SIZE, pCtx->fd);

    return FLV_OK;
}






/*! \fn int FLV_writeHeaderMetaData(int fd)
 *  \brief add meta-data in file to add file inforamtions
 *  \param fd fiel descriptor
 */
static void FLV_writeHeaderMetaData(stFLV_data *pCtx)
{
    char buffer[2048];
    char *ptr = buffer;
    char *pBegin = buffer;
    char *pLgTag = buffer + 1; // point on tag data len
    char *pStartData;          // begining of data
    int sizeWr = 0;


        /* write meta_tag */
    WR_8(ptr, FLV_TYPE_META);         // tag type META
    WR_24(ptr, 0);          // write size at the end
    WR_32(ptr, 0);          // time stamp
    WR_24(ptr, 0);          // stream id

    /* now data of data_size size */
    pStartData = ptr;

    /* first event name as a string */
    WR_8(ptr, AMF_DATA_TYPE_STRING);
    AMF_STRING(ptr, "onMetaData"); // 12 bytes

    /* mixed array (hash) with size and string/type/data tuples */
    WR_8(ptr, AMF_DATA_TYPE_MIXEDARRAY);
    WR_32(ptr, 12); // 12 elt: duration+width+height+video

    AMF_STRING(ptr, "duration");
    // Get current position & offset to save duration at the end
    pCtx->durationOffset = lseek(pCtx->fd, 0, SEEK_CUR) + ptr-pBegin;
    AMF_DOUBLE(ptr, 0.0);

    AMF_STRING(ptr, "width");
    // Get current position & offset to save width
    pCtx->widthOffset = lseek(pCtx->fd, 0, SEEK_CUR) + ptr-pBegin;
    AMF_DOUBLE(ptr, 176.0);

    AMF_STRING(ptr, "height");
    // Get current position & offset to save width
    pCtx->heigthOffset = lseek(pCtx->fd, 0, SEEK_CUR) + ptr-pBegin;
    AMF_DOUBLE(ptr, 144.0);
    ast_debug(8, "FLV: write header: default picture size 176x144\n");

    AMF_STRING(ptr, "videodatarate");
    AMF_DOUBLE(ptr, 0.0);

    AMF_STRING(ptr, "framerate");
    AMF_DOUBLE(ptr, 0.0);

    AMF_STRING(ptr, "videocodecid");
    AMF_DOUBLE(ptr, pCtx->vcodec); //  2);

    AMF_STRING(ptr, "audiodatarate");
    AMF_DOUBLE(ptr, 0.0);

    AMF_STRING(ptr, "audiosamplerate");
    AMF_DOUBLE(ptr, pCtx->sampleRate); //11025);

    AMF_STRING(ptr, "audiosamplesize");
    AMF_DOUBLE(ptr, pCtx->sampleSize); //8);

    AMF_STRING(ptr, "stereo");
    AMF_BOOL(ptr,  pCtx->stereo);//  0);


    AMF_STRING(ptr, "audiocodecid");
    AMF_DOUBLE(ptr, pCtx->acodec); //11);

    ast_debug(8, "FLV: write header: videodatarate=framerate=audiodatarate=0.0\n");
    ast_debug(8, "FLV: write header: audiocodecid=%d(%Xh) videocodecid=%d(%Xh)\n", pCtx->acodec, pCtx->acodec, pCtx->vcodec, pCtx->vcodec);
    ast_debug(8, "FLV: write header: sampleRate=%d(%Xh) sampleSize=%d(%Xh) stereo=%d\n", pCtx->sampleRate, pCtx->sampleSize, pCtx->stereo);

    AMF_STRING(ptr, "filesize");
    // Get current position to save filesize offset.
    pCtx->fileSizeOffset = lseek(pCtx->fd, 0, SEEK_CUR) + ptr-pBegin;
    AMF_DOUBLE(ptr, 0.0); // delayed write

    AMF_STRING(ptr, "");
    WR_8(ptr, AMF_DATA_TYPE_OBJECT_END);

    // write tag data len
    WR_24(pLgTag, (ptr-pStartData));


    // Calcul and write tag size
    sizeWr = ptr-pBegin;
    if (sizeWr > 0) {
        WR_32(ptr, sizeWr);
    }
    else{
        sizeWr = 0;
        WR_32(ptr, 0);
    }

    /*ast_log(LOG_ERROR, "-->dbgJYG: splSize %d splRate %d stereo %d acodec 0x%X vcodec 0x%X\n",
            pCtx->sampleSize, pCtx->sampleRate, pCtx->stereo, pCtx->acodec, pCtx->vcodec);*/

    ast_debug(3, " onMetaData %d bytes written\n", sizeWr );
    // write data + 4( = tagsize for previous tag)
    if (write(pCtx->fd, (char*)buffer, sizeWr+4)  < 0) {
        ast_log(LOG_ERROR, "Failed to write metaData for header %s\n", strerror(errno));
    }
    pCtx->filesize += sizeWr;


}

#if 0
/*! \fn int av_dbl2int(double d)
 *  \brief convert a double to int
 *  \param d double to convert
 */
static int64_t av_dbl2int(double d){
    int e;
    if     ( !d) return 0;
    else if(d-d) {
        return 0x7FF0000000000000LL + ((int64_t)(d<0)<<63) + (d!=d);
    }
    d= frexp(d, &e);
    return (int64_t)(d<0)<<63 | (e+1022LL)<<52 | (int64_t)((fabs(d)-0.5)*(1LL<<53));
}
#endif

/*! \fn int getTag(int type)
 *  \brief return tag type to use
 *  \param type packet type
 */
static uint8_t getTag(stFLV_data *pCtx, int type)
{
    switch(type)
    {
    case FLV_TYPE_AUDIO:
        return pCtx->audio_tag;
        break;
    case FLV_TYPE_VIDEO:
        return pCtx->video_tag;
        break;
    case FLV_TYPE_META:
        return pCtx->meta_tag;
        break;
    }
    return FLV_ERROR;
}


/*! \fn int getAudioFlags(int channels, int sampleSize, int sampleRate, int codec)
 *  \brief return audio flag to use in tag type
 *  \param channels channels number 0=mono 1=stereo
 *  \param sampleSize sample size 8 or 16 bits
 *  \param sampleRate sample rate in Hz
 *  \param codec codec used
 */
 #if ASTERISK_VERSION_NUM < AST_11
static uint8_t getAudioFlags(stFLV_data *pCtx, int channels, int sampleSize, int sampleRate, int codecid)
#else
static uint8_t getAudioFlags(stFLV_data *pCtx, int channels, int sampleSize, int sampleRate, struct ast_format codecid)
#endif
{
    uint8_t flags = 0;

    if (sampleSize == FLV_SAMPLESIZE_16BITS) {
        flags |= FLV_SAMPLESSIZE_16BIT;
    }
    else
        flags |= FLV_SAMPLESSIZE_8BIT;

    switch (sampleRate) {
    case  44100:
        flags |= FLV_SAMPLERATE_44100HZ;
        break;
    case  22050:
        flags |= FLV_SAMPLERATE_22050HZ;
        break;
    case    11025:
        flags |= FLV_SAMPLERATE_11025HZ;
        break;
    case     8000: //nellymoser only
    case     5512: //not mp3
        flags |= FLV_SAMPLERATE_SPECIAL;
        break;
        /*if(enc->codec_id != CODEC_ID_MP3){
            flags |= FLV_SAMPLERATE_SPECIAL;
            break;
        } */
    default:
        ast_debug(1, "unsupported sample rate %d. Force speex 11kHz\n", sampleRate);
        flags |= FLV_SAMPLERATE_11025HZ;
    }

    if (channels > 1) {
        flags |= FLV_STEREO;
    }

	// Marcos Rev89
	/* After realise that in the variable client->audiocodec (received here as "codecid") we are just
	going to store one format (the audio format) there's no sense to do the audio masking
	Original:
    int codec = codecid & AST_FORMAT_AUDIO_MASK;
    switch(codec){
	*/
	switch(FORMAT_VAR_TO_ID(codecid)){
	//
    case AST_FORMAT_SPEEX:
        flags |= FLV_CODECID_SPEEX;
        pCtx->acodec = FLV_CODECID_SPEEX >> FLV_AUDIO_CODECID_OFFSET;
        break;
    case AST_FORMAT_SLINEAR:
        //flags |= FLV_CODECID_PCM    | FLV_SAMPLESSIZE_16BIT;
        flags |= FLV_CODECID_PCM    | FLV_SAMPLESSIZE_8BIT;
        pCtx->acodec = FLV_CODECID_PCM >> FLV_AUDIO_CODECID_OFFSET;
        break;
    case AST_FORMAT_ALAW:
        flags |= FLV_CODECID_G711_ALAW  | FLV_SAMPLESSIZE_16BIT;
        pCtx->acodec = FLV_CODECID_G711_ALAW >> FLV_AUDIO_CODECID_OFFSET;
        break;
    case AST_FORMAT_ULAW:
        flags |= FLV_CODECID_G711_ULAW  | FLV_SAMPLESSIZE_16BIT;
        pCtx->acodec = FLV_CODECID_G711_ULAW >> FLV_AUDIO_CODECID_OFFSET;
        break;

    /*
    case CODEC_ID_NELLYMOSER:
        if (sampleRate == 8000) {
            flags |= FLV_CODECID_NELLYMOSER_8KHZ_MONO | FLV_SAMPLESSIZE_16BIT;
        } else {
            flags |= FLV_CODECID_NELLYMOSER | FLV_SAMPLESSIZE_16BIT;
        }
        break;
        */

    /*
    case CODEC_ID_ADPCM_SWF:
        flags |= FLV_CODECID_ADPCM | FLV_SAMPLESSIZE_16BIT;
        break;
    case CODEC_ID_PCM_S16LE:
        flags |= FLV_CODECID_RESERVED | FLV_SAMPLESSIZE_16BIT;
        break;
    case CODEC_ID_MP3:
        flags |= FLV_CODECID_MP3    | FLV_SAMPLESSIZE_16BIT;
        break;
    case 0:
        flags |= enc->codec_tag<<4;
        break;
        */
    default:
		// Marcos Rev91
		// Original: 	ast_debug(1, "unsupported audio codec id %d from 0x%X. Force SPEEX\n", codec, codecid);
		ast_debug(1, "unsupported audio codec %s. Force SPEEX\n",  GET_FORMAT_NAME(codecid));
        flags |= FLV_CODECID_SPEEX;
        pCtx->acodec = FLV_CODECID_SPEEX >> FLV_AUDIO_CODECID_OFFSET;
    }

    ast_debug(7, " FLV audio tag   0x%X from ch %d splSize %d splRate %d codecid %s\n",
              flags, channels, sampleSize, sampleRate,  GET_FORMAT_NAME(codecid)  );
    return (flags);
}

/*! \fn int getVideoFlags(int codec, int frameType)
 *  \brief return audio flag to use in tag type
 *  \param type of frame
 *  \param codec codec used
 *      codec id :
 *          FLV_CODECID_H263
 *          FLV_CODECID_SCREEN
 *          FLV_CODECID_VP6
 *          FLV_CODECID_VP6A
 *          FLV_CODECID_SCREEN2
 *          FLV_CODECID_H264
 *      frame type :
 *          FLV_FRAME_KEY
 *          FLV_FRAME_INTER
 *          FLV_FRAME_DISP_INTER
 */
 #if ASTERISK_VERSION_NUM < AST_11
static uint8_t getVideoFlags(stFLV_data *pCtx,  int codecid, int frameType)
#else
static uint8_t getVideoFlags(stFLV_data *pCtx,  struct ast_format codecid, int frameType)
#endif
{
    uint8_t flags = 0;
	// Marcos Rev90
	/* Since we realised that client->audiocodec (received here as "codecid") just stores the audio codec of the client,
	there's no video format inside this variable and it always goes to the default case, the switch has no sense.
	Original:
    int codec = codecid & AST_FORMAT_VIDEO_MASK;
    switch (codec)
    {
    case AST_FORMAT_H263:
    case AST_FORMAT_H263_PLUS:
        flags = FLV_CODECID_H263;
        pCtx->vcodec = FLV_CODECID_H263;
        break;
    case AST_FORMAT_H264:
        flags = FLV_CODECID_H264 | frameType;
        pCtx->vcodec = FLV_CODECID_H264;
        break;
    default:
        ast_debug(1, " unsupported video codec id %d from 0x%X. Force H263\n", codec, codecid);
        flags = FLV_CODECID_H263 | frameType;
        pCtx->vcodec = FLV_CODECID_H263;
    }
	*/
	flags = FLV_CODECID_H263 | frameType;
	pCtx->vcodec = FLV_CODECID_H263;
	//

    if ((frameType != FLV_FRAME_KEY) && (frameType != FLV_FRAME_INTER) && (frameType != FLV_FRAME_DISP_INTER))
    {
        ast_debug(1, " unsupported video frame type 0x%02X. Force FRAME KEY\n",frameType);
    }
    flags |= frameType;
    ast_debug(7, "  FLV video tag 0x%X from codecid %s frameType %d\n",
              flags,  GET_FORMAT_NAME(codecid), frameType );
    return (flags);

}


/*! \fn int getPictureSize(int codec, int frameType)
 *  \brief return audio flag to use in tag type
 *  \param pCtx FLV context
 *  \param pData data video frame
 *
 *  From flvdec.c of ffmpeg

    picture header
    if (get_bits_long(&s->gb, 17) != 1) {
        av_log(s->avctx, AV_LOG_ERROR, "Bad picture start code\n");
        return -1;
    }
    format = get_bits(&s->gb, 5);
    if (format != 0 && format != 1) {
        av_log(s->avctx, AV_LOG_ERROR, "Bad picture format\n");
        return -1;
    }
    s->h263_flv = format+1;
    s->picture_number = get_bits(&s->gb, 8);

    s->pict_type = AV_PICTURE_TYPE_I + get_bits(&s->gb, 2);

    // Get last 2bits of first 32 bits
    p32 = (uint32_t *)pData;
    p8  = pData+1;
 */
eFlvReturnCode FLV_getPictureSize(int *pWidth, int *pHeight, uint8_t *pData)
{
    int format, width=0, height=0;
    uint8_t *p8;
    uint16_t *p16;

    // Get last 2bits of first 32 bits
    p8  = pData+3;
    format = (((*p8) & 0x03) << 1) |  ( ((*(p8+1)) & 0x80) >> 7);

/*
    ast_log(LOG_ERROR, " -->dbgJYG: format=%d pData=0x%X p8=0x%X\n", format, pData, p8);
    ast_log(LOG_ERROR, " %02X %02X %02X %02X   %02X %02X %02X %02X \n",
            pData[0], pData[1], pData[2], pData[3],
            pData[4], pData[5], pData[6], pData[7]);
*/
    switch (format) {
    case 0:
        // Width is the fisrt 8bits and heigth next 8bits
        width  = ((*p8 & 0xEF) << 1) | ( (*(p8+1) & 0x80) >> 7);
        p8++;
        height = ((*p8 & 0xEF) << 1) | ( (*(p8+1) & 0x80) >> 7);
        break;
    case 1:
        // Width is the fisrt 16bits and heigth next 16bits
        p16 = (uint16_t*)p8;
        p8  = (uint8_t*) (p16+1);

        width  = ((*p16 & 0xEFFF) << 1) | (uint16_t) ( ( (*(p8+1) & 0x80) >> 7));
        p16++;
        p8  = (uint8_t*) (p16+1);
        height = width  = ((*p16 & 0xEFFF) << 1) | (uint16_t) ( ( (*(p8+1) & 0x80) >> 7));
        break;
    case 2:
        width = 352;
        height = 288;
        break;
    case 3:
        width = 176;
        height = 144;
        break;
    case 4:
        width = 128;
        height = 96;
        break;
    case 5:
        width = 320;
        height = 240;
        break;
    case 6:
        width = 160;
        height = 120;
        break;
    default:
        width = height = 0;
        break;
    }


    *pWidth  = width;
    *pHeight = height;
    return 0;
}

int FLV_getPictureType(uint8_t *pData)
{
    int format, width=0, height=0;
    uint8_t *p8;
    uint16_t *p16;
    uint16_t typefr;

    p8  = pData+3;
    /*format = (((*p8) & 0x03) << 1) |  ( ((*(p8+1)) & 0x80) >> 7);

    switch (format) {
    case 0:
        // Width is the fisrt 8bits and heigth next 8bits
        width  = ((*p8 & 0xEF) << 1) | ( (*(p8+1) & 0x80) >> 7);
        p8++;
        height = ((*p8 & 0xEF) << 1) | ( (*(p8+1) & 0x80) >> 7);
        break;
    case 1:
        // Width is the fisrt 16bits and heigth next 16bits
        p16 = (uint16_t*)p8;
        p8  = (uint8_t*) (p16+1);

        width  = ((*p16 & 0xEFFF) << 1) | (uint16_t) ( ( (*(p8+1) & 0x80) >> 7));
        p16++;
        p8  = (uint8_t*) (p16+1);
        height = width  = ((*p16 & 0xEFFF) << 1) | (uint16_t) ( ( (*(p8+1) & 0x80) >> 7));
        break;
    case 2:
        width = 352;
        height = 288;
        break;
    case 3:
        width = 176;
        height = 144;
        break;
    case 4:
        width = 128;
        height = 96;
        break;
    case 5:
        width = 320;
        height = 240;
        break;
    case 6:
        width = 160;
        height = 120;
        break;
    default:
        width = height = 0;
        break;
    } */


	typefr  = (uint16_t) ( ( (*(p8+1) & 0x60) >> 5));
	//ast_log(LOG_ERROR, " -->dbgJYG: format=%d typeframe=%d pData=0x%X p8=0x%X: %02X %02X\n",
	//		format, typefr, pData, p8, p8[0], p8[1]);
    return 1+typefr;
}



/*
 * Essai de fonction pour créer des fichiers images bases sur les images pleine h263
 * Non utilisé pour l'instant
 *
 * En attendant on enregistre un fichier flv avec juste une image pleine!
 */
#if 0
// !! NOT WORKING!
void decodeYUVtoRGB(int *rgba, unsigned char *yuv420sp, int width, int height)
{
    int frameSize = width * height;
    int i,j,yp;

    ast_debug(6, "YUV->RGB: %dx%d size %d\n", width, height, frameSize);

    for (j = 0, yp = 0; j < height; j++)
    {
        int uvp = frameSize + (j >> 1) * width, u = 0, v = 0;
        for (i = 0; i < width; i++, yp++) {
            int y = (0xff & ((int) yuv420sp[yp])) - 16;
            if (y < 0)
                y = 0;
            if ((i & 1) == 0) {
                v = (0xff & yuv420sp[uvp++]) - 128;
                u = (0xff & yuv420sp[uvp++]) - 128;
            }

            int y1192 = 1192 * y;
            int r = (y1192 + 1634 * v);
            int g = (y1192 - 833 * v - 400 * u);
            int b = (y1192 + 2066 * u);

            if (r < 0)
                r = 0;
            else if (r > 262143)
                r = 262143;
            if (g < 0)
                g = 0;
            else if (g > 262143)
                g = 262143;
            if (b < 0)
                b = 0;
            else if (b > 262143)
                b = 262143;

            // rgb[yp] = 0xff000000 | ((r << 6) & 0xff0000) | ((g >> 2) &
            // 0xff00) | ((b >> 10) & 0xff);
            // rgba, divide 2^10 ( >> 10)
            rgba[yp] = ((r << 14) & 0xff000000) | ((g << 6) & 0xff0000)
                    | ((b >> 2) | 0xff00);
        }
    }
}


int writeBmpImage(FILE *fp, unsigned char *buff, int len, int width, int height)
{
    char head[14] ={0};
    int *ptr;
    /*int *intArray;

    intArray = malloc(width * height);
    decodeYUVtoRGB(intArray, buff, width, height);

    len=width*height*sizeof(int);
    */
    // Create header
    head[0] = 'B';
    head[1] = 'M';

    ptr = (int*)&(head[2]);
    *ptr = len + 14; // write len

    ptr = (int*)&(head[10]);
    *ptr = 15; // write offset of data


    if (fwrite( head, 1, 14, fp   ) <= 0)
    {
       ast_log(LOG_ERROR, "Failed to write header bmp file %s\n", strerror(errno));
       //free(intArray);
       return -1;
    }

    // write data
    if (fwrite( buff /*(char*)intArray*/, 1, len, fp   ) <= 0)
    {
       ast_log(LOG_ERROR, "Failed to write %d bytes to bmp file: %s\n", len, strerror(errno));
       //free(intArray);
       return -1;
    }
    ast_debug(6, "BmpFile: %d bytes wrote\n", len);
    fflush(fp);
    //free(intArray);
    return 0;
}


#include <jpeglib.h>
#include <jerror.h>

/* put_jpeg_yuv420p_file converts an YUV420P coded image to a jpeg image and writes
 * it to an already open file.
 * Inputs:
 * - image is the image in YUV420P format.
 * - width and height are the dimensions of the image
 * - quality is the jpeg encoding quality 0-100%
 * Output:
 * - The jpeg is written directly to the file given by the file pointer fp
 * Returns nothing
 */
void put_jpeg_yuv420p_file(FILE *fp, unsigned char *image[3], int width, int height, int quality)
{
	int i,j;

	JSAMPROW y[16],cb[16],cr[16]; // y[2][5] = color sample of row 2 and pixel column 5; (one plane)
	JSAMPARRAY data[3]; // t[0][2][5] = color sample 0 of row 2 and column 5

	struct jpeg_compress_struct cinfo;
	struct jpeg_error_mgr jerr;

    ast_debug(6, "jpeg create %dx%d img file\n", width, height);


	data[0] = y;
	data[1] = cb;
	data[2] = cr;

	cinfo.err = jpeg_std_error(&jerr);  // errors get written to stderr

	jpeg_create_compress(&cinfo);
	cinfo.image_width = width;
	cinfo.image_height = height;
	cinfo.input_components = 3;
	jpeg_set_defaults(&cinfo);

	jpeg_set_colorspace(&cinfo, JCS_YCbCr);

	cinfo.raw_data_in = TRUE; // supply downsampled data
#if JPEG_LIB_VERSION >= 70
#warning using JPEG_LIB_VERSION >= 70
    cinfo.do_fancy_downsampling = FALSE;  // Fix segfault with v7
#endif
	cinfo.comp_info[0].h_samp_factor = 2;
	cinfo.comp_info[0].v_samp_factor = 2;
	cinfo.comp_info[1].h_samp_factor = 1;
	cinfo.comp_info[1].v_samp_factor = 1;
	cinfo.comp_info[2].h_samp_factor = 1;
	cinfo.comp_info[2].v_samp_factor = 1;

	jpeg_set_quality(&cinfo, quality, TRUE);
	cinfo.dct_method = JDCT_FASTEST;

	jpeg_stdio_dest(&cinfo, fp);  	  // data written to file
	jpeg_start_compress(&cinfo, TRUE);


    for (j = 0; j < height; j += 16) {
        for (i = 0; i < 16; i++) {
            y[i] = image[0] + cinfo.image_width * (i + j);
			// need to handle other chroma subsampling
            if (i % 2 == 0) {
                cb[i / 2] = image[1] + width*height + width/2*((i+j)/2);
                cr[i / 2] = image[2] + width*height + width*height/4 + width/2*((i+j)/2);
            }
        }
        ast_debug(9, "jpeg: treat %d line\n",j);
        jpeg_write_raw_data(&cinfo, data, 16);
    }

/*
	for (j=0;j<height;j+=16) {
		for (i=0;i<16;i++) {
			y[i] = image + width*(i+j);
			if (i%2 == 0) {
				cb[i/2] = image + width*height + width/2*((i+j)/2);
				cr[i/2] = image + width*height + width*height/4 + width/2*((i+j)/2);
			}
		}
        ast_debug(9, "jpeg: treat %d line\n",j);
		jpeg_write_raw_data(&cinfo, data, 16);
	}
*/
	jpeg_finish_compress(&cinfo);
	jpeg_destroy_compress(&cinfo);
    ast_debug(6, "jpeg creation ended\n");

}

        /*FILE * fpJpeg;
      char filename[100];

      //FLV_SET_FILENAME(filename, "spy");
      sprintf(filename, "/var/www/monitor/test.bmp");
      fpJpeg = fopen (filename, "wb");
      if (fpJpeg != NULL)
      {
        //unsigned char *yuv_data[3];
        //unsigned char *pTmp;
        I6DEBUG(4,client, "Spy in %s\n", filename);
        //void put_jpeg_yuv420p_file(FILE *fp, unsigned char *image, int width, int height, int quality)
        // YUV are stored => YYYYUUVV
        /-*pTmp = client->buffer + 1;
        yuv_data[0] = pTmp;
        pTmp += client->pictureOut_width;
        yuv_data[1] = pTmp;
        pTmp += client->pictureOut_width/2;
        yuv_data[2] = pTmp;

        //(unsigned char *) (client->buffer + 1)
        put_jpeg_yuv420p_file(fpJpeg, yuv_data ,
                              client->pictureOut_width, client->pictureOut_heigth, 100);
         *-/
        writeBmpImage(fpJpeg, (unsigned char *) (client->buffer + 1), client->bufferLen,client->pictureOut_width, client->pictureOut_heigth) ;
        fclose(fpJpeg);
      }
      else
      {
        RTMP_VERBOSE(client, "failed to open %s\n", filename);
      }
         */


#endif // if 0 essai de fonction




#if 0

On ne peut pas utiliser les fct get_bits() parce que la compil genere une erreur
    un des includes inclus config.h hors ce fichier est genere a la compil de ffmpeg
    donc il n existe pas qd dans l export de la machine d integration !!!


/*! \fn int getPictureSize(int codec, int frameType)
 *  \brief return audio flag to use in tag type
 *  \param pCtx FLV context
 *  \param pData data video frame
 *
 *  From flvdec.c of ffmpeg

    picture header
    if (get_bits_long(&s->gb, 17) != 1) {
        av_log(s->avctx, AV_LOG_ERROR, "Bad picture start code\n");
        return -1;
    }
    format = get_bits(&s->gb, 5);
    if (format != 0 && format != 1) {
        av_log(s->avctx, AV_LOG_ERROR, "Bad picture format\n");
        return -1;
    }
    s->h263_flv = format+1;
    s->picture_number = get_bits(&s->gb, 8);

    // Get last 2bits of first 32 bits
    p32 = (uint32_t *)pData;
    p8  = pData+1;

    format = (((*p32) & 0x3) << 1) |  ( ((*p8) & 0x80) >> 7);
 */
eFlvReturnCode FLV_getPictureSize(int *pWidth, int *pHeight, uint8_t *pData)
{
    int format, width=0, height=0;
    int tmp1, tmp2;
    //uint32_t *p32;
    //uint8_t *p8;
    GetBitContext bitsCtx;

    // init bits ctx size max read for picture size is 30+3+ 2x16 => 96 bits
    init_get_bits(&bitsCtx, pData, 96);

    // Zap 30 bits
    tmp1   = get_bits(&bitsCtx, 30);
    format = get_bits(&bitsCtx, 3);

    switch (format) {
    case 0:
        width = get_bits(&bitsCtx, 8);
        height = get_bits(&bitsCtx, 8);
        break;
    case 1:
        width = get_bits(&bitsCtx, 16);
        height = get_bits(&bitsCtx, 16);
        break;
    case 2:
        width = 352;
        height = 288;
        break;
    case 3:
        width = 176;
        height = 144;
        break;
    case 4:
        width = 128;
        height = 96;
        break;
    case 5:
        width = 320;
        height = 240;
        break;
    case 6:
        width = 160;
        height = 120;
        break;
    default:
        width = height = 0;
        break;
    }

    *pWidth  = width;
    *pHeight = height;


    return 0;
}


/*! \fn int getPictureSize(int codec, int frameType)
 *  \brief return audio flag to use in tag type
 *  \param pCtx FLV context
 *  \param pData data video frame
 */
static int getPictureSize(stFLV_data *pCtx, int dataLen, uint8_t *pData)
{
    AVCodec *decoder;
    AVCodecContext *decoderCtx;
    AVFrame        *decoderPic;

    decoderCtx = avcodec_alloc_context();
    decoder    = avcodec_find_decoder(CODEC_ID_FLV1);

    if (avcodec_open(decoderCtx, decoder) < 0){
        return FLV_ERROR;
    }

    // Decode frame to get size
    {
        AVPacket avpkt;
        int got_picture;

        decoderPic = avcodec_alloc_frame();
        av_init_packet(&avpkt);
        avpkt.data = pData;
        avpkt.size = dataLen;

        avpkt.flags = AV_PKT_FLAG_KEY;
        avcodec_decode_video2(decoderCtx, decoderPic, &got_picture, &avpkt);

        /* Check size */
        ast_debug(7, "  Frame size %dx%d\n", decoderCtx->width, decoderCtx->height);
        pCtx->pictureSizeGetted = 1;
    }

    return FLV_OK;
}
#endif

#endif

