<!-- saved from url=(0014)about:internet -->
<html lang="en">

<!--
Smart developers always View Source.

This application was built using Adobe Flex, an open source framework
for building rich Internet applications that get delivered via the
Flash Player or to desktops via Adobe AIR.

Learn more about Flex at http://flex.org
// -->

<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />

<!--  BEGIN Browser History required section -->
<link rel="stylesheet" type="text/css" href="history/history.css" />
<!--  END Browser History required section -->

<title></title>
<script src="AC_OETags.js" language="javascript"></script>

<!--  BEGIN Browser History required section -->
<script src="history/history.js" language="javascript"></script>
<!--  END Browser History required section -->

<style>
body { margin: 0px; overflow:hidden }
</style>
<script language="JavaScript" type="text/javascript">
<!--
// -----------------------------------------------------------------------------
// Globals
// Major version of Flash required
var requiredMajorVersion = 10;
// Minor version of Flash required
var requiredMinorVersion = 0;
// Minor version of Flash required
var requiredRevision = 22;
// -----------------------------------------------------------------------------
// -->
</script>
</head>

<body scroll="no">

<script language="JavaScript" type="text/javascript">
<!--
// Version check for the Flash Player that has the ability to start Player Product Install (6.0r65)
var hasProductInstall = DetectFlashVer(6, 0, 65);

// Version check based upon the values defined in globals
var hasRequestedVersion = DetectFlashVer(requiredMajorVersion, requiredMinorVersion, requiredRevision);

// For flashphone fullscreen get the window browser size to pass it to flashphone
var viewportwidth;
var viewportheight;

if ('fullscreen' == '<?php echo $_REQUEST['look']; ?>')
{
    // the more standards compliant browsers (mozilla/netscape/opera/IE7) use window.innerWidth and window.innerHeight
    if (typeof window.innerWidth != 'undefined')
    {
      viewportwidth = window.innerWidth,
      viewportheight = window.innerHeight
    }

    // IE6 in standards compliant mode (i.e. with a valid doctype as the first line in the document)

    else if (typeof document.documentElement != 'undefined'
     && typeof document.documentElement.clientWidth !=
     'undefined' && document.documentElement.clientWidth != 0)
    {
       viewportwidth = document.documentElement.clientWidth,
       viewportheight = document.documentElement.clientHeight
    }

    // older versions of IE

    else
    {
       viewportwidth = document.getElementsByTagName('body')[0].clientWidth,
       viewportheight = document.getElementsByTagName('body')[0].clientHeight
    }
    //document.write('<p>Your viewport width is '+viewportwidth+'x'+viewportheight+'</p>');
    viewportwidth = viewportwidth - 20;
    viewportheight= viewportheight- 20;
}
else
{
    viewportwidth  = 530;
    viewportheight = 332;
}

 //"flashVars", "bench=<?php echo $_REQUEST['bench']; ?>&defVideoUse=<?php echo $_REQUEST['defVideoUse']; ?>&authName=<?php echo $_REQUEST['authName']; ?>&authPass=<?php echo $_REQUEST['authPass']; ?>&gatewayURL=<?php echo $_REQUEST['gatewayURL']; ?>&videoSize=<?php echo $_REQUEST['videoSize']; ?>&encodeQuality=<?php echo $_REQUEST['encodeQuality']; ?>&videoQuality=<?php echo $_REQUEST['videoQuality']; ?>&videoBandwidth=<?php echo $_REQUEST['videoBandwidth']; ?>&videoFps=<?php echo $_REQUEST['videoFps']; ?>&look=<?php echo $_REQUEST['look']; ?>&targetURL=<?php echo $_REQUEST['targetURL']; ?>&autoCall=<?php echo $_REQUEST['autoCall']; ?>&autoRecall=<?php echo $_REQUEST['autoReCall']; ?>&autoConnect=<?php echo $_REQUEST['autoConnect']; ?>&autoAnswer=<?php echo $_REQUEST['autoAnswer']; ?>",

<?php
   $params="";

   $params .= "look=" . $_REQUEST['look'];
   if (isset($_REQUEST['defVideoUse']))
      $params .= "&defVideoUse=" . $_REQUEST['defVideoUse'];
   if (isset($_REQUEST['authName']))
      $params .= "&authName=" . $_REQUEST['authName'];
   if (isset($_REQUEST['authPass']))
      $params .= "&authPass=" . $_REQUEST['authPass'];
   if (isset($_REQUEST['gatewayURL']))
      $params .= "&gatewayURL=" . $_REQUEST['gatewayURL'];
   if (isset($_REQUEST['videoSize']))
      $params .= "&videoSize=" . $_REQUEST['videoSize'];
   if (isset($_REQUEST['encodeQuality']))
      $params .= "&encodeQuality=" . $_REQUEST['encodeQuality'];
   if (isset($_REQUEST['videoQuality']))
      $params .= "&videoQuality=" . $_REQUEST['videoQuality'];
   if (isset($_REQUEST['videoBandwidth']))
      $params .= "&videoBandwidth=" . $_REQUEST['videoBandwidth'];
   if (isset($_REQUEST['videoFps']))
      $params .= "&videoFps=" . $_REQUEST['videoFps'];
   if (isset($_REQUEST['targetURL']))
      $params .= "&targetURL=" . $_REQUEST['targetURL'];
   if (isset($_REQUEST['autoCall']))
      $params .= "&autoCall=" . $_REQUEST['autoCall'];
   if (isset($_REQUEST['autoRecall']))
      $params .= "&autoRecall=" . $_REQUEST['autoRecall'];
   if (isset($_REQUEST['autoConnect']))
      $params .= "&autoConnect=" . $_REQUEST['autoConnect'];
   if (isset($_REQUEST['bench']) && $_REQUEST['bench']!="0")
      $params .= "&bench=" . $_REQUEST['bench'];
   if (isset($_REQUEST['bench']) && $_REQUEST['bench']!="0" && isset($_REQUEST['intercall']) && $_REQUEST['intercall']!="0")
      $params .= "&intercall=" . $_REQUEST['intercall'];

   if (isset($_REQUEST['showDtmf']) && $_REQUEST['showDtmf']!="default")
      $params .= "&showDtmf=" . $_REQUEST['showDtmf'];
   if (isset($_REQUEST['showDuration']) && $_REQUEST['showDuration']!="default")
      $params .= "&showDuration=" . $_REQUEST['showDuration'];
   if (isset($_REQUEST['showCalled']) && $_REQUEST['showCalled']!="default")
      $params .= "&showCalled=" . $_REQUEST['showCalled'];
   if (isset($_REQUEST['showImgHangupCall']) && $_REQUEST['showImgHangupCall']!="default")
      $params .= "&showImgHangupCall=" . $_REQUEST['showImgHangupCall'];
   if (isset($_REQUEST['saveSettings']) && $_REQUEST['saveSettings']!="default")
      $params .= "&saveSettings=" . $_REQUEST['saveSettings'];

   error_log("Flashparams: $params");
?>


if ( hasProductInstall && !hasRequestedVersion ) {
    // DO NOT MODIFY THE FOLLOWING FOUR LINES
    // Location visited after installation is complete if installation is required
    var MMPlayerType = (isIE == true) ? "ActiveX" : "PlugIn";
    var MMredirectURL = encodeURI(window.location);
    document.title = document.title.slice(0, 47) + " - Flash Player Installation";
    var MMdoctitle = document.title;

    AC_FL_RunContent(
        "src", "playerProductInstall",
        "FlashVars", "MMredirectURL="+MMredirectURL+'&MMplayerType='+MMPlayerType+'&MMdoctitle='+MMdoctitle+"",
        "width", viewportwidth,
        "height", viewportheight,
        "align", "middle",
        "id", "FlashPhone",
        "quality", "high",
        "bgcolor", "#ffffff",
        "name", "FlashPhone",
        "allowScriptAccess","sameDomain",
        "flashVars", "<?php echo $params; ?>",
        "type", "application/x-shockwave-flash",
        "pluginspage", "http://www.adobe.com/go/getflashplayer"
    );
}
else if (hasRequestedVersion) {
    // if we've detected an acceptable version
    // embed the Flash Content SWF when all tests are passed
    AC_FL_RunContent(
            "src", "FlashPhone",
            "width", viewportwidth,
            "height", viewportheight,
            "align", "middle",
            "id", "FlashPhone",
            "quality", "high",
            "bgcolor", "#ffffff",
            "name", "FlashPhone",
            "allowScriptAccess","sameDomain",
            "allowFullScreen", "true",
            "flashVars", "<?php echo $params; ?>",
            "type", "application/x-shockwave-flash",
            "pluginspage", "http://www.adobe.com/go/getflashplayer"
    );
  }
  else {  // flash is too old or we can't detect the plugin
    var alternateContent = 'Alternate HTML content should be placed here. '
    + 'This content requires the Adobe Flash Player. '
    + '<a href=http://www.adobe.com/go/getflash/>Get Flash</a>';
    document.write(alternateContent);  // insert non-flash content
  }
// -->
</script>
</body>
</html>

