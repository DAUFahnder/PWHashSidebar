 
 // PWHashInSidebar.uc.js

 // Quellenangabe Sidebar: https://gist.github.com/Noitidart/8728393
 
 // Quellenangabe Hash-Script: 
 /*
 *  md5.js 1.0b 27/06/96
 *
 * Javascript implementation of the RSA Data Security, Inc. MD5
 * Message-Digest Algorithm.
 *
 * Copyright (c) 1996 Henri Torgemane. All Rights Reserved.
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purposes and without
 * fee is hereby granted provided that this copyright notice
 * appears in all copies.
 *
 * Of course, this soft is provided "as is" without express or implied
 * warranty of any kind.
 *
 *
 * Modified with german comments and some information about collisions.
 * (Ralf Mieke, ralf@miekenet.de, http://mieke.home.pages.de)
 */
 
/************************************************************
 *
 * Config-Block: 
 *
 ************************************************************/
 
  var PWHashInSidebar_Seite = "rechts";             // Auf welcher Seite soll die Sidebar andocken: "links" oder "rechts"
  var PWHashInSidebar_BreiteStart = "180";          // Breite in Pixel (px) mit dem die Sidebar startet. Kann anschliessend per Maus jederzeit angepasst werden. 
  var PWHashInSidebar_LadenDefault = "ja";          // Soll die Standardseite dieser Datei geladen werden: "ja" oder "nein"
  var PWHashInSidebar_LadenDefaultFarbeHintergrund = "grey";   // Wenn die Standardseite geladen werden soll (PWHash), welche Hintergrundfarbe soll benutzt werden? Alle CSS-Codes für Farbe sind möglich
  var PWHashInSidebar_LadenDefaultFarbeText = "black";   // Wenn die Standardseite geladen werden soll (PWHash), welche Textfarbe soll benutzt werden? Alle CSS-Codes für Farbe sind möglich
  var PWHashInSidebar_LadenErsatz = "https://web.whatsapp.com/";     // Wenn nicht die Standardseite geladen werden soll, welche dann?  
  
  /**************************************************
   * nachfolgend die PWHash-Seite als HTML-Datenstream
   * nur ändern wenn man weiss was man macht!
   *************************************************/
   
   var PWHashInSidebar_LadenDefaultContent = 'data:text/html,\
<!DOCTYPE HTML> <html lang="de-de"> <head> <meta content="text/html; charset=utf-8" http-equiv="content-type">\
<style>body {font-size: 17px; padding: 1px; margin: 4px; text-align: justify; color:'+PWHashInSidebar_LadenDefaultFarbeText+'; background:'+PWHashInSidebar_LadenDefaultFarbeHintergrund+';} input%23nummer {width: 5ex;text-align:center;-moz-appearance: textfield;margin-top: 4px;} div%23genfeld {text-align: center;} div%23hilfe {font-size: 87%;-moz-hyphens: auto;-o-hyphens: auto;-webkit-hyphens: auto;-ms-hyphens: auto;hyphens: auto;}</style>\
<script> function getID(ID) {return document.getElementById(ID);}; function start() {getID("ergebnis").value = Hash(getID("pw").value+getID("name").value+getID("dienst").value+getID("nummer").value);}; </script>\
<script> function array(n) { for(i=0;i<n;i++) this[i]=0; this.length=n; } function integer(n) { return n%(0xffffffff+1); } function shr(a,b) { a=integer(a); b=integer(b); if (a-0x80000000>=0) { a=a%0x80000000; a>>=b; a+=0x40000000>>(b-1); } else a>>=b; return a; } function shl1(a) { a=a%0x80000000; if (a&0x40000000==0x40000000) { a-=0x40000000; a*=2; a+=0x80000000; } else a*=2; return a; } function shl(a,b) { a=integer(a); b=integer(b); for (var i=0;i<b;i++) a=shl1(a); return a; } function and(a,b) { a=integer(a); b=integer(b); var t1=(a-0x80000000); var t2=(b-0x80000000); if (t1>=0) if (t2>=0) return ((t1&t2)+0x80000000); else return (t1&b); else if (t2>=0) return (a&t2); else return (a&b); } function or(a,b) { a=integer(a); b=integer(b); var t1=(a-0x80000000); var t2=(b-0x80000000); if (t1>=0) if (t2>=0) return ((t1|t2)+0x80000000); else return ((t1|b)+0x80000000); else if (t2>=0) return ((a|t2)+0x80000000); else return (a|b); } function xor(a,b) { a=integer(a); b=integer(b); var t1=(a-0x80000000); var t2=(b-0x80000000); if (t1>=0) if (t2>=0) return (t1^t2); else return ((t1^b)+0x80000000); else if (t2>=0) return ((a^t2)+0x80000000); else return (a^b); } function not(a) { a=integer(a); return (0xffffffff-a); } var state = new array(4); var count = new array(2); count[0] = 0; count[1] = 0; var buffer = new array(64); var transformBuffer = new array(16); var digestBits = new array(16); var S11 = 7; var S12 = 12; var S13 = 17; var S14 = 22; var S21 = 5; var S22 = 9; var S23 = 14; var S24 = 20; var S31 = 4; var S32 = 11; var S33 = 16; var S34 = 23; var S41 = 6; var S42 = 10; var S43 = 15; var S44 = 21; function F(x,y,z) { return or(and(x,y),and(not(x),z)); } function G(x,y,z) { return or(and(x,z),and(y,not(z))); } function H(x,y,z) { return xor(xor(x,y),z); } function I(x,y,z) { return xor(y ,or(x , not(z))); } function rotateLeft(a,n) { return or(shl(a, n),(shr(a,(32 - n)))); } function FF(a,b,c,d,x,s,ac) { a = a+F(b, c, d) + x + ac; a = rotateLeft(a, s); a = a+b; return a; } function GG(a,b,c,d,x,s,ac) { a = a+G(b, c, d) +x + ac; a = rotateLeft(a, s); a = a+b; return a; } function HH(a,b,c,d,x,s,ac) { a = a+H(b, c, d) + x + ac; a = rotateLeft(a, s); a = a+b; return a; } function II(a,b,c,d,x,s,ac) { a = a+I(b, c, d) + x + ac; a = rotateLeft(a, s); a = a+b; return a; } function transform(buf,offset) { var a=0, b=0, c=0, d=0; var x = transformBuffer; a = state[0]; b = state[1]; c = state[2]; d = state[3]; for (i = 0; i < 16; i++) { x[i] = and(buf[i*4+offset],0xff); for (j = 1; j < 4; j++) { x[i]+=shl(and(buf[i*4+j+offset] ,0xff), j * 8); } } a = FF ( a, b, c, d, x[ 0], S11, 0xd76aa478); d = FF ( d, a, b, c, x[ 1], S12, 0xe8c7b756); c = FF ( c, d, a, b, x[ 2], S13, 0x242070db); b = FF ( b, c, d, a, x[ 3], S14, 0xc1bdceee); a = FF ( a, b, c, d, x[ 4], S11, 0xf57c0faf); d = FF ( d, a, b, c, x[ 5], S12, 0x4787c62a); c = FF ( c, d, a, b, x[ 6], S13, 0xa8304613); b = FF ( b, c, d, a, x[ 7], S14, 0xfd469501); a = FF ( a, b, c, d, x[ 8], S11, 0x698098d8); d = FF ( d, a, b, c, x[ 9], S12, 0x8b44f7af); c = FF ( c, d, a, b, x[10], S13, 0xffff5bb1); b = FF ( b, c, d, a, x[11], S14, 0x895cd7be); a = FF ( a, b, c, d, x[12], S11, 0x6b901122); d = FF ( d, a, b, c, x[13], S12, 0xfd987193); c = FF ( c, d, a, b, x[14], S13, 0xa679438e); b = FF ( b, c, d, a, x[15], S14, 0x49b40821); a = GG ( a, b, c, d, x[ 1], S21, 0xf61e2562); d = GG ( d, a, b, c, x[ 6], S22, 0xc040b340); c = GG ( c, d, a, b, x[11], S23, 0x265e5a51); b = GG ( b, c, d, a, x[ 0], S24, 0xe9b6c7aa); a = GG ( a, b, c, d, x[ 5], S21, 0xd62f105d); d = GG ( d, a, b, c, x[10], S22,  0x2441453); c = GG ( c, d, a, b, x[15], S23, 0xd8a1e681); b = GG ( b, c, d, a, x[ 4], S24, 0xe7d3fbc8); a = GG ( a, b, c, d, x[ 9], S21, 0x21e1cde6); d = GG ( d, a, b, c, x[14], S22, 0xc33707d6); c = GG ( c, d, a, b, x[ 3], S23, 0xf4d50d87); b = GG ( b, c, d, a, x[ 8], S24, 0x455a14ed); a = GG ( a, b, c, d, x[13], S21, 0xa9e3e905); d = GG ( d, a, b, c, x[ 2], S22, 0xfcefa3f8); c = GG ( c, d, a, b, x[ 7], S23, 0x676f02d9); b = GG ( b, c, d, a, x[12], S24, 0x8d2a4c8a); a = HH ( a, b, c, d, x[ 5], S31, 0xfffa3942); d = HH ( d, a, b, c, x[ 8], S32, 0x8771f681); c = HH ( c, d, a, b, x[11], S33, 0x6d9d6122); b = HH ( b, c, d, a, x[14], S34, 0xfde5380c); a = HH ( a, b, c, d, x[ 1], S31, 0xa4beea44); d = HH ( d, a, b, c, x[ 4], S32, 0x4bdecfa9); c = HH ( c, d, a, b, x[ 7], S33, 0xf6bb4b60); b = HH ( b, c, d, a, x[10], S34, 0xbebfbc70); a = HH ( a, b, c, d, x[13], S31, 0x289b7ec6); d = HH ( d, a, b, c, x[ 0], S32, 0xeaa127fa); c = HH ( c, d, a, b, x[ 3], S33, 0xd4ef3085); b = HH ( b, c, d, a, x[ 6], S34,  0x4881d05); a = HH ( a, b, c, d, x[ 9], S31, 0xd9d4d039); d = HH ( d, a, b, c, x[12], S32, 0xe6db99e5); c = HH ( c, d, a, b, x[15], S33, 0x1fa27cf8); b = HH ( b, c, d, a, x[ 2], S34, 0xc4ac5665); a = II ( a, b, c, d, x[ 0], S41, 0xf4292244); d = II ( d, a, b, c, x[ 7], S42, 0x432aff97); c = II ( c, d, a, b, x[14], S43, 0xab9423a7); b = II ( b, c, d, a, x[ 5], S44, 0xfc93a039); a = II ( a, b, c, d, x[12], S41, 0x655b59c3); d = II ( d, a, b, c, x[ 3], S42, 0x8f0ccc92); c = II ( c, d, a, b, x[10], S43, 0xffeff47d); b = II ( b, c, d, a, x[ 1], S44, 0x85845dd1); a = II ( a, b, c, d, x[ 8], S41, 0x6fa87e4f); d = II ( d, a, b, c, x[15], S42, 0xfe2ce6e0); c = II ( c, d, a, b, x[ 6], S43, 0xa3014314); b = II ( b, c, d, a, x[13], S44, 0x4e0811a1); a = II ( a, b, c, d, x[ 4], S41, 0xf7537e82); d = II ( d, a, b, c, x[11], S42, 0xbd3af235); c = II ( c, d, a, b, x[ 2], S43, 0x2ad7d2bb); b = II ( b, c, d, a, x[ 9], S44, 0xeb86d391); state[0] +=a; state[1] +=b; state[2] +=c; state[3] +=d; } function init() { count[0]=count[1] = 0; state[0] = 0x67452301; state[1] = 0xefcdab89; state[2] = 0x98badcfe; state[3] = 0x10325476; for (i = 0; i < digestBits.length; i++) digestBits[i] = 0; } function update(b) { var index,i; index = and(shr(count[0],3) , 0x3f); if (count[0]<0xffffffff-7) count[0] += 8; else { count[1]++; count[0]-=0xffffffff+1; count[0]+=8; } buffer[index] = and(b,0xff); if (index  >= 63) { transform(buffer, 0); } } function finish() { var bits = new array(8); var        padding; var        i=0, index=0, padLen=0; for (i = 0; i < 4; i++) { bits[i] = and(shr(count[0],(i * 8)), 0xff); } for (i = 0; i < 4; i++) { bits[i+4]=and(shr(count[1],(i * 8)), 0xff); } index = and(shr(count[0], 3) ,0x3f); padLen = (index < 56) ? (56 - index) : (120 - index); padding = new array(64); padding[0] = 0x80; for (i=0;i<padLen;i++) update(padding[i]); for (i=0;i<8;i++) update(bits[i]); for (i = 0; i < 4; i++) { for (j = 0; j < 4; j++) { digestBits[i*4+j] = and(shr(state[i], (j * 8)) , 0xff); } } } function hexa(n) { var hexa_h = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/()=?"; var hexa_c=""; var hexa_m=n;for (hexa_i=0;hexa_i<8;hexa_i++){ if (getID("sonderzeichen").checked) { hexa_c=hexa_h.charAt(Math.abs(hexa_m)%2574)+hexa_c; }else { hexa_c=hexa_h.charAt(Math.abs(hexa_m)%2562)+hexa_c; };hexa_m=Math.floor(hexa_m/16); } return hexa_c; }var ascii="01234567890123456789012345678901!$&*+,-./0123456789:?ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz|~";  function Hash(nachricht) { var l,s,k,ka,kb,kc,kd; init(); for (k=0;k<nachricht.length;k++) { l=nachricht.charAt(k); update(ascii.lastIndexOf(l)); } finish(); ka=kb=kc=kd=0; for (i=0;i<4;i++) ka+=shl(digestBits[15-i], (i*8)); for (i=4;i<8;i++) kb+=shl(digestBits[15-i], ((i-4)*8)); for (i=8;i<12;i++) kc+=shl(digestBits[15-i], ((i-8)*8));for (i=12;i<16;i++) kd+=shl(digestBits[15-i], ((i-12)*8)); s=hexa(kd)+hexa(kc)+hexa(kb)+hexa(ka);s = s.substring(0,getID("pwlaenge").value); return s; } </script>\
<title>PW-Generator</title></head><body>Masterpasswort:<br/><input id="pw"type="password"/><br/>Benutzername:<br/><input id="name"/><br/>Dienst:<br/><input id="dienst"/><br/> fortl. Nummer: <input type="number" id="nummer" value="1"/><br/> Sonderzeichen?&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input id="sonderzeichen" type="checkbox" checked="checked"/><br/> PW-Laenge: &nbsp;&nbsp;&nbsp;&nbsp;<select id="pwlaenge"> <option>05</option><option>10</option><option>15</option><option>20</option><option>25</option><option selected="selected">30</option></select><br/><input type="button"onclick="start();" value="   Passwort erzeugen   "/><br/> Ausgabe:<br/> <textarea id="ergebnis" cols="16" rows="1"></textarea><br/><div id="hilfe">Infos: Das Script erzeugt aus den Daten die man oben eingibt einen Hash-Wert, den man dann als Passwort fuer den jeweiligen Service benutzen kann.<br/>Der Benutzername ermoeglicht unterschiedliche Profile pro Dienst; das Masterpasswort verhindert, dass andere Benutzer einfach dieselben Daten eingeben und damit dasselbe Passwort bekommen; die fortlaufende Nummer ermoeglicht es, sein Passwort auch mal zu aendern. Dabei aber Vorsicht: Die Seite speichert keine Daten, man muss sich die Nummer pro Dienst also selbst merken! Wer will, kann das gerne entsprechend anpassen.<br/>Falls notwendig kann man Sonderzeichen vom Passwort ausschliessen. Was die Passwortlaenge angeht: Das Script erzeugt immer mit gleichen Vorgaben denselben Hash, es werden nur je nach Vorgabe die ueberfluessigen Zeichen am Ende abgeschnitten.</div></body></html>'

  if (PWHashInSidebar_LadenDefault == "nein") {PWHashInSidebar_Laden = PWHashInSidebar_LadenErsatz} 
  else {PWHashInSidebar_Laden = PWHashInSidebar_LadenDefaultContent};
  
  
const {interfaces: Ci,	utils: Cu} = Components;
Cu.import('resource://gre/modules/Services.jsm');

/*start - windowlistener*/
var windowListener = {
	//DO NOT EDIT HERE
	onOpenWindow: function (aXULWindow) {
		// Wait for the window to finish loading
		let aDOMWindow = aXULWindow.QueryInterface(Ci.nsIInterfaceRequestor).getInterface(Ci.nsIDOMWindowInternal || Ci.nsIDOMWindow);
		aDOMWindow.addEventListener("load", function () {
			aDOMWindow.removeEventListener("load", arguments.callee, false);
			windowListener.loadIntoWindow(aDOMWindow, aXULWindow);
		}, false);
	},
	onCloseWindow: function (aXULWindow) {},
	onWindowTitleChange: function (aXULWindow, aNewTitle) {},
	register: function () {
		// Load into any existing windows
		let XULWindows = Services.wm.getXULWindowEnumerator(null);
		while (XULWindows.hasMoreElements()) {
			let aXULWindow = XULWindows.getNext();
			let aDOMWindow = aXULWindow.QueryInterface(Ci.nsIInterfaceRequestor).getInterface(Ci.nsIDOMWindowInternal || Ci.nsIDOMWindow);
			windowListener.loadIntoWindow(aDOMWindow, aXULWindow);
		}
		// Listen to new windows
		Services.wm.addListener(windowListener);
	},
	unregister: function () {
		// Unload from any existing windows
		let XULWindows = Services.wm.getXULWindowEnumerator(null);
		while (XULWindows.hasMoreElements()) {
			let aXULWindow = XULWindows.getNext();
			let aDOMWindow = aXULWindow.QueryInterface(Ci.nsIInterfaceRequestor).getInterface(Ci.nsIDOMWindowInternal || Ci.nsIDOMWindow);
			windowListener.unloadFromWindow(aDOMWindow, aXULWindow);
		}
		//Stop listening so future added windows dont get this attached
		Services.wm.removeListener(windowListener);
	},
	//END - DO NOT EDIT HERE
	loadIntoWindow: function (aDOMWindow, aXULWindow) {
		if (!aDOMWindow) {
			return;
		}
		//START - EDIT BELOW HERE
		var browser = aDOMWindow.document.querySelector('#browser')
		if (browser) {
			var splitter = aDOMWindow.document.createElement('splitter');
			var propsToSet = {
				id: 'demo-sidebar-with-html_splitter',
				//class: 'sidebar-splitter' //im just copying what mozilla does for their social sidebar splitter //i left it out, but you can leave it in to see how you can style the splitter
			}
			for (var p in propsToSet) {
				splitter.setAttribute(p, propsToSet[p]);
			}
			
			var sidebar = aDOMWindow.document.createElement('vbox');
			var propsToSet = {
				id: 'demo-sidebar-with-html_sidebar',
				//persist: 'width' //mozilla uses persist width here, i dont know what it does and cant see it how makes a difference so i left it out
			}
			for (var p in propsToSet) {
				sidebar.setAttribute(p, propsToSet[p]);
			}
			
			var sidebarBrowser = aDOMWindow.document.createElement('browser');
			var propsToSet = {
				id: 'demo-sidebar-with-html_browser',
				type: 'content',
				context: 'contentAreaContextMenu',
				disableglobalhistory: 'true',
				tooltip: 'aHTMLTooltip',
				clickthrough: 'never',
				autoscrollpopup: 'autoscroller',
				flex: '1', //do not remove this
				style: "min-width: 180px; width: "+PWHashInSidebar_BreiteStart+"px; max-width: 800px;", //you should change these widths to how you want
        src: PWHashInSidebar_Laden
			}
			for (var p in propsToSet) {
				sidebarBrowser.setAttribute(p, propsToSet[p]);
			}
			
			if (PWHashInSidebar_Seite == "rechts") {browser.appendChild(splitter)};
   if (PWHashInSidebar_Seite == "links") {browser.insertBefore(splitter, browser.firstChild);};
			
			sidebar.appendChild(sidebarBrowser);
			if (PWHashInSidebar_Seite == "rechts") {browser.appendChild(sidebar)};
   if (PWHashInSidebar_Seite == "links") {browser.insertBefore(sidebar, browser.firstChild)};   
		}
		//END - EDIT BELOW HERE
	},
	unloadFromWindow: function (aDOMWindow, aXULWindow) {
		if (!aDOMWindow) {
			return;
		}
		//START - EDIT BELOW HERE
		var splitter = aDOMWindow.document.querySelector('#demo-sidebar-with-html_splitter');
	
		if (splitter) {
			var sidebar = aDOMWindow.document.querySelector('#demo-sidebar-with-html_sidebar');
			splitter.parentNode.removeChild(splitter);
			sidebar.parentNode.removeChild(sidebar);
		}
		//END - EDIT BELOW HERE
	}
};
/*end - windowlistener*/

var HashOnline = 0;

function startup() {
 windowListener.register();
 HashOnline = 1;
}

function shutdown() {
	windowListener.unregister();
  HashOnline = 0;
}


 
 (function() {

 if (location != 'chrome://browser/content/browser.xul') return;
   
		CustomizableUI.createWidget({
			id: 'PWHashInSidebar-ToolbarButton',
			type: 'custom',
			defaultArea: CustomizableUI.AREAS,
			onBuild: function(aDocument) {			
				var toolbaritem = aDocument.createElementNS('http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul', 'toolbarbutton');
				var props = {
					id: 'PWHashInSidebar-ToolbarButton',
					class: 'toolbarbutton-1 chromeclass-toolbar-additional',
          removable: true,
					label: 'PWHashInSidebar',
					tooltiptext: 'PWHashInSidebar',
					style: 'list-style-image:  url(\'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABGdBTUEAALGPC/xhBQAAAAlwSFlzAAAOwgAADsIBFShKgAAAABl0RVh0U29mdHdhcmUAcGFpbnQubmV0IDQuMC4yMfEgaZUAAADFSURBVDhPlZM7C8JAEIRPCVEEQQsxtYXYiEEI2lpYWeYPpNU0duKvj/s62TvvzOWDKWZ3JjnyMAmUVd11VuAfoJw2CVxUsfEutKTEHyYqPOYRsY7MfzhJqGDrsJHdjW2Ys4QWbF3UKaLMJHBn65JyAeQpoYrtl73Ma7ZhMnsXK5hdQa3yIwyGyL3iW3uZZZQMMPWC+vjRD2gLeoHmXvmIyz4KXVLlktf9rALlA6/ScJ42+EFlhN6plJOPrcEfogHtyA3CmA87sZLYX4rSZQAAAABJRU5ErkJggg==\')',
					onclick: 'if (HashOnline == 0) {startup()}\
     else {shutdown()};\
     '
				};
				for (var p in props)
					toolbaritem.setAttribute(p, props[p]);
				return toolbaritem;
			}
		});
  
})();
