/* As the network tab can't be used to see encrypted requests, this small script
 * prints the unencrypted data of these requests in the console.
 */
(function() {
	const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function() {
		var arg = arguments[0];
        this.addEventListener('load', function() {
			if (!this.responseURL.includes('/cgi_gdpr')) return;

			console.log("== REQUEST ==")
			console.log($.Iencryptor.AESDecrypt(arg.split('\r\n', 2)[1].substr(5)));
			console.log("== RESPONSE ==")
            console.log($.Iencryptor.AESDecrypt(this.responseText));
			console.log("== END ==")
        });
        origSend.apply(this, arguments);
    };
})();

