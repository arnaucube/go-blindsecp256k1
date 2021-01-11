function test() {
	let m = "1952805748";

	console.log("using: https://sci-hub.do/10.1109/ICCKE.2013.6682844");
	// Q & R would be received from the Signer
	let signerQx = "26613296432153871833441195158297038913673464785502568519907582377915678491093";
	let signerQy = "81940194042971427014176158889809922552127995083760111384335138546589994227275";
	let signerRx = "59371873487402651110657306418818354906476102545298559461791300717696053835454";
	let signerRy = "98322875246066710654579302898391677189379767946198239290895789444110962324342";
	let blindRes = blind(m, signerQx, signerQy, signerRx, signerRy);
	console.log("blind", blindRes);

	// sBlind would be received from the Signer
	let sBlind = "7240298625621589352655632414257224668430424461224914067754717095121139699933353374227084479180038954015287518505167995306229258561275087198611946596619855";
	let unblindRes = unblind(sBlind, m, blindRes.uA, blindRes.uB, blindRes.uFx, blindRes.uFy);
	console.log("unblind", unblindRes);

	// ---
	// v0
	console.log("using: http://www.isecure-journal.com/article_39171_47f9ec605dd3918c2793565ec21fcd7a.pdf");
	// Q & R would be received from the Signer
	blindRes = blindv0(m, signerQx, signerQy, signerRx, signerRy);
	console.log("blindv0", blindRes);
	// sBlind would be received from the Signer
	unblindRes = unblindv0(sBlind, m, blindRes.uB, blindRes.uC, blindRes.uFx, blindRes.uFy);
	console.log("unblindv0", unblindRes);
}
