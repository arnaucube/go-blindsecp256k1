function test() {
	let m = "1952805748";

	console.log("using: https://sci-hub.do/10.1109/ICCKE.2013.6682844");
	// R would be received from the Signer
	let signerRx = "17814783168156809976981325336969869272256267559847863501362979416582031885685";
	let signerRy = "30466749656160766323378925376290982172805224557687141285291181575233995759897";
	let blindRes = wasmBlind(m, signerRx, signerRy);
	console.log("blind", blindRes);

	// Q & sBlind would be received from the Signer
	let signerQx = "91217724741799691300838336208439702708830781279546234509900618215893368170964";
	let signerQy = "10647409378909561143830454293907272341812664755625953321604115356883317910171";
	let sBlind = "1559989683738317700055715706344460781046571016142996697444777749433194958666958401306508176561868963591508234625762518936896506645022493420447764027537091595268073646775253821735958788229615883133396107736168033688269069669796190509031136746898237132145138091815479880246793211708356184248484212425679897377";
	let unblindRes = wasmUnblind(sBlind, m, blindRes.uA, blindRes.uB, blindRes.uFx, blindRes.uFy);
	console.log("unblind", unblindRes);


	// wasmVerify method not used here because the hardcoded values would
	// not match with the random generated values from the 'blind' method
	// let verified = wasmVerify(m, unblindRes.s, unblindRes.fx, unblindRes.fy, signerQx, signerQy);
	// console.log("verify", verified);

	// ---
	// v0
	console.log("using: http://www.isecure-journal.com/article_39171_47f9ec605dd3918c2793565ec21fcd7a.pdf");
	// Q & R would be received from the Signer
	blindRes = wasmBlindv0(m, signerQx, signerQy, signerRx, signerRy);
	console.log("blindv0", blindRes);
	// sBlind would be received from the Signer
	unblindRes = wasmUnblindv0(sBlind, m, blindRes.uB, blindRes.uC, blindRes.uFx, blindRes.uFy);
	console.log("unblindv0", unblindRes);

	// wasmVerifyv0 method not used here because the hardcoded values would
	// not match with the random generated values from the 'blind' method
	// let verified = wasmVerifyv0(m, unblindRes.s, unblindRes.fx, unblindRes.fy, signerQx, signerQy);
	// console.log("verify", verified);
}
