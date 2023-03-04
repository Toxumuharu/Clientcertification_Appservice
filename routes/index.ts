/*
 * GET home page.
 */

import express from 'express'
// import { NextFunction, Request, Response } from 'express';
import { pki, md, asn1 } from 'node-forge';

const router = express.Router();

router.get('/', (req: express.Request, res: express.Response, next: express.NextFunction) => {
    //res.render('index', { title: 'Express' });

    console.info("Process Start")
    try {
        // Get header
        console.info("Header Validation")

        const header = req.get('X-ARR-ClientCert');

        if (!header) throw new Error('UNAUTHORIZED');

        // Convert from PEM to pki.CERT
        console.info("Convert PEM to PKI.cert")
        const pem = `-----BEGIN CERTIFICATE-----${header}-----END CERTIFICATE-----`;
        const incomingCert: pki.Certificate = pki.certificateFromPem(pem);

        const allowedFingerPrint = "92261dee456250bee8e75c2287070b511d3e5e51";

        // Validate certificate thumbprint
        console.info("Validate Certificate Thumbprint")
        const fingerPrint = md.sha1.create().update(asn1.toDer(pki.certificateToAsn1(incomingCert)).getBytes()).digest().toHex();
        console.info(fingerPrint)

        if (fingerPrint.toLowerCase() !== allowedFingerPrint) throw new Error('UNAUTHORIZED');

        /*
        // Validate time validity
        console.info("Validate Time Validity")
        const currentDate = new Date();
        if (currentDate < incomingCert.validity.notBefore || currentDate > incomingCert.validity.notAfter) throw new Error('UNAUTHORIZED');

        // Validate issuer
        console.info("Validate Issuer")
        if (incomingCert.issuer.hash.toLowerCase() !== fingerPrint) throw new Error('UNAUTHORIZED');

        // Validate subject
        console.info("Validate Subject")
        if (incomingCert.subject.hash.toLowerCase() !== fingerPrint) throw new Error('UNAUTHORIZED');
        */

        res.render('index', { title: JSON.stringify(req.headers) });

        next();
    } catch (e) {
        if (e instanceof Error && e.message === 'UNAUTHORIZED') {
            res.status(401).send();
        } else {
            next(e);
        }
    }

});

export default router;