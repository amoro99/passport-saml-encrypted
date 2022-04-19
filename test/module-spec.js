'use strict';

const {expect} = require('chai');
const SAML = require('../lib/saml').SAML;
const url = require('url');
const privateCert = require('./cert');
describe('The passport-saml-encrypted-entrinsik module', async () => {
    it(`should merge an idp url's query string with it's SAMLRequest`, () => {
        const saml = new SAML({
            protocol: 'https://',
            path: 'someidp.com/saml/2.0/auth?id=foo',
            callbackUrl: 'https://generalsoftware.com/auth',
            entryPoint: 'https://someidp.com/saml/2.0/auth?id=foo',
            privateCert,
            signatureAlgorithm: 'RSA-SHA256'
        });


        saml.getAuthorizeUrl(null, (err,the_url) => {
            const parsed = url.parse(the_url, true);
            expect(parsed.query.id).to.equal('foo');
            expect(parsed.query.SAMLRequest).to.not.be.empty;
            expect(parsed.query.SigAlg).to.not.be.empty;
            expect(parsed.query.Signature).to.not.be.empty;
        })

        saml.getLogoutUrl({user:{nameIdFormat:'foo', nameID:'foo'}}, (err,the_url) => {
            const parsed = url.parse(the_url, true);
            expect(parsed.query.id).to.equal('foo');
            expect(parsed.query.SAMLRequest).to.not.be.empty;
            expect(parsed.query.SigAlg).to.not.be.empty;
            expect(parsed.query.Signature).to.not.be.empty;
        })

    });
    it(`should behave normally if the idp url has no query string`, () => {
        const saml = new SAML({
            protocol: 'https://',
            path: 'someidp.com/saml/2.0/auth',
            callbackUrl: 'https://generalsoftware.com/auth',
            entryPoint: 'https://someidp.com/saml/2.0/auth',
            privateCert,
            signatureAlgorithm: 'RSA-SHA256'
        });


        saml.getAuthorizeUrl(null, (err,the_url) => {
            const parsed = url.parse(the_url, true);
            expect(parsed.query.SAMLRequest).to.not.be.empty;
            expect(parsed.query.SigAlg).to.not.be.empty;
            expect(parsed.query.Signature).to.not.be.empty;
        })

        saml.getLogoutUrl({user:{nameIdFormat:'foo', nameID:'foo'}}, (err,the_url) => {
            const parsed = url.parse(the_url, true);
            expect(parsed.query.SAMLRequest).to.not.be.empty;
            expect(parsed.query.SigAlg).to.not.be.empty;
            expect(parsed.query.Signature).to.not.be.empty;
        })

    });})