'use strict';

const {expect} = require('chai');
const SAML = require('../lib/saml').SAML;
const url = require('url');


describe('The passport-saml-encrypted-entrinsik module', async () => {
    it(`should merge an idp url's query string with it's SAMLRequest`, () => {
        const saml = new SAML({
            protocol: 'https://',
            path: 'someidp.com/saml/2.0/auth?id=foo',
            callbackUrl: 'https://generalsoftware.com/auth',
            entryPoint: 'https://someidp.com/saml/2.0/auth?id=foo'
        });


        saml.getAuthorizeUrl(null, (err,the_url) => {
            const parsed = url.parse(the_url, true);
            expect(parsed.query.id).to.equal('foo');
            expect(parsed.query.SAMLRequest).to.not.be.null;
        })

        saml.getLogoutUrl({user:{nameIdFormat:'foo', nameID:'foo'}}, (err,the_url) => {
            const parsed = url.parse(the_url, true);
            expect(parsed.query.id).to.equal('foo');
            expect(parsed.query.SAMLRequest).to.not.be.null;
        })

    });
})