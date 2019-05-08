# 18+ AgeGate in Go

Welcome to the 18+ AgeGate in Go.  This repo contains code necessary for you to integrate a UK compliant Age 18+ age verification tool to your Go back-end so that your UK based visitors can confirm they are age 18 or over in a secure and anonymous way.

For more information on the UK age requirements, please visit https://www.ageverificationregulator.com

The 18+ AgeGate and verification tools are free and provided by https://18plus.org

## Components

The repository comprises three components to make your AgeGate:

- the AgeGate Module, which if your website does not otherwise have an AgeGate should be used to intercept requests to your website.
- the ReallyMe Age Verification Module, which provides your visitors with a free and anonymous way to prove to you they meet the minimum age
- the 18+ Pass Module, which offers your visitors an encrypted VPN solution for private browsing.   If you include your 18+ Pass Affiliate link, you will be compensated by 18+ for any sale from your AgeGate.  Visit https://18plus.org/affiliates for more details.

If you already have an age certification interceptor, you can add the ReallyMe Age Verification Module and 18+ Pass Module to your existing tool.

## Overview - How Age Verification Works

Visitors from the United Kingdom are presented with an age verification requirement when visiting your website.  By selecting the ReallyMe Age Verification option, the visitor will be able to securely and anonymously provide you with assurance he or she is age 18+.
ReallyMe provides a free iOS and Android application, through which a user can verify his identity.  The user can then share the fact he is aged 18+ with your website in an anonymous way where neither your website nor ReallyMe knows either the user's identity or the specific website to which he or she is visiting, respectively.

The process works as follows:  when a visitor clicks on the ReallyMe Age Verification button on the AgeGate, he or she is presented with a QR code or deeplink.  By scanning this QR code or clicking this deeplink with a phone, the ReallyMe app on the phone opens and the user is presented with a consent request.  The deeplink contains a unique AgeVerificationID, which either can be a random string you generate with the SDK, a session ID, or by concatenating the user's IP address and UTC of the time of visit.  The deeplink also contains a call-back URL.

When the user consents to share with your site the fact he or she is aged 18+, the ReallyMe app requests from Really.Me a signed version of the AgeVerificationID.  If the user is over aged 18+, ReallyMe will sign the AgeVerificationID with its private key, and issue a jwt to the user.  The user's app will then transmit this signed jwt to the URL endpoint of your server.

Your server will decode the jwt and compare the expiration time and date to current UTC, and will ensure the validity of the signature by comparing it to the ReallyMe public signing key stored in your server.

For the best user experience, the visitor's browser should continue calling to your server for a session refresh.  In this way, once the session has been validted by way of your server receiving a signed jwt with the AgeVerificationID, the AgeGate should automatically drop.
If you prefer to require the user to click a next button instead, you can add this functionality.

Finally, a cookie is stored with the visitor to prevent his needing to reconfirm his age for a period of time.  Prudent practice is to expire the cookie at the end of the session.

## Requirements

### Version

## Installing

## Configuration

## Support

For any quesitons or support, please email sdksupport@18plus.org.  Once we have answered your question we may contact you again to discuss 18+ products and services. If you’d prefer us not to do this, please let us know when you e-mail.




