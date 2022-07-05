Return-Path: <kasan-dev+bncBCX3TTWUQMPRB3FISCLAMGQEFWHHOOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id A7A39566823
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jul 2022 12:37:32 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id l2-20020a170906078200b006fed42bfeacsf2628887ejc.16
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jul 2022 03:37:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657017452; cv=pass;
        d=google.com; s=arc-20160816;
        b=OwUOJ7NGVnqLDIRweEv7dFBgVmCRAXlIG/mh0YFjIVR+83G8UuQ3YeNxTxz9PnCxIe
         ZtthaBM6AUHnTyM3c5QzMc4cmiqQ9rw3g6woe5CybGGa7LPms9vL3q1LqcKGS5Fsdbzp
         ewenA4Gcf/eUa/HVeWZYYri46yB9FT8B/3gq8nV2UICfvg2wHrhLx9RFzFIQc0R9zC90
         DHZkICUWNFT/GoW0Eu7Lo04W2r6yefQdWn2DfHt2E5BeyA7emqy14fnepWf/cr3Vvm7T
         oqwelHHgRB0ad0HL8hqO38++L9Bo2LG4lo/vi6TcUTnWZj2AoBkze/8WYaIArPvRRiWw
         SY5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QFQyRVf29ILLvwQmyJuMsYUAhe7NVTUebfVMUrixAco=;
        b=U5KVpFAoIKI9pKaKJe0Ag7zw+ilpwyw3sy2KvwNkExn5hUM/O279ycwc3QahrYLBjB
         dDc/UPOThPScTOXE7UiK04RvBNeahWgomMPUyKLpaUgFgiCeXEX2ViU8qlao0KqG+uOR
         5oAC/W9zj3NFArTLZNIvTe1GGnPq0wDwYV4QvDcu++dTlC4TPxUJ+6qhjXMdL2xJY9Lt
         DLhfpgV6azon5zQaJjAaDSBLnk1pK5VV7HtEABdOH1s6iJo2401X4/xl9jLFbzZu1TKV
         +ZgRm4c+J7ZA85hAjHraJATIN9rr1TRNzdULj74VFDP25QODOQD8JYUNpu7b98FI5CaR
         y1QA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=ukl@pengutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QFQyRVf29ILLvwQmyJuMsYUAhe7NVTUebfVMUrixAco=;
        b=WgZ7pIa/PEyc1wgQI9YSfl6TxzmU8udu7KgyOlSLnjIkR/w+oNrn9+fBRMO7kat16f
         AJH4R7B0rlXmuKYwvDJ/+/lzNEvBViI4j0NbwXu2IwrLtdYH01CgqdTBKue3WZSlfdQ4
         VB7JWTxGw+AkGeQI5tSR89NRtJlS+3zAa8gcdtccqY6l+ZcRXI+Qn1XAwXkmaRLIRWD0
         8ecgiHt6T/sJ+ZZVou+LylBvAGBPEPkvPFdcwk+qD6d/1e8Nr3iHgfPICJC9B2L/XZAK
         Wkb8doROpSZZHh0ApoYWxgpylKubCQJMDtFfaSi2RG3BgZefxiqhhEE7L7qvWAz1ZLCk
         uI/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QFQyRVf29ILLvwQmyJuMsYUAhe7NVTUebfVMUrixAco=;
        b=7HQpUNc6c4wXjbzvDd7FJIDQ6rEHI0QKm8WiDtFh08hHoymcA60K6KsEM7hnVBtHVM
         b8EmIfxCcGtGQ9XkOp3b8OFxfQBmk9jvWiZGHxcxcKuYY5GS0Tu/BS6tAPCLl+kWik4q
         I40aiA04CRSebgsyInDqLCVoLujAdOg688wNuhjrDPDnpg74BTcU7kczwCV5VgSzTF6B
         dRcsG+s8IcsKf3Sx4i/KEUt/Ae85yry1dRAG2X07fVf1koDH5Lh7UTq+KBFsTLORSiak
         mRLN5wE4uC1+W2NybFYSazA8czKu/nEGjGao/UwWf/ZiHIPnBlkZPAYythvhrFVv6FRY
         pC7A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8UDPdzfJToROf+u2+oZTj8UW42MKWmZX5dwHqb8EXp8klGVSTA
	YeFjoyoZoxL+4hGs89xCpjE=
X-Google-Smtp-Source: AGRyM1uqSxGZF5TZAog1T8uBzfJ96VYHm9e0U6meIdSeWzCqZl/mLt/S2DL5bhbeHY11sdYc95kjpg==
X-Received: by 2002:a17:907:b13:b0:72a:e5f9:1f2f with SMTP id h19-20020a1709070b1300b0072ae5f91f2fmr2163722ejl.106.1657017452314;
        Tue, 05 Jul 2022 03:37:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:9603:b0:6ff:232a:2406 with SMTP id
 gb3-20020a170907960300b006ff232a2406ls8579564ejc.0.gmail; Tue, 05 Jul 2022
 03:37:31 -0700 (PDT)
X-Received: by 2002:a17:907:c1b:b0:726:d677:eb51 with SMTP id ga27-20020a1709070c1b00b00726d677eb51mr33343748ejc.6.1657017451001;
        Tue, 05 Jul 2022 03:37:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657017450; cv=none;
        d=google.com; s=arc-20160816;
        b=HIJJ3AaOgIbBI0ZXeTfVO9y0boNlHL1FChsJiGN2a5Hm5lmVlP8voeU06L8z7hTfDE
         9Yl4rkuGRuaODSLCy1y0gUXPASkvBmqtuvzz1yC80DDMBUKxYuXXKzyk38SLzCJRhMRQ
         HmyOMA94mEFCAQY8HKxABYTcsmrwdYdRb7buxGtP3avPmAZqTjw2hdWJStmHlioKrDhB
         bGMf4UC3uvv6mHsfLyxcuYLJyJ2KErcdwq4tvPKhesqMdC/N23S2CAFP+BhEIGfQpHYH
         J/Dn8jJ2Qb1z+JdoSMcFbFPyXFQAdL13hKJOZ0cbypv30XO2W3TCrTQT/e36oMComwQB
         K0Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=mEjtMakiW0EySpcbbvi4iHxAbsgXIOf2nckHkAxDFJs=;
        b=abfmmpx4Uvqb3irR5E+oCv3OHxY/y3ntyg6yBUKArhNzXUOjZ1TfZ0zIKwkg/HWRlJ
         OjK3S0m/70kQaWU651hVt4/3hpnCb7ffwAoZgqIXLB8hOmNNgkr90eKk+RfGCmMG907d
         589dbJXvHMAWjQDat/y2Z2qXuE9cDK7+vaj2DBOWo8ILhDeAZ34ZLy4lPVX845JVVPeP
         HVtp8RfXBlWpSKsSuGdhAIIJ53welw41aDtsrH/8b6iUaYhsOiIMQvLPYmi1npvN0s5W
         umyqGsPApDkIbNKK6N7dyH1UhCLBrzDqqgz8iPmwz1IHHQJld4LS8c7RfeMiCdWr/C2w
         nlZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=ukl@pengutronix.de
Received: from metis.ext.pengutronix.de (metis.ext.pengutronix.de. [2001:67c:670:201:290:27ff:fe1d:cc33])
        by gmr-mx.google.com with ESMTPS id k24-20020a05640212d800b0043a6dd6b3e8si194065edx.5.2022.07.05.03.37.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Jul 2022 03:37:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) client-ip=2001:67c:670:201:290:27ff:fe1d:cc33;
Received: from drehscheibe.grey.stw.pengutronix.de ([2a0a:edc0:0:c01:1d::a2])
	by metis.ext.pengutronix.de with esmtps (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <ukl@pengutronix.de>)
	id 1o8fuq-0001LC-19; Tue, 05 Jul 2022 12:36:24 +0200
Received: from [2a0a:edc0:0:900:1d::77] (helo=ptz.office.stw.pengutronix.de)
	by drehscheibe.grey.stw.pengutronix.de with esmtp (Exim 4.94.2)
	(envelope-from <ukl@pengutronix.de>)
	id 1o8fue-004XxA-J7; Tue, 05 Jul 2022 12:36:16 +0200
Received: from ukl by ptz.office.stw.pengutronix.de with local (Exim 4.94.2)
	(envelope-from <ukl@pengutronix.de>)
	id 1o8fuh-0038F6-8t; Tue, 05 Jul 2022 12:36:15 +0200
Date: Tue, 5 Jul 2022 12:36:15 +0200
From: Uwe =?utf-8?Q?Kleine-K=C3=B6nig?= <u.kleine-koenig@pengutronix.de>
To: Jean Delvare <jdelvare@suse.de>
Cc: Wolfram Sang <wsa@kernel.org>, Guenter Roeck <groeck@chromium.org>,
	linux-i2c@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org,
	openipmi-developer@lists.sourceforge.net,
	linux-integrity@vger.kernel.org, linux-clk@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-gpio@vger.kernel.org,
	dri-devel@lists.freedesktop.org, chrome-platform@lists.linux.dev,
	linux-rpi-kernel@lists.infradead.org, linux-input@vger.kernel.org,
	linux-hwmon@vger.kernel.org, linux-iio@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-leds@vger.kernel.org, linux-media@vger.kernel.org,
	patches@opensource.cirrus.com, alsa-devel@alsa-project.org,
	linux-omap@vger.kernel.org, linux-mtd@lists.infradead.org,
	netdev@vger.kernel.org, devicetree@vger.kernel.org,
	platform-driver-x86@vger.kernel.org,
	acpi4asus-user@lists.sourceforge.net, linux-pm@vger.kernel.org,
	linux-pwm@vger.kernel.org, linux-rtc@vger.kernel.org,
	linux-staging@lists.linux.dev, linux-serial@vger.kernel.org,
	linux-usb@vger.kernel.org, linux-fbdev@vger.kernel.org,
	linux-watchdog@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mediatek@lists.infradead.org
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
Message-ID: <20220705103615.ceeq7rku53x743ps@pengutronix.de>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
 <20220705120852.049dc235@endymion.delvare>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="gut2agzhpaayxotv"
Content-Disposition: inline
In-Reply-To: <20220705120852.049dc235@endymion.delvare>
X-SA-Exim-Connect-IP: 2a0a:edc0:0:c01:1d::a2
X-SA-Exim-Mail-From: ukl@pengutronix.de
X-SA-Exim-Scanned: No (on metis.ext.pengutronix.de); SAEximRunCond expanded to false
X-PTX-Original-Recipient: kasan-dev@googlegroups.com
X-Original-Sender: u.kleine-koenig@pengutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33
 as permitted sender) smtp.mailfrom=ukl@pengutronix.de
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>


--gut2agzhpaayxotv
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable

On Tue, Jul 05, 2022 at 12:08:52PM +0200, Jean Delvare wrote:
> On Tue, 28 Jun 2022 16:03:12 +0200, Uwe Kleine-K=C3=B6nig wrote:
> > From: Uwe Kleine-K=C3=B6nig <uwe@kleine-koenig.org>
> >=20
> > The value returned by an i2c driver's remove function is mostly ignored=
.
> > (Only an error message is printed if the value is non-zero that the
> > error is ignored.)
> >=20
> > So change the prototype of the remove function to return no value. This
> > way driver authors are not tempted to assume that passing an error to
> > the upper layer is a good idea. All drivers are adapted accordingly.
> > There is no intended change of behaviour, all callbacks were prepared t=
o
> > return 0 before.
> >=20
> > Signed-off-by: Uwe Kleine-K=C3=B6nig <u.kleine-koenig@pengutronix.de>
> > ---
>=20
> That's a huge change for a relatively small benefit, but if this is
> approved by the I2C core maintainer then fine with me. For:

Agreed, it's huge. The benefit isn't really measureable, the motivation
is to improve the situation for driver authors who with the change
cannot make wrong assumptions about what to return in .remove(). During
the preparation this uncovered a few bugs. See for example
bbc126ae381cf0a27822c1f822d0aeed74cc40d9.

> >  drivers/hwmon/adc128d818.c                                | 4 +---
> >  drivers/hwmon/adt7470.c                                   | 3 +--
> >  drivers/hwmon/asb100.c                                    | 6 ++----
> >  drivers/hwmon/asc7621.c                                   | 4 +---
> >  drivers/hwmon/dme1737.c                                   | 4 +---
> >  drivers/hwmon/f75375s.c                                   | 5 ++---
> >  drivers/hwmon/fschmd.c                                    | 6 ++----
> >  drivers/hwmon/ftsteutates.c                               | 3 +--
> >  drivers/hwmon/ina209.c                                    | 4 +---
> >  drivers/hwmon/ina3221.c                                   | 4 +---
> >  drivers/hwmon/jc42.c                                      | 3 +--
> >  drivers/hwmon/mcp3021.c                                   | 4 +---
> >  drivers/hwmon/occ/p8_i2c.c                                | 4 +---
> >  drivers/hwmon/pcf8591.c                                   | 3 +--
> >  drivers/hwmon/smm665.c                                    | 3 +--
> >  drivers/hwmon/tps23861.c                                  | 4 +---
> >  drivers/hwmon/w83781d.c                                   | 4 +---
> >  drivers/hwmon/w83791d.c                                   | 6 ++----
> >  drivers/hwmon/w83792d.c                                   | 6 ++----
> >  drivers/hwmon/w83793.c                                    | 6 ++----
> >  drivers/hwmon/w83795.c                                    | 4 +---
> >  drivers/hwmon/w83l785ts.c                                 | 6 ++----
> >  drivers/i2c/i2c-core-base.c                               | 6 +-----
> >  drivers/i2c/i2c-slave-eeprom.c                            | 4 +---
> >  drivers/i2c/i2c-slave-testunit.c                          | 3 +--
> >  drivers/i2c/i2c-smbus.c                                   | 3 +--
> >  drivers/i2c/muxes/i2c-mux-ltc4306.c                       | 4 +---
> >  drivers/i2c/muxes/i2c-mux-pca9541.c                       | 3 +--
> >  drivers/i2c/muxes/i2c-mux-pca954x.c                       | 3 +--
>=20
> Reviewed-by: Jean Delvare <jdelvare@suse.de>

Thanks
Uwe

--=20
Pengutronix e.K.                           | Uwe Kleine-K=C3=B6nig         =
   |
Industrial Linux Solutions                 | https://www.pengutronix.de/ |

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220705103615.ceeq7rku53x743ps%40pengutronix.de.

--gut2agzhpaayxotv
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCgAdFiEEfnIqFpAYrP8+dKQLwfwUeK3K7AkFAmLEFBwACgkQwfwUeK3K
7AkavggAgLmynakXX/rOF4Jwy2OuBXH29kecKqPd6xj4yHsu3ggy8kd/hlU4jJib
vV0H9ioq69hhMqjme5AHJJsueLFi/t/iwuQwuWUKluCBBlx0RXBsVx8qxV7A0uWa
mdKU3ApPaN7y0cS1jccdN7ydsL3H2ayzIwfQuNqx1G3P/uqXfkusV0fjwQ/rQct3
qs4t2/QiHUd0tStlGw2eSKxp1z5KRrDMstK17fiZSsw/SYoMyldV8Ame6+gaxx0X
e93FqM5jj67ovjD3jJanfOwI5vesu4+szu4GK6vHRWvpsieHsSeyS+GNgfM5oLA7
iguZ0rauzy0je3hrHuKgp1maJ59ibQ==
=fYiS
-----END PGP SIGNATURE-----

--gut2agzhpaayxotv--
