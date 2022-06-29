Return-Path: <kasan-dev+bncBCX3TTWUQMPRBKX456KQMGQEJB7OY4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id AE29655F8CA
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 09:24:26 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id k5-20020a05600c0b4500b003941ca130f9sf6247636wmr.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 00:24:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656487466; cv=pass;
        d=google.com; s=arc-20160816;
        b=FGqhWo6iUcXZm8JWYXcMngo8655Edy9kUWCBIzrQl2xpic5PNZgQz698xS0zDcCdKj
         +TIlkK/tgpJSTnQNhH0N3TkUPr4EKg1RbPU+oDEKy585wrZmYmzm/dRWmcSoqYeEp42G
         Zl7R44iixHmYWlqo2jTeNhqH9dB4ssBdDi1Kow+dphK/dmP4mBjEbnxFbj5DtEFzsEXD
         jnWJUORiVMo2w0cUue+d/BTdQoi1l7CDPiZjek56sxKX8MvQTzBk0JXYntiDwFoQxOOp
         UvYLiPM3CAoXAeAYjuQ2Cx+Y2UEEXnSVn2Sq1hO1q04mCCt7FfojyPZIyRXQOF5WXpNd
         UNQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mDFU0JxXJLe8gN6x6rLlLse23s3LXPy7NXVDquDgmI4=;
        b=QNkfn/IWmeF1rSQUkX/67U1l7R+Qa9eMzmhU7eE+T0dbGmZ2R0HcWQb82oKGnPNA1t
         BzJqc6fHDdi+vkLS2UYBf1GRdOB7gK2u2U0tjJL6nII9fIzU4sPWn/Oa65i2nMVlrpTs
         +OX6UILyHjgpiwImQlKG4rGUG7WFSZCFDjyy9qBtbUy5oM23Brt9+iW1YXsL20eHgr5s
         X3B2Hc1zzLVIXDSlxjQC5MUxxmm9qOuMjQsn4u28926Sihdm47mqP2jEeMI7MCQJxy9/
         EpE5rrQs6ah4hAMTHbacteGVS79XF5Uj03S7XtgJaaP6CQQ1K4iWtu/qGbR0ImPpYtjK
         eRYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=ukl@pengutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mDFU0JxXJLe8gN6x6rLlLse23s3LXPy7NXVDquDgmI4=;
        b=DgQ78+RhMyOlGVMMUaLBUYAcCyTApRH1r93ACenFSYWNSfos7sVzfNciXqSEbvfhhq
         C3guT9m9bZ/HxItFYHg8VsxIyfmonf6hsATVU+jLETbbTqMl8l6DgBxbjD2Q81XH1unV
         YPa68dCNN2QcqlrxbBPtosQBJbXzfpiek0+Z9K5kcgW13kS5yfxBko19Asx+7/iVvYQ6
         wRLmzWDyBOaBlKH3ln4yCjXzmUkCn+08h305GdjBDnXSV971t/K+y8fNJPA+FHMZAcWc
         aQ9NJiiKryh/FObSeJqH/kL8W5of5OOAjI9XcZ8F+qqADXMcWidCsK9yvD1mSksS7d3w
         Qrcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mDFU0JxXJLe8gN6x6rLlLse23s3LXPy7NXVDquDgmI4=;
        b=ejYPtv0oMgczmRTpcDB7qeXx4sv0kLb+NOdTl+dnBvJ/fTesfe4zhQEQxwQP0AtGhl
         Ct4XqUcAqGwkNY9Tkg7Wm3LYN0UdZEMKteAU1i4FwxqP5Yna81J3A6oLAZShiLzaZBaf
         zEfdKrpiDZNA94yU42tmnwiSWO2Z56nhhMxOQdUn+3/neB0smxNv84xRIuKFlv+yLvow
         Ym5yEXCgzr9DPEwr0NR7PQ1JT+o9ZvTCGqXxAQ4pxAQKrzaXysFkER3nPPhTqUY7QV3M
         84jhTYWkyruzCAvw+mSEUw0gTwl7ajHQELJY9rkvzaZGwOv+k+lpgP5MQpGsBaPi1Gp8
         TCDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/KFENCg+D2EYzO2cJ4xxjd2hPw3TWVIKNJr9D8AWbrJH7AJ73R
	SoWKwNtO1BaL1pM4iH7qsPE=
X-Google-Smtp-Source: AGRyM1t7Giep0gGWj3dvKobaYxa9lChFLVgTYCGBPbJHi9Bw1QbRx/v3yFpCht/wL4zayoA8vDqV8A==
X-Received: by 2002:a7b:c18a:0:b0:3a0:4fe4:41d9 with SMTP id y10-20020a7bc18a000000b003a04fe441d9mr1909889wmi.58.1656487466218;
        Wed, 29 Jun 2022 00:24:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1887:b0:218:5c3b:1a23 with SMTP id
 a7-20020a056000188700b002185c3b1a23ls14531657wri.0.gmail; Wed, 29 Jun 2022
 00:24:24 -0700 (PDT)
X-Received: by 2002:a5d:6802:0:b0:21b:8a4a:e318 with SMTP id w2-20020a5d6802000000b0021b8a4ae318mr1491892wru.641.1656487464849;
        Wed, 29 Jun 2022 00:24:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656487464; cv=none;
        d=google.com; s=arc-20160816;
        b=mpn8SkwWC4oaF8A9KkHggG5oYiHgY0pWMjuyzwJxillVMJwfYkMA3FX8fLllBMTdEt
         2i95afPwMntrwuExBlP+iWPNWuZosKsSY9FbvAasfZy6Mz+bPDzV3pnDVm/OO8WJSk66
         O0r7oZRBbS/cA+6+HxMMmz0rsLsF6d/SuuO++fztCdzEZn2o3fbHXAb4juhxyW2f2Hrw
         oC5K7VoxjTP889uRSYT4Wrsd3Awcav6uSD1W1dhxZtWnctbSvog+soWgW4h/L80mLbwJ
         APz/BUtwgMNyWTm2oHBtCDlRHBSSRuJRgOlZOGy5YhWIhnxdlrjMfMBLlU21reI9ZJvr
         xZEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=mvmBWOVRqRY9R9e6hFPCadXxdAVVPSLY1ijc7/cFi0Q=;
        b=Cr3tht7jCAwVz2EUvt/4CdBUHgRXGXZGnY4krL9CshLZQDsQL2F2jjNVqefWj38kQw
         ZF6tUsIWhmCD7/fNcAWpAPvT6j6JgngLZ0yWlcf+QpzDrkai2DDjyM2LFS3vZIcuoYeb
         WLw5WtUxbjRtIXIxwtJB9jDZsDGzmaxr/crNi0XcTxx0EtZxfEjkVCrjF1NEWw549IXR
         VkBfDx2tz+hHjdSeMRKQausqAV3QBQx3FzKWAIAYCbWlE3xS1bmK+7NlP43FXcaJl5Go
         eO9fGPpI5o4emVP9sDXmz2nLigewq87oiJLKi99y9wSKBLDjQHguhkUVe1Hk4L1+6Vso
         JzDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=ukl@pengutronix.de
Received: from metis.ext.pengutronix.de (metis.ext.pengutronix.de. [2001:67c:670:201:290:27ff:fe1d:cc33])
        by gmr-mx.google.com with ESMTPS id y16-20020adfdf10000000b002132c766fd7si541286wrl.4.2022.06.29.00.24.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Jun 2022 00:24:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) client-ip=2001:67c:670:201:290:27ff:fe1d:cc33;
Received: from drehscheibe.grey.stw.pengutronix.de ([2a0a:edc0:0:c01:1d::a2])
	by metis.ext.pengutronix.de with esmtps (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <ukl@pengutronix.de>)
	id 1o6S2d-0005UO-4V; Wed, 29 Jun 2022 09:23:15 +0200
Received: from [2a0a:edc0:0:900:1d::77] (helo=ptz.office.stw.pengutronix.de)
	by drehscheibe.grey.stw.pengutronix.de with esmtp (Exim 4.94.2)
	(envelope-from <ukl@pengutronix.de>)
	id 1o6S2S-003M3c-Vk; Wed, 29 Jun 2022 09:23:08 +0200
Received: from ukl by ptz.office.stw.pengutronix.de with local (Exim 4.94.2)
	(envelope-from <ukl@pengutronix.de>)
	id 1o6S2V-001qeU-Nu; Wed, 29 Jun 2022 09:23:07 +0200
Date: Wed, 29 Jun 2022 09:23:04 +0200
From: Uwe =?utf-8?Q?Kleine-K=C3=B6nig?= <u.kleine-koenig@pengutronix.de>
To: Jeremy Kerr <jk@codeconstruct.com.au>
Cc: Wolfram Sang <wsa@kernel.org>, dri-devel@lists.freedesktop.org,
	linux-serial@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-mtd@lists.infradead.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-crypto@vger.kernel.org,
	Pengutronix Kernel Team <kernel@pengutronix.de>,
	linux-i2c@vger.kernel.org, linux-watchdog@vger.kernel.org,
	acpi4asus-user@lists.sourceforge.net,
	linux-rpi-kernel@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org, linux-gpio@vger.kernel.org,
	platform-driver-x86@vger.kernel.org,
	linux-integrity@vger.kernel.org, linux-iio@vger.kernel.org,
	linux-rtc@vger.kernel.org, netdev@vger.kernel.org,
	Broadcom internal kernel review list <bcm-kernel-feedback-list@broadcom.com>,
	chrome-platform@lists.linux.dev, linux-input@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, linux-media@vger.kernel.org,
	openipmi-developer@lists.sourceforge.net,
	linux-hwmon@vger.kernel.org,
	Support Opensource <support.opensource@diasemi.com>,
	linux-fbdev@vger.kernel.org, patches@opensource.cirrus.com,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	linux-pwm@vger.kernel.org, linux-mediatek@lists.infradead.org,
	kasan-dev@googlegroups.com, linux-staging@lists.linux.dev
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
Message-ID: <20220629072304.qazmloqdi5h5kdre@pengutronix.de>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
 <60cc6796236f23c028a9ae76dbe00d1917df82a5.camel@codeconstruct.com.au>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="3yzpq2rgg2xm7tqn"
Content-Disposition: inline
In-Reply-To: <60cc6796236f23c028a9ae76dbe00d1917df82a5.camel@codeconstruct.com.au>
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


--3yzpq2rgg2xm7tqn
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable

Hello,

[I dropped nearly all individuals from the Cc: list because various
bounces reported to be unhappy about the long (logical) line.]

On Wed, Jun 29, 2022 at 03:03:54PM +0800, Jeremy Kerr wrote:
> Looks good - just one minor change for the mctp-i2c driver, but only
> worthwhile if you end up re-rolling this series for other reasons:
>=20
> > -static int mctp_i2c_remove(struct i2c_client *client)
> > +static void mctp_i2c_remove(struct i2c_client *client)
> > =C2=A0{
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mctp_i2c_client =
*mcli =3D i2c_get_clientdata(client);
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mctp_i2c_dev *mi=
dev =3D NULL, *tmp =3D NULL;
> > @@ -1000,7 +1000,6 @@ static int mctp_i2c_remove(struct i2c_client *cli=
ent)
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mctp_i2c_free_client(mc=
li);
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&driver_cl=
ients_lock);
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Callers ignore retur=
n code */
> > -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> > =C2=A0}
>=20
> The comment there no longer makes much sense, I'd suggest removing that
> too.

Yeah, that was already pointed out to me in a private reply. It's
already fixed in

	https://git.pengutronix.de/cgit/ukl/linux/log/?h=3Di2c-remove-void

> Either way:
>=20
> Reviewed-by: Jeremy Kerr <jk@codeconstruct.com.au>

Added to my tree, too.

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
kasan-dev/20220629072304.qazmloqdi5h5kdre%40pengutronix.de.

--3yzpq2rgg2xm7tqn
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCgAdFiEEfnIqFpAYrP8+dKQLwfwUeK3K7AkFAmK7/dUACgkQwfwUeK3K
7AnTJgf9GW2H7fk9/Je11PRlCnUOSZ1sz/49RHAm4xj66pI/hdRP++D8L5o7ntEU
Hl5hKosR36cUyX12ie+YQtiCRkjhLqUoJnPzJOtcXQNV7mlMt6ds2INSO4iHYtMa
b2UH+lLQ6K/DO0+1KquElKJhfBOKucYY1WQAVK4cfasBKMR4MtukcHAgcYClRYdj
Nvvy6bCjqr8M1+uqDTJUUR/d0rWYHxFKygYRUfK7YPpz57gaVgaR9Js9GDGkVFB4
qVL5x23NzgB/Djr1Ls1F6Z5eFMjbtVb+S1HDRsU+HJOYD6v1LkT2OFx9iFpme+8m
+4HHNR5pxKogz59u4YpP1pIb0MejhA==
=ibah
-----END PGP SIGNATURE-----

--3yzpq2rgg2xm7tqn--
