Return-Path: <kasan-dev+bncBCX3TTWUQMPRBM5NSWLAMGQEML73M2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9490C568384
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jul 2022 11:32:36 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id j7-20020a056512398700b004811ba582d2sf4860042lfu.5
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jul 2022 02:32:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657099956; cv=pass;
        d=google.com; s=arc-20160816;
        b=F25CXxMskeywvTo3nD2I4SGvhAcLEKXlQd4u7TsUbeqNf6Uon2sTRAt+fkruDPd2W2
         sw+cjPbvBaF/VStaqk6hj0pyJiqvJARSZ8vutsU5XQVv4Kz+IOHHF4dTyrx1Sy3m+Uw0
         SeQq7t9uUFwxxEloGBvAXJbIzdUMUglLlcACCTeXwgzQS/gmF+PvWKJ/FcWNq+Bqo6Uj
         Joom5/MFjLeHBbvjsr2VOsR1lsw9Heco77HRMwTJLn5RHH0frBpX7mUMz7zB1aPgzA3i
         /1RaUVl9dRYgKNKRrz9On1Oh0JXHRCe5nGGjHvHmZKIl+YL/t6VlH/w5OJd7FHGNkWUm
         LrSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=oFWt4fCSdH3C+ZuPI7Kojfl46AtV0/hpN27Bg/OAHaU=;
        b=ZYwuQ4DnyL4cEnNXWemOp8TL27RX2PvVdGlGW3nHh/N30XQdRw6dZtKP6hRp5S2TWt
         lqkPnNTBwi5nwAMxhVa/ZqXS729xAd7LUKcXTgFTMpJtw8vqteJoStZ7JJx8lzOpgHIX
         Bp+muVOWjf5ONx/v7bVN9HIeKQTj0UVWX5VBzNWzrtG8b+Br5q+oKRqW/yMPW8HeUYM+
         zujEAYqhzlD8NyI8nA1OS/EJUcsS/ormA+/NrU9fQEm0AFY2OXEBPUeFyV4jLEXZWDC2
         hDFmr2cURb8uirBuvJ2GXFEccsRwMIR9PA+XsIcjlwVil8uVT8th4IKm7ec+ILoBq/TZ
         U59g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=ukl@pengutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oFWt4fCSdH3C+ZuPI7Kojfl46AtV0/hpN27Bg/OAHaU=;
        b=bvooBE4UIUpFKagIMVVrmBwHi5LiI2UYoWsGUz4BcdwaKRU7gRJhi1aTA13ytXJJUD
         3/kyhKZO2GKzALgzOkEJzEt5kHbtda4IvsR8d9rDoQb+gAjVcycnRqAxqOROYiiGdpkv
         Td24MRKBQ1uBn/NsjH6P1QuBbIw1WLtgerk0oI/ioWn+L8mZTCo9DLV9dusZkHmnKTmB
         5hoc5/d7euHeA5dQUAjCgqfVsi9+DKntc7TPnJNuLn0N5deMMlLkrG/aQ4xhVn5ppvck
         v1c4ttKbyu0gvnK4/uPECrENe08wKSaYfVNXT1FV136b/VEYuIk3QNAP92DhhCLMSNCd
         szHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oFWt4fCSdH3C+ZuPI7Kojfl46AtV0/hpN27Bg/OAHaU=;
        b=6/oquZONa5HSTPBMPzVvsulWSIzrT/Ed5mj0uO0SWVKubmiQ8nK98kPRCEU8almsuH
         gOYVyvCLXq/NmEXJgNxvmmnIUJyRWUgALTnGIK2GTeEu/YOYvjx4BaIxBtG/G92EOCzO
         gbhtaVL/AyzdYjuzwv5fE/DbabWVlq2jtJWHVYbURlGyYomkPrCKCskeQROoJKP0Xaim
         JV60uSiiNqHTiE7GktlCcTqzqBN0+zH6ZSRpLuGo2tvONcHBlq5Fv5IYBtD0vi6CIUqt
         yaAHwH0j04lzx6rJUYiuxWtibwkE9mfmBKesPH7F6dcMpZWJsQPk/xXAtvSYtn782Hkw
         Vvcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/Q/qUzqfXqvsdw52epsT41v402jXLLoYrFTixmsF1kM3s8+Hke
	fIAGJuQJ+1+tWiLQD1n9OyM=
X-Google-Smtp-Source: AGRyM1s/uWGnWaK9KJV9nMTAmS/azm4tM92GbMuJzP5RatXT9V2L5Xf7mNjEc/L5ZqbKXXYkI7OqVA==
X-Received: by 2002:a2e:3001:0:b0:25d:2c0b:3e15 with SMTP id w1-20020a2e3001000000b0025d2c0b3e15mr6078067ljw.302.1657099955878;
        Wed, 06 Jul 2022 02:32:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:99c6:0:b0:25a:89ff:c693 with SMTP id l6-20020a2e99c6000000b0025a89ffc693ls6612477ljj.9.gmail;
 Wed, 06 Jul 2022 02:32:34 -0700 (PDT)
X-Received: by 2002:a2e:9f16:0:b0:25d:48a9:4f2a with SMTP id u22-20020a2e9f16000000b0025d48a94f2amr351112ljk.454.1657099954366;
        Wed, 06 Jul 2022 02:32:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657099954; cv=none;
        d=google.com; s=arc-20160816;
        b=QV2kj2p2csDdH+b9xR3MpWp2tzIhKSnwM8bwv3KgMM4N0KG0dKqoozLYDXg4yqY+6x
         3vaNRUOEJj8acuzQutjHi0Tr7YL4BNEUEWEuc2ZJA/UYzNfL2buR2VDBYbgTAB5abLM0
         1o8IWl/wTWZbyJ0Q9hrfFoTRh6RMqxL0My+IZXK5SNlZypfLaftQ8Tta20SsMg4/zRMJ
         FPFKotT0hnFzjJKn+mLmmW1gW3BPY6dU9IKnaquLGyayi/qnECSfGwsuLe3POsPxeVuV
         tEbUswWeUvJ20gn1Oy/GjkyPGm76IASUs2mjwOQCH/6ds9/T//Ist31NOCqcIfeb9oN8
         Jtew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=tMU3E4eYksx+zNdAVlL51uq6GohePbaqlSk6+eyDGGY=;
        b=YQDTPU4bNiLmfziOfp9483+4SYz2IhOIgZO3vRIWxLlLk73Hf2elx5j5IzqQKKPFwX
         42Q3WZu7ynUrgXXht8BotzTLMX9/wFrIqqXCWDU2Ppoyo6OdhykM3UtHUJNnrt0kn1lV
         edHqrdbl6cvduoFEP9KCJWDJ4XbqkMwoLwmXnsFWWeMlrZOiffA7q1c1p9cRdBnQ7Cxy
         X1h+iz2eLPazPfGDYmZb1fITHUcgqgUzoqzAYzcNjaEBPhwUtFdd+8OcUWm+BtPx6YoD
         xd1xKjuAIgfd1epjqhLo6VJfIVXnbvBGqSAHZyXx4hEHeTxgCjO6p9JHUvm8TKBxdu58
         nv0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=ukl@pengutronix.de
Received: from metis.ext.pengutronix.de (metis.ext.pengutronix.de. [2001:67c:670:201:290:27ff:fe1d:cc33])
        by gmr-mx.google.com with ESMTPS id c38-20020a05651223a600b004811cb1ed75si1139309lfv.13.2022.07.06.02.32.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Jul 2022 02:32:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) client-ip=2001:67c:670:201:290:27ff:fe1d:cc33;
Received: from drehscheibe.grey.stw.pengutronix.de ([2a0a:edc0:0:c01:1d::a2])
	by metis.ext.pengutronix.de with esmtps (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <ukl@pengutronix.de>)
	id 1o91Nj-0005lo-Ss; Wed, 06 Jul 2022 11:31:39 +0200
Received: from [2a0a:edc0:0:900:1d::77] (helo=ptz.office.stw.pengutronix.de)
	by drehscheibe.grey.stw.pengutronix.de with esmtp (Exim 4.94.2)
	(envelope-from <ukl@pengutronix.de>)
	id 1o91Na-004jSK-Sg; Wed, 06 Jul 2022 11:31:34 +0200
Received: from ukl by ptz.office.stw.pengutronix.de with local (Exim 4.94.2)
	(envelope-from <ukl@pengutronix.de>)
	id 1o91Nd-003KbY-Gm; Wed, 06 Jul 2022 11:31:33 +0200
Date: Wed, 6 Jul 2022 11:31:30 +0200
From: Uwe =?utf-8?Q?Kleine-K=C3=B6nig?= <u.kleine-koenig@pengutronix.de>
To: Vladimir Oltean <olteanv@gmail.com>
Cc: Wolfram Sang <wsa@kernel.org>,
	Uwe =?utf-8?Q?Kleine-K=C3=B6nig?= <uwe@kleine-koenig.org>,
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
Message-ID: <20220706093130.cet7y7upl76rp6ug@pengutronix.de>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
 <20220706091315.p5k2jck3rmyjhvqw@skbuf>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="yp3ilhvx53xygi7l"
Content-Disposition: inline
In-Reply-To: <20220706091315.p5k2jck3rmyjhvqw@skbuf>
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


--yp3ilhvx53xygi7l
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable

On Wed, Jul 06, 2022 at 12:13:15PM +0300, Vladimir Oltean wrote:
> On Tue, Jun 28, 2022 at 04:03:12PM +0200, Uwe Kleine-K=C3=B6nig wrote:
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
> Assuming you remove the spurious kasan change:

It's already gone in my tree, see
https://git.pengutronix.de/cgit/ukl/linux/commit/?h=3Di2c-remove-void

> Reviewed-by: Vladimir Oltean <olteanv@gmail.com>

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
kasan-dev/20220706093130.cet7y7upl76rp6ug%40pengutronix.de.

--yp3ilhvx53xygi7l
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCgAdFiEEfnIqFpAYrP8+dKQLwfwUeK3K7AkFAmLFVmcACgkQwfwUeK3K
7AkOwAgAkt7aZ38n1lpOoBzXslSDQyp/lKc47Ehs+a1LTESfOP6+4frSHSJhaIMw
WX2bIAZO2kfHd2GJJ1+miP0YO3eys+YJus7vlVp9LsZCtTrR7uUlJ9PhG4eVmYxD
ZPZMbP533Mkp9Tj201PJRSbnOlhRhKnwpl4kQfj9nXD478yP1zbT/7CDh4Im1isE
dOUnNdPTAnT17u0fIRREu6TIC/hKy5Lh772ukCBsHwkBWQD4WTtLmdL1uZrspPa3
fKxI4tIGoKufFCNMNNzK8li/dghhpkn4uy8iNwyjkkmjfCXAkNdwNJiCDlo6qPwb
idJ3DvpJEEx44L8KdcjzBYUHdSNUkQ==
=ZnQL
-----END PGP SIGNATURE-----

--yp3ilhvx53xygi7l--
