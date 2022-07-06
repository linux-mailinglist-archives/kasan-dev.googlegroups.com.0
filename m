Return-Path: <kasan-dev+bncBCU77JVZ7MCBBMFESWLAMGQEYO7FS3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id AD8A756830F
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jul 2022 11:13:21 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id b23-20020a2e8497000000b0025d4590922csf504102ljh.7
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jul 2022 02:13:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657098801; cv=pass;
        d=google.com; s=arc-20160816;
        b=R+dJIJ9+u7zRUxfG4zfi1bQCHeiKX0Rl95nGYNQKA0KkAnGbR4aqCuLzEfflJrhOVU
         AusDfbnetbkrnezUWqk1G1/QB67h3WSVqZFB4Res+pP+zzVPjqGpBTonGtbv3p0qybVf
         kFfjQsDpfqs/CY3fvOKytvcl/R7lO7AlO9K4xzWffc1eiNoQDuTM3ScNwQlCgd5QVmEh
         ybLuDogVUKGHFuiFzZfH0i1perD2Q5x6wnMm7iqYamtutZtpRl0L3V/k5WyQ/9i3H243
         Q5+2+nhUOtvZcgkFDLJRJfd5MRwuLOWKRkxj8JM3cBneaY5Cw1A38GA/a+/lN/pYvJlO
         BfLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=MI8OmFU2j/QhPkGs2sWUfS3vQrwDIjzx4W71H9/GUD8=;
        b=y6lnaRiJgq+pPYnDMzsX1aM0a8qVZmnNxKtknQFHVHSa+xoru44/uTFFBCVtsr9Gbv
         tdolIBRNAm2XqGTgfLqO5Fch7ayTYeMINjDRqoi9v6XS68ui0uo+Zswus/I65DAnXHHj
         XZE2NAkImY+BFOI+By7UrTPKiLuptdYdU7QkiE5YIQATqZDIXDRrp0Y6L/Olmd0qp2vB
         ZDdOIvandvN5y4kvs04k/HI7kDrhLn3lIgBwvJcLV7AaHPuOuPpeEoplyREK2a8N02oU
         59xQ2+bTciASJvxrA7sWO6/xCBh51acWCvfD4MBC2Nto/eeh1GXio7HUqu5Zee9fYNYF
         3P9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UyINPEp8;
       spf=pass (google.com: domain of olteanv@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=olteanv@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MI8OmFU2j/QhPkGs2sWUfS3vQrwDIjzx4W71H9/GUD8=;
        b=HfXJUrZke0AlGmFdXXG0PAkaffIcO/fGVfdm03+2Q62MbzU8DTytwiwwfBUZZQ1nfm
         iG2UGaiVFUi3Z2hIv4Jcv/NJbJenDTcNmliraoWnQXpNDG4c0zYkOZFePCHPHc1AnhOq
         mlX3Rkzg3qnv/ZbvLYwcvxtvmfOaoMZiLnN1S6t3w1mY8xg9+xbjofYRbiZBH6SfwQ18
         N3DXuQ8g8fYBQIlmWu1yZ8UrEjNwH5isOM+q9TQRUC4yKRfXV2CguyXK4gnYS0NU866c
         O10ejrtq0M+fHOwPLJIgPMrN53BiCqcQPPLf2dIDU4FI7VGH3HmkHxg/pQe0tCZUqLZq
         Yowg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MI8OmFU2j/QhPkGs2sWUfS3vQrwDIjzx4W71H9/GUD8=;
        b=CugHNwSj+jty7mTjXLGI9EkOvaU2FeD7Ct8o5YpP/xp2O3wQ1j5h4gkKkIe3yoqKqH
         qdQ6LRtIriI2S1lZnBQtPH1IVPwyyR+uJwTSaEttEqR6MERt/x8Kc4e8kmEeEI4A+Zf1
         52VGJ7bgFMJHjE+nQ+gXuJPtq+2wJcZqDX7vHddIBfMaFs1m1S0ibOR1eORc8iBohFMc
         qjuaXGc8KiMHRSurZ8zj5jYBq70/rZXJUSYlBda5scOp/sZ9rMmFqYDMMLX4T9XDYGsf
         FViTR1cab71IRMqVzhgLHaZKexJM5kJtJN05XvHNbMGrA4qYH94GyAI42Rxn8d3xjst0
         q0gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MI8OmFU2j/QhPkGs2sWUfS3vQrwDIjzx4W71H9/GUD8=;
        b=wlLxwHyhzHWfaXB9gPNiDSBqC7oSoNs/vh784XuuO6isBCmOhCaF6CpFYKlaTHXrlv
         9WilfSsUhykkOqR6ByfFDekJSTWPqYG95XnzC51vWnb/jNwAamt27U1Wnpn7FOnCVaFp
         LYnt8IYRyhrwu4iGV4LNJ71/qx97BAdbY3PV17DdDEgP/kcInJ9kBSqeF9onivmzgC09
         FynwYORprF6jaKBme1K092Rkv9vgqoCxS9FPfiPppMRM3k2y4C8Jq3vfpLnvf/Px/vJ2
         d9E0ZGebzPggJDchQRUEIJks6aXsHbquligbaR6+Khu5Z1cTOaTN8KJsvJQpWZV7F5uk
         CZrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9dBoYQco8lxNUHJIySsh29PtdKw7nqLZIvO/UCWq6AoIWkjrEp
	SqSDStxi18BUBnDWW5RlULo=
X-Google-Smtp-Source: AGRyM1tLHfQlVukK5Z66u/aJSc6Z/bbls5V7y8kXcL0Ue3Qi2NNwXruLX07vSwWE2mKwd1qWJut5JA==
X-Received: by 2002:a05:6512:1684:b0:47f:5f27:b006 with SMTP id bu4-20020a056512168400b0047f5f27b006mr25887169lfb.225.1657098800856;
        Wed, 06 Jul 2022 02:13:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls333889lfv.3.gmail; Wed, 06 Jul 2022
 02:13:19 -0700 (PDT)
X-Received: by 2002:a05:6512:22c2:b0:485:8c7a:530d with SMTP id g2-20020a05651222c200b004858c7a530dmr2215596lfu.459.1657098799507;
        Wed, 06 Jul 2022 02:13:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657098799; cv=none;
        d=google.com; s=arc-20160816;
        b=wiqRcQ47VR/dtyN31eudiQihBTsJMlm8Xs6+7QeuhxvcGMJN74OhigI7IUU89gc0pm
         CeVLztQxF1MswXB0aEelBg7v3YGrMp5GfjGb08FlR1Zq5e+3Z5t27H/K1sRStzFITFki
         co5jrULqoCIdyiDyP3bomywzz3JdyYaJ9qHWdwZMkS/HFrLPDGH/jrSs0VUJSl8+0zpk
         g20Ya5OSodg/9rZVsiUhDB69Mf3AP8DC+QN0iffQr65PsqYXc383hNjm7nwpS0JAWAZC
         aBzRawjOdBrMELg9CvAziNwl4d2+dPBunLnSClqvntksB601FVqADYbcDu+8Cm3irE1P
         w3fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=WKlacHhWVR2IblvCAgYMcCw7cvtmo7gBzlhxFpijOWM=;
        b=em9XtJ8s8RyHgWGiDC8kBvKsKWjT2hvbj+Vhl3v5uEn5K16xDuyQs9/SfsaGej8wbz
         TWtVFrbNN+BCPiOKP9dHWz4qTp6bInjElj085bDvtcULSdEOBIAbFOW0mOgboetTavmB
         n+jvZrhcD0fGnetTBx08vmY9I21EzEX/4I6g3C5jYi559NMcg/jIdMUGKCjbIhE5Uy37
         kowIs/L4GZhYmmj0ShT+R6omnh+MQjL/xAU6H8RVZiOuxFvVwFgeicPDS1pd9BiI2HwA
         HGBRXulwRxJGBAQpFBBsoYsDZ/AqmiSRWgUM4ffDfaEp0bvgcyC6SnBgjNsHUzmLTEYD
         fycg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UyINPEp8;
       spf=pass (google.com: domain of olteanv@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=olteanv@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id g14-20020a0565123b8e00b004810be25317si1183171lfv.4.2022.07.06.02.13.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Jul 2022 02:13:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of olteanv@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id e40so18444164eda.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Jul 2022 02:13:19 -0700 (PDT)
X-Received: by 2002:a05:6402:350a:b0:435:df44:30aa with SMTP id b10-20020a056402350a00b00435df4430aamr51209856edd.403.1657098799156;
        Wed, 06 Jul 2022 02:13:19 -0700 (PDT)
Received: from skbuf ([188.26.185.61])
        by smtp.gmail.com with ESMTPSA id er13-20020a056402448d00b0043a5bcf80a2sm6350790edb.60.2022.07.06.02.13.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Jul 2022 02:13:18 -0700 (PDT)
Date: Wed, 6 Jul 2022 12:13:15 +0300
From: Vladimir Oltean <olteanv@gmail.com>
To: Uwe =?utf-8?Q?Kleine-K=C3=B6nig?= <u.kleine-koenig@pengutronix.de>
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
Message-ID: <20220706091315.p5k2jck3rmyjhvqw@skbuf>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
X-Original-Sender: OlteanV@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=UyINPEp8;       spf=pass
 (google.com: domain of olteanv@gmail.com designates 2a00:1450:4864:20::531 as
 permitted sender) smtp.mailfrom=olteanv@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jun 28, 2022 at 04:03:12PM +0200, Uwe Kleine-K=C3=B6nig wrote:
> From: Uwe Kleine-K=C3=B6nig <uwe@kleine-koenig.org>
>=20
> The value returned by an i2c driver's remove function is mostly ignored.
> (Only an error message is printed if the value is non-zero that the
> error is ignored.)
>=20
> So change the prototype of the remove function to return no value. This
> way driver authors are not tempted to assume that passing an error to
> the upper layer is a good idea. All drivers are adapted accordingly.
> There is no intended change of behaviour, all callbacks were prepared to
> return 0 before.
>=20
> Signed-off-by: Uwe Kleine-K=C3=B6nig <u.kleine-koenig@pengutronix.de>
> ---

Assuming you remove the spurious kasan change:

Reviewed-by: Vladimir Oltean <olteanv@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220706091315.p5k2jck3rmyjhvqw%40skbuf.
