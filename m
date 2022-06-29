Return-Path: <kasan-dev+bncBDRZHGH43YJRBW6N6GKQMGQELM3ABWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id E0A4A5603A1
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 16:51:08 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id z9-20020a376509000000b006af1048e0casf12154803qkb.17
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 07:51:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656514267; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y6sMUX/s/eXE71ZbrxPyCsjfBFZE+gbW/h2VjYQGiDjjwlff50OHmjFT5WerJ5+0Nz
         T1OlJggehfG3no5TodWtotdpCdGBJFkMeb1a9pRhjzorHGZTkVU4MeQMj6AEMBaVjHpu
         Uq3MomybqzldBq9ZFHsPzp3oAlpvmCq5WGV5cLtVr145x2ihn5BzbAsJTs2fo/mTiztD
         1WYrknGJmtOOD1YTkeiGgQwwGp2kG0Tnwb7tSiB2NU2EHCPJQcvNEbadd0fPOvFWFUsU
         iHl65B/+zrDbiRFVBoFybQ9AsvxXWqBA8bw3Y+YxZPnz9CvxHRse1Vig1QVVeJUlA2lW
         27NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=9JKS4ZNlPQ3/jRgvXT78Fx5gvnD42G7L0igkIYA1eRs=;
        b=x2xMJBKYYRvjoMbx7Z4/Eoj1dIdfDpw50oPdLHfQdZ+M7u9Ws5OwTYrLe6eC6P7IKL
         RLkcA+VOq4BZH1HL/WZQazIS1zOc+K1sfnLY88Y9dmX5S9n+XE8mjQABfrrsc5/QQ6S2
         oIkYjlcenJa63DKr0AZkNhzzQmiJZTsKGZpwSVKAGoSBHYu9IbKBYM5bp4LtCiIRIDhK
         E58fsVC7+K/C0ntC+ZLzzRPxWkFU/lLWINH6KC+izsG+D6A6wDfF2yyTOgZRfwjsx29t
         1evP6sWpz4Wi3rE1xFLle2ryXYl/f8IkZl3NpvFzE+bLoSX9DQm9t7XCH0++8acWYUMv
         l1cQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=B9oiCLcI;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9JKS4ZNlPQ3/jRgvXT78Fx5gvnD42G7L0igkIYA1eRs=;
        b=YVJqVfXIAm3imEykZO2ej8ej35aQRtNDZiHtnrWgkURD68yrRLUJX2xHaeFMo+Zh7d
         awuaqG4ikqj1wvqUsFY7+mAaDnuuRkM2aQ0ePn/IKohTTlOaNstvJcdbleN/6vyUo23Z
         aXYswZ+AIkLh8ik0Ci7ApL8jxc35JtCnZtuhC0lL2AeZmCUMsRUoKpLEobPldGGLIVHE
         IrKd8S2jVAfxQApDLQK7ZHA76CyrO3P5FRpJPD4aMB3Hm57/4M3nc3OGiZL6ZwrYmylU
         d/UwWzM84UQ5/2nzwfCNS582ZbVSfyzUzy8z5Vm9bShmajIvZ+csa/WGdlwqeLLCeXPn
         TyKA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9JKS4ZNlPQ3/jRgvXT78Fx5gvnD42G7L0igkIYA1eRs=;
        b=bUr59v0J8u1MZgvjnabarcfT8EdxVXplKJ8TNVjQrImyvCnpOHBAP85YA4jUJHs9eh
         vGEbaQ3ECPxYb0eitvKR6/2ZDThUXPHdWkhTLyOftGSNYRm96krT3zZU/gb9fHQ8aaQC
         0X/7g8dSC/n1dtih0rSaPa+hOftmTf6CkwmlhbAgFx8HWlc2U3SCmzu1QxwXbIR/FSaw
         WNZTR+N8Y5u30drMb3VKST2Ij81933PsIsib6Mxqh59I/FT6MnLfTHeXEAW9z9cydSmw
         DSBSBHZ06oE4cO3+cPuvK4MPcN0KeICcOec3ylC1m/AuqfoSE89uTEzWsr9n6VV9biz0
         XSmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9JKS4ZNlPQ3/jRgvXT78Fx5gvnD42G7L0igkIYA1eRs=;
        b=modf7vX9qiHRStx/IOnTXJNVTOZHzav6+00az3FbrWM51hyKx++qHuyeVEg7Ynzgji
         8YRlSRLFA1d3aQ3+gwEFxZhc45djyNkuYDxNi3qOBpDVGu6xrtPSa4b/k2ol/EGvS9A6
         FlA/Q2nZrmYtizE0vYfdHSPiO7GfFU+TM7CYh/fExz2GTGyrY1xBU633Uo495/cXFDCX
         f6Erg0N+8MZ7jk5w+QTkvkOD3/N08YUNxcrgH+as5RXGtIY1h674WX9G1YLYBkhrcu8/
         jcj6dNKBSJC/heyYfP5EfbxXN912xfCnZsk0wMLhB5rwW5f8enNYOEQ469F0VnTRpoPA
         qITw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9ZFFaF6Wl6bdQpqIurb/dfDCqdWqc+ZUTidAZhAZaQsKeqUnyJ
	waYy9EOPXnaieJ1VP0z6yXI=
X-Google-Smtp-Source: AGRyM1vYJS7uvlJEFOPivfNK94QfnRzB4S9Dm9P6TCDpVMkUX5DZ5ok94oZlRAoEqTT4JfkuXdJA7Q==
X-Received: by 2002:a05:622a:354:b0:317:7a1d:ce4e with SMTP id r20-20020a05622a035400b003177a1dce4emr2803702qtw.419.1656514267612;
        Wed, 29 Jun 2022 07:51:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1882:b0:31c:75e1:6bf6 with SMTP id
 v2-20020a05622a188200b0031c75e16bf6ls1466696qtc.4.gmail; Wed, 29 Jun 2022
 07:51:07 -0700 (PDT)
X-Received: by 2002:ac8:570c:0:b0:304:e52c:3c2f with SMTP id 12-20020ac8570c000000b00304e52c3c2fmr2747739qtw.8.1656514267003;
        Wed, 29 Jun 2022 07:51:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656514267; cv=none;
        d=google.com; s=arc-20160816;
        b=SSqtR74Dmbj+RSR5ObVPu3bkpJYX+zs4e8sBVVFdvm6qWLud2bhrfqa3wV8QkXjUrc
         YUso5wkJb19pfIigisftw7wjcQrF1K1mFXeUBzKOUrq2nkwtD4quJtpcsrhVcxfcN+LR
         VdwpUAN3Mt/vFOBVJLgvVVevhfYtZSN6Tp9RehJNxD/TdXuPVoWRESkAXlqZmN3bb+vk
         JVNKxHJcLTAIjjhe/1ATK19r18nG2/wwmuM7TRWTqITizgReVHGvjgZ1ZZFxtTXj/ue6
         8ehFYxyEeZAnDC+S5+lFT9fGUc2YNprFYuaL53KmvNNFsKv/TCimLP1w8+wUum6Xc6h8
         D6cQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pwGATE3wVInOXzoFm3DL2iTGSvGusyPbH0jPamzrOPg=;
        b=rbMi1FZITUQJQ6EcHmZ5uLEXL2HHRS/Kg+afIrK8X1hcCqLfREL7LLUd+mQxuQvQ3i
         SyBSbzWhwlk/qCiI1NaxJ6CVajXIUEhw/trtq7Q30xbVJDaQneO1gNMsnDYCadT7ZP0v
         yhdOzp6WbczdjkYd0vmWwoMyvBxpBJWkM19/Eq+EYGtWU+TlA0ZDoWbZLyWpDj86fjJ9
         M4r/U9C+ZGeYmA6H+d/5T8j52XLfoigmXoiw1p/Ss/mvua59dAdYRmttb/ckFeh1Dzsa
         DlHu3Dg7/Ap/2gjFBKOFgvb5lspHCGmumzsNf/ixCgVDETddDh+cskk0CnpXsjPCNty3
         5qvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=B9oiCLcI;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x134.google.com (mail-il1-x134.google.com. [2607:f8b0:4864:20::134])
        by gmr-mx.google.com with ESMTPS id g2-20020a05620a278200b006af266a394fsi426046qkp.3.2022.06.29.07.51.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Jun 2022 07:51:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) client-ip=2607:f8b0:4864:20::134;
Received: by mail-il1-x134.google.com with SMTP id h20so10426689ilj.13
        for <kasan-dev@googlegroups.com>; Wed, 29 Jun 2022 07:51:06 -0700 (PDT)
X-Received: by 2002:a05:6e02:168e:b0:2da:a9f0:c1aa with SMTP id
 f14-20020a056e02168e00b002daa9f0c1aamr2147237ila.151.1656514266336; Wed, 29
 Jun 2022 07:51:06 -0700 (PDT)
MIME-Version: 1.0
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de> <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Wed, 29 Jun 2022 16:50:55 +0200
Message-ID: <CANiq72nmXBv2z-LzEZe47iL39T2Bjjqr4pJqOCta-JCL4rZ9QA@mail.gmail.com>
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
To: =?UTF-8?Q?Uwe_Kleine=2DK=C3=B6nig?= <u.kleine-koenig@pengutronix.de>
Cc: Wolfram Sang <wsa@kernel.org>, =?UTF-8?Q?Uwe_Kleine=2DK=C3=B6nig?= <uwe@kleine-koenig.org>, 
	Sekhar Nori <nsekhar@ti.com>, Bartosz Golaszewski <brgl@bgdev.pl>, Russell King <linux@armlinux.org.uk>, 
	Scott Wood <oss@buserror.net>, Michael Ellerman <mpe@ellerman.id.au>, 
	Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, 
	Robin van der Gracht <robin@protonic.nl>, Miguel Ojeda <ojeda@kernel.org>, Corey Minyard <minyard@acm.org>, 
	Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>, Jason Gunthorpe <jgg@ziepe.ca>, 
	Nicolas Ferre <nicolas.ferre@microchip.com>, 
	Alexandre Belloni <alexandre.belloni@bootlin.com>, 
	Claudiu Beznea <claudiu.beznea@microchip.com>, Max Filippov <jcmvbkbc@gmail.com>, 
	Michael Turquette <mturquette@baylibre.com>, Stephen Boyd <sboyd@kernel.org>, 
	Luca Ceresoli <luca@lucaceresoli.net>, Tudor Ambarus <tudor.ambarus@microchip.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>, 
	MyungJoo Ham <myungjoo.ham@samsung.com>, Chanwoo Choi <cw00.choi@samsung.com>, 
	Michael Hennerich <michael.hennerich@analog.com>, Linus Walleij <linus.walleij@linaro.org>, 
	Andrzej Hajda <andrzej.hajda@intel.com>, Neil Armstrong <narmstrong@baylibre.com>, 
	Robert Foss <robert.foss@linaro.org>, 
	Laurent Pinchart <Laurent.pinchart@ideasonboard.com>, Jonas Karlman <jonas@kwiboo.se>, 
	Jernej Skrabec <jernej.skrabec@gmail.com>, David Airlie <airlied@linux.ie>, 
	Daniel Vetter <daniel@ffwll.ch>, Benson Leung <bleung@chromium.org>, 
	Guenter Roeck <groeck@chromium.org>, Phong LE <ple@baylibre.com>, 
	Adrien Grassein <adrien.grassein@gmail.com>, Peter Senna Tschudin <peter.senna@gmail.com>, 
	Martin Donnelly <martin.donnelly@ge.com>, Martyn Welch <martyn.welch@collabora.co.uk>, 
	Douglas Anderson <dianders@chromium.org>, Stefan Mavrodiev <stefan@olimex.com>, 
	Thierry Reding <thierry.reding@gmail.com>, Sam Ravnborg <sam@ravnborg.org>, 
	Florian Fainelli <f.fainelli@gmail.com>, 
	Broadcom internal kernel review list <bcm-kernel-feedback-list@broadcom.com>, 
	Javier Martinez Canillas <javierm@redhat.com>, Jiri Kosina <jikos@kernel.org>, 
	Benjamin Tissoires <benjamin.tissoires@redhat.com>, Jean Delvare <jdelvare@suse.com>, 
	George Joseph <george.joseph@fairview5.com>, Juerg Haefliger <juergh@gmail.com>, 
	Riku Voipio <riku.voipio@iki.fi>, Robert Marko <robert.marko@sartura.hr>, 
	Luka Perkov <luka.perkov@sartura.hr>, Marc Hulsman <m.hulsman@tudelft.nl>, 
	Rudolf Marek <r.marek@assembler.cz>, Peter Rosin <peda@axentia.se>, 
	Jonathan Cameron <jic23@kernel.org>, Lars-Peter Clausen <lars@metafoo.de>, Dan Robertson <dan@dlrobertson.com>, 
	Rui Miguel Silva <rmfrfs@gmail.com>, Tomasz Duszynski <tduszyns@gmail.com>, 
	Kevin Tsai <ktsai@capellamicro.com>, Crt Mori <cmo@melexis.com>, 
	Dmitry Torokhov <dmitry.torokhov@gmail.com>, Nick Dyer <nick@shmanahar.org>, 
	Bastien Nocera <hadess@hadess.net>, Hans de Goede <hdegoede@redhat.com>, 
	Maxime Coquelin <mcoquelin.stm32@gmail.com>, Alexandre Torgue <alexandre.torgue@foss.st.com>, 
	Sakari Ailus <sakari.ailus@linux.intel.com>, Pavel Machek <pavel@ucw.cz>, 
	Jan-Simon Moeller <jansimon.moeller@gmx.de>, =?UTF-8?B?TWFyZWsgQmVow7pu?= <kabel@kernel.org>, 
	Colin Leroy <colin@colino.net>, Joe Tessler <jrt@google.com>, 
	Hans Verkuil <hverkuil-cisco@xs4all.nl>, Mauro Carvalho Chehab <mchehab@kernel.org>, 
	Antti Palosaari <crope@iki.fi>, Jasmin Jessich <jasmin@anw.at>, Matthias Schwarzott <zzam@gentoo.org>, 
	Olli Salonen <olli.salonen@iki.fi>, Akihiro Tsukada <tskd08@gmail.com>, 
	Kieran Bingham <kieran.bingham@ideasonboard.com>, Tianshu Qiu <tian.shu.qiu@intel.com>, 
	Dongchun Zhu <dongchun.zhu@mediatek.com>, Shawn Tu <shawnx.tu@intel.com>, 
	Martin Kepplinger <martink@posteo.de>, Ricardo Ribalda <ribalda@kernel.org>, 
	Dave Stevenson <dave.stevenson@raspberrypi.com>, Leon Luo <leonl@leopardimaging.com>, 
	Manivannan Sadhasivam <mani@kernel.org>, Bingbu Cao <bingbu.cao@intel.com>, 
	"Paul J. Murphy" <paul.j.murphy@intel.com>, 
	Daniele Alessandrelli <daniele.alessandrelli@intel.com>, 
	Michael Tretter <m.tretter@pengutronix.de>, Pengutronix Kernel Team <kernel@pengutronix.de>, 
	Kyungmin Park <kyungmin.park@samsung.com>, Heungjun Kim <riverful.kim@samsung.com>, 
	Ramesh Shanmugasundaram <rashanmu@gmail.com>, Jacopo Mondi <jacopo+renesas@jmondi.org>, 
	=?UTF-8?Q?Niklas_S=C3=B6derlund?= <niklas.soderlund+renesas@ragnatech.se>, 
	Jimmy Su <jimmy.su@intel.com>, Arec Kao <arec.kao@intel.com>, 
	"Lad, Prabhakar" <prabhakar.csengg@gmail.com>, Shunqian Zheng <zhengsq@rock-chips.com>, 
	Steve Longerbeam <slongerbeam@gmail.com>, Chiranjeevi Rapolu <chiranjeevi.rapolu@intel.com>, 
	Daniel Scally <djrscally@gmail.com>, Wenyou Yang <wenyou.yang@microchip.com>, 
	Petr Cvek <petrcvekcz@gmail.com>, Akinobu Mita <akinobu.mita@gmail.com>, 
	Sylwester Nawrocki <s.nawrocki@samsung.com>, Benjamin Mugnier <benjamin.mugnier@foss.st.com>, 
	Sylvain Petinot <sylvain.petinot@foss.st.com>, Mats Randgaard <matrandg@cisco.com>, 
	Tim Harvey <tharvey@gateworks.com>, Matt Ranostay <matt.ranostay@konsulko.com>, 
	Eduardo Valentin <edubezval@gmail.com>, "Daniel W. S. Almeida" <dwlsalmeida@gmail.com>, 
	Lee Jones <lee.jones@linaro.org>, Chen-Yu Tsai <wens@csie.org>, 
	Support Opensource <support.opensource@diasemi.com>, Robert Jones <rjones@gateworks.com>, 
	Andy Shevchenko <andy@kernel.org>, Charles Keepax <ckeepax@opensource.cirrus.com>, 
	Richard Fitzgerald <rf@opensource.cirrus.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>, 
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>, Tony Lindgren <tony@atomide.com>, 
	=?UTF-8?Q?Jonathan_Neusch=C3=A4fer?= <j.neuschaefer@gmx.net>, 
	Arnd Bergmann <arnd@arndb.de>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Eric Piel <eric.piel@tremplin-utc.net>, Miquel Raynal <miquel.raynal@bootlin.com>, 
	Richard Weinberger <richard@nod.at>, Vignesh Raghavendra <vigneshr@ti.com>, Andrew Lunn <andrew@lunn.ch>, 
	Vivien Didelot <vivien.didelot@gmail.com>, Vladimir Oltean <olteanv@gmail.com>, 
	Eric Dumazet <edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>, 
	Woojung Huh <woojung.huh@microchip.com>, UNGLinuxDriver@microchip.com, 
	George McCollister <george.mccollister@gmail.com>, Ido Schimmel <idosch@nvidia.com>, 
	Petr Machata <petrm@nvidia.com>, Jeremy Kerr <jk@codeconstruct.com.au>, 
	Matt Johnston <matt@codeconstruct.com.au>, Charles Gorand <charles.gorand@effinnov.com>, 
	Krzysztof Opasiak <k.opasiak@samsung.com>, Rob Herring <robh+dt@kernel.org>, 
	Frank Rowand <frowand.list@gmail.com>, Mark Gross <markgross@kernel.org>, 
	Maximilian Luz <luzmaximilian@gmail.com>, Corentin Chary <corentin.chary@gmail.com>, 
	=?UTF-8?Q?Pali_Roh=C3=A1r?= <pali@kernel.org>, 
	Sebastian Reichel <sre@kernel.org>, Tobias Schrammm <t.schramm@manjaro.org>, 
	Liam Girdwood <lgirdwood@gmail.com>, Mark Brown <broonie@kernel.org>, 
	Alessandro Zummo <a.zummo@towertech.it>, Jens Frederich <jfrederich@gmail.com>, 
	Jon Nettleton <jon.nettleton@gmail.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Felipe Balbi <balbi@kernel.org>, Heikki Krogerus <heikki.krogerus@linux.intel.com>, 
	Daniel Thompson <daniel.thompson@linaro.org>, Jingoo Han <jingoohan1@gmail.com>, 
	Helge Deller <deller@gmx.de>, Evgeniy Polyakov <zbr@ioremap.net>, 
	Wim Van Sebroeck <wim@linux-watchdog.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Johannes Berg <johannes@sipsolutions.net>, Jaroslav Kysela <perex@perex.cz>, 
	Takashi Iwai <tiwai@suse.com>, James Schulman <james.schulman@cirrus.com>, 
	David Rhodes <david.rhodes@cirrus.com>, Lucas Tanure <tanureal@opensource.cirrus.com>, 
	=?UTF-8?B?TnVubyBTw6E=?= <nuno.sa@analog.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, Oder Chiou <oder_chiou@realtek.com>, 
	Fabio Estevam <festevam@gmail.com>, Kevin Cernekee <cernekee@chromium.org>, 
	Christophe Leroy <christophe.leroy@csgroup.eu>, Maxime Ripard <maxime@cerno.tech>, 
	=?UTF-8?Q?Alvin_=C5=A0ipraga?= <alsi@bang-olufsen.dk>, 
	Lucas Stach <l.stach@pengutronix.de>, Jagan Teki <jagan@amarulasolutions.com>, 
	Biju Das <biju.das.jz@bp.renesas.com>, Thomas Zimmermann <tzimmermann@suse.de>, 
	Alex Deucher <alexander.deucher@amd.com>, Lyude Paul <lyude@redhat.com>, 
	Xin Ji <xji@analogixsemi.com>, Hsin-Yi Wang <hsinyi@chromium.org>, 
	=?UTF-8?B?Sm9zw6kgRXhww7NzaXRv?= <jose.exposito89@gmail.com>, 
	Yang Li <yang.lee@linux.alibaba.com>, Angela Czubak <acz@semihalf.com>, 
	Alistair Francis <alistair@alistair23.me>, Eddie James <eajames@linux.ibm.com>, 
	Joel Stanley <joel@jms.id.au>, Nathan Chancellor <nathan@kernel.org>, 
	Antoniu Miclaus <antoniu.miclaus@analog.com>, Alexandru Ardelean <ardeleanalex@gmail.com>, 
	Dmitry Rokosov <DDRokosov@sberdevices.ru>, 
	Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>, Stephan Gerhold <stephan@gerhold.net>, 
	Miaoqian Lin <linmq006@gmail.com>, Gwendal Grignou <gwendal@chromium.org>, 
	Yang Yingliang <yangyingliang@huawei.com>, Paul Cercueil <paul@crapouillou.net>, 
	Daniel Palmer <daniel@0x0f.com>, Haibo Chen <haibo.chen@nxp.com>, 
	Cai Huoqing <cai.huoqing@linux.dev>, Marek Vasut <marex@denx.de>, 
	Jose Cazarin <joseespiriki@gmail.com>, Dan Carpenter <dan.carpenter@oracle.com>, 
	Jean-Baptiste Maneyrol <jean-baptiste.maneyrol@tdk.com>, Michael Srba <Michael.Srba@seznam.cz>, 
	Nikita Travkin <nikita@trvn.ru>, Maslov Dmitry <maslovdmitry@seeed.cc>, Jiri Valek - 2N <valek@2n.cz>, 
	Arnaud Ferraris <arnaud.ferraris@collabora.com>, Zheyu Ma <zheyuma97@gmail.com>, 
	Marco Felsch <m.felsch@pengutronix.de>, Oliver Graute <oliver.graute@kococonnector.com>, 
	Zheng Yongjun <zhengyongjun3@huawei.com>, CGEL ZTE <cgel.zte@gmail.com>, 
	Minghao Chi <chi.minghao@zte.com.cn>, Evgeny Novikov <novikov@ispras.ru>, Sean Young <sean@mess.org>, 
	Kirill Shilimanov <kirill.shilimanov@huawei.com>, 
	Moses Christopher Bollavarapu <mosescb.dev@gmail.com>, Paul Kocialkowski <paul.kocialkowski@bootlin.com>, 
	Janusz Krzysztofik <jmkrzyszt@gmail.com>, Dongliang Mu <mudongliangabcd@gmail.com>, 
	Colin Ian King <colin.king@intel.com>, lijian <lijian@yulong.com>, 
	Kees Cook <keescook@chromium.org>, Yan Lei <yan_lei@dahuatech.com>, 
	Heiner Kallweit <hkallweit1@gmail.com>, Jonas Malaco <jonas@protocubo.io>, 
	wengjianfeng <wengjianfeng@yulong.com>, Rikard Falkeborn <rikard.falkeborn@gmail.com>, 
	Wei Yongjun <weiyongjun1@huawei.com>, Tom Rix <trix@redhat.com>, Yizhuo <yzhai003@ucr.edu>, 
	Martiros Shakhzadyan <vrzh@vrzh.net>, Bjorn Andersson <bjorn.andersson@linaro.org>, 
	Sven Peter <sven@svenpeter.dev>, Alyssa Rosenzweig <alyssa@rosenzweig.io>, 
	Hector Martin <marcan@marcan.st>, Saranya Gopal <saranya.gopal@intel.com>, 
	=?UTF-8?Q?Guido_G=C3=BCnther?= <agx@sigxcpu.org>, 
	Sing-Han Chen <singhanc@nvidia.com>, Wayne Chang <waynec@nvidia.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Alexey Dobriyan <adobriyan@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Vincent Knecht <vincent.knecht@mailoo.org>, 
	Stephen Kitt <steve@sk2.org>, Pierre-Louis Bossart <pierre-louis.bossart@linux.intel.com>, 
	Alexey Khoroshilov <khoroshilov@ispras.ru>, Randy Dunlap <rdunlap@infradead.org>, 
	Alejandro Tafalla <atafalla@dnyon.com>, Vijendar Mukunda <Vijendar.Mukunda@amd.com>, 
	Seven Lee <wtli@nuvoton.com>, Mac Chiang <mac.chiang@intel.com>, David Lin <CTLIN0@nuvoton.com>, 
	Daniel Beer <daniel.beer@igorinstitute.com>, Ricard Wanderlof <ricardw@axis.com>, 
	Simon Trimmer <simont@opensource.cirrus.com>, Shengjiu Wang <shengjiu.wang@nxp.com>, 
	Viorel Suman <viorel.suman@nxp.com>, Nicola Lunghi <nick83ola@gmail.com>, 
	Adam Ford <aford173@gmail.com>, linux-i2c@vger.kernel.org, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, openipmi-developer@lists.sourceforge.net, 
	linux-integrity <linux-integrity@vger.kernel.org>, linux-clk@vger.kernel.org, 
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>, 
	"open list:GPIO SUBSYSTEM" <linux-gpio@vger.kernel.org>, dri-devel <dri-devel@lists.freedesktop.org>, 
	chrome-platform@lists.linux.dev, linux-rpi-kernel@lists.infradead.org, 
	linux-input <linux-input@vger.kernel.org>, linux-hwmon@vger.kernel.org, 
	linux-iio@vger.kernel.org, linux-stm32@st-md-mailman.stormreply.com, 
	linux-leds@vger.kernel.org, 
	Linux Media Mailing List <linux-media@vger.kernel.org>, patches@opensource.cirrus.com, 
	ALSA Development Mailing List <alsa-devel@alsa-project.org>, linux-omap@vger.kernel.org, 
	MTD Maling List <linux-mtd@lists.infradead.org>, 
	Network Development <netdev@vger.kernel.org>, 
	"open list:OPEN FIRMWARE AND FLATTENED DEVICE TREE BINDINGS" <devicetree@vger.kernel.org>, 
	Platform Driver <platform-driver-x86@vger.kernel.org>, acpi4asus-user@lists.sourceforge.net, 
	linux-pm@vger.kernel.org, linux-pwm@vger.kernel.org, 
	linux-rtc@vger.kernel.org, linux-staging@lists.linux.dev, 
	linux-serial@vger.kernel.org, USB list <linux-usb@vger.kernel.org>, 
	Linux Fbdev development list <linux-fbdev@vger.kernel.org>, 
	Linux Watchdog Mailing List <linux-watchdog@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=B9oiCLcI;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jun 28, 2022 at 4:08 PM Uwe Kleine-K=C3=B6nig
<u.kleine-koenig@pengutronix.de> wrote:
>
>  drivers/auxdisplay/ht16k33.c                              | 4 +---
>  drivers/auxdisplay/lcd2s.c                                | 3 +--

Acked-by: Miguel Ojeda <ojeda@kernel.org>

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72nmXBv2z-LzEZe47iL39T2Bjjqr4pJqOCta-JCL4rZ9QA%40mail.gmail.=
com.
