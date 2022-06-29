Return-Path: <kasan-dev+bncBCX3TTWUQMPRBYUF6CKQMGQER35HTNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id E9DFA55F973
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 09:44:34 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id r132-20020a1c448a000000b003a02a3f0beesf2010676wma.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 00:44:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656488674; cv=pass;
        d=google.com; s=arc-20160816;
        b=FxN/db5eOt8LsrGJJfBxc8R0MUIOXygpGHgTzub0IIp+8RU3Ham+z+uK12Z1mTw/Jf
         ZHclIDYg+Icgzt4fVVPApltUTLOqWLGfBknu4g80+Y3Prse57kKH2WT08H8NTGTNma83
         HWayj1ON+UnsuIHj8Fggk8KGMBBTTW1TVs4ngMs4mozlvhhcBg1m1OAwojkiZd9UrXJ1
         2dQLtngRk8kL6SV3UtXq0+ssQ7pLbqpl9mkwQBYre6UM2Z91vFVtfo1ftLUXxFP1xsJI
         PxlWuiuX77ZRgKGOUoOo9npdrCc4eK+OTdzD5y8kaQOL0y5kGWzqjZJA6sJs2cT0KpzQ
         F+mQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4jWYCBji9m00JOw9XCHG6q/xzyTL6hVL6v3Ehzl29Pw=;
        b=eI9/zwaMfKF8mHCh3PAH9Ab3T3WzhBj2KMTOWm6R3X8UhXIAHTHagzTEDiqNE/QqHK
         UeWF31kiYgMk7ufcs7UfxWfE7ckwGi+Gq8CDjbVGIZ6OQVzOF1KzZvUcwkFitN2wMIHv
         moDrK9DioIRToziZLlc+Snkb0M+6eZy5DwoikxSiDW6X3yT0pLXvuD2FzEGQYWwxrrpa
         vIhlHiMPD+0O0dQwvrGeRsGARlj0QeLIWOp8US4/W17JOuOVwuOjA4Pcpz19hYSBnbA9
         8ix/OyqILdNbLsi+a2rA9e4Nh4X62rtvX3s8H5YKY9UAXwn2xuqdfo3kgTv066MUTAVn
         y05g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=ukl@pengutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4jWYCBji9m00JOw9XCHG6q/xzyTL6hVL6v3Ehzl29Pw=;
        b=SpujBXl0ttdcsAycTlQguvu0oMsQdWK4J5olvhTjz3pjjccZMkopfnqNVcR13pSSm/
         xO+LGLdtdF8Vp/6LSxvYBSnIEkeCl4Gsk3DXIP6mqxc5l2QJlc/Hx+JIIFVsrQC22Prs
         OUaY9K+U4nITOrzQoo61YLH+VH92Rv5idm4Tnhz1nXBSDtgG/++xqxY+sFjdNEkRb4fV
         Vm0/Y2f8v6XW0ATswmb8dp4mX09AO1/9aGeSMhVXVbm7Ps9Pg0+NWLPTjx0vK7FBz8gI
         KOReSzZ1SS/3sShiAV0qow+YNiRdKPv47h6+5LF76fFEtfTpmcpX8wOi3tH37j1jevIb
         49Vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4jWYCBji9m00JOw9XCHG6q/xzyTL6hVL6v3Ehzl29Pw=;
        b=0PFWLa/HJh+d+JPwXwEH8s3sZxK7hm3qC0y//SbK1LspRAssbEyENpz0w/wzBId6K7
         jT9fj0o8//ZnjD99cyEoXCYYpQf83DltWIHTFT0JhCiCcLPYTV7LddWXYzHeCAMSEJiG
         Yh+5UBcWZhqpXBQQjw+udaq/CSxB7lmpvhDfgDNoOvSGfppNvIwjznunoET0um0fFDSY
         /IHFC/j0ere5ZzqYoubB2fhzK17ZnaNbFIDrqiJBefdWvZyo2v20HlDZBCmywlISap6q
         PfwJ7rmA07qW11MaY4dHPRKUcXHAYXppgSQ9slZGZ+hBga+4JP6E9dWlayakw6If9bt/
         bMtw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9URy4OurMefTdzzLN6No6uTjnqgUrpjSP9zt/r3iEoNV/FNSFc
	1tyaAWLsy+r8YVDimZq9Fs8=
X-Google-Smtp-Source: AGRyM1sixNk1wnYH3UPz06xbmOigQe+uhb1nOkwyqq52STGS1mhTpGCN0T2MLYxlHRcMVPHAe7F6GA==
X-Received: by 2002:a05:600c:1906:b0:3a0:d983:cc2b with SMTP id j6-20020a05600c190600b003a0d983cc2bmr2998362wmq.81.1656488674513;
        Wed, 29 Jun 2022 00:44:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:184a:b0:21d:2802:2675 with SMTP id
 c10-20020a056000184a00b0021d28022675ls1674736wri.1.gmail; Wed, 29 Jun 2022
 00:44:33 -0700 (PDT)
X-Received: by 2002:a05:6000:1d98:b0:21b:aead:9b6c with SMTP id bk24-20020a0560001d9800b0021baead9b6cmr1625331wrb.531.1656488672947;
        Wed, 29 Jun 2022 00:44:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656488672; cv=none;
        d=google.com; s=arc-20160816;
        b=v01nI9pP36Ug2TQ1ZeC724VDSSFBkcAjUnJ7xMag5Gm2+QqiAjS24EJvpxIi1ahcLa
         +P2jtSIJ3sSOkEbCcC2opAyIoT15z+iCYAGz4jpRmq6C/CwPCmC3UKb4dy99SBX24TnS
         FGOTHkU4auvS7nVczSVz+dxbz1Fd/KY5+pULGwOQ0mmtBzdULMrmElA7GEJHP4vHr5Pv
         fKvb/fmPNz/2jPJ2Ifi3ktxs1kpEmQMquwZrKleMPQZzpnz4s7fi8mZJRWDIA2rSuLMh
         YOQ8BeUcrN2O8sWa3tyOVW6C22ZmntzulOKXuaDfbzqd0aNmmwYGpNk0YLtqfXh8o1t3
         3AuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=IiT0UYPEG+p5liPBMja5kd363NHZyWSioarfJse3iA0=;
        b=0sHG0FAguoYYSAieSbwvIoInBWtP0EQ+oZkxFdvyDDPp1VZpyEjNJl65Gqm1wSZFVT
         sYtjq/YNCCtqPkZw3hWSbFcf11HjRT/GW1obVYQ39WfmrxfcZTHN8pd3J7DzHRN1TfaL
         aUAOecjV4sKN7kQsncKB3ErnlawkNc29CeuCRCtYHxQY6qy/Nj1rn4QzBlKKdsdDCfeV
         Ra/58BT2WRa2+BTnlIRLhAkFDifZvzV4eDkcTJuWbgvkTbyHb/3K4I8lLXu13KeXEE9x
         SnweVHo5pvzcJXkdaSukIy+JJc2rozeLEhPfxQsD/4mHWTwYuGJcD5clND5jgPiivk7D
         DgJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=ukl@pengutronix.de
Received: from metis.ext.pengutronix.de (metis.ext.pengutronix.de. [2001:67c:670:201:290:27ff:fe1d:cc33])
        by gmr-mx.google.com with ESMTPS id x11-20020adfdccb000000b0021bbdc3209asi464162wrm.1.2022.06.29.00.44.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Jun 2022 00:44:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) client-ip=2001:67c:670:201:290:27ff:fe1d:cc33;
Received: from drehscheibe.grey.stw.pengutronix.de ([2a0a:edc0:0:c01:1d::a2])
	by metis.ext.pengutronix.de with esmtps (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <ukl@pengutronix.de>)
	id 1o6SMS-0000bz-Te; Wed, 29 Jun 2022 09:43:44 +0200
Received: from [2a0a:edc0:0:900:1d::77] (helo=ptz.office.stw.pengutronix.de)
	by drehscheibe.grey.stw.pengutronix.de with esmtp (Exim 4.94.2)
	(envelope-from <ukl@pengutronix.de>)
	id 1o6SMM-003M5u-8n; Wed, 29 Jun 2022 09:43:41 +0200
Received: from ukl by ptz.office.stw.pengutronix.de with local (Exim 4.94.2)
	(envelope-from <ukl@pengutronix.de>)
	id 1o6SMO-001qhO-2i; Wed, 29 Jun 2022 09:43:40 +0200
Date: Wed, 29 Jun 2022 09:43:37 +0200
From: Uwe =?utf-8?Q?Kleine-K=C3=B6nig?= <u.kleine-koenig@pengutronix.de>
To: Crt Mori <cmo@melexis.com>
Cc: Andrew Lunn <andrew@lunn.ch>, Ricardo Ribalda <ribalda@kernel.org>,
	Jimmy Su <jimmy.su@intel.com>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Linus Walleij <linus.walleij@linaro.org>,
	Sekhar Nori <nsekhar@ti.com>,
	Gwendal Grignou <gwendal@chromium.org>,
	dri-devel@lists.freedesktop.org, Jaroslav Kysela <perex@perex.cz>,
	Benjamin Tissoires <benjamin.tissoires@redhat.com>,
	Paul Mackerras <paulus@samba.org>,
	Minghao Chi <chi.minghao@zte.com.cn>, Pavel Machek <pavel@ucw.cz>,
	Miquel Raynal <miquel.raynal@bootlin.com>,
	Heikki Krogerus <heikki.krogerus@linux.intel.com>,
	Evgeniy Polyakov <zbr@ioremap.net>,
	Matt Johnston <matt@codeconstruct.com.au>,
	Olli Salonen <olli.salonen@iki.fi>,
	Angela Czubak <acz@semihalf.com>,
	Robert Marko <robert.marko@sartura.hr>,
	Luka Perkov <luka.perkov@sartura.hr>, Sean Young <sean@mess.org>,
	Dave Stevenson <dave.stevenson@raspberrypi.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Zheyu Ma <zheyuma97@gmail.com>,
	Javier Martinez Canillas <javierm@redhat.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Chanwoo Choi <cw00.choi@samsung.com>, linux-omap@vger.kernel.org,
	Antti Palosaari <crope@iki.fi>,
	Wenyou Yang <wenyou.yang@microchip.com>,
	Dongchun Zhu <dongchun.zhu@mediatek.com>,
	Miaoqian Lin <linmq006@gmail.com>,
	Steve Longerbeam <slongerbeam@gmail.com>,
	Bingbu Cao <bingbu.cao@intel.com>,
	Shunqian Zheng <zhengsq@rock-chips.com>, lijian <lijian@yulong.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>,
	Viorel Suman <viorel.suman@nxp.com>,
	Petr Machata <petrm@nvidia.com>,
	Guido =?utf-8?Q?G=C3=BCnther?= <agx@sigxcpu.org>,
	Jean Delvare <jdelvare@suse.com>, linux-serial@vger.kernel.org,
	linux-pm@vger.kernel.org, linux-mtd@lists.infradead.org,
	Eddie James <eajames@linux.ibm.com>,
	Riku Voipio <riku.voipio@iki.fi>,
	James Schulman <james.schulman@cirrus.com>,
	Scott Wood <oss@buserror.net>, Cai Huoqing <cai.huoqing@linux.dev>,
	Jonas Malaco <jonas@protocubo.io>,
	Hsin-Yi Wang <hsinyi@chromium.org>, Haibo Chen <haibo.chen@nxp.com>,
	Petr Cvek <petrcvekcz@gmail.com>, linux-leds@vger.kernel.org,
	Joe Tessler <jrt@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andy Shevchenko <andy@kernel.org>,
	Robert Jones <rjones@gateworks.com>,
	George Joseph <george.joseph@fairview5.com>,
	Vincent Knecht <vincent.knecht@mailoo.org>,
	Robin van der Gracht <robin@protonic.nl>,
	Randy Dunlap <rdunlap@infradead.org>,
	linux-stm32@st-md-mailman.stormreply.com,
	Michael Tretter <m.tretter@pengutronix.de>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Phong LE <ple@baylibre.com>,
	Daniel Beer <daniel.beer@igorinstitute.com>,
	Krzysztof Opasiak <k.opasiak@samsung.com>,
	Bjorn Andersson <bjorn.andersson@linaro.org>,
	linux-crypto@vger.kernel.org,
	Pengutronix Kernel Team <kernel@pengutronix.de>,
	Heungjun Kim <riverful.kim@samsung.com>,
	Hans Verkuil <hverkuil-cisco@xs4all.nl>,
	David Lin <CTLIN0@nuvoton.com>, Vladimir Oltean <olteanv@gmail.com>,
	David Rhodes <david.rhodes@cirrus.com>,
	Claudiu Beznea <claudiu.beznea@microchip.com>,
	Arnaud Ferraris <arnaud.ferraris@collabora.com>,
	Jean-Baptiste Maneyrol <jean-baptiste.maneyrol@tdk.com>,
	Alexandre Belloni <alexandre.belloni@bootlin.com>,
	Dan Robertson <dan@dlrobertson.com>,
	Martyn Welch <martyn.welch@collabora.co.uk>,
	Jiri Slaby <jirislaby@kernel.org>, devicetree@vger.kernel.org,
	David Airlie <airlied@linux.ie>,
	Jon Nettleton <jon.nettleton@gmail.com>,
	Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>,
	Marco Felsch <m.felsch@pengutronix.de>,
	Wim Van Sebroeck <wim@linux-watchdog.org>,
	Sebastian Reichel <sre@kernel.org>,
	Max Filippov <jcmvbkbc@gmail.com>,
	"Lad, Prabhakar" <prabhakar.csengg@gmail.com>,
	Thierry Reding <thierry.reding@gmail.com>,
	linux-i2c@vger.kernel.org, Martiros Shakhzadyan <vrzh@vrzh.net>,
	Guenter Roeck <groeck@chromium.org>,
	Matthias Schwarzott <zzam@gentoo.org>,
	Sylwester Nawrocki <s.nawrocki@samsung.com>,
	Dmitry Rokosov <DDRokosov@sberdevices.ru>,
	Marek =?utf-8?B?QmVow7pu?= <kabel@kernel.org>,
	Saranya Gopal <saranya.gopal@intel.com>,
	Lars-Peter Clausen <lars@metafoo.de>,
	Corey Minyard <minyard@acm.org>, Evgeny Novikov <novikov@ispras.ru>,
	Frank Rowand <frowand.list@gmail.com>,
	Bartosz Golaszewski <brgl@bgdev.pl>,
	Manivannan Sadhasivam <mani@kernel.org>,
	Pierre-Louis Bossart <pierre-louis.bossart@linux.intel.com>,
	Eric Dumazet <edumazet@google.com>, linux-clk@vger.kernel.org,
	Nathan Chancellor <nathan@kernel.org>, alsa-devel@alsa-project.org,
	MyungJoo Ham <myungjoo.ham@samsung.com>,
	Charles Gorand <charles.gorand@effinnov.com>,
	Jagan Teki <jagan@amarulasolutions.com>,
	Vijendar Mukunda <Vijendar.Mukunda@amd.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Kyungmin Park <kyungmin.park@samsung.com>,
	Tianshu Qiu <tian.shu.qiu@intel.com>,
	Martin Donnelly <martin.donnelly@ge.com>,
	Woojung Huh <woojung.huh@microchip.com>,
	Rudolf Marek <r.marek@assembler.cz>,
	Charles Keepax <ckeepax@opensource.cirrus.com>,
	linux-watchdog@vger.kernel.org,
	Michael Hennerich <michael.hennerich@analog.com>,
	Ido Schimmel <idosch@nvidia.com>,
	acpi4asus-user@lists.sourceforge.net,
	Simon Trimmer <simont@opensource.cirrus.com>,
	Ricard Wanderlof <ricardw@axis.com>,
	Rikard Falkeborn <rikard.falkeborn@gmail.com>,
	Alex Deucher <alexander.deucher@amd.com>,
	wengjianfeng <wengjianfeng@yulong.com>,
	Jiri Valek - 2N <valek@2n.cz>, linux-rpi-kernel@lists.infradead.org,
	Biju Das <biju.das.jz@bp.renesas.com>,
	Wayne Chang <waynec@nvidia.com>, Chen-Yu Tsai <wens@csie.org>,
	Sing-Han Chen <singhanc@nvidia.com>,
	linux-arm-kernel@lists.infradead.org,
	Niklas =?utf-8?Q?S=C3=B6derlund?= <niklas.soderlund+renesas@ragnatech.se>,
	Hans de Goede <hdegoede@redhat.com>,
	Stephen Boyd <sboyd@kernel.org>,
	Maslov Dmitry <maslovdmitry@seeed.cc>, linux-gpio@vger.kernel.org,
	Jens Frederich <jfrederich@gmail.com>,
	Douglas Anderson <dianders@chromium.org>,
	Peter Rosin <peda@axentia.se>, Wolfram Sang <wsa@kernel.org>,
	Jarkko Sakkinen <jarkko@kernel.org>, linux-usb@vger.kernel.org,
	Jacopo Mondi <jacopo+renesas@jmondi.org>,
	Maxime Coquelin <mcoquelin.stm32@gmail.com>,
	CGEL ZTE <cgel.zte@gmail.com>, Colin Leroy <colin@colino.net>,
	platform-driver-x86@vger.kernel.org,
	linux-integrity@vger.kernel.org,
	Kevin Tsai <ktsai@capellamicro.com>,
	Pali =?utf-8?B?Um9ow6Fy?= <pali@kernel.org>,
	Jonathan Cameron <jic23@kernel.org>,
	Heiner Kallweit <hkallweit1@gmail.com>,
	Arec Kao <arec.kao@intel.com>, Stephen Kitt <steve@sk2.org>,
	Jose Cazarin <joseespiriki@gmail.com>,
	Neil Armstrong <narmstrong@baylibre.com>, linux-iio@vger.kernel.org,
	Tom Rix <trix@redhat.com>,
	Michael Turquette <mturquette@baylibre.com>,
	Peter Senna Tschudin <peter.senna@gmail.com>,
	Benjamin Mugnier <benjamin.mugnier@foss.st.com>,
	Nuno =?utf-8?B?U8Oh?= <nuno.sa@analog.com>,
	Jan-Simon Moeller <jansimon.moeller@gmx.de>,
	Wei Yongjun <weiyongjun1@huawei.com>,
	Laurent Pinchart <Laurent.pinchart@ideasonboard.com>,
	Andrzej Hajda <andrzej.hajda@intel.com>,
	Nikita Travkin <nikita@trvn.ru>,
	Jeremy Kerr <jk@codeconstruct.com.au>,
	Jasmin Jessich <jasmin@anw.at>, Sam Ravnborg <sam@ravnborg.org>,
	Kevin Cernekee <cernekee@chromium.org>,
	Alyssa Rosenzweig <alyssa@rosenzweig.io>, linux-rtc@vger.kernel.org,
	Daniel Thompson <daniel.thompson@linaro.org>,
	Florian Fainelli <f.fainelli@gmail.com>,
	Lucas Tanure <tanureal@opensource.cirrus.com>,
	Stefan Mavrodiev <stefan@olimex.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Sylvain Petinot <sylvain.petinot@foss.st.com>,
	netdev@vger.kernel.org,
	Kieran Bingham <kieran.bingham@ideasonboard.com>,
	Jernej Skrabec <jernej.skrabec@gmail.com>,
	Xin Ji <xji@analogixsemi.com>, Seven Lee <wtli@nuvoton.com>,
	Matt Ranostay <matt.ranostay@konsulko.com>,
	Broadcom internal kernel review list <bcm-kernel-feedback-list@broadcom.com>,
	Adrien Grassein <adrien.grassein@gmail.com>,
	Yang Yingliang <yangyingliang@huawei.com>,
	chrome-platform@lists.linux.dev,
	Mats Randgaard <matrandg@cisco.com>,
	Paolo Abeni <pabeni@redhat.com>,
	Alexey Dobriyan <adobriyan@gmail.com>,
	Joel Stanley <joel@jms.id.au>, linux-input@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, Lyude Paul <lyude@redhat.com>,
	Kees Cook <keescook@chromium.org>,
	Uwe =?utf-8?Q?Kleine-K=C3=B6nig?= <uwe@kleine-koenig.org>,
	Jonas Karlman <jonas@kwiboo.se>,
	Yang Li <yang.lee@linux.alibaba.com>,
	Tim Harvey <tharvey@gateworks.com>, Jiri Kosina <jikos@kernel.org>,
	Akinobu Mita <akinobu.mita@gmail.com>,
	Mark Gross <markgross@kernel.org>,
	Richard Fitzgerald <rf@opensource.cirrus.com>,
	Mark Brown <broonie@kernel.org>, linux-media@vger.kernel.org,
	Maxime Ripard <maxime@cerno.tech>, Sven Peter <sven@svenpeter.dev>,
	Martin Kepplinger <martink@posteo.de>,
	openipmi-developer@lists.sourceforge.net,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Benson Leung <bleung@chromium.org>,
	"Daniel W. S. Almeida" <dwlsalmeida@gmail.com>,
	Chiranjeevi Rapolu <chiranjeevi.rapolu@intel.com>,
	Alessandro Zummo <a.zummo@towertech.it>,
	linux-hwmon@vger.kernel.org, Felipe Balbi <balbi@kernel.org>,
	Stephan Gerhold <stephan@gerhold.net>,
	Support Opensource <support.opensource@diasemi.com>,
	Alexandru Ardelean <ardeleanalex@gmail.com>,
	Dmitry Torokhov <dmitry.torokhov@gmail.com>,
	Marc Hulsman <m.hulsman@tudelft.nl>,
	Corentin Chary <corentin.chary@gmail.com>,
	linux-fbdev@vger.kernel.org, Daniel Scally <djrscally@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Kirill Shilimanov <kirill.shilimanov@huawei.com>,
	Sakari Ailus <sakari.ailus@linux.intel.com>,
	patches@opensource.cirrus.com,
	Zheng Yongjun <zhengyongjun3@huawei.com>,
	Alejandro Tafalla <atafalla@dnyon.com>,
	"David S. Miller" <davem@davemloft.net>,
	Daniel Palmer <daniel@0x0f.com>, Hector Martin <marcan@marcan.st>,
	Moses Christopher Bollavarapu <mosescb.dev@gmail.com>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	Nick Dyer <nick@shmanahar.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Tony Lindgren <tony@atomide.com>,
	Alexandre Torgue <alexandre.torgue@foss.st.com>,
	Takashi Iwai <tiwai@suse.com>, Paul Cercueil <paul@crapouillou.net>,
	George McCollister <george.mccollister@gmail.com>,
	Mac Chiang <mac.chiang@intel.com>,
	Antoniu Miclaus <antoniu.miclaus@analog.com>,
	Alexander Potapenko <glider@google.com>,
	Adam Ford <aford173@gmail.com>, Peter Huewe <peterhuewe@gmx.de>,
	UNGLinuxDriver@microchip.com, Lee Jones <lee.jones@linaro.org>,
	Alexey Khoroshilov <khoroshilov@ispras.ru>,
	Marek Vasut <marex@denx.de>,
	Paul Kocialkowski <paul.kocialkowski@bootlin.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Eric Piel <eric.piel@tremplin-utc.net>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Tobias Schrammm <t.schramm@manjaro.org>,
	Richard Weinberger <richard@nod.at>,
	Tomasz Duszynski <tduszyns@gmail.com>,
	Janusz Krzysztofik <jmkrzyszt@gmail.com>,
	Russell King <linux@armlinux.org.uk>, linux-pwm@vger.kernel.org,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	Bastien Nocera <hadess@hadess.net>,
	Jingoo Han <jingoohan1@gmail.com>, Jakub Kicinski <kuba@kernel.org>,
	Vivien Didelot <vivien.didelot@gmail.com>,
	Yizhuo <yzhai003@ucr.edu>, Shawn Tu <shawnx.tu@intel.com>,
	Leon Luo <leonl@leopardimaging.com>,
	Yan Lei <yan_lei@dahuatech.com>, Akihiro Tsukada <tskd08@gmail.com>,
	Tudor Ambarus <tudor.ambarus@microchip.com>,
	Oliver Graute <oliver.graute@kococonnector.com>,
	Alistair Francis <alistair@alistair23.me>,
	Dongliang Mu <mudongliangabcd@gmail.com>,
	Jonathan =?utf-8?Q?Neusch=C3=A4fer?= <j.neuschaefer@gmx.net>,
	Eduardo Valentin <edubezval@gmail.com>,
	Rui Miguel Silva <rmfrfs@gmail.com>,
	Michael Srba <Michael.Srba@seznam.cz>,
	Rob Herring <robh+dt@kernel.org>,
	linux-mediatek@lists.infradead.org,
	Fabio Estevam <festevam@gmail.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	kasan-dev@googlegroups.com,
	"Paul J. Murphy" <paul.j.murphy@intel.com>,
	Nicola Lunghi <nick83ola@gmail.com>,
	Daniele Alessandrelli <daniele.alessandrelli@intel.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ramesh Shanmugasundaram <rashanmu@gmail.com>,
	Liam Girdwood <lgirdwood@gmail.com>,
	Juerg Haefliger <juergh@gmail.com>,
	Oder Chiou <oder_chiou@realtek.com>,
	Shengjiu Wang <shengjiu.wang@nxp.com>,
	Nicolas Ferre <nicolas.ferre@microchip.com>,
	Robert Foss <robert.foss@linaro.org>,
	Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>,
	Daniel Vetter <daniel@ffwll.ch>,
	Alvin =?utf-8?Q?=C5=A0ipraga?= <alsi@bang-olufsen.dk>,
	Luca Ceresoli <luca@lucaceresoli.net>,
	=?utf-8?B?Sm9zw6kgRXhww7NzaXRv?= <jose.exposito89@gmail.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	Colin Ian King <colin.king@intel.com>,
	Maximilian Luz <luzmaximilian@gmail.com>,
	Helge Deller <deller@gmx.de>, linux-staging@lists.linux.dev,
	Lucas Stach <l.stach@pengutronix.de>
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
Message-ID: <20220629074337.mks23y5rt6c536wl@pengutronix.de>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
 <CAKv63uu1XXP_XptZOeefDS_RVJvu3six5ZnJ9-oOVCPAK4D9aw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="udaf7kclxozlbsvv"
Content-Disposition: inline
In-Reply-To: <CAKv63uu1XXP_XptZOeefDS_RVJvu3six5ZnJ9-oOVCPAK4D9aw@mail.gmail.com>
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


--udaf7kclxozlbsvv
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable

Hello,

On Wed, Jun 29, 2022 at 09:24:55AM +0200, Crt Mori wrote:
> On Tue, 28 Jun 2022 at 16:04, Uwe Kleine-K=C3=B6nig
> <u.kleine-koenig@pengutronix.de> wrote:
> >  static const struct i2c_device_id mlx90614_id[] =3D {
> > diff --git a/drivers/iio/temperature/mlx90632.c b/drivers/iio/temperatu=
re/mlx90632.c
> > index 7ee7ff8047a4..e8ef47147e2b 100644
> > --- a/drivers/iio/temperature/mlx90632.c
> > +++ b/drivers/iio/temperature/mlx90632.c
> > @@ -924,7 +924,7 @@ static int mlx90632_probe(struct i2c_client *client=
,
> >         return iio_device_register(indio_dev);
> >  }
> >
> > -static int mlx90632_remove(struct i2c_client *client)
> > +static void mlx90632_remove(struct i2c_client *client)
> >  {
> >         struct iio_dev *indio_dev =3D i2c_get_clientdata(client);
> >         struct mlx90632_data *data =3D iio_priv(indio_dev);
> > @@ -936,8 +936,6 @@ static int mlx90632_remove(struct i2c_client *clien=
t)
> >         pm_runtime_put_noidle(&client->dev);
> >
> >         mlx90632_sleep(data);
> > -
> > -       return 0;
> >  }
> >
> For both mlx drivers
>=20
> Reviewed-by: "Crt Mori <cmo@melexis.com>"

Thanks, it was more complicated than (IMHO) necessary to find these
lines. I suggest to strip the irrelevant part the quoted mail for the
next time.

I added your tag without the quotes to my tree.

Best regards
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
kasan-dev/20220629074337.mks23y5rt6c536wl%40pengutronix.de.

--udaf7kclxozlbsvv
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCgAdFiEEfnIqFpAYrP8+dKQLwfwUeK3K7AkFAmK8AqYACgkQwfwUeK3K
7Am8Mwf+IBff11UStG2Xle0ayEs0RLJMDDLQ5ZsJcINntMkiJCCyvH1HrHqcvTWo
BtqcH/0oNBe5ko1loRbRALlOyYe7r1Q7508Zv+qkQf4Y8DOUmzWtlruJlDlo/HwV
DqiQBR0Ccfi3rbtXz0hWtvpecZWbgaQd9E/ZiIunLKUo3QcVz8lf+5jLQIZgy5EM
reJKul9dQD15zMfxqR2qzIVJIT1EK3OVYfO9Q0siHiTLkJ1EoQtEpW/nGYsZcKbj
OXsaiHqv4yt5atJH7kx1PzmSggDluMwRWcKmTrnQTrOTD766dAE3bxP2z1V8FUTn
HkMp469vyvmib6S/lNJi+NYdz9jcJw==
=41Qj
-----END PGP SIGNATURE-----

--udaf7kclxozlbsvv--
