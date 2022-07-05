Return-Path: <kasan-dev+bncBDD45AWIUUARBOE3SCLAMGQEVLDPI3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C0A4566756
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jul 2022 12:08:58 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id k3-20020a2ea283000000b0025bcd580d43sf3408973lja.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jul 2022 03:08:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657015737; cv=pass;
        d=google.com; s=arc-20160816;
        b=sI97AZv08rMUQn8b+Jk7OdqCceNl1nT4yhn5CCJyuhjuZdbAlyTqNQ7UDp72CoOOZk
         VEW/yfTcRpDi+vCgzdzce6Gw4Lonf/gGdGl7dpWw6M8VAVWnGQush5WLlOoZkYjJbhJR
         +gYs1IOtzrLyTlE7Ipq4JHnKlDrLS6xC3IuBHyTlEiT0mhONMS2lDWgkN6wMtlveeH1B
         xB7tTfB3oxuzAsaJw7CQy8Q7a7+cujhBV4iPlHzJz2yObLIiZm2rPbE7UzpWhhyUrIbt
         rnOGIOtGx1julkFGnJBDkzHqR/0S6QA77+zSp8tYd1AASrhXX+z7qNZiGPfbEWJExUTM
         kwNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:organization:references:in-reply-to:message-id:subject
         :cc:to:from:date:sender:dkim-signature;
        bh=TexIAFyfFNw+eklYmsOK3E/aL4JR0MvAKSzj1xkbngQ=;
        b=w2+Z+N23XQZxvYHoR9pOzn71axX+GLLTMSt5IJTErFejS5p9L7cM2zA6BftKwXQlNe
         gLtAw0RNeFEnKPwKY9lglqMZ7Qxj4pT6+NrbemHs2Fg6TH+3dQnZJQx/l1VJzZflJKr+
         8/5lopWSU9TZW5MbUp39ie+Ytugi1JOVH7e5r6mb7ZpbPLgqg8khdUwKK/ecFf7EUsWo
         NPnt4qTa6bjQYIJCboxwWce/ikS55RBqTAmBwbUi9ZW8KP/vE63GIx96saRHj/qDM1qd
         kByxe7RmGczR7dR0sMSTSc2gH+ZLBs8Jhzdhd2GGIqHTOmbPFbXVeTtYV/2JB6NoTdYx
         82WQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=eByb4sSP;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of jdelvare@suse.de designates 195.135.220.29 as permitted sender) smtp.mailfrom=jdelvare@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :organization:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TexIAFyfFNw+eklYmsOK3E/aL4JR0MvAKSzj1xkbngQ=;
        b=XMYA9Nuhsl5N4wd3+A7vJrxgYx7k9AshPXl763OhHTi0ESvU/1E8FhFaTWwRM5tygc
         XchLqNa6+yrEU3HytdgjzSmVWZywdZGDNgwowlBoF+O6cuXUfdliJd1mWkdeqnm3kK0K
         dULhoJcIMCG02wvCs1erd3QpgJeSm4f5VcZ3As0F6QBwln5YiW5oIg0Nu/MlTB0+TbiP
         Ms+pmOdqM/s05dCh4QZwte+cJ51JI0KH/7fKSLn3LYYkw9XFfhaDiRr23g7ok2crAA8U
         PbMnQ7ofD4RPuBSmWer4NjN10Uuy2Y+abY8SH2xirMtQXHCcbaL/zq8lXO1q6r/PnzRO
         Bs3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:organization:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TexIAFyfFNw+eklYmsOK3E/aL4JR0MvAKSzj1xkbngQ=;
        b=Cr0cweHXD9de7Rl7IjoVymZikzbYWYMFkNLX4rtjkJ17M/fb7MT94F4Q0JNSyW9Diu
         a62V2VillbjNEUJHRjY04xHScp0vLrrS6d1uWmn/AgTrwcccFh0eYM9VYuAMYyiyrxtS
         m59eRQDs0S5cwmbzctUWMiRFBdQQS0ZCn+POD2ED9Kr2qf6QSmJPYkGj7la+F6K8yx9Q
         OdpltGu9PVPaPUxMwcXh5AcVvcU3iONikJNIG6GAzaAkJPkyjlGiLY3gssU8g8bQ5mWU
         /i1DqJlyvzVV2kLNpANrZ+ZXLVho6d0j9hjpp4zUbd3pLPg3Y5IFXwDVRn6VQxft/FMe
         5KuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8p6CXnT1mrpMgKt/hS5N+6bqJVC9bNxQ+9DaUE82vUuCs5WCZc
	JzMc0d1kYH6IhPlqEFK/apQ=
X-Google-Smtp-Source: AGRyM1vGn5wPANzy9ZMnQS6Dm41+QFHzeKgCrw9lRUAMr2E+PRIf+NQtd+grccIwuqx14CY/fn0Jhg==
X-Received: by 2002:a2e:544b:0:b0:25d:33ea:f3f1 with SMTP id y11-20020a2e544b000000b0025d33eaf3f1mr1333353ljd.354.1657015737116;
        Tue, 05 Jul 2022 03:08:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc13:0:b0:25d:380e:3d5 with SMTP id b19-20020a2ebc13000000b0025d380e03d5ls160815ljf.10.gmail;
 Tue, 05 Jul 2022 03:08:56 -0700 (PDT)
X-Received: by 2002:a2e:8558:0:b0:25a:742f:d7 with SMTP id u24-20020a2e8558000000b0025a742f00d7mr19155625ljj.178.1657015735963;
        Tue, 05 Jul 2022 03:08:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657015735; cv=none;
        d=google.com; s=arc-20160816;
        b=e1zwExSWZr/aAzvuMRMVDbP7rXTXhUsfcIoin7CjoQ0Q2wvyZ81Mtdgma4Vxl+pa/d
         +1QdoGZsH0FlF6lQw/cwHfjFqo6ovYWFucCwY0EVY7CQZSRx90FT2ydkhiGEPZMgrixN
         QfKyeGW99DD9ACV16rZvsYydt3hjup5nnEhUiQogfUgCjNxhgTyfcco0zl3xGv+BfuvF
         smyi+Sr+Yo7ZKU5uDXpEMAce7ZwhA9QE1RFiqOUWfbVnq3YoojW0zUAQpRU70v8iTwRm
         PhWK8b5n05LiEQ7PWC+YQ5CXVuAwXg948I7d7N50h/SJ+mu3xG6yqm8xg/Q03xnkoyQv
         9gHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:organization:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=qvMJ4J1/LuqJ2bm7BlZIoOLJOYmWh+4Rpvkk33SZGOA=;
        b=R7IyiHT8oWp3jGiPdVtJtDWkzcXIBFgt1jq/CiHGyr38hfZotpiMLW+DKBcyhMnAgb
         7zHgaRIptuZnH6Fr30DJV2iUH7HO+JR/kJEQ4seRUqkd1XbU79Pi73irEmxYctHQepfL
         Gj2TBTWdYavhN6aA9/V3n64RHqJmXZFFgqrzYlLPtb7td6hns7o1OqASWkU2nIrfNJhx
         V0TLp87MoCA66GNs/JY3Y83meVxIt3c9iDb8e1n1YkbCUkmqnuLYiyfNFkgMXwDCJWXe
         bZQ9dXNzP86G3st6D78CqrVO92vcT76D+2T3z4hcmiAVohAvuZ256cZHHwOglP9gvItH
         wbDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=eByb4sSP;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of jdelvare@suse.de designates 195.135.220.29 as permitted sender) smtp.mailfrom=jdelvare@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id c7-20020ac25f67000000b0047faa025f65si556199lfc.12.2022.07.05.03.08.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Jul 2022 03:08:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of jdelvare@suse.de designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 4BB4A1F91F;
	Tue,  5 Jul 2022 10:08:55 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 2E2AF1339A;
	Tue,  5 Jul 2022 10:08:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id VBGsCbYNxGK1BQAAMHmgww
	(envelope-from <jdelvare@suse.de>); Tue, 05 Jul 2022 10:08:54 +0000
Date: Tue, 5 Jul 2022 12:08:52 +0200
From: Jean Delvare <jdelvare@suse.de>
To: Uwe =?UTF-8?B?S2xlaW5lLUvDtm5pZw==?= <u.kleine-koenig@pengutronix.de>
Cc: Wolfram Sang <wsa@kernel.org>, Guenter Roeck <groeck@chromium.org>,
 linux-i2c@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 linuxppc-dev@lists.ozlabs.org, openipmi-developer@lists.sourceforge.net,
 linux-integrity@vger.kernel.org, linux-clk@vger.kernel.org,
 linux-crypto@vger.kernel.org, linux-gpio@vger.kernel.org,
 dri-devel@lists.freedesktop.org, chrome-platform@lists.linux.dev,
 linux-rpi-kernel@lists.infradead.org, linux-input@vger.kernel.org,
 linux-hwmon@vger.kernel.org, linux-iio@vger.kernel.org,
 linux-stm32@st-md-mailman.stormreply.com, linux-leds@vger.kernel.org,
 linux-media@vger.kernel.org, patches@opensource.cirrus.com,
 alsa-devel@alsa-project.org, linux-omap@vger.kernel.org,
 linux-mtd@lists.infradead.org, netdev@vger.kernel.org,
 devicetree@vger.kernel.org, platform-driver-x86@vger.kernel.org,
 acpi4asus-user@lists.sourceforge.net, linux-pm@vger.kernel.org,
 linux-pwm@vger.kernel.org, linux-rtc@vger.kernel.org,
 linux-staging@lists.linux.dev, linux-serial@vger.kernel.org,
 linux-usb@vger.kernel.org, linux-fbdev@vger.kernel.org,
 linux-watchdog@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mediatek@lists.infradead.org
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
Message-ID: <20220705120852.049dc235@endymion.delvare>
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
	<20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
Organization: SUSE Linux
X-Mailer: Claws Mail 3.18.0 (GTK+ 2.24.32; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jdelvare@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=eByb4sSP;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       spf=pass
 (google.com: domain of jdelvare@suse.de designates 195.135.220.29 as
 permitted sender) smtp.mailfrom=jdelvare@suse.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=suse.de
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

On Tue, 28 Jun 2022 16:03:12 +0200, Uwe Kleine-K=C3=B6nig wrote:
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

That's a huge change for a relatively small benefit, but if this is
approved by the I2C core maintainer then fine with me. For:

>  drivers/hwmon/adc128d818.c                                | 4 +---
>  drivers/hwmon/adt7470.c                                   | 3 +--
>  drivers/hwmon/asb100.c                                    | 6 ++----
>  drivers/hwmon/asc7621.c                                   | 4 +---
>  drivers/hwmon/dme1737.c                                   | 4 +---
>  drivers/hwmon/f75375s.c                                   | 5 ++---
>  drivers/hwmon/fschmd.c                                    | 6 ++----
>  drivers/hwmon/ftsteutates.c                               | 3 +--
>  drivers/hwmon/ina209.c                                    | 4 +---
>  drivers/hwmon/ina3221.c                                   | 4 +---
>  drivers/hwmon/jc42.c                                      | 3 +--
>  drivers/hwmon/mcp3021.c                                   | 4 +---
>  drivers/hwmon/occ/p8_i2c.c                                | 4 +---
>  drivers/hwmon/pcf8591.c                                   | 3 +--
>  drivers/hwmon/smm665.c                                    | 3 +--
>  drivers/hwmon/tps23861.c                                  | 4 +---
>  drivers/hwmon/w83781d.c                                   | 4 +---
>  drivers/hwmon/w83791d.c                                   | 6 ++----
>  drivers/hwmon/w83792d.c                                   | 6 ++----
>  drivers/hwmon/w83793.c                                    | 6 ++----
>  drivers/hwmon/w83795.c                                    | 4 +---
>  drivers/hwmon/w83l785ts.c                                 | 6 ++----
>  drivers/i2c/i2c-core-base.c                               | 6 +-----
>  drivers/i2c/i2c-slave-eeprom.c                            | 4 +---
>  drivers/i2c/i2c-slave-testunit.c                          | 3 +--
>  drivers/i2c/i2c-smbus.c                                   | 3 +--
>  drivers/i2c/muxes/i2c-mux-ltc4306.c                       | 4 +---
>  drivers/i2c/muxes/i2c-mux-pca9541.c                       | 3 +--
>  drivers/i2c/muxes/i2c-mux-pca954x.c                       | 3 +--

Reviewed-by: Jean Delvare <jdelvare@suse.de>

--=20
Jean Delvare
SUSE L3 Support

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220705120852.049dc235%40endymion.delvare.
