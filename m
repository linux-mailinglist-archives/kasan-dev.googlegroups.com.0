Return-Path: <kasan-dev+bncBDLKHL4UYEFBBKUC6CKQMGQEPJKRTVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id A2E9055F924
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 09:37:16 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id j14-20020a17090a694e00b001ed112b078asf8626371pjm.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 00:37:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656488235; cv=pass;
        d=google.com; s=arc-20160816;
        b=TAMiZpEj1KHGp6SLG2TDp7JIzj+stnhNo6vpvDnjmUTj3x9kxXPmljdVNVm4GPlWla
         DNFBsy4uJ9kH+TksBEbiw08JtJ5fryCpCohXhKjJG9K2ysCR3YUOxwIQ1G5Je+ZWnAo9
         EYAOPOkVv3ixdokLDPCGro1riEY9WdQc8Pf+aJEv4fojlkvZDm3sHzIB4lqAFuKItFA5
         i4A3nwePxVSDu+xo/azmRwASQAHTuv1opRef2cehXnMi/z9eZ1SKInPs076EC5jS5rrW
         +MrW+WR+UxASMQ8oIiMVEGIqcKLTP3vV4Ym8aW69l+Xi8FVJKTC9MQyRJ0Z3vMcFjzoA
         regQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=piEke2fUfCYKYfTKjWY8HcRCF5DFYHisIj2LuJkuUGg=;
        b=klvxma0fNYQGjUt5SJd8fyvEEbkGxEjVYUfJXU6mAJ2z5LhHnilcqUqELklUvuuFvR
         L/7FeDimUOpk7KWIEDEq7pt+UlSYp4dtRakrO+MpfSeS7AQz/Zvqhe7eJxufXc86cf9/
         Uh4D3jiIXrqt3pvgme65MIRFot+xAQkcMr/I6BARvgYrkVWkGdP8ya1gjq941X+faKeD
         YtyfoK5XPMe85rVFPzyyRo8nrEG3yXp92pWsg+3KpKxRBKfBcc0bTv6Dp05qNqLGm0k2
         xpVRLBodXhc2WvsCWpA0bzqzTbMYs9lo2us61jTqCWqM0J2uU7yTOvNotpll9CZ73yCk
         QsSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=A9r6z16e;
       spf=pass (google.com: domain of javierm@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=javierm@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject:to:cc
         :references:from:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=piEke2fUfCYKYfTKjWY8HcRCF5DFYHisIj2LuJkuUGg=;
        b=dECNSxbKButyBYZR2tV9Kzp+NKjY1C5z3vl+KoudTP9FC0GkXC/qmT4R5L3Kyz41Wq
         69sznDOvEMtGr7+dtLidV4uianaipmfV0WEQqt43avBskGXzPta27TDAdmlsX+TZvKA7
         h6lFcEk5k1lWkmdXRny7VC93b8rs8QGAfOJXF+5rzS+Hqo7v3/QVbMMTyBmfQmc3Xs95
         +zrV4+0nqNTqk7H0BWmzqJqhft1M0vYgz/ZR8bj7pgmDBWV0tHe6o6pdL1nNwI6aRDEK
         YuGYOGrqtZlGmXiX9zjBoLx51HOTqNTsMtjrg6owXJJvSiDjKPAkEmtGayUEVjGsPheA
         LR2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:to:cc:references:from:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=piEke2fUfCYKYfTKjWY8HcRCF5DFYHisIj2LuJkuUGg=;
        b=6Wp0kIQUlJns+NZcrtGos/0L6HRF6lOG4GlEWdNte9EneSpXJYQ4gJOT5WiPiQZuzS
         7b9t74rkUyvVHG7XcT7JOyHmYaSL4svh3dbbuVQ1i36IY2uXeLz2V2DDNbdxrpNLBQHl
         x/19BH3WTV4RF4X0dk1lMb87RR84uyv9l3x22N/2oxMFSYe5IaFsyIS6KqtP6cIgNmj+
         9YDha2Zjzi3nzCg9CexRZxmKda9GWMWPwd/xCj5QfmFAezvjuYXC2Spc7hiOLSigZKVD
         hm5KoQRDnR8R7v3E77GbnnBObaTcQi1yv+ZId3WYDfXOD4wzKwNOyY+f525BC3zBEAQz
         JeDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+U+5dceGawJOrunMunVTGdg+Lp6tFHV0EuS96gm/W+lgQQ9hcF
	pryHlWNQYpxHJzWIT3tP7Xc=
X-Google-Smtp-Source: AGRyM1st93ERt8T56g0qBK6onGYaoKCNEaNcP+z1EDmsy6DeacRtLYbx13bJusAFa80YZk/JAgZVpg==
X-Received: by 2002:a63:4710:0:b0:410:ac39:831b with SMTP id u16-20020a634710000000b00410ac39831bmr1846008pga.395.1656488235026;
        Wed, 29 Jun 2022 00:37:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9729:0:b0:525:141d:2ab7 with SMTP id k9-20020aa79729000000b00525141d2ab7ls12998225pfg.1.gmail;
 Wed, 29 Jun 2022 00:37:14 -0700 (PDT)
X-Received: by 2002:a65:6045:0:b0:399:3a5e:e25a with SMTP id a5-20020a656045000000b003993a5ee25amr1914553pgp.139.1656488234414;
        Wed, 29 Jun 2022 00:37:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656488234; cv=none;
        d=google.com; s=arc-20160816;
        b=LSoC+JV28cGcOikn6a31fawU36LZjBcc2zTuNFONrnguHB0tNWdhhszB3iDW+DGVjg
         onc/aGqrDb0N/S3qyTtHsR5AiUDNITEcBJs5mWmikmRXM4ympu+4frta1geyqREvu8/1
         zgjNsUNq7bu4BD6t84NQ4StPYJXgEu2hQBJOZlzwQDj3tYpGMA1ssg+Xnf8Dj2LDfPS1
         mNxOMcjUmNAZsRJ4c6GleJLyNN2G+XDZj9mIBhahtd4WQ3zY2VihdFZxx5KvJdzAkA43
         pcHKFpyy1ohOTpqh6Uirtm1i8ZXFxZlxPccDmT6hxhnSrSIbTX1+YokxAieDQ1bddC2H
         vMnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=1h0smKgkaQYyMckjg1gEO+92UXCJgyf7f6YfzsCAFg4=;
        b=Uh4gcqaPI1bc4XmSjwTe3EtaH9H3OVOpLpgsimL7JBhfKPnXodB/DaoTjl4VaQV5fG
         h8UDUtuD+gkT6ewt1DIi6UFnWWJnA6e7jO55vDz5GRq4nb9pubTkY7mJ9tXe8cbceuZo
         flq8P9C5vLUfX5jf1X42v8vW1SUYRPABobNr7LBYLQDmnIzzO+v91PGqPSBu1hkL9J7+
         HBWPAdGQIotXfAL/DERopKuhU983RkYOVN7pEcmdffjQqMm5LDN7Jv7yaiMHLJpTLaKk
         05tvHhVPYmwiRoXPtYS41QJKL1JsMHkKE1lq3ehpjId3xA+IC8G1ZOzbusRY7sj+1r7B
         FSDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=A9r6z16e;
       spf=pass (google.com: domain of javierm@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=javierm@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id lr18-20020a17090b4b9200b001ecb6b8678fsi92011pjb.2.2022.06.29.00.37.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Jun 2022 00:37:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of javierm@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-414-O_aVtN_WNfK_WYIS5LcWOA-1; Wed, 29 Jun 2022 03:37:12 -0400
X-MC-Unique: O_aVtN_WNfK_WYIS5LcWOA-1
Received: by mail-wm1-f70.google.com with SMTP id c187-20020a1c35c4000000b003970013833aso6260252wma.1
        for <kasan-dev@googlegroups.com>; Wed, 29 Jun 2022 00:37:11 -0700 (PDT)
X-Received: by 2002:a05:6000:1448:b0:21b:b7db:c40b with SMTP id v8-20020a056000144800b0021bb7dbc40bmr1650264wrx.279.1656488230980;
        Wed, 29 Jun 2022 00:37:10 -0700 (PDT)
X-Received: by 2002:a05:6000:1448:b0:21b:b7db:c40b with SMTP id v8-20020a056000144800b0021bb7dbc40bmr1650238wrx.279.1656488230741;
        Wed, 29 Jun 2022 00:37:10 -0700 (PDT)
Received: from [192.168.1.129] (205.pool92-176-231.dynamic.orange.es. [92.176.231.205])
        by smtp.gmail.com with ESMTPSA id j10-20020a5d448a000000b0021b8c99860asm15832366wrq.115.2022.06.29.00.37.09
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Jun 2022 00:37:10 -0700 (PDT)
Message-ID: <7654a74e-a410-a8a5-c228-d006dbbc200f@redhat.com>
Date: Wed, 29 Jun 2022 09:37:08 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.10.0
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
To: =?UTF-8?Q?Uwe_Kleine-K=c3=b6nig?= <u.kleine-koenig@pengutronix.de>,
 Jeremy Kerr <jk@codeconstruct.com.au>
Cc: linux-fbdev@vger.kernel.org,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>, linux-iio@vger.kernel.org,
 dri-devel@lists.freedesktop.org, platform-driver-x86@vger.kernel.org,
 linux-mtd@lists.infradead.org, linux-i2c@vger.kernel.org,
 linux-stm32@st-md-mailman.stormreply.com, linux-rtc@vger.kernel.org,
 chrome-platform@lists.linux.dev, linux-staging@lists.linux.dev,
 kasan-dev@googlegroups.com,
 Broadcom internal kernel review list
 <bcm-kernel-feedback-list@broadcom.com>, linux-serial@vger.kernel.org,
 linux-input@vger.kernel.org, linux-media@vger.kernel.org,
 linux-pwm@vger.kernel.org, linux-watchdog@vger.kernel.org,
 linux-pm@vger.kernel.org, acpi4asus-user@lists.sourceforge.net,
 linux-gpio@vger.kernel.org, linux-mediatek@lists.infradead.org,
 linux-rpi-kernel@lists.infradead.org,
 openipmi-developer@lists.sourceforge.net,
 linux-arm-kernel@lists.infradead.org, linux-hwmon@vger.kernel.org,
 Support Opensource <support.opensource@diasemi.com>, netdev@vger.kernel.org,
 Wolfram Sang <wsa@kernel.org>, linux-crypto@vger.kernel.org,
 Pengutronix Kernel Team <kernel@pengutronix.de>,
 patches@opensource.cirrus.com, linux-integrity@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
 <60cc6796236f23c028a9ae76dbe00d1917df82a5.camel@codeconstruct.com.au>
 <20220629072304.qazmloqdi5h5kdre@pengutronix.de>
From: Javier Martinez Canillas <javierm@redhat.com>
In-Reply-To: <20220629072304.qazmloqdi5h5kdre@pengutronix.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: javierm@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=A9r6z16e;
       spf=pass (google.com: domain of javierm@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=javierm@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 6/29/22 09:23, Uwe Kleine-K=C3=B6nig wrote:
> Hello,
>=20
> [I dropped nearly all individuals from the Cc: list because various
> bounces reported to be unhappy about the long (logical) line.]
>

Yes, it also bounced for me when I tried to reply earlier today.

> diff --git a/drivers/gpu/drm/solomon/ssd130x-i2c.c b/drivers/gpu/drm/solo=
mon/ssd130x-i2c.c
> index 1e0fcec7be47..ddfa0bb5d9c9 100644
> --- a/drivers/gpu/drm/solomon/ssd130x-i2c.c
> +++ b/drivers/gpu/drm/solomon/ssd130x-i2c.c
> @@ -39,13 +39,11 @@ static int ssd130x_i2c_probe(struct i2c_client *clien=
t)
>  	return 0;
>  }
> =20
> -static int ssd130x_i2c_remove(struct i2c_client *client)
> +static void ssd130x_i2c_remove(struct i2c_client *client)
>  {
>  	struct ssd130x_device *ssd130x =3D i2c_get_clientdata(client);
> =20
>  	ssd130x_remove(ssd130x);
> -
> -	return 0;
>  }
> =20
>  static void ssd130x_i2c_shutdown(struct i2c_client *client)

Reviewed-by: Javier Martinez Canillas <javierm@redhat.com>=20
--=20
Best regards,

Javier Martinez Canillas
Linux Engineering
Red Hat

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7654a74e-a410-a8a5-c228-d006dbbc200f%40redhat.com.
