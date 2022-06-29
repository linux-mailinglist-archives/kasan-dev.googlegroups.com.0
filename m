Return-Path: <kasan-dev+bncBDLKHL4UYEFBBI4R6CKQMGQEXNLARNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 13A5455F9F9
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 10:09:09 +0200 (CEST)
Received: by mail-vk1-xa38.google.com with SMTP id p142-20020a1fbf94000000b0036bf5e57b03sf2963390vkf.14
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 01:09:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656490148; cv=pass;
        d=google.com; s=arc-20160816;
        b=iKuNeJaYjilu71rvfLKLnfr66U4aCy6tJyzPXa4l68Z6A3ICrGbRrqrEFqsYL0hV/L
         x71tCasrHKCn+y7RihSI+ZYO3a3Ju8PhsTG6teXRYPhHuWVL6ChM0a53Lp3KmOEqxenx
         ydQJkPGq/DOxPCcbitdWYozSXcvS4TgvpazXpu/woD1bugV3ECXaGvGHkk6cy2GDCkmB
         pxdJ6lkcIt2Ij5slcLqLaRzVh6Nk0wlmEi/xZlwlfvZNm+eAK+DSykqanK05PcqVTNqA
         GRX69LgXwi7oIEsbMRcr0yVT5943MKS2GIfotfwS0zwVt3fVloYdbw5QgRrTGbjuw9lF
         LBKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=5hh6ap/qf1moiSoncRep+9BFdUDupmu2Xzl4QXJMMFU=;
        b=qE0cX8JSGsWZEXbkMkL5uMHqE5VGVbQr99S9ITwln7Vt2dDQhjP9sKy2lQswduEgTN
         NO9tL2GyBBofyksJllMv90SzU30e/9fKsBeGRgY5YVmmdEsmH4jNpt5Y7+jZ+UCVMxfP
         iBWYqhBo3Kp7XH1Myhrx0qzWjxU0lpyH3iqttNi42lIO59UhBYEtOcKifetOB0jjGpmo
         +T9ZH7nuU9FpGXTtLKLGcovFTzlwfjLqo96IfHqzRDCtrhNh8rgFRu0R9Mbbx2DEENLE
         kD81/vGSAeiEvlEObQh360G7JYDF3zIMErUm8QloOVOJHg+oixNLqwyS/RruubAWUsAs
         ma6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fgsDzeyR;
       spf=pass (google.com: domain of javierm@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=javierm@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject:to:cc
         :references:from:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5hh6ap/qf1moiSoncRep+9BFdUDupmu2Xzl4QXJMMFU=;
        b=Kqh1igVUhnev48/doSl7oOq1gRqphx0VsJrxzpgDaLCr052N1J+2dWlSEXNYkPNZIQ
         dey+bjT1xG+HOEplC6S5/l9DabKDUwJ3fCylrJdaA5WRePUdTbJDHlmxFHFy8v08G7Js
         ayBm/OzMhxfHumI7Y5UFZ/SPJ7knVaIdw1PLydzGorIVifGwEkF+wJiPzykG5P1VdO+1
         gmgsHkow+zS+T+GHA4mQ/8KSFMwnSBMkbm44w+ep0zlnJq1BJwAMaf+2VvHN3xkrQenG
         OzFzzKByKaySsObFNU9cdYqm1yD9niMFP2t4IboEU9vCnv1GdNtzzhHeTezWatbEWbAb
         pQTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:to:cc:references:from:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5hh6ap/qf1moiSoncRep+9BFdUDupmu2Xzl4QXJMMFU=;
        b=jr2vRxXdt/Tqun3VlMATDXr1tBQs+u9omkL2jaYz8gts/MErzxcCzRtt+Ma4er0ZI5
         Q9MA+lWfHWrX1NqVvLd0KstTBHzBM4YIcY42O2h4AOH1uJAnNe75rgLm9z0AGiywnTx2
         wla8XITcdX7zNWTFTvj/lw9q2ZVxEl9ssNQz8jesWnOdXbPBqo4FGkxWM8p00l8h6k5s
         I+FtNU6hd5o/+wtGqQT3Md1GQKxd9/ZJ9FdenfDqdBBlp+a7svwTfubIFkxrF54GRCOk
         l0PJFZICMjMzVDV0lKyw0S3yj5JNgHuPCz+BulffUuEspg6yD6hErx6D32MGhAH2zyb0
         0dMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora++GA6laqOxWzJEp8lcTKwCDMr5yXFprbhdp5WCcsJqVy4Mg2sW
	X1dp8Nqbrqd+0q9J07D9VmE=
X-Google-Smtp-Source: AGRyM1tjQ3gjsXQUoYYeCt4CnDkjapjU8eT8E+YNlwd8IM4grgJvpWHfZ0HDg8UgIi9vmZQIhPW37g==
X-Received: by 2002:a67:f684:0:b0:356:2c32:8210 with SMTP id n4-20020a67f684000000b003562c328210mr3752967vso.24.1656490148074;
        Wed, 29 Jun 2022 01:09:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c981:0:b0:353:1bec:1d4c with SMTP id y1-20020a67c981000000b003531bec1d4cls5678685vsk.7.gmail;
 Wed, 29 Jun 2022 01:09:07 -0700 (PDT)
X-Received: by 2002:a67:ef84:0:b0:354:3ae9:e6f7 with SMTP id r4-20020a67ef84000000b003543ae9e6f7mr3160559vsp.41.1656490147456;
        Wed, 29 Jun 2022 01:09:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656490147; cv=none;
        d=google.com; s=arc-20160816;
        b=QcijQwP6cyiKjNRosMrKURlX2IkF9M2W1gNotF487L5A5buQRHbr6d2v28dRFzRrBG
         pSevdwAAm2ISA/lCNdMADWHvqyvix4xxTOCd5/YvhSD6O7y1CZchVPeGZCTQX2vL7RcK
         ZjiWoWCl7fX+4djhpU9vaxtspCoFBGkB7pV7YmZeJLS93eJ/0DPuJGwQjrR5LIVNsGPf
         7JAldyoHsU5qbB27dZx2ah3hxV4dCsriYFT6X99pyL7uelaLOYUQH8/b2RZHsc4zXN8d
         cBWrAfXgTBC5Fe3yCQgj+YPCCLRaTUI06Us9BFA2CLPdukXY7fBOEewsZxTOhFD4YXcW
         7M6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=7hQQnP6ElkRz6EikrOqVkat5RAwQAYxqOhDbZ9zjeug=;
        b=rPH5DwD5czXwwYSECFyAd3y0j9etVmIbP6YPL1x5FIILvtY+OlSN0CqeXaLnaWuWSu
         FjZcH0OCeij5byIRXZn9FoF1LUCcOksWv/MLXM49bHFsR7Xezj+04Phsqqr2vUz5N5zW
         0+irFMik40umOkLo1PnE2mhPfV2gmnIkRbdeceDu0ymv6YT1+IYCPJNWcqWtRrjFHvK+
         VirVAsX0cUwKIYz0qqq8PhdARS4chxJFZgLwVQe69qMWG40+dEiiD8iOYDg400/SljDT
         2gklapCXwrvA7DCpNU0DS+DRelxCXdBNBx1EkSmR5i+SOEgXAwPKNSeapiFx3Zw08+A7
         s7sA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fgsDzeyR;
       spf=pass (google.com: domain of javierm@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=javierm@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id h6-20020ab02346000000b0037f13500ccdsi450784uao.0.2022.06.29.01.09.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Jun 2022 01:09:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of javierm@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-455-UBiZDPLLN36TYrtcdjNr9A-1; Wed, 29 Jun 2022 04:09:05 -0400
X-MC-Unique: UBiZDPLLN36TYrtcdjNr9A-1
Received: by mail-wm1-f71.google.com with SMTP id az40-20020a05600c602800b003a048edf007so3892203wmb.5
        for <kasan-dev@googlegroups.com>; Wed, 29 Jun 2022 01:09:05 -0700 (PDT)
X-Received: by 2002:a05:600c:2246:b0:3a0:4d14:e9d5 with SMTP id a6-20020a05600c224600b003a04d14e9d5mr2201666wmm.70.1656490144655;
        Wed, 29 Jun 2022 01:09:04 -0700 (PDT)
X-Received: by 2002:a05:600c:2246:b0:3a0:4d14:e9d5 with SMTP id a6-20020a05600c224600b003a04d14e9d5mr2201616wmm.70.1656490144372;
        Wed, 29 Jun 2022 01:09:04 -0700 (PDT)
Received: from [192.168.1.129] (205.pool92-176-231.dynamic.orange.es. [92.176.231.205])
        by smtp.gmail.com with ESMTPSA id p2-20020a05600c358200b003942a244f47sm2507134wmq.32.2022.06.29.01.09.02
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Jun 2022 01:09:03 -0700 (PDT)
Message-ID: <a5a3e2ca-030a-4838-296e-50dbb6d87330@redhat.com>
Date: Wed, 29 Jun 2022 10:09:01 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.10.0
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
To: Christophe Leroy <christophe.leroy@csgroup.eu>,
 =?UTF-8?Q?Uwe_Kleine-K=c3=b6nig?= <u.kleine-koenig@pengutronix.de>,
 Jeremy Kerr <jk@codeconstruct.com.au>
Cc: "linux-fbdev@vger.kernel.org" <linux-fbdev@vger.kernel.org>,
 "linux-iio@vger.kernel.org" <linux-iio@vger.kernel.org>,
 "dri-devel@lists.freedesktop.org" <dri-devel@lists.freedesktop.org>,
 "platform-driver-x86@vger.kernel.org" <platform-driver-x86@vger.kernel.org>,
 "patches@opensource.cirrus.com" <patches@opensource.cirrus.com>,
 "linux-mtd@lists.infradead.org" <linux-mtd@lists.infradead.org>,
 "linux-i2c@vger.kernel.org" <linux-i2c@vger.kernel.org>,
 "linux-stm32@st-md-mailman.stormreply.com"
 <linux-stm32@st-md-mailman.stormreply.com>,
 "linux-rtc@vger.kernel.org" <linux-rtc@vger.kernel.org>,
 "chrome-platform@lists.linux.dev" <chrome-platform@lists.linux.dev>,
 "linux-staging@lists.linux.dev" <linux-staging@lists.linux.dev>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 Broadcom internal kernel review list
 <bcm-kernel-feedback-list@broadcom.com>,
 "linux-serial@vger.kernel.org" <linux-serial@vger.kernel.org>,
 "linux-input@vger.kernel.org" <linux-input@vger.kernel.org>,
 "linux-media@vger.kernel.org" <linux-media@vger.kernel.org>,
 "linux-pwm@vger.kernel.org" <linux-pwm@vger.kernel.org>,
 "linux-watchdog@vger.kernel.org" <linux-watchdog@vger.kernel.org>,
 "linux-pm@vger.kernel.org" <linux-pm@vger.kernel.org>,
 "acpi4asus-user@lists.sourceforge.net"
 <acpi4asus-user@lists.sourceforge.net>,
 "linux-gpio@vger.kernel.org" <linux-gpio@vger.kernel.org>,
 "linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>,
 "linux-rpi-kernel@lists.infradead.org"
 <linux-rpi-kernel@lists.infradead.org>,
 "openipmi-developer@lists.sourceforge.net"
 <openipmi-developer@lists.sourceforge.net>,
 "linux-arm-kernel@lists.infradead.org"
 <linux-arm-kernel@lists.infradead.org>,
 "linux-hwmon@vger.kernel.org" <linux-hwmon@vger.kernel.org>,
 Support Opensource <support.opensource@diasemi.com>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Wolfram Sang <wsa@kernel.org>,
 "linux-crypto@vger.kernel.org" <linux-crypto@vger.kernel.org>,
 Pengutronix Kernel Team <kernel@pengutronix.de>,
 "netdev@vger.kernel.org" <netdev@vger.kernel.org>,
 "linux-integrity@vger.kernel.org" <linux-integrity@vger.kernel.org>,
 "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
 <60cc6796236f23c028a9ae76dbe00d1917df82a5.camel@codeconstruct.com.au>
 <20220629072304.qazmloqdi5h5kdre@pengutronix.de>
 <5517f329-b6ba-efbd-ccab-3d5caa658b80@csgroup.eu>
From: Javier Martinez Canillas <javierm@redhat.com>
In-Reply-To: <5517f329-b6ba-efbd-ccab-3d5caa658b80@csgroup.eu>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: javierm@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fgsDzeyR;
       spf=pass (google.com: domain of javierm@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=javierm@redhat.com;
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

On 6/29/22 09:55, Christophe Leroy wrote:
>=20
>=20
> Le 29/06/2022 =C3=A0 09:23, Uwe Kleine-K=C3=B6nig a =C3=A9crit=C2=A0:
>> Hello,
>>
>> [I dropped nearly all individuals from the Cc: list because various
>> bounces reported to be unhappy about the long (logical) line.]
>=20
> Good idea, even patchwork made a mess of it, see=20
> https://patchwork.ozlabs.org/project/linuxppc-dev/patch/20220628140313.74=
984-7-u.kleine-koenig@pengutronix.de/
>=20

FYI, for patches like these what I usually use is:

./scripts/get_maintainer.pl --nogit-fallback --no-m --no-r

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
kasan-dev/a5a3e2ca-030a-4838-296e-50dbb6d87330%40redhat.com.
