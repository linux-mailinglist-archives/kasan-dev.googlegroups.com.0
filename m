Return-Path: <kasan-dev+bncBDQ27FVWWUFRBMXWTDTQKGQEGJAIXZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BAE5275F5
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 08:18:27 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id p83sf1943395vkd.7
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 23:18:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558592306; cv=pass;
        d=google.com; s=arc-20160816;
        b=lGha3QpprHLOC4xx9qS4++AdT6CxuNk8VF0QiYL7IiPMRYuxZoPyIPUSiki//I+VuY
         5S+1weVKkJ897FxCyRW1XFdaiMSp48IM6FGTTCHULmbVolcpUdFpfJ5MUPS8Ii1NTzKQ
         //vf7H49QH87DRe73cX37Galoa4pYoexjrmhjKjvNIwRDHwVSF9L0aKc8oiYkSYdtzVZ
         qFv8TLoXbshdDef4yqbf/VJhBD8Ncdh2xsfDomVD04NBrVmgrltgefOsdiClYcW+wCGI
         996KiAvnPbARlNAJ2Jfsds6PUZ9LiEs85atsJfixBlygA/DjTyMwJtLtvJCvnEPyjwP2
         0RYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=ws+o8kwMbIHTmWep/5flg90eruzCkHmJ04AZjhfpJZk=;
        b=lThzudhf3EaviplldA/omrfTzfMhRC8pYW3MX7vV8DXYat+K/6v9xQnmGZ5ScXwYdL
         gF6K0Opw5SKr6U1TAoDnfvmJujqO1Ulxx9qHcAjZFL7uY95+ReXsR7jBZCDsG6ja0g4D
         /xH12TlMInZoJp4CpcR/hkmE+CXEuNDRZa491PE2cKGGwxOlEn1y7maqskC8aqKEDiXG
         qEMTAt7OUkE40Gq+R5yuKq7Sdu3wuGkQetx2j7CtPt9yDFlNmitzoZzmfzFbiq9kFcJw
         Q1cQd3ie8Dk8meUpRWcJXZiHJxF7y4u8vYKlVq4jdDPI/RXYUD535tn0mDPkktDaFDK4
         rqWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=CVE170U4;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ws+o8kwMbIHTmWep/5flg90eruzCkHmJ04AZjhfpJZk=;
        b=KqdkMtntsrNcOGSaulMmAdG5DqCRgWNG542HlICQzyN+X6GyFDPBerbT/NeRSdT6VD
         fuo+JlZlLsVEE9W3DupCxf6G63XZq+7dweZPcFzFU4rb/TBAsszulO3ESdNbSBu/1RUR
         lc7yU3u/K6phemwi4mntSavlZYXiMvH/U6TS6VswvWxND8z8TXvYJowr37JFdTdpSr1x
         5VqfxdRv5KWhjLu0d/nqKMIPBZ60nArchaept7Ts4aMRve0nRL0csGoxGTHdk5kWP0ys
         1ivQ0wWr4QuOSHAxu8Z2OKumgRHuvA6hbh3HOdsbiTX3/zeRPczg9RAhhUYeMHjFSYS4
         yguQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ws+o8kwMbIHTmWep/5flg90eruzCkHmJ04AZjhfpJZk=;
        b=EbwlGeHHhEvt5d9KP6cxmo/I+Q5g51tRcEWGESE5Ky0+hbCZMWEr1ibp9hibetcbKA
         ZkLxtPeqRRf0v6+602/KZ6k0BHewvYx4aB4g3oMp+ONqR/2C3AG4xsIKEAemnyJUhfUF
         K8bdL8/4l2ApiF3QSHumSMmOC2+GECMaTOoGFDpxl+1qBfl80/ZC72RdQYzqi6HPXxoX
         1PE2482buEC55Vgr3DfAEa89qfio14nii/uEWJo6v4fMigiFWAE8DnxcUOO4CEQrx9sS
         eULYDVvtNyMVIQvGF2IY+wvcLufdLiP4qKY5lfPJCTECRDf4/JCbflzQqOFUkP6OidEe
         2UAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU8KWRGw14xB3ZnvUpria3Y/rnptaVGeGI3HwrzW5woF+81gEWT
	BTRRoL6VKMJ+KrLo3k1yng8=
X-Google-Smtp-Source: APXvYqzzry6BmVD0hpN+C2gHWXDUFdpd2fSWEH1Zec4HS/+eojhFwQCeGemB6ToklnhOTeO3q1CNZA==
X-Received: by 2002:a67:774f:: with SMTP id s76mr42587868vsc.131.1558592306342;
        Wed, 22 May 2019 23:18:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2d91:: with SMTP id v17ls290773uaj.2.gmail; Wed, 22 May
 2019 23:18:26 -0700 (PDT)
X-Received: by 2002:ab0:4a14:: with SMTP id q20mr22799331uae.67.1558592306041;
        Wed, 22 May 2019 23:18:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558592306; cv=none;
        d=google.com; s=arc-20160816;
        b=nrhQehjRLTYZ4vgcd3RR0wAPYVwMfWt0KRIHKShG4pSnRr/k93R/KljI7upqFDtRgB
         /namGrzImxD7Tum9VBH+Mfd9fSvFgohQWXzVv+SvMkp/VsPnBlB7ryIJEThTEDPM4QNe
         L/30OG+dRToKm5La3BlCUzLA/uNMTFdUsMvhaPsicuzDXCCCII4ZEsNyy53ATObTvSSt
         xusO5s48dqwJPr+kcZVMHLikGp6uYxrHyQD7VJLBWxrcX+EbrhV1PT6pUYmx7tFT7RZV
         rx8YyvaI0zc1cY4Uu3rxvU1eZjF85K8SuTYn2X/PHwKVNBGORLo0mFGyI2mCGvYPxx1D
         9rtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=R2DcKDY8hNYt3eHiRg3vn/4L/iz0wQN/kPiNKVfWds4=;
        b=UVCq36/p5Z2p+UuQtgK4hLc4t+Xf6l3uEFd9X6yOdhVyaKD66vM+7xBbTL0gYWnfHO
         3sxlypLYI7GLfmuDMYNLTq1BUcdXqvm7dCYeOyJHLcBhmImIyMbItMhrHT1UvTryZzh+
         8fCXqn7A4t1VJUkTUKD+GIGVEbqPcrx+9cTKBD6P7dbyKnzuYCYjHj4qZWPYyt9lkDS0
         GZVcyvwJaOI/BtxGB/gLz6MxZ7M9NVwQ50MPserKlhYlsXN+Dp5JH3pTGuHtAUTbdfE6
         8WWr4IYYtnS6dSN+VI0rQ4kw6nnno4UbOI4hAnvrNHPCXqOKqqkQvsEZUg6Stf/nqlZX
         Q07Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=CVE170U4;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id 92si2021103uaw.0.2019.05.22.23.18.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 23:18:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id d126so450983pfd.2
        for <kasan-dev@googlegroups.com>; Wed, 22 May 2019 23:18:25 -0700 (PDT)
X-Received: by 2002:a65:5647:: with SMTP id m7mr94371900pgs.348.1558592305053;
        Wed, 22 May 2019 23:18:25 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id 4sm9920517pfj.111.2019.05.22.23.18.23
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 22 May 2019 23:18:24 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
Subject: Re: [RFC PATCH 0/7] powerpc: KASAN for 64-bit 3s radix
In-Reply-To: <584b6b5b-7051-e2de-ca4e-a686c5491aad@c-s.fr>
References: <20190523052120.18459-1-dja@axtens.net> <584b6b5b-7051-e2de-ca4e-a686c5491aad@c-s.fr>
Date: Thu, 23 May 2019 16:18:20 +1000
Message-ID: <87k1ehzob7.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=CVE170U4;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Christophe Leroy <christophe.leroy@c-s.fr> writes:

> Hi Daniel,
>
> Le 23/05/2019 =C3=A0 07:21, Daniel Axtens a =C3=A9crit=C2=A0:
>> Building on the work of Christophe, Aneesh and Balbir, I've ported
>> KASAN to Book3S radix.
>>=20
>> It builds on top Christophe's work on 32bit, and includes my work for
>> 64-bit Book3E (3S doesn't really depend on 3E, but it was handy to
>> have around when developing and debugging).
>>=20
>> This provides full inline instrumentation on radix, but does require
>> that you be able to specify the amount of memory on the system at
>> compile time. More details in patch 7.
>>=20
>> Regards,
>> Daniel
>>=20
>> Daniel Axtens (7):
>>    kasan: do not open-code addr_has_shadow
>>    kasan: allow architectures to manage the memory-to-shadow mapping
>>    kasan: allow architectures to provide an outline readiness check
>>    powerpc: KASAN for 64bit Book3E
>
> I see you are still hacking the core part of KASAN.
>
> Did you have a look at my RFC patch=20
> (https://patchwork.ozlabs.org/patch/1068260/) which demonstrate that=20
> full KASAN can be implemented on book3E/64 without those hacks ?

I haven't gone back and looked at the book3e patches as I've just been
working on the 3s stuff. I will have a look at that for the next version
for sure. I just wanted to get the 3s stuff out into the world sooner
rather than later! I don't think 3s uses those hacks so we can probably
drop them entirely.

Regards,
Daniel

>
> Christophe
>
>>    kasan: allow arches to provide their own early shadow setup
>>    kasan: allow arches to hook into global registration
>>    powerpc: Book3S 64-bit "heavyweight" KASAN support
>>=20
>>   arch/powerpc/Kconfig                         |   2 +
>>   arch/powerpc/Kconfig.debug                   |  17 ++-
>>   arch/powerpc/Makefile                        |   7 ++
>>   arch/powerpc/include/asm/kasan.h             | 116 +++++++++++++++++++
>>   arch/powerpc/kernel/prom.c                   |  40 +++++++
>>   arch/powerpc/mm/kasan/Makefile               |   2 +
>>   arch/powerpc/mm/kasan/kasan_init_book3e_64.c |  50 ++++++++
>>   arch/powerpc/mm/kasan/kasan_init_book3s_64.c |  67 +++++++++++
>>   arch/powerpc/mm/nohash/Makefile              |   5 +
>>   include/linux/kasan.h                        |  13 +++
>>   mm/kasan/generic.c                           |   9 +-
>>   mm/kasan/generic_report.c                    |   2 +-
>>   mm/kasan/init.c                              |  10 ++
>>   mm/kasan/kasan.h                             |   6 +-
>>   mm/kasan/report.c                            |   6 +-
>>   mm/kasan/tags.c                              |   3 +-
>>   16 files changed, 345 insertions(+), 10 deletions(-)
>>   create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3e_64.c
>>   create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3s_64.c
>>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87k1ehzob7.fsf%40dja-thinkpad.axtens.net.
For more options, visit https://groups.google.com/d/optout.
