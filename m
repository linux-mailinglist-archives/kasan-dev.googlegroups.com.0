Return-Path: <kasan-dev+bncBAABBEMWT2LQMGQEMFKSYOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 22CDF58660D
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Aug 2022 10:13:06 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id p2-20020a05600c1d8200b003a3262d9c51sf7777099wms.6
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Aug 2022 01:13:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659341585; cv=pass;
        d=google.com; s=arc-20160816;
        b=O9BU9PFKT2LUrFUfWlRZrcEcSqRtzKNPyXpi0FrquCWB10iAzmI6XPaKeOf64k6lY8
         GRKXMbxWGOwtxYsiIxSHqla+Q04QamSWhzLm1QGy5e9vJvBPYNTtoxXjWeDjv/agucfB
         AazoZvzo2bXlqBjeTbd7hUwgAgyhh8rN2hWBNaaU9msB0NMux0NRkiKKBtDU2fURjYba
         Z3gSZvFbxfWm0Xn+MVOmsVe/h2BGNlBf/xp+ZSVZ4LHuoMgzp+qMF1naTAvL2CQWQe3B
         uD4/CUOz089p3bA3t9obEHBlnsRPLqoQthOj+JAdDsSwslthMqEDY12mt9q/CP+3e7Xa
         oBcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=e7O7YdmTDMxJyW2SHmwBrpepPzXG4LAfUA/bqYg58gs=;
        b=CTJ2OArKE+vJ9jisiEGmSdGorwVD1ufERWccj06sDnZkc2sjBzdl1tUQCceLCEX2ca
         xEH4yFo/qy4CkhfJjHaZpF3LJJTyWleRzbfHpkIKQgm7P8NaiPfz1LgfSIRjYmnMMAC/
         UftD+xdrAeu3Ougj8kezjNA5EuqKbP5Zd2mr5lVr+gA72s93msF9br9H0aovrATDhNT3
         okPIV/UCRiue+NcmOrAlcrNKROvR9focgoK1+CefyDI4Phe93i3BMtrtW2ZnPGXIJFm7
         cXBxIxz83paX9/SGRF3cGN43IpBsbvo3+J+dvALVvr0hME0OEiFxRgmZdAC2A1dK4wHA
         3/mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.de header.s=default header.b=clpgplu7;
       spf=pass (google.com: domain of cl@gentwo.de designates 161.97.139.209 as permitted sender) smtp.mailfrom=cl@gentwo.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gentwo.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e7O7YdmTDMxJyW2SHmwBrpepPzXG4LAfUA/bqYg58gs=;
        b=BizaFBZ1qoApUhqrrAdbQ1xOIedzks8PF5E6zDb7UGg06Z4tp4Tw8KmvNe3SjCgWdO
         bDFhmZCkR9UcXbrdp4kwuggph8/AvgKi3aJXzM84ZaVScH/z01RIT4cLHP7RQ3O3gVr9
         a/XCpxV6/yT0Je82Ra7SHDeqQDCTajlKMUi7gedcoD7jUqWPQgDrpeBQ1QXpSDP+k0jf
         20e5jQkZQn8PvGb5qH24WSN8rBe1qlnt5AtiufMT/wQlvZTEx1IfES0tM491uj/YJyu8
         RtjLmDqbXhMkJrGHns/V7qVUoYvtciTZ0+TrAijG/1W+ChTlpOW2wWdy7HhpxYN+o6FS
         mMYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e7O7YdmTDMxJyW2SHmwBrpepPzXG4LAfUA/bqYg58gs=;
        b=J7v/3uBsr09nbBWu06cSER/ktcnosgjrIW+UdirRMY9kDPRPnu1Cyk6PFUtyOVrKr7
         3kSlmWsmVcAWTps0ymAh0IG7UDhMnDQj0fKv79ZdCxpWuqbZGiHAYpzI1laZbfgcZFd/
         Z0xBzn/+uHpuzzBR2l8Jo5R90pQKCAgb2OJeU60rW100Fg7Wf/7yZCDjpDEdr5oo8A01
         +AK5rYxXum8AKRjY5ahwqPzZnce5CzAWFzXD7kYS4efkcZzchDbI/7OkouZLmg57X5Dn
         cJ1qQoYJ+IGAV0hk1ZUvLrs8Fbp59LJhH+e70sfW/Wr11joJtZ2CmCuEm4AumOBDU859
         YptA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2iA90k16grV/of9tJKawrKC6SI59hOaz5mQuPrKJEF0sItkmci
	Jz0f8cE42cIN8mKc+Fe2crE=
X-Google-Smtp-Source: AA6agR56Duuc0149mJf4TZolXl1i1dq+BaLQfOzdNhitxJnE7pDH+8O0gxHua9jmHdoVYY/AXenc/A==
X-Received: by 2002:a5d:4983:0:b0:220:5fee:1d79 with SMTP id r3-20020a5d4983000000b002205fee1d79mr3786501wrq.62.1659341585817;
        Mon, 01 Aug 2022 01:13:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:605:b0:21e:d303:d51 with SMTP id
 bn5-20020a056000060500b0021ed3030d51ls11370239wrb.2.-pod-prod-gmail; Mon, 01
 Aug 2022 01:13:05 -0700 (PDT)
X-Received: by 2002:a5d:52c4:0:b0:21e:428a:912b with SMTP id r4-20020a5d52c4000000b0021e428a912bmr9380760wrv.395.1659341585134;
        Mon, 01 Aug 2022 01:13:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659341585; cv=none;
        d=google.com; s=arc-20160816;
        b=Feo6fEFg+8MZTF6YznMDvY1CpJcJ2MlHIbD7yQd83XFCmAMjlL/e9+FKywy54ihAjn
         csmg2TFwDIqqlBpMitiYSUTmVbwUc+oWoI+Ev3JIbVjx0om7Oo5K61O5/zPsU9fvH/FD
         U5ZhPuhgzBlHwg8qCDXoBoQKRMdVqR38nePxGbHT9zguNRIhH0ONJ3zjsuHMnUaxdxWS
         5baPujO3LYKaF3FS7MgyIvnYoqCVDZQRC+3KiE/TtWlU/FfWEfo0tp4RROencma1TzHS
         wC2Pozx8cJw+vtvF3fYjeZK+2ZnYjVezTTe/Z/aLV8nCI7feh5U6gHj45lZp425llaoC
         qtvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=7ej9QGe97co2lZBbpuaLKVIWx1GQrg8akopJX1kWUqM=;
        b=oHXmGGjHWjgsW3NvIv9IKO3InfV7Sk4bLFpzi1a7qrJSuzSTvN7s3F9FPV84tV0cUV
         FSNGUbhoKqTLSOjnUPZLm51B4+rEx1JLOBOPqjRhxHn8fGcgxeal4gDcs0acKMaWgW+G
         JTPMx0+scWfYzC7plX+uUvQzTLbviY+BhqwIyROI4atiQoWW4xiNkAbOGrjoXyFHw5cZ
         ybCT89e5f/4Ch/5j2aZt+dcPT1WV6zTGsJtGtTmODdUFCxUMQB0e5DY23qelaBjEDaK3
         MxQH2uXWDTmzz/Upq9722Gq07uf9YBOB43pjAUPwO3d3L4ONIIxR3LuZC5oHrnV8yLQ/
         ytmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.de header.s=default header.b=clpgplu7;
       spf=pass (google.com: domain of cl@gentwo.de designates 161.97.139.209 as permitted sender) smtp.mailfrom=cl@gentwo.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gentwo.de
Received: from gentwo.de (gentwo.de. [161.97.139.209])
        by gmr-mx.google.com with ESMTPS id a1-20020a05600c348100b003a31dd38c4esi630680wmq.2.2022.08.01.01.13.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Aug 2022 01:13:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of cl@gentwo.de designates 161.97.139.209 as permitted sender) client-ip=161.97.139.209;
Received: by gentwo.de (Postfix, from userid 1001)
	id C85A1B0038D; Mon,  1 Aug 2022 10:13:04 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by gentwo.de (Postfix) with ESMTP id C69C8B000FB;
	Mon,  1 Aug 2022 10:13:04 +0200 (CEST)
Date: Mon, 1 Aug 2022 10:13:04 +0200 (CEST)
From: Christoph Lameter <cl@gentwo.de>
To: Feng Tang <feng.tang@intel.com>
cc: Dmitry Vyukov <dvyukov@google.com>, "Sang, Oliver" <oliver.sang@intel.com>, 
    Vlastimil Babka <vbabka@suse.cz>, lkp <lkp@intel.com>, 
    LKML <linux-kernel@vger.kernel.org>, 
    "linux-mm@kvack.org" <linux-mm@kvack.org>, 
    "lkp@lists.01.org" <lkp@lists.01.org>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
    Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
    Roman Gushchin <roman.gushchin@linux.dev>, 
    Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
    "Hansen, Dave" <dave.hansen@intel.com>, 
    Robin Murphy <robin.murphy@arm.com>, John Garry <john.garry@huawei.com>, 
    Kefeng Wang <wangkefeng.wang@huawei.com>, 
    Andrey Konovalov <andreyknvl@gmail.com>, 
    Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
    Alexander Potapenko <glider@google.com>, 
    "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: [mm/slub] 3616799128:
 BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
In-Reply-To: <YueFZm1JHDZOKVw/@feng-skl>
Message-ID: <alpine.DEB.2.22.394.2208011011120.2493025@gentwo.de>
References: <20220727071042.8796-4-feng.tang@intel.com> <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020> <YuY6Wc39DbL3YmGi@feng-skl> <Yudw5ge/lJ26Hksk@feng-skl> <CACT4Y+Y5aTQMuUU3j60KbLrH_DoFWq1e7EEF5Ka0c1F9a3FniA@mail.gmail.com> <YueFZm1JHDZOKVw/@feng-skl>
User-Agent: Alpine 2.22 (DEB 394 2020-01-19)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cl@gentwo.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gentwo.de header.s=default header.b=clpgplu7;       spf=pass
 (google.com: domain of cl@gentwo.de designates 161.97.139.209 as permitted
 sender) smtp.mailfrom=cl@gentwo.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=gentwo.de
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

On Mon, 1 Aug 2022, Feng Tang wrote:

> > Or does it make sense to prohibit KASAN+SLUB_DEBUG combination? Does
> > SLUB_DEBUG add anything on top of KASAN?
>
> I did a quick glance, seems the KASAN will select SLUB_DEBUG in
> many cases, as shown in the lib/Kconfig.kasan:
>
> 	config KASAN_GENERIC
> 		...
> 		select SLUB_DEBUG if SLUB
>
> 	config KASAN_SW_TAGS
> 		...
> 		select SLUB_DEBUG if SLUB

SLUB_DEBUG is on by default on all distros. This just means that debugging
support is compiled in but not activated. Kasan etc could depend on
SLUB_DEBUG. Without SLUB_DEBUG the debugging infrastructure of SLUB that
is use by Kasan is not included.

If you want to enable debugging on bootup then you need to set
SLUB_DEBUG_ON.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.22.394.2208011011120.2493025%40gentwo.de.
