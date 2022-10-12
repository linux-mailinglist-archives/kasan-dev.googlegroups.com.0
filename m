Return-Path: <kasan-dev+bncBDK7LR5URMGRB66ZTONAMGQETIQA4TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 044745FC95D
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Oct 2022 18:36:16 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id u12-20020ac248ac000000b004a22e401de1sf4938100lfg.19
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Oct 2022 09:36:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665592572; cv=pass;
        d=google.com; s=arc-20160816;
        b=PEplpZlyJrYaiR6HuoaGYCXuhwitEyYAmHIi7u+z4GEwQebtFfgmkzNS3+dDD9S8n7
         NLW4yUuykXkNzIhevFkLNRZNjYFXQR5Z1zk8T//7f1SDUoTLf+JGDCJAXPdIiFu0UN//
         FtstJ7Vq9p9Z1TltfKtgBsCEu2WkSbnD8w1C7Ik+ib1Zq62HbN9mnpp2nei3MisGw4c0
         SR6Wk02F+BxynWDNOKZBzw2jCxCw2GwtIwkkFzFQfvN8stlP8g8SW5SesWtyVwJQOp8X
         z7BlYLeIphe7Yi3uj0KxF6lJWwZU8uyv5Ha3RyOKW2YwWRwUwxUI0TpZvYTploxPC+nR
         25Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=Gn+5rx96AD+ODYbpdBaY/mPyoPInhUgt/h89ROmXKJk=;
        b=vSmn/T5Oo8k5ZWj0KaVjfEwEHqmxe8qz1cNRZRkk27YnQ2z68gI+JDBQJVtQ6CtabA
         5kni8Wn7sP8dl/GWJxqTA7ffQzf2MZg8eHD4IGN7fJcrD+qVOFi4zdOU9r8VsuQANmdB
         G1s5svp/cqEFZphuWu/E3S89RjJnnqYB+qY5yRmiZX9v3xRGnQABg24pfJLmZPPzYtbr
         e3GPqlGTGekk2hJ+PsmxBnFagh3yXGFnausxRuaQA0r+6LL5yGrt4sMNmL5H79afQI3G
         e6aAc4stWYLzDu7b0WrhHd6LY3kO7u/xPia9xJwMijf0H9u1pETzy9iB1zXney8tihg+
         rnLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RRz2Zz6O;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Gn+5rx96AD+ODYbpdBaY/mPyoPInhUgt/h89ROmXKJk=;
        b=fg974RovdUo6j4iOvJUQ+czgbOVaVwOPyb3k7m6tN7itmsOfheTOo4QKbkDfstIitn
         fv7fMCIW+zK+jJWgpE40z0Vp69qBK+xEGsFt5m7o0bG6fNUz508rEF3YSEbghLiXRhwp
         MOvKksGuLsZLU1IdeDEyVVK3EUPyAKqAUp7tukaSouzLFUcgLWRb39SWfwGiAt1tXo0/
         HdROJjwcgAtdvS78ZILWEK4OlzqGvcWnRq84A0bMM4nomF3DHcrWPzUTAu01PMSZA5/M
         8IOD1EYR0P3tnYZ73cjCT9wDHu5V4xbYq6BT49aTo5AB0QCUyDmgRFh5l0YAE8Aq84M4
         WeRQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Gn+5rx96AD+ODYbpdBaY/mPyoPInhUgt/h89ROmXKJk=;
        b=NAMzH8p9l4isjFg2IZHyv7cQj2ySW6Fk1Mi7ExRRsEGuJOW14a7xHY+Bd5PtDLwFWI
         yLL1m5htlF0S1Cl7EpaeEBxJtfqK/FgWvd/j821ivl8Mzx1Nb/lzaxz3gVC9Na12hViz
         8NUPQDJjVAPSLEMIyev3Gypf04ZTj+W5IOobeoKc0fSrvCwox9vvzat3Y8Hpe4jaP1yI
         x8zzdCDQDW2m0gj24E7gShl7FT5Oag322NUF/l3Zakf5TaGnMdiIHgHc9YO3jI/10rFN
         r5KhxbmjK3AzynxM53QtVBOFOj9OnDmVautfwUWtUyrbJ/HCl5wN/5UHuyJemEo0C39K
         ZK4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Gn+5rx96AD+ODYbpdBaY/mPyoPInhUgt/h89ROmXKJk=;
        b=wPiFSXYPIGQ/BUqSZAt0/VltK6+4F2XO7iJbL//gPAB+8Z+DUqySMpFsLf1Ju8Ffvq
         siqCEDyj2+DedsBHI9LtVSNBtRWUlVdx5ShMuYnlJalYw5mfyqOnpN4vx3vWHlu5fIz6
         h118TC45i/vWvwxTKXs/77hYETkSVPuxaGcCeX4w+Hpeiq5zhNnckMZCAW87OJjutY0I
         CBFpX+XRA3mGODnSUckdltkAuRGCan/mkqPrP4DhkedfTVI6Gw+07RV208BBjD+VS+ms
         3a4vLAmkwqsVzezaalAov2Lj556gfTirVdP59arR4sYHSNMTCPrDCxd7PAiiBTqicO3x
         GGhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3GS/1Y4LEa2G895BVRraWV1KDEqlx1k9ggjX6MVV8uSA2hiIZM
	euQtWVW7g7lutzFFN+S+xZY=
X-Google-Smtp-Source: AMsMyM63IuGPxyw9m9BtYIJZKwam2MMqnRxxm0LjCQL1xfgWMSdxDxdeWlM58i+/GOCg/Or2pA8r+A==
X-Received: by 2002:a2e:8719:0:b0:26f:abac:4aac with SMTP id m25-20020a2e8719000000b0026fabac4aacmr5272072lji.62.1665592572150;
        Wed, 12 Oct 2022 09:36:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4ec6:0:b0:4a2:3951:eac8 with SMTP id p6-20020ac24ec6000000b004a23951eac8ls1081032lfr.0.-pod-prod-gmail;
 Wed, 12 Oct 2022 09:36:10 -0700 (PDT)
X-Received: by 2002:ac2:5978:0:b0:4a2:6792:df61 with SMTP id h24-20020ac25978000000b004a26792df61mr10051552lfp.565.1665592570768;
        Wed, 12 Oct 2022 09:36:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665592570; cv=none;
        d=google.com; s=arc-20160816;
        b=Ccmrp+denLjPM1fFJVmwbEYs/mks268VCcNQPAbTCPS0nm2pVV2gyp5jRLrGl6i9Ty
         8N1jA63WSFBYWmGvQJioENcwimU5mByja0qsfB6oUV8UMPEyUkXieixyREtolMSYXT91
         V+PqCDCwnYS8yRukMufN4Mg0/gTHYvgojMieqKRVTjHsDtsO5fh1bNEJHWJqT4OiOVbj
         CwCgM2Csk8po5s0tfsRLnYRrj/XA1M6yh45sThixmodvtgl3PLwJS9wxMtHXGqm39WeV
         P5T5c1faJrWLjuZUUBCerSUnJq9XiaoEatg4owOpEw0p3xKAVsWSrU3FhjvhYd7cVfiq
         EJBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=Fxm/OXcIXJkYL5yUuQr39NlAJj98QVsfZpBA3iMNlkA=;
        b=Ms88Ja6QqrRjdqStfwtqFD1NnqyfukA8pB3Y8dQEK7UVeGMqcp2Ty6YUWiCOulZRxx
         fJH1ltvFbvd9l8TtR7r7FqLLwdhbBKYDGZlIZtYuVrzAAiNLeh42MUg+2oyui8bTqtI3
         /D4tevxrRx7a/vqzfsUNXzNusKbmH9BbEwueSvEfC/qR4PNXTXVkI3hFzc6dZLSWfnZH
         PP3EXyQiuSAFN4N8d5upncUgWq3gMecQY9lNiFlWqJU1oGqi2no5AL+xtCcyl4ymPebg
         ewGnoS4X4yZnV0i1zPR7z6yY3VP5oloBI0A18wSK76k2UrbVQRGk2n5V24TkNQaMDEQd
         /8Ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RRz2Zz6O;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id h14-20020a2ea48e000000b0026fb09d81bbsi299392lji.1.2022.10.12.09.36.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Oct 2022 09:36:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id z3so24238226edc.10
        for <kasan-dev@googlegroups.com>; Wed, 12 Oct 2022 09:36:10 -0700 (PDT)
X-Received: by 2002:a05:6402:4310:b0:45c:c16c:5c7d with SMTP id m16-20020a056402431000b0045cc16c5c7dmr2183811edc.246.1665592570220;
        Wed, 12 Oct 2022 09:36:10 -0700 (PDT)
Received: from pc638.lan ([155.137.26.201])
        by smtp.gmail.com with ESMTPSA id p23-20020a17090653d700b0077077b59085sm1509029ejo.184.2022.10.12.09.36.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Oct 2022 09:36:09 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Wed, 12 Oct 2022 18:36:07 +0200
To: David Hildenbrand <david@redhat.com>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Subject: Re: KASAN-related VMAP allocation errors in debug kernels with many
 logical CPUS
Message-ID: <Y0bs97aVCH7SOqwX@pc638.lan>
References: <8aaaeec8-14a1-cdc4-4c77-4878f4979f3e@redhat.com>
 <Yz711WzMS+lG7Zlw@pc636>
 <9ce8a3a3-8305-31a4-a097-3719861c234e@redhat.com>
 <Y0BHFwbMmcIBaKNZ@pc636>
 <6d75325f-a630-5ae3-5162-65f5bb51caf7@redhat.com>
 <Y0QNt5zAvrJwfFk2@pc636>
 <478c93f5-3f06-e426-9266-2c043c3658da@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <478c93f5-3f06-e426-9266-2c043c3658da@redhat.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=RRz2Zz6O;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::536 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
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

> 
> Was lucky to grab that system again. Compiled a custom 6.0 kernel, whereby I printk all vmap allocation errors, including the range similarly to what you suggested above (but printk only on the failure path).
> 
> So these are the failing allocations:
> 
> # dmesg | grep " -> alloc"
> [  168.862511] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.863020] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.863841] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.864562] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.864646] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.865688] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.865718] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.866098] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.866551] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.866752] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.867147] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.867210] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.867312] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.867650] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.867767] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.867815] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.867815] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.868059] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.868463] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.868822] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.868919] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.869843] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.869854] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.870174] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.870611] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.870806] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.870982] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  168.879000] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.449101] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.449834] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.450667] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.451539] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.452326] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.453239] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.454052] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.454697] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.454811] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.455575] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.455754] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.461450] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.805223] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.805507] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.929577] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.930389] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.931244] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.932035] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.932796] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.933592] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.934470] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.935344] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  169.970641] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.191600] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.191875] -> alloc 40960 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.241901] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.242708] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.243465] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.244211] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.245060] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.245868] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.246433] -> alloc 40960 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.246657] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.247451] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.248226] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.248902] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.249704] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.250497] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.251244] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.252076] -> alloc 319488 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.587168] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  170.598995] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  171.865721] -> alloc 2506752 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> [  172.138557] -> alloc 917504 size, align: 4096, vstart: 18446744072639352832, vend: 18446744073692774400
> 
OK. It is related to a module vmap space allocation when a module is
inserted. I wounder why it requires 2.5MB for a module? It seems a lot
to me.

> 
> Really looks like only module vmap space. ~ 1 GiB of vmap module space ...
> 
If an allocation request for a module is 2.5MB we can load ~400 modules
having 1GB address space.

"lsmod | wc -l"? How many modules your system has?

> I did try:
> 
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index dd6cdb201195..199154a2228a 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -72,6 +72,8 @@ early_param("nohugevmalloc", set_nohugevmalloc);
>  static const bool vmap_allow_huge = false;
>  #endif /* CONFIG_HAVE_ARCH_HUGE_VMALLOC */
> +static atomic_long_t vmap_lazy_nr = ATOMIC_LONG_INIT(0);
> +
>  bool is_vmalloc_addr(const void *x)
>  {
>         unsigned long addr = (unsigned long)kasan_reset_tag(x);
> @@ -1574,7 +1576,6 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
>         struct vmap_area *va;
>         unsigned long freed;
>         unsigned long addr;
> -       int purged = 0;
>         int ret;
>         BUG_ON(!size);
> @@ -1631,23 +1632,22 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
>         return va;
>  overflow:
> -       if (!purged) {
> +       if (atomic_long_read(&vmap_lazy_nr)) {
>                 purge_vmap_area_lazy();
> -               purged = 1;
>                 goto retry;
>         }
>         freed = 0;
>         blocking_notifier_call_chain(&vmap_notify_list, 0, &freed);
> -       if (freed > 0) {
> -               purged = 0;
> +       if (freed > 0)
>                 goto retry;
> -       }
> -       if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit())
> +       if (!(gfp_mask & __GFP_NOWARN)) {
>                 pr_warn("vmap allocation for size %lu failed: use vmalloc=<size> to increase size\n",
>                         size);
> +               printk("-> alloc %lu size, align: %lu, vstart: %lu, vend: %lu\n", size, align, vstart, vend);
> +       }
>         kmem_cache_free(vmap_area_cachep, va);
>         return ERR_PTR(-EBUSY);
> @@ -1690,8 +1690,6 @@ static unsigned long lazy_max_pages(void)
>         return log * (32UL * 1024 * 1024 / PAGE_SIZE);
>  }
> -static atomic_long_t vmap_lazy_nr = ATOMIC_LONG_INIT(0);
> -
> 
> 
> But that didn't help at all. That system is crazy:
> 
If an allocation fails, the next step is to drain outstanding vmap
areas. So a caller does it from its context and then repeat one more
time and only after that a fail message is printed.

>
> # lspci | wc -l
> 1117
> 
So probably you need a lot of modules in order to fully make functional your HW :)

> 
> What I find interesting is that we have these recurring allocations of similar sizes failing.
> I wonder if user space is capable of loading the same kernel module concurrently to
> trigger a massive amount of allocations, and module loading code only figures out
> later that it has already been loaded and backs off.
> 
If there is a request about allocating memory it has to be succeeded
unless there are some errors like no space no memory.

>
> My best guess would be that module loading is serialized completely, but for some reason,
> something seems to go wrong with a lot of concurrency ...
> 
lazy_max_pages() depends on number of online CPUs. Probably something
related...

I wrote a small patch to dump a modules address space when a fail occurs:

<snip v6.0>
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 83b54beb12fa..88d323310df5 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -1580,6 +1580,37 @@ preload_this_cpu_lock(spinlock_t *lock, gfp_t gfp_mask, int node)
 		kmem_cache_free(vmap_area_cachep, va);
 }
 
+static void
+dump_modules_free_space(unsigned long vstart, unsigned long vend)
+{
+	unsigned long va_start, va_end;
+	unsigned int total = 0;
+	struct vmap_area *va;
+
+	if (vend != MODULES_END)
+		return;
+
+	trace_printk("--- Dump a modules address space: 0x%lx - 0x%lx\n", vstart, vend);
+
+	spin_lock(&free_vmap_area_lock);
+	list_for_each_entry(va, &free_vmap_area_list, list) {
+		va_start = (va->va_start > vstart) ? va->va_start:vstart;
+		va_end = (va->va_end < vend) ? va->va_end:vend;
+
+		if (va_start >= va_end)
+			continue;
+
+		if (va_start >= vstart && va_end <= vend) {
+			trace_printk(" va_free: 0x%lx - 0x%lx size=%lu\n",
+				va_start, va_end, va_end - va_start);
+			total += (va_end - va_start);
+		}
+	}
+
+	spin_unlock(&free_vmap_area_lock);
+	trace_printk("--- Total free: %u ---\n", total);
+}
+
 /*
  * Allocate a region of KVA of the specified size and alignment, within the
  * vstart and vend.
@@ -1663,10 +1694,13 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
 		goto retry;
 	}
 
-	if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit())
+	if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit()) {
 		pr_warn("vmap allocation for size %lu failed: use vmalloc=<size> to increase size\n",
 			size);
 
+		dump_modules_free_space();
+	}
+
 	kmem_cache_free(vmap_area_cachep, va);
 	return ERR_PTR(-EBUSY);
 }
<snip>

it would be good to understand whether we are really run out of space?
Adding a print of lazy_max_pages() and vmap_lazy_nr would be also good.

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0bs97aVCH7SOqwX%40pc638.lan.
