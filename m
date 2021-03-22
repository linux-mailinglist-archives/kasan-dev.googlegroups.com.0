Return-Path: <kasan-dev+bncBCY5VBNX2EDRBHEQ4CBAMGQEQS7P5NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C32FF3436EB
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 03:59:41 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id 131sf14301012vkz.2
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Mar 2021 19:59:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616381980; cv=pass;
        d=google.com; s=arc-20160816;
        b=pQIHhho/c17aijw6QH8JefHvbYKQKJU1mh3YEjSHmLWdVxHfF7D1DkD6HQV80wvMSo
         yYzob4Zn7B7QwVvaT3t2jAP9p/NRUlYRfDB2Y130/OBL0BkkFVJ7LFWXznUckeHcLpcL
         hS+tKltQ3iwL4PQEAoBBtr8BDG0QaXY62joQgsfRJFkarBNF1exaLFMaNlGojSESeJ25
         DsUS5TKSOybbyGDrJlkaOnCd2h7c5yfEAInWdKKWUElPMiXOpjL9QxHDeJyBJiAFImYM
         ErpfYb0QHFCvGtSpMYx/UDNrgvhFVWRvHinDKzIiGbWQWP4qTulWe5GW03dTiwQC/aVv
         Albg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=/trtQ+JKnV3aD8lW8UX3hbaRdGJjidBGQMt0SPG19Bk=;
        b=FF3oab2R8n+AcZPEFyWYs1pNJ0cc7EgIR7Nb3iYqfRuJyOkKI/DAHpWhwZv2b2v/G+
         4+cLV8gXj/ujjR/dXNLAJo0VCkURFJwpqEoCetvq3jpsDBHo6yGUBQbVOwuCq6oDwAQ+
         ZH08iapJM567gCn8huA4oA+YGeQ2ORGecTLkDK+DhBHBt4xELpIS26M33uZ3FZZDp60E
         eofuLvg/+NOJdP37QQt5ejIRO51MXZagVfdW5a67ENDkzF+JXC0DiB6MnrMyabf2Manb
         CdHzaRkzeY2SDfS3y+FeuZWnCegYbm65Znl9vO9262ttfTYpDbvW20ob9NCodPKeKsgC
         B1bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=KeQ2EZhF;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/trtQ+JKnV3aD8lW8UX3hbaRdGJjidBGQMt0SPG19Bk=;
        b=aLNUjIKJ2Y7bGR1oXGZJI669Yjdyw/vVnYtJQP1ad1Ewbn6iQ0Qv5x4B1erikHI4cP
         GUVkWw13V3p1k7DP0jwQiDflk1ux28RKTXo787GFBKGQWhYikzxFiZoSEUS/180yktvK
         jXdDauUaK640ArVSrBnYV2vpTmoFEjYtM43YZ4AzJvxUnlKJVhDoxYiFPMR5bEgphFKk
         ujbVSyAKQz+OufIU4EBLyLOzGgnisUKrqC2LDqOsIS+8TcRm8IqIYcKrP2QE5PE3oB3L
         gITA5OBE1Z/EK52+69FcVckg3roTID8Z6wIS/RrVL/4Fa7lozfeogN3FQFFGMfGDNywg
         YYww==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/trtQ+JKnV3aD8lW8UX3hbaRdGJjidBGQMt0SPG19Bk=;
        b=m0ZSU+P9J0Yeg71RINZvvxtec8gmFWlWF6jCBni/aQ1ZpjKrfllvVAqIDf/iMRC8n8
         28UnmEyDMkxjjUptqhWB2PQem+1HNq+GLhk5d1dQqlJY7vV25RQvRTaJRl2LoBuTQ72V
         ioWOb72u5KLuS5qgvsQWn4Wn94EtuMkSpebz7KzPF/NNc6TU5TrNloahrm8sUc4Gr89t
         tuDA67pqEAPzTsMF2vTUcTls79LsxxYy888p6Hd816q8DWJAXvNa83pwQ+NocxENc5mt
         0cNU6azXOgSj5sBjwBKPWo2VS7c/KDHGxoAXVRgWmCzE8PU0nMjXXlifu9WR97OvFraF
         iQ7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/trtQ+JKnV3aD8lW8UX3hbaRdGJjidBGQMt0SPG19Bk=;
        b=h44B9CgZyp4fTru3xyeZ61Yf8cVcj9sGxt+QU+IP1QQHORxTy1UHwNIRfJ2IjG+/Ds
         wawM9Ir0kHUIb7r4tLI0X5N4s+zKJpVYR1AMgGKKVy91HbaXlOQgb/cUgvCpbZVaTeOA
         DiQWU37BWM73JUfsvGrBxYmTTNT8x7WGgz2IF9w4ZsfqPUDyhEL9twR7V5zpm+8VpX+n
         ifqRNWpK7jIg6dSEic64AbKmkATmaDy8m8GHPOnoH6yep7YUcWrfnCKglb8wme4r7anH
         3dnLew5tK3zgS35l1gku+C6fg1DYodHl44eT57eLIe5Ezkq7SHYJuWK7NXGOo1+rt+UO
         V4cw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533sf+Ms2cj8TabXbTYiajwFKKq0fOVktDoE0SXy7JdjiAzBnCt+
	HEwXJ6MLXnkspyHSgecH8zQ=
X-Google-Smtp-Source: ABdhPJxvTN3Cvjun2SHL6GktKVYOJMpLCha38X8R/6b8uEFKXSAikmc4++5tIuWpxFXsr4ZD9d8G0A==
X-Received: by 2002:a1f:978e:: with SMTP id z136mr1848965vkd.17.1616381980640;
        Sun, 21 Mar 2021 19:59:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e9c2:: with SMTP id q2ls1274774vso.9.gmail; Sun, 21 Mar
 2021 19:59:40 -0700 (PDT)
X-Received: by 2002:a67:6916:: with SMTP id e22mr8073080vsc.32.1616381980156;
        Sun, 21 Mar 2021 19:59:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616381980; cv=none;
        d=google.com; s=arc-20160816;
        b=XOB+Y408j+SffE8Spfpf++yUccafqImTzs0lbz9vGz+ZmeWAYqoNmmvzRaX9189oR3
         yPn0FYCGlb9Q6szEXKVwGG2WU1g7+EL2UYVq3MuE7xe6/8/G+Nlvm5pVQcY9Pspb1e95
         io/kWSk2YrxVeoEoy+aACYwd27gvkV/7frus7uLNle++u2FyO34hm7I8R+iPNAa8o6pZ
         3mV6yGRXugAiOPhNi2FYm6vtJBhdwcKHhxu2a0Fm44GiX71IUg+jWCs5CEz4/CcQnEup
         rriYIocar80Lub4yIBiG2OVQDWRHAD6yqWfXtGPstzEM3+yS/VJVpRQiK2CsQ/+9MYbD
         gB5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8PSyfDnBNxdEv0JuzVsHXHjHmPcZoANyRQWH8adKcPU=;
        b=cfiGnQTJR6DdFJhzaYwmlwpCJ4iUaWH7yl0hGYqY9nrZPVMhdfdaEGSYPWdQ/8NUAw
         BieTum38FuP2Tsjoj+lslSS41Zuuv2xzbCKteZqr5OrmsKPGLad4iPSG2PZEc8PWA7Ri
         9LKpz3JQhOm9JuGrIiYyCXmuqNGs6l97y3Jgxu+HAHNA3D5OSf9nS7yTcn5viTodwgxH
         PoiCBUfnfBZLp9G/ABOIZWfUXIuyYIHEVkYJpHBDiFLgvjWi57GeNUaw87Jy5vUYYzhb
         bmJryLTJSkfPMf34KTrlqxuwtHvbwtee1ttFO08iVDUjGBbjeXxOFphzv12xBkZSmYnZ
         +71Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=KeQ2EZhF;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id i18si700827ual.1.2021.03.21.19.59.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 21 Mar 2021 19:59:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id x126so9980645pfc.13
        for <kasan-dev@googlegroups.com>; Sun, 21 Mar 2021 19:59:40 -0700 (PDT)
X-Received: by 2002:aa7:86d9:0:b029:1ff:275c:b67a with SMTP id h25-20020aa786d90000b02901ff275cb67amr19223972pfo.69.1616381979110;
        Sun, 21 Mar 2021 19:59:39 -0700 (PDT)
Received: from localhost (121-45-173-48.tpgi.com.au. [121.45.173.48])
        by smtp.gmail.com with ESMTPSA id mp19sm14599055pjb.2.2021.03.21.19.59.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 21 Mar 2021 19:59:38 -0700 (PDT)
Date: Mon, 22 Mar 2021 13:59:34 +1100
From: Balbir Singh <bsingharora@gmail.com>
To: Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu, aneesh.kumar@linux.ibm.com
Subject: Re: [PATCH v11 6/6] powerpc: Book3S 64-bit outline-only KASAN support
Message-ID: <20210322025934.GG77072@balbir-desktop>
References: <20210319144058.772525-1-dja@axtens.net>
 <20210319144058.772525-7-dja@axtens.net>
 <20210320060259.GF77072@balbir-desktop>
 <87o8fcatxv.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87o8fcatxv.fsf@dja-thinkpad.axtens.net>
X-Original-Sender: bsingharora@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=KeQ2EZhF;       spf=pass
 (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::432
 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Mar 22, 2021 at 11:55:08AM +1100, Daniel Axtens wrote:
> Hi Balbir,
> 
> > Could you highlight the changes from
> > https://patchwork.ozlabs.org/project/linuxppc-dev/patch/20170729140901.5887-1-bsingharora@gmail.com/?
> >
> > Feel free to use my signed-off-by if you need to and add/update copyright
> > headers if appropriate.
> 
> There's not really anything in common any more:
> 
>  - ppc32 KASAN landed, so there was already a kasan.h for powerpc, the
>    explicit memcpy changes, the support for non-instrumented files,
>    prom_check.sh, etc. all already landed.
> 
>  - I locate the shadow region differently and don't resize any virtual
>    memory areas.
> 
>  - The ARCH_DEFINES_KASAN_ZERO_PTE handling changed upstream and our
>    handling for that is now handled more by patch 3.
> 
>  - The outline hook is now an inline function rather than a #define.
> 
>  - The init function has been totally rewritten as it's gone from
>    supporting real mode to not supporting real mode and back.
> 
>  - The list of non-instrumented files has grown a lot.
> 
>  - There's new stuff: stack walking is now safe, KASAN vmalloc support
>    means modules are better supported now, ptdump works, and there's
>    documentation.
> 
> It's been a while now, but I don't think when I started this process 2
> years ago that I directly reused much of your code. So I'm not sure that
> a signed-off-by makes sense here? Would a different tag (Originally-by?)
> make more sense?
>

Sure
 
> >> + * The shadow ends before the highest accessible address
> >> + * because we don't need a shadow for the shadow. Instead:
> >> + * c00e000000000000 << 3 + a80e 0000 0000 0000 000 = c00fc00000000000
> >
> > The comment has one extra 0 in a80e.., I did the math and had to use
> > the data from the defines :)
> 
> 3 extra 0s, even! Fixed.
> 
> >> +void __init kasan_init(void)
> >> +{
> >> +	/*
> >> +	 * We want to do the following things:
> >> +	 *  1) Map real memory into the shadow for all physical memblocks
> >> +	 *     This takes us from c000... to c008...
> >> +	 *  2) Leave a hole over the shadow of vmalloc space. KASAN_VMALLOC
> >> +	 *     will manage this for us.
> >> +	 *     This takes us from c008... to c00a...
> >> +	 *  3) Map the 'early shadow'/zero page over iomap and vmemmap space.
> >> +	 *     This takes us up to where we start at c00e...
> >> +	 */
> >> +
> >
> > assuming we have
> > #define VMEMMAP_END R_VMEMMAP_END
> > and ditto for hash we probably need
> >
> > 	BUILD_BUG_ON(VMEMMAP_END + KASAN_SHADOW_OFFSET != KASAN_SHADOW_END);
> 
> Sorry, I'm not sure what this is supposed to be testing? In what
> situation would this trigger?
>

I am bit concerned that we have hard coded (IIR) 0xa80e... in the
config, any changes to VMEMMAP_END, KASAN_SHADOW_OFFSET/END
should be guarded.

Balbir Singh.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210322025934.GG77072%40balbir-desktop.
