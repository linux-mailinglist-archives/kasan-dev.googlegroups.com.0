Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2572GFAMGQET5RGTLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F87141C4EB
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 14:45:33 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id d16-20020a17090ab31000b0019ec78322c9sf1782346pjr.5
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 05:45:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632919532; cv=pass;
        d=google.com; s=arc-20160816;
        b=zHk9uEc8A9PsQFev0ixFJ97rksyXsvFpms8rZgZFS1MWXpXZfM72y4Bslml4/6/iqW
         4EaBLPRLQxGB+hJojqWtq2gZ9OhOl2hXNz9iRO/+9w/VpLs24j0GLh0XUoG6QrDY4FAG
         jMqhMkfmddOjNOsRfy3mVog1QVD1WmEYzExYN1Nw8JXNR5UsVFEwpBCL+fgcKHFZMVR4
         ftpJ4JZhNEUO5KIUrxIJcqQSEIuslTUENJZeiAkS53J+1qs3oqfWN4wvVeQfY45//cXc
         B6MN/7QqBtKerHYKB+sDk4g/qEmHst8fxof+5aDJqb/gyquu0CFgiDaungmgNgOKXv7j
         W6Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0npWITIdLK4J0gZz79bE8Bs0TzMLrzXBO7APBrFdnvM=;
        b=qbV1tA/WlOZhJFh/Ji7N49L9Vi0aaz35K64Ls46sHjs36mMQPX4oUtKlcnjOJX6E1o
         NJzT1npszc925VG1fnJDTY+ImhCrw+ztSWgtt8eGBcrPz4C886f1EIwd/6fqpxX7X/nG
         jtZQgOxIt0QC0fd3eTqa4hKPZAhZ+EVOMBV5r/OLGueD1B+98ZuGb1Hh2W58rwWuCw+/
         LrW80qeuOzj3GVVTmEmbv+VaWgee3ES2Kl4ljyvLSzxqrpgW3OBtzKOf9m8kxXhdlXBe
         fKweBtjfru1COAHt3A4ZVpeI5EMg84/nn3kUCP85wakGv2p09mkK+9zWIZ6aZiBrsfdW
         J7zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lRVpwkBQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0npWITIdLK4J0gZz79bE8Bs0TzMLrzXBO7APBrFdnvM=;
        b=kjfUYcPFpsmzY67faLjajS1LKNa3BgKzsprZsJ64+3Qn4/rHZ2qJO8Mm5yDAztYCcm
         LLcxuiYd/PRr1q3Qg6LRh+n0mr1IwtuzgRkCcOfJIZ+1ez/XujfJYnSyMGeW5uFzPj37
         Jz8O//BBmjW3POcgYExFyCRgKBF3TNcs7eeR+/hbB3jySEGbXL3EZWbvnyz7A1xJ+akq
         xcnxfh1PoN2DNYZHyHQhVRHIuWc6HDfo/6240reikDn+Wd/DEg/LWJ3mT0aQlWhO1mnr
         kghCVR8oEbTM7e0Ml2jqt2M9NHXnB4pw9oXBdXfItxnnSG40GPR8BcliO+I0zSnUijuu
         BIrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0npWITIdLK4J0gZz79bE8Bs0TzMLrzXBO7APBrFdnvM=;
        b=SG1ITUyZXUulmetfkRXft89QRExVe9MstTiGrBHyCOjwYR5ENuewT8PPDP9OUEcNl8
         HDDuym2SHKYdRewGKchrteD59UamjftltD/QjC+zDpwZ+r9vM1Mrr1DVbYCk7W5XWMOn
         30/RRkHIj2HTiMyFb5ekt7c5W5mbbiYeaz/dxkoGJGXiH7f/XwjblsHG797yOTbrPU8f
         HLdaNyA7PgJKAgFWoa77gGpo/wupEhHnMpseZRTfezosz+tumpqE2bJQl/geHnWXYWLe
         Jv13QiCqo5xBbifHcayySrM4lIyMkqFtAD/AHjeRBro7OzwnQP2TqUkIiNJpRP+YBVZj
         dIHw==
X-Gm-Message-State: AOAM531Q4ORRWdXFvw0frdbFJH6KWqSSocsFWaUPG3rsjQFe2QOuq6HC
	+d9o0txYfyTIqhzc4pUU+iQ=
X-Google-Smtp-Source: ABdhPJwOzv7sTyXTm0czimdv+3vah988Wz8HqmhvmtN1aZB6rbKX797MgMEG24CqqnNFtr3cB2bmvw==
X-Received: by 2002:a17:90b:3797:: with SMTP id mz23mr6125061pjb.216.1632919531842;
        Wed, 29 Sep 2021 05:45:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9ece:: with SMTP id r14ls135433pfq.11.gmail; Wed, 29 Sep
 2021 05:45:31 -0700 (PDT)
X-Received: by 2002:a63:585c:: with SMTP id i28mr2277115pgm.70.1632919531205;
        Wed, 29 Sep 2021 05:45:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632919531; cv=none;
        d=google.com; s=arc-20160816;
        b=W0XcOMvvCQ9IdWpgIIGpBjsAcC2osb0mh2xUPNmkv9BhLGvbpIEsJNFDM1L0mJ1tjE
         cU/pJXU8P2So5JfwS4TADPWfc5AxnWkhtwvoZ4A3p4B+1beSU8R1CawInxHF9yBkyWTs
         ojFlOGXobyByi2j0RPMIj5616c50Zr/Ez3tCirxmn/gA2rv1UE/awXJF+zHzvBwB4KoG
         q7qD6dw7vranePDlo7UALqkJckQRo62C7MGoPRBLwkExlzWuOz1sAer7ROxsHCn/rdMR
         JuavegaSGC+/D5PvPR8x2Nippl6l9kLAlG8qamrwCuZr9HXwBqKlx/ILLrUA3i9K1OVn
         B5og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TDNN1kFSC/fnkpvN4FxxnnuhSeRYTwee8Iq2doyYjYU=;
        b=gW0eIzNknpO3r8gS9CKP6xSJTX2MWjVuGbzahyQNd+JZdId8zHEIDOBSgAzUVOjjxC
         Oc3jba69L4WITDoFwTUpCXsEcBZ3FJAFWaTstgRi/txGZyjF/Ee1KLm6VFgHOOyZYWpx
         Y/aK5Jt1OI4Z4nH5q0YtOSI0J8pPnWek3gt4NgvJNkCPCpuBywMYK0KwqHRT/Zl/jGSv
         NTKBCnSDNyFPEvEv5VzHXtYkGt66+eRsZQgaXcuBQeezGaT6cZwKYn3ZRJN0rz/WGNVj
         +BZzipW2N4q3MetLUeRwGTkxObRF6p4jLgrVUAcl51RImFcsab6WI153//cf0VSgoZ7E
         00uA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lRVpwkBQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id m1si912267pjv.1.2021.09.29.05.45.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Sep 2021 05:45:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id d12-20020a05683025cc00b0054d8486c6b8so2745228otu.0
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 05:45:31 -0700 (PDT)
X-Received: by 2002:a9d:135:: with SMTP id 50mr9862599otu.295.1632919530692;
 Wed, 29 Sep 2021 05:45:30 -0700 (PDT)
MIME-Version: 1.0
References: <20210929234929.857611-1-yanjun.zhu@linux.dev> <YVRfQDK0bZwJdmik@elver.google.com>
In-Reply-To: <YVRfQDK0bZwJdmik@elver.google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 Sep 2021 14:45:19 +0200
Message-ID: <CANpmjNMKCmEHUnKz5rdUkd1HSuLj_S_vaMu+Hr7MuB79ghMERA@mail.gmail.com>
Subject: Re: [PATCH 1/1] mm/kasan: avoid export __kasan_kmalloc
To: yanjun.zhu@linux.dev
Cc: ryabinin.a.a@gmail.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lRVpwkBQ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 29 Sept 2021 at 14:42, Marco Elver <elver@google.com> wrote:
>
> On Wed, Sep 29, 2021 at 07:49PM -0400, yanjun.zhu@linux.dev wrote:
> > From: Zhu Yanjun <yanjun.zhu@linux.dev>
> >
> > Since the function __kasan_kmalloc is only used in kasan module,
> > remove EXPORT_SYMBOL to this function.
>
> This is incorrect, see below.
>
> > @@ -521,7 +521,6 @@ void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object
> >  {
> >       return ____kasan_kmalloc(cache, object, size, flags);
> >  }
> > -EXPORT_SYMBOL(__kasan_kmalloc);
>
> Sorry, but this will break all users of kmalloc() with KASAN on if
> !TRACING:

*module users.

An allmodconfig but with CONFIG_TRACING=n will probably show you the problem.

>         __always_inline kmalloc() include/linux/slab.h
>          -> __always_inline kmem_cache_alloc_trace() include/linux/slab.h
>           -> __always_inline kasan_kmalloc() include/linux/kasan.h
>            -> __kasan_kmalloc() mm/kasan/common.c

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMKCmEHUnKz5rdUkd1HSuLj_S_vaMu%2BHr7MuB79ghMERA%40mail.gmail.com.
