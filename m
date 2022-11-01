Return-Path: <kasan-dev+bncBAABBMMPQKNQMGQEYYYXVDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 36F8961435B
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Nov 2022 03:43:05 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id u11-20020a6b490b000000b006bbcc07d893sf9740824iob.9
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Oct 2022 19:43:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667270577; cv=pass;
        d=google.com; s=arc-20160816;
        b=uBxGnMEfDrPBsPx/7Jktg2+y9u+tKOd6BlQxaYMq+gLBrbbwi4y7zu896oSysri41J
         UJxka27U93SI/FHitKFtzQlyytvi6qih40B/OnJ2TIHy37tyPGkCknMs70rUt0jWf+sg
         3k9RyJcTmI4ujlS/W0ztRONhxk0C5OG0nnaDVYoXnAwbsM4l1mT/CCIMenEUJiQoGFka
         4YFBrlYyFe/qxeWuK+YA1DvxQVuWti7s1bw3X8UPb076ZQ6AWt4wTe4yFOXuSuPl27YS
         5a10MKAmjLe9mmsgIlO3kr4eZnYhiPBLqPSwBmnSD4V4SPmDPT4WVgOaADXZTRLU0b1J
         nQHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=is/9HhbT8i9Wdu02RKpXh+SSOnDv58+A9NtSyc1yu9k=;
        b=q5WW5XurZK6oueNCu5Ef1PHPIfJtvDfseHC4nYQxgKnh3pSZ4Sg3xjFthwMEkEUvxb
         Z/YistFSHDLQm82TZRlSS3YF7h5cYjFFkl48T6CE90h0OD6iK3JjGBtnX4QmYJveEuda
         2rzewFBVGunHmUd3RqscH/h8OiuVqw8wjJfhpQBA8TsKDqw+4Lyot2KkT/3vA2dKsXHI
         r+ScP9plXCh6WvqOD2sf89m+df+l8HqRh0R5Hw32WSi8MO5geSBeYOwkuI7/7NaBcXx6
         2bwqUpFFAMFwVXXrYFlf7Z8cCxmswmismUR2A1WO7YDFo2LmkXSHi+/KBuOeqcfUxRz0
         xbGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@fastmail.com.au header.s=fm3 header.b=TLdlHt4n;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=Htik0XU8;
       spf=pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 66.111.4.26 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=is/9HhbT8i9Wdu02RKpXh+SSOnDv58+A9NtSyc1yu9k=;
        b=aC/Rtky8d2Wpcdu7gvtAjIuYlFOHBTGfj1qN21kJ+KWL7sJJaZT3N6nFes40Ds16VK
         DhoSx3y3tJmhkXTCM5e6+FzVZGQjNe6fT9R50dhsFMg6cTLPvP9GhAdHYE7XxQ5HiTOm
         e0Gf3vbzHlY2QhNn4DscWdHO2vnNyKh+Vw0w/RJacnES+uX31N7o+3foHef9h/FVUejm
         yaateV5OVwXyx0p6jT0c+MMpN5dP8Ih4Kszd78XgzhoH0HojQkjOVteNqO6vuKi26PY5
         6RLWFT3vBs1E8LniVJwakLoJAff++FLKRAFpBS+rDcFAkQO01dkQprfOsa8z2Moan1L7
         RJMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=is/9HhbT8i9Wdu02RKpXh+SSOnDv58+A9NtSyc1yu9k=;
        b=S/c0pjiXxvmItpX2SbSqGJPjxQ5FlrTowB2tKI89O7gsjTWe2yVbq2pFMmGozbKOKm
         nh+84+UhrYsM43myAZUBsj6XbhIYp1nBdaFySyyt0WZtCbD5H3/ZwsKvN9gwoBYrIlvy
         vvCHHSqSyTsLcvvmjdKHs0F1PTENBZLHDOmmzc1kGIFlkIIP18h8Z2sW6Oan3tZZtzRq
         6BHlOQ76mkFdcd+iVNu1/XPt+9mpQ3/k6W254A63T9c8tlkKJAUzmP1H3YjMNLHdADn2
         LWmCO5hFkB53vAVQGutM1eZftqP+B+VeK4+HoM8A34cGWf25MQ7E/RyQT6jEqkopWTmO
         Xefg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1aZiz76vm+JCOkVHkB0LOeoC3sydiIZve49FB3QHCJcZ2kcRRa
	h2K00OXkz7W7O3QNamZqjrE=
X-Google-Smtp-Source: AMsMyM7qfeq1L1WKjEfcq7SYYajoiaf9zKa4AtoKkqFjdejRFF8nggaQHjNMeBmNaghvwHke3tTfWw==
X-Received: by 2002:a92:cb44:0:b0:300:97b6:28ae with SMTP id f4-20020a92cb44000000b0030097b628aemr8111195ilq.234.1667270577593;
        Mon, 31 Oct 2022 19:42:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:df3:b0:2ff:8169:470 with SMTP id
 m19-20020a056e020df300b002ff81690470ls2061292ilj.2.-pod-prod-gmail; Mon, 31
 Oct 2022 19:42:57 -0700 (PDT)
X-Received: by 2002:a92:a00c:0:b0:2e9:a556:8939 with SMTP id e12-20020a92a00c000000b002e9a5568939mr9104317ili.50.1667270577068;
        Mon, 31 Oct 2022 19:42:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667270577; cv=none;
        d=google.com; s=arc-20160816;
        b=Qs8/Zf6p3UmYRBlJv04NJN+FWOh6Lbb1vWQyhLuW6DPseBXyckxxg93QYnCtaczfhl
         qZLXxz70NfJLCxBdARrA6sNq+P8f483aPTCfOgjWqHRZIorr+mxH6RKBQj9mpZB9z+94
         WiFF5s61YwzpvlKDWuBCP142Q/vwErbyFtxKPIa6mdNl9ltXlSAuKoUzB9zeUoNITarV
         zBgfBU6jzD+lla/x5FyiSo5B82cImvowJm6DFk/0YHN5XxbTbWdfCnI6ov2pVfQKsBJV
         TKamrhNaF4ZV9WDUMQPCa4VvZYbclsDJc7OZrAffU1WoDY/5j9RMgoNkyXZrK8B+t3TG
         jxWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=/dwKm9SsHVF+uc6H4cCJSM/BggzQOsC1bv5VwAzfx5w=;
        b=JRQ04kRTF3mZ6xCOV9OnVoZ9oLZV9QbcBYw54lT9FWv8KZnZ7UyEu88wdRuCQLvmej
         dJIjkgSjylvFofON+I7kg7f5SLEhTX3vIyw7EJRAX8+jEUfwvfSycm04Dc2JiEUyeeBm
         PERDjUZOxYRWvnD4/SXxiKJg/RES6UsbKUgktvc2vVECFZ7YNiNCrc/3ioc4574v+GRV
         zCjabvn0vgJD18Fsvd2b7P45XOKOJ0HWBdHoxxssk73J5Ac4x/2lMT1eWFA6li1qDV3p
         4zOjVIj8zCepJIwwSZ+umAHHdLr9/HcfDyFeU9/4ffVjS6mepc5vD4HHFIR7nVzmukdd
         3dxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@fastmail.com.au header.s=fm3 header.b=TLdlHt4n;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=Htik0XU8;
       spf=pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 66.111.4.26 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
Received: from out2-smtp.messagingengine.com (out2-smtp.messagingengine.com. [66.111.4.26])
        by gmr-mx.google.com with ESMTPS id l10-20020a92d94a000000b002f93f7596c4si367182ilq.4.2022.10.31.19.42.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 31 Oct 2022 19:42:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 66.111.4.26 as permitted sender) client-ip=66.111.4.26;
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailout.nyi.internal (Postfix) with ESMTP id 5ACD65C00CD;
	Mon, 31 Oct 2022 22:42:56 -0400 (EDT)
Received: from imap46 ([10.202.2.96])
  by compute5.internal (MEProxy); Mon, 31 Oct 2022 22:42:56 -0400
X-ME-Sender: <xms:r4dgY_bJ1KJuRJjGxL5d2A1xbcMAQY-ZyYw6m5gSovZFnxeEQfbncQ>
    <xme:r4dgY-Ydy0wW6Fcg7Isc_xSmKcXaAQXICu6vFo4n5WpfHenG1TTai1ptkS30f14CW
    goqIAG_HPY6J2QQ7A>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvgedrudeggdehudcutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenuc
    fjughrpefofgggkfgjfhffhffvvefutgesthdtredtreertdenucfhrhhomhepfdflohhh
    nhcuvfhhohhmshhonhdfuceolhhishhtshesjhhohhhnthhhohhmshhonhdrfhgrshhtmh
    grihhlrdgtohhmrdgruheqnecuggftrfgrthhtvghrnhepkeefhffguddtgeegjedtvedt
    vddvkeevvdehfeehieejhffhhfejkeejgfelveegnecuvehluhhsthgvrhfuihiivgeptd
    enucfrrghrrghmpehmrghilhhfrhhomheplhhishhtshesjhhohhhnthhhohhmshhonhdr
    fhgrshhtmhgrihhlrdgtohhmrdgruh
X-ME-Proxy: <xmx:r4dgYx-3wCqeEnC193H4AU_rM8kJGYOZK-LASIRiBJCWRlfU2AAXQQ>
    <xmx:r4dgY1o-C1CZzeI_jHgsDJJXr--Hep3Qq0ngZQO_BTKnmXNF5jzPyQ>
    <xmx:r4dgY6osCvI8vH-fIgn5PS-JyBEd4uziuvu1b7USSv2CXZENXTeUxA>
    <xmx:sIdgY9-75UVaJPCJLVIZXwEcZ6OcwmYiHX-VDM2UfA9_xQEEjybcCg>
Feedback-ID: if0294502:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id 0E03D2A20080; Mon, 31 Oct 2022 22:42:54 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.7.0-alpha0-1087-g968661d8e1-fm-20221021.001-g968661d8
Mime-Version: 1.0
Message-Id: <00ce752c-17e0-4813-afa3-fe1510545b23@app.fastmail.com>
In-Reply-To: <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-2-feng.tang@intel.com>
 <becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com>
 <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz> <Y180l6zUnNjdCoaE@feng-clx>
 <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
 <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
Date: Tue, 01 Nov 2022 02:41:45 +0000
From: "John Thomson" <lists@johnthomson.fastmail.com.au>
To: "John Thomson" <lists@johnthomson.fastmail.com.au>,
 "Feng Tang" <feng.tang@intel.com>
Cc: "Vlastimil Babka" <vbabka@suse.cz>,
 "Andrew Morton" <akpm@linux-foundation.org>,
 "Christoph Lameter" <cl@linux.com>, "Pekka Enberg" <penberg@kernel.org>,
 "David Rientjes" <rientjes@google.com>,
 "Joonsoo Kim" <iamjoonsoo.kim@lge.com>,
 "Roman Gushchin" <roman.gushchin@linux.dev>,
 "Hyeonggon Yoo" <42.hyeyoo@gmail.com>, "Dmitry Vyukov" <dvyukov@google.com>,
 "Jonathan Corbet" <corbet@lwn.net>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Hansen, Dave" <dave.hansen@intel.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 "Robin Murphy" <robin.murphy@arm.com>, "John Garry" <john.garry@huawei.com>,
 "Kefeng Wang" <wangkefeng.wang@huawei.com>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of kmalloc
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lists@johnthomson.fastmail.com.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fastmail.com.au header.s=fm3 header.b=TLdlHt4n;       dkim=pass
 header.i=@messagingengine.com header.s=fm3 header.b=Htik0XU8;       spf=pass
 (google.com: domain of lists@johnthomson.fastmail.com.au designates
 66.111.4.26 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
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


On Tue, 1 Nov 2022, at 00:18, John Thomson wrote:
> I may have got lucky. it appears as though this is all I need to boot:
> (against 6.1-rc3), and with the Bootlin toolchain. Will test my other 
> build system as well.
>
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3276,7 +3276,7 @@ static void *__slab_alloc(struct kmem_cache *s, 
> gfp_t gfpflags, int node,
>         c = slub_get_cpu_ptr(s->cpu_slab);
>  #endif
> 
> -       p = ___slab_alloc(s, gfpflags, node, addr, c, orig_size);
> +       p = ___slab_alloc(s, gfpflags, node, addr, c, 0);
>  #ifdef CONFIG_PREEMPT_COUNT
>         slub_put_cpu_ptr(s->cpu_slab);
>  #endif

Tested that with and without SLUB_DEBUG


Testing without SLUB_DEBUG below:
With this change on 6.1-rc3:
diff --git a/mm/slub.c b/mm/slub.c
index 157527d7101b..5fdb7609bb9e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3410,6 +3410,8 @@ static __always_inline
 void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
                             gfp_t gfpflags)
 {
+
+       pr_warn("SLUB: __slab_alloc from slab_alloc s->object_size=%d\n", s->object_size);
        void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
 
        trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);


UART & boot stops here:
transfer started ......................................... transfer ok, time=2.00s
setting up elf image... OK
jumping to kernel code
zimage at:     80B842A0 810B4BE4

Uncompressing Linux at load address 80001000

Copy device tree to address  80B80EE0

Now, booting the kernel...

[    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binutils) 2.39) #34 SMP Tue Nov  1 12:33:10 AEST 2022
[    0.000000] Overriding previously set SMP ops
[    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
[    0.000000] printk: bootconsole [early0] enabled
[    0.000000] CPU0 revision is: 0001992f (MIPS 1004Kc)
[    0.000000] MIPS: machine is MikroTik RouterBOARD 760iGS
[    0.000000] Initrd not found or empty - disabling initrd
[    0.000000] VPE topology {2,2} total 4
[    0.000000] Primary instruction cache 32kB, VIPT, 4-way, linesize 32 bytes.
[    0.000000] Primary data cache 32kB, 4-way, PIPT, no aliases, linesize 32 bytes
[    0.000000] MIPS secondary cache 256kB, 8-way, linesize 32 bytes.
[    0.000000] Zone ranges:
[    0.000000]   Normal   [mem 0x0000000000000000-0x000000000fffffff]
[    0.000000]   HighMem  empty
[    0.000000] Movable zone start for each node
[    0.000000] Early memory node ranges
[    0.000000]   node   0: [mem 0x0000000000000000-0x000000000fffffff]
[    0.000000] Initmem setup node 0 [mem 0x0000000000000000-0x000000000fffffff]
[    0.000000] percpu: Embedded 11 pages/cpu s16064 r8192 d20800 u45056
[    0.000000] Built 1 zonelists, mobility grouping on.  Total pages: 64960
[    0.000000] Kernel command line: earlyprintk=ttyS0,115200 console=ttyS0,115200 rootfstype=squashfs,jffs2
[    0.000000] Unknown kernel command line parameters "earlyprintk=ttyS0,115200", will be passed to user space.
[    0.000000] Dentry cache hash table entries: 32768 (order: 5, 131072 bytes, linear)
[    0.000000] Inode-cache hash table entries: 16384 (order: 4, 65536 bytes, linear)
[    0.000000] Writing ErrCtl register=00011146
[    0.000000] Readback ErrCtl register=00011146
[    0.000000] mem auto-init: stack:off, heap alloc:off, heap free:off
[    0.000000] Memory: 246284K/262144K available (7417K kernel code, 630K rwdata, 1304K rodata, 3500K init, 245K bss, 15860K reserved, 0K cma-reserved, 0K highmem)
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: HWalign=32, Order=0-3, MinObjects=0, CPUs=4, Nodes=1
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=32
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=132
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=300
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] rcu: Hierarchical RCU implementation.
[    0.000000] 	Tracing variant of Tasks RCU enabled.
[    0.000000] rcu: RCU calculated value of scheduler-enlistment delay is 10 jiffies.
[    0.000000] NR_IRQS: 256
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] rcu: srcu_init: Setting srcu_struct sizes based on contention.
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=512
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=512
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=256
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=256
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=256
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=128
[    0.000000] clocksource: GIC: mask: 0xffffffffffffffff max_cycles: 0xcaf478abb4, max_idle_ns: 440795247997 ns
[    0.000000] SLUB: __slab_alloc from slab_alloc s->object_size=256
[    0.000004] sched_clock: 64 bits at 880MHz, resolution 1ns, wraps every 4398046511103ns


This change, and kernel boots fine:

diff --git a/mm/slub.c b/mm/slub.c
index 157527d7101b..e9677c04d19c 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3410,7 +3410,11 @@ static __always_inline
 void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
                             gfp_t gfpflags)
 {
-       void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
+
+       /*
+       pr_warn("SLUB: __slab_alloc from slab_alloc s->object_size=%d\n", s->object_size);
+       void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);*/
+       void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, 0);
 
        trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
 


Cheers,

-- 
  John Thomson

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/00ce752c-17e0-4813-afa3-fe1510545b23%40app.fastmail.com.
