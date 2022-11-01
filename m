Return-Path: <kasan-dev+bncBAABBHWKQONQMGQEWQWAJAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 19BCC614684
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Nov 2022 10:21:37 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id a3-20020a2eb163000000b00276fff42408sf5734413ljm.9
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Nov 2022 02:21:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667294495; cv=pass;
        d=google.com; s=arc-20160816;
        b=NbTB9F6ZLVsRJWn2dVa3NbCba1xx0Lwk5W4Uit1O/yQEQXiUw7bNgNfVe8Q/iK/2fq
         LrZUHpeJj2OgdZeabWfcOBwAKmAGFsBs3Qssrr0D1ALZCD4xwz0zK37/YpyZzd1IpdQo
         NBrPE0Ao3ONnl0pbgJhrDKe1XDIWPIYf4sf8uxZtHfD7pTv7DMuEi6DiGOT4Q/5i75Qt
         pq5srFi/xpEGwrxuIEVlzDNfkzDzrJqLTeV7zfMvJ0xtol8CEjWZ2PDGW+O7Nx6AM5Rk
         T8suZbgBbI33L53IM0YPtPsn5ga3fXLv2JZDwyYt4FF3Ccfy7XdjKrCUn4dbvoAkrblK
         K4tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=tPPdtI2x8d4USASwj91nVSHiD5s8pTWAGBtgaB21YpE=;
        b=bXPiVoByRHvpNXkQJRH852hUFWWP1tSf7LG2PzVzxKsgqCOEWAPJyDwb5GQWHw0g42
         vm/IOXsfxQTNj7J3WZv1YgXb0SaGQ0PMdEVi+aPkhP/IFcSFvY2p1nd3rl6+qoKcOcNp
         SMYuSDiK5EuPJJEAbziQeU165/jnSOAx4JcH+a8FR6WJYVct3N67VOdNsjcD3AWahYbM
         40+sCHf262JQRtYwOSKTWw/cwRxx3Q4KlVoJp1GAHHlsGfU7MaS0AHBOyd1vdMizbSMA
         2+vAb1zpPtlu+I6Atbcis4Lbio4S7LUkzlZnrDKJtw9x0lG7G7NZ915MAqSSVYKMn6Du
         oHNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@fastmail.com.au header.s=fm3 header.b=bmvYswt1;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=NWQ36jlq;
       spf=pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 64.147.123.24 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tPPdtI2x8d4USASwj91nVSHiD5s8pTWAGBtgaB21YpE=;
        b=jEY2Q/AbqP0LJAixaqDXs5ycbQfPmKX4jdCbdPSI2qQ6SMZvYHNGj96iprZiO7ztoQ
         gRBDC5vdm+uCISZJPLg4Y1eNg3Wj10Xw0LcO8cLyyDSUouCfIUQcizByYbc9ydHFtJr8
         4KjhKGPkAqutDrZN5asujFTMJIjVq6nTbNZAyWxGADj1GOxutCNpW0Skni15zodE93JH
         Avc837Wqsy3rhfB7xKjIxZoJq6azyKbjoWE+B9X034SKcjLtpEzrzRAJAJWSbeZ8ysQf
         YdT8D0Egasn1bczKWBqaHKmG8vIYsPVPiw8UmE541JJz3ZiUtHOMd3eETH43u0ilCawK
         hVOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tPPdtI2x8d4USASwj91nVSHiD5s8pTWAGBtgaB21YpE=;
        b=p87Hv+SiGaxK5Euz5IWhsX2p6yFSKErk9QkQy5xcN47PxD7EZR8dVYWNqNU/PY7IVV
         TuDXHgT84DbpVIRgPhagnBchD1uF068q47zGZ4F5Vvv90P+3ddXmZK4kgkN4OYh39lYD
         k7oMQORbHT7jh8XTJk65vbg10iRKjgs3a9bPBUkLvE+zAfHJle/fnh5PRNXWhNSq8PAG
         MlLxzyDrUJwsk+DOAx+2jdpjKzPePV1LcHzp2bVzHx/ciqNDTVrgD/V745YH6o0+KSIQ
         Lp9fTGYHN/oWAV1/NQ74TVkeVu9sqk5lx3gTOWTKO5uFXw1T4Kshof06ljyGzoROZj2R
         j2Xw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3EfhGWsQzZVACY/hGxIcZPztS5QA32WWTGJ0RZc0b5HhwXXene
	/SUOioDk281UOj0a6nDZwZ4=
X-Google-Smtp-Source: AMsMyM5jnIOCCqC+rVIFkeQCqEYKY8kQwZcadBNWvLzcR/0XPdLScEieT4ZmY5GMQy7eKZtoQOSNqA==
X-Received: by 2002:a2e:95d1:0:b0:277:a3d:6fb6 with SMTP id y17-20020a2e95d1000000b002770a3d6fb6mr602254ljh.514.1667294495135;
        Tue, 01 Nov 2022 02:21:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1511:b0:277:4af7:14ea with SMTP id
 e17-20020a05651c151100b002774af714eals1072326ljf.2.-pod-prod-gmail; Tue, 01
 Nov 2022 02:21:34 -0700 (PDT)
X-Received: by 2002:a05:651c:1047:b0:277:6939:e278 with SMTP id x7-20020a05651c104700b002776939e278mr562808ljm.522.1667294494038;
        Tue, 01 Nov 2022 02:21:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667294494; cv=none;
        d=google.com; s=arc-20160816;
        b=RGr2Ppo/mMpF7NxRPzGjDJIqQqRKjUTuRKk8JCXs5FS+fAhhR8i6ow1CyxKSGonZwo
         a08DEvlW/xLA+/C31yWtbbNjQI0ExxssJzoBKvILnBEnHQ5FCfmXO5gbSAIbALVtD43Y
         qkR7VjYhSjAcXIf9h+c+Xf856vBVtoD0I+sxqE+rgZxurdhnLZZcLeHEg72NdgOFqo06
         dhJZTADnnd1A+UJHu4S7Rf3++cxRI7FCbXuV1PaIRoVP/+8F4CTx2pqx4kY5oweLux3J
         BvN4vM26LghwIW/mnlduFc6H9LnwWI0rqu+tMy2F6bBTgJ2M3owTF1wylat2+h3l9Grs
         8kMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=DmXcbh9DqaxTidfPEVRhGG+9ZolCRC1Se1Rd95/vqz4=;
        b=enZiqKPkWU7aVN0hfxFymvMr57OwsVaY4LqueNPFEl2FYe/Mtu74eJu2HXXr9oAx8O
         rI90GgMQj6EDs09BgKvf1RdfGq6lupqNODFsht3aIiFZGErNuGUqhpCgM2VnYf6k77kW
         zTNcJt5C0usVgpBT4PGOWqRmfiHuFNz6yyizwrQXT7g9s7g2scKcNBzgxv06Qymi/Hu1
         ohdcFtCLQ1oaD+06hiQfvAAUWe7bThelFbborLzo/dDkWrRVAZVD014jjeXm/O6t1x1S
         nvSK6oGNGg/Jk2d1vtDjfCqZh6YsjGSF4OcpM0AWXOa0NEwgAAtej7KgbokgkcjeHshH
         sS7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@fastmail.com.au header.s=fm3 header.b=bmvYswt1;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=NWQ36jlq;
       spf=pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 64.147.123.24 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
Received: from wout1-smtp.messagingengine.com (wout1-smtp.messagingengine.com. [64.147.123.24])
        by gmr-mx.google.com with ESMTPS id k27-20020a05651c10bb00b002776daa0487si29028ljn.2.2022.11.01.02.21.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Nov 2022 02:21:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 64.147.123.24 as permitted sender) client-ip=64.147.123.24;
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailout.west.internal (Postfix) with ESMTP id E8A4A32006F5;
	Tue,  1 Nov 2022 05:21:29 -0400 (EDT)
Received: from imap46 ([10.202.2.96])
  by compute5.internal (MEProxy); Tue, 01 Nov 2022 05:21:31 -0400
X-ME-Sender: <xms:F-VgYzUOYmWCzfhs9Y8mafW1xiYw3z3zlw0Yg1cpMpLWHEbFHn0R2A>
    <xme:F-VgY7nGVZp9MdbhwGh3T7gC-q7F-Z8X80u-6R267VcCfvEkTUOnzwsxa5OFTdUcC
    wK_E9mEvEXT8P-Lsw>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvgedrudehgddtvdcutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenuc
    fjughrpefofgggkfgjfhffhffvvefutgesthdtredtreertdenucfhrhhomhepfdflohhh
    nhcuvfhhohhmshhonhdfuceolhhishhtshesjhhohhhnthhhohhmshhonhdrfhgrshhtmh
    grihhlrdgtohhmrdgruheqnecuggftrfgrthhtvghrnhepjeejfeeilefgfedtkeekfeek
    ffegleetlefhheekleeggfdttdevveduheettefgnecuffhomhgrihhnpehkvghrnhgvlh
    drohhrghenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhm
    pehlihhsthhssehjohhhnhhthhhomhhsohhnrdhfrghsthhmrghilhdrtghomhdrrghu
X-ME-Proxy: <xmx:F-VgY_Yq_F4ld2wYsxpZkKbbvA8uCOSdLsMeaoaAijpuCS4_0AEPIQ>
    <xmx:F-VgY-W6ojN479ExDsA5xCkJtX3gwATcRzH4ftYW8UrnOoLGF30Yuw>
    <xmx:F-VgY9kVk02sOLPiLYKNuYIU-gw80TJ70Cg8I-uupaVumhV43og5eQ>
    <xmx:GeVgY8fHMBPdSwWodz6CdXqbUOVIcUiXxClLzUJDmuWLwMBUPgWtZw>
Feedback-ID: ia7894244:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id B42052A20080; Tue,  1 Nov 2022 05:21:27 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.7.0-alpha0-1087-g968661d8e1-fm-20221021.001-g968661d8
Mime-Version: 1.0
Message-Id: <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
In-Reply-To: <Y2DReuPHZungAGsU@feng-clx>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-2-feng.tang@intel.com>
 <becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com>
 <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz> <Y180l6zUnNjdCoaE@feng-clx>
 <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
 <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
Date: Tue, 01 Nov 2022 09:20:21 +0000
From: "John Thomson" <lists@johnthomson.fastmail.com.au>
To: "Feng Tang" <feng.tang@intel.com>
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
 "Kefeng Wang" <wangkefeng.wang@huawei.com>,
 "Thomas Bogendoerfer" <tsbogend@alpha.franken.de>, linux-mips@vger.kernel.org
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of kmalloc
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lists@johnthomson.fastmail.com.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fastmail.com.au header.s=fm3 header.b=bmvYswt1;       dkim=pass
 header.i=@messagingengine.com header.s=fm3 header.b=NWQ36jlq;       spf=pass
 (google.com: domain of lists@johnthomson.fastmail.com.au designates
 64.147.123.24 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
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

On Tue, 1 Nov 2022, at 07:57, Feng Tang wrote:
> Hi Thomson,
>
> Thanks for testing!
>
> + mips maintainer and mail list. The original report is here
>
> https://lore.kernel.org/lkml/becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com/



I am guessing my issue comes from __kmem_cache_alloc_lru accessing s->object_size when (kmem_cache) s is NULL?
If that is the case, this change is not to blame, it only exposes the issue?

I get the following dmesg (note very early NULL kmem_cache) with the below change atop v6.1-rc3:

transfer started ......................................... transfer ok, time=2.02s
setting up elf image... OK
jumping to kernel code
zimage at:     80B842A0 810B4EFC

Uncompressing Linux at load address 80001000

Copy device tree to address  80B80EE0

Now, booting the kernel...

[    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binutils) 2.39) #61 SMP Tue Nov  1 18:04:13 AEST 2022
[    0.000000] slub: kmem_cache_alloc called with kmem_cache: 0x0
[    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache: 0x0
[    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
[    0.000000] printk: bootconsole [early0] enabled
[    0.000000] CPU0 revision is: 0001992f (MIPS 1004Kc)
[    0.000000] MIPS: machine is MikroTik RouterBOARD 760iGS

normal boot


diff --git a/mm/slub.c b/mm/slub.c
index 157527d7101b..10fcdf2520d2 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3410,7 +3410,13 @@ static __always_inline
 void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
 			     gfp_t gfpflags)
 {
-	void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
+	void *ret;
+	if (IS_ERR_OR_NULL(s)) {
+		pr_warn("slub: __kmem_cache_alloc_lru called with kmem_cache: %pSR\n", s);
+		ret = slab_alloc(s, lru, gfpflags, _RET_IP_, 0);
+	} else {
+		ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
+	}
 
 	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
 
@@ -3419,6 +3425,8 @@ void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
 
 void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
 {
+	if (IS_ERR_OR_NULL(s))
+		pr_warn("slub: kmem_cache_alloc called with kmem_cache: %pSR\n", s);
 	return __kmem_cache_alloc_lru(s, NULL, gfpflags);
 }
 EXPORT_SYMBOL(kmem_cache_alloc);
@@ -3426,6 +3434,8 @@ EXPORT_SYMBOL(kmem_cache_alloc);
 void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
 			   gfp_t gfpflags)
 {
+	if (IS_ERR_OR_NULL(s))
+		pr_warn("slub: __kmem_cache_alloc_lru called with kmem_cache: %pSR\n", s);
 	return __kmem_cache_alloc_lru(s, lru, gfpflags);
 }
 EXPORT_SYMBOL(kmem_cache_alloc_lru);


Any hints on where kmem_cache_alloc would be being called from this early?
I will start looking from /init/main.c around pr_notice("%s", linux_banner);

Thank you for your help.

Let me know if you want me to stop replying to this mm/slub debug memory wasting email,
and take this to a new email?

Cheers,
-- 
  John Thomson

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/53b53476-bb1e-402e-9f65-fd7f0ecf94c2%40app.fastmail.com.
