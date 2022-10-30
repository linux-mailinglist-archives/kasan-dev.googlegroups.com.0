Return-Path: <kasan-dev+bncBAABBP467ONAMGQE3D7MUGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id C45B1612C66
	for <lists+kasan-dev@lfdr.de>; Sun, 30 Oct 2022 20:23:45 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id q1-20020a17090aa00100b002139a592adbsf3897059pjp.1
        for <lists+kasan-dev@lfdr.de>; Sun, 30 Oct 2022 12:23:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667157824; cv=pass;
        d=google.com; s=arc-20160816;
        b=KgoLyYOP9cCLsFFrvgiRXtosN5mkqRUtbOwq+UiOAtE1lKs/8sd/u/jicyH3/F+4TQ
         Kgmb2xcEs1UALwRpa6vvP/Fd/ORuzrGEdUj7K2A3CZbFBFneVg9e7e9ZQlLgPAGRHpsr
         W3k0rt7j1Oz06YVg+y2ElyCly7Nes+M+RjImlZZTg3oN/OzxrRrNJ+OZhtAgAPAajSeW
         tGNAMfZ/Inu9GZF6YNPdxcxTsac04qB3C2xeUi+V3IUF0myW+eRuANegyh/rZIOO8hnw
         YLTsD8+aE3tolPZ4+uUX2uZpmsI3U6O2DeuYqHRIXZi269jXL0phSm2pRFdfTo8bkuZa
         3Nyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=Ya7Rrz9RfhQB499jI6boBzMALZEahQ0H/TWT9bE3NGs=;
        b=UvNYyxnryrlaCVV7u4SxTro+yjsOtclrBF6Yrlj9TQ3kCBM6PJ1U/4thtKK5XVWKEa
         g9NMjstQNWcOyVTSL9Nfjme/WytkjdvDYIEqAIbvRyJzWNCIkF9FFolKlfBzlvthCvtc
         Xeo63qkxK9nvrzersuqB7PM/5s3xb68qGkGj1EEsHELm7+r3qW8bD7gKBVQYZqRGQLEn
         HUzwNoBlB9+wFA8ZItoddP7yQ3PnxLj+Q5vx/Z7yvaj0e7fmdkTp5UMKcGn9oJf7qQlt
         PLqj1BfjUu4V1m4hltpF8eTG9GWdhgfNVIlWNhsp1fvxTWOyJCZU+T303y62PSsd9S7H
         g2LQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@fastmail.com.au header.s=fm3 header.b=Aw56PXPA;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=f0WWAltV;
       spf=pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 66.111.4.26 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ya7Rrz9RfhQB499jI6boBzMALZEahQ0H/TWT9bE3NGs=;
        b=AdFq74FXDwguo+anVQP2/wGdpU2mRmm6ckpbvaSrEG4XgpBji+e8xZv2YkUFlfGutO
         +AZY80ac0qZRTIYdXEwzkXivbc1WaPNBG8YwefllWv/dSicwUG166rOSf6hufpwUEipJ
         IgyJ1XqTLGtN2lW6ewxbsiDbr867c6n4rq+85gg0FIUr2+svZJHK+pZl8Id/W0LPDmMi
         /ylfabKQf/HaL9yfqxsigBlll933CvS3E5osn3QBxYAD6YhB8X7xf012CJ2uI+EvSl3y
         NIAx6v1rp1VZK2BcfJZAm+gCw7XOxj/+llXGyBQb5oWRKY4UvTPgZy/3WA3IYAK5YPA0
         axsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ya7Rrz9RfhQB499jI6boBzMALZEahQ0H/TWT9bE3NGs=;
        b=meVVoaxdgdBvNW5d/iCqE6rBaNhdCaje9WVKbDQoxMsIeDVZeq2VDXaTLHWzZ9I4bs
         Vf+jO8lQ/1zb2sOgEwRTG2r0NaQK4bjp62uCAr5ZmfjNArwFRzTmmLuDXx9SrEDGWLFQ
         hMs60FhRCN6zE8CFI/ERtqad8T9CgtT5VWuhSTfMshiactv3fCrssuQx+kfg3sBYNAce
         D5n1dhecTw0dYPjml5+fXx6LwunjWNhneUkU4awVx4BvVcHox0mmZapwARrkjUBufLCk
         wA3VQ6KyyGVFC2zR5ee5DWW7FwN82osdlZo/QTMXswyCOsP9HXpY+tqM2/gceVQugBPS
         aUcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2HMJHO027gg7u1uH2ncS4UjhgYvMn3wqHFNPxwCRkjsyjd4IaL
	JwpzPT76EAD0Je8FgyWEL38=
X-Google-Smtp-Source: AMsMyM73cJmXJa3XzYUzT3RxR6mVw08pJ9r7IHT7/nX638Ir5wNuaBTFFi1rIUUtqVVlCnb4gRPM1A==
X-Received: by 2002:a05:6a00:4008:b0:56c:ee89:d5a9 with SMTP id by8-20020a056a00400800b0056cee89d5a9mr10839444pfb.75.1667157823956;
        Sun, 30 Oct 2022 12:23:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b88c:b0:210:6f33:e22d with SMTP id
 o12-20020a17090ab88c00b002106f33e22dls5052163pjr.2.-pod-control-gmail; Sun,
 30 Oct 2022 12:23:43 -0700 (PDT)
X-Received: by 2002:a17:902:a713:b0:183:e2a9:6409 with SMTP id w19-20020a170902a71300b00183e2a96409mr10322216plq.149.1667157823360;
        Sun, 30 Oct 2022 12:23:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667157823; cv=none;
        d=google.com; s=arc-20160816;
        b=spZZRhVBLqVeCXfg1XsxOSCQKe0Th12IkVH9RFWbE0qmxaLtMCkTFJh5+H64cIRqm4
         8IbF4xzzGlFemnvLmoxSm/PA6b7I2rwNh8NuCMmdBFtZr9H/5KiwD78A9/pwRrpZEZ8a
         Ry9i0aSow8QmW9UNp71SCOg79SPmWWkIA4LfYWmmhEF4MFV368uJQvFFEJALU7zxz05s
         WrWo+f4L3qHrYBagRMxu18ZQ6v2b95/hXQNO5j/Vm+KTQZzTU0Ds9qmDH9eZUFSYgtNo
         66XW7s2H5d9Fvdpoviiq2jgRot6vUHEpdHKyg0HoAOMe5nz6vtS6KKOt7yFn/kzDBv7w
         gomQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=ki0w8E89xq1IweuEOycTi68h20ldYBwm17VLVgE61nc=;
        b=J/zLG2ALFy45u9ZsVGjlWF0C+G30eFCQT87jU7LRfM0jLM/iOajLqDdhYrr0cnpxfb
         AWtyGQ9UGdsvPoS6Yt5cUdS81qG9eXypok+lCBv25cwHvuRHmCbt8QCyrmKN2gldZCop
         dDY94caXQTSV9ugU2V7YrQ2sHdctfi7FBUejxT+BFzo3sQcqu9l8Id9AlgFZuWdZ2kxP
         VPnRu+qdyFlHavEmb3nX8/xqb6aArKwNgj02UndDOHCU3DAtjD4knDjHwA6w18EINpT+
         Ff3uNjiMp4gY4dX67uWAYHlUa9DRc9FgVQdB5hA2+Uizi4wbT4aMj/lPvqkMH/4NL3dL
         vn9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@fastmail.com.au header.s=fm3 header.b=Aw56PXPA;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=f0WWAltV;
       spf=pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 66.111.4.26 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
Received: from out2-smtp.messagingengine.com (out2-smtp.messagingengine.com. [66.111.4.26])
        by gmr-mx.google.com with ESMTPS id b139-20020a621b91000000b0056a940f6b44si199825pfb.4.2022.10.30.12.23.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 30 Oct 2022 12:23:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 66.111.4.26 as permitted sender) client-ip=66.111.4.26;
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailout.nyi.internal (Postfix) with ESMTP id 983B95C003F;
	Sun, 30 Oct 2022 15:23:42 -0400 (EDT)
Received: from imap46 ([10.202.2.96])
  by compute5.internal (MEProxy); Sun, 30 Oct 2022 15:23:42 -0400
X-ME-Sender: <xms:PM9eY5vphbLAIyz6udFLL4e0t4A5DU-yp5oGj81moFHnFlWmpe12ig>
    <xme:PM9eYyfVv19d4B-Ptwc3J1rPbUCijAKxgfwEte-OZJLfOTnuwD2f1NomDJI9sPVMm
    wtSwiNqQ8pSl2eA6w>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvgedruddtgdduvdeiucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepofgfggfkjghffffhvfevufgtsehttdertderredtnecuhfhrohhmpedflfho
    hhhnucfvhhhomhhsohhnfdcuoehlihhsthhssehjohhhnhhthhhomhhsohhnrdhfrghsth
    hmrghilhdrtghomhdrrghuqeenucggtffrrghtthgvrhhnpeekfefhgfdutdeggeejtdev
    tddvvdekvedvheefheeijefhhffhjeekjefgleevgeenucevlhhushhtvghrufhiiigvpe
    dtnecurfgrrhgrmhepmhgrihhlfhhrohhmpehlihhsthhssehjohhhnhhthhhomhhsohhn
    rdhfrghsthhmrghilhdrtghomhdrrghu
X-ME-Proxy: <xmx:PM9eY8wjg2dZFQM58nlzVcEHxKjnyV7wVICEc7eDtFC905gIJI5Hvw>
    <xmx:PM9eYwPy8hGMtCKd4f2fgIGmFP2K7N7Am2cosPlS4W9XOuoc8N7ksg>
    <xmx:PM9eY5-B59pqdYEG36q0KjY6I5CI6Pr1-5L-RGiY5FuonDvv5fyffQ>
    <xmx:Ps9eYxMYzW3G_WO5bZbDWt0QgswlrOu5a5v4YO6aLbk-mc1-7R_diA>
Feedback-ID: ia7894244:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id 71A9E2A20080; Sun, 30 Oct 2022 15:23:40 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.7.0-alpha0-1087-g968661d8e1-fm-20221021.001-g968661d8
Mime-Version: 1.0
Message-Id: <becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com>
In-Reply-To: <20220913065423.520159-2-feng.tang@intel.com>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-2-feng.tang@intel.com>
Date: Sun, 30 Oct 2022 19:23:04 +0000
From: "John Thomson" <lists@johnthomson.fastmail.com.au>
To: "Feng Tang" <feng.tang@intel.com>,
 "Andrew Morton" <akpm@linux-foundation.org>,
 "Vlastimil Babka" <vbabka@suse.cz>, "Christoph Lameter" <cl@linux.com>,
 "Pekka Enberg" <penberg@kernel.org>, "David Rientjes" <rientjes@google.com>,
 "Joonsoo Kim" <iamjoonsoo.kim@lge.com>,
 "Roman Gushchin" <roman.gushchin@linux.dev>,
 "Hyeonggon Yoo" <42.hyeyoo@gmail.com>, "Dmitry Vyukov" <dvyukov@google.com>,
 "Jonathan Corbet" <corbet@lwn.net>, "Andrey Konovalov" <andreyknvl@gmail.com>
Cc: "Dave Hansen" <dave.hansen@intel.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 "Robin Murphy" <robin.murphy@arm.com>, "John Garry" <john.garry@huawei.com>,
 "Kefeng Wang" <wangkefeng.wang@huawei.com>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of kmalloc
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lists@johnthomson.fastmail.com.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fastmail.com.au header.s=fm3 header.b=Aw56PXPA;       dkim=pass
 header.i=@messagingengine.com header.s=fm3 header.b=f0WWAltV;       spf=pass
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

On Tue, 13 Sep 2022, at 06:54, Feng Tang wrote:
> kmalloc's API family is critical for mm, with one nature that it will
> round up the request size to a fixed one (mostly power of 2). Say
> when user requests memory for '2^n + 1' bytes, actually 2^(n+1) bytes
> could be allocated, so in worst case, there is around 50% memory
> space waste.


I have a ralink mt7621 router running Openwrt, using the mips ZBOOT kernel, and appear to have bisected
a very-nearly-clean kernel v6.1rc-2 boot issue to this commit.
I have 3 commits atop 6.1-rc2: fix a ZBOOT compile error, use the Openwrt LZMA options,
and enable DEBUG_ZBOOT for my platform. I am compiling my kernel within the Openwrt build system.
No guarantees this is not due to something I am doing wrong, but any insight would be greatly appreciated.


On UART, No indication of the (once extracted) kernel booting:

transfer started ......................................... transfer ok, time=2.01s
setting up elf image... OK
jumping to kernel code
zimage at:     80BA4100 810D4720
Uncompressing Linux at load address 80001000
Copy device tree to address  80B96EE0
Now, booting the kernel...

Nothing follows

6edf2576a6cc  ("mm/slub: enable debugging memory wasting of kmalloc") reverted, normal boot:
transfer started ......................................... transfer ok, time=2.01s
setting up elf image... OK
jumping to kernel code
zimage at:     80BA4100 810D47A4
Uncompressing Linux at load address 80001000
Copy device tree to address  80B96EE0
Now, booting the kernel...

[    0.000000] Linux version 6.1.0-rc2 (john@john) (mipsel-openwrt-linux-musl-gcc (OpenWrt GCC 11.3.0 r19724+16-1521d5f453) 11.3.0, GNU ld (GNU Binutils) 2.37) #0 SMP Fri Oct 28 03:48:10 2022
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
[    0.000000] Kernel command line: console=ttyS0,115200 rootfstype=squashfs,jffs2
[    0.000000] Dentry cache hash table entries: 32768 (order: 5, 131072 bytes, linear)
[    0.000000] Inode-cache hash table entries: 16384 (order: 4, 65536 bytes, linear)
[    0.000000] Writing ErrCtl register=00019146
[    0.000000] Readback ErrCtl register=00019146
[    0.000000] mem auto-init: stack:off, heap alloc:off, heap free:off
[    0.000000] Memory: 246220K/262144K available (7455K kernel code, 628K rwdata, 1308K rodata, 3524K init, 245K bss, 15924K reserved, 0K cma-reserved, 0K highmem)
[    0.000000] SLUB: HWalign=32, Order=0-3, MinObjects=0, CPUs=4, Nodes=1
[    0.000000] rcu: Hierarchical RCU implementation.


boot continues as expected


possibly relevant config options:
grep -E '(SLUB|SLAB)' .config
# SLAB allocator options
# CONFIG_SLAB is not set
CONFIG_SLUB=y
CONFIG_SLAB_MERGE_DEFAULT=y
# CONFIG_SLAB_FREELIST_RANDOM is not set
# CONFIG_SLAB_FREELIST_HARDENED is not set
# CONFIG_SLUB_STATS is not set
CONFIG_SLUB_CPU_PARTIAL=y
# end of SLAB allocator options
# CONFIG_SLUB_DEBUG is not set


With this commit reverted: cpuinfo and meminfo

system type		: MediaTek MT7621 ver:1 eco:3
machine			: MikroTik RouterBOARD 760iGS
processor		: 0
cpu model		: MIPS 1004Kc V2.15
BogoMIPS		: 586.13
wait instruction	: yes
microsecond timers	: yes
tlb_entries		: 32
extra interrupt vector	: yes
hardware watchpoint	: yes, count: 4, address/irw mask: [0x0ffc, 0x0ffc, 0x0ffb, 0x0ffb]
isa			: mips1 mips2 mips32r1 mips32r2
ASEs implemented	: mips16 dsp mt
Options implemented	: tlb 4kex 4k_cache prefetch mcheck ejtag llsc pindexed_dcache userlocal vint perf_cntr_intr_bit cdmm perf
shadow register sets	: 1
kscratch registers	: 0
package			: 0
core			: 0
VPE			: 0
VCED exceptions		: not available
VCEI exceptions		: not available

processor		: 1
cpu model		: MIPS 1004Kc V2.15
BogoMIPS		: 586.13
wait instruction	: yes
microsecond timers	: yes
tlb_entries		: 32
extra interrupt vector	: yes
hardware watchpoint	: yes, count: 4, address/irw mask: [0x0ffc, 0x0ffc, 0x0ffb, 0x0ffb]
isa			: mips1 mips2 mips32r1 mips32r2
ASEs implemented	: mips16 dsp mt
Options implemented	: tlb 4kex 4k_cache prefetch mcheck ejtag llsc pindexed_dcache userlocal vint perf_cntr_intr_bit cdmm perf
shadow register sets	: 1
kscratch registers	: 0
package			: 0
core			: 0
VPE			: 1
VCED exceptions		: not available
VCEI exceptions		: not available

processor		: 2
cpu model		: MIPS 1004Kc V2.15
BogoMIPS		: 586.13
wait instruction	: yes
microsecond timers	: yes
tlb_entries		: 32
extra interrupt vector	: yes
hardware watchpoint	: yes, count: 4, address/irw mask: [0x0ffc, 0x0ffc, 0x0ffb, 0x0ffb]
isa			: mips1 mips2 mips32r1 mips32r2
ASEs implemented	: mips16 dsp mt
Options implemented	: tlb 4kex 4k_cache prefetch mcheck ejtag llsc pindexed_dcache userlocal vint perf_cntr_intr_bit cdmm perf
shadow register sets	: 1
kscratch registers	: 0
package			: 0
core			: 1
VPE			: 0
VCED exceptions		: not available
VCEI exceptions		: not available

processor		: 3
cpu model		: MIPS 1004Kc V2.15
BogoMIPS		: 586.13
wait instruction	: yes
microsecond timers	: yes
tlb_entries		: 32
extra interrupt vector	: yes
hardware watchpoint	: yes, count: 4, address/irw mask: [0x0ffc, 0x0ffc, 0x0ffb, 0x0ffb]
isa			: mips1 mips2 mips32r1 mips32r2
ASEs implemented	: mips16 dsp mt
Options implemented	: tlb 4kex 4k_cache prefetch mcheck ejtag llsc pindexed_dcache userlocal vint perf_cntr_intr_bit cdmm perf
shadow register sets	: 1
kscratch registers	: 0
package			: 0
core			: 1
VPE			: 1
VCED exceptions		: not available
VCEI exceptions		: not available

MemTotal:         249744 kB
MemFree:          211088 kB
MemAvailable:     187364 kB
Buffers:               0 kB
Cached:             8824 kB
SwapCached:            0 kB
Active:             1104 kB
Inactive:           8860 kB
Active(anon):       1104 kB
Inactive(anon):     8860 kB
Active(file):          0 kB
Inactive(file):        0 kB
Unevictable:           0 kB
Mlocked:               0 kB
HighTotal:             0 kB
HighFree:              0 kB
LowTotal:         249744 kB
LowFree:          211088 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:                 0 kB
Writeback:             0 kB
AnonPages:          1192 kB
Mapped:             2092 kB
Shmem:              8824 kB
KReclaimable:       1704 kB
Slab:               9372 kB
SReclaimable:       1704 kB
SUnreclaim:         7668 kB
KernelStack:         592 kB
PageTables:          264 kB
SecPageTables:	       0 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:      124872 kB
Committed_AS:      14676 kB
VmallocTotal:    1040376 kB
VmallocUsed:        2652 kB
VmallocChunk:          0 kB
Percpu:              272 kB


Cheers,

-- 
  John Thomson

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/becf2ac3-2a90-4f3a-96d9-a70f67c66e4a%40app.fastmail.com.
