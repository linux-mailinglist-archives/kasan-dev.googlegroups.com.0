Return-Path: <kasan-dev+bncBAABBVPDRWNQMGQEOSI3DTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B3436177E7
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Nov 2022 08:46:31 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id 23-20020a1f1617000000b003b891d085casf228580vkw.22
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Nov 2022 00:46:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667461590; cv=pass;
        d=google.com; s=arc-20160816;
        b=UrowKWhxSSvyPigQ5r8dCqtmoxcK8jSArpgIrkEmxi8cqnDK2foZjdcZGkWCHCPjNF
         os796L2YBvAgGyEl/d87BCaZX/iofu6si3DhhlZTsxQZawf/qKOY8kywqfyA7nFUqyI6
         yBAZ3dZhLmbHiD1Wt4zVocQeEZzHvDd9gEb+CP6AaVvGaPMyDaaEhOg7LnVxcPpDEP6S
         QzRD8+JTf1MGrP12IVvk1lc6d+s5PvN1qYfizMK6lQedCouSczAexaCkwxhuZNxCBg1e
         zkIVK6iqKbVW4mUhsroFxqGbJDUBsiBtsbNCZ+2+khdSWYlMNtYsvb0CsdGNAvzu00Ry
         BkuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=w32uqkvmgeOQa9sBi6P4gXAYynIjO0zMK3PNeL5//iA=;
        b=BoDT8k3ldzjC0gJULn1WBCDQtTCmRhEkAdYOiHcGUK1SiNXKPv8PKStbGqncPfmg/6
         lcIiEtOkXypc54nzXs/nnkNbF0JXfRLGspPEUipbg3v0h8qzCEysmrO58A9h7WC9xCpn
         X6UiDmIk5YrNbUBmyifLC4D8se6sZo91ZZIvpFONRB/LTAZnmCR/yUcmYPVIHl+1Px6b
         racMlx2AJaGw19wq5/EP1x6hpHOLuMWWZkkfVqtgnHPBqeEIcKm02JYQfCfbcfje7tgX
         cfJ3CehjE5cJHGmWxsdnPUxyMhtdqP/ZhUSPiSJJjjMKJW1ZfJE3FybRKMs9ddELUg7T
         grVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@fastmail.com.au header.s=fm3 header.b=FC+Hvo6g;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=cvCkb37c;
       spf=pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 66.111.4.27 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=w32uqkvmgeOQa9sBi6P4gXAYynIjO0zMK3PNeL5//iA=;
        b=bqN6aElv+dhR6MMGLW1KWlnO+6SpQjXs57kzc8vLfUKY+7nO5dd02HJQilT1cmtflQ
         CWyY1krNdLu0j69MOHcgH5nKNMw5mVV9hvbLS/MUSyatVTCG7Fv4J+1lhV8jvYzOo0iA
         7A2QZNACDh7tnaZYn0cuQESNYGCTNVvQQBHyuwFoav3lfQJBAoxA0zxUTwi+Q11a/65n
         zz0fTRG9jd/i7EpoF3LUSvdcKU7FJBlQdl5qnFIRfFeOkSKjcjSdHxtX5vyF28kCXrbq
         MZ8Cmx26ob7jN7S8dLnM5/7RTWghhXT2a3cE6zAaNql1AT3aFKTAHrJoqooeOOeS++dl
         RUFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=w32uqkvmgeOQa9sBi6P4gXAYynIjO0zMK3PNeL5//iA=;
        b=bkcU8wRoxW9hnRbW9gnX9d6PVCSCwJm4im53ymwVf2Z+cyHB4S58kaQRx/MzuJzZTw
         wW2vjhy3zUoCD+1b0L6RDYK8y7EnWIq6mXEMCC5GfTpwQjK3oXG5Aom+MkQaVVYtu39m
         4AFmxSA6bgDMDLCleUltykAQhp7cqPrsJGkI3w8T2FJMTl5x6otNgTtpgwYjC5tVr64Q
         f7M51036qfdZsYM/bP/N461NGU8FrZreRi0H9SrF+ksS24veOa/1guVQsXfNTK7ohtk5
         NxymLrAd7WdEXFcu6WgxDchsX5BWcM3V0Gpjg7u4hOwuEDJn/KcOvXy33zi3/lBErLC1
         vQ+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0pBxQZPD8PmXuoEV3O9ZpFwRn0rVIjYzSSbWxst2OcxveIpnp/
	2P/Rw1GQewd+BX7mgxiMoEM=
X-Google-Smtp-Source: AMsMyM6WP15/605e57m2hLGhqrccaGWQ44oiWm6S4IYzlSnwpfbO3ltG7ipuYCcD2n+ukaILs1SXZg==
X-Received: by 2002:a67:e281:0:b0:398:8b:12df with SMTP id g1-20020a67e281000000b00398008b12dfmr16205406vsf.66.1667461589943;
        Thu, 03 Nov 2022 00:46:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c99a:0:b0:3ac:74da:f230 with SMTP id y26-20020a67c99a000000b003ac74daf230ls223706vsk.1.-pod-prod-gmail;
 Thu, 03 Nov 2022 00:46:29 -0700 (PDT)
X-Received: by 2002:a05:6102:15aa:b0:390:9b9b:f679 with SMTP id g42-20020a05610215aa00b003909b9bf679mr16241210vsv.34.1667461589377;
        Thu, 03 Nov 2022 00:46:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667461589; cv=none;
        d=google.com; s=arc-20160816;
        b=BKNlVM5yIFFr5n/UKiBBq6ZPQBPFIOGjdTF+OGaZ7iFbbV/R7psnZc+kJ+2iuLuTZX
         rjO4ZSwFNNHE5JY9a1ijo9QkpAEpnVh99uILFCTYyU3YTd6PsE+n95U6FY2llZZMQH+h
         pLunrypIl3K+NaLhfR4nv+c6R9XYYrIgdMYupLhA25xo0S9gbbxBtXPWE/nGtU8zc0G1
         rSS7b83eohu0U8Qz1IpD89mstTORxD7CG9FpxzRMnFchrbgkZbRBVg2Fx+DKZ7QSTQ5q
         xIq+f4WbsamYiRtmHqZ1McqNprdAgCWWpdkhY6it3pWeZiEHE7YpAvG3A1D11vXvz61f
         r37g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=UJZ0UysFtjqjPIhOXvrXl9HpVojGVqoZMb7srL4hqgM=;
        b=ASKQVtV6iq7xTvUHZR7iDUDvTzAh7aSM7uKjTQxcPWEahhCr684SHqBSpFEVuIeh/R
         2GKnbI3g1DdswUWM690d40ii++O7SJ1TgvCzsFcVJfB3P6X8hdZIZMj4ETvvC6xXahDo
         jPjGY+MRdR7HnRwxlfvD5S9r6xKoquALXXgoisz/KMNm4ZEJnIykiL9/B2YiRyhhXUUs
         URQeX4QiNZHBXgQS4AsRKKntA1Fdrha3xVF0jFO8U+eMID5VbN8HTuLuFCFsaGveBorm
         2dMFPnuK+d1ztpwdtWLOrurNGfVmRN5ZYleUypyuu3BiFHBPVnZ10OUejnY3xQ6z1Ets
         yAzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@fastmail.com.au header.s=fm3 header.b=FC+Hvo6g;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=cvCkb37c;
       spf=pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 66.111.4.27 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
Received: from out3-smtp.messagingengine.com (out3-smtp.messagingengine.com. [66.111.4.27])
        by gmr-mx.google.com with ESMTPS id a39-20020ab03ca7000000b0040ac33271e7si4119uax.2.2022.11.03.00.46.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Nov 2022 00:46:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 66.111.4.27 as permitted sender) client-ip=66.111.4.27;
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailout.nyi.internal (Postfix) with ESMTP id D690D5C00DF;
	Thu,  3 Nov 2022 03:46:28 -0400 (EDT)
Received: from imap46 ([10.202.2.96])
  by compute5.internal (MEProxy); Thu, 03 Nov 2022 03:46:28 -0400
X-ME-Sender: <xms:03FjY7b1CAJwEuzluTxLif4B88JXlNghnCfO2eG1MaKSB7A_FCm-mg>
    <xme:03FjY6Y-UIo2Aau6fJrpHEbbm2WcFjVhtUvcGRn14177hNBSvwZXLMc3UQu2XLaSf
    bc1GyQwGL4woAhdAA>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvgedrudekgdduuddtucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepofgfggfkjghffffhvfevufgtsehttdertderredtnecuhfhrohhmpedflfho
    hhhnucfvhhhomhhsohhnfdcuoehlihhsthhssehjohhhnhhthhhomhhsohhnrdhfrghsth
    hmrghilhdrtghomhdrrghuqeenucggtffrrghtthgvrhhnpeejjeefieelgfeftdekkeef
    keffgeelteelhfehkeelgefgtddtveevudehteetgfenucffohhmrghinhepkhgvrhhnvg
    hlrdhorhhgnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhho
    mheplhhishhtshesjhhohhhnthhhohhmshhonhdrfhgrshhtmhgrihhlrdgtohhmrdgruh
X-ME-Proxy: <xmx:03FjY98o3Kiu4I6CSH9uilu0NoH7Ih6mkFGolflG5k3i8TCRM2Z6-w>
    <xmx:03FjYxot7QbczOxt5fdS2BWXeauqOf_ZLQ8VXESEdWvC7vBA8paBhw>
    <xmx:03FjY2pUvWU4z2LA7p-0jmUCKmvuQjFQwiMjDY0pFM_MJ0yvrvmhHQ>
    <xmx:1HFjY6oCruZq-H7sCgY9ssAM3LduTSZ-Pv_fsrM3Ec4HIMvHFnJQ8w>
Feedback-ID: ia7894244:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id 3C91C2A20085; Thu,  3 Nov 2022 03:46:27 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.7.0-alpha0-1087-g968661d8e1-fm-20221021.001-g968661d8
Mime-Version: 1.0
Message-Id: <f479b9cc-1301-410c-a36e-80c365964566@app.fastmail.com>
In-Reply-To: <Y2NrRt5FF+zi4Vf1@feng-clx>
References: <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
 <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
 <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
 <Y2D4D52h5VVa8QpE@hyeyoo> <Y2ElURkvmGD5csMc@feng-clx>
 <70002fbe-34ec-468e-af67-97e4bf97819b@app.fastmail.com>
 <Y2IJSR6NLVyVTsDY@feng-clx> <Y2IZNqpABkdxxPjv@hyeyoo>
 <Y2NrRt5FF+zi4Vf1@feng-clx>
Date: Thu, 03 Nov 2022 07:45:49 +0000
From: "John Thomson" <lists@johnthomson.fastmail.com.au>
To: "Feng Tang" <feng.tang@intel.com>, "Hyeonggon Yoo" <42.hyeyoo@gmail.com>
Cc: "Vlastimil Babka" <vbabka@suse.cz>,
 "Andrew Morton" <akpm@linux-foundation.org>,
 "Christoph Lameter" <cl@linux.com>, "Pekka Enberg" <penberg@kernel.org>,
 "David Rientjes" <rientjes@google.com>,
 "Joonsoo Kim" <iamjoonsoo.kim@lge.com>,
 "Roman Gushchin" <roman.gushchin@linux.dev>,
 "Dmitry Vyukov" <dvyukov@google.com>, "Jonathan Corbet" <corbet@lwn.net>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Hansen, Dave" <dave.hansen@intel.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 "Robin Murphy" <robin.murphy@arm.com>, "John Garry" <john.garry@huawei.com>,
 "Kefeng Wang" <wangkefeng.wang@huawei.com>,
 "Thomas Bogendoerfer" <tsbogend@alpha.franken.de>,
 "John Crispin" <john@phrozen.org>,
 "Matthias Brugger" <matthias.bgg@gmail.com>,
 "linux-mips@vger.kernel.org" <linux-mips@vger.kernel.org>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of kmalloc
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lists@johnthomson.fastmail.com.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fastmail.com.au header.s=fm3 header.b=FC+Hvo6g;       dkim=pass
 header.i=@messagingengine.com header.s=fm3 header.b=cvCkb37c;       spf=pass
 (google.com: domain of lists@johnthomson.fastmail.com.au designates
 66.111.4.27 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
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

On Thu, 3 Nov 2022, at 07:18, Feng Tang wrote:
> On Wed, Nov 02, 2022 at 04:16:06PM +0900, Hyeonggon Yoo wrote:
>> On Wed, Nov 02, 2022 at 02:08:09PM +0800, Feng Tang wrote:
> [...]
>> > > transfer started ......................................... transfer ok, time=2.11s
>> > > setting up elf image... OK
>> > > jumping to kernel code
>> > > zimage at:     80B842A0 810B4BC0
>> > > 
>> > > Uncompressing Linux at load address 80001000
>> > > 
>> > > Copy device tree to address  80B80EE0
>> > > 
>> > > Now, booting the kernel...
>> > > 
>> > > [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binutils) 2.39) #73 SMP Wed Nov  2 05:10:01 AEST 2022
>> > > [    0.000000] ------------[ cut here ]------------
>> > > [    0.000000] WARNING: CPU: 0 PID: 0 at mm/slub.c:3416 kmem_cache_alloc+0x5a4/0x5e8
>> > > [    0.000000] Modules linked in:
>> > > [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc3+ #73
>> > > [    0.000000] Stack : 810fff78 80084d98 00000000 00000004 00000000 00000000 80889d04 80c90000
>> > > [    0.000000]         80920000 807bd328 8089d368 80923bd3 00000000 00000001 80889cb0 00000000
>> > > [    0.000000]         00000000 00000000 807bd328 8084bcb1 00000002 00000002 00000001 6d6f4320
>> > > [    0.000000]         00000000 80c97d3d 80c97d68 fffffffc 807bd328 00000000 00000000 00000000
>> > > [    0.000000]         00000000 a0000000 80910000 8110a0b4 00000000 00000020 80010000 80010000
>> > > [    0.000000]         ...
>> > > [    0.000000] Call Trace:
>> > > [    0.000000] [<80008260>] show_stack+0x28/0xf0
>> > > [    0.000000] [<8070c958>] dump_stack_lvl+0x60/0x80
>> > > [    0.000000] [<8002e184>] __warn+0xc4/0xf8
>> > > [    0.000000] [<8002e210>] warn_slowpath_fmt+0x58/0xa4
>> > > [    0.000000] [<801c0fac>] kmem_cache_alloc+0x5a4/0x5e8
>> > > [    0.000000] [<8092856c>] prom_soc_init+0x1fc/0x2b4
>> > > [    0.000000] [<80928060>] prom_init+0x44/0xf0
>> > > [    0.000000] [<80929214>] setup_arch+0x4c/0x6a8
>> > > [    0.000000] [<809257e0>] start_kernel+0x88/0x7c0
>> > > [    0.000000] 
>> > > [    0.000000] ---[ end trace 0000000000000000 ]---
>> > > [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
>> > > [    0.000000] printk: bootconsole [early0] enabled
>> > > 
>> > > Thank you for working through this with me.
>> > > I will try to address the root cause in mt7621.c.
>> > > It looks like other arch/** soc_device_register users use postcore_initcall, device_initcall,
>> > > or the ARM DT_MACHINE_START .init_machine. A quick hack to use postcore_initcall in mt7621
>> > > avoided this zero ptr kmem_cache passed to kmem_cache_alloc_lru.
>> > 
>> > If IIUC, the prom_soc_init() is only called once in kernel, can the
>> > 'soc_dev_attr' just be defined as a global data structure instead
>> > of calling kzalloc(), as its size is small only containing 7 pointers.
>> 
>> But soc_device_registers() too uses kmalloc. I think calling it
>> after slab initialization will be best solution - if that is correct.
>
> Yes, you are right, there is other kmalloc() down the call chain.
>
> Hi John,
>
> Will you verify and submit a patch for your proposal of deferring
> calling prom_soc_init()? thanks
>
> - Feng

Hi Feng,

My proposed mt7621.c changes are RFC here:
https://lore.kernel.org/lkml/20221103050538.1930758-1-git@johnthomson.fastmail.com.au/
That series lets me boot the v6.1-rc3 kernel. I have only tried it with my config (as sent earlier). If there are other suspect config settings that I should test, please let me know?
I used device_initcall, but postcore_initcall also works fine.
I rephrased Vlastimil's explanation and used it in patch 3 description.
I have not referenced a Fixes tag yet (unsure which/if any I should use)

Cheers,
-- 
  John Thomson

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f479b9cc-1301-410c-a36e-80c365964566%40app.fastmail.com.
