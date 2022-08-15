Return-Path: <kasan-dev+bncBDAZZCVNSYPBBUMA5GLQMGQE57VJ3EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A638592F2B
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Aug 2022 14:47:14 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id h5-20020aca1805000000b0033ad9f4a769sf1661860oih.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Aug 2022 05:47:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660567633; cv=pass;
        d=google.com; s=arc-20160816;
        b=hcc48JOAFD8yKIPoeQPtN59L63+EkwKzXL9RFEUuaZyHEzEf1/z3lnB5byamcLrnsC
         bCOgn8hHmB1HwB50euM+WE29ySS2I5GoZpmpsIy/ywzyW40/+4ZC0u1N2cx6G3Vdt7aW
         IbW4p8UvD6PTlEBLVv0tqtsWAE0JwBnZjMosAuv1tatFiL6qEg65nu6WJTMC5rHgbrpL
         rnn8FoN3luK7PpSEE7pjGP+OXFCc7LMrzu81ToCmZVm59fRVFv0+pMO6r1SlvO6tqwOp
         /ZGE/nm9owXRSy6zxVHD8N+z6HSr7i9PIuH/uspyufXPPJEpEva7JLnXuluLjcJSA2jU
         YBnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=zC9t3ltdLTlQj7ef+Mjy9nEpg4suXfZw2vWFA13MoO0=;
        b=oaiBGFkHhHc2ZnC6CJ5MpSAEi/i+SMtVPYpNE5N1VAdzgiqS11h9LNll3EnjBG3DI4
         y+t+W7csg2CnL2oEG1jpT1JFg3ikLJsKWnu7Wt16i34grKdx1p26gHi+vqzu35qiM4zl
         A6UiUeh5sfeBqN3+vZ2qD2+QorZ86ahVkmgQ0kYwo9JQVzLCfRCRcbzqoC2hnj4miLhm
         GcbK4nCjgQ6ywkLqqimkQ+0fOwOF9E83m/Yh1eqXztnUiGytXCeo24H9Xu0v0uoAOIwh
         ZFr0W+5wErGi44MrV1qHYbhc7OLEFxe86XBdM3hNoKWBeVj2Frf80NrIpFQtsSumNRCR
         oIBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=T9p8KoYd;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc;
        bh=zC9t3ltdLTlQj7ef+Mjy9nEpg4suXfZw2vWFA13MoO0=;
        b=eOXojXZC24fSLnBzMggi862NXfzcoHMZ6mlnhAsJ+n8/dstTDLIMteqaDHtTezwAHn
         0FU3zNOjI3W2ZbJ78zu0yOf0Ia9ysew/hGZ9pDrTUmFpqbeOMZ1sPmVq+meYZZmHfo7k
         ewPgD6QkdGawovWehJEEsvpSF2466lmQ2G2pKggp8d7/uGt3vz5CKQkCPF0z6gvN/9tQ
         6GktkChQsnTBl519Y16+A1PHJ9TrFk4WnOn/+028MdDyLAbxqODPgYKXFcoDtMxaRcPQ
         FhkDUlg60sg/h/hZcl0/FJ4UguAjWLTJGl4wAMm24OuJ3g6j+LdL1lKRX/qx5u0kLO7x
         B0Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=zC9t3ltdLTlQj7ef+Mjy9nEpg4suXfZw2vWFA13MoO0=;
        b=mWUeFzwxxUga6nALkXPPRqRaPORKNtsL8tF4tKKWslCjlQCrrHaU5VnWPUcOafSW/Y
         WWUQjitzDi2PBWdYLnvrwph0YtBjbnikFKJ13r1jjpus9l6/NzWVsaMCrzUhogKmcDi9
         mBDxlxA9cgIcSY7cmj+2YXJQtNP3/UMSlWo2Wm2fp3uXqkNyQT64eN314G7fzJ6oleLV
         7vADsEh1e+vmRmv15ppGlnAns9XSHTaaoFFA3YkgF7ghvX79d+vRJqPNORD7OTvEUxWP
         TtfycKcx6edDg41fp839yRqGflbq+hERHakeD6bxxEFj8hoyJupTbtbfbind39bIj/lK
         krCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3D6b5wwmnSyM3NPXzv9wa64/X0wyvMV8R7gIehubFs6oIrkmxe
	2qiXCdyqAtyT8OwA//EKC2E=
X-Google-Smtp-Source: AA6agR5fLg4wwNeenT9d+JNYJ5nqjPG9GJN5ZzMym+PYjVdzkzgTuwYxVEPlglfF8ZBPdgNPK+LULA==
X-Received: by 2002:a05:6808:a19:b0:344:13cb:afce with SMTP id n25-20020a0568080a1900b0034413cbafcemr4641065oij.255.1660567633147;
        Mon, 15 Aug 2022 05:47:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:3029:b0:342:fca9:5e23 with SMTP id
 ay41-20020a056808302900b00342fca95e23ls2650163oib.11.-pod-prod-gmail; Mon, 15
 Aug 2022 05:47:12 -0700 (PDT)
X-Received: by 2002:a05:6808:1408:b0:343:a964:bf1a with SMTP id w8-20020a056808140800b00343a964bf1amr4529615oiv.14.1660567632601;
        Mon, 15 Aug 2022 05:47:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660567632; cv=none;
        d=google.com; s=arc-20160816;
        b=jWsSyrB5ftnjb4+N2elBd9PWHFzimTibaqaOqHGjoNPSDNSX7GXduLRYvoBnW+4+9A
         bbxKPBA8o/0okzfezF4H4cBHMIkK7ntF6lLyZEb0KLccGfHeV+Z5F39YNr9QPMzPa3ct
         SJthX7BMcWzrcmGF1VDVyr+DwSkdAlUXcx/w2qnJm60pdET4nWK9wFqKU4+sEsg5Cp2k
         nsdtgFLkZaRqT/vUkG62h9RrGX3MSFliFogui6Y7hAzCdDZQSQ4MWyME4Qlkt5ReGeAL
         L/BnWKSIbEpt4qERWs7gq6qdbnQ7blRmBHmSIvugJwj8OigQdYBBxjpoS9evUiqz2H1g
         TwpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=KePVTXAFujzNzzbPfqFf41h/bug3iO9RRMejt0Zslew=;
        b=x0FPVRwERIm11zEu9PTGw+E5c2n8o6NSGMYP3R8A3PGC0kWNUqWN+RPK7GHOECFNd1
         ZGfcJzvr6a2x6Z+731B7HPgk0aqsCmU4sTPMkCSA132ZZJVydi2VNdlIclujxY3P5FSi
         4eRuiwkCRMRvXnziaYPtcKmhzdb9VjoGRDiSvPEvhiDI9+qTRoC6FSQ8+ZyD9I+ksSQn
         aNjKGqnlLIIccEV7bq/VFUPBD2HntT5Bry6Rate+dnmH56AVfQ3+iA9wGvfhwuN5EsGg
         ZeL/d30KZXlBGcQ4DVJkAEpcfRibrIR2rGCRR8U//K71y9IdiXO+OMle5R096ldZhzEi
         3CPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=T9p8KoYd;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id o7-20020a056871078700b00101c9597c72si793122oap.1.2022.08.15.05.47.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Aug 2022 05:47:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 56A35611C2;
	Mon, 15 Aug 2022 12:47:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1EC1DC433B5;
	Mon, 15 Aug 2022 12:47:09 +0000 (UTC)
Date: Mon, 15 Aug 2022 13:47:06 +0100
From: Will Deacon <will@kernel.org>
To: Max Schulze <max.schulze@online.de>
Cc: linux-arm-kernel@lists.infradead.org, catalin.marinas@arm.com,
	naush@raspberrypi.com, glider@google.com, elver@google.com,
	dvyukov@google.com, kasan-dev@googlegroups.com
Subject: Re: kmemleak: Cannot insert 0xffffff806e24f000 into the object
 search tree (overlaps existing) [RPi CM4]
Message-ID: <20220815124705.GA9950@willie-the-truck>
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=T9p8KoYd;       spf=pass
 (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

[+kfence folks as kfence_alloc_pool() is starting the stacktrace]

On Mon, Aug 15, 2022 at 11:52:05AM +0200, Max Schulze wrote:
> Hello,
> 
> I get these messages when booting 5.19.0 on RaspberryPi CM4.
> 
> Full boot log is at https://pastebin.ubuntu.com/p/mVhgBwxqPj/
> 
> Anyone seen this? What can I do ?
> 
> Thanks,
> 
> Max
> 
> 
> [0.087630] kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> [0.087756] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.19.0-v8-0815+ #5
> [0.087836] Hardware name: Raspberry Pi Compute Module 4 Rev 1.0 (DT)
> [0.087901] Call trace:
> [0.087941]  dump_backtrace.part.0+0x1dc/0x1ec
> [0.088029]  show_stack+0x24/0x80
> [0.088089]  dump_stack_lvl+0x8c/0xb8
> [0.088161]  dump_stack+0x1c/0x38
> [0.088224]  create_object.isra.0+0x490/0x4b0
> [0.088298]  kmemleak_alloc+0x3c/0x50
> [0.088365]  kmem_cache_alloc+0x2f8/0x450
> [0.088435]  __proc_create+0x18c/0x400
> [0.088509]  proc_create_reg+0x54/0xd0
> [0.088569]  proc_create_seq_private+0x94/0x120
> [0.088634]  init_mm_internals+0x1d8/0x248
> [0.088704]  kernel_init_freeable+0x188/0x388
> [0.088776]  kernel_init+0x30/0x150
> [0.088837]  ret_from_fork+0x10/0x20
> [0.088903] kmemleak: Kernel memory leak detector disabled
> [0.088958] kmemleak: Object 0xffffff806e24d000 (size 2097152):
> [0.089021] kmemleak:   comm "swapper", pid 0, jiffies 4294892296
> [0.089085] kmemleak:   min_count = -1
> [0.089131] kmemleak:   count = 0
> [0.089174] kmemleak:   flags = 0x5
> [0.089219] kmemleak:   checksum = 0
> [0.089264] kmemleak:   backtrace:
> [0.089306]  kmemleak_alloc_phys+0x94/0xb0
> [0.089379]  memblock_alloc_range_nid+0x1c0/0x20c
> [0.089460]  memblock_alloc_internal+0x88/0x100
> [0.089532]  memblock_alloc_try_nid+0x148/0x1ac
> [0.089604]  kfence_alloc_pool+0x44/0x6c
> [0.089674]  mm_init+0x28/0x98
> [0.089733]  start_kernel+0x178/0x3e8
> [0.089797]  __primary_switched+0xc4/0xcc
> [0.090185] cblist_init_generic: Setting adjustable number of callback queues.
> 
> 
> early_memtest reports no problems, 
> 
> 
> [0.000000] Zone ranges:
> [0.000000]   DMA  [mem 0x0000000000000000-0x000000003fffffff]
> [0.000000]   DMA32[mem 0x0000000040000000-0x000000007fffffff]
> [0.000000]   Normal   empty
> [0.000000] Movable zone start for each node
> [0.000000] Early memory node ranges
> [0.000000]   node   0: [mem 0x0000000000000000-0x0000000037ffffff]
> [0.000000]   node   0: [mem 0x0000000040000000-0x000000007fffffff]
> [0.000000] Initmem setup node 0 [mem 0x0000000000000000-0x000000007fffffff]
> 
> 
> The Address differs a bit across reboots, but callstack looks always the same, and "Object is always 0xffffff806e24d000 (size 2097152)" 
> 
> 
> Aug 15 03:42:44 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 03:50:37 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 03:50:37 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 06:58:14 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 07:04:01 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 07:04:01 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 07:27:40 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 07:36:10 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 07:41:57 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 07:47:43 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 07:53:29 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 07:59:18 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 08:05:06 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 08:13:00 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 08:21:47 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 08:27:36 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 08:33:23 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 08:39:13 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 08:45:03 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 08:50:51 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 08:56:40 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 09:02:27 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 09:08:16 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 09:23:45 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 09:32:34 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 09:38:23 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 09:44:09 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 09:49:55 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 09:55:40 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 10:01:27 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 10:07:19 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 10:15:13 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 10:24:00 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 10:28:56 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 10:34:44 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 10:42:45 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 10:51:32 kernel:kmemleak: Cannot insert 0xffffff806e24ff40 into the object search tree (overlaps existing)
> Aug 15 11:03:53 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> Aug 15 11:14:55 kernel:kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220815124705.GA9950%40willie-the-truck.
