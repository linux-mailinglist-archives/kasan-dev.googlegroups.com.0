Return-Path: <kasan-dev+bncBDBK55H2UQKRBEHS7PCQMGQEIJG3IGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C34DB493CA
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:41:06 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-45ddbdb92dfsf16279575e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:41:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757346065; cv=pass;
        d=google.com; s=arc-20240605;
        b=kAChEGcJKZjSp7e6/6n6CrLlf45g6/17+igkJYGfKn9/yPh4YKSmenJ3QU2tyAYeX5
         kIvEX4EXEJr8xsPe66EcYit5Zana5UDfJRcMQfSwqWB/pFQq5q+ZpNCp8Df+Q4nPc47e
         SxfttPLzC9cAyQktibvlDyM2lS+wPicAd0LGEuJhbuEZ9Z9KM7S/bof4pqwHlCBpM6cB
         ooYotU89qTdJJrdeBYCziR6lceverRcP9+MuD6KPCoBbLGKdQjp1wSqNETDqfs+xzD5b
         qjomGEoV9JEf3J7UMAmMpRi3GxW8Uk4ZetlAA23x4MIqnBcalqKDtbs+MHjXa4PMAVm5
         c9Vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MThHiUFvakhBMXG4Cb0sojoA3wVhZ5ShV0Kv5/h+0ao=;
        fh=KYuKWaEd0/gYLXqOS2dTenpm0kfi7opOL4Ne8hCDzFg=;
        b=P+niFjUH7VImkHtX/dpNfROKP0bxzWTwSXE3Fho78eK7IOg0r8sI782e5gWPE8GnsK
         acnBTNmn5uBqxZsOV4qQGdtpW4dbiKjeFGKLbM6gnGP4ebr8gy0gCJQcmDl1e8/oMPnT
         BKJtCtXfnpVy+cqME2kEOxo2cBWsW/xf8hHb1wDd2v+46fs8VZ05E2b4xOWvfC+VJq8E
         pdxqnvyrLJBoURJKS0xWAbw6loTtvoU2ilkcYpL/rrfKBfG9CCoFV6Jrtgu1mKkhwn7o
         Pze8dS3gXdIDyUkSGKerUxRQWQD8t5hd1qIu/ZyNNLjMZEz+FgJIw076XXrcnD0LM1Ro
         S/3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=DdCdk6UH;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757346065; x=1757950865; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MThHiUFvakhBMXG4Cb0sojoA3wVhZ5ShV0Kv5/h+0ao=;
        b=bfmLL4f7fEbbT6LsXrniX4zBTKUO6xFuvLuxtYqQ8aiFEmdd2/o/yiO5fVH4qByccF
         hBsXUCoVIE/7PxTE/1krl0a7bK2Mw0uJ4I6A++5wFpFfeALvQ0QzyGKvdR2R47QtoIDq
         OTNVeHaBpso3dEOag5Gd3zQ5lWktQdgP0Pi/AbTAelAkr+O+v8nFsOlim1H18R9kB1sq
         364CQa8izCYC9Lv0/OCWINVU45eKd6l15HETWQNRBk80LcJz9HqXQuBhpa5bD8y58VZ5
         FbNwjPoCPtXNUVIXsLTXCOMgvb075wRTsKCRJdP75I3NFcDO2/K5bvkMl/WX2Api20AI
         BcIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757346065; x=1757950865;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MThHiUFvakhBMXG4Cb0sojoA3wVhZ5ShV0Kv5/h+0ao=;
        b=w5MPbF1htqLPYaBVbqqcZK/ZQDeXiDFldgftd2Lf0jGpGeU0fX4+1pGpKxelJmA1Xl
         WQqmQ0py9duf6aFyarSSwvqy/zJbIqGlZXz5KLD9NirC9a7xhL/bJB7sg4Ha7oGN4hpO
         fcIxhpKBz1OiE0mL483K7BKKiacoylCVDDFvfTNnGA+tJArYylmfi/JyiNbLjx/evuzc
         ftqnVC4i9eraUusXf9dNU92PIOvLswBSfqNNAE5zIXJyRkoLkUGgj7o1DyTCUt7/3s9H
         LGnbtub6DyPGvmGdXafJ572Cwz9l3sJhxmCBb9VbzF837pt0imw8ZHjimpIKGV6WWbgf
         /azQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX5jVHdnfffJb1FzWGtCN0WUXwMh3a/ohDL1tyY9WF5BC1Ilg2mfYJsj16hegGwnMVGq3ZsqA==@lfdr.de
X-Gm-Message-State: AOJu0YwUClBhrwZrE5PIxtuZOypa6NzmDZPjevkfew5W+a3cwrd4gt5W
	phGn5BTUuHdG7dX8FezlpOjHHwcLTOeC+TMnE1B3GFADngNqGYa6zdpE
X-Google-Smtp-Source: AGHT+IFOc1oT/e4hyXB5W2yMjmPs82zowBceVjZmjHtSTCv74PsSmGlNdJ2wZwcFJV5aHz1loNFoVA==
X-Received: by 2002:a05:6000:3101:b0:3d5:319d:a95c with SMTP id ffacd0b85a97d-3e64392b88bmr6686147f8f.39.1757346065211;
        Mon, 08 Sep 2025 08:41:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcx+obM0rftOcOzTy8Ny/2BWaaPgHorvdB7sjZ+bRwEvw==
Received: by 2002:a05:600c:4f56:b0:456:241d:50bd with SMTP id
 5b1f17b1804b1-45deb706441ls3242285e9.2.-pod-prod-04-eu; Mon, 08 Sep 2025
 08:41:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUlo/OIVkiP0YV4m5VnAE+SDPzLOKWv8DpDnM7JbBviB/NHitXFYVOOMmaXGgUI7yaCDnQ4Nm+Kp1M=@googlegroups.com
X-Received: by 2002:a05:600c:1c08:b0:45b:7dac:af41 with SMTP id 5b1f17b1804b1-45dddee31b4mr74705095e9.32.1757346062025;
        Mon, 08 Sep 2025 08:41:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757346062; cv=none;
        d=google.com; s=arc-20240605;
        b=MF946P8ZXOEAPZV2Z5cb/82/rHa9nYG3bYElU8p5Pn8LstuOEOVkrGjpPu7oGpY9l8
         IstFlBJz04fxCX9v2RZKOGk3qEN4kHWZ6v0ZYpjHWqrZHWxHdizg1AfS2N1yQrwgimPb
         RVHCP5joBFXY4E3Lgs/9WAsIda1IZaZB+FJKpQqv+Fp2s0inO2Jg29ayoArOG7cGvo04
         w/zwD15Wh8vhiPdy3GeYrkHl3AudtAceiuZIC99DE5Lvj6ONrnRCz8Ir6N6OAZ0upfs8
         jzb1pNDxyCYmW9drUpPlAdxRK7cCjl38sDHGg4OTC0dXDpE7jQyOGvbDPoOdVT1IHzxm
         f5ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=i/NTHz2QW7PrsPI9dqlnUBz3BBd0hMA6KRgZuxingf0=;
        fh=/VQt35BaQ4BGPRlk/c/1bxVgilIVwwPQ7yAE8MRtwj8=;
        b=eXmGnKNBzBM7Y+5Fa9OdxIjSeGRwKeYqID+zdeqV5Ap96L9Nh3+27Gvb5Ya2YXZ6JL
         nlmzwyTUhtmwkDeIE/eq7qN3cE4pHpQA8Ll1Y2HlDs7mfve7/wDktARtDjl8CnW0YM+e
         9DLY9WUJ9DfxRv8wHsjrltKOJeXYJ/NCecd2GgtUFf20SHaCJ+6vZDfVrdqGHBd7ZzDt
         foZIbz22zUHfyCAik+XzUVX/2Qn6Vle5oHWo2+j/Jydheyln4v/3cN7OVfkzQGGQK36B
         fnQUTdUUYitTajmQt6uyBNxldBSgqRmUYE7jtdBy9q51g3X8+n1DBWK32Bq3AktUABGT
         QlxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=DdCdk6UH;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45dd058fa6csi3485905e9.1.2025.09.08.08.41.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:41:02 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uvdzB-00000008yn3-1EwA;
	Mon, 08 Sep 2025 15:40:53 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id D2D5E300230; Mon, 08 Sep 2025 17:40:52 +0200 (CEST)
Date: Mon, 8 Sep 2025 17:40:52 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: nathan@kernel.org, arnd@arndb.de, broonie@kernel.org,
	Liam.Howlett@oracle.com, urezki@gmail.com, will@kernel.org,
	kaleshsingh@google.com, rppt@kernel.org, leitao@debian.org,
	coxu@redhat.com, surenb@google.com, akpm@linux-foundation.org,
	luto@kernel.org, jpoimboe@kernel.org, changyuanl@google.com,
	hpa@zytor.com, dvyukov@google.com, kas@kernel.org, corbet@lwn.net,
	vincenzo.frascino@arm.com, smostafa@google.com,
	nick.desaulniers+lkml@gmail.com, morbo@google.com,
	andreyknvl@gmail.com, alexander.shishkin@linux.intel.com,
	thiago.bauermann@linaro.org, catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com, jan.kiszka@siemens.com, jbohac@suse.cz,
	dan.j.williams@intel.com, joel.granados@kernel.org,
	baohua@kernel.org, kevin.brodsky@arm.com, nicolas.schier@linux.dev,
	pcc@google.com, andriy.shevchenko@linux.intel.com,
	wei.liu@kernel.org, bp@alien8.de, ada.coupriediaz@arm.com,
	xin@zytor.com, pankaj.gupta@amd.com, vbabka@suse.cz,
	glider@google.com, jgross@suse.com, kees@kernel.org,
	jhubbard@nvidia.com, joey.gouly@arm.com, ardb@kernel.org,
	thuth@redhat.com, pasha.tatashin@soleen.com,
	kristina.martsenko@arm.com, bigeasy@linutronix.de,
	lorenzo.stoakes@oracle.com, jason.andryuk@amd.com, david@redhat.com,
	graf@amazon.com, wangkefeng.wang@huawei.com, ziy@nvidia.com,
	mark.rutland@arm.com, dave.hansen@linux.intel.com,
	samuel.holland@sifive.com, kbingham@kernel.org,
	trintaeoitogc@gmail.com, scott@os.amperecomputing.com,
	justinstitt@google.com, kuan-ying.lee@canonical.com, maz@kernel.org,
	tglx@linutronix.de, samitolvanen@google.com, mhocko@suse.com,
	nunodasneves@linux.microsoft.com, brgerst@gmail.com,
	willy@infradead.org, ubizjak@gmail.com, mingo@redhat.com,
	sohil.mehta@intel.com, linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	x86@kernel.org, llvm@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v4 13/18] kasan: arm64: x86: Handle int3 for inline KASAN
 reports
Message-ID: <20250908154052.GG4067720@noisy.programming.kicks-ass.net>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
 <9030d5a35eb5a3831319881cb8cb040aad65b7b6.1755004923.git.maciej.wieczor-retman@intel.com>
 <20250813151702.GO4067720@noisy.programming.kicks-ass.net>
 <nuzda7g3l2e4qeqdh6m4bmhlux6ywnrrh4ktivldljm2od7vou@z4wtuggklxei>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <nuzda7g3l2e4qeqdh6m4bmhlux6ywnrrh4ktivldljm2od7vou@z4wtuggklxei>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=DdCdk6UH;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Mon, Aug 18, 2025 at 08:26:11AM +0200, Maciej Wieczor-Retman wrote:
> On 2025-08-13 at 17:17:02 +0200, Peter Zijlstra wrote:
> >On Tue, Aug 12, 2025 at 03:23:49PM +0200, Maciej Wieczor-Retman wrote:
> >> Inline KASAN on x86 does tag mismatch reports by passing the faulty
> >> address and metadata through the INT3 instruction - scheme that's setup
> >> in the LLVM's compiler code (specifically HWAddressSanitizer.cpp).
> >> 
> >> Add a kasan hook to the INT3 handling function.
> >> 
> >> Disable KASAN in an INT3 core kernel selftest function since it can raise
> >> a false tag mismatch report and potentially panic the kernel.
> >> 
> >> Make part of that hook - which decides whether to die or recover from a
> >> tag mismatch - arch independent to avoid duplicating a long comment on
> >> both x86 and arm64 architectures.
> >> 
> >> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> >
> >Can we please split this into an arm64 and x86 patch. Also, why use int3
> >here rather than a #UD trap, which we use for all other such cases?
> 
> Sure, two patches seem okay. I'll first add all the new functions and modify the
> x86 code, then add the arm64 patch which will replace its die() + comment with
> kasan_inline_recover().
> 
> About INT3 I'm not sure, it's just how it's written in the LLVM code. I didn't
> see any justification why it's not #UD. My guess is SMD describes INT3 as an
> interrupt for debugger purposes while #UD is described as "for software
> testing". So from the documentation point INT3 seems to have a stronger case.
> 
> Does INT3 interfere with something? Or is #UD better just because of
> consistency?

INT3 from kernel space is already really tricky, since it is used for
self-modifying code.

I suppose we *can* do this, but #UD is already set up to effectively
forward to WARN and friends, and has UBSAN integration. Its just really
weird to have KASAN do something else again.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908154052.GG4067720%40noisy.programming.kicks-ass.net.
