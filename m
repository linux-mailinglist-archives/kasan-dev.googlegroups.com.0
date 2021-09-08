Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ7E4SEQMGQEYNV646A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 575864040CA
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Sep 2021 23:59:04 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id x125-20020a1c3183000000b002e73f079eefsf1682183wmx.0
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Sep 2021 14:59:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631138344; cv=pass;
        d=google.com; s=arc-20160816;
        b=1ILweRtyGwbvkocrwPOyvZTvBxzPe8qMyoNaOPCb+QHK74j3M5ln/bglrLG5oLNs8V
         rahFBbgQz3ptw4PDW5u64zI8MUtV2Fv22tm/9RVvwjrvzshtFLlt5YYtbd+nsD8dgaRE
         kKe7yVo7CgE5tL1PpU9WYKkjIps5Th6pMb4grwJDvdUIPS8Wfja38i2NkATBsHMV5kUq
         NWp8/xdV9ICsoGQIZNsHLDUKpNbIezSRse4KjrRhvZoRuWbofPw67OMhck+g1+e/kYyC
         9fT/n+kH3Z+/nZayOefn0jetGU+5VqJ3l7Llq9IPmAkoYc8zUw+lNU5gKt4x+fbnxwWg
         k3jQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=T7HjAKV1IAoaxOwxAbOy++tSH+OMacvPrfIlAYamuXg=;
        b=oHzpGwEnvNT7xxE6EX5HwJE1WdT0wJIjtRrY6K6VG5/sPNmGA/WHEmqasbk39O7cwZ
         fw59vdACYe2gBJ3RHvXYgZeDPe6fnpTK3yNRFnvdIoaO40Um+95PhpjluS169BDIUexA
         O+gDshCxidD5S0VIGRFkDSvlslWGx5ah58dck3IKJlA7kJfMM5f2w8URYGfxjS4as0XL
         oqpG+8JKM3MLd1WbDBfilgJxXU72RGOT7SZsBRhIC5mDgvKeR8qPOdU34FG8LRnLezYw
         sskw1r5QG+7RfwpF8Op68AiJtQJJq7fkRFaIxNpClvO5qnaWxWMhl534J3YbIX7GbmZH
         h8kQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Db08IbxJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=T7HjAKV1IAoaxOwxAbOy++tSH+OMacvPrfIlAYamuXg=;
        b=QEQzIzNig0YDKkyURRffsyvyKsAZDhgLniHJiv47PD5oQKf6cRzxEh0ph3o1xEaMKC
         z6UEPvzKL1ZCtWnL4elN7JZCfJF2NUpU29MqaEYvLe58/ZuFTjp08EBpWFqi7hSS2pdr
         8KDI+u+WpIQhO8fjnmhIT5eK+2sAY2UygiaMXBo6Jl0iHZvW2R/6gM/E0bq5WA7JMRGa
         8z7pSx9AGezEtgRHNoP9ZvXbsgRXLKozR7AydZcBWgwl4HFYgKV+cbBBn2ZiypVeX1N4
         ec/22rPBvIwfbav163slQUBbJ75Gk7UZQQXcQbm8WemB7pNjL4n8T04kDmDJmURCRZok
         /l6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=T7HjAKV1IAoaxOwxAbOy++tSH+OMacvPrfIlAYamuXg=;
        b=ZE+3eMFQxiEXsKsOBLxlIffpsJT8qf3TTf1AtsmuaG4xTZVTBqvwFTWMTw29k0xB4A
         K0vgJF82kxUQTDK/NrDo0hJhE1YLfsSzrBD4uGg3oTE/5kWRiCja7bLZR+ZQtHfQ39tS
         jdM9zAiLOBVyjafu1CJDkfiqrfIZFOiXnhHEu1cXdI8mEodCsAX8DbpovkXGeyXX4OaJ
         pibFlHaqQDMG5U8etG9jMXj8IB+o/bnizD3ruEy7Uc93MklQothuVauiYpsQ8aTIgDqR
         ht8xVQukBkFxofwJGaGTGVwiR1nch1j01h9tusU6Yfuv/AUAxMUAulsoj4iBS60OKSKM
         HK0A==
X-Gm-Message-State: AOAM531CLnOIlhHveSiZRELqDqCs2ZGpEeLyAgIDcfQkI2U5Ghi9RVUw
	SSCkGJ+LcPR0XbZqYaaVtyA=
X-Google-Smtp-Source: ABdhPJw/0lpmUkn5WOfwy7klZPt+2sjm+xuR8Y77qwTZnyj4qFA8LCepI0nmqpCnjXeGIgUZgSvmPA==
X-Received: by 2002:a05:600c:c8:: with SMTP id u8mr323323wmm.47.1631138344094;
        Wed, 08 Sep 2021 14:59:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5120:: with SMTP id o32ls29686wms.0.canary-gmail;
 Wed, 08 Sep 2021 14:59:03 -0700 (PDT)
X-Received: by 2002:a05:600c:a4b:: with SMTP id c11mr314797wmq.97.1631138343074;
        Wed, 08 Sep 2021 14:59:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631138343; cv=none;
        d=google.com; s=arc-20160816;
        b=NKSnrMu9+Z3wLt2MnAnFsPO+CeyRrYHsFte3noVsEa29t69JgHqTT8/Hu1pMRsdt61
         swQMA8990cfnmyk3tX/hGykQCJwKXXTpDcWy9h0uI67GUJiOcPKWHRVIvbdI4TxJx/uq
         T+T67bODmMHExkXUWmHS4bgFFROvPUjmrnr20SbyDyzqT4aLGlCMrTFC30CAkNV+t1QY
         pTFbZ7Cro3FFo0x/rYzKK7lA6kPx+ajnpUdjo2WmI3ooMMUsNYxP3r5gL5I279i8sW/K
         DtzcYQUlXPE9ds2VY3BUG486OFZBwpQu9vxM9gsCQg3zWzqhsr39PqA1Jr2Pg/x7lZHF
         eBhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+LR8frgXEe3ow5R83HHc128uph7ex7SBJh9j6e+S9jU=;
        b=iAJ/Pv6ab4jYlN/g5lN99g9xzmCTxgwqyLqHowvezHbHvabunZtFkgRCrG/xNH8j3U
         JnFFt108pyeovbpkLKFahGW30bdD0CQqX4UAXiPqbkjRN0JhXZAOHYB9v5mpvNEkBOGL
         WBB1GA+8xQ26e/vX8k0IrKf9KGzvwYUEXAUeTrakB+ABO3B/Lgl0gPDy2aLIIrlcYWrf
         w1o6tukIel+jnh0XXMfa3l0KdWBi1SEdlwMMuZDehlR9f9V7pSmQO32f40emBs2vucjM
         qwKFWaWRPoeK9xzf9f3zB6sX9npFteF3zYfqh/r/iClEt9Y/vfJrreK3UcyqtJbHFu0j
         RkAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Db08IbxJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id s80si314651wme.2.2021.09.08.14.59.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Sep 2021 14:59:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id b6so5374151wrh.10
        for <kasan-dev@googlegroups.com>; Wed, 08 Sep 2021 14:59:03 -0700 (PDT)
X-Received: by 2002:adf:f208:: with SMTP id p8mr418298wro.379.1631138342436;
        Wed, 08 Sep 2021 14:59:02 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:6c42:a08d:7652:61ef])
        by smtp.gmail.com with ESMTPSA id o10sm358689wrc.16.2021.09.08.14.59.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Sep 2021 14:59:01 -0700 (PDT)
Date: Wed, 8 Sep 2021 23:58:56 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Guenter Roeck <linux@roeck-us.net>
Cc: Nathan Chancellor <nathan@kernel.org>, Arnd Bergmann <arnd@kernel.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	llvm@lists.linux.dev, Nick Desaulniers <ndesaulniers@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>, linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH] Enable '-Werror' by default for all kernel builds
Message-ID: <YTkyIAevt7XOd+8j@elver.google.com>
References: <20210906142615.GA1917503@roeck-us.net>
 <CAHk-=wgjTePY1v_D-jszz4NrpTso0CdvB9PcdroPS=TNU1oZMQ@mail.gmail.com>
 <YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain>
 <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
 <YTkjJPCdR1VGaaVm@archlinux-ax161>
 <75a10e8b-9f11-64c4-460b-9f3ac09965e2@roeck-us.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <75a10e8b-9f11-64c4-460b-9f3ac09965e2@roeck-us.net>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Db08IbxJ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as
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

On Wed, Sep 08, 2021 at 02:16PM -0700, Guenter Roeck wrote:
> On 9/8/21 1:55 PM, Nathan Chancellor wrote:
[...]
> > I have started taking a look at these. Most of the allmodconfig ones
> > appear to be related to CONFIG_KASAN, which is now supported for
> > CONFIG_ARM.
> > 
> 
> Would it make sense to make KASAN depend on !COMPILE_TEST ?
> After all, the point of KASAN is runtime testing, not build testing.

It'd be good to avoid. It has helped uncover build issues with KASAN in
the past. Or at least make it dependent on the problematic architecture.
For example if arm is a problem, something like this:

--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -71,7 +71,7 @@ config ARM
 	select HAVE_ARCH_BITREVERSE if (CPU_32v7M || CPU_32v7) && !CPU_32v6
 	select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL && !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
-	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
+	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL && (!COMPILE_TEST || !CC_IS_CLANG)
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_PFN_VALID
 	select HAVE_ARCH_SECCOMP

More generally, with clang, the problem is known and due to KASAN stack
instrumentation (CONFIG_KASAN_STACK):

 | config KASAN_STACK
 |         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
 |         depends on KASAN_GENERIC || KASAN_SW_TAGS
 |         depends on !ARCH_DISABLE_KASAN_INLINE
 |         default y if CC_IS_GCC
 |         help
 |           The LLVM stack address sanitizer has a know problem that
 |           causes excessive stack usage in a lot of functions, see
 |           https://bugs.llvm.org/show_bug.cgi?id=38809
 |           Disabling asan-stack makes it safe to run kernels build
 |           with clang-8 with KASAN enabled, though it loses some of
 |           the functionality.
 |           This feature is always disabled when compile-testing with clang
 |           to avoid cluttering the output in stack overflow warnings,
 |           but clang users can still enable it for builds without
 |           CONFIG_COMPILE_TEST.  On gcc it is assumed to always be safe
 |           to use and enabled by default.
 |           If the architecture disables inline instrumentation, stack
 |           instrumentation is also disabled as it adds inline-style
 |           instrumentation that is run unconditionally.

This is already disabled if COMPILE_TEST and building with clang. As
far as I know, there's no easy fix for clang and it's been discussed
many times over with LLVM devs.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YTkyIAevt7XOd%2B8j%40elver.google.com.
