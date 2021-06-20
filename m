Return-Path: <kasan-dev+bncBDW2JDUY5AORB6GGXSDAMGQEBDZ3IFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id C1DB03ADE16
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 13:16:08 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id h104-20020adf90710000b029010de8455a3asf7032156wrh.12
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 04:16:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624187768; cv=pass;
        d=google.com; s=arc-20160816;
        b=pYIal5kv/RudOpyOd1WOqBtNpHKjMICATkP9NFj1h71UFmHLdPDN/AKP0k0an1+aL/
         wN4WfP+GqTIUI8jjeFojQOExxevnA15t7rNsalsCD0/Zl+tn+bDZ3DALZAja/X0epkY4
         07UZ5dmMiFz0tFf5gUfYcdziX09HpDMOCN5CKL8fng5H7Yoq/kp3Dihy7DjbIeVphhdP
         WxcJ/AQXIhlKqvkMoup3hI15SKPe8OFNBDpHfMjNd8KA4u6WOAh0Qid+YF5RFNUJGugz
         aHcMJyWAUbNgzdTApmCpsNIXdHKY1J482dMtcaf8PjajJqmxNQKWQmGsISI2gTYxW8bj
         /hrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=C9V+N5ftIovf5HNyVMX0kxm4VoN9PZGrJv/4syvYOHU=;
        b=zcj06m2Sy9X6sqYcwhr7gJ1gmUM7p10LMhSReGc69C6iaRX7UhQyoQftQfMHh90d1N
         4RQpTgllwjTfrXq/7eHVCx3XYvAIYNCLpelZSa3zHcunapLaNAqFpexLreZL4smww/f8
         94Z9iMXHag4KdCbMmVrXPVuQEk+V3SCT3/h+J+rUjPc4D7OXHWD4xdfFi/bOQ59jFE60
         4w/9bEIutJjRySXPFovBQW4upKr0/aq6ge9JsPFpKU3qfQWFbmcVjUJTtjuOLxVjaxqt
         +E5rW4iwZVJQDPDIfpiC3hU1ILNYtHYDhLdC5rDLqAwBSm4kXIwLgsJgqJHCFR0t/Bnj
         gJQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="jN/BusFB";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C9V+N5ftIovf5HNyVMX0kxm4VoN9PZGrJv/4syvYOHU=;
        b=WIFQd9yWHoloaG3XnVMlztNM0LdWiAaFM/2znCjVK86fU2UCtkSK6ik17deJM5ldp7
         3PT88R4Yw5r6/5Xlt/Iq1oXbyOEI5xU7GsLBcwVUOMCe/Kzku4MLCc47igdZ5NmJgDWB
         gFttI86COpQdZiqfQuxEqAQHu61uOxyFtQmxlvILSpQ6nqQbvZ1jzHuXAPZgtqtht6Xk
         dY/woQTC7HtTJOsDiIN4mpegdfFTEDO+vl+/MWT3nIpfhOTyr5pDslXMd5DxDq+ph6xr
         a6QqzlBNTys7SdG2bWO0eJLkNrwaCevoYscbokV+bO5oCY2wJWs1xa9ThjS4x2KFTIAA
         RKhw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C9V+N5ftIovf5HNyVMX0kxm4VoN9PZGrJv/4syvYOHU=;
        b=gN2MIwxMREDqS069BiZhO0JoJGV5KAipzmhMaZC5hc6FeJdWaNWonpTl+KB0AWrMsP
         N0vcROvGCBysRMlS7xLEYGqPGIeX/wMTYPNM6rh3IOsrK+BNpDkBHwLutumLRO0ADNRj
         Chj97dK1bTFrCsoVgfx3AUAo1BJa05yx5I9xVC7G1+eMxzOUWnpYgYzs/AR7Rv3/0TIM
         LdWDCnHVB4YCgsD+KFGfRS9MfXQT5biPUEb4m9XXof0OOcNOEeVt7v0oe//XsojlHrZq
         3j9HcDu3BOXVwELI735db3TyzvparW1EuuABPyOE4rRT00pwqP5J9yPNBXKd+oAGjMz2
         VzvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C9V+N5ftIovf5HNyVMX0kxm4VoN9PZGrJv/4syvYOHU=;
        b=H1jzRQPcvWxysdbwGn4MC+AARGtl1v4C/EL8e1pE25/AOtsw0+/ZRd0FUm3IXynzjs
         /9tlrULgBvzU7DyhX4FHWeZqA3q8XiBcjO7CIZW5a5vgAcqFsYVhf5bur3m2Q1+x9TNM
         ucYU9srJAcsiE/mjb1sHzq7AjL/PwrUNQtkDpAOQm91mQVDzbVJaUVsehxCz8x35srX2
         hmEXgDJOhJmNk09ZB4wG1TQ+Q/lQ0UT9DplnJBRZuGbbigPAKBPAK4CXFdceqSA1PBmZ
         UsBG1kdNslEsadUcJne5baTTWvoRvgpP7SEpKqsTCgKTmORbMbpezlV3poeHXW1uxSqL
         2U8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321ou16vpO/o9KriJir2H/9rvbrb9Tea/RTvWIz88wTzp49wyCL
	MWrSoBcLwplfpoZRvgxPuR4=
X-Google-Smtp-Source: ABdhPJzhJh4pmJUtutenfOt2DF895gc2Cynk48LPQuR2686Zxd1Fe0da43gFhws1xHINCEJITXDzTQ==
X-Received: by 2002:a1c:4c0c:: with SMTP id z12mr568182wmf.0.1624187768511;
        Sun, 20 Jun 2021 04:16:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a141:: with SMTP id r1ls3319624wrr.3.gmail; Sun, 20 Jun
 2021 04:16:07 -0700 (PDT)
X-Received: by 2002:adf:9031:: with SMTP id h46mr22870201wrh.125.1624187767744;
        Sun, 20 Jun 2021 04:16:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624187767; cv=none;
        d=google.com; s=arc-20160816;
        b=E+TmMWOSmJQjAVByLMZ9GBn+BtASTRGpCj2m6P9QX/O4s8w1xLx0ehGX1u5yi3rC19
         wK6gp8mj4SqFydAi0GNvVMeRFGtzfZYk51LPXOQljqiTKGQ8TccDa6HKuaUD98o88Fof
         bHNtWCyZgzsEbO0rpBUlXkWpJQCkb1klQLZn7B5rl+z3vh1RB/ySfGuyu/wNgq/oKohn
         rk+ciL9JzDsdJr6WJhJDksE5al0ZDgmMQCg4+sDT+wC3GUV9o+45cX6j1lNfchGsWiJJ
         QFO3CRQIp0amEUrsHChMhdWeTnpqqkxYUfNaxSFNpEJX2dGA5twzCfIvZUwgnkGTpyro
         b6UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V5/7gChl8XVHJy56wbmIvB0M6WNYjYtPIXj58muV060=;
        b=T15TbtlsMzZ8shtoXI7C+3P0zqSOnXG1wSOSac7dKSlIRpV5WCdCLuqdFjzMm+qCRX
         GzXwzWxucUB7Um7DUQmRkgyREaNvyumY4CqdQmguXBVrHOurb0a5s57Q9l73nD+t+WAH
         kY1ibvd0AN1pVo4/PTzGLFe0y4Qcmtva7i1A0OKtMhH5/jLC7TP7WcAPD5HetfJdusQ3
         tprwFMhx4pFt5ExayGMpHMKBU2XQuXXKnZt5TcRXI8qBs5jvnktCCdMQZVEhqmFWv7Eh
         RqhsL5AI42HBFe5ScKl+QCSJNK4NEGRJN92zaHZCYC90DpNynumzINyGLKVW4ldbNqOH
         kqug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="jN/BusFB";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id z70si717727wmc.0.2021.06.20.04.16.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 20 Jun 2021 04:16:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id c7so13979467edn.6
        for <kasan-dev@googlegroups.com>; Sun, 20 Jun 2021 04:16:07 -0700 (PDT)
X-Received: by 2002:a05:6402:42d2:: with SMTP id i18mr15359424edc.168.1624187767478;
 Sun, 20 Jun 2021 04:16:07 -0700 (PDT)
MIME-Version: 1.0
References: <20210617093032.103097-1-dja@axtens.net> <20210617093032.103097-2-dja@axtens.net>
In-Reply-To: <20210617093032.103097-2-dja@axtens.net>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 20 Jun 2021 14:15:47 +0300
Message-ID: <CA+fCnZecs6jVgMmVq0N1iGRO4Cm+rbm5xyj_sMdKkxhX6-nvaA@mail.gmail.com>
Subject: Re: [PATCH v15 1/4] kasan: allow an architecture to disable inline instrumentation
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linuxppc-dev@lists.ozlabs.org, christophe.leroy@csgroup.eu, 
	aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="jN/BusFB";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Thu, Jun 17, 2021 at 12:30 PM Daniel Axtens <dja@axtens.net> wrote:
>
> For annoying architectural reasons, it's very difficult to support inline
> instrumentation on powerpc64.*
>
> Add a Kconfig flag to allow an arch to disable inline. (It's a bit
> annoying to be 'backwards', but I'm not aware of any way to have
> an arch force a symbol to be 'n', rather than 'y'.)
>
> We also disable stack instrumentation in this case as it does things that
> are functionally equivalent to inline instrumentation, namely adding
> code that touches the shadow directly without going through a C helper.
>
> * on ppc64 atm, the shadow lives in virtual memory and isn't accessible in
> real mode. However, before we turn on virtual memory, we parse the device
> tree to determine which platform and MMU we're running under. That calls
> generic DT code, which is instrumented. Inline instrumentation in DT would
> unconditionally attempt to touch the shadow region, which we won't have
> set up yet, and would crash. We can make outline mode wait for the arch to
> be ready, but we can't change what the compiler inserts for inline mode.
>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>  lib/Kconfig.kasan | 14 ++++++++++++++
>  1 file changed, 14 insertions(+)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index cffc2ebbf185..cb5e02d09e11 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -12,6 +12,15 @@ config HAVE_ARCH_KASAN_HW_TAGS
>  config HAVE_ARCH_KASAN_VMALLOC
>         bool
>
> +config ARCH_DISABLE_KASAN_INLINE
> +       bool
> +       help
> +         Sometimes an architecture might not be able to support inline
> +         instrumentation but might be able to support outline instrumentation.
> +         This option allows an architecture to prevent inline and stack
> +         instrumentation from being enabled.

This seems too wordy.

How about: "An architecture might not support inline instrumentation.
When this option is selected, inline and stack instrumentation are
disabled."

> +
> +

Drop the extra empty line.

>  config CC_HAS_KASAN_GENERIC
>         def_bool $(cc-option, -fsanitize=kernel-address)
>
> @@ -130,6 +139,7 @@ config KASAN_OUTLINE
>
>  config KASAN_INLINE
>         bool "Inline instrumentation"
> +       depends on !ARCH_DISABLE_KASAN_INLINE
>         help
>           Compiler directly inserts code checking shadow memory before
>           memory accesses. This is faster than outline (in some workloads
> @@ -141,6 +151,7 @@ endchoice
>  config KASAN_STACK
>         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
>         depends on KASAN_GENERIC || KASAN_SW_TAGS
> +       depends on !ARCH_DISABLE_KASAN_INLINE
>         default y if CC_IS_GCC
>         help
>           The LLVM stack address sanitizer has a know problem that
> @@ -154,6 +165,9 @@ config KASAN_STACK
>           but clang users can still enable it for builds without
>           CONFIG_COMPILE_TEST.  On gcc it is assumed to always be safe
>           to use and enabled by default.
> +         If the architecture disables inline instrumentation, this is

this => stack instrumentation



> +         also disabled as it adds inline-style instrumentation that
> +         is run unconditionally.
>
>  config KASAN_SW_TAGS_IDENTIFY
>         bool "Enable memory corruption identification"
> --
> 2.30.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZecs6jVgMmVq0N1iGRO4Cm%2Brbm5xyj_sMdKkxhX6-nvaA%40mail.gmail.com.
