Return-Path: <kasan-dev+bncBDV37XP3XYDRBK7J3TUQKGQER5S5ZNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id DA32C71CD5
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jul 2019 18:24:11 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id l16sf10049709wmg.2
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jul 2019 09:24:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563899051; cv=pass;
        d=google.com; s=arc-20160816;
        b=OAqXD2U96j1tGnZgz6pUzwmqsTHwTXoCowDmTFt8HQAZDTOFG2VERZUWlmoJS/sF/x
         uDSif0fldkNiNH/Dq5x9FBgOkDX9mXIvGfhNKpnfxR/OOpLE/vyfa4X2xvpueDDdFFjp
         3/eC4gVJ78yj3hX9ZHi66lS16AT9WltBzz28ZQa49JOI8MUoq/ayUdj2cWaPRQYagR+/
         2ZZnvlQVN5NmqdXzhuN0gNs0i6T74fN5JI+iDNWEN/8LwIH7gev6ryKT16rW8KnuAoKa
         S7qVHccD+qvo/Mre7PKplUt8AbOktLJ4xng8xEoocHP2B5kO61NtqWwq6EQJ1117aafk
         2BZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=YTz/d6RgJw7vG8dlI9dMr9qb45edQKOrafBdBPJ53DY=;
        b=jxqfzRHaeftsTseUre4K2BuVGXj9AixWHBILxgzce1z5ZekU0gwwXHPo3U58uajfGt
         p5B3ooq7Q/MqOOdvMOA4pip94lUNF9fAe/fnJpBx4GNgwa/qW1ySElo4qYPZipNj9zYU
         U6AMeI3/6cC/sidfezYqQwy2Neo25/z5abPtyGMpdPwXtqFSEqvsb/rZ2dq5LI2mhD/P
         hHhj6oM7RRqS6HSfiUk6NYw1bDYeuRtKHe7tRH7BEU9qOlEGr3o/1ZWvIhKxIYElqchr
         3EgE1pUbVinUMVdxhHV7U11+qVf7rZCfOGFdUDnFPZ31CX9SbBLC9bmK9pWi035jl3GN
         cKZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YTz/d6RgJw7vG8dlI9dMr9qb45edQKOrafBdBPJ53DY=;
        b=j/iQFpedZHnetY3W8a0J/TnxLrtVXaCkc6IjKgOzafBE0p4x5I0aKzeu+vVdfClRL2
         HZtEszV42PI7MylIFbVCLIOMqZoCUJx0YqNNsb0IDjkWfbnoaTCiHSFHWVltsPPT00HY
         O2nIFk6GxSHS/OOjvD4aMivr1yHYrtmicyAUN04EUpf00d7M2BLHAVyFG5QZkW/AkhhW
         6EVmJXxHPbpYLtP+r6Gg9wsVJUj3o9U/aVJjXsENgoJkIebUTBddGdcjPmjlP67c2QEn
         aIVeVpeeWwmHWhvH8WF4xoljmO5JlP0NYebMxyOiC4x1JdCDx7yezjQfNbTJcoKzlqwO
         D3dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YTz/d6RgJw7vG8dlI9dMr9qb45edQKOrafBdBPJ53DY=;
        b=pzhfsoqXw97t8dgypXs4lcs78SXy1F7o7WQCR+4Z2NSEv+f9pJ4dxmKQ8MzdrSUrHL
         je1cxm+AvyBvPBjWjYHblju/tIGAejLbBa07uhSVNhvDsScVnB2ZrNVqn6IqGe7o2KbZ
         H9aOu9t0pMOFT5Ax6ledRRMJhCkvQGQ7G22Yk2FEXuts+8fEY9f2V0pT3uaJuDsd9zzp
         jeDK2y9p2zpu7kwFm4N00/c3sa/w5xuUYK65LpGoODFCdB5XTD6OfcHjFX6IDiDuMt4G
         z2khuEvIQ0SH1/ebWXHkjsE6u6IQZgaN8fxwMew1E0nB6w92cYn113STIR+ILx92w7Cz
         nlfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUI9RP+KdIaOxPSZ0lGIPNVdt54avN/NbOdHDYkaC4NqDkeDfda
	GLVgQlO7+itwnO6W7YELLSA=
X-Google-Smtp-Source: APXvYqwMTnusoQKftZ9/UUHnYZ1x1cdYDfINVyl+71FvyU1CzYp83cl9BGM0gEnqcxNyovGLmlWsAA==
X-Received: by 2002:a05:6000:1189:: with SMTP id g9mr44313776wrx.51.1563899051591;
        Tue, 23 Jul 2019 09:24:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4907:: with SMTP id x7ls11878959wrq.0.gmail; Tue, 23 Jul
 2019 09:24:11 -0700 (PDT)
X-Received: by 2002:adf:dd03:: with SMTP id a3mr35999842wrm.87.1563899051059;
        Tue, 23 Jul 2019 09:24:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563899051; cv=none;
        d=google.com; s=arc-20160816;
        b=FHvyFb1kszqytqq1aDQK3g0Rp2FE4kF513Dxo/HfUArsoiPKCEEiLZcZ0+z7axXpJg
         ITk40O3ixuNddENAoWume1OKbP1f+jtBvqEVqX6+a4KGNRxz66fMK+XvKdaRqoHdw0gM
         95nyLQOlmYUx6pzBAAClrV7PaAufopyBbH9FPDM1Wbf5KfK2z3I7E/JdboCWc+WvLgNh
         BheR0kK7KqtKGI3rYRkhGFLN7DIN4EZtr6OUTaP2jEMASolIYNU893ZoVMzonN0ltrjA
         KpDffpLMa5ru/B3N8h/qV1NN6oKHq5ePfPc2Fkp/W+N1FMpgUYmwKmjBbs6KskaJbAoj
         Z8FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=MMJBYXKZKq/K0xhBsKvlfCTzpFlBz/mgOHrf5z8HQi0=;
        b=jhLT/qvm9M/eWqf1tu77xfXV7+VQSi0/TLZBUN1ODEoS57wbdhGlZt3PQTP9SMte/L
         +C1/G0D31RYSWHgAVC/q2rPGwTYkqQ7Pz+MwMxoMmCw32kKThMGMKwc9Dy+OyjEKI2pT
         RBu3ubwsYWHG9qxHIElygiTeU95Dqwx1Qz3KCuRgXaXWfAsZW77FMyXrA7ZVJwHrRwT3
         Qep2Yx84DxkQl5BwkFIMEkZiWqswu879eAFYi+4BMA8LK0O6OQeePy57EScFwZBX93o4
         zKlXYY/gGFgK3LoUeldQyK6Rpk2STVozQgqGp+DNDat5OnwA/v2RdG1oMXvHpDDasTWI
         R1pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s13si2706664wra.1.2019.07.23.09.24.10
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Jul 2019 09:24:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 25DE3337;
	Tue, 23 Jul 2019 09:24:10 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 736473F71A;
	Tue, 23 Jul 2019 09:24:08 -0700 (PDT)
Date: Tue, 23 Jul 2019 17:24:03 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Peter Zijlstra <peterz@infradead.org>, x86@kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 2/2] lib/test_kasan: Add stack overflow test
Message-ID: <20190723162403.GA56959@lakrids.cambridge.arm.com>
References: <20190719132818.40258-1-elver@google.com>
 <20190719132818.40258-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190719132818.40258-2-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Fri, Jul 19, 2019 at 03:28:18PM +0200, Marco Elver wrote:
> Adds a simple stack overflow test, to check the error being reported on
> an overflow. Without CONFIG_STACK_GUARD_PAGE, the result is typically
> some seemingly unrelated KASAN error message due to accessing random
> other memory.

Can't we use the LKDTM_EXHAUST_STACK case to check this?

I was also under the impression that the other KASAN self-tests weren't
fatal, and IIUC this will kill the kernel.

Given that, and given this is testing non-KASAN functionality, I'm not
sure it makes sense to bundle this with the KASAN tests.

Thanks,
Mark.

> 
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Thomas Gleixner <tglx@linutronix.de>
> Cc: Ingo Molnar <mingo@redhat.com>
> Cc: Borislav Petkov <bp@alien8.de>
> Cc: "H. Peter Anvin" <hpa@zytor.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Mark Rutland <mark.rutland@arm.com>
> Cc: Peter Zijlstra <peterz@infradead.org>
> Cc: x86@kernel.org
> Cc: linux-kernel@vger.kernel.org
> Cc: kasan-dev@googlegroups.com
> ---
>  lib/test_kasan.c | 36 ++++++++++++++++++++++++++++++++++++
>  1 file changed, 36 insertions(+)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index b63b367a94e8..3092ec01189d 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -15,6 +15,7 @@
>  #include <linux/mman.h>
>  #include <linux/module.h>
>  #include <linux/printk.h>
> +#include <linux/sched/task_stack.h>
>  #include <linux/slab.h>
>  #include <linux/string.h>
>  #include <linux/uaccess.h>
> @@ -709,6 +710,32 @@ static noinline void __init kmalloc_double_kzfree(void)
>  	kzfree(ptr);
>  }
>  
> +#ifdef CONFIG_STACK_GUARD_PAGE
> +static noinline void __init stack_overflow_via_recursion(void)
> +{
> +	volatile int n = 512;
> +
> +	BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));
> +
> +	/* About to overflow: overflow via alloca'd array and try to write. */
> +	if (!object_is_on_stack((void *)&n - n)) {
> +		volatile char overflow[n];
> +
> +		overflow[0] = overflow[0];
> +		return;
> +	}
> +
> +	stack_overflow_via_recursion();
> +}
> +
> +static noinline void __init kasan_stack_overflow(void)
> +{
> +	pr_info("stack overflow begin\n");
> +	stack_overflow_via_recursion();
> +	pr_info("stack overflow end\n");
> +}
> +#endif
> +
>  static int __init kmalloc_tests_init(void)
>  {
>  	/*
> @@ -753,6 +780,15 @@ static int __init kmalloc_tests_init(void)
>  	kasan_bitops();
>  	kmalloc_double_kzfree();
>  
> +#ifdef CONFIG_STACK_GUARD_PAGE
> +	/*
> +	 * Only test with CONFIG_STACK_GUARD_PAGE, as without we get other
> +	 * random KASAN violations, due to accessing other random memory (we
> +	 * want to avoid actually corrupting memory in these tests).
> +	 */
> +	kasan_stack_overflow();
> +#endif
> +
>  	kasan_restore_multi_shot(multishot);
>  
>  	return -EAGAIN;
> -- 
> 2.22.0.657.g960e92d24f-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190723162403.GA56959%40lakrids.cambridge.arm.com.
