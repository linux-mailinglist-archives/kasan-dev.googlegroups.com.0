Return-Path: <kasan-dev+bncBDV37XP3XYDRBENP4CJAMGQEVPPM7SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E21E6500DF3
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Apr 2022 14:46:09 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id w34-20020a0565120b2200b0044adfdd1570sf2278442lfu.23
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Apr 2022 05:46:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649940369; cv=pass;
        d=google.com; s=arc-20160816;
        b=G9kMBHSzK9lvKYU2ErdR0nItygTORRAmwmtazQVtOyssrsINZuWUIi0TiZ+EkgUYFy
         MpzzscGmqwfTRDUR2SlENuhKekOJup+u4PcjVZDx3rjUe33rWpeD4WCKNySGtZe51VfY
         5rBZk93YLpddaDyM+rOS6QdxaoSfx8cOhaaKnLXmK1IVSIy0InT0rzDe+QB7z1ME9W7x
         1yRtGZv5CRD6NNIZBoNCHOEXkEVLtyrQcCLF3vdR0koZaGTy2J7ZO1xBuDAG+wWv3pws
         F481I3qIbJwK15cOTSmU0zvshXwL/A9irLy7NcnoogBVAXvhb0GNO5P3ZOpr7gtQPill
         YUAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qksJVtRpjaxa81xF+ho0VZc43eoYE5U7+2ZMR9xrD20=;
        b=lfaAMtxgVLZfmKemUBxvxzkSb8/F/YsbIFPe/wv88D9B7nOIYA1ZQKd39hfkpanSLH
         vzRMxa+MZoyqAsS7OL+RGfP9wCzwKECAm4m2AFUl3WG9/yeX2FXZpLfeC3IGuI/ZQH9e
         gTFyPHkfTDXrcB7Rh698ojHXl2JfsQydWvl0wFE4qyHOgj5KbfOoLFWsVavNrBC9Yt1X
         GJq/8LVPWT1GD4WSHhtTyi0BnTG/cbAQgNrVcOxECcJtD8RI6yvXwtEXAUK+B2sHOWfL
         TNGRhwJ/dw5A/Tn6Ya6JIy1tG1YRtiRSMCfs5GU9dl0O61sJcWQ75KNLOcgyjTINQgLg
         xgcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qksJVtRpjaxa81xF+ho0VZc43eoYE5U7+2ZMR9xrD20=;
        b=eZ5A1w/wWchGBidMVIMz12jvyNVC35GBSfQI6sl0/KbSNiXZErUXs+yEWQ1vrZM/fQ
         EFYUuh/A5hFKDF45gpZRoyanwe5Fmn8+Tqa14hS3IvnAaT9I4PBHQXvLn4cl/kawfj5a
         KDUOK3D+W2dbCV9i0OzlAR/0ZKRiQeVYr7MK2mRyBySy7FDRZARMTjUHl4iAKcMwEV+h
         WIgU2s+tXAEhPhHtAoYaYqVJSTYQ9G/URkMqsP8FjLf9Fvq9fcD1Dpg2UTBBse2O3BTp
         VE7xwOTOyT0V6UzF7s43d44cuvJsstIDRYHV9TYWluftleb/4TQCRuDh1NlHrlCNdOdF
         3mWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qksJVtRpjaxa81xF+ho0VZc43eoYE5U7+2ZMR9xrD20=;
        b=xfpr10Qh7PM0KJusalcmI9ZSp2i5YnBBcjz280zwiT63N+GjqwQmrXHOsV4cIp4+Ju
         Dtpi5cqGkMVZPP6Y9iyLBlGmSzz60gOzVr6NL7ZKvBTlfoQNeqSfBa9pVqnGqr28N/bB
         11w6cD4JAkhB6UvoF8ddSoeew+/fQDUfIYGRgDdTZKV93ePSLqSIl6mx1Ih8ZgFN+jSx
         WwMbnH7iUbdRSugf6qOqHVppDAfh1TRBIXBALA2AMwxXsv2ItcHdkH5BydcvQ35bFR2e
         Q1aWpXUjrlOe1ITtigUsgjlt9+Nqy+wf+G5qk8VUC5QBW/MLzcYVjdoqfeKuBF+TkJ5r
         T3yQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5338SN2XWo6F8a/LYhJ8qQE8DILuPuCKZ/mIKR0ao6OX7BIAbITA
	dmhs5CaD4vEV9JBH3ewa3cE=
X-Google-Smtp-Source: ABdhPJxhdNSo8P8bPa+FKFXYmw8gmx1uxoMymFWQSWPLTRkuy7bH6CgKO6N2RUScAoPEJwlboRjxjA==
X-Received: by 2002:a05:651c:160b:b0:24d:a0fa:26cc with SMTP id f11-20020a05651c160b00b0024da0fa26ccmr428338ljq.150.1649940369282;
        Thu, 14 Apr 2022 05:46:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c3:0:b0:24a:fddc:ed41 with SMTP id x3-20020a2ea7c3000000b0024afddced41ls981242ljp.9.gmail;
 Thu, 14 Apr 2022 05:46:07 -0700 (PDT)
X-Received: by 2002:a2e:95d2:0:b0:24b:59a5:21ba with SMTP id y18-20020a2e95d2000000b0024b59a521bamr1487734ljh.439.1649940367781;
        Thu, 14 Apr 2022 05:46:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649940367; cv=none;
        d=google.com; s=arc-20160816;
        b=ycbzpy66A53NJl808ctNw50SfvyrBowcRTwemkB+RYr/+hWYcI2OHs5SXKc1Sk/W+G
         YkQv8V+ncUBmNx8vmAGl/nvaHStHMcegDYK/RrpfzQnmy9lSlzduLdOp/N/PP7Ujcske
         Pp2sy60lRuNWW7UPrctDTuG4rDPwwSc0/mDKm/Tcu+X0KXsp1LS4r3dtcgt5VFz02qM9
         1UVIGFVCuFFM50ZfH+QUJ1DMIWqnYSE3TuWTbHyLbQbmk9r2rgiCJQHQvcvMQErQZHNR
         EV3sFrphN2DV8RE8qYKI7o4EnBbY6ihYgDPl3i+Tvf8LDzvt4LLClF/IF9LOmvJYsQCW
         bIjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=6KFOwKoPEIsZwPb2uiiRkr1OqP8mZh6A0ZzLiM9xZxc=;
        b=iKXjC4R0v7mH5J46wFNwwkf4WdTziUGQTfYAjHxASwm3SXBeupe045FqHSzQRT9HBh
         Bgo3tTMEWulgkl+zXHywY46qoqZCIDRnWolAKW97f7uIV5j/mDWEzAwes1NvXHpNLpcH
         Z+mDMBA6DtObIvSsEj6Xu8GSW+8eh6SSYIUQD5qvzy/GqMpYnbM0JTEL37CplaeBqLlt
         PiRnRPISjtBifPJ/LRPx6RMbuarhUqZssvsVp2/3iva6DLqX43T5HhQwZBtUrIOyQv+/
         daRKk3H5KrHNV6QmnowmXaw09x3QD4ULiE3Heol8QbptdyxQg/4LE138HuTMvCEwmFe+
         unOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id bx33-20020a05651c19a100b0024da01a8c6dsi22561ljb.1.2022.04.14.05.46.07
        for <kasan-dev@googlegroups.com>;
        Thu, 14 Apr 2022 05:46:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 62BBC1424;
	Thu, 14 Apr 2022 05:46:06 -0700 (PDT)
Received: from lakrids (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 133923F70D;
	Thu, 14 Apr 2022 05:46:03 -0700 (PDT)
Date: Thu, 14 Apr 2022 13:46:01 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v3 2/3] kasan, arm64: implement stack_trace_save_shadow
Message-ID: <YlgXiddhNAQxzmTC@lakrids>
References: <cover.1649877511.git.andreyknvl@google.com>
 <78cd352296ceb14da1d0136ff7d0a6818e594ab7.1649877511.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <78cd352296ceb14da1d0136ff7d0a6818e594ab7.1649877511.git.andreyknvl@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Wed, Apr 13, 2022 at 09:26:45PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Implement stack_trace_save_shadow() that collects stack traces based on
> the Shadow Call Stack (SCS) for arm64 by copiing the frames from SCS.
> 
> The implementation is best-effort and thus has limitations.
> 
> stack_trace_save_shadow() fully handles task and softirq contexts, which
> are both processed on the per-task SCS.
> 
> For hardirqs, the support is limited: stack_trace_save_shadow() does not
> collect the task part of the stack trace. For KASAN, this is not a problem,
> as stack depot only saves the interrupt part of the stack anyway.
> 
> Otherwise, stack_trace_save_shadow() also takes a best-effort approach
> with a focus on performance. Thus, it:
> 
> - Does not try to collect stack traces from other exceptions like SDEI.
> - Does not try to recover frames modified by KRETPROBES or by FTRACE.
> 
> However, stack_trace_save_shadow() does strip PTR_AUTH tags to avoid
> leaking them in stack traces.
> 
> The -ENOSYS return value is deliberatly used to match
> stack_trace_save_tsk_reliable().
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/kasan/common.c | 62 +++++++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 62 insertions(+)

As things stand, NAK to this patch, for the reasons I have laid out in
my replies to earlier postings and to my reply to the cover letter of
this posting.

To be clear, that NAK applies regardless of where this is placed within
the kernel tree. If we *really* need to have a special unwinder, that
should live under arch/arm64/, but my first objection is that it is not
necessary.

I am more than happy to extend the existing unwinder with some options
to minimize overhead (e.g. to stop dumping at an exception boundary),
since that sounds useful to you, and I know is relatively simple to
implement.

Thanks,
Mark.

> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index d9079ec11f31..23b30fa6e270 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -30,6 +30,68 @@
>  #include "kasan.h"
>  #include "../slab.h"
>  
> +#ifdef CONFIG_SHADOW_CALL_STACK
> +#include <linux/scs.h>
> +#include <asm/scs.h>
> +
> +/*
> + * Collect the stack trace from the Shadow Call Stack in a best-effort manner:
> + *
> + * - Do not collect the task part of the stack trace when in a hardirq.
> + * - Do not collect stack traces from other exception levels like SDEI.
> + * - Do not recover frames modified by KRETPROBES or by FTRACE.
> + *
> + * Note that marking the function with __noscs leads to unnacceptable
> + * performance impact, as helper functions stop being inlined.
> + */
> +static inline int stack_trace_save_shadow(unsigned long *store,
> +					  unsigned int size)
> +{
> +	unsigned long *scs_top, *scs_base, *frame;
> +	unsigned int len = 0;
> +
> +	/* Get the SCS base. */
> +	if (in_task() || in_serving_softirq()) {
> +		/* Softirqs reuse the task SCS area. */
> +		scs_base = task_scs(current);
> +	} else if (in_hardirq()) {
> +		/* Hardirqs use a per-CPU SCS area. */
> +		scs_base = *this_cpu_ptr(&irq_shadow_call_stack_ptr);
> +	} else {
> +		/* Ignore other exception levels. */
> +		return 0;
> +	}
> +
> +	/*
> +	 * Get the SCS pointer.
> +	 *
> +	 * Note that this assembly might be placed before the function's
> +	 * prologue. In this case, the last stack frame will be lost. This is
> +	 * acceptable: the lost frame will correspond to an internal KASAN
> +	 * function, which is not relevant to identify the external call site.
> +	 */
> +	asm volatile("mov %0, x18" : "=&r" (scs_top));
> +
> +	/* The top SCS slot is empty. */
> +	scs_top -= 1;
> +
> +	for (frame = scs_top; frame >= scs_base; frame--) {
> +		if (len >= size)
> +			break;
> +		/* Do not leak PTR_AUTH tags in stack traces. */
> +		store[len++] = ptrauth_strip_insn_pac(*frame);
> +	}
> +
> +	return len;
> +}
> +#else /* CONFIG_SHADOW_CALL_STACK */
> +static inline int stack_trace_save_shadow(unsigned long *store,
> +					  unsigned int size)
> +{
> +	return -ENOSYS;
> +}
> +#endif /* CONFIG_SHADOW_CALL_STACK */
> +
>  depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
>  {
>  	unsigned long entries[KASAN_STACK_DEPTH];
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YlgXiddhNAQxzmTC%40lakrids.
