Return-Path: <kasan-dev+bncBDV37XP3XYDRBSHUSWJAMGQENX3HDRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 99EE74ED757
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 11:54:17 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id w17-20020a05651c103100b0024986ae896fsf9953524ljm.10
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 02:54:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648720457; cv=pass;
        d=google.com; s=arc-20160816;
        b=a3VvHrIc2rT5loGnUoZe463A3OwIEYJGA6f2YdHXLiz8La85GqnN7KrCf7694sFWy8
         r3Hc35McZUhZIYNunu+RHtBK0AklnV9hRC5DZkejWQyoXJTAI3gP8vBitwhcZzBcxnjQ
         +xrBNmLfyuxflkBEnFsv38/mIAFBmG2T5ySFZ9MrMix//J273nkl/9cK1zQpEbrM7yen
         uQAC+quY+788++f84ewnL5QHxr3HDcPBur0GvOWU2LeD5GeflXorJQsbz6BoOWDfNMIn
         c6a+HM6N4UkBs3J/BwK7wYM2XRmJHcyhNq+JiWRFqXLJRrpn3pdVYtoP/hAv7QptdYuU
         WlnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bxrn2ip2WMnOcVgPTaKa3x+QQCGo3oBC2O52TH7G3RM=;
        b=zJ1U0+gDKAO1o7R9eGKcsx5F7GbqHw5CqsKBJivI0aUOCkxrpeiVk9kzzAUbRlqi4S
         C3Ie0gMIEnT/kXFwfr0ozNvV866RVJSo6+d+5eXbtQiY/YXmYfnnssnICSVSMrnfz553
         BO0//wrd5xG0JwaHYSMdsC77lSAdTivnSZCtnF2pxgv1TFh5Ojs+qqm9eVndl1ifLdiT
         +kIuK9uR5A5PfKdAfGCSG++PV/OMvElOF5963QvZh62IQxBdF+55IaYP/gLP3Qlilsn5
         eH/TRsDhaKkjUWcZJNYLPzZnYnYUpoYAaK2shzkg8NFb9J4c/ittYEiLYsxu60l1RjOi
         QpFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bxrn2ip2WMnOcVgPTaKa3x+QQCGo3oBC2O52TH7G3RM=;
        b=oYssOLzw3YJd2wt8KhWAULx4svvryteFBYEvp1Gt8wjG2MWBaclBmV00VKYK2e7i1E
         DsbUW/hleF96bpc7z7hOA/UyJxHqY8AkUO9Sb8Wha/QiMOt0z6ytqVgOLmbYqjG1sx/N
         LExrry4UeXUWodZWjFr7essTWgTetvK/TdlOVaoFVJ/gTvLbcRVlOOjzcOvBSA0pf9Pq
         tZzffyBobUgzQZt7BpJfl3hJZXBl76VFAqC1KkD1UKhfZHsB1gL7CThTR3u+kJAedz6u
         y5zsiNPIFfiPf+FIsFI9h7Ottu8XCsn8FpzYf/sCDsu+ckC2AJKLMw+kx+3OFG32Nk1D
         Y1Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bxrn2ip2WMnOcVgPTaKa3x+QQCGo3oBC2O52TH7G3RM=;
        b=iHlJ3aYzrcuMiWm/eTEobL99UkLQ4/38CUS224pxl1yuxWgYMNKQ2PoBehMiFoaIv9
         D/FAiow0gQfNLx4p4cRPNufLzdH6v3kvJ3qD72ZsLWs41oVfDpV1IGTtsilu8KbR0Pa9
         V2q6WqfEXKjn04P0p5ddctgfdEcYl6+mpP1kCwyYrmMy/eNAuL3MPeahmsFhiQjZK/Qc
         CTNJBIuClIT9Kt3Vn8oJE/uJhS/iKjWHRzGwBw+diF+r5Sp8JEMr9aSE7Ka7v5Ii3MhR
         OrN9rrNnCaFdgSDP28ScXMm9QRj78z/RCUy5HPDsmqw/o/MPWNoZm+zFBffyeH/0PodR
         WAyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532AyYcht1p/YWFKwfYxe7pehOfSXcpmTetHrkXhkCq0mHmdMFBt
	5qEZSHFgAiYp1v1VN/46wpo=
X-Google-Smtp-Source: ABdhPJzTNBjFGg1NZXJvVbqsKUdVRiJ5NhPXYQ8wI2ranpEiofCHiOrkNwKqfcsNTclerh1U4QTv8w==
X-Received: by 2002:a05:6512:6c5:b0:44a:2642:b77d with SMTP id u5-20020a05651206c500b0044a2642b77dmr10533090lff.616.1648720457154;
        Thu, 31 Mar 2022 02:54:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5285:0:b0:44a:94d2:1d8f with SMTP id q5-20020ac25285000000b0044a94d21d8fls4285764lfm.0.gmail;
 Thu, 31 Mar 2022 02:54:16 -0700 (PDT)
X-Received: by 2002:a19:8c4b:0:b0:44a:b6a4:4873 with SMTP id i11-20020a198c4b000000b0044ab6a44873mr8289684lfj.549.1648720456164;
        Thu, 31 Mar 2022 02:54:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648720456; cv=none;
        d=google.com; s=arc-20160816;
        b=xBbFs9ocF7n/xrvAZEjqGsQeB+Xe6tmhDtnp3w4lfDtc+t/dwAAUF0WuvLwEX1036b
         MTtnVopOAHIuYmaxRPwORWrerWmH/rl9G8/hHcxasTqGpTUFHL74QO6NNwpDspQJnXFU
         NIFcAnCF1ZcG8cTe59sdS1Ma4rK3saswlElUJA/2Ksg+QnFVYp/CbNMZWJH801b3h6QQ
         +Za3CZViVBsOOIF4jKXaWl391EjbTaB+Ao0PuPyo6xUa/UDpR+MJovqDldMupkh2gHZb
         /ytuF0hH+DX9oFzwUO+PUlBsmRnn4W8NnfH0/wHrVGera4tU17GXV6WEnZLkwmRgUtWM
         St0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=jv2fS1BduljnteA1QUPfJWYuOGFqCTI32CeiUCBRMhU=;
        b=RExYElAUyQRtpD38S+kVVKS3vv1TJwCxklU3lknkVg8e2Z9EsVQeb8Ef2etFA/93tV
         UxVTBC9QQENMJfp8VNbKREAU5boSr0y5u29dlxPlKC9A/r5G58A4Wf/Ftnvq3g/GoGJI
         gXD3vCsPkzdmtO2ON3bOvHHvSYrVegK0/I6IdS/vB4nyNU8rzAmb+PwFl3enVKN/Y/L3
         qXEwPXNq61dQp6LtQrY2ufYzM6inaAesiQQ145F9zPv9Xzv/W5eJXZIWLAraAbhhLUM9
         Cf/ZxtR/FCUCiJlWRE1d6ZCUlqKCsieko5cPunMiy5ysJwomphL9tuhTw0cQHqa6Y1s9
         qELg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i3-20020a056512340300b0044a2d961b74si1430979lfr.4.2022.03.31.02.54.15
        for <kasan-dev@googlegroups.com>;
        Thu, 31 Mar 2022 02:54:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 413B323A;
	Thu, 31 Mar 2022 02:54:15 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 658873F718;
	Thu, 31 Mar 2022 02:54:12 -0700 (PDT)
Date: Thu, 31 Mar 2022 10:54:08 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 0/4] kasan, arm64, scs, stacktrace: collect stack
 traces from Shadow Call Stack
Message-ID: <YkV6QG+VtO7b0H7g@FVFF77S0Q05N>
References: <cover.1648049113.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1648049113.git.andreyknvl@google.com>
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

Hi Andrey,

On Wed, Mar 23, 2022 at 04:32:51PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> kasan, arm64, scs, stacktrace: collect stack traces from Shadow Call Stack
> 
> Currently, KASAN always uses the normal stack trace collection routines,
> which rely on the unwinder, when saving alloc and free stack traces.
> 
> Instead of invoking the unwinder, collect the stack trace by copying
> frames from the Shadow Call Stack whenever it is enabled. This reduces
> boot time by 30% for all KASAN modes when Shadow Call Stack is enabled.

That is an impressive number. TBH, I'm shocked that this has *that* much of an
improvement, and I suspect this means we're doing something unnecssarily
expensive in the regular unwinder.

I've given some specific comments on patches, but a a high-level, I don't want
to add yet another unwind mechanism. For maintenance and correctness reasons,
we've spent the last few years consolidating various unwinders, which this
unfortunately goes against.

I see that there are number of cases this unwinder will fall afoul of (e.g.
kretprobes and ftrace graph trampolines), and making those work correctly will
require changes elsewhere (e.g. as we rely upon a snapshot of the FP to
disambiguate cases today).

I'm also very much not keen on having to stash things in the entry assembly for
this distinct unwinder.

Going forward, I'm also planning on making changes to the way we unwind across
exception boundaries (e.g. to report the LR and FP), and as that depends on
finding the pt_regs based on the FP, that's not going to work with SCS.

So at a high level, I don't want to add an SCS based unwinder.

However, I'm very much open to how we could improve the standard unwinder to be
faster, which would be more generally beneficial. I can see that there are some
things we could reasonably do with simple refactoring.

Thanks,
Mark.

> Stack staces are collected from the Shadow Call Stack via a new
> stack_trace_save_shadow() interface.
> 
> Note that the frame of the interrupted function is not included into
> the stack trace, as it is not yet saved on the SCS when an interrupt
> happens.
> 
> ---
> 
> To deal with this last thing, we could save the interrupted frame address
> in another per-CPU variable. I'll look into implementing this for v3.
> 
> I decided to postpone the changes to stack depot that avoid copying
> frames twice until a planned upcoming update for stack depot.
> 
> Changes v1->v2:
> - Provide a kernel-wide stack_trace_save_shadow() interface for collecting
>   stack traces from shadow stack.
> - Use ptrauth_strip_insn_pac() and READ_ONCE_NOCHECK, see the comments.
> - Get SCS pointer from x18, as per-task value is meant to save the SCS
>   value on CPU switches.
> - Collect stack frames from SDEI and IRQ contexts.
> 
> Andrey Konovalov (4):
>   stacktrace: add interface based on shadow call stack
>   arm64, scs: save scs_sp values per-cpu when switching stacks
>   arm64: implement stack_trace_save_shadow
>   kasan: use stack_trace_save_shadow
> 
>  arch/Kconfig                       |  6 +++
>  arch/arm64/Kconfig                 |  1 +
>  arch/arm64/include/asm/assembler.h | 12 +++++
>  arch/arm64/include/asm/scs.h       | 13 ++++-
>  arch/arm64/kernel/entry.S          | 28 ++++++++--
>  arch/arm64/kernel/irq.c            |  4 +-
>  arch/arm64/kernel/sdei.c           |  5 +-
>  arch/arm64/kernel/stacktrace.c     | 83 ++++++++++++++++++++++++++++++
>  include/linux/stacktrace.h         | 15 ++++++
>  kernel/stacktrace.c                | 21 ++++++++
>  mm/kasan/common.c                  |  9 ++--
>  11 files changed, 183 insertions(+), 14 deletions(-)
> 
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YkV6QG%2BVtO7b0H7g%40FVFF77S0Q05N.
