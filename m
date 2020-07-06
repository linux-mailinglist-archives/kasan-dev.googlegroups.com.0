Return-Path: <kasan-dev+bncBDV37XP3XYDRBLUDRX4AKGQEZS45V4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 70739215A98
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Jul 2020 17:22:24 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id a189sf11026440oob.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Jul 2020 08:22:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594048943; cv=pass;
        d=google.com; s=arc-20160816;
        b=syDjmD3Yigg/+TDkHtJT1w6zS/ryJ1+PCXIiH4qB+KB8KqHSrnlTxIVcHrmj0wk/Ma
         SNGWmbCJlvc249007Sy3r/OSiuFlY3ZogH/rjofp9sEV4YNSXg0zJbKq7YG6wL6Naol+
         VlW6CSPvgLrHiN7TX2uN26NUzCXglnA5hg+GyvBAuTYyL/ZunavFnnKXVLH+gaTB6ZUk
         N83w9R6qwdJbnFhcL1vVvK+9mGeku/sDFTf/qwCJ3katH6BoNYejKbY5VIEYzeoDTuHb
         JoV8YEtgFBExTVdcXs8U8W7sgyVm6p2ecrnNId4+fOHrOp1Nr+anHkGTNBlFpr6KQPxn
         4jBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=NzUg4X/APrZIIuywMWswwUussT+NmnQxHw/C+ijEki8=;
        b=kmzuIbShQra34GFYB7OcGlVn3KFXDZW083F9TG3q8y8l+dpOaCCkm2gYI/ba39Srv8
         KSjpWdYPB3wbNJPzwiP8RvJZS3RCuJfDpFtqFqdXP5OlBkSl2rWx+faQC5tVtx0FK1WA
         925ZhORftv4f8Je6uV03Y8FYZG8sidtdvae+PHaK8kpFWsBEowBIdmDt1amYC6rzdQ88
         CHbJ/99ycSaQB3IV8v7MwvKT23oMGeKM0FuZkWvR0mRpUx9qEv86sv0+SQKhIMFsC6v2
         eOYYb8QnNW4VUtAzRsHYQTcLqbnpO6PtKdLVOja7Lw5dL6YVW8Bcm+fr4crNoNCT4yww
         d1Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NzUg4X/APrZIIuywMWswwUussT+NmnQxHw/C+ijEki8=;
        b=qFw2S1F12i/Mzbw5ylsDGdq+9NxtaJLmkDYYc+Gr7optxJ0q7Ilxi3nTKBXkEG0YlB
         Q60Qt11yrsG3ydM4nH5wbGb5Yn2sKJyYkCrEKUO4zj2PYwsH9lsO/UMTeQ/TAUmDNCCH
         aNkh3ufGB8jFBF6hkxnbiaz23o7CoZ0YBcgc8laUVvLjSKJUt6f7KRNVDzeFMlj0tNx+
         kShTYNy7URMVXu4X6T+uloXWIztvhmqz9a14Y+tbPTCUhePP77QunQh8QJx5QXU2pJsV
         CMefmli8+y7REhcfxygIVYsSdcymtYf+jK7KcmyrfoLQq+PSTLELI1qDhkQJEwX8e6wQ
         UMuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NzUg4X/APrZIIuywMWswwUussT+NmnQxHw/C+ijEki8=;
        b=pRLtxCpnsw8BqFX5iu/RTWb2iNBvXadykh6iC3MrbUIDV+Pzo3MwLP8JlyAumhCa+q
         MuVQ9odSpPffgLAzJb6dQ+TWn8nGzFGBCl02YniTGUJ1JnU5ROb95EcI7GcrtqdQaTDr
         06CHZWTvJJ7kPzcCgEVQleIFX/cd9/sBTtfK+N+S14nLoqYxcCFxku7+4pyIvfSbIMBO
         XOYulv7pU3HSiX1hernQJxAYBS/9QSiDJx3dV28zliRwPTEdGiQogLXZ3RvHg2z8f4BO
         PJyRLgk74AQRsFCAJXH/1HDEou2ouop39hcynVCfT/SMu2c6RvSKGeH38YsefjEdVvqe
         Otmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530v1Kpb2BxhUd1Mm9Qm4PCDWPqxjJXygbJEtpqUCLBg5FtYBnvf
	HnSyhZcySRBHoEd0t9C2dso=
X-Google-Smtp-Source: ABdhPJxnF76g4NRzJ3XahsoTBfP87LYxYuf8xrRgGW+A9KWicIQltk2uqmiMn8muVcxaQfrr7P4maA==
X-Received: by 2002:a9d:2f0a:: with SMTP id h10mr8123950otb.314.1594048943019;
        Mon, 06 Jul 2020 08:22:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:544a:: with SMTP id i71ls3217412oib.9.gmail; Mon, 06 Jul
 2020 08:22:22 -0700 (PDT)
X-Received: by 2002:aca:3241:: with SMTP id y62mr28979990oiy.128.1594048942619;
        Mon, 06 Jul 2020 08:22:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594048942; cv=none;
        d=google.com; s=arc-20160816;
        b=HlBMRTT42W5EfFp91r8nbLKP2+mqojouF7/j3K/OZRqqsZ1cr8LfH8CwnGkXSLn7uO
         arGzEbE7gDEmkBdG60oecXeiWmxM2O/oMnEYQUlJ0nEfeluoRHW0zixd9w3x/eazi+Yv
         Jsw3oQaRHEEB+FL3YNOHQOSrgqGaY4vlC2fiXAjmY5SPZ7Civ7Qf4oTypJAzihPHpnbZ
         arMO4URCc9DjIeJqaGr3c0iZ31kM3DvefQ1UqaGUE6DIYTSeOzXYHpEScRhRfVxR+e2r
         7AkXvbVwgiG5tS4+EPUbMUgJdm6Gr6pYxrMl2pueXpWeF7wLfgGf2CQP9/bDbde0iA4V
         803w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=m5OZ58ec3PDgTvUu7LB/qq1pRxAf3/JiyywPSKf9zXw=;
        b=d9CbtcV4So6WDvlKRU6lvFF1q7EjsI95zH3qKfQ3YqWFKQ5+1UkoH2+W72qQ+TO09b
         o/EG+IjE/caGhSLQ0OCuANNYYdNBMPGKz7v7aX1/c11oOYf4y+BRv8kqydjctp17IdPz
         ubXzNEpFTjIJZ99NN1fFkLBR2kDrLKjtlid8QeSIA5J9I0HJxC2KHvNILZ/jVrUSOEh7
         uugvAGspDeuzCYFf8pee72CzSVpnENtyCYH294MKW/qKQ8bC6r1dZ7j7nLxli2WloASV
         qIQBr5r+Qn/jLWufzPEwHoQ8sB0KlfFeQpb9wwNZaRhzu+dCmoF7ZhYys118KwkNU+Xa
         XxMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c26si1303526otn.4.2020.07.06.08.22.22
        for <kasan-dev@googlegroups.com>;
        Mon, 06 Jul 2020 08:22:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 42D44C0A;
	Mon,  6 Jul 2020 08:22:22 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1987A3F71E;
	Mon,  6 Jul 2020 08:22:20 -0700 (PDT)
Date: Mon, 6 Jul 2020 16:21:53 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH] kasan: Remove kasan_unpoison_stack_above_sp_to()
Message-ID: <20200706152152.GA45787@lakrids.cambridge.arm.com>
References: <20200706143505.23299-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200706143505.23299-1-vincenzo.frascino@arm.com>
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

On Mon, Jul 06, 2020 at 03:35:05PM +0100, Vincenzo Frascino wrote:
> The function kasan_unpoison_stack_above_sp_to() is defined in kasan code
> but never used. The function was introduced as part of the commit:
> 
>    commit 9f7d416c36124667 ("kprobes: Unpoison stack in jprobe_return() for KASAN")
> 
> ... where it was necessary because x86's jprobe_return() would leave
> stale shadow on the stack, and was an oddity in that regard.
> 
> Since then, jprobes were removed entirely, and as of commit:
> 
>   commit 80006dbee674f9fa ("kprobes/x86: Remove jprobe implementation")
> 
> ... there have been no callers of this function.
> 
> Remove the declaration and the implementation.
> 
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

This looks sane to me, and I'm not aware of any cases oputside of
jprobes that would need this, so FWIW:

Reviewed-by: Mark Rutland <mark.rutland@arm.com>

Mark.

> ---
>  include/linux/kasan.h |  2 --
>  mm/kasan/common.c     | 15 ---------------
>  2 files changed, 17 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 82522e996c76..0ebf2fab8567 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -38,7 +38,6 @@ extern void kasan_disable_current(void);
>  void kasan_unpoison_shadow(const void *address, size_t size);
>  
>  void kasan_unpoison_task_stack(struct task_struct *task);
> -void kasan_unpoison_stack_above_sp_to(const void *watermark);
>  
>  void kasan_alloc_pages(struct page *page, unsigned int order);
>  void kasan_free_pages(struct page *page, unsigned int order);
> @@ -101,7 +100,6 @@ void kasan_restore_multi_shot(bool enabled);
>  static inline void kasan_unpoison_shadow(const void *address, size_t size) {}
>  
>  static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> -static inline void kasan_unpoison_stack_above_sp_to(const void *watermark) {}
>  
>  static inline void kasan_enable_current(void) {}
>  static inline void kasan_disable_current(void) {}
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 757d4074fe28..6339179badb2 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -180,21 +180,6 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
>  	kasan_unpoison_shadow(base, watermark - base);
>  }
>  
> -/*
> - * Clear all poison for the region between the current SP and a provided
> - * watermark value, as is sometimes required prior to hand-crafted asm function
> - * returns in the middle of functions.
> - */
> -void kasan_unpoison_stack_above_sp_to(const void *watermark)
> -{
> -	const void *sp = __builtin_frame_address(0);
> -	size_t size = watermark - sp;
> -
> -	if (WARN_ON(sp > watermark))
> -		return;
> -	kasan_unpoison_shadow(sp, size);
> -}
> -
>  void kasan_alloc_pages(struct page *page, unsigned int order)
>  {
>  	u8 tag;
> -- 
> 2.27.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200706152152.GA45787%40lakrids.cambridge.arm.com.
