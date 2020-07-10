Return-Path: <kasan-dev+bncBDX4HWEMTEBRBV6EUH4AKGQE7JJBKTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id E879621B548
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 14:43:04 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id g18sf3110880otj.12
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 05:43:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594384983; cv=pass;
        d=google.com; s=arc-20160816;
        b=oJtkbsg9TwgGInc0VT1o9sdvEo5cOJCXQf+oqxhNobi6DclADlGDggSA2L4NwDbOdO
         oXoUeG4jQraf8hTqIxiyfDSZowLUWfS4MH0Z0ZsgTe8DM59VKicsrbD4oyOpJBpdRmUF
         U2IIYen1zTbP0Os2Pyd1GMPR+DrU0pFv5dba++IwCrq7cwG8J7OdU8mPHHw6AQurIyEd
         OsPkqK01o8chqDYz9eKHIgNkH4ENtVg0WPTunjLOEq/oo8ZnH8rSpR5P5Vsbxk4iGuD9
         jlUBKBvJc2Fz8CKCkFrUlW+Q6RA7sqNTQUbC6rF23OJyeQZoz3DGwN2//Fo7BijbYA+o
         ZrIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=U7HRQVwkh2MNQ6+koI8FwJAkHn9ognyVY3zGxuzggJo=;
        b=LdfKSuBWwB7PAKbgOdjaA/FWQ5p6WumZMq9Jw7AxqXsBd26rz3DG6/c7PQ1+4WuNpw
         5HgF1EJI0BMXci0AzkDhRX5u/XNnA05bsfPvkstbccZFJa1mB/BC+vVqdZT1E8UqStbk
         7KAliOoLYf1Io5cVErOiFUcDSOQLVqkF9qZvCYPUgOVyikH09txoc+k0qSEr/IhGnf0W
         sW2WfiA5daxp8zB322nLC+LqhJzVfaOcZudFGq0NwBIB5XDeAeK0dtV+5s9QMHjbieNr
         5TCtghmZoS3mriaBFyEdINmgInxvWsVlMF9gUk06k2/0i1CqCRYXSdNBdZ7PoCCJr2v6
         Kb8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VTtWM8GX;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U7HRQVwkh2MNQ6+koI8FwJAkHn9ognyVY3zGxuzggJo=;
        b=lJPkfDaBsJBNviUuW57tAUDNm+2uCG+RQRBso+W4fgHi6qt/pk+c3fw51Ctn3Vc9wT
         eX1wERzYMWPmMl2zdBR5JkmON1T3409Pgp5J8lg6sZQMHJkXyoc8aTx4hLK9G9jkmsiR
         fLuSc8fGzSaVLIyFjvcndGzD0HUcwLXEFY6dPoUENynCGasuuVkxinN0JwiF3LeD+ZpA
         dEgX9htXUzbr3kypzLaVxX5o7OAczF12gUqAaZzXMClYLnpganGceKzB3KH74kCe4hXG
         hN2Q7L0kthtbRAAtA8Z2V5x0CGBMk6I15u4T17U69nSqLakgPnKOFuz0ai1cG/drrS/8
         VZaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U7HRQVwkh2MNQ6+koI8FwJAkHn9ognyVY3zGxuzggJo=;
        b=ZF/SPuj7uoqVWcN6doKfuxVNam8SlvrKRBcfUdH6JBKbR4UfO6wke6DDYm02ZxxyCZ
         tOAdvJJpfDL5flAyLLzUFR1fFcD1PKQ6F8lptOZt51RTmlUYjym/V9eiHhlTRe6A7eqy
         wkrBdB9s/QOTP6qzl2cE5H3eTt6OxeSf8sv8SKJKw7K5bAd5ibPuzp5c568/IbyUi+zc
         iRNf90Ca4Q9GDadJ3jTIzVSVr5i7jQQKFtYwwM0SeqA0uNeqTNURjbqWpP9MzpaHZ9aM
         aikxLGBPsf8Eq9+1fB/rJ1pDrynIXm0oqdt1uQ0UJECBJmtj0fV802PyfZX5860oFL1o
         qtyQ==
X-Gm-Message-State: AOAM532QlD6a9GlSBQtitBqfzXDVzsUA32cx6sFhWOYP5Cd/9hdicqBS
	rbDn9q4GTs85lreG3akIl1M=
X-Google-Smtp-Source: ABdhPJzBP9CSxamv+Uz1Q9MNW3GyuTa6aE/o1zLaSpJAaHo5JIvpH2gxX69+aVcE19nc4vBc/OYGaw==
X-Received: by 2002:a9d:6190:: with SMTP id g16mr62026634otk.233.1594384983741;
        Fri, 10 Jul 2020 05:43:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1599:: with SMTP id i25ls1957518otr.3.gmail; Fri,
 10 Jul 2020 05:43:03 -0700 (PDT)
X-Received: by 2002:a9d:6b19:: with SMTP id g25mr60513689otp.160.1594384983450;
        Fri, 10 Jul 2020 05:43:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594384983; cv=none;
        d=google.com; s=arc-20160816;
        b=ojcooX5z1c1nCpr1/FWgR0AbSWNCGu+aLujMtsUnGT2O3p/ADbIhxSpY3Jne2P/OXL
         LnNK5oquKx5XHx8XnKKWW6ZhD+A4ONgV0xp8D5BCf/QqQ3gUhSg1+PlT5hq6K4DxVlxJ
         skGWQzozzzneKaZjvkAO++0NhFrsD2Jad05X2ZojvDbmZbWXaAYOAOqGYtID1X1a5C3e
         KPRjca90EZkrjwFGokHxJK4jEU2ojyJwr2d8IKUwoznVBDo+P8awfNA1cEJETLq04Dk8
         tFw0RstH8S4uug0PkV6iX1nqTN+jt6JDr9tTpYAwXpLJlumbR80w+XSVVEBKMPP6NNez
         mgbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8AQCz6U9rg/TZdMooPQtBnohp0JVWtGHbcPbtcQ4I1c=;
        b=U1g3lXr0WrBr2HkJaxh3xB5qi1jYgBGmbgW3OcsohaZx0o1UeUzI1ooKsatlcS65w1
         Xxo2WtmATPHDFHjlmt5rGUJt8AuBLnBny+B60wXkFNuWQd/PIgP+VTNhTiB+38E9tVj1
         a1PEGVgeAaZvupcO6WOq84Qr24rxMxe6qPg9Ju7imBnyHYCljYBzI7Hue/DZpJtvZYAx
         O56nt9v/ayAHj7bTkhoQ3Z6/TP61Oh6b9kekITfa1dioPAXnwLk/O3fjNx+FsqD/syLD
         3ZnNdfLOyzEbu3DU/4HT8jGIyntBAI+2DX8uGPnS6RfgO+SKAxt5WauLRvfn+SZJaTPV
         24Xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VTtWM8GX;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id y16si156077oot.2.2020.07.10.05.43.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jul 2020 05:43:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id k4so2191488pld.12
        for <kasan-dev@googlegroups.com>; Fri, 10 Jul 2020 05:43:03 -0700 (PDT)
X-Received: by 2002:a17:90b:30c4:: with SMTP id hi4mr5250427pjb.166.1594384982354;
 Fri, 10 Jul 2020 05:43:02 -0700 (PDT)
MIME-Version: 1.0
References: <20200706143505.23299-1-vincenzo.frascino@arm.com>
In-Reply-To: <20200706143505.23299-1-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jul 2020 14:42:51 +0200
Message-ID: <CAAeHK+wvLb9BD=GdKuZp9v2620JKWgk9ShXUdx2tWSZNw1UJBQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: Remove kasan_unpoison_stack_above_sp_to()
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Mark Rutland <mark.rutland@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VTtWM8GX;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Jul 6, 2020 at 4:35 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
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

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Thanks!

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
>         kasan_unpoison_shadow(base, watermark - base);
>  }
>
> -/*
> - * Clear all poison for the region between the current SP and a provided
> - * watermark value, as is sometimes required prior to hand-crafted asm function
> - * returns in the middle of functions.
> - */
> -void kasan_unpoison_stack_above_sp_to(const void *watermark)
> -{
> -       const void *sp = __builtin_frame_address(0);
> -       size_t size = watermark - sp;
> -
> -       if (WARN_ON(sp > watermark))
> -               return;
> -       kasan_unpoison_shadow(sp, size);
> -}
> -
>  void kasan_alloc_pages(struct page *page, unsigned int order)
>  {
>         u8 tag;
> --
> 2.27.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200706143505.23299-1-vincenzo.frascino%40arm.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwvLb9BD%3DGdKuZp9v2620JKWgk9ShXUdx2tWSZNw1UJBQ%40mail.gmail.com.
