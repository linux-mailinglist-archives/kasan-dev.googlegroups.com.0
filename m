Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2VZVOXQMGQEJLDCNOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 57C9C87610E
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Mar 2024 10:39:56 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3662d8ed7c5sf2535175ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Mar 2024 01:39:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709890795; cv=pass;
        d=google.com; s=arc-20160816;
        b=iw2C6PUYsdU7OaaPJJz6rQNj4jfjLR0eZairNx6k2nv1Pw1L6VRMSAvFApj0tHeFVe
         2XyJHpcHz1fnu1vCd5mZUZJrFkfNhcuxbp/1QA3EezQv8vtPHeHarfXqsJ9M4kufA0RU
         O1xh0m1WcabsK10Jd/lxARFtQ8Q5CxUePgLjxbzlE9lhMhnAF8FL0Wc+wWcVuD0swCxo
         skRay93Pg1GlT8L4ExC3zXGYIdkrGgjlUkZttURD9mIKSv8/+6qPXVm1/14uVbXhkGPo
         Ivv1WsP5RzHiQWhFs/w8xGZev0gu0DTPypmIKuusFd1opNAx5cWDWHbfe9KXgE2ZgtrO
         2SdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SMDkXeqI+MOttT7nt3QKYnvQBVsMk7u2qhv2FtyqWXA=;
        fh=KK79lVbyotPm6q+qsF7mjx9+cL/+N3/pPCcRr7PCJug=;
        b=0hFQ/IDsRZwgvBsnyk0zNH0IYOncC07O7TowJuUagljB1OLj3PqhMSN9ThT0Q+tUoI
         +2PkIwPWPL7fOLQ3yAi6kX86P7TFafVGaLmBUTr6zVsIqzd1YJvqSI9YudC2aSzW6ZQT
         +9D4DSNMf+fnJy4npOGNaStUTkaOfVFXEuRTO1z3Y0JkXpTkVDqHxgDLMn4cPEJMofBs
         1CUfiJAR19TqhxkgGy1BnIho5x2CcmPAAq7il9i/wvy9bzAOMbneEBnaocyL5ceYCR2I
         3OTvQzDnFZkF6NXqUDpJROCXSuu3/0Rfr6xkLKNy7FfRngnIMhtI5FxeGGJZT/YxRaD+
         3zfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=E0XHU2GY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709890795; x=1710495595; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SMDkXeqI+MOttT7nt3QKYnvQBVsMk7u2qhv2FtyqWXA=;
        b=rgNrfogj4V2/Eg7qNnfWyQJf3Zbklu8Yc6GhttFM8/KhUwDzZ6v06eKsYDLNF4oMpR
         rQGh3kscdi5dvj5KXKGbzpCgJG8p8FtUeGI0OFf6iDgxPw+u9xWRuPgERlf6dx+nr4hU
         e55Etu7If1KSLJ5Pr09ddLiOhZGNqJwnObMo4rUzsqvpW9cQ29MeR2LYaUyQ91QS2Otu
         7tGY5huPFp6N5ucGyiDnTCC7CLrxWQ7cd4mGYbJrrClU6C/uV0g4Oxe1O7wrhaq/dCv+
         u3BTnyrp7xa43XTGZQGWBVdpmUmkKlgypSt1Q36PN7uquDc6kkvhI0l4kFtn7wxFUz1N
         Yp4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709890795; x=1710495595;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SMDkXeqI+MOttT7nt3QKYnvQBVsMk7u2qhv2FtyqWXA=;
        b=YF4dseIwVmDw7EbpgwCKmTpaQTxVcg17VfZTpDIYwK6eTng947VK7hS2SE9LYt5FLO
         s3uWxX38MfgKVwtnP8DyfLkWzXeMTljRV77nGskUTj+YKU2C76AgCCoYxJhSORujmp66
         CnDq3c+GJfIjydkrGh5p6istJ1DgBjF7npUK9f7Yy9Nfygx6fN5qULvb9oA+lLoFNv+M
         cJ5oroCwvlSYHCQ4UD7s0l4mrYjy4k+DF9wK9WSBqJ1d8euYKx4lK0V3s8XtrBOYLWtf
         QHO5BVjaiSmNuPs4d6vJm03mv1Kw/k0VVjCFhpCP2Yo1zuuboug9Yhx27eX7e+LR70u0
         NdOw==
X-Forwarded-Encrypted: i=2; AJvYcCWDomDHkCwUrNQpR7X6Y9XtTkb6JqFduQViPco7u0gaNzESRPtDhGzOQzCYOSjTnK4vvJ9c1goLvdzNSfBqYhmQpqgbXGm4Zw==
X-Gm-Message-State: AOJu0Yyraxlw73x/JcwFnPfcfCzTUTig+O3Css6A/Ulasc08z86EVFzj
	sCnJN90vQxs05AVQ3frtvaNqBXPGM3aFhhZDD02cQiMmUNWeTTQm
X-Google-Smtp-Source: AGHT+IHGYaBwqMUmTJRW+ALAMZbtCrdm+1yhYXS1Y5A4farXEGJrGrC957HHLV7C0pMkBFtBblyR4w==
X-Received: by 2002:a05:6e02:194d:b0:366:1e8f:5f1a with SMTP id x13-20020a056e02194d00b003661e8f5f1amr3397515ilu.19.1709890795045;
        Fri, 08 Mar 2024 01:39:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1806:b0:364:f794:ec16 with SMTP id
 a6-20020a056e02180600b00364f794ec16ls339974ilv.0.-pod-prod-04-us; Fri, 08 Mar
 2024 01:39:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWH1LOcRX8D4I8imysrPBcuUqh4bAw+dbJ3bY6RwtP6tpLc69KW3LT4SlKLQ+Ra7pc1ReUJNxULbSa/zIcVmZ5VQsAmHNR0T6/ozw==
X-Received: by 2002:a05:6e02:1c82:b0:365:1563:c4e5 with SMTP id w2-20020a056e021c8200b003651563c4e5mr25400941ill.9.1709890794244;
        Fri, 08 Mar 2024 01:39:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709890794; cv=none;
        d=google.com; s=arc-20160816;
        b=bL6bTkODMyOttMa1f9SGcZdvz7jtJjL34CgBFHSfnQ3M5pxubgcS2EUaEkHapCTvTx
         8hcCyuNDv8aycZEwaQgb94Peu3l3RrKGyN4twoJLY4HrhlHWA5bdApFqObIvkNMoweQr
         A+6HtEH9Be/H7rRLIabfQcckZGhznkBYCz/yqYPO864w1zQiwFmR93rM8PbLi/a+YKng
         T+AvOh3HgybAHwNkXA94gwCYevq+bsjqSPJ/FKBs62IbnrKcuXCwY4RVxfIAnx1wdeyj
         VfjeuZt/o/hjUNIldaL2fn3eZhkyUIOI0dkYBBrybYNGt4JJppkRqVIU5jDuiIZTJpa0
         yfIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Mkn/lM2x4sb3JsolgYFeL1UFRJfnKJyId5+RqBqRGmc=;
        fh=lXyp2n9u98AzQc5ToR6aDkuwcPtBmuKm1MQUcu9T2no=;
        b=nSz3YymnguGccGC6Y0tvywihwm93a4Sxl624chcGgE3DMLqKjqTMUDyOvvfTWy5Sca
         HdP9JbmZQ4TopK1YCFAxhkdLsI97wQBhMKn1Rv6+6YbOnQ0rpuRXYhMNTUicRtp0jora
         GDCpqh8inPdBkFBsj7QsBs5rwaaWjN3u1lA3ZW3Ws+WF7zkHeqD0GSGXiDMkiWDvg39v
         9Og01U/Cf5bgQfEUsBFg76r8Kna6Ev7x/nZHaZ/babRc/AaMqMELCvvYaw0K1BSprhth
         EOo8TxzBG3tCoQp6DasX8OJYHgRxM6VbLdi0SEtAFjcluhhomw8e3XNQMYH3zcvzFosH
         5zkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=E0XHU2GY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa30.google.com (mail-vk1-xa30.google.com. [2607:f8b0:4864:20::a30])
        by gmr-mx.google.com with ESMTPS id i9-20020a056e02054900b0036503a50b98si1261097ils.4.2024.03.08.01.39.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Mar 2024 01:39:54 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) client-ip=2607:f8b0:4864:20::a30;
Received: by mail-vk1-xa30.google.com with SMTP id 71dfb90a1353d-4d3d1354a34so12794e0c.2
        for <kasan-dev@googlegroups.com>; Fri, 08 Mar 2024 01:39:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV4egZps3BOI617bJEVHnWFcHm9+ELK6iwLoWIVMNhheo8lJRlt+Cq5pI+/RHcCmV/WDn8nMNrCbj1+p6PAkesK6YCWzCe7upTNjQ==
X-Received: by 2002:a05:6122:2703:b0:4d1:34a1:c892 with SMTP id
 ej3-20020a056122270300b004d134a1c892mr11242267vkb.13.1709890793488; Fri, 08
 Mar 2024 01:39:53 -0800 (PST)
MIME-Version: 1.0
References: <20240308043448.masllzeqwht45d4j@M910t>
In-Reply-To: <20240308043448.masllzeqwht45d4j@M910t>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Mar 2024 10:39:15 +0100
Message-ID: <CANpmjNOc4Z6Qy_L3pjuW84BOxoiqXgLC1tWbJuZwRUZqs2ioMA@mail.gmail.com>
Subject: Re: [BUG] kmsan: instrumentation recursion problems
To: Changbin Du <changbin.du@huawei.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=E0XHU2GY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as
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

On Fri, 8 Mar 2024 at 05:36, 'Changbin Du' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Hey, folks,
> I found two instrumentation recursion issues on mainline kernel.
>
> 1. recur on preempt count.
> __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> preempt_disable() -> __msan_metadata_ptr_for_load_4()
>
> 2. recur in lockdep and rcu
> __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> pfn_valid() -> rcu_read_lock_sched() -> lock_acquire() -> rcu_is_watching() -> __msan_metadata_ptr_for_load_8()
>
>
> Here is an unofficial fix, I don't know if it will generate false reports.
>
> $ git show
> commit 7f0120b621c1cbb667822b0f7eb89f3c25868509 (HEAD -> master)
> Author: Changbin Du <changbin.du@huawei.com>
> Date:   Fri Mar 8 20:21:48 2024 +0800
>
>     kmsan: fix instrumentation recursions
>
>     Signed-off-by: Changbin Du <changbin.du@huawei.com>
>
> diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
> index 0db4093d17b8..ea925731fa40 100644
> --- a/kernel/locking/Makefile
> +++ b/kernel/locking/Makefile
> @@ -7,6 +7,7 @@ obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
>
>  # Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
>  KCSAN_SANITIZE_lockdep.o := n
> +KMSAN_SANITIZE_lockdep.o := n

This does not result in false positives?

Does
KMSAN_ENABLE_CHECKS_lockdep.o := n
work as well? If it does, that is preferred because it makes sure
there are no false positives if the lockdep code unpoisons data that
is passed and used outside lockdep.

lockdep has a serious impact on performance, and not sanitizing it
with KMSAN is probably a reasonable performance trade-off.

>  ifdef CONFIG_FUNCTION_TRACER
>  CFLAGS_REMOVE_lockdep.o = $(CC_FLAGS_FTRACE)
> diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> index b2bccfd37c38..8935cc866e2d 100644
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -692,7 +692,7 @@ static void rcu_disable_urgency_upon_qs(struct rcu_data *rdp)
>   * Make notrace because it can be called by the internal functions of
>   * ftrace, and making this notrace removes unnecessary recursion calls.
>   */
> -notrace bool rcu_is_watching(void)
> +notrace __no_sanitize_memory bool rcu_is_watching(void)

For all of these, does __no_kmsan_checks instead of __no_sanitize_memory work?
Again, __no_kmsan_checks (function-only counterpart to
KMSAN_ENABLE_CHECKS_.... := n) is preferred if it works as it avoids
any potential false positives that would be introduced by not
instrumenting.

>  {
>         bool ret;
>
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index 9116bcc90346..33aa4df8fd82 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -5848,7 +5848,7 @@ static inline void preempt_latency_start(int val)
>         }
>  }
>
> -void preempt_count_add(int val)
> +void __no_sanitize_memory preempt_count_add(int val)
>  {
>  #ifdef CONFIG_DEBUG_PREEMPT
>         /*
> @@ -5880,7 +5880,7 @@ static inline void preempt_latency_stop(int val)
>                 trace_preempt_on(CALLER_ADDR0, get_lock_parent_ip());
>  }
>
> -void preempt_count_sub(int val)
> +void __no_sanitize_memory preempt_count_sub(int val)
>  {
>  #ifdef CONFIG_DEBUG_PREEMPT
>
>
> --
> Cheers,
> Changbin Du

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOc4Z6Qy_L3pjuW84BOxoiqXgLC1tWbJuZwRUZqs2ioMA%40mail.gmail.com.
