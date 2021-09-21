Return-Path: <kasan-dev+bncBCMIZB7QWENRBZPQU2FAMGQE5GE3EPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id A46B64131EB
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 12:48:06 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id i2-20020a1709026ac200b0013a0caa0cebsf8662635plt.23
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 03:48:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632221285; cv=pass;
        d=google.com; s=arc-20160816;
        b=lG7sMyotRFEwbeyvRA9d1MLdEJXCKXPvTMs9ZFwRV6ZYvdm+aPu8oa/Of9zCWK0DEa
         j3Asmr3HFix2o0PbCDTOXUUb5+qJ27Pbh7MSooSB3hicL29nv+W3j5s5fhndv2I8sIrY
         My0QGl+Ipr46y75TR3IB2Itd0Kq3Y+n1VW1YnBaoiuJesqTdq2QApG4GyPsINpZVhG1i
         wp0cW6UhuK5rfmfd7tdydpWXZFpHNf+q/Fq40RWB1PYV7UT0PMEiWBpb+ZrRSkFvubDE
         rJNFfBJm63sRHeyOU2De8mIJLlbqhPxAKXznjsv9cP7k0xgVZMSgapMs5cSakDG3O+Em
         R6fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ofFTSugPhctX+CRcLztw/U6N1e8TryLSW6fZOpjTkCQ=;
        b=swM8Qhp4OHimGi3B1vnWzIR0RaQhzjsBUvAV9Jg507bMt9uoYTe4H1tSCkSBvrAKrD
         hzcNEJpyD+NuIwOpy0vcB7jD6QyF4iAO3/n/KQ2wkaFkJN2Y8UbiwsfcedAbcPv8TdR3
         1tGwMacoIfqang747EVOiF6DHGU6e+b9dg7hfrzvcjfN9LGSjgE+ix6NUnsQPTS9kRpm
         AGb9zOulFcviR97qHOkrKNSM89+T+o1g83OzKcM0Tn2t/t1X0vIWE41zxbhgV+gvKpR9
         ywrBTAubTxpUTVIz53rqDV+wbVWPDR3wXh4FzZh/1N2XlxXXF2Ie4RWQoi8cCSvU3C8X
         AIBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PVwaMyY2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ofFTSugPhctX+CRcLztw/U6N1e8TryLSW6fZOpjTkCQ=;
        b=cHdTLpI1rsGh46nI3CCzBUbh2x3Er8IfNAFAONCuAr4XrmL1r9qawmqNt5cCuJzux2
         tYlwoP9YG/yPJNRbaaGTdYrVPjaprfDjTP+SicRY2OdMBQWn5O++6wCG3/neuhF2v2mr
         BXE3adUuYadRkXOXybc8Wl99MJgjDf5BpF0wswwBiAUxc8hXIIcQhmInAfutaw2Z6iw+
         8Ngo8ANOGdiKkWFYdskKiQgHzG0zKqV8+9QM4BTJ9ZO8ZzvTUduNkRXrq7uSbXaMKfoo
         3hjttl6GPgLQ60WZQFVZ4AAldr6CBusgJ/tGIgfF/xnfw7g0rD0Ag0Fr12oyEnA8cp7t
         9CNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ofFTSugPhctX+CRcLztw/U6N1e8TryLSW6fZOpjTkCQ=;
        b=rB4RQm/7P8UuIINPCF1nJpDuwilNue00NFT9nQt4OZSUjk99x5Tnbo3hEwJFoBP/s+
         voK3km8IQ6NnTjP9+rsfFMdJHV0bB61L1Ca64J8FWsFGfmbeCxPuzrAMdj6AsVCJqQPJ
         CmvbjRiQF4HiX0Q955H4ry5HYFOvrevbWVjVo7gzW2bCdT5fJJCDZUK2HNRYnWQ+t4ht
         gPGyvSMj9fW8FzSD+mFAeb37GRvDSWb/BTSudaqVDUUArVCKz3ZUPtcDEuUEbdcyXajF
         c++iJuF7gIRRpCh4ht0j8aEstOIgwgUJfV014XiFn7RfWRz5go3tmnRENTs+ONX1/f9y
         Tf7g==
X-Gm-Message-State: AOAM532dWYIWtx/nqPWH5ZINVi3q10gkRqdofk19SshacvT95yfitHZN
	xbwyZ4aWx+maZBLJtKeldVo=
X-Google-Smtp-Source: ABdhPJwBqJHFdEUvop7s49WA586y01xquelWGHPJPGcNGwK+5lqh/WL5u90kjDB7HM9H+943NX1uNg==
X-Received: by 2002:a17:902:b696:b0:13a:7871:55f5 with SMTP id c22-20020a170902b69600b0013a787155f5mr27000602pls.60.1632221285365;
        Tue, 21 Sep 2021 03:48:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a409:: with SMTP id p9ls9808650plq.3.gmail; Tue, 21
 Sep 2021 03:48:04 -0700 (PDT)
X-Received: by 2002:a17:90a:1a06:: with SMTP id 6mr4589972pjk.150.1632221284787;
        Tue, 21 Sep 2021 03:48:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632221284; cv=none;
        d=google.com; s=arc-20160816;
        b=zjHxdahOEuQhuLcErCkuaWd4dM5tGqPoCLU+5cpPUwS2OrpOqaDoorRVb9oSKThjS2
         bnPVaIKTG/b0mEgY2zkeq3Pr8JUVdjVGI8epteElyjoHoMI4DPA17fGRvWn2KaLXALdF
         0n2BC86+Of2Gy4nj0WnocE4diJIvP4QbpKUmW2IghdSr0e1w5vS2My7X7EPqFWNR1PYX
         K07XzzsnKgBYNZ6hbWHB+l0kK04ngEj378V5soHlMwdWHYSCkWhRTsgoI8Oat59Hy4+K
         icqI2JX6RZ1++intpduazfvcHD6Puvd1B3gE8r+PLYHkHt428wuoa6Oshx/uVTJGO4bn
         q8xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2DaWAIvqIvKGgWien1JtzLRCFsCI+adGg6lemtVNxaQ=;
        b=G+FMnE7PxTnfR71N5lICtybDAn+MnH7Ygi41naH+n7mchZ0k0TA9Sq/o2IlOh+Xzxi
         /GsBfzJi7DYkqJ2YEoTecSMVpGQpbZdOy41EU0TOKdRfwnqLNe3pNs4gve/IIAYCN/cO
         baa/GF5sMSAeuTCCns/et9Ctjr13ixNE4Jx5/UUwXvCQjnVBdkR0s9tn1oWuy5OmrawF
         Cfyev3OkduJ5/f8zdaCdXnAFprIBm7UG44pP5mPyFFdVlwJ75NMeI1/hZBHzvljch1jP
         +W4Dnie8jzvfutn+Ekg6z4vI+V7mny4OKrsPGFY9qDOhNwyhB5e7SSgLd5SeHL1q80+C
         Pz3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PVwaMyY2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id n63si276579pfd.3.2021.09.21.03.48.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Sep 2021 03:48:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id 5-20020a9d0685000000b0054706d7b8e5so8883846otx.3
        for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 03:48:04 -0700 (PDT)
X-Received: by 2002:a9d:7244:: with SMTP id a4mr25928089otk.137.1632221283883;
 Tue, 21 Sep 2021 03:48:03 -0700 (PDT)
MIME-Version: 1.0
References: <20210921101014.1938382-1-elver@google.com>
In-Reply-To: <20210921101014.1938382-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Sep 2021 12:47:52 +0200
Message-ID: <CACT4Y+aUD=hRR0oJH7Spcs375RNuRxga=umSzgN7PsZG4kX4BQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/5] stacktrace: move filter_irq_stacks() to kernel/stacktrace.c
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PVwaMyY2;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, 21 Sept 2021 at 12:10, Marco Elver <elver@google.com> wrote:
>
> filter_irq_stacks() has little to do with the stackdepot implementation,
> except that it is usually used by users (such as KASAN) of stackdepot to
> reduce the stack trace.
>
> However, filter_irq_stacks() itself is not useful without a stack trace
> as obtained by stack_trace_save() and friends.
>
> Therefore, move filter_irq_stacks() to kernel/stacktrace.c, so that new
> users of filter_irq_stacks() do not have to start depending on
> STACKDEPOT only for filter_irq_stacks().
>
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v2:
> * New patch.
> ---
>  include/linux/stackdepot.h |  2 --
>  include/linux/stacktrace.h |  1 +
>  kernel/stacktrace.c        | 30 ++++++++++++++++++++++++++++++
>  lib/stackdepot.c           | 24 ------------------------
>  4 files changed, 31 insertions(+), 26 deletions(-)
>
> diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
> index 6bb4bc1a5f54..22919a94ca19 100644
> --- a/include/linux/stackdepot.h
> +++ b/include/linux/stackdepot.h
> @@ -19,8 +19,6 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
>  unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>                                unsigned long **entries);
>
> -unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_entries);
> -
>  #ifdef CONFIG_STACKDEPOT
>  int stack_depot_init(void);
>  #else
> diff --git a/include/linux/stacktrace.h b/include/linux/stacktrace.h
> index 9edecb494e9e..bef158815e83 100644
> --- a/include/linux/stacktrace.h
> +++ b/include/linux/stacktrace.h
> @@ -21,6 +21,7 @@ unsigned int stack_trace_save_tsk(struct task_struct *task,
>  unsigned int stack_trace_save_regs(struct pt_regs *regs, unsigned long *store,
>                                    unsigned int size, unsigned int skipnr);
>  unsigned int stack_trace_save_user(unsigned long *store, unsigned int size);
> +unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_entries);
>
>  /* Internal interfaces. Do not use in generic code */
>  #ifdef CONFIG_ARCH_STACKWALK
> diff --git a/kernel/stacktrace.c b/kernel/stacktrace.c
> index 9f8117c7cfdd..9c625257023d 100644
> --- a/kernel/stacktrace.c
> +++ b/kernel/stacktrace.c
> @@ -13,6 +13,7 @@
>  #include <linux/export.h>
>  #include <linux/kallsyms.h>
>  #include <linux/stacktrace.h>
> +#include <linux/interrupt.h>
>
>  /**
>   * stack_trace_print - Print the entries in the stack trace
> @@ -373,3 +374,32 @@ unsigned int stack_trace_save_user(unsigned long *store, unsigned int size)
>  #endif /* CONFIG_USER_STACKTRACE_SUPPORT */
>
>  #endif /* !CONFIG_ARCH_STACKWALK */
> +
> +static inline bool in_irqentry_text(unsigned long ptr)
> +{
> +       return (ptr >= (unsigned long)&__irqentry_text_start &&
> +               ptr < (unsigned long)&__irqentry_text_end) ||
> +               (ptr >= (unsigned long)&__softirqentry_text_start &&
> +                ptr < (unsigned long)&__softirqentry_text_end);
> +}
> +
> +/**
> + * filter_irq_stacks - Find first IRQ stack entry in trace
> + * @entries:   Pointer to stack trace array
> + * @nr_entries:        Number of entries in the storage array
> + *
> + * Return: Number of trace entries until IRQ stack starts.
> + */
> +unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_entries)
> +{
> +       unsigned int i;
> +
> +       for (i = 0; i < nr_entries; i++) {
> +               if (in_irqentry_text(entries[i])) {
> +                       /* Include the irqentry function into the stack. */
> +                       return i + 1;
> +               }
> +       }
> +       return nr_entries;
> +}
> +EXPORT_SYMBOL_GPL(filter_irq_stacks);
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 0a2e417f83cb..e90f0f19e77f 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -20,7 +20,6 @@
>   */
>
>  #include <linux/gfp.h>
> -#include <linux/interrupt.h>
>  #include <linux/jhash.h>
>  #include <linux/kernel.h>
>  #include <linux/mm.h>
> @@ -341,26 +340,3 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
>         return retval;
>  }
>  EXPORT_SYMBOL_GPL(stack_depot_save);
> -
> -static inline int in_irqentry_text(unsigned long ptr)
> -{
> -       return (ptr >= (unsigned long)&__irqentry_text_start &&
> -               ptr < (unsigned long)&__irqentry_text_end) ||
> -               (ptr >= (unsigned long)&__softirqentry_text_start &&
> -                ptr < (unsigned long)&__softirqentry_text_end);
> -}
> -
> -unsigned int filter_irq_stacks(unsigned long *entries,
> -                                            unsigned int nr_entries)
> -{
> -       unsigned int i;
> -
> -       for (i = 0; i < nr_entries; i++) {
> -               if (in_irqentry_text(entries[i])) {
> -                       /* Include the irqentry function into the stack. */
> -                       return i + 1;
> -               }
> -       }
> -       return nr_entries;
> -}
> -EXPORT_SYMBOL_GPL(filter_irq_stacks);
> --
> 2.33.0.464.g1972c5931b-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaUD%3DhRR0oJH7Spcs375RNuRxga%3DumSzgN7PsZG4kX4BQ%40mail.gmail.com.
