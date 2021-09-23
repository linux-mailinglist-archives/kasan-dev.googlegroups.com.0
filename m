Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQWDWGFAMGQEUZSPMNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EBCB415C9E
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 13:15:15 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id p12-20020ad4496c000000b0037a535cb8b2sf19258539qvy.15
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 04:15:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632395714; cv=pass;
        d=google.com; s=arc-20160816;
        b=eMMoAPkcxEtnVYo42P0SJpfsjKjk4w0styZnz31RVa18SQjOr8BmUP+Txsbhqx8xw4
         N7Sg+BpRxXxTfhkvCmpYlG/axPKvJguBfGiHxJtja2qWIFqd/ICcYP8peImV8ZQKoh5N
         3ONQFqht8fZUHMyqaeG0bEouM1E8htGGRZy0rDF/8N+5mPvGKLOyzOg06mBPCYlmckST
         ykPMEScNvG4fQCitRkaY4UXXmF+aMjjIkR9b/IzzzLiP4U/nHN0EwJ3xaw5sfoqKUEOs
         JWZKNk79tk7NUMJtMWm+dfg0td6OZzMMZfbcvT/AC+RTm5+7KClfwOdyemeLqyejC6Qj
         NThg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JKubqrkm+JkeEKY/PfBVxr3sUA7b8RT8dXbLWq3fMXA=;
        b=Zys6Sxgs9NT0xj4nVM6V4KzkwMREWc6WJ27o6T1kR4QcTgArmvM4DINOctEc5sasPV
         wdpoauaoiiSqITG53GlRQNtYugKFkDMj5w0r0lyC8p8stYsjGJUYtJgdoYknA3iGCKea
         1vP4CVwwR7zSEvJ/+m9oLGakrjUwv3otQFOIqG2sL4DTRm84v+XLBQynkcMqARx/L2fM
         5bzPRZ+3WgvXhhblIXUSgeieXGe2YRUAweAvl09fkdKVvMAXMezThLlm1IlbDXao8POC
         YEdKn6h4yJs+chdEnOcr8huBLfw4Z9Y23DEtcBlpTllCWir4Jd+UHICKRxaIGOWsLd4C
         m6rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="L4y/1Lm4";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=JKubqrkm+JkeEKY/PfBVxr3sUA7b8RT8dXbLWq3fMXA=;
        b=EbPuOlWpsvIVZWKUp9atGvSIgit3qcAkCIl10ydR+Aeb3UfIL8xOBYRfy/WEwVaR2I
         52y6RVv+QjixfRj7R0mtpUStE3KS5YdH09S1Yxir8jZPiWaSB+r58khHsqGkcdpkyKEd
         tH58xJDbPaezw3iaZ9k5t7CUYnLcVeU7M4EMzpJvrXFv2iFP3EPQ3SHJDwj3ZbSxDHBo
         DMURNT/+3GzyC/fzMxfK+QgfSlooyxY0XEhvSt8OGij5x+wIoRvn1ektRglzJiRTVo8m
         p6AkbA5KDN+vcKcfM5kNce3dhwFZv05BN9IYOqVbOU6vSFEGTkjzyR541KR0unlQPl2Y
         F/2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JKubqrkm+JkeEKY/PfBVxr3sUA7b8RT8dXbLWq3fMXA=;
        b=uvQcBU7hDU17p3wNvthk6P93XXBZICHvjZwQUYILs5kY6tZe08pqrE9i//JAfKDzz0
         99eYO4cjgy1Ug6V2ioJnlBYXzQf+PZc79IHAp/EZqb752MXsAuLij75HAbfymfvmXAxh
         AoDI5rIE0SkpxuNGIVXOYPOOL565g51BvjTldlzLQSSdvh6A2XEDLwtgy97ftDrNApoN
         K3OqEL70tI1jWljMA4NNsQLhgIdhWtAAkT72Lk4anlSwExCNT1cQvMvpeBShkxvKPJ/3
         9rG+/19KzqOBzaPqDjl5B69HFHu2Oj9bLFtzP5rvgNQS0rd62iK0pG9eOxTYMExHxYiq
         iBCQ==
X-Gm-Message-State: AOAM533mwxbG5J9/wvPaUDpwR/OedccBZ118pK0WSLfqldgkJy5oYS8A
	8ryI3BDTGxpVmUkxEYQEBpc=
X-Google-Smtp-Source: ABdhPJzvfRrKIjpFx0SFBL2osvH2Jgk82ivTiqJXT2EGVHud+KbNM9XnUqjQmS9AgeAqo43OEa3ZNg==
X-Received: by 2002:a37:6596:: with SMTP id z144mr4229540qkb.292.1632395714535;
        Thu, 23 Sep 2021 04:15:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:f90b:: with SMTP id l11ls4062014qkj.0.gmail; Thu, 23 Sep
 2021 04:15:14 -0700 (PDT)
X-Received: by 2002:a05:620a:6a3:: with SMTP id i3mr4101352qkh.483.1632395714079;
        Thu, 23 Sep 2021 04:15:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632395714; cv=none;
        d=google.com; s=arc-20160816;
        b=GklkMdKdzWU0GLALDLVfHO1I9V2aSGvZ2vHUQb4MT761SFcHY6LynWO7i7eUKt6M2j
         dGF8QrsWYP4F5EioBLGwcvpXJVcBwQy5RR3vTu+d33s06Kxn3DQlPuB+ixHVANlfv1XT
         6oAOOGIx1iDJaRHwIeAuZ8kgbuqVFpgHYmu7G0h3rc+YQ61Izbe8gXt8T16vFZ0t7v3I
         ljzdWCC6XBC7m8Sj7yz0Wy2fYA3Nn2PpHRjx0JOJonVrWtPkkA5wE8WrlHThf0ipqrCX
         BLTolmUmLomUC2r2AB7iySHXKKcclyIKEC13HAPuj6zstYU6jsqC2blO1UBFe6AL5C/Q
         Np4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lqxtxP5+e+pk1U3fha6q3vivDTvYwQzQQPvtliibVDE=;
        b=di87baypAXsQrpKHFzR+nga2w0Tlk2tpBcMWNojtSfErMnLkAR1sHlUUDr3y3+c7yL
         YdYOa3Ru1US0JppTTbF1o2rO3KNsKqSacVsHZory/vPUPNQfvpwArt6v9edysU8KqF1d
         41UVhodyi5y2coF5ePNGr52ZsfU9NqVqDip8uMbPpDdOYAtPe9+olEtijqEiUVR9HbVU
         +xDmhLlFxnJwzpRD9LOCGEp1pv1HsWRlx87TY6JfmgwPKkoSNDtfquEX+BOvvvwlzJev
         OsF33aSIa86iYyPSobZilwICu+TngA+hXw4HQhAK2rAlgKcvmzireT7J5mFrGk7SuSsD
         0oKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="L4y/1Lm4";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x830.google.com (mail-qt1-x830.google.com. [2607:f8b0:4864:20::830])
        by gmr-mx.google.com with ESMTPS id q27si403552qtl.0.2021.09.23.04.15.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 04:15:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) client-ip=2607:f8b0:4864:20::830;
Received: by mail-qt1-x830.google.com with SMTP id u21so5749013qtw.8
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 04:15:14 -0700 (PDT)
X-Received: by 2002:ac8:5c49:: with SMTP id j9mr4078733qtj.246.1632395713528;
 Thu, 23 Sep 2021 04:15:13 -0700 (PDT)
MIME-Version: 1.0
References: <20210923104803.2620285-1-elver@google.com>
In-Reply-To: <20210923104803.2620285-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Sep 2021 13:14:36 +0200
Message-ID: <CAG_fn=Vr7CJiug+C2LT2U5wdmysG5BbTFwU2-yaz-pe0kvaXPw@mail.gmail.com>
Subject: Re: [PATCH v3 1/5] stacktrace: move filter_irq_stacks() to kernel/stacktrace.c
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="L4y/1Lm4";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Sep 23, 2021 at 12:48 PM Marco Elver <elver@google.com> wrote:
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
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

> ---
> v3:
> * Rebase to -next due to conflicting stackdepot changes.
>
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
> index ee03f11bb51a..c34b55a6e554 100644
> --- a/include/linux/stackdepot.h
> +++ b/include/linux/stackdepot.h
> @@ -30,8 +30,6 @@ int stack_depot_snprint(depot_stack_handle_t handle, ch=
ar *buf, size_t size,
>
>  void stack_depot_print(depot_stack_handle_t stack);
>
> -unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_e=
ntries);
> -
>  #ifdef CONFIG_STACKDEPOT
>  int stack_depot_init(void);
>  #else
> diff --git a/include/linux/stacktrace.h b/include/linux/stacktrace.h
> index 9edecb494e9e..bef158815e83 100644
> --- a/include/linux/stacktrace.h
> +++ b/include/linux/stacktrace.h
> @@ -21,6 +21,7 @@ unsigned int stack_trace_save_tsk(struct task_struct *t=
ask,
>  unsigned int stack_trace_save_regs(struct pt_regs *regs, unsigned long *=
store,
>                                    unsigned int size, unsigned int skipnr=
);
>  unsigned int stack_trace_save_user(unsigned long *store, unsigned int si=
ze);
> +unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_e=
ntries);
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
> @@ -373,3 +374,32 @@ unsigned int stack_trace_save_user(unsigned long *st=
ore, unsigned int size)
>  #endif /* CONFIG_USER_STACKTRACE_SUPPORT */
>
>  #endif /* !CONFIG_ARCH_STACKWALK */
> +
> +static inline bool in_irqentry_text(unsigned long ptr)
> +{
> +       return (ptr >=3D (unsigned long)&__irqentry_text_start &&
> +               ptr < (unsigned long)&__irqentry_text_end) ||
> +               (ptr >=3D (unsigned long)&__softirqentry_text_start &&
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
> +unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_e=
ntries)
> +{
> +       unsigned int i;
> +
> +       for (i =3D 0; i < nr_entries; i++) {
> +               if (in_irqentry_text(entries[i])) {
> +                       /* Include the irqentry function into the stack. =
*/
> +                       return i + 1;
> +               }
> +       }
> +       return nr_entries;
> +}
> +EXPORT_SYMBOL_GPL(filter_irq_stacks);
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 69c8c9b0d8d7..b437ae79aca1 100644
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
> @@ -417,26 +416,3 @@ depot_stack_handle_t stack_depot_save(unsigned long =
*entries,
>         return __stack_depot_save(entries, nr_entries, alloc_flags, true)=
;
>  }
>  EXPORT_SYMBOL_GPL(stack_depot_save);
> -
> -static inline int in_irqentry_text(unsigned long ptr)
> -{
> -       return (ptr >=3D (unsigned long)&__irqentry_text_start &&
> -               ptr < (unsigned long)&__irqentry_text_end) ||
> -               (ptr >=3D (unsigned long)&__softirqentry_text_start &&
> -                ptr < (unsigned long)&__softirqentry_text_end);
> -}
> -
> -unsigned int filter_irq_stacks(unsigned long *entries,
> -                                            unsigned int nr_entries)
> -{
> -       unsigned int i;
> -
> -       for (i =3D 0; i < nr_entries; i++) {
> -               if (in_irqentry_text(entries[i])) {
> -                       /* Include the irqentry function into the stack. =
*/
> -                       return i + 1;
> -               }
> -       }
> -       return nr_entries;
> -}
> -EXPORT_SYMBOL_GPL(filter_irq_stacks);
> --
> 2.33.0.464.g1972c5931b-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVr7CJiug%2BC2LT2U5wdmysG5BbTFwU2-yaz-pe0kvaXPw%40mail.gm=
ail.com.
