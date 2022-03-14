Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXGQXOIQMGQEJP3WARI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 131BA4D7B1F
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Mar 2022 08:01:50 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id j10-20020a17090a7e8a00b001bbef243093sf13168301pjl.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Mar 2022 00:01:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1647241308; cv=pass;
        d=google.com; s=arc-20160816;
        b=haDKSeYOZNolXO4UXIzUM0/0gu4PDKfD9M2XBFo82JCmSKPff/euDXXE2v40vpGtix
         7QoIgyUzoZGc6gZgqV1sXtq6ram1HJDfvm5L8tRNwEjCYUkLUoRi7XRR9fFEwAt3t/FW
         XULMagJt9zP8lA6P+AqSXeDHKAJ8YsK/7KOk2mH/TsazmnQdLxXgqajPYz5y4bJSHseg
         Ms0Vi3nr1bg9u4H33+XGLLb48Fslz9rkHmqHvhsOw7SnCRzgT1JS7A79TLQ+UcMkbzSf
         TAhEykUueuzbHDcXByf3P+7t4HFZdyPBCnmlxUbPpfsmJvT+0gp2LkUev0gll/q+PHdA
         mP0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=b41/FjVrZWVFulegzgFPI++zf8/4XMaAZyDx51PVQc8=;
        b=FJpCL1rS69sr+WT0g6CC7ntDUQFc8N6Wdi8Iz7gP7wXBm7tIMSCFrqMQMegoBV0sBQ
         zdEAKSV01KR5m3xL9+K+xpheUannn6Z4Y7pvv9IaeMtKwUorGvQa9Y9bfaCHuR9l403s
         3ssOOqKyi8wt8bycrEhxmhUJo24VEUxgblmfXPNeBrFUzm2tql82De8BDTWTcNpylK9I
         UshQqBFEOoWvp7vRlZk6m+nYxR2tZFun7DsOKBAbAf9lESgflsNRwuuf6b479SWy9E5j
         QEaDxfneAOALKCtnx2y/ujnKWLiMliI+HZO+3kbe7WHsyfas3hZYQfOu7VS6+fOUXbAu
         miSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YVTqjtBD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b41/FjVrZWVFulegzgFPI++zf8/4XMaAZyDx51PVQc8=;
        b=but8azrU0zodVGGdmNQ0zXHJezw6MzBi7zVllhxlIkaJk4AA7tTj2nBAn4fKR3mAgH
         Zis+UekiPdmVpzyVA47fB6aIKTctj2QObcgJldnesNbwj55GFic+G0raTSHuGrukTH9I
         /hIXkVpuMPxf+xK0dWRaqdlGhvobV0DtqOAtxu/ZAqqZtPYq5Nh11ciZsl9k9HAOQ7og
         l4WwTTUzj8XyL1HMH3rc2yoOj2EBgJUlZzG6I5SDnu7HXYp55fLbIrZNKLXzGwg1jEXK
         NMVYkljGbxTy+pN7rE4ikFOwAiXlbXWawy1uJPY50RCWC5MXdO8igui+Wjuv1fgnF8ZW
         T0lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b41/FjVrZWVFulegzgFPI++zf8/4XMaAZyDx51PVQc8=;
        b=S4bwlmKFEbdVxfem+RfieMxXfMVe4VEELQrDKB6iWG3cM8ttIV/+inQcRlUMLzZUEQ
         yeszbSNqxT8GqRdC2nde38AWpEteDIeJEAqtmEt6BrUhFAobvLlFTchP59kWK7VwoPC0
         /R7qXg59VSXHkBtvswKbpFBODx6AGezZDoZD7V6RyquLxrznvdmshbBWwJJtMsLUiDqh
         skmXspwpr7vvdStwSi3en/OxC0ZkGA/wa/aPn5cjCQUeBzGST20WDXJTSCU2FY7A/sew
         fdst+cdvVNFo0Zq4IL0fswO3AK19vq874r0Lt+w+V4ug0134yPqatPoMFqgjvBbmB4sq
         25/A==
X-Gm-Message-State: AOAM53054I8MjES2aLoYnoYJy7rObVXyEp3fmK1t7IFCcAPKX/5q2+iW
	OnwRp8Ab3rVaZQiAWiMIYGQ=
X-Google-Smtp-Source: ABdhPJwBW7i6ZX+VvB4luOON4wWvS7aHJ92zkleyDTkW2sKx//pcV+7kfB9igHc+npKET6sW2PS57Q==
X-Received: by 2002:a05:6a00:1809:b0:4f7:673d:7de5 with SMTP id y9-20020a056a00180900b004f7673d7de5mr22493306pfa.52.1647241308764;
        Mon, 14 Mar 2022 00:01:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1684:b0:4e1:b713:eb10 with SMTP id
 k4-20020a056a00168400b004e1b713eb10ls3857411pfc.9.gmail; Mon, 14 Mar 2022
 00:01:48 -0700 (PDT)
X-Received: by 2002:a05:6a00:1a56:b0:4f7:c17b:28da with SMTP id h22-20020a056a001a5600b004f7c17b28damr5478953pfv.50.1647241307983;
        Mon, 14 Mar 2022 00:01:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1647241307; cv=none;
        d=google.com; s=arc-20160816;
        b=Nf4GsyW8k//DUpHhZ4F9IRvwnehoqAleKtvyb0Z7lAZhgaEhHokPbJWDjsrgO+wZZi
         qRUGflT9zoCCjPffbWnMxnzxnpYOTOoWP05xrWG01ydVJ7MNRnR0Q3py/U+DUSinUUts
         wOWdajar5koTgYurXjxss/rqTSF4bpoF6h/Vnz768ZZojdwt2Xr7G4JLj+FQ6TJMZZuI
         A5EbCPqMtRYPFcptPbSm/OCIx0xHyoZNH0NCtPXjfx79USqFyFihVh/lE2mKJRy3/BQk
         JwrLc4dUtIxPUUkH1sWsMP9GNSvF5qJLhWQ8lXv5YzpwWR2xx0npWDgJQBMHipJNHP9v
         DO3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=srqCigb1vWPaMd3DOBZQqhVr8vvkskgf2mmVXi17bKI=;
        b=vz2MobA7ijzxEiBmAUf5e06PvkPy/d9luYqcsdbojO+1cY0XuNgxaFugO5TJuW2xz9
         QvydCymswc5WPuBXhe9vk0lfurE30d1Li4p1/SP75ZMivveeqb6lU7G5GewgX6wKWigF
         IEt+evGKIcTNWJtmhfzRVl4dOc2+H2QRBCWxItHLAIVcV2Qel7EQWFgqIKgX3+9o0dYk
         xqPIB0V7hXOXxbXg7dZrdCvgZwz3GBhfHq9+L0RJbZCFxvhce5e78ABkGsqLoDmkkOEX
         xL2mzrlQcrHsi2+O5PFnTPvgbxpYkrkho9pUP5pUMuspwzYSVA/nhw/GBqI1z5QVsphd
         YrsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YVTqjtBD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id b13-20020a6567cd000000b0037c8bd7aa3esi901656pgs.3.2022.03.14.00.01.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Mar 2022 00:01:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id x200so28832839ybe.6
        for <kasan-dev@googlegroups.com>; Mon, 14 Mar 2022 00:01:47 -0700 (PDT)
X-Received: by 2002:a05:6902:24f:b0:62d:69d:c9fc with SMTP id
 k15-20020a056902024f00b0062d069dc9fcmr14878938ybs.87.1647241306986; Mon, 14
 Mar 2022 00:01:46 -0700 (PDT)
MIME-Version: 1.0
References: <57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl@google.com>
In-Reply-To: <57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Mar 2022 08:00:00 +0100
Message-ID: <CANpmjNNBzVovK=N9b2Lv0VUqpE_4nU+6gqO91_ojVoEbR0C5hA@mail.gmail.com>
Subject: Re: [PATCH] kasan, scs: collect stack traces from shadow stack
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YVTqjtBD;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as
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

On Sat, 12 Mar 2022 at 21:14, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Currently, KASAN always uses the normal stack trace collection routines,
> which rely on the unwinder, when saving alloc and free stack traces.
>
> Instead of invoking the unwinder, collect the stack trace by copying
> frames from the Shadow Call Stack whenever it is enabled. This reduces
> boot time by 30% for all KASAN modes when Shadow Call Stack is enabled.

This is impressive.

> To avoid potentially leaking PAC pointer tags, strip them when saving
> the stack trace.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Things to consider:
>
> We could integrate shadow stack trace collection into kernel/stacktrace.c
> as e.g. stack_trace_save_shadow(). However, using stack_trace_consume_fn
> leads to invoking a callback on each saved from, which is undesirable.
> The plain copy loop is faster.

Why is stack_trace_consume_fn required? This is an internal detail of
arch_stack_walk(), but to implement stack_trace_save_shadow() that's
not used at all.

I think having stack_trace_save_shadow() as you have implemented in
kernel/stacktrace.c or simply in kernel/scs.c itself would be
appropriate.

> We could add a command line flag to switch between stack trace collection
> modes. I noticed that Shadow Call Stack might be missing certain frames
> in stacks originating from a fault that happens in the middle of a
> function. I am not sure if this case is important to handle though.

I think SCS should just work - and if it doesn't, can we fix it? It is
unclear to me what would be a deciding factor to choose between stack
trace collection modes, since it is hard to quantify when and if SCS
doesn't work as intended. So I fear it'd just be an option that's
never used because we don't understand when it's required to be used.

> Looking forward to thoughts and comments.
>
> Thanks!
>
> ---
>  mm/kasan/common.c | 36 +++++++++++++++++++++++++++++++++++-
>  1 file changed, 35 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index d9079ec11f31..65a0723370c7 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -9,6 +9,7 @@
>   *        Andrey Konovalov <andreyknvl@gmail.com>
>   */
>
> +#include <linux/bits.h>
>  #include <linux/export.h>
>  #include <linux/init.h>
>  #include <linux/kasan.h>
> @@ -21,6 +22,7 @@
>  #include <linux/printk.h>
>  #include <linux/sched.h>
>  #include <linux/sched/task_stack.h>
> +#include <linux/scs.h>
>  #include <linux/slab.h>
>  #include <linux/stacktrace.h>
>  #include <linux/string.h>
> @@ -30,12 +32,44 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> +#ifdef CONFIG_SHADOW_CALL_STACK
> +
> +#ifdef CONFIG_ARM64_PTR_AUTH
> +#define PAC_TAG_RESET(x) (x | GENMASK(63, CONFIG_ARM64_VA_BITS))

This should go into arch/arm64/include/asm/kasan.h, and here it should
then just do

#ifndef PAC_TAG_RESET
#define ...


> +#else
> +#define PAC_TAG_RESET(x) (x)
> +#endif

But perhaps there's a better, more generic location for this macro?

> +static unsigned int save_shadow_stack(unsigned long *entries,
> +                                     unsigned int nr_entries)
> +{
> +       unsigned long *scs_sp = task_scs_sp(current);
> +       unsigned long *scs_base = task_scs(current);
> +       unsigned long *frame;
> +       unsigned int i = 0;
> +
> +       for (frame = scs_sp - 1; frame >= scs_base; frame--) {
> +               entries[i++] = PAC_TAG_RESET(*frame);
> +               if (i >= nr_entries)
> +                       break;
> +       }
> +
> +       return i;
> +}
> +#else /* CONFIG_SHADOW_CALL_STACK */
> +static inline unsigned int save_shadow_stack(unsigned long *entries,
> +                                       unsigned int nr_entries) { return 0; }
> +#endif /* CONFIG_SHADOW_CALL_STACK */
> +
>  depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
>  {
>         unsigned long entries[KASAN_STACK_DEPTH];
>         unsigned int nr_entries;
>
> -       nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> +       if (IS_ENABLED(CONFIG_SHADOW_CALL_STACK))
> +               nr_entries = save_shadow_stack(entries, ARRAY_SIZE(entries));
> +       else
> +               nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
>         return __stack_depot_save(entries, nr_entries, flags, can_alloc);
>  }
>
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNBzVovK%3DN9b2Lv0VUqpE_4nU%2B6gqO91_ojVoEbR0C5hA%40mail.gmail.com.
