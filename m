Return-Path: <kasan-dev+bncBCMIZB7QWENRBJOYXOIQMGQEIBD3A4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 386454D7B6D
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Mar 2022 08:17:59 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id p15-20020a17090a748f00b001bf3ba2ae95sf9346535pjk.9
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Mar 2022 00:17:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1647242278; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yv9yBzik3+CC3EctaEjgVes+lFUm7zMw4e9O1v2MD0IOQp5mF/n7gXhR73VMXu/Ch7
         vB+mP/IPm14uXCzq+2WSIFgAGgZyX3cdUfGblbaeSHp5zO/bNzJ5HskD0QZlw/HyEp17
         L++yWvNSz2Faj/L2XeumQj7925ohcA73zKlBZWYqFKJY4MByCv6JzYuheR+P5w2xpmqs
         3wbejKaNWljy7WGLZInPgz7Mjj4jg6VRIOyX4SR0mifqxgSdmlcR7boCFTjELnWuuFLt
         ML8JU+v3rkjCnHKNeFwdQ5RUjS/P6iiBgqfkOAj68CBU4ke/CLgXUi9gNRGCAx5IkCiq
         sYyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HpozNCNc1BElEXWai289GpG9IL2yJV6JSywhmxFoe1k=;
        b=haH9HylB/h9h+tNCR6KqOXHcEHjEQj/Dfq2d02EZroZ87s/2q0zTYjSuQdRwMtwm/l
         3xpFMan7d/bnIamURPRyVJGMKTukh4RxzAsPNZ7Fu4SF21CiLKjH4Ky7TGzP/x+bpRKw
         mP5AE3v1+DDgoGSaUl7vXaqbjHEGWdBDKIXRrPMhDhjq5AAhjTmRPzkMGrFb3/oYe1OA
         6mSKtTBk89eXYTeiwOAzYjpkqv/RIt8gyPLun7kbcS4xjz5/Oh6Q8txZMDaevLV/mxIV
         KfTGRGtpqn2GYLefyowbY4N516We4bQbUzfZLoEToP5OPt2ApJ9vQkj2/jwVx/gxoo+1
         I8cA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D8uyMk8E;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c34 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HpozNCNc1BElEXWai289GpG9IL2yJV6JSywhmxFoe1k=;
        b=LCWaeW+/u/B7wUnCmYbEr88AFD9JVe2hRnrL8MS6yJvA1ouJt5lSF2ooV79mQiuKqk
         N1+zMBt86BM2+uvFQ6aV3q3Q2+2B0aSAitUO6zVSE+hoIhrvpT1Si/pJmHc0jpu8CKdC
         tBdbAXTj3aIZUIMUzLrIpWopZCoSyKgcdvODX5vQqdT5Xwme/rShvcgJM20w14trzrx2
         CUsO/R0A1IDD4bdk74+tr/7oEU6WcMFANvhzclISOoH8n9rO2D2REqsMBWRdCttP28Ss
         reZNf9SCLPMpYTpU56bUomByN2Zs0xbFx8x8CKFSRIAGpVeCMFEYERx+4csP7k0gwMWW
         ttNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HpozNCNc1BElEXWai289GpG9IL2yJV6JSywhmxFoe1k=;
        b=AW1uiItmVjMJAba0O6GUEWYZvBHFsnOvmOrd3cQKIKD2Y77J2sOIJx1fS01GZp2z6d
         aU88CkJIe/R52iUl3Bs9MIlUQ+azhUElmrhPyU0B+tSSzyOOCZM9BkR5gTxls2HoluZK
         1+WhD85aSM4kLb+xh/MPRsTkdDpd60WlXxYDf1bS+msFEHBk7BuCNiG90HpjMKqKK9YQ
         php6AfIiucFevlEIHRorqcpWupePgnJoyumNbWDNNg3myGFP8F+I1BH6AVlgPnEe5azt
         kUVAaW707TMt/cUrI2BEguRJhBGE7e8rGjJ9LDMfxp+wWRBtwq03os114p1bQg+14mgH
         VXwg==
X-Gm-Message-State: AOAM531S8XwNQeWAk4XcmEuudCGUoPvbjhE6qU3vsyYpmEMJFsmF34/p
	b18hcyNW4hXs1H4ghWbPIHA=
X-Google-Smtp-Source: ABdhPJzNf8yEyP2i9QCt6ehmQJJ+vYUmhKSte1P+/WoSjyN3cMD1ZEqd6cZ52kQcHKV6U8hVuy/6nA==
X-Received: by 2002:a62:644a:0:b0:4f6:d760:caa4 with SMTP id y71-20020a62644a000000b004f6d760caa4mr22568545pfb.61.1647242277988;
        Mon, 14 Mar 2022 00:17:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1cd:b0:14f:eb8d:b29f with SMTP id
 e13-20020a17090301cd00b0014feb8db29fls5782499plh.9.gmail; Mon, 14 Mar 2022
 00:17:57 -0700 (PDT)
X-Received: by 2002:a17:902:c9cb:b0:153:78a6:9de4 with SMTP id q11-20020a170902c9cb00b0015378a69de4mr3137838pld.66.1647242277215;
        Mon, 14 Mar 2022 00:17:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1647242277; cv=none;
        d=google.com; s=arc-20160816;
        b=peqph+QRLynL8FlsG3TMKnInIDIZoD1yb6VYzEYwxXbTJbUmB5s+d+eRVjTm9l47JS
         SEuS1fXUHRfkDm0y4AFJRtDteX6O/GUcW8chvZ0zZkoRnWiHJLUxob79/5tO/TqIbcCl
         NOKYHas4QT6s5rrnbc3WK3rSG5GPW1+N/+Z7GjjuliBae+aou5xHXZ8u94hN1iPLqBtk
         UL6ZhKMFGYC+Z1eJNRu6emuQzd9no/7FaIaISVIS5nXxFcD6kX25kpi+0e9Wok1KbA5k
         3O6immcxQFE6iFDVGJ0K5YAXU0mwuIcF298JPEt5cdP+KTscodU4A97DlVipto4gKyQb
         mYoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jHOQpg8FkWZ2D9kBQlZqUsUw9/chXLkk2DroGgT0P6g=;
        b=W9yl9nhb/AGeWdAY2nQg5xQEYW2GxZFy4JwZXxwEMEMrAcuJl1NPEt0LwdeZExWCfp
         zbS0GrSH84YnU3mQYOoMzOCqO6hxp5D77u7y+iReCanqPAIvX4gn+Bm05p1JWDienEp9
         enDcd+3gprHZj+SZugom3bHU+DbayLsQq46xbLGiJsG+/k8fgF2hR6mxsYlkF3V2XHvn
         Zn7n5n4xIF+uIdCb3pChp+QnnaVbykZPvTIaFxWfDL5oD+Es2Csuq4Cz/TJfyTBOyatW
         c2nvCtW00L7AbjTLFqqmp29Bdt0yovwZkZ25yRrp2Rm2X1YR01MzBXT2SK84PIemDDJV
         evFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D8uyMk8E;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c34 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc34.google.com (mail-oo1-xc34.google.com. [2607:f8b0:4864:20::c34])
        by gmr-mx.google.com with ESMTPS id b12-20020a17090a990c00b001bc2f04b85esi1053362pjp.1.2022.03.14.00.17.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Mar 2022 00:17:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c34 as permitted sender) client-ip=2607:f8b0:4864:20::c34;
Received: by mail-oo1-xc34.google.com with SMTP id k13-20020a4a948d000000b003172f2f6bdfso19070386ooi.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Mar 2022 00:17:57 -0700 (PDT)
X-Received: by 2002:a05:6870:9619:b0:d9:a25e:ed55 with SMTP id
 d25-20020a056870961900b000d9a25eed55mr10310764oaq.163.1647242276344; Mon, 14
 Mar 2022 00:17:56 -0700 (PDT)
MIME-Version: 1.0
References: <57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl@google.com>
In-Reply-To: <57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Mar 2022 08:17:45 +0100
Message-ID: <CACT4Y+ZtahUje36PKfGYLVkb2SawMXOC9aPNwgfNgZ1ujCAVBA@mail.gmail.com>
Subject: Re: [PATCH] kasan, scs: collect stack traces from shadow stack
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=D8uyMk8E;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c34
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
>
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
>
> We could add a command line flag to switch between stack trace collection
> modes. I noticed that Shadow Call Stack might be missing certain frames
> in stacks originating from a fault that happens in the middle of a
> function. I am not sure if this case is important to handle though.
>
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
> +#else
> +#define PAC_TAG_RESET(x) (x)
> +#endif
> +
> +static unsigned int save_shadow_stack(unsigned long *entries,
> +                                     unsigned int nr_entries)
> +{
> +       unsigned long *scs_sp = task_scs_sp(current);
> +       unsigned long *scs_base = task_scs(current);

Just to double-check: interrupt frames are also appended to the the
current task buffer, right?

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZtahUje36PKfGYLVkb2SawMXOC9aPNwgfNgZ1ujCAVBA%40mail.gmail.com.
