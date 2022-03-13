Return-Path: <kasan-dev+bncBDW2JDUY5AORBUUDXKIQMGQEZWVFGMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 152034D78D0
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Mar 2022 00:44:20 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id q15-20020a056830018f00b005b25bbeed24sf10415527ota.18
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Mar 2022 16:44:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1647215058; cv=pass;
        d=google.com; s=arc-20160816;
        b=EHThdIncOh5OGJWtu/uq8qFFo2c2xQAPxqz+KSTSDJiOxXYnjdzhtWiUsDDKedOmuw
         kShNRprg79W1P839Tq06tuaFpHO2+vcgOMMcSBr12Qqq+extTwh7ykk4AXDoeOfbrJYo
         1KZOIpPF9KdheZV5u+Vu8R43+nbJUd4ixg7oPqMwyvhUVbvpYto3TJ8I6l50ZikoMR95
         HoNf9c+JkL8EBFZp+oidrmYIgJE75UFlSn3Q5tchrm/bEkgD41sj+rN8MwVyqyeWDIU8
         7+6Lcl9Aq+2OlNEfWzbxFgB9dkY23RS/G1EKJB/DcIjrGYQsN10KbM/1x8T0biLnE7aN
         MtmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=/wdXv36Q/Y+VQmBgu0an+5DMc3QAWRrInQV93INd4J8=;
        b=nSQasTyK8ff63/vy/dO3lTRIdc9vnk45PrABK/o/19CcwaFDjhq1jpr7liGNtXzOPl
         /D+PgI7c07arWsHsIrYorH5H9vEHJ2Fn2Nr3+02zfVwDPiIzu1qA8ZSvTE0nIzl/exQ2
         JO0ISWv/tvEYPLLlSZGshAklNL3U1hqAvLKvgVlW2kNFpxJhGVe10FK9zVaCSLAnkzeZ
         WAUyqWW8P9dGhn48iqxoLfIPEYcjeixj6QIEllK1dDTT28tC+5/axxlufE94aPWEmGS5
         cQPP96thwe8BKH95EpXqXz1T8QE1iOAXXiNYaWqyjaurrr8Pqfvm1CoGgpRAioRjLLUE
         HxKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QwLaq6hT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/wdXv36Q/Y+VQmBgu0an+5DMc3QAWRrInQV93INd4J8=;
        b=FZ3KB4vJT0f7+x7XDMCNlve2XvN7PVYUBk8zWIjbjLhx2bdOMGHCMomXkxujoYvx7S
         96Y4+jWICQ3+SVND9xW9EuLfShmZ1erOa0d2RwrWivh3DUSMov8fxWeiC71a1sp5aet+
         j+eT3qjBk4neWffnp87kuHV7EDy7cKJrNeijp/da3pCC/UamN5+RZzfGx2nX69sM/sEI
         39EFTjm+FWmECO0BnsU3eFY91EJzTE8q8t8Md5rIaUYt1DM130Rgcc81NYpc2wwBpObt
         4I5iBrp0gIlDOGPwTBux3+8v6fsdFl3i6Bua5WAjNU39LahhavWh1RMKDd9imYH3Dtrb
         XL/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/wdXv36Q/Y+VQmBgu0an+5DMc3QAWRrInQV93INd4J8=;
        b=O/1BL8ckN2imAnc6/JPD9YpdzZvZ+CSgvrnp3Dv5xO0SLQewmRh1Jy2PrtmSOk6jcP
         ekbcWw06s8ugJO16LNNtNrzn8Li7cM0ggtCGXNNn25wZ3XTn8J252CR4XmJFQM4/QsjR
         vr7eteEZdGacH9m/t8Ybe+Tpf8atmCOU5Y1ELOvyOkiBr52ECcRd3Df757pQte6SO9Pa
         YsPpLBiwNXHmGHt4IVoYDjRYU2cMEfwjZTs3cm3Pu96w67z4GGeetIYaRgjPrNQ2kPru
         vzMwXC6XWDFaP7oOMGD1SymbZ0ritAK/ZBK8LQWTBf7oGw2GUG6ifuGIYrVcpnp26mwB
         6vSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/wdXv36Q/Y+VQmBgu0an+5DMc3QAWRrInQV93INd4J8=;
        b=WEKGOvnsv2Tlf8cC3clk3q2y3AbtxAs/82YtwL+O2CoyxwbcAaAAc9nqg94spxB7Vg
         PiVL8VnyimjAy6D0HO7OpH1HLL+uNm8mrIQ7ZfciOqqn2AEjivHQJfkx0Cw/Ic5zJcXH
         9i5KWgY/ZbXMsylQQfW+yWTELJjvdER9ubXY0ldZl7JUNl6mEjMVARNyw0W/i5XXeEf6
         FzJvhmDW1QXWiJR3ZQ9Cts2SEBbcqVqTo+K+6+HpgX2/g+TMmPiToHXCF3M1Neg+NCRc
         JzoBnsiLyfHg7jemHwDnSqZHfybr7XKjCwDHOUpKVeohyL9zUenHSZdmZy3cnE8YsUK3
         Wajg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532WgQfaDxMUsRJIwjFRRA8OBQYgz7M+S/sTGeN3wlZrGUlZUWot
	a06y2Q3mytBR1EafK+jiq50=
X-Google-Smtp-Source: ABdhPJxf2B6wuHUc/6fqye6Ze42xLPz9BB5S9sVujP4OZDHRHOqh0k2FQiYy2iVy6F5jQldXAgsZUw==
X-Received: by 2002:a05:6808:d4:b0:2da:503b:40a with SMTP id t20-20020a05680800d400b002da503b040amr13251242oic.121.1647215058677;
        Sun, 13 Mar 2022 16:44:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b387:b0:da:ea30:ee8d with SMTP id
 w7-20020a056870b38700b000daea30ee8dls1937095oap.0.gmail; Sun, 13 Mar 2022
 16:44:18 -0700 (PDT)
X-Received: by 2002:a05:6870:f604:b0:d1:bd6e:47e3 with SMTP id ek4-20020a056870f60400b000d1bd6e47e3mr10446529oab.30.1647215058376;
        Sun, 13 Mar 2022 16:44:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1647215058; cv=none;
        d=google.com; s=arc-20160816;
        b=esRzwlmOEJBqY+/lwGTaFBmP5DoZYiiPHnBVjz6NRvVLbsNDcPder3LPFV7SrdvAkZ
         7j/jUQ69XFiTk9gZmDo3lGcg2uMiahbdCwRp05sL2UMLYggywVSuVpydrHuAVvJqQGKU
         Q0EaRD2GyJVmwboua9luC5xC1hPKX8jCWcP/muECDZVPWBLeD0RwGMm51f1oA4YCSNmK
         S5BE4E2IMZ1ryBmFR6c/TGQEdiyY4JQkIIUUGVuFIW9j/KudEpj9oUDZDol2R7N20rtu
         mGIwwl5HCJKBFRzGuOy94VXc6VpUlDm+IZCUYzy4WOdYAtM38rPFOLidnrkaFNXpvFwx
         aO9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8Y6GoVLUy81HdtypjoVfjZaaJkl3pvlY7l5U9nDab9U=;
        b=tI+KoBkCWSdBO/ci4JE51XmDNq/yb8yY+jMYJsHqe1grH8nl9o3uylaHcFn6WxJcLc
         JFqOob3i7V9xkaJWiWMYPOjdcJDoDqfgEHWrQ+gvFKkNxdAYl5Afvkg3d8nlQucoSF2f
         yvvjxcD1b+wQsz/zINDLOdJUv1+mPwLFDsLng6CWbD+kfUnrg3pAeXioDqISB7ovtQhm
         uuPKOtI2xcakiv5z386cxgpzayzcwjzlu9RzdP7DzArMowIpHsR1sSvuvYjt1pA6Jq4A
         yxNBQLt/WR32yhHprsIqF+pk4Mu85nECdiLIApd4mWaXOIEfQ1nxVbpMd18zHHPDE9jk
         yz6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QwLaq6hT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd34.google.com (mail-io1-xd34.google.com. [2607:f8b0:4864:20::d34])
        by gmr-mx.google.com with ESMTPS id i3-20020a9d6103000000b005ad267a9a05si1170321otj.3.2022.03.13.16.44.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Mar 2022 16:44:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) client-ip=2607:f8b0:4864:20::d34;
Received: by mail-io1-xd34.google.com with SMTP id x4so16315450iop.7
        for <kasan-dev@googlegroups.com>; Sun, 13 Mar 2022 16:44:18 -0700 (PDT)
X-Received: by 2002:a05:6602:2b8e:b0:5e9:74e7:6b01 with SMTP id
 r14-20020a0566022b8e00b005e974e76b01mr17690829iov.127.1647215058035; Sun, 13
 Mar 2022 16:44:18 -0700 (PDT)
MIME-Version: 1.0
References: <57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl@google.com>
In-Reply-To: <57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 14 Mar 2022 00:44:07 +0100
Message-ID: <CA+fCnZe-zj8Xqi5ACz0FjRX92b5KnnP=qKCjEck0=mAjV0nohA@mail.gmail.com>
Subject: Re: [PATCH] kasan, scs: collect stack traces from shadow stack
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Linux Memory Management List <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Florian Mayer <fmayer@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=QwLaq6hT;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sat, Mar 12, 2022 at 9:14 PM <andrey.konovalov@linux.dev> wrote:
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

Another option here is to instruct stack depot to get the stack from
the Shadow Call Stack. This would avoid copying the frames twice.

>  }
>
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe-zj8Xqi5ACz0FjRX92b5KnnP%3DqKCjEck0%3DmAjV0nohA%40mail.gmail.com.
