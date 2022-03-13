Return-Path: <kasan-dev+bncBDW2JDUY5AORBAOGXCIQMGQE65W2TZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 596B94D7701
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Mar 2022 17:59:46 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id q15-20020a056830018f00b005b25bbeed24sf10135243ota.18
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Mar 2022 09:59:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1647190785; cv=pass;
        d=google.com; s=arc-20160816;
        b=yNhPj6Goc9cPfNBQBkqVHG8QkZHRltCPauwcygXPkr2Xhj0yz727rvVUGlu1iLAVRl
         2oycOapbQGeRtne1Ol4R+jOG6opcZPqNFD8c5uAJMa2AApm4mS+9/zv3Tq3+t9AQUPKH
         /OOxmAYxrm1dDZustqiUIiABde9SSIqUAvWrjSe4x/r3QAlJIkZqYJ15B722LnlloSpD
         ABs49CL271oh8hfXDFJxB8uzqDixEMzn2tUnLhbojmjSE4mhLlrUdrNprYfmsYWk+UY9
         890f5kembtGERBTG+oUtqsvZYlzH16o7aXkEjUdmusEX2x5/uRZ6p+S2t67xDevfKEMa
         a9Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=KNpSznRP6XHleqF/S63niaPEkvO3Rw3GRLLHwlKHFGQ=;
        b=hczhOlNxJnsB27imp3lpcgz/Zt4DjjUADgFGo7tcWti1vzwYILAjntYKT3ptr/oUfq
         P7/KeaWRzAgl2mNT5fFqQ2RnAlHR1rnZrweNm2PSyAqQ11wk/Fg7wgp2ni5Ngpn3ilJV
         w4hu8O0g23dMFMDn+eG0BSJ+x0kG3A2eCVg0lE4EB3phDb3Q8OV5lJriEu6Ym7GC4JgG
         q8g3JrQnUcPSnVsFyqEOtMvfOl2aBqW7ntKs0DxJv0tz8oVpNlfuPujCk36x/ot3Gze7
         tRM0RS8fYguqzmiK7xP74mf/6rUp90lXWZeBguMSiTQVzVQlcOnVWvLf8jxhWSMaoB1m
         CQbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Hq45Dc3i;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KNpSznRP6XHleqF/S63niaPEkvO3Rw3GRLLHwlKHFGQ=;
        b=s9DIdkvDoafPt3EQm6nU2rEdKSIaEo3QnacKpdx5rKpyCbwqfiFLSbAup5v+PDW3gf
         Gdj7dr7Bolilibf/cPTLt649QBXWyFxsOpdYyYoHoh5/X7imTHG1N1ge2KNxVyr5E14Q
         oiWxgyOL0nW7gtBqooPl4gpdzh8GC7tQdGFNiDBseksTWdbNpSD9I5OlmVumS12Onb+8
         cTmUquV5KCJpMIjSZ08BoIIiRalQIhqtTaTwD6OxcnagMJyCii5D/WtfWVaU+90IquPD
         yEjLAk2fHnqh6rGWxcXvTedne0koML32el27/EpF4J7NQBKmTD7Y03JCiuGMQK9Lzr7k
         LRew==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KNpSznRP6XHleqF/S63niaPEkvO3Rw3GRLLHwlKHFGQ=;
        b=o9AmxeheptwGz3sI+myPwmkK+VgpdBMrSnlSZ0SZcp3lsmvnMrsC7cLlnnsJb6oTOs
         9h09g5VOfol+Jj5SXhDxxbN3AtG0NGYTlzaj845VyUK3yX2vhih2DVgTKvyq+H+QRkNr
         lD6lxxLvjQ5N2vohSoeh9EimAwhk6EHRu1MkSgqmcww3TQZ+6wXTjxZTlyV/wIj6MPvA
         GSkGeGerzg9kPM6f1Gn3bZPpY0nf28+ycCQh6lFU17jrCZIS7omVRdqwHml06rSmbi2S
         uEZ41MU9Hoay4aX2xJeGRhEX80XICskmC8hG9/uIV6x3V4W3u55PPCsOQQjOVtuVdbr2
         9gEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KNpSznRP6XHleqF/S63niaPEkvO3Rw3GRLLHwlKHFGQ=;
        b=NEmGItWnT7OkoNrwpNSoju+Wi+hTGWg975H9c8beD8Bab/+yMle9OLosueL25b1sTq
         StouQggopPoykMX/Cm6XWRrwzlYUQEOaeqcvE3QznKm1UsjV6QtWsoyUW9hNBrlBqLIx
         jH5i9xdsNK7TQtRx6C5bLUDfYW8B2Scgoi22hYRCmZ0QCDTCD0O09PIlRiZF6dmkkH/w
         emcjeFEDqJ7UepHXnKxAbIm4QBdJb3HotkrhckKz1Co6UZnakB3kX/82gQUnlNmcVDCo
         HsEHu7xsKKimD+IwDNZwHWjYeOU7ohPzIpo/WnKy9zp0Wn1OALePIvr2+c6eTD/7ZnZW
         Gp9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530NLG72XlGaBIPCSPOUlPJAzGDb02koDzEoV8zuUdWSZ+3GnKs0
	GLI8ytKcBEEsiIROmD825NE=
X-Google-Smtp-Source: ABdhPJy0lx2ME9djIui+wEO+bEE5ywbcNvMNHwuQKZif3Q4/kO/PM13OOMV3qKTDg9ZJ/ZwUiyug+A==
X-Received: by 2002:a05:6830:2b10:b0:5c9:3635:1334 with SMTP id l16-20020a0568302b1000b005c936351334mr6327718otv.67.1647190785106;
        Sun, 13 Mar 2022 09:59:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7113:0:b0:5b2:258f:4079 with SMTP id n19-20020a9d7113000000b005b2258f4079ls1578590otj.11.gmail;
 Sun, 13 Mar 2022 09:59:44 -0700 (PDT)
X-Received: by 2002:a9d:4d12:0:b0:5c9:4997:452c with SMTP id n18-20020a9d4d12000000b005c94997452cmr3642145otf.127.1647190784772;
        Sun, 13 Mar 2022 09:59:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1647190784; cv=none;
        d=google.com; s=arc-20160816;
        b=HbMVxtHxRzy4LF0R1SQluljKP2NpakdAbZVWzH94Bm8pAic5AWwLvr5hbGS5qmNaSc
         6+DERDFgH+87p5CIJ0hyU0AoTOU7iCxOjyB73W+LvgcF1ZvfIx8+2okIJpW90kgYlFed
         j/rYPpWAmjz80X3Mg7Km1tf5v/xIk446BgplyLoEuZoQg7nMNEZByCp1aimqTlCmMoXb
         QLazAdAD3VPp7zRZL9D46lbV4uiOCCHi0Mvx59Ez9riJjRYo5Y4AAUCn7dZ9nH97oKjG
         H6G3Wy+hkArvUZ9DbIV14Jpyij4oItd7GB/iiI5M0W3RGjARjWVAnmhlC9gCO5zhNp1G
         RnOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jKA+BAzUTFl+hnrRa9zqREom7b/VJAytojV31ApXxMs=;
        b=xlKf3wWVStVmNy6Xe8kG6jiFpasjd1yWJkoQx19KviEDpXQi3KAdSrAaacvvRQtO9f
         w/HdSOeB0N/gjZL8xgiyvR3RPpoqAwAoyIlHlHrG8CUEiTG22L/aXybvxjBVeYTXuRQv
         enjSG7CjwSudLqO50HjNxT9+pDLhabGpNiQ+OcdZZ9txlkcj02gbl2AVuG2zzPq6NOC8
         gxIxkZAepuE78yYu7aJ0gXmcKcat82kqVOKWvEgTlXl8t+iEAcxzA5WKFD7jczA4gqkD
         3XIWjHzG21cwI3vu3GCOH0dNNRcqWURNZZfUGQTu2pi/xiEJF+49Ym+001vKC7ggSflK
         Y6dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Hq45Dc3i;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id x30-20020a056830245e00b005c935a2447asi741036otr.4.2022.03.13.09.59.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Mar 2022 09:59:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id 195so15742531iou.0
        for <kasan-dev@googlegroups.com>; Sun, 13 Mar 2022 09:59:44 -0700 (PDT)
X-Received: by 2002:a05:6638:d85:b0:317:d2f5:8f1d with SMTP id
 l5-20020a0566380d8500b00317d2f58f1dmr18097708jaj.117.1647190784476; Sun, 13
 Mar 2022 09:59:44 -0700 (PDT)
MIME-Version: 1.0
References: <57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl@google.com>
In-Reply-To: <57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 13 Mar 2022 17:59:33 +0100
Message-ID: <CA+fCnZfstj6V8JQJEvt2RfZ3Snc2Gnvo0uOYHqPh4LA=BHDdzw@mail.gmail.com>
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
 header.i=@gmail.com header.s=20210112 header.b=Hq45Dc3i;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2c
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
>  }
>
> --
> 2.25.1
>

CC Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfstj6V8JQJEvt2RfZ3Snc2Gnvo0uOYHqPh4LA%3DBHDdzw%40mail.gmail.com.
