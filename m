Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBXEUOJQMGQEDNEI3FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3765D511299
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 09:34:32 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id p18-20020aa78612000000b0050d1c170018sf681124pfn.15
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 00:34:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651044870; cv=pass;
        d=google.com; s=arc-20160816;
        b=MUQpW+UNNtBU0Ic+v8sQs0aMlmhuyLgAAB4CJXX47Fp3UI+keZ9oyW/bBTyKCd5PFW
         BBJ6yjlbWfTSYCI1WX7Sj4EibDpXdk5w1LDzyVAR70YsMC8pDjXUlfeAAxTaNcTE5dLv
         /G6KySCj2V7pQjjdcn1ZXb6Dp/LKKHgAcm68Fbkck0+4QIPnZj08FRYdwwa8bD47NBs6
         +BIY0IL1hIRI8puCRKDqLmeUqkQHXbd1c5zLNwFabVaYZ84tmTbOSEvAV8rXD49qoZhk
         NUzyKCzg05oq/Y8CSz55DwXdfYzj/Bfqn/sT8zNWHzMMEKIggxH3CdkPyuxEqwa2oRnS
         Flmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+r7aJf7mp7z9U6z53VaQYXzVOmK2ZCew7Mw0DwEnfM8=;
        b=P5mLRv6u7kFnVmjjUhM6FII/QFIkwpirFvQex1B82YDnDnBUiXIDqFBBx2MRGqk8Y7
         /AXK08UBZfTOy/u1jJ4na+s0OnaDz5QXbSB5mgk+h6+slJhw4q7PKkV41/7oci9AhA/G
         UrbYcf8fX1Mp2WaSmcLa2zoDORR/qruaeopwmttk7iC/8SPFz0bu4SLDCRYXmTMc7nVy
         Zk+6iOoxGxDRZABdRwRLjssOcoPyKtT3NT0KCT62J2/Vx4pxBTbY3q/sYTwoawzrjKF3
         Y7xI3ziCRHv7K0VMDlBzVlL0KYwlIkZDNvVmAQ42czSpG9BqQv8xq9kw9Nuy83NBk/Xh
         PRyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hrx36cVw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+r7aJf7mp7z9U6z53VaQYXzVOmK2ZCew7Mw0DwEnfM8=;
        b=QuVp4RMb3A/vRmopzAX6w0gjoK5i8e3olEXNwKEnDBzOMd8a2MyonA4fUDQCjWIz0O
         fpn7jpQYRYP99anVbazyEHNGn1A5ku4QCMIV8xiK1IAMfGqD6Hmmcid9YbrYgJlde0WZ
         TNKCD22LF8WztHOzfW44BbrMEdNOG3QF7kyCA/sij1nHThLHXj+otlV5021XbZpBepnT
         HuY/sHRYm5sOFLhy2DLmrTqjZ/QywfMqQjtiOSWUciEV9S/T5iuMlcnfvHu87r1XTPMa
         VEDKCDgIKrc0EcYyhCvYkLft1FY9M+ith/mzWLQXZyCEEpUSWy1POg+3GF31+yetSbbi
         /EpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+r7aJf7mp7z9U6z53VaQYXzVOmK2ZCew7Mw0DwEnfM8=;
        b=ulieNFm3uSX7+0IYsuQRX4jPzuwYyJ4uhVW9xtsBLdhHK4sEilT+7UcZIxh9ZAY0G0
         35Ju8S2nyRO73EsRazgZI+Y7GFoklcIRTYxatO/I/cwKAYN4zGn1GWzDIO6WQOJDZqPV
         5jl7JhbC0UbN0SFzK1FAeawRl89FgCYwYCBwYj4L1ZNZ21qYXI9EaTtmcOM7uHcx5ydl
         tVJckoqb025/VF/t0Vuqayge2AgVG7Ez1Lx0shBd6aQmybm6NtYsENFiC8peWaWdEKMq
         djPWP7pLLk/kaQZ6XKBtat7hcXaViRFnx3Mxt5Nwj8xjeABanIWT9DTwMNOJ64BZTemG
         Kk/g==
X-Gm-Message-State: AOAM5324FCtlAtsG09ZAGqOoigpyAa8ZoVz6xaIxaQ8ruOHZsg2wVdk0
	LIebLf+hqFmfX6IZf2WZOkA=
X-Google-Smtp-Source: ABdhPJwlMA6R1MRwHnrKUpQLRyxQwzVacq4zG32NVpY9mBRfmf2d4cR3AiDEfXrJa1TOilux+DyHxw==
X-Received: by 2002:a17:90b:4ac1:b0:1da:26fd:7ae5 with SMTP id mh1-20020a17090b4ac100b001da26fd7ae5mr3926947pjb.231.1651044870519;
        Wed, 27 Apr 2022 00:34:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4a47:b0:1d9:80ca:c6cd with SMTP id
 lb7-20020a17090b4a4700b001d980cac6cdls1312840pjb.0.canary-gmail; Wed, 27 Apr
 2022 00:34:29 -0700 (PDT)
X-Received: by 2002:a17:90a:b78f:b0:1d2:fcc5:c4c1 with SMTP id m15-20020a17090ab78f00b001d2fcc5c4c1mr31677319pjr.15.1651044869756;
        Wed, 27 Apr 2022 00:34:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651044869; cv=none;
        d=google.com; s=arc-20160816;
        b=QcB90A3W0OXCVwSQ9MYbh1641DBlScr6BGY7wsi2ZbwVMF30zrD6Z57QYD+Ni35eIP
         3ISKHDoExNOQ5MmFldyhjEJFsjHMFWcHK2yHq74DECCTXg7Gp99qgbO8/n0+Gu4unQ8/
         qYIfn2aIzEzZutnJAIKSLd+0nKiuN3eKWYu6iluRvoAQVndnAMvvvDfuPoU4LRLWoeEL
         AinVqeaaDoCuFpWNbgIFcvBD+HdPcbDooHiYGAasXDX8AAxv3gwTJYFgvbzfdsMt2k0W
         //df/2qH8fELI+2MEAmOe+KoIlUeSfmCWbt1OdWUwyDe5UodGhWcdzMbmi6UIlCPxl5m
         aFDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MeaX4XdIMOSF04IoR3Cab+z51sfQuXXpK7U3HQj8e9Y=;
        b=KArXIZfwouyiwlACIhpghQ8T5EkpLPNaP6Ly5Pn1rrFp+PHl51z+1mmSgv8vNutiNV
         saZ9kjjJjrUIb5kWR2MND2NwDPxfaJe/5iZRTEIjZ5zPuFLFwDbJtCyE9ArGQxnFxpa1
         0t6OJqNvMpFOQc8OisFYM8ZbrPcEojwoFE7Krjh5yUwHskReys/1v3TpIwUqjkbibNtq
         KLlkIbIgVLhxGjwwDwviKigJpxEEUGAQEq97QyQVrGxhxf7P0I/hYaPHy4GMslPmO6mA
         +re9WPQy9Uy0RM/tqsHYOWkN9L3bPTMnIIYwQ1i6AizywwqyUcCTx3QMaBhUf/lTaJzf
         RP4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hrx36cVw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id lw4-20020a17090b180400b001cb5c591f9asi259262pjb.1.2022.04.27.00.34.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Apr 2022 00:34:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id y2so1808142ybi.7
        for <kasan-dev@googlegroups.com>; Wed, 27 Apr 2022 00:34:29 -0700 (PDT)
X-Received: by 2002:a25:cc0b:0:b0:648:4590:6cb6 with SMTP id
 l11-20020a25cc0b000000b0064845906cb6mr15972505ybf.87.1651044868807; Wed, 27
 Apr 2022 00:34:28 -0700 (PDT)
MIME-Version: 1.0
References: <20220427071100.3844081-1-xu.xin16@zte.com.cn>
In-Reply-To: <20220427071100.3844081-1-xu.xin16@zte.com.cn>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Apr 2022 09:33:52 +0200
Message-ID: <CANpmjNM8hKG+HH+pBR4cDLcU-sUWFO6t4CF89bt5uess0Zm3dg@mail.gmail.com>
Subject: Re: [PATCH] mm/kfence: fix a potential NULL pointer dereference
To: cgel.zte@gmail.com
Cc: glider@google.com, akpm@linux-foundation.org, dvyukov@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	xu xin <xu.xin16@zte.com.cn>, Zeal Robot <zealci@zte.com.cn>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hrx36cVw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as
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

On Wed, 27 Apr 2022 at 09:11, <cgel.zte@gmail.com> wrote:
>
> From: xu xin <xu.xin16@zte.com.cn>
>
> In __kfence_free(), the returned 'meta' from addr_to_metadata()
> might be NULL just as the implementation of addr_to_metadata()
> shows.
>
> Let's add a check of the pointer 'meta' to avoid NULL pointer
> dereference. The patch brings three changes:
>
> 1. Add checks in both kfence_free() and __kfence_free();
> 2. kfence_free is not inline function any longer and new inline
>    function '__try_free_kfence_meta' is introduced.

This is very bad for performance (see below).

> 3. The check of is_kfence_address() is not required for
> __kfence_free() now because __kfence_free has done the check in
> addr_to_metadata();
>
> Reported-by: Zeal Robot <zealci@zte.com.cn>

Is this a static analysis robot? Please show a real stack trace with
an actual NULL-deref.

Nack - please see:
https://lore.kernel.org/all/CANpmjNO5-o1B9r2eYS_482RBVJSyPoHSnV2t+M8fJdFzBf6d2A@mail.gmail.com/

> Signed-off-by: xu xin <xu.xin16@zte.com.cn>
> ---
>  include/linux/kfence.h | 10 ++--------
>  mm/kfence/core.c       | 30 +++++++++++++++++++++++++++---
>  2 files changed, 29 insertions(+), 11 deletions(-)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 726857a4b680..fbf6391ab53c 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -160,7 +160,7 @@ void *kfence_object_start(const void *addr);
>   * __kfence_free() - release a KFENCE heap object to KFENCE pool
>   * @addr: object to be freed
>   *
> - * Requires: is_kfence_address(addr)
> + * Requires: is_kfence_address(addr), but now it's unnecessary

(As an aside, something can't be required and be unnecessary at the same time.)

There's a reason it was designed this way - is_kfence_address() is
much cheaper than a full call.

>   * Release a KFENCE object and mark it as freed.
>   */
> @@ -179,13 +179,7 @@ void __kfence_free(void *addr);
>   * allocator's free codepath. The allocator must check the return value to
>   * determine if it was a KFENCE object or not.
>   */
> -static __always_inline __must_check bool kfence_free(void *addr)
> -{
> -       if (!is_kfence_address(addr))
> -               return false;
> -       __kfence_free(addr);
> -       return true;
> -}
> +bool __must_check kfence_free(void *addr);

There's a reason is_kfence_address() is inline here, because this
function is actually called in relatively hot paths, and a simple
load+cmp is much cheaper than a call!

>  /**
>   * kfence_handle_page_fault() - perform page fault handling for KFENCE pages
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 6e69986c3f0d..1405585369b3 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -1048,10 +1048,10 @@ void *kfence_object_start(const void *addr)
>         return meta ? (void *)meta->addr : NULL;
>  }
>
> -void __kfence_free(void *addr)
> -{
> -       struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
>
> +/* Require: meta is not NULL*/
> +static __always_inline void __try_free_kfence_meta(struct kfence_metadata *meta)
> +{
>  #ifdef CONFIG_MEMCG
>         KFENCE_WARN_ON(meta->objcg);
>  #endif
> @@ -1067,6 +1067,30 @@ void __kfence_free(void *addr)
>                 kfence_guarded_free(addr, meta, false);
>  }
>
> +void __kfence_free(void *addr)
> +{
> +       struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
> +
> +       if (!meta) {
> +               kfence_report_error(addr, false, NULL, NULL, KFENCE_ERROR_INVALID);
> +               return;
> +       }
> +
> +       __try_free_kfence_meta(meta);
> +}
> +
> +bool __must_check kfence_free(void *addr)
> +{
> +       struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
> +
> +       if (!meta)
> +               return false;
> +
> +       __try_free_kfence_meta(meta);
> +
> +       return true;
> +}
> +
>  bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs *regs)
>  {
>         const int page_index = (addr - (unsigned long)__kfence_pool) / PAGE_SIZE;
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM8hKG%2BHH%2BpBR4cDLcU-sUWFO6t4CF89bt5uess0Zm3dg%40mail.gmail.com.
