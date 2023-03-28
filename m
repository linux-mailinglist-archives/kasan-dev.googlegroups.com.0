Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYFLROQQMGQEH3JATHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 77C1C6CBE35
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 13:56:17 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id s1-20020a6bd301000000b0073e7646594asf7401355iob.8
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 04:56:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680004576; cv=pass;
        d=google.com; s=arc-20160816;
        b=lK7i8bekumgFkos2/5cft7/2slvUWcwoCAW9eOpgRvN2yLkQ2Fz+hOYsZskQF581Ko
         EzkfDzOcs5STq2qBVycWuP86taGCXLPXGEvmmQwwQHt7MieXdBpTgZRbyyMRzf4ap2aO
         MTz5nvKfIJsOtovSpKF3CC05lyvZ3KPcx+JdyoH0SN5lasBonIIk/S9SbXsopAB10sbd
         /7V0emRIZtdJMJpgkUHt+KZBr/PsUANgfZWYgy8phRhTJF8OXa/AGguODg7voBvagECv
         jnBApbelBv/RcE/ZLeSImIB6LXTLA+yOQy7+d7paekTMXtLjlnSxtSAdVhkYB8VXw3+B
         SQgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3UBDXjHp+uPzm0MnInj+PC44QZQz2PmYTlXnuOaJTlQ=;
        b=WUSBQ8ngycST25VflhtX/+NWoPJJ4BVYGnfyOnuSBFM7yLAgDi2YPcqoPydQ/lw1ic
         uE7m03xYr7W6psy8GHOpWbPVUjnH1QWUksczwidGaU5TvXajD3C2erjEqMKsQx6+U16k
         6E01Pn6CyO8Us8wp5ofuICxfJHfJHDRPl952v6RcHzF+FMj9BF/ISTNYQq2L24YYKY3e
         8WEqiBovrVQqkWlAm8w4BvcMQN3mv5vQdNgkwA3sJl43vTUaFXgzVe9wF6Xy7qfOC9n6
         2x1HrQdj8HN3GQtj5jBlluGOtPXBbAKF2sCxXIryDGqAiVZrV013JCgTMQOK7mnQGPgw
         8BtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hoLgsOkZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680004576;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3UBDXjHp+uPzm0MnInj+PC44QZQz2PmYTlXnuOaJTlQ=;
        b=WY4npOfctpAjmRzpvWUzwzwxpidy1viPcgnX+SMw8mk9UkF1oivCPSzEO89BDT4tnt
         jmuABqF+7psXzbU4zecwS5mW5j/psraQFijtloFugIruc/AzT0TiLA87dcaUWHbBghs9
         cJ6/rBiNEgD6DfNGvhD/H95eievVA+V6LjheJkdOPPcznHJaAC1Vw7MSydnMTC0KdJHQ
         C1tt98Z3vQXM8RVaooepYTnSyGiifNPZpohnqrUbgQLZj++SHe1pyRNJZhgo99lLm12I
         4CTdlaF2reFrFNYItAjJ0ovoE3pnezou7QAw+hrMkCFzTc0PSrPKvsePKRfH3RGv3/nO
         5PcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680004576;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=3UBDXjHp+uPzm0MnInj+PC44QZQz2PmYTlXnuOaJTlQ=;
        b=nZNyLnQ2y2T/MeNxtRqp4KNR2t5A1XrND54A8372a3pwp9ouwzYXSCPOZNF/lKPUT3
         oEiSr8LMln+4ru3mxY5I1/2FFuH8dhjzGzN4BA/Eib78ZFQFeRWGzpUJBn7+AdOV4s4g
         rdpLW6QJyCzA3v4jT4STCurqAs28ouL78rEWJKJ7HfCAZWaP7hUup8iEvDWDmhnhSJJW
         zixP+nMdeiikRhkDVIkfSpMlISNiACOqdXhD78LTVrSFFgvqn5qTHiwfDEv0PXNp9MD2
         38Pt2tFOK1pDU4yVNcrTi76laIjc5tsRsnA8SvG+lnvCjO1RLEukgUDBjZ2zqHCal/z8
         hKYQ==
X-Gm-Message-State: AAQBX9d/CRXvUrZxudTyC4N8+6N6AgDv2TR6wW6v6JNsdA5IvVHMMpyx
	d1rZvVLL2MpzQJu9+/iovYw=
X-Google-Smtp-Source: AKy350a6WHprjdYn54jXr+npkBqc2IGoReb2I3IBiL/fd436itF1aaCS0DC83tTlq4JOEiSrYlIu3w==
X-Received: by 2002:a05:6e02:1a8f:b0:310:a298:1c95 with SMTP id k15-20020a056e021a8f00b00310a2981c95mr8069742ilv.6.1680004576169;
        Tue, 28 Mar 2023 04:56:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c07:b0:322:ecc7:b8 with SMTP id
 l7-20020a056e021c0700b00322ecc700b8ls3356240ilh.11.-pod-prod-gmail; Tue, 28
 Mar 2023 04:56:15 -0700 (PDT)
X-Received: by 2002:a92:d58c:0:b0:323:833:91e7 with SMTP id a12-20020a92d58c000000b00323083391e7mr11195476iln.23.1680004575578;
        Tue, 28 Mar 2023 04:56:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680004575; cv=none;
        d=google.com; s=arc-20160816;
        b=UhXMFZd9BY/SCBDHJbFmkhjVflmoo2lAgB/FCi/bDuO7rK7bF5d43VeLvznCqhyHEE
         bRZQRVHfV2WIS5xZarLD4G4F2b/TaAfc2x21OkehoLfUG+NJWPKyWj2QGJqu28vHTtQK
         WtQlDxGY/PFplOik6CzduiWt/JnJ3qVnj1FqpODlhLAcy8YWX+Xn/7kbem11AhnvMfhf
         5z+tOKsdb6XizaXI0oBToXfYE1+e0jjO4I8bY/R5FkkDPC+iThVfXrenQ6/c3D6mYr7d
         mjmPJb9waJxfgD8AMRQ5t+O5IPbzILXM77bwPChXNnI3WMVtc332kSxCeUrLCIq+nmFv
         KdNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nc5W1lE9EjIhY3BF/8rAhRpdJPCQCh8hr/U0i6aHjsc=;
        b=EuRFd8l3XWbj/Y2yA10TH6tKamA94lxRqJQiIOu8hyIys1y5xU/twJuXKA/KFnnxed
         5K685vW8jBnnb4ATmc7rJfZKa5Vxk+Xs4R5GX0LmxQilBoAQlGgsfqHpn3S8FAqe+NsN
         uLlivCUZmAgO1HIEPHeRlOyJm4B/6TV/hdi7bhajfw3hiDK99Tfyn0jKaxwPufmyvjtc
         1Kmn4v7lDzQCO2VoAM1NmZLPp43Q2U57bx/4T3zJTNj213MqT7jFkVMFncSRotSUdQdC
         6Ig7jkFD3Xzu8u2yvwsAIRztHftBfJyF0oO4RuIF65uLWIwfH9xprmZMh7Qzee5HupxG
         I56Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hoLgsOkZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2b.google.com (mail-yb1-xb2b.google.com. [2607:f8b0:4864:20::b2b])
        by gmr-mx.google.com with ESMTPS id r10-20020a92440a000000b00324493a66eesi1116048ila.4.2023.03.28.04.56.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 04:56:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) client-ip=2607:f8b0:4864:20::b2b;
Received: by mail-yb1-xb2b.google.com with SMTP id i6so14651525ybu.8
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 04:56:15 -0700 (PDT)
X-Received: by 2002:a25:ab81:0:b0:b65:89bd:3c85 with SMTP id
 v1-20020a25ab81000000b00b6589bd3c85mr15082098ybi.4.1680004575191; Tue, 28 Mar
 2023 04:56:15 -0700 (PDT)
MIME-Version: 1.0
References: <20230328095807.7014-1-songmuchun@bytedance.com> <20230328095807.7014-7-songmuchun@bytedance.com>
In-Reply-To: <20230328095807.7014-7-songmuchun@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Mar 2023 13:55:38 +0200
Message-ID: <CANpmjNPeQBcV7qnpXJOoLYjonsjPnOW-cerYm=_U3ptNZrXu0Q@mail.gmail.com>
Subject: Re: [PATCH 6/6] mm: kfence: replace ALIGN_DOWN(x, PAGE_SIZE) with PAGE_ALIGN_DOWN(x)
To: Muchun Song <songmuchun@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	jannh@google.com, sjpark@amazon.de, muchun.song@linux.dev, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hoLgsOkZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as
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

On Tue, 28 Mar 2023 at 11:59, 'Muchun Song' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Replace ALIGN_DOWN(x, PAGE_SIZE) with PAGE_ALIGN_DOWN(x) to simplify
> the code a bit.
>
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/core.c | 12 ++++++------
>  1 file changed, 6 insertions(+), 6 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index f205b860f460..dbfb79a4d624 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -230,17 +230,17 @@ static bool alloc_covered_contains(u32 alloc_stack_hash)
>
>  static inline void kfence_protect(unsigned long addr)
>  {
> -       kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), true);
> +       kfence_protect_page(PAGE_ALIGN_DOWN(addr), true);
>  }
>
>  static inline void kfence_unprotect(unsigned long addr)
>  {
> -       kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), false);
> +       kfence_protect_page(PAGE_ALIGN_DOWN(addr), false);
>  }
>
>  static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
>  {
> -       return ALIGN_DOWN(meta->addr, PAGE_SIZE);
> +       return PAGE_ALIGN_DOWN(meta->addr);
>  }
>
>  /*
> @@ -308,7 +308,7 @@ static inline bool check_canary_byte(u8 *addr)
>  /* __always_inline this to ensure we won't do an indirect call to fn. */
>  static __always_inline void for_each_canary(const struct kfence_metadata *meta, bool (*fn)(u8 *))
>  {
> -       const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
> +       const unsigned long pageaddr = PAGE_ALIGN_DOWN(meta->addr);
>         unsigned long addr;
>
>         /*
> @@ -455,7 +455,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
>         }
>
>         /* Detect racy use-after-free, or incorrect reallocation of this page by KFENCE. */
> -       kcsan_begin_scoped_access((void *)ALIGN_DOWN((unsigned long)addr, PAGE_SIZE), PAGE_SIZE,
> +       kcsan_begin_scoped_access((void *)PAGE_ALIGN_DOWN((unsigned long)addr), PAGE_SIZE,
>                                   KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT,
>                                   &assert_page_exclusive);
>
> @@ -464,7 +464,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
>
>         /* Restore page protection if there was an OOB access. */
>         if (meta->unprotected_page) {
> -               memzero_explicit((void *)ALIGN_DOWN(meta->unprotected_page, PAGE_SIZE), PAGE_SIZE);
> +               memzero_explicit((void *)PAGE_ALIGN_DOWN(meta->unprotected_page), PAGE_SIZE);
>                 kfence_protect(meta->unprotected_page);
>                 meta->unprotected_page = 0;
>         }
> --
> 2.11.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230328095807.7014-7-songmuchun%40bytedance.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPeQBcV7qnpXJOoLYjonsjPnOW-cerYm%3D_U3ptNZrXu0Q%40mail.gmail.com.
