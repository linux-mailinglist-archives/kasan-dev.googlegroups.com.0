Return-Path: <kasan-dev+bncBCMIZB7QWENRBJNLRT4AKGQEGYHQHOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D5BA215714
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Jul 2020 14:14:31 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id u128sf26568983pfu.12
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Jul 2020 05:14:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594037669; cv=pass;
        d=google.com; s=arc-20160816;
        b=hLixWCZC1A2qJoFmcSznXKK/juxrFy1t7G6KL0g5xm0kPMRQ57TjF1pVgSwejaNJ5y
         KyDtpJ4ZgniGDXAhmBwB5SsDl65P10PSagriXbA5X0U45wi7N+mTUCFuuCEwqR6qOen6
         TVonqXjIx9hiS81urMj4wM9MlmRd4PDq4ilREJKQczz2yp0ewAg+kSExuAoQO8HTDFb5
         b/SeowmoAWrZ3mbNCs5BoMsa5dGZCuf/O7BGLlu0Mo0c48DIPbDmod33KXpHLXggXNfC
         ApBGFAF1UxXnCJWvM5ubvoGwIyO2poLcrI2TxxHyLSmELeuk1XCrF95u8VMEM+NBpLmK
         3i/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fW5KY/SiIwI9PVn4wOiT2IZHJGbRIJ0GFczSEP756lA=;
        b=cYgcxWjd6dkFheH6HgGSVtstlw5E7UtLqEHVqwiOSI9N+CTm+zGJ64i952zjqgQs+H
         ojIornfAp4XK67Ydgu/cKrDXcfe1TQ07cVyu5Vai9HTgoOvAvlSX7KcXaooHDsQz8g1Z
         nV1/kbPAFLMVp1+rezeiJMn8Ya8r6eruXd38L9rz4NuThgU3rEeU1icFSrHkIFc0ek0P
         Y9CG41N+v0JQ8d7ZfNb42Du/l9G7YOSgxCWVu/VxhteO7boQHG9JdqRfGj3Dh/6ozukS
         l8INV8bAkZZf64nnK0ZYbOYae+dtdLi3DU5HQp6aWGoCDr4ey83smqlPddvgwb1EvYZk
         /L6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nko1XfT+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fW5KY/SiIwI9PVn4wOiT2IZHJGbRIJ0GFczSEP756lA=;
        b=Bdy5dzkXHJb4q6nxWbvTf+CfUUP3Gn+ry4bvhFnhgtBarsxNAkFBcjTB5qG0tGzcKn
         Rh6iGrD59mvQTYL2Iumm7VxAZuYYMz3HwHytTD1Bb7HQk9BO4B62vDfLoapVRchb3Ib+
         2eVQSYfmZ2o9Ski7iVX7+IYo0UR6AFQl3F3MpZ5/aj5Lba6o43u1BXPfRFf9uXC+hxha
         N43PYjXdP7stNT3yXq57XO8wDBmxXdq3gju7lvRfdk1fLYpXVSsw0mY36tjdQ4OLbOMR
         RX94jVHGT1zC6JkkAFDvhYqdWDcRmnvFW/URQPxLPx7OLTMCkP6X1+vBxLk9+ARbJ6U9
         EqdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fW5KY/SiIwI9PVn4wOiT2IZHJGbRIJ0GFczSEP756lA=;
        b=EU/aesLzlBV/W7NVe00yMcgWBLe2zDIW2MfWNjZrepVcNtQC/TXo9WMjzmemcqvf/Q
         UtnjN/+//+pH15oEn4cm97n3rxFqg5kE3woLiHBboVF5XzHrmskpdU25YoWnESBnODJ0
         gt1SoGAFpoMJU0r537U7SPc6DER9dFjBUSosviHPbKCN38GjI6xIr6CpdQnJnECRJcNC
         TfRJqCybJSFpO3I/pMRGiZBKkypLbCyoTsbjgC+wTlg7lN+hGPKF3tuSzSeKZzyGLnNY
         aXghmnMtvIy5Mmeml0Py9VqLo+Mzn1NpAGzlAksOSpO7OyrBNm6pYgLl8nWpmt634GdH
         E0eA==
X-Gm-Message-State: AOAM533U7IApYwHbLMVqGr2Ie2yvJeS5XV05gjdttL+hFHJFZMWdn9HT
	CfoInCoyYbA5QnkLiledTtA=
X-Google-Smtp-Source: ABdhPJxnmH14mbo5F+kBkS3A4bN6g3rog6WynqC1W+oGByUl0zsCk+k7apn6J1z6OwBGHWVPb6DYPQ==
X-Received: by 2002:a17:90a:65c7:: with SMTP id i7mr34275847pjs.103.1594037669641;
        Mon, 06 Jul 2020 05:14:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7b91:: with SMTP id w17ls5971384pll.10.gmail; Mon,
 06 Jul 2020 05:14:29 -0700 (PDT)
X-Received: by 2002:a17:90a:334c:: with SMTP id m70mr22951771pjb.88.1594037669187;
        Mon, 06 Jul 2020 05:14:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594037669; cv=none;
        d=google.com; s=arc-20160816;
        b=sCWtBy0uaHCF4jNyrJd8QVm/c2hW7oCz7HsEL9Q3KjdV140PCD7pLbNxZdSSyapvJK
         PBVtakWYpjvuCaWxdkinK5VnNywrQ6qQ80DilpVJantc6BsJObh6zmjikzkby/9GiSNm
         kMJA1Q1byOMC/9NObP79iQcnomBW38FlX1TFAiQnwP32NyK4MB7WH3bcFthJpIKzRlt1
         MdfDwc6AIWFhKprYegT9yDY5iBXASrs+jJChLxxaiTXxKy7kDFTwp90HoSOZXXpjMAQi
         /9kgHQ09+HJJa6t1WMhxRTg+rVeMhikiQDq1pJIbxMUlcrt/vsmwwVqXGAesscEMqNNe
         vDmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JMy1NuuvAJma8T47+ZbalKDZNjVJ2jnk0BZDVxqbCwQ=;
        b=wyVuN0c8RGqnCFiuS5gqJ4x1XnQT5OGfJ3EueM0jBK3lYb1C8kjgCTwqHsjNXcwRs7
         gYcyr5VxpuJCPdxDJnQUSt418nf4OQcCx7rKVOu6IS84WTzUEhnx7Zo3EVoYJzG96/lp
         T649Xv/OdQO7yDM19gmP9/XqLFhWcmntmYgRHVFEQUhor4t75fz+56OHdLSxWtIxhMg4
         XPK1PZ6rlcvaupsfjwfU8FFhZBUizWT0FDc1D0+pPMyIw6iOGZBLaoiqKAUA6st4xQ4O
         Aiip1iyj7ZGrFhMxv6xqeGtRA2v4unbJDZJE8OAkA8nHEdkMH4V02VFAhIJTxeGL5mQ9
         8R0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nko1XfT+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id 10si310411pfp.0.2020.07.06.05.14.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Jul 2020 05:14:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id b185so23861917qkg.1
        for <kasan-dev@googlegroups.com>; Mon, 06 Jul 2020 05:14:29 -0700 (PDT)
X-Received: by 2002:a05:620a:4ca:: with SMTP id 10mr47782458qks.250.1594037668024;
 Mon, 06 Jul 2020 05:14:28 -0700 (PDT)
MIME-Version: 1.0
References: <20200706115039.16750-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200706115039.16750-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 6 Jul 2020 14:14:16 +0200
Message-ID: <CACT4Y+aphKiK4oZOjCnHr3nGGL3X-HTb1sPfMyT_b947r4X8-g@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: fix KASAN unit tests for tag-based KASAN
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org, 
	Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nko1XfT+;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Mon, Jul 6, 2020 at 1:50 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> We use tag-based KASAN, then KASAN unit tests don't detect out-of-bounds
> memory access. They need to be fixed.
>
> With tag-based KASAN, the state of each 16 aligned bytes of memory is
> encoded in one shadow byte and the shadow value is tag of pointer, so
> we need to read next shadow byte, the shadow value is not equal to tag
> value of pointer, so that tag-based KASAN will detect out-of-bounds
> memory access.
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Matthias Brugger <matthias.bgg@gmail.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

Thanks for fixing these tests!

> ---
>
> changes since v1:
> - Reduce amount of non-compiled code.
> - KUnit-KASAN Integration patchset is not merged yet. My patch should
>   have conflict with it, if needed, we can continue to wait it.
>
> changes since v2:
> - Add one marco to make unit tests more readability.
>
> ---
>  lib/test_kasan.c | 47 ++++++++++++++++++++++++++++++-----------------
>  1 file changed, 30 insertions(+), 17 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index e3087d90e00d..b5049a807e25 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -23,6 +23,8 @@
>
>  #include <asm/page.h>
>
> +#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : 13)
> +
>  /*
>   * Note: test functions are marked noinline so that their names appear in
>   * reports.
> @@ -40,7 +42,8 @@ static noinline void __init kmalloc_oob_right(void)
>                 return;
>         }
>
> -       ptr[size] = 'x';
> +       ptr[size + OOB_TAG_OFF] = 'x';
> +
>         kfree(ptr);
>  }
>
> @@ -92,7 +95,8 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
>                 return;
>         }
>
> -       ptr[size] = 0;
> +       ptr[size + OOB_TAG_OFF] = 0;
> +
>         kfree(ptr);
>  }
>
> @@ -162,7 +166,8 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
>                 return;
>         }
>
> -       ptr2[size2] = 'x';
> +       ptr2[size2 + OOB_TAG_OFF] = 'x';
> +
>         kfree(ptr2);
>  }
>
> @@ -180,7 +185,9 @@ static noinline void __init kmalloc_oob_krealloc_less(void)
>                 kfree(ptr1);
>                 return;
>         }
> -       ptr2[size2] = 'x';
> +
> +       ptr2[size2 + OOB_TAG_OFF] = 'x';
> +
>         kfree(ptr2);
>  }
>
> @@ -216,7 +223,8 @@ static noinline void __init kmalloc_oob_memset_2(void)
>                 return;
>         }
>
> -       memset(ptr+7, 0, 2);
> +       memset(ptr + 7 + OOB_TAG_OFF, 0, 2);
> +
>         kfree(ptr);
>  }
>
> @@ -232,7 +240,8 @@ static noinline void __init kmalloc_oob_memset_4(void)
>                 return;
>         }
>
> -       memset(ptr+5, 0, 4);
> +       memset(ptr + 5 + OOB_TAG_OFF, 0, 4);
> +
>         kfree(ptr);
>  }
>
> @@ -249,7 +258,8 @@ static noinline void __init kmalloc_oob_memset_8(void)
>                 return;
>         }
>
> -       memset(ptr+1, 0, 8);
> +       memset(ptr + 1 + OOB_TAG_OFF, 0, 8);
> +
>         kfree(ptr);
>  }
>
> @@ -265,7 +275,8 @@ static noinline void __init kmalloc_oob_memset_16(void)
>                 return;
>         }
>
> -       memset(ptr+1, 0, 16);
> +       memset(ptr + 1 + OOB_TAG_OFF, 0, 16);
> +
>         kfree(ptr);
>  }
>
> @@ -281,7 +292,8 @@ static noinline void __init kmalloc_oob_in_memset(void)
>                 return;
>         }
>
> -       memset(ptr, 0, size+5);
> +       memset(ptr, 0, size + 5 + OOB_TAG_OFF);
> +
>         kfree(ptr);
>  }
>
> @@ -415,7 +427,8 @@ static noinline void __init kmem_cache_oob(void)
>                 return;
>         }
>
> -       *p = p[size];
> +       *p = p[size + OOB_TAG_OFF];
> +
>         kmem_cache_free(cache, p);
>         kmem_cache_destroy(cache);
>  }
> @@ -512,25 +525,25 @@ static noinline void __init copy_user_test(void)
>         }
>
>         pr_info("out-of-bounds in copy_from_user()\n");
> -       unused = copy_from_user(kmem, usermem, size + 1);
> +       unused = copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
>
>         pr_info("out-of-bounds in copy_to_user()\n");
> -       unused = copy_to_user(usermem, kmem, size + 1);
> +       unused = copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
>
>         pr_info("out-of-bounds in __copy_from_user()\n");
> -       unused = __copy_from_user(kmem, usermem, size + 1);
> +       unused = __copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
>
>         pr_info("out-of-bounds in __copy_to_user()\n");
> -       unused = __copy_to_user(usermem, kmem, size + 1);
> +       unused = __copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
>
>         pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> -       unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
> +       unused = __copy_from_user_inatomic(kmem, usermem, size + 1 + OOB_TAG_OFF);
>
>         pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> -       unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
> +       unused = __copy_to_user_inatomic(usermem, kmem, size + 1 + OOB_TAG_OFF);
>
>         pr_info("out-of-bounds in strncpy_from_user()\n");
> -       unused = strncpy_from_user(kmem, usermem, size + 1);
> +       unused = strncpy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
>
>         vm_munmap((unsigned long)usermem, PAGE_SIZE);
>         kfree(kmem);
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200706115039.16750-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaphKiK4oZOjCnHr3nGGL3X-HTb1sPfMyT_b947r4X8-g%40mail.gmail.com.
