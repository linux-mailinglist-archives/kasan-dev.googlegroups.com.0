Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6W3473QKGQEPPSYZLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id F35E120CED6
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 15:34:51 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id z12sf9988553plk.23
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 06:34:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593437690; cv=pass;
        d=google.com; s=arc-20160816;
        b=VplFw7x5+sEmSUMUh19jHKfMHfZDoO6oRrPQcGMcvaIU8U5fXkknnKt6bchLbXkgo/
         3GxwCMJjT8o6AkplKp9s+YzPyCPdnhz0JVwhMeFHG67UqBz8etdzeaVdp5fveeTm8Fq5
         lNLHwfnixSYtaJq5YvYZwDfKPUNex1Hq3NZOHPmJLVvDgsRYnDmoosMOmKnyLRI44Chm
         GGPj1CK7LTd3+sE3EZBXEERBK3KEpii2J5RF1toZZ8Ekwd9aDgVjcnwxvLzrgw+BGFeO
         s9C9UjSxGV5y/0UvcGPpfJAXWgsHw+NffGtJKsFyNv+qRr9nINDNXg/EEMC2kCb9QiZH
         yoww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9ZuP/hoT4VxrdDy/jgwZRfwUJm3PJ3y+EfAvlKg41EI=;
        b=GxoFT1tkaAh5Q3cfvnvlp9omdJiTviMReVFlyaVSQFyVdrOtgi7FszThjL4GmDimmw
         X/q3NXUqIROqsfgLu6OZ1qOt0K5jC7ZKBwP5yYYBd4773xRQxitJ32uspwJL073vWdxG
         ZVPCGzajGOKcIaWuGuZoy20/BPipzsBdWPkTbySstYdMjymd0a4sLUJ4+iSF02fpp6nf
         wWXWe4obV3M7fVh4Ve2UO3Ad9fNa6re8nSMj38KzsXft/nkn8vm+MrvKFj5YNVa8vMxk
         pUzTjNbTONH4IPDdaSeUwi8ND2fPuvQ1u6JHM778gwToFvYpfFoYnuyyAuCOKuJwR/Hq
         tpvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uoCEwiDC;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9ZuP/hoT4VxrdDy/jgwZRfwUJm3PJ3y+EfAvlKg41EI=;
        b=TC/fTqLLqgqwmmmz0MIACx6zj4gqMIY7wVdFCQWasxifn013qQHsOk1oEcsGFxac66
         bg5t34j4pghhQcLm5sSJLbSSJzB12j6kGqprodqPHL1625mrGBsnhS74p2pZIMB9OfIy
         13APfRtx5DBX0adOVGaEla/+AC/7BS3SNRyuuPHHDYZdci8SrursDk6/UVeHNDr+Iors
         fXariU0HLNXzyIO3mVP1IMvgWbzD08s++xfcpbwYKsWdBZbpmOrzGG9m0C6jSqCvjhfJ
         t4QJLSBJhx5564p0PPaskftf/Osru8/kyxtfvU9XGY4T5O6mkmcoD6GbFglYevkebWko
         hqxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9ZuP/hoT4VxrdDy/jgwZRfwUJm3PJ3y+EfAvlKg41EI=;
        b=AmO5W7S0264Ica/mKGxCjBolQxvG2ZRRjmPAyokaxZZoD5BuDvI+Q0XoN13qIKOCRA
         Ws1JLeZFE0PCUmdVT9bUTCu6nAYnQZzDG7YpgoDoVVemwVb1/yX1j0x87zelXkXABlTz
         GAx/mvqaSRAIsbYsU9I++3MrthjkG9ZY+0YlrZFG1FEmKsS0iz5JKqvnShhM5uEe6K+m
         Jtd/X6mZ2bIzPiQ10BhzIrmH3r/bzy1c3+gkoHkuuopBljyRbZYjv/6PRXBNxtet8x/f
         +RqYAhb91mFq9NDCsoHk6iqY1VscZVJeMZmd9nCOINb4Tza3tqX97j20Tk7qI2m5NFEz
         Q18g==
X-Gm-Message-State: AOAM532xf1IHwjexHDD9ymNwjGGxIAI2ZxRLszTCc45bUwYDEb0NJMxy
	+VCMpnza0Nu1XtxScwPgVQg=
X-Google-Smtp-Source: ABdhPJzg2UqECf97K6Xpf4AUukGuLy8TYJv7qKE6eacB9OCApha3Q2beCmPUBpNprQfFs5LFCWkczg==
X-Received: by 2002:a17:90a:c28c:: with SMTP id f12mr17563173pjt.224.1593437690472;
        Mon, 29 Jun 2020 06:34:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:134a:: with SMTP id k10ls5442195pfu.11.gmail; Mon,
 29 Jun 2020 06:34:50 -0700 (PDT)
X-Received: by 2002:a63:dd4d:: with SMTP id g13mr10210301pgj.179.1593437690100;
        Mon, 29 Jun 2020 06:34:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593437690; cv=none;
        d=google.com; s=arc-20160816;
        b=QyQ8UW4q8GleJ9W1cqFxaGWHD7+zPJ/z9p/eYR7Yidvz639BHH26E5rd+2L78Z+YP7
         4rnwBuUo7npd7DEgxcF7/dr9TN1B5ka06gKw1uuGQZjRh8+9O2fjR3QsJchzER4lIAOJ
         1LivYf2bBQPHRgyiDlNp+O0mtCasNvAMFLdi+zmmHfh4hvEC+SpNVD6VXAqmON9VB6Nb
         0XSoi3KJqDI8vC2U3OMdS04/DwGpO0BHDJ3uScvzJkZ6ne7WIPir2gMSVQvSjaIz2kBh
         PSfqBsckdfAluST+4c5lNFyID/drlx2RLGnPZyDIcYMznEUhYPzK/9lRTiacuSIZaUwj
         uNxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4UqCNZ+OTg1lzw/q2Kz2sA9G3h4mbPe/xzzDfR/Wl6o=;
        b=as7pzlD1dAcmYfy7nn06e/YTs6xvZbqe7j5UqTHqhu0mPd7i9CWCl3z88k/P9HBU3k
         AYMMH0bFHuKx6Edbxf0yJTK8fRjm6w7BdGp44V/kva3ZeuJL/JUVFxdD75nPlctjssTn
         X33V4OZXfzzEXT3rlZt4COzlzTpVRN4U5RlOclomYbNUutXNZcui6mIu9WtmyoJoTYly
         XSCZ3Yss+JJLEORGUdM+J5U+rn0UZHkHnW2SMZESPDFRotAl1DVd0d/l2+5On3SXJi4I
         6B6Fj7ajtGVTJeuRWD0N/bACsV3fO8ysWCpqOZyGI/koOjP3qtm0vzFP+NKPsfmHfj+F
         kF5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uoCEwiDC;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id y20si113864plb.2.2020.06.29.06.34.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jun 2020 06:34:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id c1so774093pja.5
        for <kasan-dev@googlegroups.com>; Mon, 29 Jun 2020 06:34:50 -0700 (PDT)
X-Received: by 2002:a17:902:6ac1:: with SMTP id i1mr14053992plt.147.1593437689499;
 Mon, 29 Jun 2020 06:34:49 -0700 (PDT)
MIME-Version: 1.0
References: <20200629104157.3242503-1-elver@google.com>
In-Reply-To: <20200629104157.3242503-1-elver@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Jun 2020 15:34:38 +0200
Message-ID: <CAAeHK+wbaHoeEqaKCNgPhFFWQZ0Ck2BYF9QiCcOuyB9JGDmhsw@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan: Improve and simplify Kconfig.kasan
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Arnd Bergmann <arnd@arndb.de>, Daniel Axtens <dja@axtens.net>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uoCEwiDC;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Jun 29, 2020 at 12:42 PM Marco Elver <elver@google.com> wrote:
>
> Turn 'KASAN' into a menuconfig, to avoid cluttering its parent menu with
> the suboptions if enabled. Use 'if KASAN ... endif' instead of having
> to 'depend on KASAN' for each entry.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  lib/Kconfig.kasan | 15 ++++++++-------
>  1 file changed, 8 insertions(+), 7 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 34b84bcbd3d9..89053defc0d9 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -18,7 +18,7 @@ config CC_HAS_KASAN_SW_TAGS
>  config CC_HAS_WORKING_NOSANITIZE_ADDRESS
>         def_bool !CC_IS_GCC || GCC_VERSION >= 80300
>
> -config KASAN
> +menuconfig KASAN
>         bool "KASAN: runtime memory debugger"
>         depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
>                    (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
> @@ -29,9 +29,10 @@ config KASAN
>           designed to find out-of-bounds accesses and use-after-free bugs.
>           See Documentation/dev-tools/kasan.rst for details.
>
> +if KASAN
> +
>  choice
>         prompt "KASAN mode"
> -       depends on KASAN
>         default KASAN_GENERIC
>         help
>           KASAN has two modes: generic KASAN (similar to userspace ASan,
> @@ -88,7 +89,6 @@ endchoice
>
>  choice
>         prompt "Instrumentation type"
> -       depends on KASAN
>         default KASAN_OUTLINE
>
>  config KASAN_OUTLINE
> @@ -113,7 +113,6 @@ endchoice
>
>  config KASAN_STACK_ENABLE
>         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
> -       depends on KASAN
>         help
>           The LLVM stack address sanitizer has a know problem that
>           causes excessive stack usage in a lot of functions, see
> @@ -134,7 +133,7 @@ config KASAN_STACK
>
>  config KASAN_S390_4_LEVEL_PAGING
>         bool "KASan: use 4-level paging"
> -       depends on KASAN && S390
> +       depends on S390
>         help
>           Compiling the kernel with KASan disables automatic 3-level vs
>           4-level paging selection. 3-level paging is used by default (up
> @@ -151,7 +150,7 @@ config KASAN_SW_TAGS_IDENTIFY
>
>  config KASAN_VMALLOC
>         bool "Back mappings in vmalloc space with real shadow memory"
> -       depends on KASAN && HAVE_ARCH_KASAN_VMALLOC
> +       depends on HAVE_ARCH_KASAN_VMALLOC
>         help
>           By default, the shadow region for vmalloc space is the read-only
>           zero page. This means that KASAN cannot detect errors involving
> @@ -164,8 +163,10 @@ config KASAN_VMALLOC
>
>  config TEST_KASAN
>         tristate "Module for testing KASAN for bug detection"
> -       depends on m && KASAN
> +       depends on m
>         help
>           This is a test module doing various nasty things like
>           out of bounds accesses, use after free. It is useful for testing
>           kernel debugging features like KASAN.
> +
> +endif # KASAN
> --
> 2.27.0.212.ge8ba1cc988-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwbaHoeEqaKCNgPhFFWQZ0Ck2BYF9QiCcOuyB9JGDmhsw%40mail.gmail.com.
