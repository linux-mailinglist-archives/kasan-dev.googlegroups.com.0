Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMF57T7QKGQEJO2DJ3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 716832F4FD7
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:24:17 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id d10sf714886ote.22
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:24:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610555056; cv=pass;
        d=google.com; s=arc-20160816;
        b=m3arqPjEBpz4bAjXgh3Pq1gmBSOicKqU2JNwOJ5Tzj3QksMuUy+CrgF6l5f/9pjoUQ
         FAL2Gwt786LE9bAotXk2s1hA4OJ5m0A2+eG8vwoDCZ4ziPdEeUXmLAt33ccAGnCACP8x
         n0uwmBqxDX0fqw7ehQEDxzEBeuGOA9QYspzkTsTfoNxlGiIrZkpIQtOEKlBgBChx2f3i
         qp3O4d76R9w7ueM99b5KNEtoQjJCzFKS5r8wld0bDiX/Db93l6uo4EUR730Uo+b5GT9D
         lLxiNsVFlcVNTlk5FZMb99ktOdZ9EQsCt0N/b7hf7bZev8UbK0WHkJSu6zlc2mOv+yzW
         KPtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6v6Fn5LJ5vOxD8iHCKOdKBYJ8VZ5GrkuXelJEfS4cYo=;
        b=HXouACNmFRUawHq3c2agh4z/NbWPShTOoXVoDjJE+UP0aRGzpL1Onxs/gpS+ipL/P8
         KTvNqt3FZbzMAV3R6201WZQOcwyvWE8k3xG+UPstNJ3bG3gGhO3fnY7VYa7VxuzdBQ5o
         5fbunSMDVuHHFCQZkX3t/sPXsa+yuNjt6OVM2gBfvv9VrBdkyNeh7fjmxuPDrDS/cWVe
         uiFEid3z+UqhP0Jc6xJZUqMMS3vl96RZ4Fvx24HZ3n7l4KO50+CyCrCzBWMETXCB0kJ7
         FfO0p9U9ClFvlXYBsuQPuGnYh2sruaS9wSVVjIRkqsexmCeCDFRm8aMtDjGiyK6WNzPO
         8mCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tlmb7Dtm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6v6Fn5LJ5vOxD8iHCKOdKBYJ8VZ5GrkuXelJEfS4cYo=;
        b=ccVsvRDKdFkSYsq6xh/ulnAnssypYdb93kLC5o7Klirs/FCr8IdRShlHPdK6+IR/Xl
         5Pt3kXQqoZQAqwgl7F8Y5V69XFQft0Acs/3QPQVi36ONpm636LvnyXniXoNlHhdBtzI1
         KlqJODY22bUqS6+5gCq73Hvy8M0xS2OPwTv6xNypT73N5bQR/KUHkIRdibVN3dsxb8Sp
         LT2nBvaKqc1ifKwSvbmbmgDESrwCHrIOP6gljK2bQc0pXfmpGXaLxkI8W3QUT5Vgss5K
         DpYHTr99r2hdpwvmVud+Waa65u8uETSo4Y9yiMB/hYJYjjoPliADNKpzkNpkkBLYx7zv
         C58A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6v6Fn5LJ5vOxD8iHCKOdKBYJ8VZ5GrkuXelJEfS4cYo=;
        b=KdPPi6Oa9BeqLxonqCpusg2bgHUR6oaTHO19aqPpkIu6kNxbIguSbNMgqDEf/yv6zS
         NykzdJ1MoaPuz1TtGxPhSLrRkZGTOF8CzEQu1kGTTvIS7R+XxgioF1RXLBS3Gi7cQVij
         1puCNDuJaCjJ6dQFCRVu42HSFJla/cA1lSjdOwadnzLRJpwlJhqm4Ba5Rxqs7FTFqSQq
         1mLW2hKqxrsw6F81j/IqMkvJG9MLplWldosjQ5AgkGD9vjLrK1hBTZv+n87Dw6j2j9/F
         ZV3A6Ek9nHaONlLB9DXbrhLK30UNV+c62VHQFua5DwEjpdJ26YSkw51MlspWDc36VEZt
         fl0g==
X-Gm-Message-State: AOAM5310lDO1W39EUaN01qOWtFEaidzr6PmzrLmkPWLavAeEkvIpApB5
	gnjhe1TpgRrYUpETWeRc96k=
X-Google-Smtp-Source: ABdhPJxpmyYTDxdsLDzhTreZHQVEvAMoZR48C7DheIkVR6jHquaaNULUJCGTyx9lVQ5yqN+v32o+sg==
X-Received: by 2002:aca:728b:: with SMTP id p133mr14212oic.125.1610555056376;
        Wed, 13 Jan 2021 08:24:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:714:: with SMTP id y20ls655960ots.9.gmail; Wed, 13
 Jan 2021 08:24:16 -0800 (PST)
X-Received: by 2002:a9d:2ae3:: with SMTP id e90mr1774475otb.105.1610555056065;
        Wed, 13 Jan 2021 08:24:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610555056; cv=none;
        d=google.com; s=arc-20160816;
        b=lfsTG3IuBUPBVmAZAk7tvBHGApHGYFymvoUR8XyZW23syVNU7WTxP9lY7IX3Q3+pyy
         3y6+8tsbbq9bwy7TUXV6g7jAJ/O6063ruG8RPGPKV1kCX0LH/vDp2c5Dv84jkYc5Tzhy
         B75U7uxGLFWzJolgfCFI0W1OwpIaWnVxM6DpWpIf7qSMW/ehmLMOBR3RMEumA0vVG+aD
         bFr+HARWQnSuC9VFKrHrpblBEHpf1qUXJcFmpbcNtmyMRQdrGDtQR7olbeEbz29KXF3j
         B62dc6B+tAQMEXnduJ9jHSOYVlACPWm0Ca2cwO/keq2Vd2Dy8tE36FXRsIHLS2w6MTvE
         DZ6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GyTHDPIRlWLUaLwyKAW0evEpBngzgktQyEH3p/lXCIQ=;
        b=TAQd5dzNqZ/DdZpPoc09561fb6ZDcultnzXd8FU0gUeSs5ETCWblFXRJ8Wzpq1W8KR
         WobS1ETHoTlzkdBIdt4C+3Fe4Z9SZ97plpVwqRgD/JfZNiX7OtAB4TG+J2Tg74Rx7R8n
         6NFgext3oFhwmsMI5qP6yNy8p3iMBp95DrhgSvvfHOx2ij9icbJH/kZCnQEvGTMEFzpI
         M5BnRUrkAOZsStvlM5997akw+QXXFjI5B5Y8vsq0mE6KXwxO/UNMglCbdX8Jpn+vH38C
         DdiWqVmtZSh3O/VuZKkQC+tcUzEEegzqPx14nY5EPVWWyLiYHPOYXugL57D8ANN9Td5B
         2NLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tlmb7Dtm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id r27si152799oth.2.2021.01.13.08.24.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:24:16 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id s2so2719113oij.2
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:24:16 -0800 (PST)
X-Received: by 2002:aca:c085:: with SMTP id q127mr58645oif.70.1610555055524;
 Wed, 13 Jan 2021 08:24:15 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <2b43049e25dcd04850ba6c205cd6dcc7caa4a886.1610554432.git.andreyknvl@google.com>
In-Reply-To: <2b43049e25dcd04850ba6c205cd6dcc7caa4a886.1610554432.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jan 2021 17:24:03 +0100
Message-ID: <CANpmjNOdax5uH1bG_D+7SWBL6FphCefcKs+5wig9NZxeEghUYA@mail.gmail.com>
Subject: Re: [PATCH v2 03/14] kasan: clean up comments in tests
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tlmb7Dtm;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
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

On Wed, 13 Jan 2021 at 17:21, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Clarify and update comments in KASAN tests.
>
> Link: https://linux-review.googlesource.com/id/I6c816c51fa1e0eb7aa3dead6bda1f339d2af46c8
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  lib/test_kasan.c        | 59 +++++++++++++++++++++++++----------------
>  lib/test_kasan_module.c |  5 ++--
>  2 files changed, 39 insertions(+), 25 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 2947274cc2d3..6f46e27c2af7 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -28,10 +28,9 @@
>  #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
>
>  /*
> - * We assign some test results to these globals to make sure the tests
> - * are not eliminated as dead code.
> + * Some tests use these global variables to store return values from function
> + * calls that could otherwise be eliminated by the compiler as dead code.
>   */
> -
>  void *kasan_ptr_result;
>  int kasan_int_result;
>
> @@ -39,14 +38,13 @@ static struct kunit_resource resource;
>  static struct kunit_kasan_expectation fail_data;
>  static bool multishot;
>
> +/*
> + * Temporarily enable multi-shot mode. Otherwise, KASAN would only report the
> + * first detected bug and panic the kernel if panic_on_warn is enabled.
> + */
>  static int kasan_test_init(struct kunit *test)
>  {
> -       /*
> -        * Temporarily enable multi-shot mode and set panic_on_warn=0.
> -        * Otherwise, we'd only get a report for the first case.
> -        */
>         multishot = kasan_save_enable_multi_shot();
> -
>         return 0;
>  }
>
> @@ -56,12 +54,12 @@ static void kasan_test_exit(struct kunit *test)
>  }
>
>  /**
> - * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> - * not cause a KASAN error. This uses a KUnit resource named "kasan_data." Do
> - * Do not use this name for a KUnit resource outside here.
> - *
> + * KUNIT_EXPECT_KASAN_FAIL() - check that the executed expression produces a
> + * KASAN report; causes a test failure otherwise. This relies on a KUnit
> + * resource named "kasan_data". Do not use this name for KUnit resources
> + * outside of KASAN tests.
>   */
> -#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
> +#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do { \
>         fail_data.report_expected = true; \
>         fail_data.report_found = false; \
>         kunit_add_named_resource(test, \
> @@ -69,7 +67,7 @@ static void kasan_test_exit(struct kunit *test)
>                                 NULL, \
>                                 &resource, \
>                                 "kasan_data", &fail_data); \
> -       condition; \
> +       expression; \
>         KUNIT_EXPECT_EQ(test, \
>                         fail_data.report_expected, \
>                         fail_data.report_found); \
> @@ -121,7 +119,8 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
>                 return;
>         }
>
> -       /* Allocate a chunk that does not fit into a SLUB cache to trigger
> +       /*
> +        * Allocate a chunk that does not fit into a SLUB cache to trigger
>          * the page allocator fallback.
>          */
>         ptr = kmalloc(size, GFP_KERNEL);
> @@ -168,7 +167,9 @@ static void kmalloc_large_oob_right(struct kunit *test)
>  {
>         char *ptr;
>         size_t size = KMALLOC_MAX_CACHE_SIZE - 256;
> -       /* Allocate a chunk that is large enough, but still fits into a slab
> +
> +       /*
> +        * Allocate a chunk that is large enough, but still fits into a slab
>          * and does not trigger the page allocator fallback in SLUB.
>          */
>         ptr = kmalloc(size, GFP_KERNEL);
> @@ -469,10 +470,13 @@ static void ksize_unpoisons_memory(struct kunit *test)
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         real_size = ksize(ptr);
> -       /* This access doesn't trigger an error. */
> +
> +       /* This access shouldn't trigger a KASAN report. */
>         ptr[size] = 'x';
> -       /* This one does. */
> +
> +       /* This one must. */
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr[real_size] = 'y');
> +
>         kfree(ptr);
>  }
>
> @@ -568,7 +572,7 @@ static void kmem_cache_invalid_free(struct kunit *test)
>                 return;
>         }
>
> -       /* Trigger invalid free, the object doesn't get freed */
> +       /* Trigger invalid free, the object doesn't get freed. */
>         KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p + 1));
>
>         /*
> @@ -585,7 +589,10 @@ static void kasan_memchr(struct kunit *test)
>         char *ptr;
>         size_t size = 24;
>
> -       /* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
> +       /*
> +        * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
> +        * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
> +        */
>         if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
>                 kunit_info(test,
>                         "str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
> @@ -610,7 +617,10 @@ static void kasan_memcmp(struct kunit *test)
>         size_t size = 24;
>         int arr[9];
>
> -       /* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
> +       /*
> +        * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
> +        * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
> +        */
>         if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
>                 kunit_info(test,
>                         "str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
> @@ -634,7 +644,10 @@ static void kasan_strings(struct kunit *test)
>         char *ptr;
>         size_t size = 24;
>
> -       /* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
> +       /*
> +        * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
> +        * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
> +        */
>         if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
>                 kunit_info(test,
>                         "str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
> @@ -706,7 +719,7 @@ static void kasan_bitops_generic(struct kunit *test)
>         }
>
>         /*
> -        * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
> +        * Allocate 1 more byte, which causes kzalloc to round up to 16 bytes;
>          * this way we do not actually corrupt other memory.
>          */
>         bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
> diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
> index 3b4cc77992d2..eee017ff8980 100644
> --- a/lib/test_kasan_module.c
> +++ b/lib/test_kasan_module.c
> @@ -123,8 +123,9 @@ static noinline void __init kasan_workqueue_uaf(void)
>  static int __init test_kasan_module_init(void)
>  {
>         /*
> -        * Temporarily enable multi-shot mode. Otherwise, we'd only get a
> -        * report for the first case.
> +        * Temporarily enable multi-shot mode. Otherwise, KASAN would only
> +        * report the first detected bug and panic the kernel if panic_on_warn
> +        * is enabled.
>          */
>         bool multishot = kasan_save_enable_multi_shot();
>
> --
> 2.30.0.284.gd98b1dd5eaa7-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOdax5uH1bG_D%2B7SWBL6FphCefcKs%2B5wig9NZxeEghUYA%40mail.gmail.com.
