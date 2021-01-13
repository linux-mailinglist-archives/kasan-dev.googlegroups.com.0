Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB567T7QKGQEEMI642I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 68FD62F4FEC
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:25:44 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id l22sf3808343iom.4
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:25:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610555143; cv=pass;
        d=google.com; s=arc-20160816;
        b=Reh/qGspkf1SoJN8qjlkKPrsah8nWlMuJ7wozcHBTW5/OJEzA0jHPuV9XQBY/j3pJh
         NXgirqWJXdEtuwtZKqqHUnfYm0eMwKBOf65Rx6KMsVfnfrOpkiPJ65DS48A7o/PnLiIJ
         X61Zf7OO1VMBKiNN+S0r/+BsvjOtFndO25sBj7W6DnfEObSJE20dnoUrWUUbXOjSQZbS
         qE/M4gLZrsZdUAcytXn6zBeWXZq5RMTPpBD8yr8j9sCHyYWkw0237oS9DsC7yMekiXC0
         cIZkDb0fioPvLJDdIRweeawa4q/OfiiXZwd3amY456pqk9cuavIMGxXQVVnDnxPr3y2h
         XAng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QgJi5BVyi9ZJs3CUEhdmwn0vIrZWDu4aOAKAjIlmCfI=;
        b=wxw67BTH6tiYXurrsVu7kTeEl+e7uzkuzbmbCGSTXNKW/BcjRsi1gnMMvWWSkVIyhA
         ULdDTN92ux9gjSICi+zYyXo5lmhncTGUAh8AC9Vo51xRC7iWFRN0R6QjcT3mkd/LXnkJ
         EH0XpyuIqrPB9xG0KDQTANupDOZh5sPtd+N5MiGDhV0Q/mzPcbVjucqoNiohZ63ZHMsQ
         plgpup41u0WwgiSNHnCP5dxUfjq1wB4+60o+97kWV2W92TinNuws3jfUmeVnH7/iGCUz
         fCBhJPnVtD5KPNeADp6BeE8YqGF7M4ucxLVLka3ZBllb0wAwsKbYnG7Ee0mWY2DNtTwi
         LZNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jSgTpyYi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QgJi5BVyi9ZJs3CUEhdmwn0vIrZWDu4aOAKAjIlmCfI=;
        b=N3xFWoC9KVP/4oYKZ5P3i0Q+gF2dkRDMHuPcbwOzX/3XfXCloxJabsB/NAYA7k9eYo
         MWcRgmmDdiJ1Gr5bP+91u8JmehgRrhURZgS23CKE1OT793j2yIwJdJQtEQe+7WcApip1
         /pW8zob745Uo0DRrqJ7OGaYaws70vWk+a0LRiW2EzMToFx3f7pu0KGrjIX73I5cRx9z7
         CbjsWu33elBs0iFyh12NGhVZGq6T5d8gYxRLhZ5ZmYjvyPc1xx4+aF/MFJ/949XGyNM+
         aQvDZqx83dAw96ClU7ynAVV7QXfstpi3DIjL+vVg9/Ou/5yVpbz2yAp7P7EoGfuIyDnV
         H+Jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QgJi5BVyi9ZJs3CUEhdmwn0vIrZWDu4aOAKAjIlmCfI=;
        b=mHHuIo4KqcZ0EJUQ5rUFGk7igasoMAMfPv0kciDHEWWWzDiiwmtGuiuokNzF0Liq6y
         hXpqHO3IkVAQD02L5G4Xyc+Y9fmoCanNpsJ2woiZTzOSbOltzuEUlLwp+TfdVrLUXXGl
         3IUBQ+XFmU/e8aJ0yB80LybyHW4Ua7j32m/tFqdmElvmPGje9VdOv1SGrTXZb6Z2poof
         IGm71ieZKC6wTugnt7fTQZl+X93htJXoMpsv+ZlAsKLYwUkrXw8OcFEOOHgPGJt5pN3a
         +TdiCFv9xR0CYeMPJldYq6BjeN9FeiFnuti67dB9Xbv9N/aAWmdt4ZSj9kU0BFueZnBL
         odnA==
X-Gm-Message-State: AOAM5327KnufyoZnhIgUAMdMz0H0odb4oOYsZCYKmmPoNfyz9K7DUVeH
	hLwztbq0JbUTaxUG18bUUQQ=
X-Google-Smtp-Source: ABdhPJzeR2zHDvFoDfxovNRm1Szhk/cjF4+ahHNnsSjFAjqo11ArnnjqIxpALGMUhXHc0OmRG1P/Mw==
X-Received: by 2002:a05:6e02:180a:: with SMTP id a10mr3060163ilv.40.1610555143407;
        Wed, 13 Jan 2021 08:25:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9914:: with SMTP id x20ls341460iol.7.gmail; Wed, 13 Jan
 2021 08:25:43 -0800 (PST)
X-Received: by 2002:a05:6602:224a:: with SMTP id o10mr2443681ioo.28.1610555142980;
        Wed, 13 Jan 2021 08:25:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610555142; cv=none;
        d=google.com; s=arc-20160816;
        b=bAyQWHb3VUR6xrYLOOcW3mX3lvmkKi7QQ+/gWP86qnR0J90gZPW/vTjRamV93lJ3PN
         8pvZEFqka2moSRH4kOtMS9X0cvEYLQ96LXxCqzxcgpQZRFBIg8yBz/PjzOJRJ0sf8Xs+
         ePyc3EMxS/y2HwWmRJCOY7I0H+DaUlFU5gCiO7FyVdyEKcdUBATXhA+ScHChn/R6Ouh/
         zEhQ1FJ5aJkbUHHUz+uVs2D+8Ap3vWqFbbdsMjaQroKbb/G65hU0JfuulPgC1t/hiRIP
         6nC/Cu/JT/Cx0aw0tVhSYKGgi3AxyBd71BqoC3xKXj4cyuh7rBNolAh8sIAYVfc0+jrB
         iR8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Rj6WRYh2NAKrrsW/5ki70/RayzjiACCNyfDalLAwfF0=;
        b=05WEJ+agSiNxb8u/NUkg7haSO1yiKN62zlcZWbW3WwSq1Igcj5kshxNviI/MKOCN/m
         bolr2/SlN+xnjNrXNhTJzdqN+2h6/r9ZDDY/lRWctepnvQXSJFl2zjooBtNZNcWENOaM
         wQTuqnWNquW6nJxlAv3W5V5vQdWh5bQbXydA7h8GisjeRB6NbCDZj7M3PDVS0bSX3HKB
         IiD5+18+nlF5a8g5XE27q9hV9ULFvHA/IBa2A8WVEVJ2+7rz0QZFCscHgSyg5efc4e9i
         tR7ordkNYkVaicUyN2fEV/eeqy5NuQ3NKSMjVcy8OjQTf+lFNmsXkym13kn2bZauIvCT
         Be3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jSgTpyYi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id d13si85171iow.0.2021.01.13.08.25.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:25:42 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id l207so2716324oib.4
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:25:42 -0800 (PST)
X-Received: by 2002:aca:58d6:: with SMTP id m205mr17059oib.121.1610555142511;
 Wed, 13 Jan 2021 08:25:42 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <0afed913e43017575794de0777b15ef6b2bdd486.1610554432.git.andreyknvl@google.com>
In-Reply-To: <0afed913e43017575794de0777b15ef6b2bdd486.1610554432.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jan 2021 17:25:30 +0100
Message-ID: <CANpmjNMZHiwKDTyBdHzHB6CexJTfN9TUjk=q6zmj_nebtq9=mg@mail.gmail.com>
Subject: Re: [PATCH v2 04/14] kasan: add macros to simplify checking test constraints
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
 header.i=@google.com header.s=20161025 header.b=jSgTpyYi;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as
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
> Some KASAN tests require specific kernel configs to be enabled.
> Instead of copy-pasting the checks for these configs add a few helper
> macros and use them.
>
> Link: https://linux-review.googlesource.com/id/I237484a7fddfedf4a4aae9cc61ecbcdbe85a0a63
> Suggested-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Nice!

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  lib/test_kasan.c | 101 +++++++++++++++--------------------------------
>  1 file changed, 31 insertions(+), 70 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 6f46e27c2af7..714ea27fcc3e 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -73,6 +73,20 @@ static void kasan_test_exit(struct kunit *test)
>                         fail_data.report_found); \
>  } while (0)
>
> +#define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {                  \
> +       if (!IS_ENABLED(config)) {                                      \
> +               kunit_info((test), "skipping, " #config " required");   \
> +               return;                                                 \
> +       }                                                               \
> +} while (0)
> +
> +#define KASAN_TEST_NEEDS_CONFIG_OFF(test, config) do {                 \
> +       if (IS_ENABLED(config)) {                                       \
> +               kunit_info((test), "skipping, " #config " enabled");    \
> +               return;                                                 \
> +       }                                                               \
> +} while (0)
> +
>  static void kmalloc_oob_right(struct kunit *test)
>  {
>         char *ptr;
> @@ -114,10 +128,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
>         char *ptr;
>         size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
>
> -       if (!IS_ENABLED(CONFIG_SLUB)) {
> -               kunit_info(test, "CONFIG_SLUB is not enabled.");
> -               return;
> -       }
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
>
>         /*
>          * Allocate a chunk that does not fit into a SLUB cache to trigger
> @@ -135,10 +146,7 @@ static void kmalloc_pagealloc_uaf(struct kunit *test)
>         char *ptr;
>         size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
>
> -       if (!IS_ENABLED(CONFIG_SLUB)) {
> -               kunit_info(test, "CONFIG_SLUB is not enabled.");
> -               return;
> -       }
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
>
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> @@ -152,10 +160,7 @@ static void kmalloc_pagealloc_invalid_free(struct kunit *test)
>         char *ptr;
>         size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
>
> -       if (!IS_ENABLED(CONFIG_SLUB)) {
> -               kunit_info(test, "CONFIG_SLUB is not enabled.");
> -               return;
> -       }
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
>
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> @@ -218,10 +223,7 @@ static void kmalloc_oob_16(struct kunit *test)
>         } *ptr1, *ptr2;
>
>         /* This test is specifically crafted for the generic mode. */
> -       if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -               kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
> -               return;
> -       }
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
>
>         ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
> @@ -454,10 +456,7 @@ static void kasan_global_oob(struct kunit *test)
>         char *p = &global_array[ARRAY_SIZE(global_array) + i];
>
>         /* Only generic mode instruments globals. */
> -       if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -               kunit_info(test, "CONFIG_KASAN_GENERIC required");
> -               return;
> -       }
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
>
>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>  }
> @@ -486,10 +485,7 @@ static void kasan_stack_oob(struct kunit *test)
>         volatile int i = OOB_TAG_OFF;
>         char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
>
> -       if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
> -               kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
> -               return;
> -       }
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_STACK);
>
>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>  }
> @@ -501,15 +497,8 @@ static void kasan_alloca_oob_left(struct kunit *test)
>         char *p = alloca_array - 1;
>
>         /* Only generic mode instruments dynamic allocas. */
> -       if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -               kunit_info(test, "CONFIG_KASAN_GENERIC required");
> -               return;
> -       }
> -
> -       if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
> -               kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
> -               return;
> -       }
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_STACK);
>
>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>  }
> @@ -521,15 +510,8 @@ static void kasan_alloca_oob_right(struct kunit *test)
>         char *p = alloca_array + i;
>
>         /* Only generic mode instruments dynamic allocas. */
> -       if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -               kunit_info(test, "CONFIG_KASAN_GENERIC required");
> -               return;
> -       }
> -
> -       if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
> -               kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
> -               return;
> -       }
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_STACK);
>
>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>  }
> @@ -593,11 +575,7 @@ static void kasan_memchr(struct kunit *test)
>          * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
>          * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
>          */
> -       if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
> -               kunit_info(test,
> -                       "str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
> -               return;
> -       }
> +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_AMD_MEM_ENCRYPT);
>
>         if (OOB_TAG_OFF)
>                 size = round_up(size, OOB_TAG_OFF);
> @@ -621,11 +599,7 @@ static void kasan_memcmp(struct kunit *test)
>          * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
>          * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
>          */
> -       if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
> -               kunit_info(test,
> -                       "str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
> -               return;
> -       }
> +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_AMD_MEM_ENCRYPT);
>
>         if (OOB_TAG_OFF)
>                 size = round_up(size, OOB_TAG_OFF);
> @@ -648,11 +622,7 @@ static void kasan_strings(struct kunit *test)
>          * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
>          * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
>          */
> -       if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
> -               kunit_info(test,
> -                       "str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
> -               return;
> -       }
> +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_AMD_MEM_ENCRYPT);
>
>         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> @@ -713,10 +683,7 @@ static void kasan_bitops_generic(struct kunit *test)
>         long *bits;
>
>         /* This test is specifically crafted for the generic mode. */
> -       if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -               kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
> -               return;
> -       }
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
>
>         /*
>          * Allocate 1 more byte, which causes kzalloc to round up to 16 bytes;
> @@ -744,11 +711,8 @@ static void kasan_bitops_tags(struct kunit *test)
>  {
>         long *bits;
>
> -       /* This test is specifically crafted for the tag-based mode. */
> -       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -               kunit_info(test, "CONFIG_KASAN_SW_TAGS required\n");
> -               return;
> -       }
> +       /* This test is specifically crafted for tag-based modes. */
> +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
>
>         /* Allocation size will be rounded to up granule size, which is 16. */
>         bits = kzalloc(sizeof(*bits), GFP_KERNEL);
> @@ -777,10 +741,7 @@ static void vmalloc_oob(struct kunit *test)
>  {
>         void *area;
>
> -       if (!IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
> -               kunit_info(test, "CONFIG_KASAN_VMALLOC is not enabled.");
> -               return;
> -       }
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
>
>         /*
>          * We have to be careful not to hit the guard page.
> --
> 2.30.0.284.gd98b1dd5eaa7-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMZHiwKDTyBdHzHB6CexJTfN9TUjk%3Dq6zmj_nebtq9%3Dmg%40mail.gmail.com.
