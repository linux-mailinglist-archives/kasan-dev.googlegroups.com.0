Return-Path: <kasan-dev+bncBDX4HWEMTEBRBD4V37ZAKGQEZBKOLIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 62D78171AB5
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 14:56:33 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id g2sf1205008plg.8
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 05:56:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582811791; cv=pass;
        d=google.com; s=arc-20160816;
        b=bK/UrP4bKFHSYSKaudZnZKJVXaImRmmCKVmsQloFc2L4WsMgUZeYL8pfJyCjIErr4j
         kzCI1csYoVrNb/ska3VnRjMDAd8U0WU6kaBYMAYuQS69DXO6NJ/wI/wkDzRq/G6qKeJ9
         XuOjjYPbPDnzgLtBvz3Mp/GgbQ7L/316Uj27j7mKqqRb0Ky0gDHFhlrl5kteYQAy8pQq
         dvtxVZu1Jq7/sELWYP8DdH5OkeStMBC7dAGnSFK+uQKlWHgUj/Psj+LJpQpDbYK2Xqa3
         3pouUBn5biuhK9z9DlYKnZBheSxcJzmDHhkwU1ZD97q05JM7RWfxlNtsBYEbWJTWrzdJ
         B4bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2jFT0o5lKosDNBTdD9GsRYvfqXPyx7zDt03hkb1yhPc=;
        b=rKk6rTlCHZt8wQEgUi+9aLTfbss9Sv8f5V4zw86znA9X7Kfkm2D4VzKXfoTMbBUxHf
         q/8EpnN8AsykNg3vdPQAt2wepi/D/grlwjvcK7tgrlcrSq+Czic2xWLsYLqrizir8sKd
         R7GUpfrdICLCKzOYOYaZRfHCZE4tUTLGGHwXkc8ZujtpK7Ty9KH+FjcbRSaSUb7siJw0
         miPQolBerqaYxYT5Nn5gCtzR7QpQr3tN29BUx+wLhHlZ50qdwzz+wfNuFsaOwvhyis/c
         Q4F1OKUr9ECelYH4waveXgvowhjqj9+P7M5oZUzpCFFaGhoF6jkRUXk9iIby8N5mdyP8
         mYwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="UpFbP/+/";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2jFT0o5lKosDNBTdD9GsRYvfqXPyx7zDt03hkb1yhPc=;
        b=PP2xY6EDHgowCtNmojr2y46YtpZxuNqJnq+rSgwLinekqgWmePt7ZLyJkvt2M9WeEJ
         aXMLsLZ2jGCxmQ9bGn78icMmwVhPxQv/qUgdXA51rF62XbtOczWwN2R0zJDATRNy+dDQ
         SRCsH0xKifgDM3QKwpfW5r1soN6nEOONtKbiZ6LRwhi+392ZvyZ62Zh4PP3xCikqQyYT
         0lbwxBJjihhk7NCxiPVniGKwV+IK/eHcHgA8AxJjaAgC5GVjwX67uqECkiDElM8oW1fy
         m8p0yDhTTNOXZlXNMHyRTI5G2gc+XbIRroF0jrjb0MvwKknpNMgk5NGf8/b7OVq6q9DA
         DlNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2jFT0o5lKosDNBTdD9GsRYvfqXPyx7zDt03hkb1yhPc=;
        b=TxDueVnWdSuWil3fm7xYa2OJRDCYmt3B+i1/LeKFaY7WKVDhKqCeVbW3uOkbZNsvnw
         xaOz9QxJGv4c8L851U7Obx4aKXWS3vIV7vwKnuC/y7KMQIFNYf2fubp3BEHpNOKYST8p
         GiYXxaQ1RMilRZlADz6+B2djJtzEGkkq9c4g3oWWoZP2JZM0RLnQcdHhBf94Zy0E3jje
         2/UmmjIm+4HTUi6Khf2WNAneQ7tdz0DiYvmum4krG9T0eLI8QayA165PLjGDm2nTWLae
         Ybexv8APgcVn95FL/wESMdV57+vp7UvXqYjTCMRxkhSExYzNhF+doADQEqZ5zyUAvzWG
         zBcQ==
X-Gm-Message-State: APjAAAX4ky/ZirICfnNSxj09AQr53sNArWyp65IO8hMl3ZFf1cSXbvj9
	XfHahoz0XPFt7lnktJnh8YM=
X-Google-Smtp-Source: APXvYqxo+P9NmNmKRld9O4TZ31Z968CAyW3LfjuYw3y4147xes0+jD0z8zc7vG9Dlchgy8QsyqOHnw==
X-Received: by 2002:a62:5544:: with SMTP id j65mr4309191pfb.121.1582811791389;
        Thu, 27 Feb 2020 05:56:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5f8b:: with SMTP id t133ls1061317pgb.1.gmail; Thu, 27
 Feb 2020 05:56:30 -0800 (PST)
X-Received: by 2002:a62:1548:: with SMTP id 69mr4271707pfv.239.1582811790801;
        Thu, 27 Feb 2020 05:56:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582811790; cv=none;
        d=google.com; s=arc-20160816;
        b=Hx4+1Gpe7bHhMEJ5Wm8Z8pDT4Hzu+MkbZbR9+3k5CKgOYL46N0bbI7UJGpEZiQa1yL
         akWtSvP8GaHkiPqeZlcv72AsRxgW/2+uni4Wzs82Co1oE/gbpR97eFJTuuY1OYIJycqU
         zuDNHNdG8/wdLehbs9ebyFfcjcmRWfcQLFDTu+UxnDR0NkTKi7o/XV7IyWJSB2H+Y3bt
         fP0jzhHOvcy9Hj6n4WW62mroQ900/8I8fJDOJqZqMH8XbeV43FoYrYL0LXDWpvoLsvyN
         Nu4IfnfREAfSPob+bSxAkskoJP1ngcdGg+fE1eUsNYRM01Bra+4XGX3VAROtutZbZ1dH
         wBSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C4oVbWZsDjkczADX1E+Ggf+CTZ9yneGghFA2KUHY0RU=;
        b=NX2Ntke5hwgZwQhAFyCK3B24CK0A+srGFUEsTD14Nj3iKXjHM0pQ0P89z/tNZk0gv3
         if2thYZTOSB1hpu2Bi6DyAdORYJUykVVbt2bEW+HxoqblNPg1L+hWqdQd/Y4Xir3X84L
         KAVc8Xvobs6Ev87emm30fJA/w3dTLkr2pFuExS2RXhg1zHcf1xPk0xpjYc1CGWX2AJe5
         W7nN3ylt9pTo/6WCRYxx02AVMkCz2AnAYxNxoMfmpzAWwp5KtibfPxq7n08QoTWqzOlF
         6CxaF0mWBVcB96DI1W2DuFiXn4xvacj3ZtlZJEUK0ZKdS0omGXPCLv8eaJmqdK+lZXnv
         2dkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="UpFbP/+/";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id y13si108828plp.0.2020.02.27.05.56.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 05:56:30 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id r67so1180356pjb.0
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 05:56:30 -0800 (PST)
X-Received: by 2002:a17:902:8682:: with SMTP id g2mr4583665plo.336.1582811789766;
 Thu, 27 Feb 2020 05:56:29 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
In-Reply-To: <20200227024301.217042-1-trishalfonso@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Feb 2020 14:56:18 +0100
Message-ID: <CAAeHK+yA1ibD2yYT++==pc5PLKfisFv3ieru54PDDYF4EE_Hfg@mail.gmail.com>
Subject: Re: [RFC PATCH 1/2] Port KASAN Tests to KUnit
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, davidgow@google.com, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, juri.lelli@redhat.com, 
	vincent.guittot@linaro.org, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="UpFbP/+/";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044
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

On Thu, Feb 27, 2020 at 3:44 AM 'Patricia Alfonso' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Transfer all previous tests for KASAN to KUnit so they can be run
> more easily. With proper KASAN integration into KUnit, developers can
> run these tests with their other KUnit tests and see "pass" or "fail"
> with the appropriate KASAN report instead of needing to parse each KASAN
> report to test KASAN functionalities.
>
> Stack tests do not work in UML so those tests are protected inside an
> "#if (CONFIG_KASAN_STACK == 1)" so this only runs if stack
> instrumentation is enabled.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> ---
> The KUnit version of these tests could be in addition to the existing
> tests if that is preferred.

Will it be possible to run KASAN tests with KUnit on arbitrary
hardware/vm with arbitrary architecture (like it is possible now by
loading test_kasan.ko)?

>
>  lib/Kconfig.kasan |   2 +-
>  lib/test_kasan.c  | 352 +++++++++++++++++++++-------------------------
>  2 files changed, 161 insertions(+), 193 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 5b54f3c9a741..f8cc9ed60677 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -160,7 +160,7 @@ config KASAN_VMALLOC
>
>  config TEST_KASAN
>         tristate "Module for testing KASAN for bug detection"
> -       depends on m && KASAN
> +       depends on KASAN && KUNIT
>         help
>           This is a test module doing various nasty things like
>           out of bounds accesses, use after free. It is useful for testing
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 3872d250ed2c..988650387a2a 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -23,17 +23,18 @@
>
>  #include <asm/page.h>
>
> +#include <kunit/test.h>
> +
>  /*
>   * Note: test functions are marked noinline so that their names appear in
>   * reports.
>   */
>
> -static noinline void __init kmalloc_oob_right(void)
> +static noinline void kmalloc_oob_right(void)
>  {
>         char *ptr;
>         size_t size = 123;
>
> -       pr_info("out-of-bounds to right\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -44,12 +45,11 @@ static noinline void __init kmalloc_oob_right(void)
>         kfree(ptr);
>  }
>
> -static noinline void __init kmalloc_oob_left(void)
> +static noinline void kmalloc_oob_left(void)
>  {
>         char *ptr;
>         size_t size = 15;
>
> -       pr_info("out-of-bounds to left\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -60,12 +60,11 @@ static noinline void __init kmalloc_oob_left(void)
>         kfree(ptr);
>  }
>
> -static noinline void __init kmalloc_node_oob_right(void)
> +static noinline void kmalloc_node_oob_right(void)
>  {
>         char *ptr;
>         size_t size = 4096;
>
> -       pr_info("kmalloc_node(): out-of-bounds to right\n");
>         ptr = kmalloc_node(size, GFP_KERNEL, 0);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -77,7 +76,7 @@ static noinline void __init kmalloc_node_oob_right(void)
>  }
>
>  #ifdef CONFIG_SLUB
> -static noinline void __init kmalloc_pagealloc_oob_right(void)
> +static noinline void kmalloc_pagealloc_oob_right(void)
>  {
>         char *ptr;
>         size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
> @@ -85,7 +84,6 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
>         /* Allocate a chunk that does not fit into a SLUB cache to trigger
>          * the page allocator fallback.
>          */
> -       pr_info("kmalloc pagealloc allocation: out-of-bounds to right\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -96,12 +94,11 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
>         kfree(ptr);
>  }
>
> -static noinline void __init kmalloc_pagealloc_uaf(void)
> +static noinline void kmalloc_pagealloc_uaf(void)
>  {
>         char *ptr;
>         size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
>
> -       pr_info("kmalloc pagealloc allocation: use-after-free\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -112,12 +109,11 @@ static noinline void __init kmalloc_pagealloc_uaf(void)
>         ptr[0] = 0;
>  }
>
> -static noinline void __init kmalloc_pagealloc_invalid_free(void)
> +static noinline void kmalloc_pagealloc_invalid_free(void)
>  {
>         char *ptr;
>         size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
>
> -       pr_info("kmalloc pagealloc allocation: invalid-free\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -128,14 +124,13 @@ static noinline void __init kmalloc_pagealloc_invalid_free(void)
>  }
>  #endif
>
> -static noinline void __init kmalloc_large_oob_right(void)
> +static noinline void kmalloc_large_oob_right(void)
>  {
>         char *ptr;
>         size_t size = KMALLOC_MAX_CACHE_SIZE - 256;
>         /* Allocate a chunk that is large enough, but still fits into a slab
>          * and does not trigger the page allocator fallback in SLUB.
>          */
> -       pr_info("kmalloc large allocation: out-of-bounds to right\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -146,13 +141,12 @@ static noinline void __init kmalloc_large_oob_right(void)
>         kfree(ptr);
>  }
>
> -static noinline void __init kmalloc_oob_krealloc_more(void)
> +static noinline void kmalloc_oob_krealloc_more(void)
>  {
>         char *ptr1, *ptr2;
>         size_t size1 = 17;
>         size_t size2 = 19;
>
> -       pr_info("out-of-bounds after krealloc more\n");
>         ptr1 = kmalloc(size1, GFP_KERNEL);
>         ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
>         if (!ptr1 || !ptr2) {
> @@ -166,13 +160,12 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
>         kfree(ptr2);
>  }
>
> -static noinline void __init kmalloc_oob_krealloc_less(void)
> +static noinline void kmalloc_oob_krealloc_less(void)
>  {
>         char *ptr1, *ptr2;
>         size_t size1 = 17;
>         size_t size2 = 15;
>
> -       pr_info("out-of-bounds after krealloc less\n");
>         ptr1 = kmalloc(size1, GFP_KERNEL);
>         ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
>         if (!ptr1 || !ptr2) {
> @@ -184,13 +177,12 @@ static noinline void __init kmalloc_oob_krealloc_less(void)
>         kfree(ptr2);
>  }
>
> -static noinline void __init kmalloc_oob_16(void)
> +static noinline void kmalloc_oob_16(void)
>  {
>         struct {
>                 u64 words[2];
>         } *ptr1, *ptr2;
>
> -       pr_info("kmalloc out-of-bounds for 16-bytes access\n");
>         ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
>         ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
>         if (!ptr1 || !ptr2) {
> @@ -204,12 +196,11 @@ static noinline void __init kmalloc_oob_16(void)
>         kfree(ptr2);
>  }
>
> -static noinline void __init kmalloc_oob_memset_2(void)
> +static noinline void kmalloc_oob_memset_2(void)
>  {
>         char *ptr;
>         size_t size = 8;
>
> -       pr_info("out-of-bounds in memset2\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -220,12 +211,11 @@ static noinline void __init kmalloc_oob_memset_2(void)
>         kfree(ptr);
>  }
>
> -static noinline void __init kmalloc_oob_memset_4(void)
> +static noinline void kmalloc_oob_memset_4(void)
>  {
>         char *ptr;
>         size_t size = 8;
>
> -       pr_info("out-of-bounds in memset4\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -237,12 +227,11 @@ static noinline void __init kmalloc_oob_memset_4(void)
>  }
>
>
> -static noinline void __init kmalloc_oob_memset_8(void)
> +static noinline void kmalloc_oob_memset_8(void)
>  {
>         char *ptr;
>         size_t size = 8;
>
> -       pr_info("out-of-bounds in memset8\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -253,12 +242,11 @@ static noinline void __init kmalloc_oob_memset_8(void)
>         kfree(ptr);
>  }
>
> -static noinline void __init kmalloc_oob_memset_16(void)
> +static noinline void kmalloc_oob_memset_16(void)
>  {
>         char *ptr;
>         size_t size = 16;
>
> -       pr_info("out-of-bounds in memset16\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -269,12 +257,11 @@ static noinline void __init kmalloc_oob_memset_16(void)
>         kfree(ptr);
>  }
>
> -static noinline void __init kmalloc_oob_in_memset(void)
> +static noinline void kmalloc_oob_in_memset(void)
>  {
>         char *ptr;
>         size_t size = 666;
>
> -       pr_info("out-of-bounds in memset\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -285,12 +272,11 @@ static noinline void __init kmalloc_oob_in_memset(void)
>         kfree(ptr);
>  }
>
> -static noinline void __init kmalloc_uaf(void)
> +static noinline void kmalloc_uaf(void)
>  {
>         char *ptr;
>         size_t size = 10;
>
> -       pr_info("use-after-free\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -301,12 +287,11 @@ static noinline void __init kmalloc_uaf(void)
>         *(ptr + 8) = 'x';
>  }
>
> -static noinline void __init kmalloc_uaf_memset(void)
> +static noinline void kmalloc_uaf_memset(void)
>  {
>         char *ptr;
>         size_t size = 33;
>
> -       pr_info("use-after-free in memset\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -317,12 +302,11 @@ static noinline void __init kmalloc_uaf_memset(void)
>         memset(ptr, 0, size);
>  }
>
> -static noinline void __init kmalloc_uaf2(void)
> +static noinline void kmalloc_uaf2(void)
>  {
>         char *ptr1, *ptr2;
>         size_t size = 43;
>
> -       pr_info("use-after-free after another kmalloc\n");
>         ptr1 = kmalloc(size, GFP_KERNEL);
>         if (!ptr1) {
>                 pr_err("Allocation failed\n");
> @@ -342,14 +326,13 @@ static noinline void __init kmalloc_uaf2(void)
>         kfree(ptr2);
>  }
>
> -static noinline void __init kfree_via_page(void)
> +static noinline void kfree_via_page(void)
>  {
>         char *ptr;
>         size_t size = 8;
>         struct page *page;
>         unsigned long offset;
>
> -       pr_info("invalid-free false positive (via page)\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -361,13 +344,12 @@ static noinline void __init kfree_via_page(void)
>         kfree(page_address(page) + offset);
>  }
>
> -static noinline void __init kfree_via_phys(void)
> +static noinline void kfree_via_phys(void)
>  {
>         char *ptr;
>         size_t size = 8;
>         phys_addr_t phys;
>
> -       pr_info("invalid-free false positive (via phys)\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -378,7 +360,7 @@ static noinline void __init kfree_via_phys(void)
>         kfree(phys_to_virt(phys));
>  }
>
> -static noinline void __init kmem_cache_oob(void)
> +static noinline void kmem_cache_oob(void)
>  {
>         char *p;
>         size_t size = 200;
> @@ -389,7 +371,6 @@ static noinline void __init kmem_cache_oob(void)
>                 pr_err("Cache allocation failed\n");
>                 return;
>         }
> -       pr_info("out-of-bounds in kmem_cache_alloc\n");
>         p = kmem_cache_alloc(cache, GFP_KERNEL);
>         if (!p) {
>                 pr_err("Allocation failed\n");
> @@ -402,7 +383,7 @@ static noinline void __init kmem_cache_oob(void)
>         kmem_cache_destroy(cache);
>  }
>
> -static noinline void __init memcg_accounted_kmem_cache(void)
> +static noinline void memcg_accounted_kmem_cache(void)
>  {
>         int i;
>         char *p;
> @@ -415,7 +396,6 @@ static noinline void __init memcg_accounted_kmem_cache(void)
>                 return;
>         }
>
> -       pr_info("allocate memcg accounted object\n");
>         /*
>          * Several allocations with a delay to allow for lazy per memcg kmem
>          * cache creation.
> @@ -435,31 +415,19 @@ static noinline void __init memcg_accounted_kmem_cache(void)
>
>  static char global_array[10];
>
> -static noinline void __init kasan_global_oob(void)
> +static noinline void kasan_global_oob(void)
>  {
>         volatile int i = 3;
>         char *p = &global_array[ARRAY_SIZE(global_array) + i];
>
> -       pr_info("out-of-bounds global variable\n");
> -       *(volatile char *)p;
> -}
> -
> -static noinline void __init kasan_stack_oob(void)
> -{
> -       char stack_array[10];
> -       volatile int i = 0;
> -       char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
> -
> -       pr_info("out-of-bounds on stack\n");
>         *(volatile char *)p;
>  }
>
> -static noinline void __init ksize_unpoisons_memory(void)
> +static noinline void ksize_unpoisons_memory(void)
>  {
>         char *ptr;
>         size_t size = 123, real_size;
>
> -       pr_info("ksize() unpoisons the whole allocated chunk\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -473,72 +441,36 @@ static noinline void __init ksize_unpoisons_memory(void)
>         kfree(ptr);
>  }
>
> -static noinline void __init copy_user_test(void)
> +#if (CONFIG_KASAN_STACK == 1)
> +static noinline void kasan_stack_oob(void)
>  {
> -       char *kmem;
> -       char __user *usermem;
> -       size_t size = 10;
> -       int unused;
> -
> -       kmem = kmalloc(size, GFP_KERNEL);
> -       if (!kmem)
> -               return;
> -
> -       usermem = (char __user *)vm_mmap(NULL, 0, PAGE_SIZE,
> -                           PROT_READ | PROT_WRITE | PROT_EXEC,
> -                           MAP_ANONYMOUS | MAP_PRIVATE, 0);
> -       if (IS_ERR(usermem)) {
> -               pr_err("Failed to allocate user memory\n");
> -               kfree(kmem);
> -               return;
> -       }
> -
> -       pr_info("out-of-bounds in copy_from_user()\n");
> -       unused = copy_from_user(kmem, usermem, size + 1);
> -
> -       pr_info("out-of-bounds in copy_to_user()\n");
> -       unused = copy_to_user(usermem, kmem, size + 1);
> -
> -       pr_info("out-of-bounds in __copy_from_user()\n");
> -       unused = __copy_from_user(kmem, usermem, size + 1);
> -
> -       pr_info("out-of-bounds in __copy_to_user()\n");
> -       unused = __copy_to_user(usermem, kmem, size + 1);
> -
> -       pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> -       unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
> -
> -       pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> -       unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
> -
> -       pr_info("out-of-bounds in strncpy_from_user()\n");
> -       unused = strncpy_from_user(kmem, usermem, size + 1);
> +       char stack_array[10];
> +       volatile int i = 0;
> +       char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
>
> -       vm_munmap((unsigned long)usermem, PAGE_SIZE);
> -       kfree(kmem);
> +       *(volatile char *)p;
>  }
>
> -static noinline void __init kasan_alloca_oob_left(void)
> +static noinline void kasan_alloca_oob_left(void)
>  {
>         volatile int i = 10;
>         char alloca_array[i];
>         char *p = alloca_array - 1;
>
> -       pr_info("out-of-bounds to left on alloca\n");
>         *(volatile char *)p;
>  }
>
> -static noinline void __init kasan_alloca_oob_right(void)
> +static noinline void kasan_alloca_oob_right(void)
>  {
>         volatile int i = 10;
>         char alloca_array[i];
>         char *p = alloca_array + i;
>
> -       pr_info("out-of-bounds to right on alloca\n");
>         *(volatile char *)p;
>  }
> +#endif /* CONFIG_KASAN_STACK */
>
> -static noinline void __init kmem_cache_double_free(void)
> +static noinline void kmem_cache_double_free(void)
>  {
>         char *p;
>         size_t size = 200;
> @@ -549,7 +481,6 @@ static noinline void __init kmem_cache_double_free(void)
>                 pr_err("Cache allocation failed\n");
>                 return;
>         }
> -       pr_info("double-free on heap object\n");
>         p = kmem_cache_alloc(cache, GFP_KERNEL);
>         if (!p) {
>                 pr_err("Allocation failed\n");
> @@ -562,7 +493,7 @@ static noinline void __init kmem_cache_double_free(void)
>         kmem_cache_destroy(cache);
>  }
>
> -static noinline void __init kmem_cache_invalid_free(void)
> +static noinline void kmem_cache_invalid_free(void)
>  {
>         char *p;
>         size_t size = 200;
> @@ -574,7 +505,6 @@ static noinline void __init kmem_cache_invalid_free(void)
>                 pr_err("Cache allocation failed\n");
>                 return;
>         }
> -       pr_info("invalid-free of heap object\n");
>         p = kmem_cache_alloc(cache, GFP_KERNEL);
>         if (!p) {
>                 pr_err("Allocation failed\n");
> @@ -594,12 +524,11 @@ static noinline void __init kmem_cache_invalid_free(void)
>         kmem_cache_destroy(cache);
>  }
>
> -static noinline void __init kasan_memchr(void)
> +static noinline void kasan_memchr(void)
>  {
>         char *ptr;
>         size_t size = 24;
>
> -       pr_info("out-of-bounds in memchr\n");
>         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
>         if (!ptr)
>                 return;
> @@ -608,13 +537,12 @@ static noinline void __init kasan_memchr(void)
>         kfree(ptr);
>  }
>
> -static noinline void __init kasan_memcmp(void)
> +static noinline void kasan_memcmp(void)
>  {
>         char *ptr;
>         size_t size = 24;
>         int arr[9];
>
> -       pr_info("out-of-bounds in memcmp\n");
>         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
>         if (!ptr)
>                 return;
> @@ -624,12 +552,11 @@ static noinline void __init kasan_memcmp(void)
>         kfree(ptr);
>  }
>
> -static noinline void __init kasan_strings(void)
> +static noinline void kasan_strings(void)
>  {
>         char *ptr;
>         size_t size = 24;
>
> -       pr_info("use-after-free in strchr\n");
>         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
>         if (!ptr)
>                 return;
> @@ -645,23 +572,18 @@ static noinline void __init kasan_strings(void)
>         ptr += 16;
>         strchr(ptr, '1');
>
> -       pr_info("use-after-free in strrchr\n");
>         strrchr(ptr, '1');
>
> -       pr_info("use-after-free in strcmp\n");
>         strcmp(ptr, "2");
>
> -       pr_info("use-after-free in strncmp\n");
>         strncmp(ptr, "2", 1);
>
> -       pr_info("use-after-free in strlen\n");
>         strlen(ptr);
>
> -       pr_info("use-after-free in strnlen\n");
>         strnlen(ptr, 1);
>  }
>
> -static noinline void __init kasan_bitops(void)
> +static noinline void kasan_bitops(void)
>  {
>         /*
>          * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
> @@ -676,70 +598,52 @@ static noinline void __init kasan_bitops(void)
>          * below accesses are still out-of-bounds, since bitops are defined to
>          * operate on the whole long the bit is in.
>          */
> -       pr_info("out-of-bounds in set_bit\n");
>         set_bit(BITS_PER_LONG, bits);
>
> -       pr_info("out-of-bounds in __set_bit\n");
>         __set_bit(BITS_PER_LONG, bits);
>
> -       pr_info("out-of-bounds in clear_bit\n");
>         clear_bit(BITS_PER_LONG, bits);
>
> -       pr_info("out-of-bounds in __clear_bit\n");
>         __clear_bit(BITS_PER_LONG, bits);
>
> -       pr_info("out-of-bounds in clear_bit_unlock\n");
>         clear_bit_unlock(BITS_PER_LONG, bits);
>
> -       pr_info("out-of-bounds in __clear_bit_unlock\n");
>         __clear_bit_unlock(BITS_PER_LONG, bits);
>
> -       pr_info("out-of-bounds in change_bit\n");
>         change_bit(BITS_PER_LONG, bits);
>
> -       pr_info("out-of-bounds in __change_bit\n");
>         __change_bit(BITS_PER_LONG, bits);
>
>         /*
>          * Below calls try to access bit beyond allocated memory.
>          */
> -       pr_info("out-of-bounds in test_and_set_bit\n");
>         test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
>
> -       pr_info("out-of-bounds in __test_and_set_bit\n");
>         __test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
>
> -       pr_info("out-of-bounds in test_and_set_bit_lock\n");
>         test_and_set_bit_lock(BITS_PER_LONG + BITS_PER_BYTE, bits);
>
> -       pr_info("out-of-bounds in test_and_clear_bit\n");
>         test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
>
> -       pr_info("out-of-bounds in __test_and_clear_bit\n");
>         __test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
>
> -       pr_info("out-of-bounds in test_and_change_bit\n");
>         test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
>
> -       pr_info("out-of-bounds in __test_and_change_bit\n");
>         __test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
>
> -       pr_info("out-of-bounds in test_bit\n");
>         (void)test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
>
>  #if defined(clear_bit_unlock_is_negative_byte)
> -       pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
>         clear_bit_unlock_is_negative_byte(BITS_PER_LONG + BITS_PER_BYTE, bits);
>  #endif
>         kfree(bits);
>  }
>
> -static noinline void __init kmalloc_double_kzfree(void)
> +static noinline void kmalloc_double_kzfree(void)
>  {
>         char *ptr;
>         size_t size = 16;
>
> -       pr_info("double-free (kzfree)\n");
>         ptr = kmalloc(size, GFP_KERNEL);
>         if (!ptr) {
>                 pr_err("Allocation failed\n");
> @@ -750,29 +654,130 @@ static noinline void __init kmalloc_double_kzfree(void)
>         kzfree(ptr);
>  }
>
> -#ifdef CONFIG_KASAN_VMALLOC
> -static noinline void __init vmalloc_oob(void)
> +static void kunit_test_oob(struct kunit *test)
> +{
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_right());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_left());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_node_oob_right());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_large_oob_right());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_krealloc_more());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_krealloc_less());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_16());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_in_memset());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_memset_2());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_memset_4());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_memset_8());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_memset_16());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_oob());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_global_oob());
> +       KUNIT_EXPECT_KASAN_FAIL(test, ksize_unpoisons_memory());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_memchr());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_memcmp());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_strings());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_bitops());
> +#ifdef CONFIG_SLUB
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_pagealloc_oob_right());
> +#endif /* CONFIG_SLUB */
> +
> +#if (CONFIG_KASAN_STACK == 1)
> +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_stack_oob());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_alloca_oob_right());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_alloca_oob_left());
> +#endif /*CONFIG_KASAN_STACK*/
> +}
> +
> +static void kunit_test_uaf(struct kunit *test)
> +{
> +#ifdef CONFIG_SLUB
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_pagealloc_uaf());
> +#endif
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_uaf());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_uaf_memset());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_uaf2());
> +}
> +
> +static void kunit_test_invalid_free(struct kunit *test)
>  {
> -       void *area;
> +#ifdef CONFIG_SLUB
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_pagealloc_invalid_free());
> +#endif
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_invalid_free());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_double_free());
> +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_double_kzfree());
> +}
>
> -       pr_info("vmalloc out-of-bounds\n");
> +static void kunit_test_false_positives(struct kunit *test)
> +{
> +       kfree_via_page();
> +       kfree_via_phys();
> +}
>
> -       /*
> -        * We have to be careful not to hit the guard page.
> -        * The MMU will catch that and crash us.
> -        */
> -       area = vmalloc(3000);
> -       if (!area) {
> -               pr_err("Allocation failed\n");
> +static void kunit_test_memcg(struct kunit *test)
> +{
> +       memcg_accounted_kmem_cache();
> +}
> +
> +static struct kunit_case kasan_kunit_test_cases[] = {
> +       KUNIT_CASE(kunit_test_oob),
> +       KUNIT_CASE(kunit_test_uaf),
> +       KUNIT_CASE(kunit_test_invalid_free),
> +       KUNIT_CASE(kunit_test_false_positives),
> +       KUNIT_CASE(kunit_test_memcg),
> +       {}
> +};
> +
> +static struct kunit_suite kasan_kunit_test_suite = {
> +       .name = "kasan_kunit_test",
> +       .test_cases = kasan_kunit_test_cases,
> +};
> +
> +kunit_test_suite(kasan_kunit_test_suite);
> +
> +#if IS_MODULE(CONFIG_TEST_KASAN)
> +static noinline void __init copy_user_test(void)
> +{
> +       char *kmem;
> +       char __user *usermem;
> +       size_t size = 10;
> +       int unused;
> +
> +       kmem = kmalloc(size, GFP_KERNEL);
> +       if (!kmem)
> +               return;
> +
> +       usermem = (char __user *)vm_mmap(NULL, 0, PAGE_SIZE,
> +                           PROT_READ | PROT_WRITE | PROT_EXEC,
> +                           MAP_ANONYMOUS | MAP_PRIVATE, 0);
> +       if (IS_ERR(usermem)) {
> +               pr_err("Failed to allocate user memory\n");
> +               kfree(kmem);
>                 return;
>         }
>
> -       ((volatile char *)area)[3100];
> -       vfree(area);
> +       pr_info("out-of-bounds in copy_from_user()\n");
> +       unused = copy_from_user(kmem, usermem, size + 1);
> +
> +       pr_info("out-of-bounds in copy_to_user()\n");
> +       unused = copy_to_user(usermem, kmem, size + 1);
> +
> +       pr_info("out-of-bounds in __copy_from_user()\n");
> +       unused = __copy_from_user(kmem, usermem, size + 1);
> +
> +       pr_info("out-of-bounds in __copy_to_user()\n");
> +       unused = __copy_to_user(usermem, kmem, size + 1);
> +
> +       pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> +       unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
> +
> +       pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> +       unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
> +
> +       pr_info("out-of-bounds in strncpy_from_user()\n");
> +       unused = strncpy_from_user(kmem, usermem, size + 1);
> +
> +       vm_munmap((unsigned long)usermem, PAGE_SIZE);
> +       kfree(kmem);
>  }
> -#else
> -static void __init vmalloc_oob(void) {}
> -#endif
>
>  static int __init kmalloc_tests_init(void)
>  {
> @@ -782,44 +787,7 @@ static int __init kmalloc_tests_init(void)
>          */
>         bool multishot = kasan_save_enable_multi_shot();
>
> -       kmalloc_oob_right();
> -       kmalloc_oob_left();
> -       kmalloc_node_oob_right();
> -#ifdef CONFIG_SLUB
> -       kmalloc_pagealloc_oob_right();
> -       kmalloc_pagealloc_uaf();
> -       kmalloc_pagealloc_invalid_free();
> -#endif
> -       kmalloc_large_oob_right();
> -       kmalloc_oob_krealloc_more();
> -       kmalloc_oob_krealloc_less();
> -       kmalloc_oob_16();
> -       kmalloc_oob_in_memset();
> -       kmalloc_oob_memset_2();
> -       kmalloc_oob_memset_4();
> -       kmalloc_oob_memset_8();
> -       kmalloc_oob_memset_16();
> -       kmalloc_uaf();
> -       kmalloc_uaf_memset();
> -       kmalloc_uaf2();
> -       kfree_via_page();
> -       kfree_via_phys();
> -       kmem_cache_oob();
> -       memcg_accounted_kmem_cache();
> -       kasan_stack_oob();
> -       kasan_global_oob();
> -       kasan_alloca_oob_left();
> -       kasan_alloca_oob_right();
> -       ksize_unpoisons_memory();
>         copy_user_test();
> -       kmem_cache_double_free();
> -       kmem_cache_invalid_free();
> -       kasan_memchr();
> -       kasan_memcmp();
> -       kasan_strings();
> -       kasan_bitops();
> -       kmalloc_double_kzfree();
> -       vmalloc_oob();
>
>         kasan_restore_multi_shot(multishot);
>
> @@ -827,4 +795,4 @@ static int __init kmalloc_tests_init(void)
>  }
>
>  module_init(kmalloc_tests_init);
> -MODULE_LICENSE("GPL");
> +#endif /* IS_MODULE(CONFIG_TEST_KASAN) */
> --
> 2.25.0.265.gbab2e86ba0-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227024301.217042-1-trishalfonso%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByA1ibD2yYT%2B%2B%3D%3Dpc5PLKfisFv3ieru54PDDYF4EE_Hfg%40mail.gmail.com.
