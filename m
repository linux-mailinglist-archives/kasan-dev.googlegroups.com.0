Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDP2U76AKGQEDFEZVIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 52863290C95
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 22:05:34 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id v4sf1203045vkn.4
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 13:05:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602878733; cv=pass;
        d=google.com; s=arc-20160816;
        b=af6QSN54JTky0MIDxL+zWlh/fLmhm9cdYzpyfMl3NBOFv6iV4VCpMKNyPIaTMi5fp0
         /PHfV+SCkGk2B9XaCgJdTpQCXzroweff6vMj2pHtego6dOKDIBYeXX8FH43wPNsaYo3t
         ZITHsiJbWyu/tlAP7UB4KKsv/KJm/0Ky2HXadhW3yItnc/NJS0c9ZQs9MPQNvFFnkvgh
         Ey09nDSye/ype27mwGzmPiIiXpOuQ6zq2xD1x+8dd3BKOVhWTO7teafzLUXk9aVLpshk
         lEGneML/oZzqs4XbnD1JhH9xzyTnDVFTusoHkgWF2kbuQ0R1pOHibs9dK4vGtvaj/QLM
         Xt+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zYRzT4wEIhi1pLQdIX7qzQSWmlysbgTnZafVKR7ZKBE=;
        b=yAVj+BqEIrLsIq0FuIqREA/lJrBbjEfq0cTKQAR96Tg7tCdF7+DtSvuQGk4rYE0xvi
         5stlQHmzV/TqwLpz2Fa2My1ONKkSne1i+P/u8sVenanKYcOWek8o97zhWUw4K2349jdT
         zAV2O87uP1wVSYtIlDBqHO5XYDGFGyYQpOdVB6YeCvlnwpwkJJkd/EBrhDokPf4qC4Qu
         50VtrFOs4SImn0Sa0tbjaxlVrgP9usQC2emmx/n7W7fB0yMBg+1WJF+QDOIsrZikUwol
         em66Tbs0mmlzyCOKHeirdu3a409oW6lzSe6LDXxZ4f9UahKAmlUGN5fpMeh47y0LuaUc
         A+ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t1Dv5NTl;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zYRzT4wEIhi1pLQdIX7qzQSWmlysbgTnZafVKR7ZKBE=;
        b=peu1buxG0Ik2IVf5g1OmGuuyLfualxKyEOQnVm6BA3WPbfhf1yQFi1mByNNjIZO1hZ
         aLftDELvge/a4UHYc7DGznf1vhJhyOT/m6cyv/+4s1haIhWmfpOL1r6h/xSpw0PZ3LIN
         Pf2HhIRKCwusHH+NYbT+yaA3aM8FqJAvJ0eA5iilxT342dKRgQ9vrlOZxeFQ3zg9IVaf
         KBAnS9Td9fFdOarYl1cAUJOz8588KoU53U7scngZN0Uq1+bYs06SbhxoabJA4pcBJv5D
         kmMMBEoWkhQtzET+1zwzUSPNc+d3PCAUj4K2tj/cU5FKZBA9Xr8O/BiEGI+YrzQpSBVC
         vKBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zYRzT4wEIhi1pLQdIX7qzQSWmlysbgTnZafVKR7ZKBE=;
        b=jDr8DcsmAxV4wDDv6HHIXfBfHUFzoL2XEDomxXpHD6ozyxGZJnF2u21F2Ojas5/8wK
         u9IoSr2KsW4oERS6YXGg8PYikhZaTiRk+2Cc/5EkoYXYWedBlWHvVB06y2/CgUYKNv93
         gwvhrbk3reK49UGrkmafX1AN4/AxlQUyq542kQ4zysYz8rIJYO8yU/frLs9cAIZ29Rj+
         P5UwZLhp5eOJhG97S1kJRSaXrtqc1ysHlQ2hp/scH2mRvbieUXXWdHcCWMXKFKLUKhq5
         Ej+kwp2YNJ0bZyABzIPpPv9xUt2htXCJNrPjWYK4w5rK8fmz5sGk59V9OwWAejSqYhB7
         t7Cw==
X-Gm-Message-State: AOAM530togwLoqwSURd1D8RDt2U7l4HzeM2EeXznq+lhLBTFS05RnmU0
	YjC2oJwkxGeiDS981IutDzk=
X-Google-Smtp-Source: ABdhPJyhJB5w5J/h3Ij/bfVZ2ekwyRBMBaYErm4oG5HkcK3HGR+C0+Xe9fPkvnkOOBPJv1MWwd0Edg==
X-Received: by 2002:ab0:69c5:: with SMTP id u5mr3149020uaq.45.1602878733168;
        Fri, 16 Oct 2020 13:05:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:24d7:: with SMTP id k23ls282754uan.5.gmail; Fri, 16 Oct
 2020 13:05:32 -0700 (PDT)
X-Received: by 2002:ab0:6059:: with SMTP id o25mr3082157ual.61.1602878732706;
        Fri, 16 Oct 2020 13:05:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602878732; cv=none;
        d=google.com; s=arc-20160816;
        b=F9DP6HaB5+y6ikQyJftkZODe6ZMCYTph3gWlP9SVjWhLi5tkT+ZPP7xSDClphCFxo9
         sUU1MZt7QZhO0Vy9B9CCQrB+25Q4EQoWxCgPrwrIpxG4+UIdye2D6af4LTW8NpKgk98Q
         aRIX3k715QuMwk9af1ivgsRwQikj8OJ3Bx1Qo9+dGdF96ZbRuwPaqAQ49Ai7fXshr6s0
         UGBkggWNma+rYXuGIChqTloIFG7WMvNky6w9AbzTG3cVHQEBuIgqjEvKF5qFyn1LFnOu
         tFAEVCxejiB1fvx3n5DGW9+x+CV7VK7N5+f9P6yhAae5W6FYrFL23tZOsvSZwpUK82wf
         pWEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JlmEeUtoxILUOsMKYCpMQdn4yPK9pTLKCLX4Si8MjAU=;
        b=qmGB7OVU+035FPdgLw9bp8Ea0JWmYrVJYt8w19/Kgmz7EA5weSUiARacf3XnoR9YN+
         x/fXiXqB99rNLtNfeziKcjYtxku9CxhlQRk6kMm1VN4vhBNNTmMAbK8DfX2SUzt0M4T5
         bIjAZH0+zkVbkwrkSSHkIA2HbkLn6G66TwRI9QiaafUI6CJTywrLplWT0EUdUeyagXk0
         Xi6Iqb/2TlVkD1m+2oraid69XNvZr+Zy3pCtwvJCJhCN5iGp9M2RWXnMVwdJjGJTYaCz
         KoJc481xNUeuSbFgnsMKaSnYP385qKFOp9Rqp4Vxwwmx0s3/uwhrwKn15jXjr9pJmm8t
         Emaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t1Dv5NTl;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id r131si187310vkd.0.2020.10.16.13.05.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Oct 2020 13:05:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id e10so2125028pfj.1
        for <kasan-dev@googlegroups.com>; Fri, 16 Oct 2020 13:05:32 -0700 (PDT)
X-Received: by 2002:a63:8c42:: with SMTP id q2mr4523721pgn.130.1602878731581;
 Fri, 16 Oct 2020 13:05:31 -0700 (PDT)
MIME-Version: 1.0
References: <44861eaca17ffbb51726473bc8e86ad9e130c67e.1602876780.git.andreyknvl@google.com>
In-Reply-To: <44861eaca17ffbb51726473bc8e86ad9e130c67e.1602876780.git.andreyknvl@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Oct 2020 22:05:20 +0200
Message-ID: <CAAeHK+y=6cGn9OUd7wgB_RZyBDkZSpSBvyf8_c+V_ESz=hA7qw@mail.gmail.com>
Subject: Re: [PATCH] kasan: adopt KUNIT tests to SW_TAGS mode
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, David Gow <davidgow@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=t1Dv5NTl;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
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

On Fri, Oct 16, 2020 at 9:33 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Now that we have KASAN-KUNIT tests integration, it's easy to see that
> some KASAN tests are not adopted to the SW_TAGS mode and are failing.
>
> Adjust the allocation size for kasan_memchr() and kasan_memcmp() by
> roung it up to OOB_TAG_OFF so the bad access ends up in a separate
> memory granule.
>
> Add new kmalloc_uaf_16() and kasan_bitops_uaf() tests that rely on UAFs,
> as it's hard to adopt the existing kmalloc_oob_16() and kasan_bitops_oob()
> (rename from kasan_bitops()) without losing the precision.
>
> Disable kasan_global_oob() and kasan_alloca_oob_left/right() as SW_TAGS
> mode doesn't instrument globals nor dynamic allocas.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  lib/test_kasan.c | 144 ++++++++++++++++++++++++++++++++---------------
>  1 file changed, 99 insertions(+), 45 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 63c26171a791..3bff25a7fdcc 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -216,6 +216,12 @@ static void kmalloc_oob_16(struct kunit *test)
>                 u64 words[2];
>         } *ptr1, *ptr2;
>
> +       /* This test is specifically crafted for the generic mode. */
> +       if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +               kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
> +               return;
> +       }
> +
>         ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
>
> @@ -227,6 +233,23 @@ static void kmalloc_oob_16(struct kunit *test)
>         kfree(ptr2);
>  }
>
> +static void kmalloc_uaf_16(struct kunit *test)
> +{
> +       struct {
> +               u64 words[2];
> +       } *ptr1, *ptr2;
> +
> +       ptr1 = kmalloc(sizeof(*ptr1), GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
> +
> +       ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
> +       kfree(ptr2);
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
> +       kfree(ptr1);
> +}
> +
>  static void kmalloc_oob_memset_2(struct kunit *test)
>  {
>         char *ptr;
> @@ -429,6 +452,12 @@ static void kasan_global_oob(struct kunit *test)
>         volatile int i = 3;
>         char *p = &global_array[ARRAY_SIZE(global_array) + i];
>
> +       /* Only generic mode instruments globals. */
> +       if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +               kunit_info(test, "CONFIG_KASAN_GENERIC required");
> +               return;
> +       }
> +
>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>  }
>
> @@ -467,6 +496,12 @@ static void kasan_alloca_oob_left(struct kunit *test)
>         char alloca_array[i];
>         char *p = alloca_array - 1;
>
> +       /* Only generic mode instruments dynamic allocas. */
> +       if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +               kunit_info(test, "CONFIG_KASAN_GENERIC required");
> +               return;
> +       }
> +
>         if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
>                 kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
>                 return;
> @@ -481,6 +516,12 @@ static void kasan_alloca_oob_right(struct kunit *test)
>         char alloca_array[i];
>         char *p = alloca_array + i;
>
> +       /* Only generic mode instruments dynamic allocas. */
> +       if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +               kunit_info(test, "CONFIG_KASAN_GENERIC required");
> +               return;
> +       }
> +
>         if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
>                 kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
>                 return;
> @@ -551,6 +592,9 @@ static void kasan_memchr(struct kunit *test)
>                 return;
>         }
>
> +       if (OOB_TAG_OFF)
> +               size = round_up(size, OOB_TAG_OFF);
> +
>         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> @@ -573,6 +617,9 @@ static void kasan_memcmp(struct kunit *test)
>                 return;
>         }
>
> +       if (OOB_TAG_OFF)
> +               size = round_up(size, OOB_TAG_OFF);
> +
>         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         memset(arr, 0, sizeof(arr));
> @@ -619,13 +666,50 @@ static void kasan_strings(struct kunit *test)
>         KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strnlen(ptr, 1));
>  }
>
> -static void kasan_bitops(struct kunit *test)
> +static void kasan_bitops_modify(struct kunit *test, int nr, void *addr)
> +{
> +       KUNIT_EXPECT_KASAN_FAIL(test, set_bit(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, __set_bit(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, clear_bit(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, clear_bit_unlock(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit_unlock(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, change_bit(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, __change_bit(nr, addr));
> +}
> +
> +static void kasan_bitops_test_and_modify(struct kunit *test, int nr, void *addr)
>  {
> +       KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, __test_and_set_bit(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, test_and_clear_bit(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, __test_and_clear_bit(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, test_and_change_bit(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, __test_and_change_bit(nr, addr));
> +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = test_bit(nr, addr));
> +
> +#if defined(clear_bit_unlock_is_negative_byte)
> +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =
> +                               clear_bit_unlock_is_negative_byte(nr, addr));
> +#endif
> +}
> +
> +static void kasan_bitops_oob(struct kunit *test)
> +{
> +       long *bits;
> +
> +       /* This test is specifically crafted for the generic mode. */
> +       if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +               kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
> +               return;
> +       }
> +
>         /*
>          * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
>          * this way we do not actually corrupt other memory.
>          */
> -       long *bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
> +       bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, bits);
>
>         /*
> @@ -633,56 +717,24 @@ static void kasan_bitops(struct kunit *test)
>          * below accesses are still out-of-bounds, since bitops are defined to
>          * operate on the whole long the bit is in.
>          */
> -       KUNIT_EXPECT_KASAN_FAIL(test, set_bit(BITS_PER_LONG, bits));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test, __set_bit(BITS_PER_LONG, bits));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test, clear_bit(BITS_PER_LONG, bits));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit(BITS_PER_LONG, bits));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test, clear_bit_unlock(BITS_PER_LONG, bits));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit_unlock(BITS_PER_LONG, bits));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test, change_bit(BITS_PER_LONG, bits));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test, __change_bit(BITS_PER_LONG, bits));
> +       kasan_bitops_modify(test, BITS_PER_LONG, bits);
>
>         /*
>          * Below calls try to access bit beyond allocated memory.
>          */
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               __test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> +       kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, bits);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               test_and_set_bit_lock(BITS_PER_LONG + BITS_PER_BYTE, bits));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               __test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               __test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> +       kfree(bits);
> +}
>
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               kasan_int_result =
> -                       test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> +static void kasan_bitops_uaf(struct kunit *test)
> +{
> +       long *bits = kzalloc(sizeof(*bits), GFP_KERNEL);
>
> -#if defined(clear_bit_unlock_is_negative_byte)
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               kasan_int_result = clear_bit_unlock_is_negative_byte(
> -                       BITS_PER_LONG + BITS_PER_BYTE, bits));
> -#endif
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, bits);
>         kfree(bits);
> +       kasan_bitops_modify(test, BITS_PER_LONG, bits);
> +       kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, bits);
>  }

This actually ends up modifying the data in a freed object, which
isn't a good idea. I'll change this to do an OOB too, but for the
tag-based mode.

>
>  static void kmalloc_double_kzfree(struct kunit *test)
> @@ -728,6 +780,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(kmalloc_oob_krealloc_more),
>         KUNIT_CASE(kmalloc_oob_krealloc_less),
>         KUNIT_CASE(kmalloc_oob_16),
> +       KUNIT_CASE(kmalloc_uaf_16),
>         KUNIT_CASE(kmalloc_oob_in_memset),
>         KUNIT_CASE(kmalloc_oob_memset_2),
>         KUNIT_CASE(kmalloc_oob_memset_4),
> @@ -751,7 +804,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(kasan_memchr),
>         KUNIT_CASE(kasan_memcmp),
>         KUNIT_CASE(kasan_strings),
> -       KUNIT_CASE(kasan_bitops),
> +       KUNIT_CASE(kasan_bitops_oob),
> +       KUNIT_CASE(kasan_bitops_uaf),
>         KUNIT_CASE(kmalloc_double_kzfree),
>         KUNIT_CASE(vmalloc_oob),
>         {}
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By%3D6cGn9OUd7wgB_RZyBDkZSpSBvyf8_c%2BV_ESz%3DhA7qw%40mail.gmail.com.
