Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU5SQ2KQMGQEFPWRRIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B52354444C
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 08:55:17 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id o16-20020a170902d4d000b00166d7813226sf9552323plg.13
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jun 2022 23:55:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654757715; cv=pass;
        d=google.com; s=arc-20160816;
        b=C2F1EVlcX8/g2xEEb75BJOLPs2S6b3dZLpxFKKCFMpuy8XK0dj6vJNGzwLk+0UlREw
         xtwVymaV6NZQma49Svh8BJNkC0d/dtNLQ8gVGHZL3SBrfLKpU+LuDFzIcom6deHuN6H6
         Zy+FQUDPmxdUEN9neynEt5YQLazhPVLwmCI2AMA86cWZGDP0syY7ZZi/72JZ00FKq25p
         RXtGEUGeFeR9sxjlR/EUljZ19rcj9My3mUd0Hy9RAERLe2X1EQiKavFRvgM8kfgXohPc
         W6RQ4W8I+Gy1fq59+rGLatanXMZL9Sj7DnRAYGPHuaL4EOkAZ4Ymu2q+tv+fusx3gN3a
         WwcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2w4hvpDUc49e9FgV7jHZrKSQffqoN8HEpG22QqfHHGA=;
        b=JHfgFSHyMHpbVswPQ04SJE3QHLzMDE/TDOOILcdN50mPuvkwQlnQPtKy5ZVdMMiF4X
         bLHioNCRFEsnIA6sz19er5AfW2DVPBSbFhCm27CiNVCd8SOI7BryfdnoO0gE4F2rdTIh
         sFhlcDNBIgDDdybKhSfvIep9EyUnH8cJe/+qWPCKXJvtcbPaKAoFILFdYIDtNFemE1fg
         ivkvscEHfYx21WQFGbUHIbmN7zf+IvG4E/CfHGhXzE2QVMrwJ1W8oZUhrgK6kOrOY63O
         EohbeB/TVTjtLu0/kK552KF8cL/8dp9RwmCgkQAGsV12QPDdojcOJdhkx7m51dmIpJfe
         BkSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rbSfirct;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2w4hvpDUc49e9FgV7jHZrKSQffqoN8HEpG22QqfHHGA=;
        b=Qw2peybeIJzeRaa+SRTM9U3AiH3d9YypbZcioPk9Y840tXOUSkOx33ZBwKjfntZ83q
         BzGkeAXTfkrvHQCGMiTp8Cyb6FX0BqnTHvw+5ecq5uuIrgqS9QZ6djFUYHYhWP7slM1s
         kFWz9gKjA916SwbGxR6l/35+2oWEhrWxfUv8pApHSMbGuMEYet8Bww47qIRZ0dyATBwk
         vqOK6U/O5S68NJb4++CSyVh8/iiAqvv+uzxnkPVcvB23uzOd0TibXw4pjkIiA0wtdqIc
         XZRhkAu+ljW0igPfUSsqMIVp9hyH1PK2yaQyQz50ZqmrMhH+lX4B5ejUaMCaKW7EoggN
         mMPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2w4hvpDUc49e9FgV7jHZrKSQffqoN8HEpG22QqfHHGA=;
        b=kUW0LttxdnmGqzYAsIitAqaMi7OFN9uPgEj2hreRKJoUZHwypCKUJRELqlzcCpVFcA
         rjXDYjUvbqCq6BDqnu/75CFvN9dIeu0AjkBMe3vaSD7E/8N/TS4JHmcdMP4j+O08n0k1
         MmvVqSS/Dp4tHn0a/MOnIn8JgpM6cMSxtzjKTojxUEAovdYHmW4TKMJS+ftKUl5L3v/b
         EE9IQAKDc5Hh5US7E53tLyt14BiNeloWfqotTPqSW6gd7BtveNFL2Cn8w30o0zuQiqSa
         MmZFmhmeaJ+LbH6Te6mtLxnIXYPbjBz972KyFH/10c6y9WOwFVzqboOVk4/wRW2BBUPJ
         63mQ==
X-Gm-Message-State: AOAM532cDM33MRU8T5ycxZUrgJj0yWgXCjMkVjKgfImUISSaQy+EtM2j
	ns4Bk3l2RLIaXPjDZPXS7uw=
X-Google-Smtp-Source: ABdhPJyT0BwO92GnMBl+6ZgLP93trfASHG5sbiPpmPumCMJVj9sv6fQ4PbFlI4IxdEIH0s65DbdDUw==
X-Received: by 2002:a17:902:db0f:b0:164:597:3382 with SMTP id m15-20020a170902db0f00b0016405973382mr38035079plx.76.1654757715580;
        Wed, 08 Jun 2022 23:55:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:da84:b0:166:32e1:3703 with SMTP id
 j4-20020a170902da8400b0016632e13703ls12663214plx.4.gmail; Wed, 08 Jun 2022
 23:55:14 -0700 (PDT)
X-Received: by 2002:a17:902:d48d:b0:167:53e2:3dc5 with SMTP id c13-20020a170902d48d00b0016753e23dc5mr28595692plg.105.1654757714806;
        Wed, 08 Jun 2022 23:55:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654757714; cv=none;
        d=google.com; s=arc-20160816;
        b=eWDtFohhdOemYKSw19atB6+GbN/4kuFzfOedHiEkDlreQs1phTLYwEz88NKJxE8Fdm
         vr9dZlauy6E/s9WD4RQLMDUZUWRzRtJguBPtwpRMctUJKBqCGoS335ugN+IYmZYKfnlV
         oyZbbdteRuqyKzLf+ar0NPHZau3o6XI0a3A7tdiRX28OD8V0adYajP5ysUU1v6IMQurU
         qkE3L1iCjTzm95/33X9C9dwQxARCLYu8apmTK1i2LfJ4LmlBOK1Xw6lQJbs3FqXN6X3+
         YA96ENcLLMMSSW+6NUvyr3GyY5ACHgBT3icobTiy2wQvWwrg3YAtP/GZ/MPRAgY/Vxjw
         Agvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Hzn4RqA/oVkoeaB2GIBLmXQFW/1IHl+Sw+drpCifoBo=;
        b=tzuAQXLRH8Lw8ldZ0aQSPfi0wftTeuGTgvvw7h7LzcF/ndS7N9fJAomnubk3RO9+VD
         LwqZ8Tx3AIl4XCqHVznltRwJixz2BEcmHtcMrbmjG8t2SllO6B1CXWtTWLJ2D20564os
         3gOdPaF38xgJer9XpI/3qOvWKtt9FE1+0R2mC18saSlKzykZ4KNKU/bdlife/qoT4DGq
         uD5fm0WYvfRocvZGmcQ8BqJPL65quL33lv/yUY7r1oSxJsWJmU9lhKUODcT7C/+K0b4T
         FglMsThuWyITKZdTJEtOtWZ7EgXfTwC0ZTExStIf3qP+KtoGUjJeY/4mfWgNpzf2Usd3
         Rt4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rbSfirct;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id b17-20020a656691000000b003fc882fe683si1008073pgw.2.2022.06.08.23.55.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Jun 2022 23:55:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id r3so6068804ybr.6
        for <kasan-dev@googlegroups.com>; Wed, 08 Jun 2022 23:55:14 -0700 (PDT)
X-Received: by 2002:a25:b686:0:b0:664:2b6:8e13 with SMTP id
 s6-20020a25b686000000b0066402b68e13mr6435489ybj.533.1654757714276; Wed, 08
 Jun 2022 23:55:14 -0700 (PDT)
MIME-Version: 1.0
References: <20220608214024.1068451-1-keescook@chromium.org>
In-Reply-To: <20220608214024.1068451-1-keescook@chromium.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 08:54:37 +0200
Message-ID: <CANpmjNPNM4pB0H2X9iR6F3LeOBsbzj7+eE7fAUEy0Rp8db77XQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: test: Silence GCC 12 warnings
To: Kees Cook <keescook@chromium.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rbSfirct;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as
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

On Wed, 8 Jun 2022 at 23:40, Kees Cook <keescook@chromium.org> wrote:
>
> GCC 12 continues to get smarter about array accesses. The KASAN tests
> are expecting to explicitly test out-of-bounds conditions at run-time,
> so hide the variable from GCC, to avoid warnings like:
>
> ../lib/test_kasan.c: In function 'ksize_uaf':
> ../lib/test_kasan.c:790:61: warning: array subscript 120 is outside array bounds of 'void[120]' [-Warray-bounds]

Since this keeps happening, I wonder if we could just pass
'-Wno-array-bounds' ? We already have 'CFLAGS_test_kasan.o += $(call
cc-disable-warning, vla)'.

Although eventually I'd assume all the OPTIMIZE_HIDE_VAR() should be
in place, and hopefully it'll have been the last one. I leave it to
you.

>   790 |         KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
>       |                                       ~~~~~~~~~~~~~~~~~~~~~~^~~~~~
> ../lib/test_kasan.c:97:9: note: in definition of macro 'KUNIT_EXPECT_KASAN_FAIL'
>    97 |         expression; \
>       |         ^~~~~~~~~~
>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  lib/test_kasan.c | 10 ++++++++++
>  1 file changed, 10 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index c233b1a4e984..58c1b01ccfe2 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -131,6 +131,7 @@ static void kmalloc_oob_right(struct kunit *test)
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         /*
>          * An unaligned access past the requested kmalloc size.
>          * Only generic KASAN can precisely detect these.
> @@ -159,6 +160,7 @@ static void kmalloc_oob_left(struct kunit *test)
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
>         kfree(ptr);
>  }
> @@ -171,6 +173,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
>         ptr = kmalloc_node(size, GFP_KERNEL, 0);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
>         kfree(ptr);
>  }
> @@ -191,6 +194,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
>
>         kfree(ptr);
> @@ -271,6 +275,7 @@ static void kmalloc_large_oob_right(struct kunit *test)
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
>         kfree(ptr);
>  }
> @@ -410,6 +415,8 @@ static void kmalloc_oob_16(struct kunit *test)
>         ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>
> +       OPTIMIZER_HIDE_VAR(ptr1);
> +       OPTIMIZER_HIDE_VAR(ptr2);
>         KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
>         kfree(ptr1);
>         kfree(ptr2);
> @@ -756,6 +763,8 @@ static void ksize_unpoisons_memory(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         real_size = ksize(ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
> +
>         /* This access shouldn't trigger a KASAN report. */
>         ptr[size] = 'x';
>
> @@ -778,6 +787,7 @@ static void ksize_uaf(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         kfree(ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
>         KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
>         KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
> --
> 2.32.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220608214024.1068451-1-keescook%40chromium.org.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPNM4pB0H2X9iR6F3LeOBsbzj7%2BeE7fAUEy0Rp8db77XQ%40mail.gmail.com.
