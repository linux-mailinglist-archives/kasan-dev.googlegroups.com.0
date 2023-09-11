Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKO27STQMGQEZV6I5SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 906DC79A96A
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 17:07:22 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-401db2550e0sf37742045e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 08:07:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694444842; cv=pass;
        d=google.com; s=arc-20160816;
        b=QKkiyyV8x+s/DJtBIlBsZe77IPNkmuJLsbL21gPeP31IJi9QmF6uwMJcaM0TciP144
         LFQuZn2G84Fbz2Lf5ZJ7jUfPYCWPt0w2iNcXjFtojdCCZ60Crb1kXKbrxmz1Xmm3E+SK
         W33JOepzW2ZWRRf8hF86PoRr3B/Fxewy2NjI2BtjuHJ6u5ZjrVU5J7u1hOnw++nLlqLt
         gl9MEtHC5sI98fmNX8g5HB7zKBzYQAo81uOOm+jZx0XpWpmGVxap29oqJ49GA6hcJa3V
         BNyM8SCmBJDHv1+cXDtFOkAp0fBBlq5Mq4XiMjMrJVru65vJBKhyuEpJvumQxisW8KWp
         lKmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=q+uZiv5eXa5s2PMv4S9nb5Hm0jKAzImUX1lxflcnFsU=;
        fh=xOEYjjBxoZTZ/EHX1QhB46LMgR1TviO8E01fK4wIwx0=;
        b=0XJZbIFf5rmeaT+ZimwmDRiDWhx2hfKxrydA4mB/bNWjvvrdyKeICO84HD2QIsASgo
         Tm8PJzSlqZcAXkvLR8GpC57vN3qt2ox4JODspKFxbYYYzB94UAW9qQW/cqaBFljWknpO
         KeUnABAPHZ5JlVnlWNPUk4u4dMbrF7cnfSnrwOiAeXD+i1xv6d7TczT2II7ICWt0btHJ
         HKkkXuO4PjfF8r6JmO67GSM2vIw6C0uY2m/SLsFCWJa+VcybfY/tEguN0qUhs32krTXM
         O96/PTt8ibkqmPFar+2FCxsE/FYSWbMAPpz2TljNcjEA2dFUZi5FvqHLXoUhGYs4k0zp
         6/5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=SsdqREde;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694444842; x=1695049642; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=q+uZiv5eXa5s2PMv4S9nb5Hm0jKAzImUX1lxflcnFsU=;
        b=brhXD3hbk+q5agcl4bF30BoNkqjGOXt9+s3QrCYbTK8G1//Yj92Bwl6sWd5Zn0Y9b/
         w4QKN16uGxPnk03HoWvDVaeazanN3hUSFbBhjtU3+uaY/3M6I2SdJOlCejMzBQ2fOm3R
         4QB4LfKnnyEgMaZefcvKhBoQVBYP7dOy3vUUaYPiZ3u8RuU4nb3LaCAB+ulKEWCHfCaw
         Y9NNjhTAo4DRA2snoyk3whNBq1Zab/1gV9BCmN0cMkMqUa7GZiziqvnKngPZlgQxjv2a
         whio64tGPnpvvDO+u9iEFTExY86EcGBaXfgvtasve8SPVRliCxxxkNJA6AkEEgQKJ1/7
         +wGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694444842; x=1695049642;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=q+uZiv5eXa5s2PMv4S9nb5Hm0jKAzImUX1lxflcnFsU=;
        b=A3PzDXBBqwZD3rz3b19dKE83ISpMg+XEoxMd/XLhTQ5VcdETvUndIlstd9c8kMwbNt
         A3fIzTLfIDfXv2OFjedDBfJ9qelW/gsakdjQczD/EJLmjE44+SXz9hDU+onNyPA4fwHt
         O+kQ0ZHmpyQlTLiVbbZwGMwUl3+XBg0LKGw/z6uRlEN9mreLPma5WLW2JXGyHHnk6Kum
         HWmNQV9uPi7DNrzXnNIeBwgYr9La8B/wwoVuNNcQy2lGjIVMc9uZWeHy+GZEU+TEEhqq
         WY/JlFb72+L2q6GgCl9flfsjhNjefsseHqytHprNL2+53IMQrl3wjKQKEFXXD/WLTj17
         W3yw==
X-Gm-Message-State: AOJu0YwfPM7Qkp4vqSRbp9EA3ORt4WX42iPkx7mRzBP9a0BTBngMmj+D
	ElajlxkdOBv1c/lzXhfEaPA=
X-Google-Smtp-Source: AGHT+IGq43WPesVLv5MaLoMSIWuyCgmrYdfUkOjZXvtKz7GtlF0tnjG1ge+YxEAisorcvxwtkiaIVg==
X-Received: by 2002:a1c:f70b:0:b0:3fd:3006:410b with SMTP id v11-20020a1cf70b000000b003fd3006410bmr8226936wmh.34.1694444841725;
        Mon, 11 Sep 2023 08:07:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:474e:b0:401:b3a5:ebfe with SMTP id
 w14-20020a05600c474e00b00401b3a5ebfels349741wmo.0.-pod-prod-03-eu; Mon, 11
 Sep 2023 08:07:20 -0700 (PDT)
X-Received: by 2002:a7b:c412:0:b0:3fb:df34:176e with SMTP id k18-20020a7bc412000000b003fbdf34176emr8978553wmi.31.1694444839959;
        Mon, 11 Sep 2023 08:07:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694444839; cv=none;
        d=google.com; s=arc-20160816;
        b=CWDiv3Q/zdH5x5LbbNwLaD8wCuNiS5Nov3HgAtIttIPY6Fc0dfgdmAJn6+GA3bRVZ/
         AX2GQCmzJuarJryOmy2sCnLhvaLAjD4zzc3t+0kZMet/l5YcIZlxk0Rh16KvkgR3BOwf
         OcyUrXlBEFxdxcOVbx4nWixDBdYGp7pN2Hd1wPaqk6uN9vCWzkuZTOkAcdu8zUUu6wf1
         1UHE1/gl2uCMvEKOFT3J8Ku2WnT1jkvcoomHbViI4wnhhvjJnYxoBvTnEBBb55p0LiVC
         D3IwuNSPkFsWpGntS4BmKT21959j4SsIwqi4VDIJBFfmwswTAsTGUVjH9cQo4dZS/pSo
         1kOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dOpTUAby7ZVIO6+YPrYOI97+9Zg13vBp8MSTW+q41J4=;
        fh=xOEYjjBxoZTZ/EHX1QhB46LMgR1TviO8E01fK4wIwx0=;
        b=icroXZjV1aAkxWPeE9o/H4vUIusUYCAbCcis+YUUUw29KTl3W1QUsAHMj7EvqZ13Ku
         UgNpQc985ECio96Nl1fH0zF8FRhHTcwRzVJz1MPRAFtO2m2v1hZ7QoQK9f1Kr1w1Ssdl
         pwdUpE2pj5NHIqFuVwYfoBpm2UGzhAGgEfOdu9T3lRnSIPSGrvhtVcjrjx0klGmAWPgv
         8RL1DMvOKVLvKRP4ozdhc50I+8od2Qj6G7R+X7LrQ2NGEYgxZlOJwhjQnHMCu3lB2An2
         03hrg+q6fKiBtlOO4zifJJgrEh0fmD3TYwgXnmlLTzpbHB1p0+ZzdVm/x3PDHbqImKM3
         d++A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=SsdqREde;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id ay40-20020a05600c1e2800b003fef434e6a5si1084972wmb.0.2023.09.11.08.07.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Sep 2023 08:07:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-403012f276dso23473245e9.0
        for <kasan-dev@googlegroups.com>; Mon, 11 Sep 2023 08:07:19 -0700 (PDT)
X-Received: by 2002:a05:600c:b44:b0:401:dc7c:2488 with SMTP id
 k4-20020a05600c0b4400b00401dc7c2488mr8666846wmr.11.1694444839305; Mon, 11 Sep
 2023 08:07:19 -0700 (PDT)
MIME-Version: 1.0
References: <20230911145702.2663753-1-glider@google.com> <20230911145702.2663753-3-glider@google.com>
In-Reply-To: <20230911145702.2663753-3-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Sep 2023 17:06:42 +0200
Message-ID: <CANpmjNP61zOdXR=FYjtzUqcjxg=j_Otqotqv_OTN_Hi2E-LXLg@mail.gmail.com>
Subject: Re: [PATCH v2 3/4] kmsan: merge test_memcpy_aligned_to_unaligned{,2}()
 together
To: Alexander Potapenko <glider@google.com>
Cc: dvyukov@google.com, akpm@linux-foundation.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=SsdqREde;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
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

On Mon, 11 Sept 2023 at 16:57, Alexander Potapenko <glider@google.com> wrote:
>
> Introduce report_reset() that allows checking for more than one KMSAN
> report per testcase.
> Fold test_memcpy_aligned_to_unaligned2() into
> test_memcpy_aligned_to_unaligned(), so that they share the setup phase
> and check the behavior of a single memcpy() call.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Acked-by: Marco Elver <elver@google.com>

> ---
>  mm/kmsan/kmsan_test.c | 37 +++++++++++++------------------------
>  1 file changed, 13 insertions(+), 24 deletions(-)
>
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index a8d4ca4a1066d..6eb1e1a4d08f9 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -67,6 +67,17 @@ static bool report_available(void)
>         return READ_ONCE(observed.available);
>  }
>
> +/* Reset observed.available, so that the test can trigger another report. */
> +static void report_reset(void)
> +{
> +       unsigned long flags;
> +
> +       spin_lock_irqsave(&observed.lock, flags);
> +       WRITE_ONCE(observed.available, false);
> +       observed.ignore = false;
> +       spin_unlock_irqrestore(&observed.lock, flags);
> +}
> +
>  /* Information we expect in a report. */
>  struct expect_report {
>         const char *error_type; /* Error type. */
> @@ -454,7 +465,7 @@ static void test_memcpy_aligned_to_aligned(struct kunit *test)
>   *
>   * Copying aligned 4-byte value to an unaligned one leads to touching two
>   * aligned 4-byte values. This test case checks that KMSAN correctly reports an
> - * error on the first of the two values.
> + * error on the mentioned two values.
>   */
>  static void test_memcpy_aligned_to_unaligned(struct kunit *test)
>  {
> @@ -470,28 +481,7 @@ static void test_memcpy_aligned_to_unaligned(struct kunit *test)
>                         sizeof(uninit_src));
>         kmsan_check_memory((void *)dst, 4);
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> -}
> -
> -/*
> - * Test case: ensure that memcpy() correctly copies uninitialized values between
> - * aligned `src` and unaligned `dst`.
> - *
> - * Copying aligned 4-byte value to an unaligned one leads to touching two
> - * aligned 4-byte values. This test case checks that KMSAN correctly reports an
> - * error on the second of the two values.
> - */
> -static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
> -{
> -       EXPECTATION_UNINIT_VALUE_FN(expect,
> -                                   "test_memcpy_aligned_to_unaligned2");
> -       volatile int uninit_src;
> -       volatile char dst[8] = { 0 };
> -
> -       kunit_info(
> -               test,
> -               "memcpy()ing aligned uninit src to unaligned dst - part 2 (UMR report)\n");
> -       memcpy_noinline((void *)&dst[1], (void *)&uninit_src,
> -                       sizeof(uninit_src));
> +       report_reset();
>         kmsan_check_memory((void *)&dst[4], sizeof(uninit_src));
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
> @@ -589,7 +579,6 @@ static struct kunit_case kmsan_test_cases[] = {
>         KUNIT_CASE(test_init_memcpy),
>         KUNIT_CASE(test_memcpy_aligned_to_aligned),
>         KUNIT_CASE(test_memcpy_aligned_to_unaligned),
> -       KUNIT_CASE(test_memcpy_aligned_to_unaligned2),
>         KUNIT_CASE(test_memset16),
>         KUNIT_CASE(test_memset32),
>         KUNIT_CASE(test_memset64),
> --
> 2.42.0.283.g2d96d420d3-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP61zOdXR%3DFYjtzUqcjxg%3Dj_Otqotqv_OTN_Hi2E-LXLg%40mail.gmail.com.
