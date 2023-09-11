Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEG27STQMGQE4ABNG6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id D0CAB79A969
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 17:06:57 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-51bdae07082sf34005a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 08:06:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694444817; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sfjrv0oZcT4HYDRW5wL1+2c6Pj3bLsvqUZ/wCleAUau7ar3GqWphx1Gz/AtoSCaqdN
         R88C5UW14LFmfuYW1dEn9kbJuZm9zGWgFfBi1Rj69xFSG2CNwERUwODZP2JC6JHrKUc+
         jWDUNRM9fNsLyZJWI26kt7zKaOpo2KgOhZbsck5jhqlDOm2UfEOw8pZn8NLdmop2uWt3
         jAW/oIrIzs1DqB+E5GMGjNjjIwf076EB1zLOBaGlcddBVIpiifyv+ruVOrNldtR5M467
         AB+PynTFNteasKZ7rdLJNXFdaSifZ1YaAoV1wFI57/UDAQt+ss5Lrd49UtipIYrA1F5e
         hM0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=T5ZSemWUDEdFtmxiR8VS5eS42VhAgnCVvQ9L8+FQVH8=;
        fh=xOEYjjBxoZTZ/EHX1QhB46LMgR1TviO8E01fK4wIwx0=;
        b=W3ohKgqjDswjZiZXDuoezZh1v1VO8Dso1+Qbkk/E9wPJDZulXgJrmZGzqOFwhHH1mD
         d4gFaP/xYi2TQyYk1GDPs48OiFsFAQO0pXIbvg9kvHSj0B/1Stnk0qOFuIcQOum4LK4j
         GSxoKshgSeAO3sEbcL33SZu0dFVpeZ4SjWVPSqH0OqKoidfWsWbH+1U37D4nZ5R8vKX2
         fuAGENR1XEON2Lpf9C/GgU+XqPALJGhSMEnvnaMYBh8C61xO8+yM0/I6m4psNoCPleEt
         k0M72cR5GBFWQCO1vy9k8K+I3r3jO0kd8xW/QqET1f93k6Vs9hOkd6JSxXlgZwXdc0nH
         p/UA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=QQtMuecs;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694444817; x=1695049617; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=T5ZSemWUDEdFtmxiR8VS5eS42VhAgnCVvQ9L8+FQVH8=;
        b=c8x5SoeUf0PccddO8Ec6z5NkxQrQ0iUou/RVCpUsjinjaQC4P33e/E/aK+jD5zAoGe
         WOjf5v4AKPxCF04Z/dG1wD4w8kqx6usDTT2nlCjwfqczhlBTEKSKbok1bl9pDduclNJd
         p0LhAmyP8WpqFh1UvagSBaRWjm78lgsjQuAf1vtbxcXB+62d5x+6rllxwUPtSbIRQ0ix
         Wpq7bwv6y9Q0GCJ2gvVxoYM8Dr2wZTz0ZLbh5bvFE5DpiSQawx9ueZ3WqGx0Be/iodZ4
         SQDX5/RWKvWmsrvkmw3pirOCXeMx4rCpexu3l3eK+YX8rekkvgXZSLzG5L7rZejvc96W
         SNvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694444817; x=1695049617;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=T5ZSemWUDEdFtmxiR8VS5eS42VhAgnCVvQ9L8+FQVH8=;
        b=DwWQpNUKKTTdooax+gc/M5na0J86DoD9oe41C4UhtFnXtRZNFouue0GTwnIPo2eA0S
         V0u2pOOzDHNO9UfMDGxk9a0vpVK2bUQFy6DPAv/nJjqm8eu1hCdoZo5dBrvObPLmXUlL
         PtPiVlYjE6Sn7Fwdc1ecffxjGFvj2keot/VoMUmWZ+aE+Fih8mvz6XWoOTg6+ZanMj7E
         bkrYzVwaieKNOfrHyAEdOiZ4YsB0S217nvtZ/ZbDHj904vu6HH2LyorfNNH+C4Kq5pRQ
         WxhVfZGYaJlFh2AWCxJxqx3myb31d4+HZPfxrWTcYlIUXqBUlm7SuJ832VK9Mxhwdmjb
         OHSA==
X-Gm-Message-State: AOJu0YzOyUcdonOEwgpSHnkxmg3Qqm9Lfmg8EVe+253/7jCRrt8lqlWx
	iCOej2ND90JRTg/xYueB4sA=
X-Google-Smtp-Source: AGHT+IGtQ6xX6kcrHglxywLsG+BhxsTQZaDOCZDQqFa93v0MweLprvnJEdrnhPsGKbyIVdor99D6gA==
X-Received: by 2002:a05:6402:400e:b0:52f:2f32:e76c with SMTP id d14-20020a056402400e00b0052f2f32e76cmr137743eda.2.1694444817060;
        Mon, 11 Sep 2023 08:06:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:706:b0:525:b947:ff2 with SMTP id
 w6-20020a056402070600b00525b9470ff2ls460144edx.1.-pod-prod-00-eu; Mon, 11 Sep
 2023 08:06:55 -0700 (PDT)
X-Received: by 2002:a17:907:3f0b:b0:9a5:c2c0:1d0f with SMTP id hq11-20020a1709073f0b00b009a5c2c01d0fmr19568202ejc.12.1694444815212;
        Mon, 11 Sep 2023 08:06:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694444815; cv=none;
        d=google.com; s=arc-20160816;
        b=CY9j6EG7dXuoONVULDyOL3P7eIzEB7mXO99urGlJM+/yfLUtBy55c+Nh94uAQ0bMjb
         AKESwvmz5Nhgz/wrNXZz/1SYfj851vyRC3SVhixkKtoXzd6p7OEKlcWXxyyGsLLU8YpV
         4H0Ahf5Br93nYN64FUs2x0sc58WBvu390iyZXyNoDl2JuewtLAakyWo5mhmB5LuhqBBV
         Nn5WeimBZqnW5hgdLTzLuWE8auDodA7iX04Lm+d76liKmaekUKTRnfyxKUu/xn+J0iru
         GfoKO7mq/CYhv8bUKIXFFlAcbuop6HIl/wBgDL2IAZluL/TdDyB/OnfjEmfddTVWG/Ww
         1HTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XQQwAsg44hbarepY67H1tYdIQRedwFcPBpbpUI6JdQk=;
        fh=xOEYjjBxoZTZ/EHX1QhB46LMgR1TviO8E01fK4wIwx0=;
        b=MG7cFpm0C+7N5wS+77orz6my2HHretABDTXPLiUMw1E4wm08UjLQFuu0yl7qhV4B2r
         EAS4axyeagvxUHggH4dxG0Ed/WdjUupgkFqD10xVNOgGWl9LYmCnZOSyrwCI3HUmILx1
         j1GrcWqgrA64Ed5txfzkkQQL0QUp6YjNVzGVpbJ9zuDysDkAqybjNgUJN3D0XBcoxHG/
         tzKAqKyyK8TcHXg8gDtXn4r2/Ui3TGoe2IKfhs9wUkoWqqZ59VWV8u04tX3dubTuwwKC
         dtNfvfpN/v9HJZgIuUglmlIQDkifjW5vCnSY5TrVlwXf8TdKJd34OR6A4JO+BMFhcBG3
         HS/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=QQtMuecs;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id ey24-20020a1709070b9800b009a9f5afda63si722082ejc.0.2023.09.11.08.06.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Sep 2023 08:06:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-31aec0a1a8bso2859979f8f.0
        for <kasan-dev@googlegroups.com>; Mon, 11 Sep 2023 08:06:55 -0700 (PDT)
X-Received: by 2002:adf:e5c6:0:b0:314:3e96:bd7e with SMTP id
 a6-20020adfe5c6000000b003143e96bd7emr9131234wrn.4.1694444814652; Mon, 11 Sep
 2023 08:06:54 -0700 (PDT)
MIME-Version: 1.0
References: <20230911145702.2663753-1-glider@google.com> <20230911145702.2663753-4-glider@google.com>
In-Reply-To: <20230911145702.2663753-4-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Sep 2023 17:06:15 +0200
Message-ID: <CANpmjNOnPhYg1hyvDRzatUF6aNdysOW4ftv=W4foRd6Wr8bPpQ@mail.gmail.com>
Subject: Re: [PATCH v2 4/4] kmsan: introduce test_memcpy_initialized_gap()
To: Alexander Potapenko <glider@google.com>
Cc: dvyukov@google.com, akpm@linux-foundation.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=QQtMuecs;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as
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
> Add a regression test for the special case where memcpy() previously
> failed to correctly set the origins: if upon memcpy() four aligned
> initialized bytes with a zero origin value ended up split between two
> aligned four-byte chunks, one of those chunks could've received the zero
> origin value even despite it contained uninitialized bytes from other
> writes.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Suggested-by: Marco Elver <elver@google.com>

Acked-by: Marco Elver <elver@google.com>

> ---
>  mm/kmsan/kmsan_test.c | 53 +++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 53 insertions(+)
>
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index 6eb1e1a4d08f9..07d3a3a5a9c52 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -486,6 +486,58 @@ static void test_memcpy_aligned_to_unaligned(struct kunit *test)
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>
> +/*
> + * Test case: ensure that origin slots do not accidentally get overwritten with
> + * zeroes during memcpy().
> + *
> + * Previously, when copying memory from an aligned buffer to an unaligned one,
> + * if there were zero origins corresponding to zero shadow values in the source
> + * buffer, they could have ended up being copied to nonzero shadow values in the
> + * destination buffer:
> + *
> + *  memcpy(0xffff888080a00000, 0xffff888080900002, 8)
> + *
> + *  src (0xffff888080900002): ..xx .... xx..
> + *  src origins:              o111 0000 o222
> + *  dst (0xffff888080a00000): xx.. ..xx
> + *  dst origins:              o111 0000
> + *                        (or 0000 o222)
> + *
> + * (here . stands for an initialized byte, and x for an uninitialized one.
> + *
> + * Ensure that this does not happen anymore, and for both destination bytes
> + * the origin is nonzero (i.e. KMSAN reports an error).
> + */
> +static void test_memcpy_initialized_gap(struct kunit *test)
> +{
> +       EXPECTATION_UNINIT_VALUE_FN(expect, "test_memcpy_initialized_gap");
> +       volatile char uninit_src[12];
> +       volatile char dst[8] = { 0 };
> +
> +       kunit_info(
> +               test,
> +               "unaligned 4-byte initialized value gets a nonzero origin after memcpy() - (2 UMR reports)\n");
> +
> +       uninit_src[0] = 42;
> +       uninit_src[1] = 42;
> +       uninit_src[4] = 42;
> +       uninit_src[5] = 42;
> +       uninit_src[6] = 42;
> +       uninit_src[7] = 42;
> +       uninit_src[10] = 42;
> +       uninit_src[11] = 42;
> +       memcpy_noinline((void *)&dst[0], (void *)&uninit_src[2], 8);
> +
> +       kmsan_check_memory((void *)&dst[0], 4);
> +       KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> +       report_reset();
> +       kmsan_check_memory((void *)&dst[2], 4);
> +       KUNIT_EXPECT_FALSE(test, report_matches(&expect));
> +       report_reset();
> +       kmsan_check_memory((void *)&dst[4], 4);
> +       KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> +}
> +
>  /* Generate test cases for memset16(), memset32(), memset64(). */
>  #define DEFINE_TEST_MEMSETXX(size)                                          \
>         static void test_memset##size(struct kunit *test)                   \
> @@ -579,6 +631,7 @@ static struct kunit_case kmsan_test_cases[] = {
>         KUNIT_CASE(test_init_memcpy),
>         KUNIT_CASE(test_memcpy_aligned_to_aligned),
>         KUNIT_CASE(test_memcpy_aligned_to_unaligned),
> +       KUNIT_CASE(test_memcpy_initialized_gap),
>         KUNIT_CASE(test_memset16),
>         KUNIT_CASE(test_memset32),
>         KUNIT_CASE(test_memset64),
> --
> 2.42.0.283.g2d96d420d3-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOnPhYg1hyvDRzatUF6aNdysOW4ftv%3DW4foRd6Wr8bPpQ%40mail.gmail.com.
