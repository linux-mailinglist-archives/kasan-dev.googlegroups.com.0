Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMUXRCQAMGQESPUB6RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id C59526A9A1B
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 16:01:08 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id e1-20020a17090301c100b0019cd429f407sf1509811plh.17
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Mar 2023 07:01:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677855667; cv=pass;
        d=google.com; s=arc-20160816;
        b=bqmVHN8aokP0AQW91V+904JnaIlCQvNWZf2O/ObB5QO9HACU+xfZi9asOeT04zS2X2
         wEe66dlYAzj2OWEx2TGksKzsBelf2F0F3ra1BPo9ddRSP9MjSX7HZEceo+Qyudc5CqoB
         wgfvps0N24VdAGaR2oPiDwZB5aHBjiIOBsNQrq+NGvxJgvjM5GsKMVJyMPtGkvT9f7TC
         rEd7JYB6GYB6i5i+LeTtnr/1bl5FNm1attU4kztrdDCWJFOx20Iq7F8TGc5pfAEf53/e
         yh/tSNe+kGa/0vbzSDwn/5qJdeUosvTYHfY5HoNH3eOoSFjGio4KzPm/V87C2K+wJ49O
         uJ1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7YnGZLIqTnY4kJoDvgpNy5Q6AOyZyXMtu3J6T8Zw+gU=;
        b=znqDYCjjsqqYVajqjTP4bczFZ2zznV4oNqJRkte2BKc5AEL1POHJr2Ef5Nwv/o3WRb
         hEC5W6DEhAGaw6Mt8F1qPal4cIucjMyUQ5tKJwMx/IgaVZGdEuulZD9EBsKysoPXoKcw
         K2Vh/jwJesj/Swq1yTlJmChATujSsD/6SY+tEvBvyx1u7lVSpWJBf80tB5c1kmMuxm+Q
         I5XJQTaclRCyKlReEOTrn5ewmUGfTqJ0pIiR5P1zsvzEDAaYLuRDE4R3Cq81EEVJlQYw
         Lx/giEdUZR489P0mCnx/P/MJnVZrh2f3Ue9tWfrrCDz8rrvEd88ytPKLHyN53ieQeXDG
         WSPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bnJsE3al;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677855667;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7YnGZLIqTnY4kJoDvgpNy5Q6AOyZyXMtu3J6T8Zw+gU=;
        b=IgFNwT4ewKcd+NEKDpHNRf6hl9v8fwnwtUHuGMkm9vmBRLQOdr1xNQDHpsb/n0ETxu
         5ycg5k65uvRPl+AdNwhhA/XHixcJOTN0IZbaCKirgIXEgxPtTDXWGcALUbH5/qP3cYnG
         rbfHsNpBJQh1FRh1ls4+9cusMfCxz8Y9lhfqWEUwcyZOJJQ7wrYvfTH6+H02MGvjpxu3
         1glIH63nYfpk0/rmL94g8JfPc2bfYL7UgvsXmx2KXu/QkG9EKbfrkG6hXFgcqD9ScCi9
         +MG/VR3wtGTk8MQ1d05kSIhAy08CMKwkfoO6AgrtJ4Xa1/JZoFjBID+VAP/f0Qlrt0XX
         8/uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677855667;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=7YnGZLIqTnY4kJoDvgpNy5Q6AOyZyXMtu3J6T8Zw+gU=;
        b=HJFYY/dyPVM6i8kbw+wf33Wh0O0ZR4IwvQLD3MJ2v+rD0HbPLNVg/ITNmVyN/VYrG+
         X5ipDs9XsZri0N7uBxlh0beRSGNhlGbZYzvxf6t5t+fSONPTdrFatef1yt2S97sOFtFq
         wtFEFaFKiR74rQ5cnJAqzqm7PflYE/r+Xjo0AZBM3rUYYj4r8LOsm49fwHqWY5Mcmjta
         uFy9thWV/oLx5vntBPpbAFNz6gOoiglB6sorc3/E0A+XpHeLDTDM2tpwa/ZWJO1zn7A+
         wUYSYibggQL31VcUssyn7n1IbH9lrLxen5nTyA2kBLFf4GA/TKfrAweU5jIpOhzfBwnr
         OLKQ==
X-Gm-Message-State: AO0yUKVP/j/zuR5t2GF5rslj41y5ILjegZs5oCCc+VK4cm0B2UniE0wx
	UEef8OiuaellgKGjxPGxqrI=
X-Google-Smtp-Source: AK7set+2Cr8OJyJ+tBKvqjFu+2Gua8eoNsuVygcSdrTa/+mkfsb57AzSElMl21Q58jkljMRUDiuySw==
X-Received: by 2002:a17:902:edcd:b0:199:49d7:cead with SMTP id q13-20020a170902edcd00b0019949d7ceadmr820872plk.11.1677855666945;
        Fri, 03 Mar 2023 07:01:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1958:0:b0:4da:d60d:b232 with SMTP id 24-20020a631958000000b004dad60db232ls702123pgz.9.-pod-prod-gmail;
 Fri, 03 Mar 2023 07:01:05 -0800 (PST)
X-Received: by 2002:a62:64c4:0:b0:5a9:c7bb:4d94 with SMTP id y187-20020a6264c4000000b005a9c7bb4d94mr2226512pfb.33.1677855665699;
        Fri, 03 Mar 2023 07:01:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677855665; cv=none;
        d=google.com; s=arc-20160816;
        b=KtBSN+RNtTiaXKj8u+Cb2r2dmTRwJ2mWRBpdhMKchLJOVTLQUBObhez+O1wGBCMx4Z
         Eun/+FwD5mg/NnorQ2X5EO5xcy7ys7W4BJIXzB3SEr8ORSksW3GlSO0GM1Gq7iDGzg9Y
         O9LK8E7Lr+agi/wDzRUndxwVvm1H5cy9kd94/NoZta9JYZWTOoNs8jYkVlSf85hglxyr
         /GPiGOpFmCdLUH/KwAbQ8Xqj3FKXCVvgelDurInfB/XsEA8lyxlp4SP6Kxli+BtWW//y
         qmkyf5ACDoGbT5wX3hbhgCMTlHLQQTvQyT7W14fmLqg3SFXzR/UgHurCLbkuuEzzx7T4
         31Iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/aydHlOGXKxNYbYaenvW8HmCoQRPXb5oRnbMkROWhOQ=;
        b=gAj6b0YnZ8kTHB58jn0NWr/CuxhWLWGga23vDRn9vWOUUyhOZmuo/dhZFrWPDvL0aQ
         U2UoUmIsCqGO+X9QoRbs+C0+KUs1SYnho7avM0VJ4XlmIi41E2sPsnA6q3gyR76wPmpQ
         D3QNGSMYnMhlKUbwcdu4LGQ1lTdwz1nUb+udNDh3QGflDouh07BLVT/b90mgZgcWs/4P
         MwQBIgeAuQAahdOev2Z9DjgzI4JHyPL8fa07YS+pH3pgq0ayRnUrRyMwfuGarsuZWgJp
         W4mThcb/NMZgHPWnpTkAmPqilnpfMzPSHyn7I1sXCJ7nQtjTAM0/K7OunkEPkxGXkISs
         VdXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bnJsE3al;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe31.google.com (mail-vs1-xe31.google.com. [2607:f8b0:4864:20::e31])
        by gmr-mx.google.com with ESMTPS id x4-20020a655384000000b004fb840b5440si121233pgq.5.2023.03.03.07.01.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Mar 2023 07:01:05 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) client-ip=2607:f8b0:4864:20::e31;
Received: by mail-vs1-xe31.google.com with SMTP id m10so2634213vso.4
        for <kasan-dev@googlegroups.com>; Fri, 03 Mar 2023 07:01:05 -0800 (PST)
X-Received: by 2002:a05:6102:243:b0:415:82c8:8753 with SMTP id
 a3-20020a056102024300b0041582c88753mr1347560vsq.1.1677855664805; Fri, 03 Mar
 2023 07:01:04 -0800 (PST)
MIME-Version: 1.0
References: <20230303141433.3422671-1-glider@google.com> <20230303141433.3422671-4-glider@google.com>
In-Reply-To: <20230303141433.3422671-4-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 3 Mar 2023 16:00:28 +0100
Message-ID: <CANpmjNP8OaOvY02VHqy3JMeDxVzfHguZG8PHhMOKKPjK-Q73Bg@mail.gmail.com>
Subject: Re: [PATCH 4/4] kmsan: add memsetXX tests
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, dvyukov@google.com, 
	nathan@kernel.org, ndesaulniers@google.com, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bnJsE3al;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as
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

On Fri, 3 Mar 2023 at 15:14, 'Alexander Potapenko' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Add tests ensuring that memset16()/memset32()/memset64() are
> instrumented by KMSAN and correctly initialize the memory.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> v2:
>  - drop a redundant parameter of DEFINE_TEST_MEMSETXX()

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kmsan/kmsan_test.c | 22 ++++++++++++++++++++++
>  1 file changed, 22 insertions(+)
>
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index aeddfdd4f679f..7095d3fbb23ac 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -504,6 +504,25 @@ static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>
> +/* Generate test cases for memset16(), memset32(), memset64(). */
> +#define DEFINE_TEST_MEMSETXX(size)                                          \
> +       static void test_memset##size(struct kunit *test)                   \
> +       {                                                                   \
> +               EXPECTATION_NO_REPORT(expect);                              \
> +               volatile uint##size##_t uninit;                             \
> +                                                                            \
> +               kunit_info(test,                                            \
> +                          "memset" #size "() should initialize memory\n"); \
> +               DO_NOT_OPTIMIZE(uninit);                                    \
> +               memset##size((uint##size##_t *)&uninit, 0, 1);              \
> +               kmsan_check_memory((void *)&uninit, sizeof(uninit));        \
> +               KUNIT_EXPECT_TRUE(test, report_matches(&expect));           \
> +       }
> +
> +DEFINE_TEST_MEMSETXX(16)
> +DEFINE_TEST_MEMSETXX(32)
> +DEFINE_TEST_MEMSETXX(64)
> +
>  static noinline void fibonacci(int *array, int size, int start)
>  {
>         if (start < 2 || (start == size))
> @@ -550,6 +569,9 @@ static struct kunit_case kmsan_test_cases[] = {
>         KUNIT_CASE(test_memcpy_aligned_to_aligned),
>         KUNIT_CASE(test_memcpy_aligned_to_unaligned),
>         KUNIT_CASE(test_memcpy_aligned_to_unaligned2),
> +       KUNIT_CASE(test_memset16),
> +       KUNIT_CASE(test_memset32),
> +       KUNIT_CASE(test_memset64),
>         KUNIT_CASE(test_long_origin_chain),
>         {},
>  };
> --
> 2.40.0.rc0.216.gc4246ad0f0-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230303141433.3422671-4-glider%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP8OaOvY02VHqy3JMeDxVzfHguZG8PHhMOKKPjK-Q73Bg%40mail.gmail.com.
