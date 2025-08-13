Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNUE6HCAMGQERYML5LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 617F4B242FC
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 09:43:52 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-243030571c2sf15595495ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 00:43:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755071031; cv=pass;
        d=google.com; s=arc-20240605;
        b=A+e879fmM7Is0SZo/9NoPhmbWm8/388U852oGnRGxWwIf1ZIhCDScAH8WdUYtY5DMi
         L7xj20QeHEvwxkSu+rb/hHBgUfDVvXipfTL4+W10p6hjmP9xTTUN7iRwPmqMo8HDH38o
         fG3inqOuZclvvvrhKQMclNsu7ZVlnzugYJAcMrmPXVkIet40YkmyC+gY3O6RYHnHI9/P
         PySXK58UaknBeg48aeX4PiJoUHKPBywFD6wcCKveWsIQf8k2Wsh/ejA1wC6/dDFOpN9T
         QND9nTDvP2OwNrEdrrzYp6TMQTode5mZ0MPgeayvuq5dj7QOXS6WIV5pBthekgmwLbrS
         GR+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5WucnJ7VBZyzS7FLhCoobgd1cjZ5qbig8VkBKMDrGDo=;
        fh=GWUIPvqFq6uCbuiXmCRiFaOsFAJrCtrNWoGOVcgi6C4=;
        b=AQg6hf+XyGR5GwKofKKwdLLEmgx0m2BeqAKb/mqr5qIjFk3jk+9gfU/ZovkCnpknlA
         f3dO/Rr4S4FRG2+nM8w8eGU/liGU+x5mSjOl/f5i0JndyHHtMLviU/lRRKrN26x13SJf
         ATpoUrolYN/FNR1wb1f2eMdvI1HR9HOXUurU1DEfPQgsFl0auw6eaajEk1rDQJlksE76
         wUoaydzCY3cl99rEUAzBZuD52tr3nxr1/ALHal0SoMYldff0TazJLBKF6qN5L9B5VvBD
         uB0Zjm+WD6WS8ybH3Tvc7Cyc0iO5ddSE3z436Npc4uG9gj6AnXyKnBDgpu5XzHksS5PR
         qGAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uBMh07VI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755071031; x=1755675831; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5WucnJ7VBZyzS7FLhCoobgd1cjZ5qbig8VkBKMDrGDo=;
        b=uIGUmuDtpIlxAOKS4cKyvmrLxDw3kNzhw/OuRkYaVBU/oyTv037nmjqP//Q777H64k
         zKgqJVHRf6lxSBsBuwMGMgnoCgiSeszEAPmdPe/pVUqQNCuIO/wAbeoDjSytHi05GsNO
         m8OIQlPIwAlWwPHNktFSz5TFIINrsZK/g72qXXRGhqASO79F8Xe8j7mnpukz8gLjXjfL
         sB1BzNPkz6RNhbR44rRWmOBMxb97peAo/l0jcSbQZq8K5vUasnkPVAMPMj6Ub2KZauwg
         +NjxxpOnikptlRg8v6MlepOtWc1jakWeNVLp6/rNEdPZA2V0z7wYG5gOzKVluIAZ11EO
         hgyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755071031; x=1755675831;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5WucnJ7VBZyzS7FLhCoobgd1cjZ5qbig8VkBKMDrGDo=;
        b=WxvIzgIdIBT04T1cTPjs4hNLHalRrDWryK3xqJSIUti4FIge3rVL/6B7gKRmHeBT1h
         2X+nAB8wuOpKbn0GZHflzMTPHuicRUNV8FrVieiHA4Rkp6H32m2h/Cx0mTcj14JyJx0H
         VZMaJ8XelMFC3nxOJZPXEkMX47EAU1mU5R5m0PrMVQQogv3GTr/XfjFKH9MTSZuyaJMT
         q9ujlUY2JxcI8xzfNpaGenCnGkiSUijurucsTRjqYVO1nWiFPLyivrZ7QjH9tGSMfU+G
         kAwy351WNr1UX4ZHOyrLjNhe9XOkMyvk6fHt+Qj7ge9DNUEzQyaACsoZWbYYtpPpZNWS
         /pAg==
X-Forwarded-Encrypted: i=2; AJvYcCUGkwLV4LN7PSlSJCSDUwGbpgBXEdI2xUih0LLED29F1R1dvxyVByl1qTumFuvRFmkPdsB6+w==@lfdr.de
X-Gm-Message-State: AOJu0YwIIs2zc8frPUd1sS1YHMgtfxlJfc4uZsMTZ9JFf3044BVtY8FK
	hdp/KzylH0t8rmpC0F40C9gwzqxY8OudsYsDuXnVTn7549KdJcGaxAnK
X-Google-Smtp-Source: AGHT+IEqcewbsNTCwxqYRmp3jSxa/RwgpNiacF5bcoB55yfbxyJk0PmtICCbEaunrW4VujnUWSVx5Q==
X-Received: by 2002:a17:903:19c7:b0:242:e0f1:f4bf with SMTP id d9443c01a7336-2430d0e63d1mr25795485ad.18.1755071030778;
        Wed, 13 Aug 2025 00:43:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd3pQ/ddTV5MK2eIao6OS4txrF3ajuNyd/KpwmAZqcFEA==
Received: by 2002:a17:903:3c6f:b0:23c:7b21:3a41 with SMTP id
 d9443c01a7336-242afcdf966ls76814535ad.2.-pod-prod-05-us; Wed, 13 Aug 2025
 00:43:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUkeH3kTZDCPhldpkPmokQ0CTTEqwL/LH0uRYZaeL4SisGlF/qrxoQ4IHRzlRfvBYK0VJjnQY6hi7E=@googlegroups.com
X-Received: by 2002:a17:903:19cc:b0:240:3915:99ba with SMTP id d9443c01a7336-2430d0a3eb8mr26983815ad.5.1755071028517;
        Wed, 13 Aug 2025 00:43:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755071028; cv=none;
        d=google.com; s=arc-20240605;
        b=jpf50Kj35YMkboZghQdIMs3xFeVKr5N0MKp7nYsSeWUnhisHNzVCXGuW8szk/x7KPJ
         xX6HrLtnD4Fbzl7Bu/OO5o7TmIcICedmLXcr34gxCgZ/HvnBbc/lQRH+y0TwGq+WR8Km
         qyqgykhF66d2z9zS7xcmatLIezP68YD4ePAMSV0W2OOuDZ06HNLVDxZsE4YIVy64d1pS
         rsim5b9vkt6vwRES8xHlMUImrtM5pbaFIjRytuds6+YNVviTGwe8niII6srvEjEIrcLb
         fc3Ecu0IqSg0VGYd1RYjlxhLAGYh2fnVKzOXZDa6L1o7e6t+ayXLKErscJ4OD6F5kO4t
         5XAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0UJVq92P3ua8XtJx9QTbL1ot/TXYdNOLOGqwOrYBgLQ=;
        fh=3SgoaGjfEFtyQtsfrpoowoxVpQudQO8EAsOjsYxZbf0=;
        b=asL871KQVISoTktbZKGipQwphR4y2JjbKFqtfqCIETXaAHaUd8mXQVYeXlLFgiargr
         hsz0BKigs/Gs/y/nSy2M5tuv4OcoxkBaE62eoiJfVJ4iMfgoFOuGhZV4XjPW0znvifMS
         ADH6H5g/CYIF7Hafa39p1PZ5Csap4OOgUDwGKYSGNvJCVRzpK8zL1jCCuYoIRb6XgYk2
         jpLe3B1Mxr8H6AOtLzvRVwuo6c7VkXQXSIaH4mOL+B3R0Rwvz+0U1ivyGdX1e0beT+W7
         AvP/Cu8iIDPzEhd7X2zBEAE3UD3UYGTF0EFrbNCTGmVo7LMYuqf7SDcsMqweDSe+3cyf
         2FoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uBMh07VI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241d1f93e96si12940405ad.3.2025.08.13.00.43.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 00:43:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-24049d1643aso46630185ad.3
        for <kasan-dev@googlegroups.com>; Wed, 13 Aug 2025 00:43:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXGaUT3IgK4uxMitaQ2BbXOcrcDk09sQUyeU8lF7EWGvCzCcXVb8GMRZv6qTGv1qfxwpV5DfeCRWBU=@googlegroups.com
X-Gm-Gg: ASbGncvbrc1MNbF3MFwzd3yiXICYtam0c2UZQky0R+Hv+vlyB0mUkqIHl6Fma2cEFT4
	nGzrkXc1YufbD0lN41W9XkCWmQz+0Fpf+LUTkOFjtqw2XC3XSurwlEyRzeyj0UmaB4VXqDM9hFV
	oxqY3xm4Mw9ckK+9ABk2lWQyu/mTcdyyTGBszgytwmDWYZjqm8EEKInUhLbz+uGgaii339Za83X
	PINsP/fVzUzjiGahKFjjAkm/Fdr+mkFlv7IatIdJDjiHL4=
X-Received: by 2002:a17:902:fe97:b0:242:e0f1:f4b9 with SMTP id
 d9443c01a7336-2430d0e6bdcmr25815355ad.20.1755071027377; Wed, 13 Aug 2025
 00:43:47 -0700 (PDT)
MIME-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com> <20250811221739.2694336-4-marievic@google.com>
In-Reply-To: <20250811221739.2694336-4-marievic@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Aug 2025 09:43:10 +0200
X-Gm-Features: Ac12FXxjpczGPECwg-9WltDjK8Gi36eYjjkxdZ5ApzKUTkuNT451Pn6siym2g_E
Message-ID: <CANpmjNOjStrdwpjbyZwk20DNux4nLt2e4T3=yRgAeyxtd7pJQQ@mail.gmail.com>
Subject: Re: [PATCH v2 3/7] kunit: Pass parameterized test context to generate_params()
To: Marie Zhussupova <marievic@google.com>
Cc: rmoar@google.com, davidgow@google.com, shuah@kernel.org, 
	brendan.higgins@linux.dev, mark.rutland@arm.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=uBMh07VI;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, 12 Aug 2025 at 00:17, Marie Zhussupova <marievic@google.com> wrote:
>
> To enable more complex parameterized testing scenarios,
> the generate_params() function needs additional context
> beyond just the previously generated parameter. This patch
> modifies the generate_params() function signature to
> include an extra `struct kunit *test` argument, giving
> test users access to the parameterized test context when
> generating parameters.
>
> The `struct kunit *test` argument was added as the first parameter
> to the function signature as it aligns with the convention
> of other KUnit functions that accept `struct kunit *test` first.
> This also mirrors the "this" or "self" reference found
> in object-oriented programming languages.
>
> This patch also modifies xe_pci_live_device_gen_param()
> in xe_pci.c and nthreads_gen_params() in kcsan_test.c
> to reflect this signature change.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---
>
> Changes in v2:
>
> - generate_params signature changes in
>   xe_pci.c and kcsan_test.c were squashed
>   into a single patch to avoid in-between
>   breakages in the series.
> - The comments and the commit message were changed to
>   reflect the parameterized testing terminology. See
>   the patch series cover letter change log for the
>   definitions.
>
> ---
>  drivers/gpu/drm/xe/tests/xe_pci.c | 2 +-
>  include/kunit/test.h              | 9 ++++++---
>  kernel/kcsan/kcsan_test.c         | 2 +-

Acked-by: Marco Elver <elver@google.com>

>  lib/kunit/test.c                  | 5 +++--
>  4 files changed, 11 insertions(+), 7 deletions(-)
>
> diff --git a/drivers/gpu/drm/xe/tests/xe_pci.c b/drivers/gpu/drm/xe/tests/xe_pci.c
> index 1d3e2e50c355..62c016e84227 100644
> --- a/drivers/gpu/drm/xe/tests/xe_pci.c
> +++ b/drivers/gpu/drm/xe/tests/xe_pci.c
> @@ -129,7 +129,7 @@ EXPORT_SYMBOL_IF_KUNIT(xe_pci_fake_device_init);
>   * Return: pointer to the next &struct xe_device ready to be used as a parameter
>   *         or NULL if there are no more Xe devices on the system.
>   */
> -const void *xe_pci_live_device_gen_param(const void *prev, char *desc)
> +const void *xe_pci_live_device_gen_param(struct kunit *test, const void *prev, char *desc)
>  {
>         const struct xe_device *xe = prev;
>         struct device *dev = xe ? xe->drm.dev : NULL;
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index d2e1b986b161..b527189d2d1c 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -128,7 +128,8 @@ struct kunit_attributes {
>  struct kunit_case {
>         void (*run_case)(struct kunit *test);
>         const char *name;
> -       const void* (*generate_params)(const void *prev, char *desc);
> +       const void* (*generate_params)(struct kunit *test,
> +                                      const void *prev, char *desc);
>         struct kunit_attributes attr;
>         int (*param_init)(struct kunit *test);
>         void (*param_exit)(struct kunit *test);
> @@ -1691,7 +1692,8 @@ do {                                                                             \
>   * Define function @name_gen_params which uses @array to generate parameters.
>   */
>  #define KUNIT_ARRAY_PARAM(name, array, get_desc)                                               \
> -       static const void *name##_gen_params(const void *prev, char *desc)                      \
> +       static const void *name##_gen_params(struct kunit *test,                                \
> +                                            const void *prev, char *desc)                      \
>         {                                                                                       \
>                 typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);      \
>                 if (__next - (array) < ARRAY_SIZE((array))) {                                   \
> @@ -1712,7 +1714,8 @@ do {                                                                             \
>   * Define function @name_gen_params which uses @array to generate parameters.
>   */
>  #define KUNIT_ARRAY_PARAM_DESC(name, array, desc_member)                                       \
> -       static const void *name##_gen_params(const void *prev, char *desc)                      \
> +       static const void *name##_gen_params(struct kunit *test,                                \
> +                                            const void *prev, char *desc)                      \
>         {                                                                                       \
>                 typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);      \
>                 if (__next - (array) < ARRAY_SIZE((array))) {                                   \
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index c2871180edcc..fc76648525ac 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -1383,7 +1383,7 @@ static void test_atomic_builtins_missing_barrier(struct kunit *test)
>   * The thread counts are chosen to cover potentially interesting boundaries and
>   * corner cases (2 to 5), and then stress the system with larger counts.
>   */
> -static const void *nthreads_gen_params(const void *prev, char *desc)
> +static const void *nthreads_gen_params(struct kunit *test, const void *prev, char *desc)
>  {
>         long nthreads = (long)prev;
>
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index 49a5e6c30c86..01b20702a5a2 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -695,7 +695,7 @@ int kunit_run_tests(struct kunit_suite *suite)
>                         /* Get initial param. */
>                         param_desc[0] = '\0';
>                         /* TODO: Make generate_params try-catch */
> -                       curr_param = test_case->generate_params(NULL, param_desc);
> +                       curr_param = test_case->generate_params(&test, NULL, param_desc);
>                         test_case->status = KUNIT_SKIPPED;
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
>                                   "KTAP version 1\n");
> @@ -726,7 +726,8 @@ int kunit_run_tests(struct kunit_suite *suite)
>
>                                 /* Get next param. */
>                                 param_desc[0] = '\0';
> -                               curr_param = test_case->generate_params(curr_param, param_desc);
> +                               curr_param = test_case->generate_params(&test, curr_param,
> +                                                                       param_desc);
>                         }
>                         /*
>                          * TODO: Put into a try catch. Since we don't need suite->exit
> --
> 2.51.0.rc0.205.g4a044479a3-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOjStrdwpjbyZwk20DNux4nLt2e4T3%3DyRgAeyxtd7pJQQ%40mail.gmail.com.
