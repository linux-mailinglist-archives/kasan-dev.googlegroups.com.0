Return-Path: <kasan-dev+bncBC6OLHHDVUOBBQ5I7TCAMGQERKGHWVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D975B27EC9
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 13:04:37 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70a88ddec70sf18036616d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 04:04:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755255876; cv=pass;
        d=google.com; s=arc-20240605;
        b=KigopHdVY3zWJukMTzI9YFvos4+7NqiMTGd+LdcQN9jQlR1s90+V7GrEcQ5or88krP
         S6o1aDkDVMbcnWkX7cQZHA4ALw1LUHXZQMePUkIymxo3hodduZMEPQQeHkYBiAKjRfVW
         wgmjDTrJNVavy+eh6gn68KGXGBEYxB1UpGeaqw0kBVNqhk9oSZ2/6Eg4wPRSxybBwXOh
         Q3xZMdNNqkFliucVTC8kLhc8OL1o29/Jw7L3AEno8eP3q8yJstSLFSiu0ZIYKnpo6Zoo
         Gjk+z4BC5DOkn5MjzUfL4bPpMSfrTe6ofGdVkCy+PXIZUi+m76GF+n5glC+DgzJeEWa9
         QvCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dvHGNI1M43EsUddGghW/mGN5GaJnqKuJLWJnLETlEbQ=;
        fh=ErKAlRELX7TiNcx76tch6onSR6jTJ2tARFW9tnzEHCY=;
        b=RQl5Zx5u4MrQxr5kwL9rxfNABtDbNJQ7EAQaExITHEPugOX4UrH4cC5wvCfZFOHLZY
         Prf7d7rC0LHlnuwFhN1RJRDMYLUz8eBAXzRlQ0jhNlSgvQgXk+Hvu68n6t3WLxE4KU1M
         RbghjvuJax3oeTRKLWhyAMCfw3cyWKO5MEPgLVNLWyrIUGWrtoWPopa0Bq/oEbW3w7tH
         bqSFFq2V+15n0jFj/3yH5+yzMdQZu9ze6RKvxX6+EPN6KCASUbn0F24SjffkE9heDDJc
         mPggqHz/Iyi/PUegcyoQrxxTi9i5OsVn7fZJ7YJoJUTa0dcYJaO4HQ6JBjo3IuOU60ZB
         C/fA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="j6uVtcg/";
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755255876; x=1755860676; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dvHGNI1M43EsUddGghW/mGN5GaJnqKuJLWJnLETlEbQ=;
        b=or2jp2J9HxpkEdixWrNSGfFkp9QpQ1mMj6zIKTmiP/SnJQnBVMUVD1PpmyJgeD6FLn
         lsUJ7lRBdviXY16D5EI4djyOQZfgp8NA78XPAyeGn3J5Y/cNuk1QWQRq32ytFcqGiT2b
         gyBIS2sKCnt3njrTeHtL1zzkOdOUwDOx0Zk2DsKytKTiVV4335JI5T6ofGUJmDSuq7/h
         mKsXifXIktmW6FV10Ya7YVb7Ib4xWpZ6gFv/ioC1yxhMGSPpK7T5y1GAn0Rq5nlkjpC8
         0sDkmLpPYtTN45gXcycYjjsQ3dUuHtQ+BsgiGpqYvRHzO7bQVbQvMIVASHrlMal0/wZv
         XM2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755255876; x=1755860676;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dvHGNI1M43EsUddGghW/mGN5GaJnqKuJLWJnLETlEbQ=;
        b=WQpLhl+Zb3U29ht7Ias3Dllx0KYvhweyLRf4L2xv2qi3KN3/NoYK+jlAQFtgbELgPh
         rNgCP2L7NhWQoGnYR0LbiMMjFgi/j9LBFuhhmL9uOYEM+KCfPhGsXB9tXwoYHhPTE4Ja
         KoKAp6skfBtQQxFQ3i8ykPW0juo60B2RrwyMvZ+ifVbEuXyoENc2lfUe6MEaMPFwnwr9
         ZKCKM85KingG+nebKZg7SdbYrvo5IVYWDIV8q20HC68ckgyrqBooiu/bdkl8EBWKUlvY
         BxD4mMUGCpkqy544Atz5oLd3KOB042mkjbdFkw7NJSUF8yeBYeq+/DymZY4Teh9FXahQ
         blZQ==
X-Forwarded-Encrypted: i=2; AJvYcCUFmF9e/Df+8WBTatfO/7HH/ldNhdm4tG70YmgUKZaqLuUSeKKDsEi7b/YaPDZUo1V52tR/bQ==@lfdr.de
X-Gm-Message-State: AOJu0YxO0J0hUem4LsY3zzbyz/S7w+QtF94VB//hM7q4/nPbFNSkOWDQ
	KoZGMp0qZKkKlxLAcMld1CX1LKD6xDZ+zC2f65J0152jijsFJEpSj08D
X-Google-Smtp-Source: AGHT+IGRo3E8cO7ZKcPRX9VyQLwo6kfNHBnhFz7IzNlpbYDdZ2VmEIj+6U0uQx872A9rSLnSPGWn9g==
X-Received: by 2002:ad4:5f89:0:b0:709:a83c:d88b with SMTP id 6a1803df08f44-70ba7c4aac3mr16139506d6.34.1755255876129;
        Fri, 15 Aug 2025 04:04:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdgMaIFLObjC+Jip3l+PG2e+2fHns1fcSa8hq+76fEjAg==
Received: by 2002:ad4:5d69:0:b0:70b:acc1:ba4f with SMTP id 6a1803df08f44-70bacc1c59als1898686d6.1.-pod-prod-08-us;
 Fri, 15 Aug 2025 04:04:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVsxJsLCzZzamT+LrwUQjp5kVgX9TBY8iWATXZhrqwe1w2UiDQCFiCdMxYYHF/HsDo817DKyLjmOKw=@googlegroups.com
X-Received: by 2002:a05:6214:76a:b0:709:f3e2:59fe with SMTP id 6a1803df08f44-70ba7af6aefmr15641116d6.17.1755255874960;
        Fri, 15 Aug 2025 04:04:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755255874; cv=none;
        d=google.com; s=arc-20240605;
        b=AZX7Hc1q2Kp3dV7qzgBhaLXgWEWFkX68EmKSi5MezQpinMzzeKWMBYAYcVSF8tuV18
         15jYyYeT33km3fv+sdaBGI94q2vP7NaA1rcTJB53wdtOoEALCyk+PlYHPO5dImf9IE2X
         XH1Eq8qHApDRW8oRWFV9VjorOjNogXkB7JKLDIqhS13VWW04pcmb+vr0OfuCkfTZ7fbt
         uMizHhElWRz6/gLDnIhHLeaNs846OGfKL3BmvnSxJBGL7M4jdTfTmDOtmMVWDvSWCyow
         TqTEhu17WtBhyGFFxFOuHWJyrS7ubahVpeYSaJnuqEYMNtOckWo9tmpkzujJGys6Ls3O
         A96g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ggv+zSCfw8D26Qqe4ajz3v7a8n/uFVhcNreljuK0RUc=;
        fh=MFa3Mi6VirNZbQ9JNI4+gR1ReH7+x0y+6cANPd88DEE=;
        b=i66J8RgF7xILtF2Shd6n2IeGpK3FeCjvji3N9BkmbBgSczHwXBlpWf1gcvfi/Yr35I
         MncB0Yd5uBEVwG8/PIPGpVP0y28ooodtwQcfWFpQh2YziCH/W9CCu+0yPmoPanmzFsvp
         SGR59mAfKj57kDI4rlKnDQkBZz1ZngFxqhK+2XhKd/8+vIhsnGuDo2bCzZ+DXiDXqZEg
         U8+BtGt+lT+P5EgbEbeZJwEUMxNIUcE10Ym1aSEvCmarwWEXgwE3gj7Vybks8xeUlSQu
         5vc9XGowYgikIGZKXGKoHMK5DpaeBH2onZrzVWFYusiUdghR8cWaJPtxNQzQAz22aVyW
         bZDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="j6uVtcg/";
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x72d.google.com (mail-qk1-x72d.google.com. [2607:f8b0:4864:20::72d])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70ba91aa2b6si425806d6.4.2025.08.15.04.04.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Aug 2025 04:04:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::72d as permitted sender) client-ip=2607:f8b0:4864:20::72d;
Received: by mail-qk1-x72d.google.com with SMTP id af79cd13be357-7e8704da966so122554785a.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Aug 2025 04:04:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWUAYiJbVg40zP1Yf4ntomOeTJ5CUwZuy/DoTU+OIQTzgiVy2hJMvXnenzPsDiM/XTBIk0BNP4aOwE=@googlegroups.com
X-Gm-Gg: ASbGncvpKDR8n4RfwnQgSeykCUjPOGdvgQQgjsHl/LotTt9hPL+9NYJUoyB5svc+9Zk
	VBrJLbUhJGgSlnFblE+3sJWIIXMqQ8VjLeUjKZK9BH+s/v3rdgp6LE1P1bydOgOiz0KdTGOd04H
	wwtxi6uyT6/SOOdI35v2aCxp1aQBU12kOQ91f5xh9FlmBVOeHaZKd2e059DoHYfWGAI/xsUuf70
	YeP/Pjst4P3nnEsdCcFYDOFAw==
X-Received: by 2002:a05:620a:6cc6:b0:7e6:8e43:4571 with SMTP id
 af79cd13be357-7e87e0dbc24mr181297285a.64.1755255874005; Fri, 15 Aug 2025
 04:04:34 -0700 (PDT)
MIME-Version: 1.0
References: <20250815103604.3857930-1-marievic@google.com> <20250815103604.3857930-3-marievic@google.com>
In-Reply-To: <20250815103604.3857930-3-marievic@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Aug 2025 19:04:21 +0800
X-Gm-Features: Ac12FXxjQpWOUTkjmalKCNMWlZUcA8lL3JG3JcVOWa1BTIUZU_qejiU4XP91Ljs
Message-ID: <CABVgOS=3WjF=LObZNUcW9wsdnjzrmhAsjHP8uu02cO3F5iWkrA@mail.gmail.com>
Subject: Re: [PATCH v3 2/7] kunit: Introduce param_init/exit for parameterized
 test context management
To: Marie Zhussupova <marievic@google.com>
Cc: rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000e9de26063c655a32"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="j6uVtcg/";       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::72d
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

--000000000000e9de26063c655a32
Content-Type: text/plain; charset="UTF-8"

On Fri, 15 Aug 2025 at 18:36, Marie Zhussupova <marievic@google.com> wrote:
>
> Add (*param_init) and (*param_exit) function pointers to
> `struct kunit_case`. Users will be able to set them via the new
> KUNIT_CASE_PARAM_WITH_INIT() macro.
>
> param_init/exit will be invoked by kunit_run_tests() once before and once
> after the parameterized test, respectively. They will receive the
> `struct kunit` that holds the parameterized test context; facilitating
> init and exit for shared state.
>
> This patch also sets param_init/exit to None in rust/kernel/kunit.rs.
>
> Reviewed-by: Rae Moar <rmoar@google.com>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---

Thanks, I've tested the param_init failure case, and it works well for me now.

Reviewed-by: David Gow <davidgow@google.com>

Cheers,
-- David

>
> Changes in v3:
> v2: https://lore.kernel.org/all/20250811221739.2694336-3-marievic@google.com/
> - kunit_init_parent_param_test() now sets both the `struct kunit_case`
>   and the `struct kunit` statuses as failed if the parameterized test
>   init failed. The failure message was also changed to include the failure
>   code, mirroring the kunit_suite init failure message.
> - A check for parameter init failure was added in kunit_run_tests(). So,
>   if the init failed, the framework will skip the parameter runs and
>   update the param_test statistics to count that failure.
> - Commit message formatting.
>
> Changes in v2:
> v1: https://lore.kernel.org/all/20250729193647.3410634-3-marievic@google.com/
> - param init/exit were set to None in rust/kernel/kunit.rs to fix the
>   Rust breakage.
> - The name of __kunit_init_parent_test was changed to
>   kunit_init_parent_param_test and its call was changed to happen only
>   if the test is parameterized.
> - The param_exit call was also moved inside the check for if the test is
>   parameterized.
> - KUNIT_CASE_PARAM_WITH_INIT() macro logic was change to not automatically
>   set generate_params() to KUnit's built-in generator function. Instead,
>   the test user will be asked to provide it themselves.
> - The comments and the commit message were changed to reflect the
>   parameterized testing terminology. See the patch series cover letter
>   change log for the definitions.
>
> ---
>  include/kunit/test.h | 25 +++++++++++++++++++++++++
>  lib/kunit/test.c     | 27 ++++++++++++++++++++++++++-
>  rust/kernel/kunit.rs |  4 ++++
>  3 files changed, 55 insertions(+), 1 deletion(-)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index b47b9a3102f3..d2e1b986b161 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -92,6 +92,8 @@ struct kunit_attributes {
>   * @name:     the name of the test case.
>   * @generate_params: the generator function for parameterized tests.
>   * @attr:     the attributes associated with the test
> + * @param_init: The init function to run before a parameterized test.
> + * @param_exit: The exit function to run after a parameterized test.
>   *
>   * A test case is a function with the signature,
>   * ``void (*)(struct kunit *)``
> @@ -128,6 +130,8 @@ struct kunit_case {
>         const char *name;
>         const void* (*generate_params)(const void *prev, char *desc);
>         struct kunit_attributes attr;
> +       int (*param_init)(struct kunit *test);
> +       void (*param_exit)(struct kunit *test);
>
>         /* private: internal use only. */
>         enum kunit_status status;
> @@ -218,6 +222,27 @@ static inline char *kunit_status_to_ok_not_ok(enum kunit_status status)
>                   .generate_params = gen_params,                                \
>                   .attr = attributes, .module_name = KBUILD_MODNAME}
>
> +/**
> + * KUNIT_CASE_PARAM_WITH_INIT - Define a parameterized KUnit test case with custom
> + * param_init() and param_exit() functions.
> + * @test_name: The function implementing the test case.
> + * @gen_params: The function to generate parameters for the test case.
> + * @init: A reference to the param_init() function to run before a parameterized test.
> + * @exit: A reference to the param_exit() function to run after a parameterized test.
> + *
> + * Provides the option to register param_init() and param_exit() functions.
> + * param_init/exit will be passed the parameterized test context and run once
> + * before and once after the parameterized test. The init function can be used
> + * to add resources to share between parameter runs, and any other setup logic.
> + * The exit function can be used to clean up resources that were not managed by
> + * the parameterized test, and any other teardown logic.
> + */
> +#define KUNIT_CASE_PARAM_WITH_INIT(test_name, gen_params, init, exit)          \
> +               { .run_case = test_name, .name = #test_name,                    \
> +                 .generate_params = gen_params,                                \
> +                 .param_init = init, .param_exit = exit,                       \
> +                 .module_name = KBUILD_MODNAME}
> +
>  /**
>   * struct kunit_suite - describes a related collection of &struct kunit_case
>   *
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index 14a8bd846939..917df2e1688d 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -641,6 +641,20 @@ static void kunit_accumulate_stats(struct kunit_result_stats *total,
>         total->total += add.total;
>  }
>
> +static void kunit_init_parent_param_test(struct kunit_case *test_case, struct kunit *test)
> +{
> +       if (test_case->param_init) {
> +               int err = test_case->param_init(test);
> +
> +               if (err) {
> +                       kunit_err(test_case, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
> +                               "# failed to initialize parent parameter test (%d)", err);
> +                       test->status = KUNIT_FAILURE;
> +                       test_case->status = KUNIT_FAILURE;
> +               }
> +       }
> +}
> +
>  int kunit_run_tests(struct kunit_suite *suite)
>  {
>         char param_desc[KUNIT_PARAM_DESC_SIZE];
> @@ -678,6 +692,11 @@ int kunit_run_tests(struct kunit_suite *suite)
>                         kunit_run_case_catch_errors(suite, test_case, &test);
>                         kunit_update_stats(&param_stats, test.status);
>                 } else {
> +                       kunit_init_parent_param_test(test_case, &test);
> +                       if (test_case->status == KUNIT_FAILURE) {
> +                               kunit_update_stats(&param_stats, test.status);
> +                               goto test_case_end;
> +                       }
>                         /* Get initial param. */
>                         param_desc[0] = '\0';
>                         /* TODO: Make generate_params try-catch */
> @@ -714,10 +733,16 @@ int kunit_run_tests(struct kunit_suite *suite)
>                                 param_desc[0] = '\0';
>                                 curr_param = test_case->generate_params(curr_param, param_desc);
>                         }
> +                       /*
> +                        * TODO: Put into a try catch. Since we don't need suite->exit
> +                        * for it we can't reuse kunit_try_run_cleanup for this yet.
> +                        */
> +                       if (test_case->param_exit)
> +                               test_case->param_exit(&test);
>                         /* TODO: Put this kunit_cleanup into a try-catch. */
>                         kunit_cleanup(&test);
>                 }
> -
> +test_case_end:
>                 kunit_print_attr((void *)test_case, true, KUNIT_LEVEL_CASE);
>
>                 kunit_print_test_stats(&test, param_stats);
> diff --git a/rust/kernel/kunit.rs b/rust/kernel/kunit.rs
> index 4b8cdcb21e77..cda64574b44d 100644
> --- a/rust/kernel/kunit.rs
> +++ b/rust/kernel/kunit.rs
> @@ -207,6 +207,8 @@ pub const fn kunit_case(
>          status: kernel::bindings::kunit_status_KUNIT_SUCCESS,
>          module_name: core::ptr::null_mut(),
>          log: core::ptr::null_mut(),
> +        param_init: None,
> +        param_exit: None,
>      }
>  }
>
> @@ -226,6 +228,8 @@ pub const fn kunit_case_null() -> kernel::bindings::kunit_case {
>          status: kernel::bindings::kunit_status_KUNIT_SUCCESS,
>          module_name: core::ptr::null_mut(),
>          log: core::ptr::null_mut(),
> +        param_init: None,
> +        param_exit: None,
>      }
>  }
>
> --
> 2.51.0.rc1.167.g924127e9c0-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOS%3D3WjF%3DLObZNUcW9wsdnjzrmhAsjHP8uu02cO3F5iWkrA%40mail.gmail.com.

--000000000000e9de26063c655a32
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"
Content-Description: S/MIME Cryptographic Signature

MIIUnQYJKoZIhvcNAQcCoIIUjjCCFIoCAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGg
ghIEMIIGkTCCBHmgAwIBAgIQfofDAVIq0iZG5Ok+mZCT2TANBgkqhkiG9w0BAQwFADBMMSAwHgYD
VQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
AxMKR2xvYmFsU2lnbjAeFw0yMzA0MTkwMzUzNDdaFw0zMjA0MTkwMDAwMDBaMFQxCzAJBgNVBAYT
AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSowKAYDVQQDEyFHbG9iYWxTaWduIEF0bGFz
IFI2IFNNSU1FIENBIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDYydcdmKyg
4IBqVjT4XMf6SR2Ix+1ChW2efX6LpapgGIl63csmTdJQw8EcbwU9C691spkltzTASK2Ayi4aeosB
mk63SPrdVjJNNTkSbTowej3xVVGnYwAjZ6/qcrIgRUNtd/mbtG7j9W80JoP6o2Szu6/mdjb/yxRM
KaCDlloE9vID2jSNB5qOGkKKvN0x6I5e/B1Y6tidYDHemkW4Qv9mfE3xtDAoe5ygUvKA4KHQTOIy
VQEFpd/ZAu1yvrEeA/egkcmdJs6o47sxfo9p/fGNsLm/TOOZg5aj5RHJbZlc0zQ3yZt1wh+NEe3x
ewU5ZoFnETCjjTKz16eJ5RE21EmnCtLb3kU1s+t/L0RUU3XUAzMeBVYBEsEmNnbo1UiiuwUZBWiJ
vMBxd9LeIodDzz3ULIN5Q84oYBOeWGI2ILvplRe9Fx/WBjHhl9rJgAXs2h9dAMVeEYIYkvW+9mpt
BIU9cXUiO0bky1lumSRRg11fOgRzIJQsphStaOq5OPTb3pBiNpwWvYpvv5kCG2X58GfdR8SWA+fm
OLXHcb5lRljrS4rT9MROG/QkZgNtoFLBo/r7qANrtlyAwPx5zPsQSwG9r8SFdgMTHnA2eWCZPOmN
1Tt4xU4v9mQIHNqQBuNJLjlxvalUOdTRgw21OJAFt6Ncx5j/20Qw9FECnP+B3EPVmQIDAQABo4IB
ZTCCAWEwDgYDVR0PAQH/BAQDAgGGMDMGA1UdJQQsMCoGCCsGAQUFBwMCBggrBgEFBQcDBAYJKwYB
BAGCNxUGBgkrBgEEAYI3FQUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUM7q+o9Q5TSoZ
18hmkmiB/cHGycYwHwYDVR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEE
bzBtMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsG
AQUFBzAChi9odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMBEG
A1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAgEAVc4mpSLg9A6QpSq1JNO6tURZ4rBI
MkwhqdLrEsKs8z40RyxMURo+B2ZljZmFLcEVxyNt7zwpZ2IDfk4URESmfDTiy95jf856Hcwzdxfy
jdwx0k7n4/0WK9ElybN4J95sgeGRcqd4pji6171bREVt0UlHrIRkftIMFK1bzU0dgpgLMu+ykJSE
0Bog41D9T6Swl2RTuKYYO4UAl9nSjWN6CVP8rZQotJv8Kl2llpe83n6ULzNfe2QT67IB5sJdsrNk
jIxSwaWjOUNddWvCk/b5qsVUROOuctPyYnAFTU5KY5qhyuiFTvvVlOMArFkStNlVKIufop5EQh6p
jqDGT6rp4ANDoEWbHKd4mwrMtvrh51/8UzaJrLzj3GjdkJ/sPWkDbn+AIt6lrO8hbYSD8L7RQDqK
C28FheVr4ynpkrWkT7Rl6npWhyumaCbjR+8bo9gs7rto9SPDhWhgPSR9R1//WF3mdHt8SKERhvtd
NFkE3zf36V9Vnu0EO1ay2n5imrOfLkOVF3vtAjleJnesM/R7v5tMS0tWoIr39KaQNURwI//WVuR+
zjqIQVx5s7Ta1GgEL56z0C5GJoNE1LvGXnQDyvDO6QeJVThFNgwkossyvmMAaPOJYnYCrYXiXXle
A6TpL63Gu8foNftUO0T83JbV/e6J8iCOnGZwZDrubOtYn1QwggWDMIIDa6ADAgECAg5F5rsDgzPD
hWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBS
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
jmkLAgMBAAGjggHgMIIB3DAeBgNVHREEFzAVgRNkYXZpZGdvd0Bnb29nbGUuY29tMA4GA1UdDwEB
/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDBAYIKwYBBQUHAwIwHQYDVR0OBBYEFBp5bTxrTm/d
WMmRETO8lNkA4c7fMFgGA1UdIARRME8wCQYHZ4EMAQUBAjBCBgorBgEEAaAyCgMDMDQwMgYIKwYB
BQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQC
MAAwgZoGCCsGAQUFBwEBBIGNMIGKMD4GCCsGAQUFBzABhjJodHRwOi8vb2NzcC5nbG9iYWxzaWdu
LmNvbS9jYS9nc2F0bGFzcjZzbWltZWNhMjAyMzBIBggrBgEFBQcwAoY8aHR0cDovL3NlY3VyZS5n
bG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NhdGxhc3I2c21pbWVjYTIwMjMuY3J0MB8GA1UdIwQYMBaA
FDO6vqPUOU0qGdfIZpJogf3BxsnGMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwuZ2xvYmFs
c2lnbi5jb20vY2EvZ3NhdGxhc3I2c21pbWVjYTIwMjMuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQBF
tO3/N2l9hTaij/K0xCpLwIlrqpNo0nMAvvG5LPQQjSeHnTh06tWTgsPCOJ65GX+bqWRDwGTu8WTq
c5ihCNOikBs25j82yeLkfdbeN/tzRGUb2RD+8n9I3CnyMSG49U2s0ZdncsrIVFh47KW2TpHTF7R8
N1dri01wPg8hw4u0+XoczR2TiBrBOISKmAlkAi+P9ivT31gSHdbopoL4x0V2Ow9IOp0chrQQUZtP
KBytLhzUzd9wIsE0QMNDbw6jeG8+a4sd17zpXSbBywIGw7sEvPtnBjMaf5ib3kznlOne6tuDVx4y
QFExTCSrP3OTMUkNbpIdgzg2CHQ2aB8i8YsTZ8Q8Q8ztPJ+xDNsqBUeYxILLjTjxQQovToqipB3f
6IMyk+lWCdDS+iCLYZULV1BTHSdwp1NM3t4jZ8TMlV+JzAyRqz4lzSl8ptkFhKBJ7w2tDrZ3BEXB
8ASUByRxeh+pC1Z5/HhqfiWMVPjaWmlRRJVlRk+ObKIv2CblwxMYlo2Mn8rrbEDyfum1RTMW55Z6
Vumvw5QTHe29TYxSiusovM6OD5y0I+4zaIaYDx/AtF0mMOFXb1MDyynf1CDxhtkgnrBUseHSOU2e
MYs7IqzRap5xsgpJS+t7cp/P8fdlCNvsXss9zZa279tKwaxR0U2IzGxRGsWKGxDysn1HT6pqMDGC
Al0wggJZAgEBMGgwVDELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKjAo
BgNVBAMTIUdsb2JhbFNpZ24gQXRsYXMgUjYgU01JTUUgQ0EgMjAyMwIQAUXA7LnOuRz2DvkWTeMc
0TANBglghkgBZQMEAgEFAKCBxzAvBgkqhkiG9w0BCQQxIgQgAajXmtqTYc6VnbKNqUv+24zFMJ72
ByNZMBgUPX1WmIQwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUw
ODE1MTEwNDM0WjBcBgkqhkiG9w0BCQ8xTzBNMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
YIZIAWUDBAECMAoGCCqGSIb3DQMHMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcN
AQEBBQAEggEAcvY56TR4MH7v42ch8NNQfTa8pwOy7kx+tOuaMaqvReI6Pt2JGQVNimtaAZMJXYiw
Q83xTk+nTz3W4xkPNSSqrzqgj+fYRTfjx0fvJhmcU9qPai4cr/RGJRHPxhYvMhG6eQYtZOOxkjNK
V2pcfmeJaTl+wIoBOksms454xmJplt3Jxtxt5CQm3QCj2Fg1RTQNnzfchG9VczxkZI0m8dCiV9pU
jqPbY8IVX2ys5gkIDew6m8/aHN2ODHfhOeLMJm0I7iJT+j8U4RtDVD51YdoRdPBRO3G+Gzn6L+g1
w0HmR834n3JfEAOjfxczf8/lEvAaJbwxwW/TsBJ4TKH+JtH2Iw==
--000000000000e9de26063c655a32--
