Return-Path: <kasan-dev+bncBC6OLHHDVUOBBEN4W7CAMGQEMNK25YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CB61B18D25
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Aug 2025 11:44:51 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3e40058db50sf25337675ab.1
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Aug 2025 02:44:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754127890; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wq+IGmxMkIDBXwqGR0TWRmtIEIlLJtq6tVkvAv59VISeljO+gD1WxpoFLp2hZMBvgS
         nX6Q+sReAaOhlvzDkr4xjpfd0BclBzUfgYgtbgkpkWfXWwOljfFvbhyBaZG6+P07qtK6
         xRnZ5bRy/Pox5Pzrrg8gbKOdn+RcLlIvSpa1BJ4DzB8hbQ+1lPAcOQyRnPa9SsvwIoHO
         EbT5TOHEMyGOrxJ+15Xx0A5GE7fs7I51yc0PraLwGTeRyNC1tiVcTO5wi8a6zMq7w/3Y
         AzIeJ65EYk4DoJxPk/RBvS+3/FAfCmGhTjaEsBosgHODDHh6aw0QwXs/PZa5UIE8cneY
         U5EQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xIeQDtpy64V5Zy0K2bq5rlWRFoq48Mhe9Rb/9MRkHIw=;
        fh=UcGSxYgqs2j4imZzB/McEOlhcEDYpqV1nHCM78JJ97k=;
        b=PhOlkN/1kIcOyHvQq4FbCYBQCOwlrV/Gi3BU6KwvUpM4CHKhNlEw6cgzky1PirFCTr
         hlWyVHOY3l5Bswskt3C4svlHOLfNwDn2XQRTTQs5mE1zQfKsCzO9C78cOIIz2MJX5E0Y
         Lyp+MoEacBvjw6VDNJRk9Lb1rLdl6WB6/hZe9dyg1UeZossSyHjCi4ExScAFCntK7q7L
         5PBLDsM9TlY0Tt4gZ493gQMz/5j0FlJb4P45Q2jchy0p4/lFXBXF1DtlXvSpP69xLCNM
         Hl0Q+TO3fLI3KMvgcpzPXl0vIaBr94s6oGkcjqjiZYmC0rIt/1gpXvPJFC62WyOpDdYK
         CHyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AjqZr5Fd;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754127890; x=1754732690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xIeQDtpy64V5Zy0K2bq5rlWRFoq48Mhe9Rb/9MRkHIw=;
        b=GPHgfXqGVsTW4MP76lOu2BKm5L3IgeJKg10gLqeXw5oRYJsnPpTbr2VAl/FukKXcAZ
         yX8l2JCV1VYs8tkbeqjIqQWVG9baIKFg1EWQGTS10fHW71UNrUoBol3KOpDiIKk4lD0z
         nnEudpOwVfCHZz283Z/Xo7ts+FqBYXAxqCL0v1q8rLLMCKkYXLhcinDp48Qkv2T6caJt
         aCvy5UoplPOi2gF89mcEalF1Sdrp5RgZrEcfQW8IvnPT3G2Uc8ASLUUWjsw1j1xzjPZE
         iqftzU5CyTMXzIz3ZjDygQaGrZ5Kmkx7eWkRjVv/ly0ZNBF9aZ2oNkDfQShQyYt+0NWu
         aVNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754127890; x=1754732690;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xIeQDtpy64V5Zy0K2bq5rlWRFoq48Mhe9Rb/9MRkHIw=;
        b=HeZOl+e3n/wzwQvINvkGUnHiHX298AdrlksmkA4BPtEZx5zE7Fr9WQXC8GxOmFgGYK
         0ME+c59MvBv58776nX+5npGRahDqCz4AsKFNex3HKDUJvkjAwj3OsW802eAqi3PwsMVF
         4dRU71j03ti1oJGX8bWsJcYqHxYSCWbBTALvjdiBFJxtwP90OIAV32D8WxFuvkzHz+Wc
         e45d817TrGMPdDd0FzxcQc90+R7Cydkj+g0LPbJmqUl95ByLOXa89RlUo5j/8zOYakj5
         IzAPFsJEfG+Skp++zXelb3MGtuEY72tjtk8L0JlGkjoIjwKXQPcEN6UGbJ3IWKIK9kYO
         yIuQ==
X-Forwarded-Encrypted: i=2; AJvYcCXqVXvOEyY5eD7/wicb+JdJj5SVxULU3VbL1p+KQyObPGnACSg/fDWVPBb3CW6B8qGVr3QrlQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx1EugzUNblS6QzpH3vy7nnZn86IHOJnXpOPPit0/4iOm0qW5Tl
	7RZTSqHll6ujV/GkN+Wwbv9NVr3IjtU9FfJ8LtFOOpeNclDd7Eju5/Vu
X-Google-Smtp-Source: AGHT+IHLKqcmFKqDR0cV4UP8OyApxtEuZIw8XxOizJDTxn9weFLdcZIwTCmO8bgcPTDxFMR1yGe7cA==
X-Received: by 2002:a05:6e02:2407:b0:3e3:f8cb:ab24 with SMTP id e9e14a558f8ab-3e41619966bmr46655255ab.20.1754127890099;
        Sat, 02 Aug 2025 02:44:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfIkmoHioxSLNoG5inLSGAF1Ixc4CSpLEjGNsd9xzTopA==
Received: by 2002:a05:6e02:3e05:b0:3e3:fcdb:e921 with SMTP id
 e9e14a558f8ab-3e4009f4f50ls24078055ab.0.-pod-prod-04-us; Sat, 02 Aug 2025
 02:44:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVTkyjdqdn/z3R0LGJiG+TdgfAu1VUzqQKIPz/VAIQ6rWLSVYevGTbe7dWkj7ikyIU6Wf2pvp9bP4s=@googlegroups.com
X-Received: by 2002:a05:6e02:1f0d:b0:3e3:f1db:d352 with SMTP id e9e14a558f8ab-3e41616f18amr50185855ab.15.1754127888831;
        Sat, 02 Aug 2025 02:44:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754127888; cv=none;
        d=google.com; s=arc-20240605;
        b=DVGLI00xAoRgj2aCQkkFPGAQ4zsttSvJLQJ+El4ey7UC5F6440X6H1Td9JxksnnvTi
         vCi5KAp1sY62dqs7EZeTIi4nODjvwY/K41waW1uVjHQMFSSPeflMHqlO3ZvkNDHu5FxU
         +kroGe39yozVQ3n88SPyTJeOem1ED2RQuXAClAe9o7CfuY6z2PSBAZdWWd2U//CqHmft
         BqlDeg+kJQpQ0zhyRNEBRYpcvM4i3thsrxqHQTHMRayF97tLip9BidinnXB3t6WabD85
         elve12KV2sPQgrGFgtnS4IUAgUquH96CexujDEuCCeuBOiGuwW802/llVt2CPRZdYxwW
         10ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XxeWFy02yGxaSYd+nzfTbW+4NHHzq89SogD7vFOWO08=;
        fh=ahEZG5ImE7agHcn/fY/3+UZnevFixe1P5R63U0keerk=;
        b=Y8CfzDtw5C1ntm+RZelL22uoHQkBPsUnKvO/NhI19xIVDI8fZ/9qzfTTEEuy4dIIBy
         zexnUy50+30yDwsBof7X/ZoSBqI64v+6UqdlFQ8EpxuAYn7U9bXXbTjW9mxRXUakd7YZ
         mnd4W4zJDj4jgAYs+GHtdJmTmcMkUq5HVS0RiZ77f3Fb6AiiNb8YF2UnpEUdG7Og+P8+
         +hExHF2+fa5rxWY70YHLop8E2SJ9NYzInncDHT8zhH/WeW12hu6c/N18H3iuC+6l2B8E
         GUfhMllzF7rDIYeygGJvUBTgl2HFwRDYi81OuLyqHbpxr3JDheV6QsjuxlaQRTsM4UQ5
         6tOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AjqZr5Fd;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e402a13342si2244345ab.2.2025.08.02.02.44.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Aug 2025 02:44:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-70739d1f07bso27480706d6.2
        for <kasan-dev@googlegroups.com>; Sat, 02 Aug 2025 02:44:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXpMgIHBkJ+oP/LkTXayMv+LYJc+2uCfDqMdjJ7xXpKbLZJhxx8Yv73drwx2t6gmL2UYptGZvxEHCg=@googlegroups.com
X-Gm-Gg: ASbGncuA3R6ukF0L9PV+UsLk3KChEdY7x1C63obs6yfZhFgzR1QXQf1F3wGbkBDlHtp
	hyrJPAKapfzM5qPi5+sHDsqCH4EJIdTFFlSo/2ZhsVAc3pusUD2MATETdH1DnPBLS+/LMNUAmlr
	urBBT2u6S1Q3TeVGKSuBfbf2SD6iaZYVZni0xJAG3qk/BeAZlUtZ1/OETIbdC/eVFt0GaYlQVN1
	7bjdcVZAxoe79vgG4Q=
X-Received: by 2002:a05:6214:5283:b0:6fa:ccb6:602a with SMTP id
 6a1803df08f44-70936539ed7mr35394746d6.20.1754127887787; Sat, 02 Aug 2025
 02:44:47 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-2-marievic@google.com>
In-Reply-To: <20250729193647.3410634-2-marievic@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 2 Aug 2025 17:44:34 +0800
X-Gm-Features: Ac12FXyBddcaH4ASc55JFTtU-OzYr71ML2o65LdxQ89fGSsOvq3Er5PhauJVb-c
Message-ID: <CABVgOSkaqvqU7r51tyyNc+NXD9D72zA_3QeYoYYxO6qszkOHCw@mail.gmail.com>
Subject: Re: [PATCH 1/9] kunit: Add parent kunit for parameterized test context
To: Marie Zhussupova <marievic@google.com>
Cc: rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000aff01a063b5eb9f3"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=AjqZr5Fd;       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f2b
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

--000000000000aff01a063b5eb9f3
Content-Type: text/plain; charset="UTF-8"

On Wed, 30 Jul 2025 at 03:37, Marie Zhussupova <marievic@google.com> wrote:
>
> Currently, KUnit parameterized tests lack a mechanism
> to share resources across individual test invocations
> because the same `struct kunit` instance is reused for
> each test.
>
> This patch refactors kunit_run_tests() to provide each
> parameterized test with its own `struct kunit` instance.
> A new parent pointer is added to `struct kunit`, allowing
> individual parameterized tests to reference a shared
> parent kunit instance. Resources added to this parent
> will then be accessible to all individual parameter
> test executions.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---

I'm definitely a fan of this, though it's not without its downsides.

For most tests, I don't think this will be a noticeable difference,
since the "shared" struct kunit is reset after each parameter anyway,
so this is a pretty safe change.

Having a 'parent' struct kunit, and hence potentially a hierarchy,
does give us a good way of implementing more complicated parameterised
tests which might need some more persistent state. (Ultimately, we
could have another level for suites, and then allow
suite_init/suite_exit to setup something persistent, too.)

Anyway, this looks good to me. I've left some small notes below, but
nothing I think is actionable.

Reviewed-by: David Gow <davidgow@google.com>

Cheers,
-- David

>  include/kunit/test.h | 12 ++++++++++--
>  lib/kunit/test.c     | 32 +++++++++++++++++++-------------
>  2 files changed, 29 insertions(+), 15 deletions(-)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index 39c768f87dc9..a42d0c8cb985 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -268,14 +268,22 @@ struct kunit_suite_set {
>   *
>   * @priv: for user to store arbitrary data. Commonly used to pass data
>   *       created in the init function (see &struct kunit_suite).
> + * @parent: for user to store data that they want to shared across
> + *         parameterized tests.

A part of me would prefer this not to explicitly call out
parameterized tests here, as the obvious extensions to this (having
suites have a struct kunit, or other forms of test hierarchy) would
still make use of this in non-parameterised use-cases.

But since parameterised tests are the only current use-case for it, I
can live with it if you'd prefer.

>   *
>   * Used to store information about the current context under which the test
>   * is running. Most of this data is private and should only be accessed
> - * indirectly via public functions; the one exception is @priv which can be
> - * used by the test writer to store arbitrary data.
> + * indirectly via public functions; the two exceptions are @priv and @parent
> + * which can be used by the test writer to store arbitrary data or data that is
> + * available to all parameter test executions, respectively.
>   */
>  struct kunit {
>         void *priv;
> +       /*
> +        * Reference to the parent struct kunit for storing shared resources
> +        * during parameterized testing.
> +        */
> +       struct kunit *parent;
>
>         /* private: internal use only. */
>         const char *name; /* Read only after initialization! */
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index f3c6b11f12b8..4d6a39eb2c80 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -647,6 +647,7 @@ int kunit_run_tests(struct kunit_suite *suite)
>         struct kunit_case *test_case;
>         struct kunit_result_stats suite_stats = { 0 };
>         struct kunit_result_stats total_stats = { 0 };
> +       const void *curr_param;
>
>         /* Taint the kernel so we know we've run tests. */
>         add_taint(TAINT_TEST, LOCKDEP_STILL_OK);
> @@ -679,36 +680,39 @@ int kunit_run_tests(struct kunit_suite *suite)
>                 } else {
>                         /* Get initial param. */
>                         param_desc[0] = '\0';
> -                       test.param_value = test_case->generate_params(NULL, param_desc);
> +                       /* TODO: Make generate_params try-catch */

Thanks for adding the TODO here: this isn't a regression, but it's
good to note that we should get around to fixing it.

> +                       curr_param = test_case->generate_params(NULL, param_desc);
>                         test_case->status = KUNIT_SKIPPED;
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
>                                   "KTAP version 1\n");
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
>                                   "# Subtest: %s", test_case->name);
>
> -                       while (test.param_value) {
> -                               kunit_run_case_catch_errors(suite, test_case, &test);
> +                       while (curr_param) {
> +                               struct kunit param_test = {
> +                                       .param_value = curr_param,
> +                                       .param_index = ++test.param_index,
> +                                       .parent = &test,
> +                               };
> +                               kunit_init_test(&param_test, test_case->name, test_case->log);
> +                               kunit_run_case_catch_errors(suite, test_case, &param_test);
>
>                                 if (param_desc[0] == '\0') {
>                                         snprintf(param_desc, sizeof(param_desc),
>                                                  "param-%d", test.param_index);
>                                 }
>
> -                               kunit_print_ok_not_ok(&test, KUNIT_LEVEL_CASE_PARAM,
> -                                                     test.status,
> -                                                     test.param_index + 1,
> +                               kunit_print_ok_not_ok(&param_test, KUNIT_LEVEL_CASE_PARAM,
> +                                                     param_test.status,
> +                                                     param_test.param_index,
>                                                       param_desc,
> -                                                     test.status_comment);
> +                                                     param_test.status_comment);
>
> -                               kunit_update_stats(&param_stats, test.status);
> +                               kunit_update_stats(&param_stats, param_test.status);
>
>                                 /* Get next param. */
>                                 param_desc[0] = '\0';
> -                               test.param_value = test_case->generate_params(test.param_value, param_desc);
> -                               test.param_index++;
> -                               test.status = KUNIT_SUCCESS;
> -                               test.status_comment[0] = '\0';
> -                               test.priv = NULL;
> +                               curr_param = test_case->generate_params(curr_param, param_desc);
>                         }
>                 }
>
> @@ -723,6 +727,8 @@ int kunit_run_tests(struct kunit_suite *suite)
>
>                 kunit_update_stats(&suite_stats, test_case->status);
>                 kunit_accumulate_stats(&total_stats, param_stats);
> +               /* TODO: Put this kunit_cleanup into a try-catch. */
> +               kunit_cleanup(&test);

Hmm... it is a shame we can't easily include this in the existing
try-catch mechanism. Definitely worth fixing in a follow-up.


>         }
>
>         if (suite->suite_exit)
> --
> 2.50.1.552.g942d659e1b-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSkaqvqU7r51tyyNc%2BNXD9D72zA_3QeYoYYxO6qszkOHCw%40mail.gmail.com.

--000000000000aff01a063b5eb9f3
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
0TANBglghkgBZQMEAgEFAKCBxzAvBgkqhkiG9w0BCQQxIgQgjq0kHLJKgEPSKYFuzbuqT1jG2Lz7
9JXirfk9/r/YZtgwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUw
ODAyMDk0NDQ4WjBcBgkqhkiG9w0BCQ8xTzBNMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
YIZIAWUDBAECMAoGCCqGSIb3DQMHMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcN
AQEBBQAEggEAAnW7hmThK50h5iMzYqnRT7s1V+I4foLcmYhnfX7tYIkHcPUBcGn5NwXDfWRthkLr
El1ajeJt0yQvO3GwjK3JCDjU5diH/Ug+YB246MqdtiW6nuEo98V1pi9yagXxCruj/VRwgIwsDpXi
WSBmhuswm3E1F9LwONpl9R1lolU8U1VywH5bpmojenp+s4J7BSn/hYGiPJbR08ZNPx3EEusQiYXt
j3EbsQf8+rZn06iT4nyCOkNum4mbmHACIFs4m01BdlRXWbEo0QjLxNttVyANw+Dww2pQaOBomxGR
xX1zkP4+PHEKmMBDECY/FH8ggK8Eoj6RaReOs8aAhB91wKXCVw==
--000000000000aff01a063b5eb9f3--
