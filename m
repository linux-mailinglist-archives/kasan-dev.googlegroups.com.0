Return-Path: <kasan-dev+bncBC6OLHHDVUOBBFN4W7CAMGQEXMWXEGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 98715B18D2A
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Aug 2025 11:44:55 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-87c056ae7c0sf516249939f.2
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Aug 2025 02:44:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754127894; cv=pass;
        d=google.com; s=arc-20240605;
        b=EHkNHFYyhj+E0LNKm6+oWW6+tAFdE+/kQNcNw78owNlsuQtCHsPcwjL9cXfxYvqDrv
         3/Zo5n+NlNzEzStP8Jq5rw8aCRqbsBL+AXdY+oBuhWzObo+z16wTv7NpItWaVqt2qi8a
         ZZ8Tik8hyEg5ssm/hmgNVPcz2UIGwmb8YxCQYDeRcI8Yox0bDyJ2Y1oPKjRviA+BE2CC
         ElyqpgST2cWIjxVr6WdPmN/oh4swNCNnCuo6m9XMaZjKbN+k32oIivuEfIEnIyVHfj55
         pNnSRfUbLMbRb7Jxp7+EPlUmlRsJqbkypRHuwD6GjUMfnZJOK7NGK22lPDuEiMz5C9OP
         NSEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=F0IAzX1SYupT3KJ6135ID7kiug1gPRXxVyOloRO9Cmw=;
        fh=xmhE2ZXp/8f4JGSjoz7c7uiPv32xj2eYPWkxGbr0x+A=;
        b=B1UE3eZb2ipAVqLNwX4DFo5xjLZmFKM1R1V56Tlo4JUYrjm1oKd3tEXPIoahlq3uKr
         np/UbiKyDrg3a9OfL/Xdwsn0It2joN+2Ti/a0RN/8wl6T+FvEjvQ61RpOgOCho5qUIPA
         S95LUYm0XvP86YrsTTNGcIehRoznPqBlo5dMtMFZKpnlh3JJwFy+WoV745KQsnApEH8j
         eYuupfqsf+HVaX60SvxZ4mmElAb64UFQg15OwK8y/rCYNHkoO++QK6pMQpKIySJPxOej
         /X+hWVKprOKF4U+i0h9nac6gx01gQBMSSDsm4xFW8XWvFMksTvTrOlOjwxwcXr3YjcRd
         7FTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QsK2tKYu;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754127894; x=1754732694; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=F0IAzX1SYupT3KJ6135ID7kiug1gPRXxVyOloRO9Cmw=;
        b=MPrYqsegv2gMVnQLEiopy8C2NTgwUQzwli5ZPgEtq9rfI5jgkf0bgKc5tf0plMxD3w
         kEMbtw3J4Y/1KcgMaXyPgj0o4sdzLbvXFfBDjDwANbU5aFKi4j9UE6rfNdAE0e9KMzni
         Z2UWI7y7BSjJA2jUkT0Ka5CojiNG51SpoJzuAMSK+5/uLbc2Z/vQD6+vSjBcbpaKbJlM
         kvZfe5PTmnXxjzd6aMSN8n40YL9wcJK2Z0GqLxfmR2I97EDDIJUQ9Dvi24k+ByfmRVQ2
         PGakfNujPcL56+PzyHpF0FrZgBKKw1W1B+HrGkkVDios200e1KTTv4cDOr8VEpyXLVMp
         Y9nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754127894; x=1754732694;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F0IAzX1SYupT3KJ6135ID7kiug1gPRXxVyOloRO9Cmw=;
        b=JR895jHSngbtuq+AsP1SxLHYzWZnz5MbdZ0j8of4tHURzvlzHNw4IJ5au8qjt8RDMC
         NXs4TPfiDj9HLSZkUaHdeCe6mBg+kWVOxETuluIyBmyr9B92Pn44TigJPizBcoKsJymA
         4j6laG0U+gzbssqxuq1xvwcNZdx3cejCuVw9MD3SYBhKWMwLp3mhEFNZUNTHdHKtjEdY
         XKNuB4OjIP9/SkQIcSUrTFz3oc6q1tXo2UifZLh+mIolUOC0092LVkJ+3p7DPYEh/Owx
         XdMENjCFYFJ4zc5hrSg+PVwixPhsF8udBxVuGMRMhf8V0abVWxWgfeoDtTea/5I6lHiZ
         Hefw==
X-Forwarded-Encrypted: i=2; AJvYcCUZsGkhMm2Qg7uDen9d+NakGoXU8wcx2bBqb7MvOhJjKmFQaic5+D8rw6lArNLmalg9Y3WcoQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyh02PsiPtS+XsMRG8l8zt8PD4I85/C+ZoIn16rlyCNtn4jP1ql
	PMmwhhtyWdRW1BeHUrTLhpE92wBk4Vb9PcOo73ZtLPJiplPmUUVJkzpg
X-Google-Smtp-Source: AGHT+IGNYz3vdlNCJaA1oiJs30OuCtjtk/Eq9UtuJkEbhXK2LJSmlzsVYzTI6wqj+8ANPgZTJ4HFng==
X-Received: by 2002:a05:6e02:4701:b0:3e3:b45b:2c9 with SMTP id e9e14a558f8ab-3e4161d3f99mr44495915ab.19.1754127894031;
        Sat, 02 Aug 2025 02:44:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfurqelAQQuEkjgg23GrZJC8fAKC0u9V6JF+PcDAZoJCA==
Received: by 2002:a92:ca4d:0:b0:3e0:5c71:88f9 with SMTP id e9e14a558f8ab-3e4024e626cls33717905ab.1.-pod-prod-02-us;
 Sat, 02 Aug 2025 02:44:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVfqG3Lz7uH7h7YpG5zvJwbNJgbsk8/GGRnDCZeMNBkAzWnHrwE4J78T9XYHNQOB0yNgXWu/fa7pLE=@googlegroups.com
X-Received: by 2002:a05:6e02:440c:20b0:3e3:f9fa:2c8c with SMTP id e9e14a558f8ab-3e4161928a1mr32932465ab.12.1754127893112;
        Sat, 02 Aug 2025 02:44:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754127893; cv=none;
        d=google.com; s=arc-20240605;
        b=M1KldeS0AL5fNwnXbQMnDu2ql7lXRngZ7S2KTN73ndvGdsSmp4I6Hzs/ZpQGtB/ON8
         W4eRNQgakfQgTGNS7n+RWquIl47U0uo8ZB0Yw1otQYp7wx4ICnAXKxy9ofyIlefRNQgn
         ArSQQVk6WTONeb5Y/HZH0bzVh/1bqx/d9P+dOWyYgJeMV74nUy7kojadG1L1CDw/oVOS
         2zfVSlJednOT6Q4wvn4o8kO6NPgvMErzPbKd00nlnxEMC4sZRrqyflvs+py1JkPraEcA
         CBUzTiO3PGJEhVFH6JdvbfBKRn5OfB9oNg7KLxMbpq0oUqhtEyRLL73exrToaDt21Yoi
         wtoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FtJgif/JJwFNo88scdGnRjoeFxiBFkMGzgjJv82eG3A=;
        fh=TttE5wyX641VkRYxydV99cL57QmFykP2j0coSqdtCvQ=;
        b=ar5wpJDN9F20LSlvjYYDU+fuLz26zIxi4qhn+zqH67CRJzlpXEn7Lua3EyGXPRAHsR
         lu+qxRyIRY3ffd4i4edGG3xmGMaQBrw3VOPgzinxdVlqLLEQsXaGA5Gl9YR07g/srKJu
         jCXR4fTl5jTXq14YeVZ4jn93rW9rMKyjOC2Hhgm4XmuGw3Accb7dfDSW71v9iwJOOMim
         wBdDWneeuscqkaeZWpnIA+oyZreMeBjeWlbHD7XPWHosRoxNMBuH+2oZdaaVnUryz0K7
         V/RrRws1WFx6mscZLWLRTuD2dHriWlSS0l97x9mLCYP64Ha0TRwI2uf7cBoaCBcUYNu9
         XQFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QsK2tKYu;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e402b1e315si2490075ab.4.2025.08.02.02.44.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Aug 2025 02:44:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-70749d4c598so26153816d6.0
        for <kasan-dev@googlegroups.com>; Sat, 02 Aug 2025 02:44:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX4uUmE8RLFRrGEcnCEEWEOg8Me/1/oBZLfo0xAe1qDcTQ1jDYD5NFEadS+CmqDbgydzbw2k/V5Jqw=@googlegroups.com
X-Gm-Gg: ASbGncuiCmREYpN1QDd5B2k4CuVoAuffXIqSC0JxTNSOTVjXD6yF90Ag5qloQqZv8TC
	ILU8SiZ7jwJpfTYgiXXoTYqUEV0T0BTIaPRvvjw7L9n0hfvA2AsIVZpVD2A+GBjqZELzW3V1XFv
	nANxTcztSyHZk1MsZEFmw0YldKSGy0Eb2y4tFhyWU2H3yaluD+shd9ejORjqqbaUlfSALFa0eWU
	Z5nnfv4
X-Received: by 2002:a05:6214:2a4c:b0:707:4229:6e8c with SMTP id
 6a1803df08f44-70935f7681dmr45877396d6.12.1754127892104; Sat, 02 Aug 2025
 02:44:52 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-3-marievic@google.com>
In-Reply-To: <20250729193647.3410634-3-marievic@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 2 Aug 2025 17:44:39 +0800
X-Gm-Features: Ac12FXzXfGgkKw84HTUHTA1VpjNWzhFIir87zpRY1R2N1G6lbLlU-1K1xKejtKg
Message-ID: <CABVgOS=6kNCrFZXC2RZGBSb0QNng++kNjEtLr++rS+O+Txd_+w@mail.gmail.com>
Subject: Re: [PATCH 2/9] kunit: Introduce param_init/exit for parameterized
 test shared context management
To: Marie Zhussupova <marievic@google.com>
Cc: rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000f1242e063b5eb9a1"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=QsK2tKYu;       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f29
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

--000000000000f1242e063b5eb9a1
Content-Type: text/plain; charset="UTF-8"

On Wed, 30 Jul 2025 at 03:37, Marie Zhussupova <marievic@google.com> wrote:
>
> Add `param_init` and `param_exit` function pointers to
> `struct kunit_case`. Users will be able to set them
> via the new `KUNIT_CASE_PARAM_WITH_INIT` macro.
>
> These functions are invoked by kunit_run_tests() once before
> and once after the entire parameterized test series, respectively.
> They will receive the parent kunit test instance, allowing users
> to register and manage shared resources. Resources added to this
> parent kunit test will be accessible to all individual parameterized
> tests, facilitating init and exit for shared state.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---

Thanks: this looks good to me, modulo the issues below (particularly
the Rust breakage).

I was initially unsure of the names 'param_init' and 'param_exit',
preferring just 'init'/'exit', but have since come to like it, as
otherwise it'd be easy to confuse it with the kunit_suite init/exit
functions, which behave differently. So happy to keep that.

With the Rust issue fixes, this is:
Reviewed-by: David Gow <davidgow@google.com>

Cheers,
-- David

>  include/kunit/test.h | 33 ++++++++++++++++++++++++++++++++-
>  lib/kunit/test.c     | 23 ++++++++++++++++++++++-
>  2 files changed, 54 insertions(+), 2 deletions(-)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index a42d0c8cb985..d8dac7efd745 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -92,6 +92,8 @@ struct kunit_attributes {
>   * @name:     the name of the test case.
>   * @generate_params: the generator function for parameterized tests.
>   * @attr:     the attributes associated with the test
> + * @param_init: The init function to run before parameterized tests.
> + * @param_exit: The exit function to run after parameterized tests.
>   *
>   * A test case is a function with the signature,
>   * ``void (*)(struct kunit *)``
> @@ -129,6 +131,13 @@ struct kunit_case {
>         const void* (*generate_params)(const void *prev, char *desc);
>         struct kunit_attributes attr;
>
> +       /*
> +        * Optional user-defined functions: one to register shared resources once
> +        * before the parameterized test series, and another to release them after.
> +        */
> +       int (*param_init)(struct kunit *test);
> +       void (*param_exit)(struct kunit *test);
> +

As noted by the test robot, these need to be initialised in
rust/kernel/kunit.rs when a kunit_case is being set up. Since
parameterised tests aren't used in Rust, they can just be set to None.

>         /* private: internal use only. */
>         enum kunit_status status;
>         char *module_name;
> @@ -218,6 +227,27 @@ static inline char *kunit_status_to_ok_not_ok(enum kunit_status status)
>                   .generate_params = gen_params,                                \
>                   .attr = attributes, .module_name = KBUILD_MODNAME}
>
> +/**
> + * KUNIT_CASE_PARAM_WITH_INIT() - Define a parameterized KUnit test case with custom
> + * init and exit functions.
> + * @test_name: The function implementing the test case.
> + * @gen_params: The function to generate parameters for the test case.
> + * @init: The init function to run before parameterized tests.
> + * @exit: The exit function to run after parameterized tests.
> + *
> + * Provides the option to register init and exit functions that take in the
> + * parent of the parameterized tests and run once before and once after the
> + * parameterized test series. The init function can be used to add any resources
> + * to share between the parameterized tests or to pass parameter arrays. The
> + * exit function can be used to clean up any resources that are not managed by
> + * the test.
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
> @@ -269,7 +299,8 @@ struct kunit_suite_set {
>   * @priv: for user to store arbitrary data. Commonly used to pass data
>   *       created in the init function (see &struct kunit_suite).
>   * @parent: for user to store data that they want to shared across
> - *         parameterized tests.
> + *         parameterized tests. Typically, the data is provided in
> + *         the param_init function (see &struct kunit_case).
>   *
>   * Used to store information about the current context under which the test
>   * is running. Most of this data is private and should only be accessed
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index 4d6a39eb2c80..d80b5990d85d 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -641,6 +641,19 @@ static void kunit_accumulate_stats(struct kunit_result_stats *total,
>         total->total += add.total;
>  }
>
> +static void __kunit_init_parent_test(struct kunit_case *test_case, struct kunit *test)

There's no fundamental reason this needs to start '__': other internal
functions here don't.

(But please keep it static and internal.)

> +{
> +       if (test_case->param_init) {
> +               int err = test_case->param_init(test);
> +
> +               if (err) {
> +                       kunit_err(test_case, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
> +                               "# failed to initialize parent parameter test.");
> +                       test_case->status = KUNIT_FAILURE;
> +               }
> +       }
> +}
> +
>  int kunit_run_tests(struct kunit_suite *suite)
>  {
>         char param_desc[KUNIT_PARAM_DESC_SIZE];
> @@ -668,6 +681,8 @@ int kunit_run_tests(struct kunit_suite *suite)
>                 struct kunit_result_stats param_stats = { 0 };
>
>                 kunit_init_test(&test, test_case->name, test_case->log);
> +               __kunit_init_parent_test(test_case, &test);
> +
>                 if (test_case->status == KUNIT_SKIPPED) {
>                         /* Test marked as skip */
>                         test.status = KUNIT_SKIPPED;
> @@ -677,7 +692,7 @@ int kunit_run_tests(struct kunit_suite *suite)
>                         test_case->status = KUNIT_SKIPPED;
>                         kunit_run_case_catch_errors(suite, test_case, &test);
>                         kunit_update_stats(&param_stats, test.status);
> -               } else {
> +               } else if (test_case->status != KUNIT_FAILURE) {
>                         /* Get initial param. */
>                         param_desc[0] = '\0';
>                         /* TODO: Make generate_params try-catch */
> @@ -727,6 +742,12 @@ int kunit_run_tests(struct kunit_suite *suite)
>
>                 kunit_update_stats(&suite_stats, test_case->status);
>                 kunit_accumulate_stats(&total_stats, param_stats);
> +               /*
> +                * TODO: Put into a try catch. Since we don't need suite->exit
> +                * for it we can't reuse kunit_try_run_cleanup for this yet.
> +                */
> +               if (test_case->param_exit)
> +                       test_case->param_exit(&test);

Not thrilled that this is introducing another TODO here, but since we
already have a number of places around parameterised tests where we're
not running things from the separate try-catch thread, I don't think
we should hold up useful features on it. The actual test code is still
properly handled.

But I'm looking forward to going through and cleaning all of these up
at some point.


>                 /* TODO: Put this kunit_cleanup into a try-catch. */
>                 kunit_cleanup(&test);
>         }
> --
> 2.50.1.552.g942d659e1b-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOS%3D6kNCrFZXC2RZGBSb0QNng%2B%2BkNjEtLr%2B%2BrS%2BO%2BTxd_%2Bw%40mail.gmail.com.

--000000000000f1242e063b5eb9a1
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
0TANBglghkgBZQMEAgEFAKCBxzAvBgkqhkiG9w0BCQQxIgQgJYINxxie/13U5jFi7vMOJrN1B+jz
qsl6IBheTGriGFMwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUw
ODAyMDk0NDUyWjBcBgkqhkiG9w0BCQ8xTzBNMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
YIZIAWUDBAECMAoGCCqGSIb3DQMHMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcN
AQEBBQAEggEAJBBWiTpZp591aYHuf1phoJoSMxSuXByUlal1YaJJz57zWxZXjhWWZ6CzEjTZDXm0
asU9ZFf1Ocki7XH2Xrv+6QU6mDCz7UrDjV4EaJNVOrj6hEb1zO25iBBFdO+/ZepAdethv2lF3Q+m
2uY1fHVNjU2QxuarQOjZSx4PMEQKnapCSElxH2cXLlYmhf5LeI9rjM2ye9AOsXMr6OT/MsKRo5i2
W7UxisSIUkzysRXE/IacxRg8wLzrckqMJyT4YwV5vxuZNmgVVj3aKKKUXMwXxUmKWsXrQ4movkEm
I4eQ5HU3+ZnlXLOaA+BAyUATTI2ZpKgcBO87BSmjnP7F+jb6qw==
--000000000000f1242e063b5eb9a1--
