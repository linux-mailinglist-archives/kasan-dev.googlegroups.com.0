Return-Path: <kasan-dev+bncBDPPVSUFVUPBBX6BZDCAMGQELR72T4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 51468B1B747
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 17:18:57 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id 5614622812f47-41c5eac5214sf5389729b6e.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 08:18:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754407136; cv=pass;
        d=google.com; s=arc-20240605;
        b=C++iF2Vp4yIVcL+DkM4Dc5hmkButidker0JiJr3/rOoBBS9DCPG8nZ5epra8nlXZAn
         2drkbMsERduIdtV+jFmjPD2jj+2yGM00KiYP8WGMgSBhgvWd47tCtTI5qNEHB9SbC6NG
         5e+bmaK683ZVSN+zTKhueJDvVV+zJrPJmAZ+vkQHbVqqNISMNrNd9p3u5T7g8uNmyXol
         2QR7h2tK//Dwc6DiEb3xlfdYv6jQ+WqJ7b5wWKwulFANP8/DGyaIoCq4nhgtCfsQ2VtG
         HP7AXvxr4PHUgXFBiPlQtqqUFKWx0NMFwk0r5710G/VSionDELPy+K1khrJFbGid7OD6
         MBig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=olNsFMCMKzHCjtPBuowUFPW8HnYM9spbIVcynhxXplE=;
        fh=SSBLJhtlM0n+tm+9UlFqhZWWIcC3LJNdZs0aHba9NM8=;
        b=E8Pw56bBwhccUSTULxxGgqg8+1kWuGxyBI8KNKRHTVuxpPZjGkOckEEQtsbxiK2qyC
         8kqQ+KGpe0I5O/Ma4XOIySMIuws4Lu/pVO8U4ergllKEuPnuPZAUx8nbadNpY8tuKOn3
         dw3+vZTl6mQSQ9Wgfz3VXz6XXDZLmo9rKw+G3DqpRwT5VpER/ygjVCgfJzfzAJTRplee
         ceswHv7cz+VOZtATpSU+JgTpY6ezC2OJdmc7GEyuxV6TSad7v2vnTg5WEyR0BYxY7dD8
         Gn0PM2FAoVrNguLmIAi3SjXPl12ZtlufChLJqdPw+4pUsx+159LfNn+s95x5hqYCnmB+
         /Vtw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=M7Sysbx2;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754407136; x=1755011936; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=olNsFMCMKzHCjtPBuowUFPW8HnYM9spbIVcynhxXplE=;
        b=h5aAe08SO66/eLIi3Hj86w8DqsiGwhGeXLdxk1GIKDWch0HKQcYzMxqqHNM2HR3KRt
         LDW6eQS9SqdcrUtznychVTg6JPkZuqXGHTlMK1+P60WqsdnmTvnenRKIARCrjkRlAsfN
         aLN1M3FZUaeeF45RuSeQzV/H4M4Rxn7N+gxPv8HLAZ47ixlqe3fGx0XUdouQq2bkxCFz
         05CJ5WzDarzkMLsNIFJYUTimQURi2yxyWTNOB7yrjVOD5hNFF32rzEy0KJDorSMiJePa
         TnLi5qmUobdXJM/6JIg3M4PkM6qmdj8PmMJSCX8BtojOemI/nh1b6QSs1Wa+o08Yn7xc
         1u4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754407136; x=1755011936;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=olNsFMCMKzHCjtPBuowUFPW8HnYM9spbIVcynhxXplE=;
        b=wj3CsfmOoSsLMiJaYe0rdALomulteEVEAaYO0nqCSoBQFg3uCiNrwmWBOhqaJkzahS
         cy97jEPQSnhMj2RCN0UQWY1yYqpBs4oaMMPWsCrwUIQo776Q/vfFxsPV0g/SNiriQ2nr
         OUH9Svmu0bOO8d2q8EjyFWyctuKQi2u8JN5pzprGyeW3y3vCtUAhJI/5F9/HSV+JL4XH
         9MiYYauhg7ty8rxeZ7uBtsUt7lqj3ZwF4qoDodre7+yW5vawrum2L450c2jizrf4OfTW
         FGERfi9MbNpSiz7UKihlnNfQ/PiaWwaz+7VgumhQf0weeKr1J3rVTurJA85VP/D57uk8
         Sa+A==
X-Forwarded-Encrypted: i=2; AJvYcCWV33QMT3nUpE4jX/Fd2u8sGWz9Zy2q++BGpQccCBdsOj/63FjQUMEs+hBkOqlEBCoNZu5KvA==@lfdr.de
X-Gm-Message-State: AOJu0YzUVTeuZaDGMGSeziKyAGtmRKCVdhcLsy+/wP6jHvPs/5LRWNLo
	Yw3VZz2r9PNJBRg5QZnjJanGAZM59gfIe4tE74/uzZgu3aHVuSaHIpfX
X-Google-Smtp-Source: AGHT+IHccU62XZuqpT8rCBw8lW3hZEaoLVCAlpdKqmBsiN9ZT0nq9IFCKJCWalPriHn9mqN4tBYM5g==
X-Received: by 2002:a05:6808:2518:b0:435:73d5:41b8 with SMTP id 5614622812f47-43573d54f53mr1022790b6e.25.1754407135612;
        Tue, 05 Aug 2025 08:18:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZchqDx3C4dYIoWDE74jhZFJPqkn7iXQF8TnSx2ry0u0ng==
Received: by 2002:ad4:4ea3:0:b0:707:2629:964c with SMTP id 6a1803df08f44-707769a706dls85592596d6.0.-pod-prod-03-us;
 Tue, 05 Aug 2025 08:18:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrN9XysAnTFPS9ep93jHUJ8ViS6oy58tMUkMKeGGXdgtEjxg0g88pcn8LgO1AgAIv7z7jRSH4UwtM=@googlegroups.com
X-Received: by 2002:a05:6122:46aa:b0:531:312c:a710 with SMTP id 71dfb90a1353d-5395f1f8548mr6281493e0c.6.1754407134597;
        Tue, 05 Aug 2025 08:18:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754407134; cv=none;
        d=google.com; s=arc-20240605;
        b=YzLYUnqr9eb/7A2idFiik9l0LbPBfnZ+tJNXftkeg4aVyEPvtX1XOnPBg30LAicvNM
         j8O2zquj0x+PnEhlzxzY7HBRcKYvgt+pm5NpbvZy7cxs2ANvkw7XShrJBXDRqzthnz99
         5edcbkXDIGTve0FAnJOmSq466P/fCBlFCHqLAbXlEajh8Nc+VYR/Zy8t0CwqXLMyD90W
         RBx+kQAeOMWN3BedxHIsycS+MYXS5tDAKkdVSawgPnuib0PgdphQGs5tMS2X9iVMCZkr
         Zh3hsbKH2iSg0MH9ELIqQhQz3JIDlfLPt4MdnsV9cJQUxCpP9e+CgdgUMeDBdjmrc08s
         gOlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7HJX1dAULQPf05eofh/qdij5Fv1pcs+BHpuoBOdIhSk=;
        fh=EXsnaU/MhkSyQ6s0h54DPhSKHDzgxwdd1i8wLupRTvM=;
        b=QH+IN/q/X8WOKDTa3ahFyd+qXBno3zyS6bnFP4wJAwi0GUu6MiWELIRTQ5E7zw87YO
         6F0NepSBBJPqb241PImOSDg9Hx3gQzTpSlKtLmK4caIMqN1uvd5KxCWZnTLYn7m4EFf4
         1aNAeK9+cAq/xJf+NHZNNDuaWvVl5+Ztm2FWldptWzEysuByzQhJFGDiW7CICxjneaZF
         DqfTT7xt+IGmdCaAw6+NncbOjtcOJmqwPTpYeyH/poz0HBGK9toKjOPkYUmvqZ7Urv4b
         GKWO10Ceo4FlyQ0xsixbUVZbSUkuFrG7vvT8Kg5F+Utt9FGtH3xf1Daaem8R1baEVpk0
         Zd3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=M7Sysbx2;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53936c9c11csi545393e0c.3.2025.08.05.08.18.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 08:18:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id d75a77b69052e-4b062b6d51aso27208171cf.2
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 08:18:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWNdy56oTQsB97sBBy5HL1oKccyiVztOiRDZ5VWvPTyf+sG3W1k7w7M4tmw6Q5Y317VqaipDbLThN4=@googlegroups.com
X-Gm-Gg: ASbGnctumYamHZUjvG6E6OdG3ZH9gB6xStNvDlN5NAM+o9m0kUVN7XPcv6qJ9uKEM87
	uZxRIMyi5uc1BeNkwxbdE2NaJdL/308SY2Xky0CxEs7Yap67/jsj1mqlYK6Vp6g1XaTNlRZfUOs
	AJyLOlYtWXJLiWYoegW+uakf72C77YFg06K9iaBzqTMcclUD/itcaQT5CGv23m1YtwYEo6w+U0/
	n5DBpBQXWczLHOhtESysQlrFzd8qXamemArR8MEykC7bHSkb/QW
X-Received: by 2002:a05:6214:262b:b0:707:4539:5183 with SMTP id
 6a1803df08f44-70935ea93cfmr185305046d6.5.1754407133193; Tue, 05 Aug 2025
 08:18:53 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-7-marievic@google.com>
In-Reply-To: <20250729193647.3410634-7-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Aug 2025 11:18:42 -0400
X-Gm-Features: Ac12FXxnJBB1YWr-XbyGzOFY7Eh7XZaJzVBa5N68AZZyN0_GMOzIt18D0BHtBBQ
Message-ID: <CA+GJov7AH5Qyiaua7LKZjVNRoUd==DiSXvd1UP7TcSzvn5JZtQ@mail.gmail.com>
Subject: Re: [PATCH 6/9] kunit: Enable direct registration of parameter arrays
 to a KUnit test
To: Marie Zhussupova <marievic@google.com>
Cc: davidgow@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: rmoar@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=M7Sysbx2;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::833 as
 permitted sender) smtp.mailfrom=rmoar@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Rae Moar <rmoar@google.com>
Reply-To: Rae Moar <rmoar@google.com>
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

On Tue, Jul 29, 2025 at 3:37=E2=80=AFPM Marie Zhussupova <marievic@google.c=
om> wrote:
>
> KUnit parameterized tests currently support two
> primary methods for getting parameters:
> 1.  Defining custom logic within a `generate_params`
>     function.
> 2.  Using the KUNIT_ARRAY_PARAM and KUNIT_ARRAY_PARAM_DESC
>     macros with pre-defined static arrays.
>
> These methods present limitations when dealing with
> dynamically generated parameter arrays, or in scenarios
> where populating parameters sequentially via
> `generate_params` is inefficient or overly complex.
>
> This patch addresses these limitations by adding a new
> `params_data` field to `struct kunit`, of the type
> `kunit_params`. The struct `kunit_params` is designed to
> store the parameter array itself, along with essential metadata
> including the parameter count, parameter size, and a
> `get_description` function for providing custom descriptions
> for individual parameters.
>
> The `params_data` field can be populated by calling the new
> `kunit_register_params_array` macro from within a
> `param_init` function. By attaching the parameter array
> directly to the parent kunit test instance, these parameters
> can be iterated over in kunit_run_tests() behind the scenes.
>
> This modification provides greater flexibility to the
> KUnit framework, allowing testers to easily register and
> utilize both dynamic and static parameter arrays.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>

Hello!

Very excited by the prospect of setting up an array dynamically
instead of statically for parameterized tests. In general, I am happy
to see this framework is becoming more flexible and therefore more
tailored to our test author's needs.

I already commented on the modpost error but I have a few more
comments and ideas below. Let me know what you think.

Thanks!
-Rae

> ---
>  include/kunit/test.h | 54 ++++++++++++++++++++++++++++++++++++++++----
>  lib/kunit/test.c     | 26 ++++++++++++++++++++-
>  2 files changed, 75 insertions(+), 5 deletions(-)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index 4ba65dc35710..9143f0e22323 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -245,7 +245,8 @@ static inline char *kunit_status_to_ok_not_ok(enum ku=
nit_status status)
>   */
>  #define KUNIT_CASE_PARAM_WITH_INIT(test_name, gen_params, init, exit)   =
       \
>                 { .run_case =3D test_name, .name =3D #test_name,         =
           \
> -                 .generate_params =3D gen_params,                       =
         \
> +                 .generate_params =3D (gen_params)                      =
         \
> +                  ?: kunit_get_next_param_and_desc,                     =
       \
>                   .param_init =3D init, .param_exit =3D exit,            =
           \
>                   .module_name =3D KBUILD_MODNAME}
>
> @@ -294,6 +295,21 @@ struct kunit_suite_set {
>         struct kunit_suite * const *end;
>  };
>
> +/* Stores the pointer to the parameter array and its metadata. */
> +struct kunit_params {
> +       /*
> +        * Reference to the parameter array for the parameterized tests. =
This
> +        * is NULL if a parameter array wasn't directly passed to the
> +        * parent kunit struct via the kunit_register_params_array macro.
> +        */
> +       const void *params;
> +       /* Reference to a function that gets the description of a paramet=
er. */
> +       void (*get_description)(const void *param, char *desc);
> +
> +       int num_params;

Since in some cases we know the number of params within a series/suite
of the parameterized tests, is it possible for us to print a test plan
line in KTAP when this number is known? This would be helpful for
reading test results but also the parser could verify the number of
subtests is the number expected.

> +       size_t elem_size;
> +};
> +
>  /**
>   * struct kunit - represents a running instance of a test.
>   *
> @@ -302,12 +318,14 @@ struct kunit_suite_set {
>   * @parent: for user to store data that they want to shared across
>   *         parameterized tests. Typically, the data is provided in
>   *         the param_init function (see &struct kunit_case).
> + * @params_data: for users to directly store the parameter array.
>   *
>   * Used to store information about the current context under which the t=
est
>   * is running. Most of this data is private and should only be accessed
> - * indirectly via public functions; the two exceptions are @priv and @pa=
rent
> - * which can be used by the test writer to store arbitrary data or data =
that is
> - * available to all parameter test executions, respectively.
> + * indirectly via public functions. There are three exceptions to this: =
@priv,
> + * @parent, and @params_data. These members can be used by the test writ=
er to
> + * store arbitrary data, data available to all parameter test executions=
, and
> + * the parameter array, respectively.
>   */
>  struct kunit {
>         void *priv;
> @@ -316,6 +334,8 @@ struct kunit {
>          * during parameterized testing.
>          */
>         struct kunit *parent;
> +       /* Stores the params array and all data related to it. */
> +       struct kunit_params params_data;

I might slightly prefer the term params_array rather than params_data.
Up to what you prefer.

>
>         /* private: internal use only. */
>         const char *name; /* Read only after initialization! */
> @@ -386,6 +406,8 @@ void kunit_exec_list_tests(struct kunit_suite_set *su=
ite_set, bool include_attr)
>  struct kunit_suite_set kunit_merge_suite_sets(struct kunit_suite_set ini=
t_suite_set,
>                 struct kunit_suite_set suite_set);
>
> +const void *kunit_get_next_param_and_desc(struct kunit *test, const void=
 *prev, char *desc);
> +
>  #if IS_BUILTIN(CONFIG_KUNIT)
>  int kunit_run_all_tests(void);
>  #else
> @@ -1735,6 +1757,30 @@ do {                                              =
                              \
>                 return NULL;                                             =
                       \
>         }
>
> +/**
> + * kunit_register_params_array() - Register parameters for a KUnit test.
> + * @test: The KUnit test structure to which parameters will be added.
> + * @params_arr: An array of test parameters.
> + * @param_cnt: Number of parameters.
> + * @get_desc: A pointer to a function that generates a string descriptio=
n for
> + * a given parameter element.
> + *
> + * This macro initializes the @test's parameter array data, storing info=
rmation
> + * including the parameter array, its count, the element size, and the p=
arameter
> + * description function within `test->params_data`. KUnit's built-in
> + * `kunit_get_next_param_and_desc` function will automatically read this
> + * data when a custom `generate_params` function isn't provided.
> + */
> +#define kunit_register_params_array(test, params_arr, param_cnt, get_des=
c)                     \

I also might slightly prefer params_array and param_count here instead
of params_arr and param_cnt. Again this is definitely a nitpick so up
to you.

> +       do {                                                             =
                       \
> +               struct kunit *_test =3D (test);                          =
                 \
> +               const typeof((params_arr)[0]) * _params_ptr =3D &(params_=
arr)[0];                 \
> +               _test->params_data.params =3D _params_ptr;               =
                         \
> +               _test->params_data.num_params =3D (param_cnt);           =
                         \
> +               _test->params_data.elem_size =3D sizeof(*_params_ptr);   =
                         \
> +               _test->params_data.get_description =3D (get_desc);       =
                         \
> +       } while (0)
> +
>  // TODO(dlatypov@google.com): consider eventually migrating users to exp=
licitly
>  // include resource.h themselves if they need it.
>  #include <kunit/resource.h>
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index f50ef82179c4..2f4b7087db3f 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -337,6 +337,13 @@ void __kunit_do_failed_assertion(struct kunit *test,
>  }
>  EXPORT_SYMBOL_GPL(__kunit_do_failed_assertion);
>
> +static void __kunit_init_params(struct kunit *test)
> +{
> +       test->params_data.params =3D NULL;
> +       test->params_data.num_params =3D 0;
> +       test->params_data.elem_size =3D 0;
> +}
> +
>  void kunit_init_test(struct kunit *test, const char *name, struct string=
_stream *log)
>  {
>         spin_lock_init(&test->lock);
> @@ -347,6 +354,7 @@ void kunit_init_test(struct kunit *test, const char *=
name, struct string_stream
>                 string_stream_clear(log);
>         test->status =3D KUNIT_SUCCESS;
>         test->status_comment[0] =3D '\0';
> +       __kunit_init_params(test);
>  }
>  EXPORT_SYMBOL_GPL(kunit_init_test);
>
> @@ -641,6 +649,22 @@ static void kunit_accumulate_stats(struct kunit_resu=
lt_stats *total,
>         total->total +=3D add.total;
>  }
>
> +const void *kunit_get_next_param_and_desc(struct kunit *test, const void=
 *prev, char *desc)
> +{
> +       struct kunit_params *params_arr =3D &test->params_data;
> +       const void *param;
> +
> +       if (test->param_index < params_arr->num_params) {
> +               param =3D (char *)params_arr->params
> +                       + test->param_index * params_arr->elem_size;
> +
> +               if (params_arr->get_description)
> +                       params_arr->get_description(param, desc);
> +               return param;
> +       }
> +       return NULL;
> +}

I also agree with David that it should definitely be considered: 1 -
whether to utilize struct kunit_params for the case of using
KUNIT_ARRAY_PARAM and 2 - whether the user should actively input this
function instead of setting generate_params to NULL.

Another idea that just popped into my head is if we have access to
struct kunit* test now in all of the generate_params functions,
instead of setting a "desc" could we just set the test->name field?

> +
>  static void __kunit_init_parent_test(struct kunit_case *test_case, struc=
t kunit *test)
>  {
>         if (test_case->param_init) {
> @@ -687,7 +711,7 @@ int kunit_run_tests(struct kunit_suite *suite)
>                         /* Test marked as skip */
>                         test.status =3D KUNIT_SKIPPED;
>                         kunit_update_stats(&param_stats, test.status);
> -               } else if (!test_case->generate_params) {
> +               } else if (!test_case->generate_params && !test.params_da=
ta.params) {

I agree with David that it is helpful to have one check for whether a
test is a parameterized test rather than two. My instinct is that if
test_case->generate_params is NULL it should be safe to assume the
test isn't a parameterized test.

However, as an alternative or even as a helpful addition, I like the
idea of a simple kunit_test_is_param function that can pass in the
test and it will return a bool whether the test is parameterized or
not.




>                         /* Non-parameterised test. */
>                         test_case->status =3D KUNIT_SKIPPED;
>                         kunit_run_case_catch_errors(suite, test_case, &te=
st);
> --
> 2.50.1.552.g942d659e1b-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov7AH5Qyiaua7LKZjVNRoUd%3D%3DDiSXvd1UP7TcSzvn5JZtQ%40mail.gmail.com.
