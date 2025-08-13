Return-Path: <kasan-dev+bncBC6OLHHDVUOBBU5Q6HCAMGQEURGUOMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D024B24521
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 11:18:13 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-7e7ff9e2738sf1327003685a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 02:18:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755076692; cv=pass;
        d=google.com; s=arc-20240605;
        b=OfkI8QhJf0LLmkI/OiopW7rwEFm5Nw1UBHYtJOMZquiZFMM/64/YwavOzbKPpt7NtI
         l5bzKixfrBJ0VSiAjFe6Q1L2VufeFcIaBw/6Do+hhiFaUem/o7s1dS+ijk73FUzEcRBe
         ViAkIS4sgtEjZ12BqfKFT3eO9cRKkUOl1vrrI8MBs4NriP5bCC0EhLTUwXZN6RJuwlIx
         f6u0FrNduHWrTQvCPLJ6YLkhkP+0qJdAP3jUgBbrYakYD93hYX/bJ/aidQ9FM9gF8f1A
         TF+YA9g4co1BDqRjyl7W8u51as3Cfw3YniZcaWyL6SvhYVQi+TmV4sObzaBZ4DdwNJ0y
         D+3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KVeqfmjPSeAn8VfkzCd/lomTR+6kt7dp3LAhT8TnGT8=;
        fh=WBIhrfOgWxWILamy88yI2hukPRA4oeCyeHwmZSwqrcg=;
        b=CIsf1PdevwbLb6lEqhkP84qnT40iGxsB2lLzSOTLd9jlvNHL3Rvj9AFC7/TYJXfpb+
         KcSDNRUOeK95ienznaxUQiY0Y7wcdis0IsGIU6Lsa3QE8ZPBCU/nUQ6dPFMDonver+YU
         XCleisBEYe3Iem/ti+Ai2aIGgCcTXlQqw7/c3v9oaHuCjv8lUaMPQh1pNBHCCWUh1b6k
         3lwLJdE4frosJcSC/lZkQqtJnWu9it72LN6bgkB322iInHjmro1+uiy8PmQv3BCZx4pW
         PvRAJkU4BcWOGfVmMXB0b9+eM3vzpi7ZQbVe9+dB0WHiOWlg1ZXzIQM0rZL4gutB/W+X
         6o/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="iMHb1/30";
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755076692; x=1755681492; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KVeqfmjPSeAn8VfkzCd/lomTR+6kt7dp3LAhT8TnGT8=;
        b=wrvwFuvsAPpY0f1O6iyfqdR0TTA+9gUqMJhZbFeMdCbh++eUqi9o3Inyw3gEtAK/zO
         OcL3wGRUywqZrvuqfr3UGhTAuc+4Wx1CsuUP9eVriDgKEGQCu7YiR4Pl+KQYfwHWPbaQ
         zYrcVGnvons30kJHkcLudK5qxklLm6gM/I7sLK5YYJ9MteKRY/pbQ6ZjE5IvxzVEw7zg
         FTBczuJUrTZ2prPNcN0mqzzHXyS14cG6Poxr0/8okLeI3IZntDwYBZFkvIDpMYnq39px
         r4+o8JgnoAd6YMiQ87fj451l5m/6oxAUVqOvRS8WdYEityaesCdTOjbQpm+AUl2Ry8IK
         +wnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755076692; x=1755681492;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KVeqfmjPSeAn8VfkzCd/lomTR+6kt7dp3LAhT8TnGT8=;
        b=svRgAMcAyLhzZjFwkfAw2XTkT5ovpj76KPEEGyvnYXwDN8w1BrOaTgcRoWacytwxzH
         YvhWvH5i9EI06rFqvCz2CzFcSDRQpJUq4I461rIND5Xi71cGs69wbGB7Vb14SbnHtq6q
         gnom8s0BASKu/rw9Oa9XBP6NNs/Vp1teKsy/iGoIw74+tjE4MXP3G5mI/D6UZy239y/P
         6B1bz8+GcjPLtRPo1gVZ5BmGAyKyIDRCKj8uXEDFbNvJa3ns+XMYItZbNvdqnsrLX7C5
         j4REuWUbC1v8TEAuO1kOZoxYBOHAz79WYs2qqHTzc/in3Q0ETYt+xePuhHxJ9so+VOAm
         1YrQ==
X-Forwarded-Encrypted: i=2; AJvYcCVinmGXvnRncy5GIw0FjEq/tRDdOg1uOHuEPRNT7AtPvBhjS0o1bM4cA9TNcaInIPGCHGRTYg==@lfdr.de
X-Gm-Message-State: AOJu0YyuUMRBBSZUjggt9hiD1bs8GOtwVEliXQWuG6VkBGFaS7ql1C1l
	QGLdc13DoVw5ZzysSCu4Y/GPHUrULf90b0fd7cxp/tktfjIWRQCz0QjT
X-Google-Smtp-Source: AGHT+IF+qKDLs+CkLgGaSH51q0ZTKgaVxXsUric/ONWyTnEqYLIi+zFLpOGNBuc1J0+qa1pTKKyaow==
X-Received: by 2002:ad4:5ae9:0:b0:704:9239:bdf3 with SMTP id 6a1803df08f44-709e899a01dmr25523456d6.40.1755076691439;
        Wed, 13 Aug 2025 02:18:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeudTBZW4aRmgPPIfY+74OKs4522oXmK3XMtJVLVVKySQ==
Received: by 2002:ad4:5ca6:0:b0:707:b7f:69d1 with SMTP id 6a1803df08f44-709883faf68ls114009016d6.2.-pod-prod-09-us;
 Wed, 13 Aug 2025 02:18:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWAsc6KL8rdk/5yjpny8uFlPyye+5eDnZhB0X5Jhy7ismCrlEz7bNduTvwdeNShx9jDqUpmiSNU6Jk=@googlegroups.com
X-Received: by 2002:a05:6122:3c54:b0:532:fc17:7839 with SMTP id 71dfb90a1353d-53b0b47c6d9mr707957e0c.2.1755076690535;
        Wed, 13 Aug 2025 02:18:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755076690; cv=none;
        d=google.com; s=arc-20240605;
        b=Mco1LHgVT+5TR9jme5FZ6s2qPvjEuZE6JFH/Ba9xutAvFicLbe9NoVOx7EYqKwG6hz
         89ymvwLBdZ+byqYgezEtegU6PLN0/P0tcdvermetjP41looRMa0VL7RAnouYjWkMytdz
         jK+xaCOHsDu1BwK5iIxxBt4QEIbq36KRtip4IONELBUE6Lic8uHDd8Zbg101UAC25B75
         BBSwAF18scJCB9TgPuOgugbA8G57WQpjTTepj3VLwzIzlYGJuuUPpmanblUyh9fDZVti
         uFrBPj5bUiog3j25g7NHyigCAFNrrEvEHP+1TkyFFeIChbP4suDnh0ZOrgcBk48TK+0e
         xdFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xbZZwbMEdBqyfqji+09lebY1tgG6+3dmSbMmacTHbMk=;
        fh=e2OkmbNCEPMiFeLp0h7rTDmF6sULqM96/+XikWLJjJU=;
        b=Lpn+AjjsXB0TINmDEa7RoLJYQW2ySxu3djOsv9ajDJBXpPFt2OS9bAo3OINsFCWWRX
         pV3PTqKJ15PvjJI8VkqwndPeU1tbY+YxaaaVcoQFL26QQjdPR78FaU3G0MOyicXHmLRV
         BHXaVHQFss4Rriw3GshBtsovCmNNfz8UrSw4Q4IBBOyT2wmSIbq4jxAtYbjcRpbsrFoO
         jUSgZTMAD6QTPv1hWTUlFBk4kjFWkn21FO7EF6mNY/CcO15a288a5FOgQITTT+XINIJb
         e+LnUaXBkbDuHOHaxH5bFZpq4kIq9gxjN0wlJIZQbqSgnsgUnvlmi5VZ0mKYePUx8e8v
         ahKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="iMHb1/30";
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539b003907fsi764128e0c.0.2025.08.13.02.18.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 02:18:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-70744318bb3so52529856d6.3
        for <kasan-dev@googlegroups.com>; Wed, 13 Aug 2025 02:18:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUclRog5n4pdkYBURgReZ2cY6HFCB6KEmDLLuWtZpN5Ei2CQl23SO7DsaWSLFCy6XVlIiDc1pVRlaE=@googlegroups.com
X-Gm-Gg: ASbGnctJXMoFMIEpOHFNaVuBEEM1TPeKywyj5F8b3PI525scEBB/npx/HXLcWJBUJb4
	Tef/onEcsCqwkk9tTEdXda1HM1JI4HJX4/TZ6lBFiz1+NBgN2xY8Hgxg4sMg7RcYD/12SAzuqrh
	Zt0KnG+ZVTvhMOkVnFMYUdIzmgkk1evfol/OS1S5mR50HoVWqNRaZidJsWOb/q51bcPRuiMObq3
	srF1CE+
X-Received: by 2002:a05:6214:4d04:b0:709:ee6f:4988 with SMTP id
 6a1803df08f44-709ee6f4a1dmr11251396d6.1.1755076689562; Wed, 13 Aug 2025
 02:18:09 -0700 (PDT)
MIME-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com> <20250811221739.2694336-5-marievic@google.com>
In-Reply-To: <20250811221739.2694336-5-marievic@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Aug 2025 17:17:56 +0800
X-Gm-Features: Ac12FXyaZBPXd1qWSSbQjfntOQ8fFwW2qaUKygT1ieSUwA4IVOaf_-MIVSOltEQ
Message-ID: <CABVgOS=X25Y9Q9cYU3K6-5YyzvjC1bWWLzXDgYwjOPgrX4+PTQ@mail.gmail.com>
Subject: Re: [PATCH v2 4/7] kunit: Enable direct registration of parameter
 arrays to a KUnit test
To: Marie Zhussupova <marievic@google.com>
Cc: rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000afd62c063c3ba252"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="iMHb1/30";       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f35
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

--000000000000afd62c063c3ba252
Content-Type: text/plain; charset="UTF-8"

On Tue, 12 Aug 2025 at 06:18, 'Marie Zhussupova' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> KUnit parameterized tests currently support two
> primary methods for getting parameters:
> 1.  Defining custom logic within a generate_params()
>     function.
> 2.  Using the KUNIT_ARRAY_PARAM() and KUNIT_ARRAY_PARAM_DESC()
>     macros with a pre-defined static array and passing
>     the created *_gen_params() to KUNIT_CASE_PARAM().
>
> These methods present limitations when dealing with
> dynamically generated parameter arrays, or in scenarios
> where populating parameters sequentially via
> generate_params() is inefficient or overly complex.
>
> This patch addresses these limitations by adding a new
> `params_array` field to `struct kunit`, of the type
> `kunit_params`. The `struct kunit_params` is designed to
> store the parameter array itself, along with essential metadata
> including the parameter count, parameter size, and a
> get_description() function for providing custom descriptions
> for individual parameters.
>
> The `params_array` field can be populated by calling the new
> kunit_register_params_array() macro from within a
> param_init() function. This will register the array as part of the
> parameterized test context. The user will then need to pass
> kunit_array_gen_params() to the KUNIT_CASE_PARAM_WITH_INIT()
> macro as the generator function, if not providing their own.
> kunit_array_gen_params() is a KUnit helper that will use
> the registered array to generate parameters.
>
> The arrays passed to KUNIT_ARRAY_PARAM(,DESC) will also
> be registered to the parameterized test context for consistency
> as well as for higher availability of the parameter count that
> will be used for outputting a KTAP test plan for
> a parameterized test.
>
> This modification provides greater flexibility to the
> KUnit framework, allowing testers to easily register and
> utilize both dynamic and static parameter arrays.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---

Big fan of the changes here, especially the support for KTAP test
plans and the use of struct kunit_params for the static array
versions.

Reviewed-by: David Gow <davidgow@google.com>

Cheers,
-- David


>
> Changes in v2:
>
> - If the parameter count is available for a parameterized
>   test, the kunit_run_tests() function will now output
>   the KTAP test plan for it.
> - The name of the struct kunit_params field in struct
>   kunit was changed from params_data to params_array.
>   This name change better reflects its purpose, which
>   is to encapsulate both the parameter array and its
>   associated metadata.
> - The name of `kunit_get_next_param_and_desc` was changed
>   to `kunit_array_gen_params` to make it simpler and to
>   better fit its purpose of being KUnit's built-in generator
>   function that uses arrays to generate parameters.
> - The signature of get_description() in `struct params_array`
>   was changed to accept the parameterized test context,
>   as well. This way test users can potentially use information
>   available in the parameterized test context, such as
>   the parameterized test name for setting the parameter
>   descriptions.
> - The type of `num_params` in `struct params_array` was
>   changed from int to size_t for better handling of the
>   array size.
> - The name of __kunit_init_params() was changed to be
>   kunit_init_params(). Logic that sets the get_description()
>   function pointer to NULL was also added in there.
> - `kunit_array_gen_params` is now exported to make
>   it available to use with modules.
> - Instead of allowing NULL to be passed in as the
>   parameter generator function in the KUNIT_CASE_PARAM_WITH_INIT
>   macro, users will now be asked to provide
>   `kunit_array_gen_params` as the generator function.
>   This will ensure that a parameterized test remains
>   defined by the existence of a parameter generation
>   function.
> - KUNIT_ARRAY_PARAM(,DESC) will now additionally
>   register the passed in array in struct kunit_params.
>   This will make things more consistent i.e. if a
>   parameter array is available then the struct kunit_params
>   field in parent struct kunit is populated. Additionally,
>   this will increase the availability of the KTAP test plan.
> - The comments and the commit message were changed to
>   reflect the parameterized testing terminology. See
>   the patch series cover letter change log for the
>   definitions.
>
> ---
>  include/kunit/test.h | 65 ++++++++++++++++++++++++++++++++++++++++----
>  lib/kunit/test.c     | 30 ++++++++++++++++++++
>  2 files changed, 89 insertions(+), 6 deletions(-)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index b527189d2d1c..8cc9614a88d5 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -234,9 +234,13 @@ static inline char *kunit_status_to_ok_not_ok(enum kunit_status status)
>   * Provides the option to register param_init() and param_exit() functions.
>   * param_init/exit will be passed the parameterized test context and run once
>   * before and once after the parameterized test. The init function can be used
> - * to add resources to share between parameter runs, and any other setup logic.
> - * The exit function can be used to clean up resources that were not managed by
> - * the parameterized test, and any other teardown logic.
> + * to add resources to share between parameter runs, pass parameter arrays,
> + * and any other setup logic. The exit function can be used to clean up resources
> + * that were not managed by the parameterized test, and any other teardown logic.
> + *
> + * Note: If you are registering a parameter array in param_init() with
> + * kunit_register_param_array() then you need to pass kunit_array_gen_params()
> + * to this as the generator function.
>   */
>  #define KUNIT_CASE_PARAM_WITH_INIT(test_name, gen_params, init, exit)          \
>                 { .run_case = test_name, .name = #test_name,                    \
> @@ -289,6 +293,20 @@ struct kunit_suite_set {
>         struct kunit_suite * const *end;
>  };
>
> +/* Stores the pointer to the parameter array and its metadata. */
> +struct kunit_params {
> +       /*
> +        * Reference to the parameter array for a parameterized test. This
> +        * is NULL if a parameter array wasn't directly passed to the
> +        * parameterized test context struct kunit via kunit_register_params_array().
> +        */
> +       const void *params;
> +       /* Reference to a function that gets the description of a parameter. */
> +       void (*get_description)(struct kunit *test, const void *param, char *desc);
> +       size_t num_params;
> +       size_t elem_size;
> +};
> +
>  /**
>   * struct kunit - represents a running instance of a test.
>   *
> @@ -296,16 +314,18 @@ struct kunit_suite_set {
>   *       created in the init function (see &struct kunit_suite).
>   * @parent: reference to the parent context of type struct kunit that can
>   *         be used for storing shared resources.
> + * @params_array: for storing the parameter array.
>   *
>   * Used to store information about the current context under which the test
>   * is running. Most of this data is private and should only be accessed
> - * indirectly via public functions; the two exceptions are @priv and @parent
> - * which can be used by the test writer to store arbitrary data and access the
> - * parent context, respectively.
> + * indirectly via public functions; the exceptions are @priv, @parent and
> + * @params_array which can be used by the test writer to store arbitrary data,
> + * access the parent context, and to store the parameter array, respectively.
>   */
>  struct kunit {
>         void *priv;
>         struct kunit *parent;
> +       struct kunit_params params_array;
>
>         /* private: internal use only. */
>         const char *name; /* Read only after initialization! */
> @@ -376,6 +396,8 @@ void kunit_exec_list_tests(struct kunit_suite_set *suite_set, bool include_attr)
>  struct kunit_suite_set kunit_merge_suite_sets(struct kunit_suite_set init_suite_set,
>                 struct kunit_suite_set suite_set);
>
> +const void *kunit_array_gen_params(struct kunit *test, const void *prev, char *desc);
> +
>  #if IS_BUILTIN(CONFIG_KUNIT)
>  int kunit_run_all_tests(void);
>  #else
> @@ -1696,6 +1718,8 @@ do {                                                                             \
>                                              const void *prev, char *desc)                      \
>         {                                                                                       \
>                 typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);      \
> +               if (!prev)                                                                      \
> +                       kunit_register_params_array(test, array, ARRAY_SIZE(array), NULL);      \
>                 if (__next - (array) < ARRAY_SIZE((array))) {                                   \
>                         void (*__get_desc)(typeof(__next), char *) = get_desc;                  \
>                         if (__get_desc)                                                         \
> @@ -1718,6 +1742,8 @@ do {                                                                             \
>                                              const void *prev, char *desc)                      \
>         {                                                                                       \
>                 typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);      \
> +               if (!prev)                                                                      \
> +                       kunit_register_params_array(test, array, ARRAY_SIZE(array), NULL);      \
>                 if (__next - (array) < ARRAY_SIZE((array))) {                                   \
>                         strscpy(desc, __next->desc_member, KUNIT_PARAM_DESC_SIZE);              \
>                         return __next;                                                          \
> @@ -1725,6 +1751,33 @@ do {                                                                            \
>                 return NULL;                                                                    \
>         }
>
> +/**
> + * kunit_register_params_array() - Register parameter array for a KUnit test.
> + * @test: The KUnit test structure to which parameters will be added.
> + * @array: An array of test parameters.
> + * @param_count: Number of parameters.
> + * @get_desc: Function that generates a string description for a given parameter
> + * element.
> + *
> + * This macro initializes the @test's parameter array data, storing information
> + * including the parameter array, its count, the element size, and the parameter
> + * description function within `test->params_array`.
> + *
> + * Note: If using this macro in param_init(), kunit_array_gen_params()
> + * will then need to be manually provided as the parameter generator function to
> + * KUNIT_CASE_PARAM_WITH_INIT(). kunit_array_gen_params() is a KUnit
> + * function that uses the registered array to generate parameters
> + */
> +#define kunit_register_params_array(test, array, param_count, get_desc)                                \
> +       do {                                                                                    \
> +               struct kunit *_test = (test);                                                   \
> +               const typeof((array)[0]) * _params_ptr = &(array)[0];                           \
> +               _test->params_array.params = _params_ptr;                                       \
> +               _test->params_array.num_params = (param_count);                                 \
> +               _test->params_array.elem_size = sizeof(*_params_ptr);                           \
> +               _test->params_array.get_description = (get_desc);                               \
> +       } while (0)
> +
>  // TODO(dlatypov@google.com): consider eventually migrating users to explicitly
>  // include resource.h themselves if they need it.
>  #include <kunit/resource.h>
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index 01b20702a5a2..cbde238ff334 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -337,6 +337,14 @@ void __kunit_do_failed_assertion(struct kunit *test,
>  }
>  EXPORT_SYMBOL_GPL(__kunit_do_failed_assertion);
>
> +static void kunit_init_params(struct kunit *test)
> +{
> +       test->params_array.params = NULL;
> +       test->params_array.get_description = NULL;
> +       test->params_array.num_params = 0;
> +       test->params_array.elem_size = 0;
> +}
> +
>  void kunit_init_test(struct kunit *test, const char *name, struct string_stream *log)
>  {
>         spin_lock_init(&test->lock);
> @@ -347,6 +355,7 @@ void kunit_init_test(struct kunit *test, const char *name, struct string_stream
>                 string_stream_clear(log);
>         test->status = KUNIT_SUCCESS;
>         test->status_comment[0] = '\0';
> +       kunit_init_params(test);
>  }
>  EXPORT_SYMBOL_GPL(kunit_init_test);
>
> @@ -641,6 +650,23 @@ static void kunit_accumulate_stats(struct kunit_result_stats *total,
>         total->total += add.total;
>  }
>
> +const void *kunit_array_gen_params(struct kunit *test, const void *prev, char *desc)
> +{
> +       struct kunit_params *params_arr = &test->params_array;
> +       const void *param;
> +
> +       if (test->param_index < params_arr->num_params) {
> +               param = (char *)params_arr->params
> +                       + test->param_index * params_arr->elem_size;
> +
> +               if (params_arr->get_description)
> +                       params_arr->get_description(test, param, desc);
> +               return param;
> +       }
> +       return NULL;
> +}
> +EXPORT_SYMBOL_GPL(kunit_array_gen_params);
> +
>  static void kunit_init_parent_param_test(struct kunit_case *test_case, struct kunit *test)
>  {
>         if (test_case->param_init) {
> @@ -701,6 +727,10 @@ int kunit_run_tests(struct kunit_suite *suite)
>                                   "KTAP version 1\n");
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
>                                   "# Subtest: %s", test_case->name);
> +                       if (test.params_array.params)
> +                               kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT
> +                                         KUNIT_SUBTEST_INDENT "1..%zd\n",
> +                                         test.params_array.num_params);
>
>                         while (curr_param) {
>                                 struct kunit param_test = {
> --
> 2.51.0.rc0.205.g4a044479a3-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811221739.2694336-5-marievic%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOS%3DX25Y9Q9cYU3K6-5YyzvjC1bWWLzXDgYwjOPgrX4%2BPTQ%40mail.gmail.com.

--000000000000afd62c063c3ba252
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
0TANBglghkgBZQMEAgEFAKCBxzAvBgkqhkiG9w0BCQQxIgQgNOA0pgA4JVyLlGrT6avX3/AJ4U1y
3w9Vk1IpXWx15ZQwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUw
ODEzMDkxODEwWjBcBgkqhkiG9w0BCQ8xTzBNMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
YIZIAWUDBAECMAoGCCqGSIb3DQMHMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcN
AQEBBQAEggEAm7LopTIa72R82vZuWDP63r6oeIqPY0rCTYPik1xYIeARkRge1/v8MolHbiTy356T
bPiirGRUfneZEVX/5aonHLLA/1L7xWFTDpo72TdYKEUa15MnTowHCPp45MM/YsXbJaGY3JGywy5V
izlShCt0QlE6/FFeOUBJhpxoh7Cd7YcaT0cNItA9WZMq+5UHUIXaKkN161lWbxslZGkgZ6n4YATm
QwfqJWW5RyTTDBXDn0SCO91ezWe1XSzo8330SVBTUioJrfNitqgjeyG/sJnVwMGa+5rLHzEa7RCe
BQTMP11ZSRmHI1yDDGJpBZeRtCBKUtg/wRxwWTaIYRAYa3fDOA==
--000000000000afd62c063c3ba252--
