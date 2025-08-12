Return-Path: <kasan-dev+bncBDPPVSUFVUPBBVX553CAMGQEZ2HIN4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id DC5C8B23BC7
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 00:23:19 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-2e9b1f85b2bsf11106838fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:23:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755037398; cv=pass;
        d=google.com; s=arc-20240605;
        b=esVR+sPeI2tUevk5KCZR0sOvyqWgI00mmG1F8e0GsrC4wTzOkB7zhrDyYLa+ZDBrYB
         tOc5ZxO8irPjiyHrRXHmz2rBT/Gsim4lWWi6Gk/nQqEj9kKY3eo2nXu8sumZkieBeU75
         7AO0Vm7lbnfuA3Xa+ZUDIdFWeKbfEHor3nUxWOHGYhM63IF6QUUSoRGEY/lMm1pq9QQf
         v4r37AS5Dn0O94yiNUFcZ8NyJxj5QidQuTTXBGlR4n93We8h8gZUjSfNCmmc8SWsPYl2
         w3l4Wwm5fHMHJbqHySSarA5wEz++/I1DlcmPTUGp//mzOrc1SuXvEgFlVQRdQ3CDY3vm
         /Hww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ujgJGzMWYwLzOmUz0y+blzTPP8nb/fPZXLvK4zF4Wjc=;
        fh=sCz0VYCX8L90fWOSDBNjwKgYH9cfJCou/FBGjO+U6tQ=;
        b=CN6nXfi0CG3DOOgoV+ezlrLbZaVE087GvFRJgQx4tuVlxi1J1xb6ELHzpe7pczYP6h
         oHOPzYuEn3VWso0opalMIKfwa4oSOJSc62x2c/NzbmiNGQE2EcdlSvZeAwc8OwLCsc9m
         1VzV8T7htT0aTH9w09NZHuegZG88qKTTNoQLOwy3pbKx4CE8pu2iI+Df8+6weQ1OnKhF
         1x3G+qtK+VKzXlxqTHpX1tDfYj00gqQiBJDzVyCthtWU1Xwv3qBxkoa4jNd8GgCCAbH0
         LAZlrWQlB17qRSJfSsiO83vsPOvztNWa+tJJj/k1LcO3lQsbhhOEfKjb41J80GS2fQ9d
         3U3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=U6+mmVDA;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755037398; x=1755642198; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ujgJGzMWYwLzOmUz0y+blzTPP8nb/fPZXLvK4zF4Wjc=;
        b=TpIBmPCVepmwTCQGIxV4iVGqkIOoFTjXz606ipyNGs+U/fGi5QAMiZNsmGWCOaQ/dV
         NTQPdNRNaL9yaw/4SRPNPjlH5YKhu9e5ni86QDMeP3/v5ODk+tuVUiqE/QRuOHGAg6zn
         veEQqTyUiY8QkVSYgY9yx1hR1AlhLQO7CZ2Pa5PN0sYsTxlxeM4BfFcFWMSEoErmbiHz
         Wq7PoTuRUpOv7Avf0jCKQ6Fp2G+uNO8XQ9dCHAazQSRr/b9qPwqCZ2cDfCZM6AO8wjwW
         zbBXwEyPJqB4ZzdKmcmtEadkDLIkrYZzySSfgNUzScg5e6ZwQGmY/ptq7t/WoukDUB86
         WqRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755037398; x=1755642198;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ujgJGzMWYwLzOmUz0y+blzTPP8nb/fPZXLvK4zF4Wjc=;
        b=NF7IKRJzYi4xI4Vlt3DtJ760BaTYBEqfK3rnFbPYMTttqfaTsdGVlWMbcSIS3W5ZLb
         NDzK0WZvJ9Vi7UxkyJRNJXbHJf0caC+sGedya8zRMCMWTAKmuIuLVzrsURJbZSmHf1HB
         6i27Fq/9WONn+evAwgyWv0WC/1bxl0KNLTCbPP1xStTW/jdB91ree8tRCLH95IiFAivQ
         S1rVnaBOOcsaGY/vzFoXdWlxN3zA2mXZkC/0/qU7F3ayQigBKaTThoQAE0e6Eg9omeTm
         2Y2t/ZkW8T+y4UTQF00mVJmsQWfCqD9qFty2okfwwoZ5SJnP3o0aJgmjnjiQkYxbWwhh
         4llg==
X-Forwarded-Encrypted: i=2; AJvYcCV068iCCIhaiL2x3Tl2k2+M4HrO7U0HtrvZZ+iyeiHol85vSG3IM8yWEV4VjcGOK6iKISP9eQ==@lfdr.de
X-Gm-Message-State: AOJu0YxhBZ4NCvsgJ9mDY6tpuz6siMWi4AnxNjipuG0f7zsC9kjZecbS
	nf4qRFKxGfeKdIN/1k+27dnDjiv9XEaHX9oKB6bwL5BLxg44zvN7KVko
X-Google-Smtp-Source: AGHT+IGFvPlG6keuyoiIZPllaHQ4SdXgblcSUPS+PGIAaFo46v7MCEX9Ipm7fWR9cQywA6esMA07Ng==
X-Received: by 2002:a05:6871:4b88:b0:2c1:ac88:4a8d with SMTP id 586e51a60fabf-30cb5cc1f44mr606076fac.30.1755037398479;
        Tue, 12 Aug 2025 15:23:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfasfNTq7vJu+pWtRXBVHJA6d1WKQRGDIpjm/GvUrCd/g==
Received: by 2002:a05:6870:2b15:b0:30c:593:af6b with SMTP id
 586e51a60fabf-30c0594514dls4673239fac.2.-pod-prod-07-us; Tue, 12 Aug 2025
 15:23:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWhGk+PZgrn4Jss+chq8oInrvFjAEXG5B0z+X0S9pbVgqni9JDDZXNwMRJVcZWsSfCvpUBfoUg96zI=@googlegroups.com
X-Received: by 2002:a05:6870:d14f:b0:30b:99a5:c058 with SMTP id 586e51a60fabf-30cb5c3b4dbmr685427fac.26.1755037396060;
        Tue, 12 Aug 2025 15:23:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755037396; cv=none;
        d=google.com; s=arc-20240605;
        b=kG8DGgnQOKvJI0UbQKXVMk3mgrTCCzVezhIYvFs6QNYGvcrZ066e/KmGA8Pgd5Wnxs
         MbDBrDmubbj7QpT7ByZhyTAH6ankPyRbLknKeXbF8BzHqEvGRWSjwhVsi3EQPuHPjJdW
         oPRJm2luxWbEXvwP/L7R4ngytYFkPa9MlMugCcAvbpYYRIXn+mBCsFmJFQB9hd96rS3k
         epjnTpP/ihTRZ3xCvoRAkAp9f7/Gu6uA5A41yAegoRd44Q5Wj0tEw+8Qk8b296itU/RP
         waqnDijOIcE+3E7VkWBIIxpP2CyTrv/F221P2iPGPoNMSsz4iffjFYTRFTTmSWLMbzpc
         TwgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NCjfCIARl7FEQlaEVHD1Q7u5jqwvzYtlI2DxlC6TvyE=;
        fh=9b0ycW++zidn0xRv+zNnDEmEmwhO5XJqcU+l2UeiSTM=;
        b=Wv7oOSdxeOzIRPm8Wda+eVkag3fkq7Ql3oNrk385qzn45dpzrSIX80vLWfJBhGemIt
         Gi9QCyNd2K8KXTRsZxKolHMS3SAaPRLN4hy6AiwOntB1WJKSyZelCnYKB80rJ8yjv3wp
         l2CoXxNxDxVwpLpKmefeWDROzpeNtDvOf7GWFIEFXLltjlrAP6jPXJh643Xx3t3wnVqC
         AtY7SXS8MlZPxUU2majwG+6L9CNoeCxrHj+0dZ+qFqQ8KLzxKExtxQL1EBe1rhunIahO
         F43nSPybBsXVetlKlewsB0zTu00BH+k/5cOp/1VlOppjJ19vz/1WAtCLmoTmy29SIeCP
         i/qg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=U6+mmVDA;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7436f87ba53si81565a34.2.2025.08.12.15.23.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Aug 2025 15:23:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-70884da4b55so62081606d6.3
        for <kasan-dev@googlegroups.com>; Tue, 12 Aug 2025 15:23:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU6jG8zsfMwBPCgR55RAZHuIYe/AoFaDxHQrfRa0GwoTIg2vgOIn+FquwAiNviVyCQPRTpsqXdi+bg=@googlegroups.com
X-Gm-Gg: ASbGnctVPErwmBbgUS4DNNSuxXAu6zBdUPn/U1Se//R7d9+WECmGEPhZI4axicYkuK4
	qfhA1evPkqSafWKruKF4IpBVk63gR/MhfoK+ZMDWnA3umU7+bEZv+5O3+tpQ4CodSDrs+/KeHXS
	AIIZRWpEfyeiWD1nZGtrDRihh1kGxmRDnQgWzxl0CPY5Tih2ys94Ntku6yZz4YyD8sLkPsvgegZ
	enAzh7DzwEgEfTc
X-Received: by 2002:a05:6214:b65:b0:707:2a42:b9b3 with SMTP id
 6a1803df08f44-709e87fc8eemr13324846d6.10.1755037394932; Tue, 12 Aug 2025
 15:23:14 -0700 (PDT)
MIME-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com> <20250811221739.2694336-5-marievic@google.com>
In-Reply-To: <20250811221739.2694336-5-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Aug 2025 18:23:03 -0400
X-Gm-Features: Ac12FXz_Z-KSxKbEjvzCLajE68vHYuAwVU6cW7c0HNZTIqwbxoPdgclX4rSmmA4
Message-ID: <CA+GJov6bvx5FTKvDE9Bng1m4iDynwruDnFf5orpzc+yMc2-yzw@mail.gmail.com>
Subject: Re: [PATCH v2 4/7] kunit: Enable direct registration of parameter
 arrays to a KUnit test
To: Marie Zhussupova <marievic@google.com>
Cc: davidgow@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: rmoar@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=U6+mmVDA;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f35 as
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

On Mon, Aug 11, 2025 at 6:17=E2=80=AFPM Marie Zhussupova <marievic@google.c=
om> wrote:
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

Hello!

Thanks for all your effort in updating this patch series. It is
looking really good. I think I am happy with this patch as is but I do
have a comment below.

Thanks!
-Rae

> ---
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
> @@ -234,9 +234,13 @@ static inline char *kunit_status_to_ok_not_ok(enum k=
unit_status status)
>   * Provides the option to register param_init() and param_exit() functio=
ns.
>   * param_init/exit will be passed the parameterized test context and run=
 once
>   * before and once after the parameterized test. The init function can b=
e used
> - * to add resources to share between parameter runs, and any other setup=
 logic.
> - * The exit function can be used to clean up resources that were not man=
aged by
> - * the parameterized test, and any other teardown logic.
> + * to add resources to share between parameter runs, pass parameter arra=
ys,
> + * and any other setup logic. The exit function can be used to clean up =
resources
> + * that were not managed by the parameterized test, and any other teardo=
wn logic.
> + *
> + * Note: If you are registering a parameter array in param_init() with
> + * kunit_register_param_array() then you need to pass kunit_array_gen_pa=
rams()
> + * to this as the generator function.
>   */
>  #define KUNIT_CASE_PARAM_WITH_INIT(test_name, gen_params, init, exit)   =
       \
>                 { .run_case =3D test_name, .name =3D #test_name,         =
           \
> @@ -289,6 +293,20 @@ struct kunit_suite_set {
>         struct kunit_suite * const *end;
>  };
>
> +/* Stores the pointer to the parameter array and its metadata. */
> +struct kunit_params {
> +       /*
> +        * Reference to the parameter array for a parameterized test. Thi=
s
> +        * is NULL if a parameter array wasn't directly passed to the
> +        * parameterized test context struct kunit via kunit_register_par=
ams_array().
> +        */
> +       const void *params;
> +       /* Reference to a function that gets the description of a paramet=
er. */
> +       void (*get_description)(struct kunit *test, const void *param, ch=
ar *desc);

I'm a little bit uncertain whether I like this change to
get_description. I don't like that the function signature for a
get_description function is different now between
kunit_register_params_array and the KUNIT_ARRAY_PARAM_DESC. I think I
would prefer it as it was before.

However, I do still like the idea of users being able to set struct
kunit test->name for each param run as the test name but that would
require some reworking because the struct kunit test that is passed
into generate_params and get_description is the parent test I believe
rather than each individual param run. So I think I might prefer it as
it was.


> +       size_t num_params;
> +       size_t elem_size;
> +};
> +
>  /**
>   * struct kunit - represents a running instance of a test.
>   *
> @@ -296,16 +314,18 @@ struct kunit_suite_set {
>   *       created in the init function (see &struct kunit_suite).
>   * @parent: reference to the parent context of type struct kunit that ca=
n
>   *         be used for storing shared resources.
> + * @params_array: for storing the parameter array.
>   *
>   * Used to store information about the current context under which the t=
est
>   * is running. Most of this data is private and should only be accessed
> - * indirectly via public functions; the two exceptions are @priv and @pa=
rent
> - * which can be used by the test writer to store arbitrary data and acce=
ss the
> - * parent context, respectively.
> + * indirectly via public functions; the exceptions are @priv, @parent an=
d
> + * @params_array which can be used by the test writer to store arbitrary=
 data,
> + * access the parent context, and to store the parameter array, respecti=
vely.
>   */
>  struct kunit {
>         void *priv;
>         struct kunit *parent;
> +       struct kunit_params params_array;
>
>         /* private: internal use only. */
>         const char *name; /* Read only after initialization! */
> @@ -376,6 +396,8 @@ void kunit_exec_list_tests(struct kunit_suite_set *su=
ite_set, bool include_attr)
>  struct kunit_suite_set kunit_merge_suite_sets(struct kunit_suite_set ini=
t_suite_set,
>                 struct kunit_suite_set suite_set);
>
> +const void *kunit_array_gen_params(struct kunit *test, const void *prev,=
 char *desc);
> +
>  #if IS_BUILTIN(CONFIG_KUNIT)
>  int kunit_run_all_tests(void);
>  #else
> @@ -1696,6 +1718,8 @@ do {                                               =
                              \
>                                              const void *prev, char *desc=
)                      \
>         {                                                                =
                       \
>                 typeof((array)[0]) *__next =3D prev ? ((typeof(__next)) p=
rev) + 1 : (array);      \
> +               if (!prev)                                               =
                       \
> +                       kunit_register_params_array(test, array, ARRAY_SI=
ZE(array), NULL);      \
>                 if (__next - (array) < ARRAY_SIZE((array))) {            =
                       \
>                         void (*__get_desc)(typeof(__next), char *) =3D ge=
t_desc;                  \
>                         if (__get_desc)                                  =
                       \
> @@ -1718,6 +1742,8 @@ do {                                               =
                              \
>                                              const void *prev, char *desc=
)                      \
>         {                                                                =
                       \
>                 typeof((array)[0]) *__next =3D prev ? ((typeof(__next)) p=
rev) + 1 : (array);      \
> +               if (!prev)                                               =
                       \
> +                       kunit_register_params_array(test, array, ARRAY_SI=
ZE(array), NULL);      \
>                 if (__next - (array) < ARRAY_SIZE((array))) {            =
                       \
>                         strscpy(desc, __next->desc_member, KUNIT_PARAM_DE=
SC_SIZE);              \
>                         return __next;                                   =
                       \
> @@ -1725,6 +1751,33 @@ do {                                              =
                              \
>                 return NULL;                                             =
                       \
>         }
>
> +/**
> + * kunit_register_params_array() - Register parameter array for a KUnit =
test.
> + * @test: The KUnit test structure to which parameters will be added.
> + * @array: An array of test parameters.
> + * @param_count: Number of parameters.
> + * @get_desc: Function that generates a string description for a given p=
arameter
> + * element.
> + *
> + * This macro initializes the @test's parameter array data, storing info=
rmation
> + * including the parameter array, its count, the element size, and the p=
arameter
> + * description function within `test->params_array`.
> + *
> + * Note: If using this macro in param_init(), kunit_array_gen_params()
> + * will then need to be manually provided as the parameter generator fun=
ction to
> + * KUNIT_CASE_PARAM_WITH_INIT(). kunit_array_gen_params() is a KUnit
> + * function that uses the registered array to generate parameters
> + */
> +#define kunit_register_params_array(test, array, param_count, get_desc) =
                               \
> +       do {                                                             =
                       \
> +               struct kunit *_test =3D (test);                          =
                         \
> +               const typeof((array)[0]) * _params_ptr =3D &(array)[0];  =
                         \
> +               _test->params_array.params =3D _params_ptr;              =
                         \
> +               _test->params_array.num_params =3D (param_count);        =
                         \
> +               _test->params_array.elem_size =3D sizeof(*_params_ptr);  =
                         \
> +               _test->params_array.get_description =3D (get_desc);      =
                         \
> +       } while (0)
> +
>  // TODO(dlatypov@google.com): consider eventually migrating users to exp=
licitly
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
> +       test->params_array.params =3D NULL;
> +       test->params_array.get_description =3D NULL;
> +       test->params_array.num_params =3D 0;
> +       test->params_array.elem_size =3D 0;
> +}
> +
>  void kunit_init_test(struct kunit *test, const char *name, struct string=
_stream *log)
>  {
>         spin_lock_init(&test->lock);
> @@ -347,6 +355,7 @@ void kunit_init_test(struct kunit *test, const char *=
name, struct string_stream
>                 string_stream_clear(log);
>         test->status =3D KUNIT_SUCCESS;
>         test->status_comment[0] =3D '\0';
> +       kunit_init_params(test);
>  }
>  EXPORT_SYMBOL_GPL(kunit_init_test);
>
> @@ -641,6 +650,23 @@ static void kunit_accumulate_stats(struct kunit_resu=
lt_stats *total,
>         total->total +=3D add.total;
>  }
>
> +const void *kunit_array_gen_params(struct kunit *test, const void *prev,=
 char *desc)
> +{
> +       struct kunit_params *params_arr =3D &test->params_array;
> +       const void *param;
> +
> +       if (test->param_index < params_arr->num_params) {
> +               param =3D (char *)params_arr->params
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
>  static void kunit_init_parent_param_test(struct kunit_case *test_case, s=
truct kunit *test)
>  {
>         if (test_case->param_init) {
> @@ -701,6 +727,10 @@ int kunit_run_tests(struct kunit_suite *suite)
>                                   "KTAP version 1\n");
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT =
KUNIT_SUBTEST_INDENT
>                                   "# Subtest: %s", test_case->name);
> +                       if (test.params_array.params)
> +                               kunit_log(KERN_INFO, &test, KUNIT_SUBTEST=
_INDENT
> +                                         KUNIT_SUBTEST_INDENT "1..%zd\n"=
,
> +                                         test.params_array.num_params);
>
>                         while (curr_param) {
>                                 struct kunit param_test =3D {
> --
> 2.51.0.rc0.205.g4a044479a3-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov6bvx5FTKvDE9Bng1m4iDynwruDnFf5orpzc%2ByMc2-yzw%40mail.gmail.com.
