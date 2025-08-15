Return-Path: <kasan-dev+bncBDPPVSUFVUPBBTMW7XCAMGQEC3KELRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4ACA1B28284
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 16:59:27 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4b0fa8190d4sf79028801cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 07:59:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755269966; cv=pass;
        d=google.com; s=arc-20240605;
        b=K/hLdQfkWhTFLNRpyk/chuBysh+AuYMfbe378eihTsQfTCe6Ry669p3a+ohYrbyz8q
         u57ui6Z5GO+AmImHTs69S3/x49tvwDEXz7rvZ3nXFewPW0Uw1BiusAf0pBaTrJSCnSY8
         hBBpo+hqmnQ1EHDnYDMk+GUO04KbQglsZV9rH2tO0u4ZIGz+ymNeX4An7X9J3SWSw3P6
         7MHlFMnP+buYAOA+BUoF6+DHyIrSquI0apvaYRne7afV+EB9cyAMlnJ+N62XycVBhJjo
         1x9IxrT0jVmn56c/kMQfcluiLU3VEtunH3R/y4NNYo67Yya9RFZUWi3WkjacyzTGGBW0
         sojA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ibz5LvVNJXtqR/cl/FLkeU2GEzcNSf0fgdY4l9ThDtA=;
        fh=/GXfp2sDrvweGr7HivWIed/d4+p4P3a9PctC4kQwbCY=;
        b=Yyopm/obtSYcxaT1y4HcSNma8Bv3Dik8z5hdGa3gzM+g6HU85RY0fcJO0RS/ZvVGIH
         DIimH9B/U8ucjRBKzTd0l49t+5/swxulnKttdhdxoHergGTUgPnDB3GEcJHrwwi+Jq86
         D24u3rWY5CYYMPx+VCQqVTXU5oUkXfWDtQDA7uxNySMY/2tC5Mk3IKqcHByoyL7qBxSt
         86iXxwtQOILZVlMG+DYLKrxCwk6bc/+OHLd1iI2GULS49+uvlzy4QaJVB16HWPP4udH+
         XxO8RIMQ8YbrwuNm6EdfGwWiYhGi0sMQhyI2g0aLK+UWckl97rzzL9Jb5jvDCpk4ZnKN
         /PVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ReZT83WN;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755269966; x=1755874766; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ibz5LvVNJXtqR/cl/FLkeU2GEzcNSf0fgdY4l9ThDtA=;
        b=hprZGwJexMUot0BUnsrcYP6GVDt7lAIW/1tHO35G2PGEjIuXboeasPgxsWQW0yfHVo
         JHU6TPlr9E8WAT53K8AsfD4xKBqJGIgJFz28xLGlJpfanRicZg0pICDjX/ia0TrinTXJ
         2absBHEJDrkhE5zPCuYMKx0DM5bbq748QEyU07lFUTevQOJktTrg4eXPT6EPsqwNbeNJ
         Mx8gC2YK4qPJlWno7TuQxxYZhGUjcMLy3g9QQOeOwVrrxou6O1OxhAqsPaIuoIN+ELoB
         XTUP8awlrd7bqBaFz2P4+w8LOMO224fALXiSWneoGKhQLLd4Y+1cKSxA1E66akr7ZYGX
         JuwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755269966; x=1755874766;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ibz5LvVNJXtqR/cl/FLkeU2GEzcNSf0fgdY4l9ThDtA=;
        b=u0TEqi27yk5gG4Q59qQ0EtxV1FfmvuavVsmJoIH7CQSwS7XTqYHh0vFzVoY5Z/j0Jl
         rQHxr0WLELY4Zm0BTU5FiOIJFVYUs47zBOOCmawRAUObUVVwHL3uUCZsHuDKiQbc0lTf
         E94xwaGQeYEywWmApr+zkdWxPdi0VUmyxwyJstjvwdGJ8fm83j5+/ByhrRAuwwkZngvc
         jWTptFT1u7zGK0rqwvUplhnXisEIC8sPUNr02dIZEHyY6j3QsD6adYfcLSIWMPYSpcIR
         l0VRSIZ5r8qFp448JXrwx94vbWvcstPfFbndkC5hmmgICVPhyb+PzmaKf4pT20SG5SWi
         TOgA==
X-Forwarded-Encrypted: i=2; AJvYcCWOcLOoGBXens7YVeOZbWPOc5KA2GzaRHcSjXdBqMQ0pgTZAM7gQ9TatBIvWmJ4oUWhal+cRQ==@lfdr.de
X-Gm-Message-State: AOJu0YxFjJsUJYKvKfz+0ezKJzjXdPCJ+VxluJRgu8A8NuFVKLkVafp/
	zCtzMrJYLbttXBpaX1zY4Y108x5bj4fiwXcUtJ02dwLurU6TE/gXBHS5
X-Google-Smtp-Source: AGHT+IF3pnZRz8QziBeuop2+dygfv30KJgp2frmEbbpp50XD9qutinB3lM1TdM0TbJRc1EXKqrTuUw==
X-Received: by 2002:a05:622a:a15:b0:4ab:5d26:db8a with SMTP id d75a77b69052e-4b11d2dea99mr37956841cf.18.1755269965893;
        Fri, 15 Aug 2025 07:59:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeYzvgRkhasNFlQJFx7rFXUDMZ/NjEf+iNiGb+7yC1pEg==
Received: by 2002:ac8:7d48:0:b0:4aa:fbf6:4242 with SMTP id d75a77b69052e-4b0fae0376dls26403251cf.1.-pod-prod-00-us-canary;
 Fri, 15 Aug 2025 07:59:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUU4PgJx0L7aNr+kH4PXaBgfBpChyPCyH1mnPQMkUT2cypJatVrED+OfbwEn3AaJ6S1P8oXudfnnzM=@googlegroups.com
X-Received: by 2002:a05:620a:44d1:b0:7e8:a40:2cf9 with SMTP id af79cd13be357-7e8717a32e1mr811956385a.26.1755269964828;
        Fri, 15 Aug 2025 07:59:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755269964; cv=none;
        d=google.com; s=arc-20240605;
        b=JPZoJ6rPcBK3wn+vJO8V3JOsHw8wxbPsmuRDFe6G88tngKlLhBgW6VaSNmpXW4XFqu
         UaySQjttbkCqBrVFMk1oHPgEOMYlh9aH8OrS8nbgVX7c+xYc3nxetZwNDmvfrYHRvc+1
         nf0ot4j3lnyVoBtji40SZc4gezYfGLBB5ylaewDkjRgo/foziTueeB76/taOAlmSXdcH
         GNqYCanNTByt6oLlpUKC7URIsPfczsPYPvinYCjmPND3vY0+ibUPhHtlzrV/r7j54gkz
         ijKi1n4I/8jTrE/TCd52/2WUUuhBL1U1l+dBfXmr7h9OlHIWMVvcqeY7DHFo74t6UIni
         bgZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=50nh9ojpuXl09KZsM4s/5KZbwzDlcF/XYcNNU05X9hw=;
        fh=rqp9ul1skRHgqrmMTIVuiIGC5YOqwSNq3Ns4+vwEk/o=;
        b=GgYoyf76anTSB5Sn4uAOesAxoK1Q3+IT6F6kT6Rxu03tdgyY7I0/8l0RRvLQKbmy4C
         MS3LX0VHxnguL4sqh9rTtiGNcsO+T98ldhRfOefeeGE8uA5xIpbxjdgcnneX2G08GR5N
         YQ8r6eA4j8M4BFtuHQvhLTVBYGGedmGuOKNEwljsO2XlcGlbdWRwUg2AoKU/wGEkXIEu
         nx3AzwOJzoGSjMQcxvd8T9dzK4zjm13iCvpshB0CmmKv+/XS/6wqkQscD+RxmvkZssJQ
         sHm4+7RmqAJ2VycmIsZKW51jU+kHxJGCtf/rsnizrnADLDt6d1iVwCeI6UhuTHkPBJfp
         cTHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ReZT83WN;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e87e1dcbe1si6472485a.5.2025.08.15.07.59.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Aug 2025 07:59:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 6a1803df08f44-70a88ddb1a2so19171786d6.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Aug 2025 07:59:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXkTfo/gOEUevvPTeOW4foZXNertS0x4xbcJXopP+Yo4c1ZVl5fPbYRtT4zx3sZuKpOevdOQdD04As=@googlegroups.com
X-Gm-Gg: ASbGncvrSqPNEwuMip8A50X0mHzHwHeCnfNY9pEabb27A79/nib2mg77A/ehWw6FhNI
	ULNTCrd371rMZKr4CmV8bKgj55U0WSilf98t02G2NPpQDtLOtwAlQ4KnuIlHq7CMfXuFG4InpfK
	VPADiKJWOzjQzPheTORI/gnJixk7sbkV2aVuP73xeC1xXRns4SEZliQ36sJJwrSBGJs9ULl0KU/
	oEeKE+nhSolfVYDjUHVwgeYkz8q+XZS+w==
X-Received: by 2002:a05:6214:2242:b0:704:a1c6:fff3 with SMTP id
 6a1803df08f44-70b97e04d15mr95594636d6.15.1755269961267; Fri, 15 Aug 2025
 07:59:21 -0700 (PDT)
MIME-Version: 1.0
References: <20250815103604.3857930-1-marievic@google.com> <20250815103604.3857930-5-marievic@google.com>
In-Reply-To: <20250815103604.3857930-5-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Aug 2025 10:59:10 -0400
X-Gm-Features: Ac12FXwK-0tPDAQTbVtLDfpATZ41CarassR39o4F4FtdW7kdqfwXD7XBdOKQgaE
Message-ID: <CA+GJov50Q81TAg8PUVNeg=tLUn+WLi8=Y+=FctC9hjs8TVh3mw@mail.gmail.com>
Subject: Re: [PATCH v3 4/7] kunit: Enable direct registration of parameter
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
 header.i=@google.com header.s=20230601 header.b=ReZT83WN;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f34 as
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

On Fri, Aug 15, 2025 at 6:36=E2=80=AFAM Marie Zhussupova <marievic@google.c=
om> wrote:
>
> KUnit parameterized tests currently support two primary methods f
> or getting parameters:
> 1.  Defining custom logic within a generate_params() function.
> 2.  Using the KUNIT_ARRAY_PARAM() and KUNIT_ARRAY_PARAM_DESC()
>     macros with a pre-defined static array and passing
>     the created *_gen_params() to KUNIT_CASE_PARAM().
>
> These methods present limitations when dealing with dynamically
> generated parameter arrays, or in scenarios where populating parameters
> sequentially via generate_params() is inefficient or overly complex.
>
> This patch addresses these limitations by adding a new `params_array`
> field to `struct kunit`, of the type `kunit_params`. The
> `struct kunit_params` is designed to store the parameter array itself,
> along with essential metadata including the parameter count, parameter
> size, and a get_description() function for providing custom descriptions
> for individual parameters.
>
> The `params_array` field can be populated by calling the new
> kunit_register_params_array() macro from within a param_init() function.
> This will register the array as part of the parameterized test context.
> The user will then need to pass kunit_array_gen_params() to the
> KUNIT_CASE_PARAM_WITH_INIT() macro as the generator function, if not
> providing their own. kunit_array_gen_params() is a KUnit helper that will
> use the registered array to generate parameters.
>
> The arrays passed to KUNIT_ARRAY_PARAM(,DESC) will also be registered to
> the parameterized test context for consistency as well as for higher
> availability of the parameter count that will be used for outputting a KT=
AP
> test plan for a parameterized test.
>
> This modification provides greater flexibility to the KUnit framework,
> allowing  testers to easily register and utilize both dynamic and static
> parameter arrays.
>
> Reviewed-by: David Gow <davidgow@google.com>
> Signed-off-by: Marie Zhussupova <marievic@google.com>

Hello!

This patch series is looking great! Happy to add this as an
improvement to the KUnit framework.

Reviewed-by: Rae Moar <rmoar@google.com>

Thanks!
-Rae

> ---
>
> Changes in v3:
> v2: https://lore.kernel.org/all/20250811221739.2694336-5-marievic@google.=
com/
> - Commit message formatting.
>
> Changes in v2:
> v1: https://lore.kernel.org/all/20250729193647.3410634-7-marievic@google.=
com/
> - If the parameter count is available for a parameterized test, the
>   kunit_run_tests() function will now output the KTAP test plan for it.
> - The name of the struct kunit_params field in struct kunit was changed
>   from params_data to params_array. This name change better reflects its
>   purpose, which is to encapsulate both the parameter array and its
>   associated metadata.
> - The name of `kunit_get_next_param_and_desc` was changed to
>   `kunit_array_gen_params` to make it simpler and to better fit its purpo=
se
>   of being KUnit's built-in generator function that uses arrays to genera=
te
>   parameters.
> - The signature of get_description() in `struct params_array` was changed=
 to
>   accept the parameterized test context, as well. This way test users can
>   potentially use information available in the parameterized test context=
,
>   such as the parameterized test name for setting the parameter descripti=
ons.
> - The type of `num_params` in `struct params_array` was changed from int =
to
>   size_t for better handling of the array size.
> - The name of __kunit_init_params() was changed to be kunit_init_params()=
.
>   Logic that sets the get_description() function pointer to NULL was also
>   added in there.
> - `kunit_array_gen_params` is now exported to make it available to use
>   with modules.
> - Instead of allowing NULL to be passed in as the parameter generator
>   function in the KUNIT_CASE_PARAM_WITH_INIT macro, users will now be ask=
ed
>   to provide `kunit_array_gen_params` as the generator function. This wil=
l
>   ensure that a parameterized test remains defined by the existence of a
>   parameter generation function.
> - KUNIT_ARRAY_PARAM(,DESC) will now additionally register the passed in a=
rray
>   in struct kunit_params. This will make things more consistent i.e. if a
>   parameter array is available then the struct kunit_params field in pare=
nt
>   struct kunit is populated. Additionally, this will increase the
>   availability of the KTAP test plan.
> - The comments and the commit message were changed to reflect the
>   parameterized testing terminology. See the patch series cover letter
>   change log for the definitions.
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
> index ac8fa8941a6a..ce4bb93f09f4 100644
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
> @@ -706,6 +732,10 @@ int kunit_run_tests(struct kunit_suite *suite)
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
> 2.51.0.rc1.167.g924127e9c0-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov50Q81TAg8PUVNeg%3DtLUn%2BWLi8%3DY%2B%3DFctC9hjs8TVh3mw%40mail.gmail=
.com.
