Return-Path: <kasan-dev+bncBDPPVSUFVUPBBQWBZDCAMGQEQWID3II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F6DFB1B743
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 17:18:28 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-31f4d0f60casf5747326a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 08:18:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754407107; cv=pass;
        d=google.com; s=arc-20240605;
        b=lgPRJixgn/shgHsn+oU75durNvkr6V4BHvFNhhcXDf29qou0L5oYfCut5qSxjTnFQK
         P6cBYb8sVZzsaETuFm4IBPWQiTk3sXswMnlmLI7/eHl5iNgzEzsv8Ly2oRftiAKvp30Q
         TN1AyO0+1S8hDlSKGXyLnIWXrKejnxRARN9MiGdkJL+OJBdaPbL3O/AHoHVTEPtWXVPT
         UKNCwSCqSpzUUYHmqwxG0p99ogH2JXEzt6eX4NmbZTJJFfjVVXnX0IqIzBqGP2IFBa7N
         tr1bm5j0QQpiGRPxu814TZANU091MM8BBfkE6ve+8SbFj/ccEfVHT72eHy56Tu044H41
         zpow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Yvpvh3xFKQRwq3c/jDDi2Xa5WIbtEyyE+PnBaY92Tm0=;
        fh=HoiaMhmGPCocO+bKVlSrjloOqnB9niKbrN2pdNuaRP4=;
        b=Is+jfINLYDgEsL9M9Khg6N/gONo9+QSKX0c5xgMqPQhXEIYWmRoe0XMJQvubvKTDj3
         5WQEINSbd1yYqMBJpxi7pNuKGqnLc3U1JWScsBZJEssVZPXGy225LaFyU+kGnJWmAoeB
         iCB3nPIdkNqy/nZ35hxY7qHV3tYDqXbP6UlHBcrF2YoQ9RiLD4bTNoOg7YvdaZNGm0Ao
         MP9OeupScWgJBDYsALqHyjbElqWVXVyfMYfAtZG5DEYVf2HFODvpSzYlcTKCAhzpV+tJ
         Iv8EItE/yUrYMG9Lonw6hFknkVwzNwYSt0/2LAew/jd5FepIU2MkLW/yc2fprX94JuYb
         /bCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=V9LoHkMr;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754407107; x=1755011907; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Yvpvh3xFKQRwq3c/jDDi2Xa5WIbtEyyE+PnBaY92Tm0=;
        b=SjoCw+C0XXRRf28+RqJIB1WXjymzuOr9fPnpzUUGSXE7PS1Z8mXRB1HCqbQWl+2DTO
         i8MnLtsZPhytV0VnyFpmgvwV04Qc2Nzj5sq3TD4J3zJhNhWj/vytwCZNYfoAyuXxL/6B
         N5LnV2R5Jp8WmbmtaUCnHHm3qRcuCagBKg9E+DaH1hk760E2BoCHdfpSTivq7Ro2Nt+C
         2ENl/NP7z9jvisXtsNua0RVjS2yAjKjYMwza+5QwukXZQPYjOtfT8o2c/oxRrAQ0CItl
         YdYlSG+V2jtNms4QZv8z6v34ar9F0fDrTts1FRFxx7cnzceYG5N7cRNkAkQwf4k9J5tb
         LJKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754407107; x=1755011907;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Yvpvh3xFKQRwq3c/jDDi2Xa5WIbtEyyE+PnBaY92Tm0=;
        b=OdL2z2ZuMXlGLo2ci3MpvGN1aT0c7zDtvge58HWkzvGhZX9wfBtvBNHZ6LIU+m7kjF
         dIIx4AU0zb/bYRhJrMJbEWNDfIvf0Vf3xZr5J5pjbyPNL4Ea2C85ZXiIo0Wo/jxH90FR
         gtKcIuKV+eNFGBiNgqKvwx+F+rviYi30mzj0LU00xXVL2lMxBCPOLwVvK/srNl+BzHLa
         aafNykPzhh+7KOpWlrFXxMQiiTZ8bsHEUGrb664VMG2/2WhmkHD++ZdZWwJf3d8d7kya
         fQiDRTRG6+fU0eFMnpsFx7T4Z4vTj6KXLAYFfxyxppM9xHb3PjrJHgc8kbVqK4iDnd5B
         AdDw==
X-Forwarded-Encrypted: i=2; AJvYcCUttxPsKQRIvuQED1c+R6AymQfmDhEqrNbxNnhclso6n9PgxJKwDxl9hgzLqsPoOAa8Vg1iDQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz1h/35or/3MW8cjgQukp/zZVo4jgPkuA69aCxr24+HJ3AxMbZ3
	Ymhkujg9J3uWnfRZqALrMnr/q7J6G0WxsF/M3/xPxeRlVkaHT9nwfQzR
X-Google-Smtp-Source: AGHT+IFamn6T7gJN4YXx/YnILE6rbwFQeeB46D+Z2Fefrhp7JaUx5OvNaNPJWmjTPuW/ilqX1OSiPw==
X-Received: by 2002:a17:90b:5785:b0:31f:42cd:6900 with SMTP id 98e67ed59e1d1-321161f2ce2mr21184606a91.12.1754407106585;
        Tue, 05 Aug 2025 08:18:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfF3PaLdWuY9T7pXz8cA1WhCO1323Wm401WxcsLcm1iYw==
Received: by 2002:a17:90b:2c8c:b0:31e:f3b4:707e with SMTP id
 98e67ed59e1d1-31f910f2922ls5161959a91.0.-pod-prod-02-us; Tue, 05 Aug 2025
 08:18:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVI81YJB0+GZgw8dfhV8Hpn2StDAJEaRPjAoPHiiV/sZK+WJJ3mGTA8ZH2T2G2Ctl4wEIN5zCGlmQc=@googlegroups.com
X-Received: by 2002:a17:90b:33cd:b0:31f:42cd:690d with SMTP id 98e67ed59e1d1-321161f21d0mr18147912a91.13.1754407105210;
        Tue, 05 Aug 2025 08:18:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754407105; cv=none;
        d=google.com; s=arc-20240605;
        b=PvoXukL4qqImeY6SV4baIz9SKK/7LvY/U8z0+FsX+s4afH6ObpY32ezb7lF74LewDZ
         o8hAFCt0JeOqn7zZTDfcce9BhE2bAzYMrcmnBHWUC9xJG7FxgTwirzggskAaVdBpx+bS
         FnKXXCUjNSAmFFBCqBOO1ybp270HCCqm+CR8XtBbsA2g5B/7Q+hu1oJPl0i/itDMT18m
         x+2HORzYazA7XEHyFFI7kMj3pcYSOZgOJTq6Qpy1JLU8+30UTBmW4mhrbfLF2rt1VUo/
         2nUkqNNheLRZiywbo7Bqf5CtbfJ8r5hmstmcsslgqSjHGu3QOiB6fGPjMiPxRxQ3R4Yk
         iPTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Ei2suQoiKM6jZ+vrvxUS6sJAz8bgwy+vg3WdcqYInd4=;
        fh=UNE0xo+vHohAsTA8BGqa1llaOsnmY4B8ueFLgxmj2qg=;
        b=Fmjn8mz/X001ePkFOgQYnapli2P2W6OIF0I2KuwQVRIFg5tyAq1psqIdsZhB7jBpT6
         vJKv7gA87lj0kDSt0EttL5D7jJ+i6P6XvLRbud/YHLAJQvKVcHGWHE4X4jYdSbQNQPzU
         m7rBNFsJTqmz0AtO3OypkKnzA93gtTDpsWwk2Vk0snH7hF07kacjG6v72lhC1JFM9b4l
         uKA2GwySWsqd9HXCWGqahr8KPYwONLfzjaX1mpgzxAGG5HLOCJuUy9/yM36J5Mqviypa
         oBqupbKAwJjdoFKDfF7yaMhok0DmwvvIzeiAco1RBWDv/leZVmximmgYc5I5/uAa36jU
         y5mg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=V9LoHkMr;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-321028690e7si376265a91.0.2025.08.05.08.18.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 08:18:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-70748a0e13dso46888746d6.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 08:18:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVSNRB27+eKGfb63QzUFhRvtby8UpyJntDcM7BR/VA06pq0DpkBN0yb0w4Tqt6y0vD+v8nxbGxBEmI=@googlegroups.com
X-Gm-Gg: ASbGnctVpykG9DFX/2d3UXbNy4e/NJIQYWAjw/yHsY67NK87bdvwOvvgaA/1L8gz8jX
	dHs7+waGYARQtgWV5qFwzKNzpaPUv+oQoCTLHORkYDQgnMXcwkA3J3TnCWGRkgXL+jiyxf9mGq4
	wc60TvghIPLSNti2f1s8mQsHrJk6rwO6+FOO3NCw+fecWKy7qDx24YV26m4mu+N57UvwDA938hB
	cZoGso9/0MGcy6+YRnYVnPNdLFdHkJSoE4HjrEeZw==
X-Received: by 2002:ad4:5c62:0:b0:707:6302:90aa with SMTP id
 6a1803df08f44-7093626d773mr195026586d6.27.1754407103617; Tue, 05 Aug 2025
 08:18:23 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-4-marievic@google.com>
In-Reply-To: <20250729193647.3410634-4-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Aug 2025 11:18:12 -0400
X-Gm-Features: Ac12FXz9W5TjaYltj_nslVN8LL6euuV8WCMgJLzVdBjdaff9DG8lUm24r6Pqnn8
Message-ID: <CA+GJov5Faik_aBzDO6QY3Rj_ycq=A6ZqOsuP-m6G1n3jtpNCYg@mail.gmail.com>
Subject: Re: [PATCH 3/9] kunit: Pass additional context to generate_params for
 parameterized testing
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
 header.i=@google.com header.s=20230601 header.b=V9LoHkMr;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2b as
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
> To enable more complex parameterized test scenarios,
> the `generate_params` function sometimes needs additional
> context beyond just the previously generated parameter.
> This patch modifies the `generate_params` function signature
> to include an extra `struct kunit *test` argument, giving
> users access to the parent kunit test's context when
> generating subsequent parameters.
>
> The `struct kunit *test` argument was added as the first parameter
> to the function signature as it aligns with the convention
> of other KUnit functions that accept `struct kunit *test` first.
> This also mirrors the "this" or "self" reference found
> in object-oriented programming languages.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>

Hello!

Extremely happy about this change. This will provide us much more
flexibility when defining test parameters. Thank you for this
implementation!

Reviewed-by: Rae Moar <rmoar@google.com>


-Rae

> ---
>  include/kunit/test.h | 9 ++++++---
>  lib/kunit/test.c     | 5 +++--
>  2 files changed, 9 insertions(+), 5 deletions(-)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index d8dac7efd745..4ba65dc35710 100644
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
>
>         /*
> @@ -1701,7 +1702,8 @@ do {                                               =
                              \
>   * Define function @name_gen_params which uses @array to generate parame=
ters.
>   */
>  #define KUNIT_ARRAY_PARAM(name, array, get_desc)                        =
                       \
> -       static const void *name##_gen_params(const void *prev, char *desc=
)                      \
> +       static const void *name##_gen_params(struct kunit *test,         =
                       \
> +                                            const void *prev, char *desc=
)                      \
>         {                                                                =
                       \
>                 typeof((array)[0]) *__next =3D prev ? ((typeof(__next)) p=
rev) + 1 : (array);      \
>                 if (__next - (array) < ARRAY_SIZE((array))) {            =
                       \
> @@ -1722,7 +1724,8 @@ do {                                               =
                              \
>   * Define function @name_gen_params which uses @array to generate parame=
ters.
>   */
>  #define KUNIT_ARRAY_PARAM_DESC(name, array, desc_member)                =
                       \
> -       static const void *name##_gen_params(const void *prev, char *desc=
)                      \
> +       static const void *name##_gen_params(struct kunit *test,         =
                       \
> +                                            const void *prev, char *desc=
)                      \
>         {                                                                =
                       \
>                 typeof((array)[0]) *__next =3D prev ? ((typeof(__next)) p=
rev) + 1 : (array);      \
>                 if (__next - (array) < ARRAY_SIZE((array))) {            =
                       \
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index d80b5990d85d..f50ef82179c4 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -696,7 +696,7 @@ int kunit_run_tests(struct kunit_suite *suite)
>                         /* Get initial param. */
>                         param_desc[0] =3D '\0';
>                         /* TODO: Make generate_params try-catch */
> -                       curr_param =3D test_case->generate_params(NULL, p=
aram_desc);
> +                       curr_param =3D test_case->generate_params(&test, =
NULL, param_desc);
>                         test_case->status =3D KUNIT_SKIPPED;
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT =
KUNIT_SUBTEST_INDENT
>                                   "KTAP version 1\n");
> @@ -727,7 +727,8 @@ int kunit_run_tests(struct kunit_suite *suite)
>
>                                 /* Get next param. */
>                                 param_desc[0] =3D '\0';
> -                               curr_param =3D test_case->generate_params=
(curr_param, param_desc);
> +                               curr_param =3D test_case->generate_params=
(&test, curr_param,
> +                                                                       p=
aram_desc);
>                         }
>                 }
>
> --
> 2.50.1.552.g942d659e1b-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov5Faik_aBzDO6QY3Rj_ycq%3DA6ZqOsuP-m6G1n3jtpNCYg%40mail.gmail.com.
