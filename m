Return-Path: <kasan-dev+bncBDPPVSUFVUPBBQ6XUTCAMGQETGM4JAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id BDE5FB1543A
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 22:15:01 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-74b29ee4f8bsf5496269b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 13:15:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753820100; cv=pass;
        d=google.com; s=arc-20240605;
        b=SPzgeT1f0TzVFcUi+mby24QTx/o6SwN5ofIvTqy+sAINGm2o8BQZw+Bvcp+seZs4qj
         jyx4B3k56PdtVIRrevTfH6qOLa7KcDgIaTnS9EJHpZRb/akJ7NcdOg8fyWJeeoO8VEPZ
         6U68yOkt3Y9TxnADEHgXF+CcY25QWTDEHETa3YNJytokhLM51i48P8DW8KG45t5YlDfw
         12smoqZjDmovIBtdlBhFkYyR28lHAya32Vng3kF+FdArZbyAa/QRgJvymgbBm5oqNju7
         RnjQAvyz5P8SIY7DcHbzWb5slyKLb6p59x4PIHyTrGCrxAIRZuM8FzOWm+I9ffrK/To3
         43Kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pvVRopzOenYLk5UvpSdBWXu4IFU5/T9IVC+DL8tlMZs=;
        fh=hrQOYlTORgaoWpeLPSFlqJQ+ufqDxu/u5bIYsA3oT8A=;
        b=CHJzhjqsJCoHHkIP1X0qELB/0qSSu7fetSee56zCaWYLR50rjJdU/3yyDry0pjGTcX
         m1olM2g5OEDli7iMR3rMXA+u/b3LrrJExr4gOdRHt5LI+CsoOaQKlCT8XNuASZv2pM70
         426r6fr4prZtDLOYfHvBcsXwXoD1DJV3d2zImlXdCvLeBA0Kpx5SAu2NYF8na2f5O7zt
         Qgu30VKtW9ekNe5bKgd1wyrz1nY5PGxiIun4sB7ZEUcFJ0teqHwbbCYC1JLDkVg0CIsH
         Jov6CrRzAe4U4sQmXOuD4tDAO5DMH801kQwg0zaJaW/71lB06humGEZgeS+ZAo1RQIos
         nzbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="RGzQdi/N";
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753820100; x=1754424900; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pvVRopzOenYLk5UvpSdBWXu4IFU5/T9IVC+DL8tlMZs=;
        b=G5MukqlF5I837BVwjmf/C7yIA0ry/LKWrpAHS/sZQGOVw+SHeCsro703yeR+ed+nDZ
         jvzc5j42i6NQz3cNsf1ZpJeXudt6gjrBcj9yytQz8XOF+Q6krlbqZw4SbFVy38e6+Dek
         Hs+YHqO13/VNyBo/1eyte+L9TY0zAayLwlE570nykponC4PnB5QMomdhykMf1ve4uV9y
         SHTFocrLZpmAnsvDcBuiRh1/fp//J22iW2BkZzLgkMcSanf9i8yIvBhG6IDEdU4B4gAq
         /K4+4qpq02cDTSmSOiawzWZnSsP1iL9IZex+s/YRgf+1WbZ6Lx7YEH8Ie87eHTVjFXSi
         fZmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753820100; x=1754424900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pvVRopzOenYLk5UvpSdBWXu4IFU5/T9IVC+DL8tlMZs=;
        b=l6f+xAm3oVyw2fEULBUXFsOCmf7yDpO9HdzGsLQrEswzBFjtVhbLFtq+yDsAkGmYtK
         gm3fAq0MojSPfwSnyHBTITRDS9RokdSPch/Z+Wm5Fz5yXvhhdba9mvQ55iHoYGWbKdNQ
         iLr7K5buMlY8E1b5rBMOHPSRYEP/vm23GYvWeM2YNxA+J5ZDAOvucEa7170aWHnvR9Vm
         ULXEB6AVVa5HpJLLjri6F9e+7TI5/r4CQjnTX8RVFPxYjRjmfj64ZTFqyi/X+E1Yq6uG
         wrw1S2Tg+DHIC/exvjkcVgZsOx/MvxGh8pH3Ci6HZmPP7cPfoxxbPhbVT8IckeglP3R8
         dhAg==
X-Forwarded-Encrypted: i=2; AJvYcCVlvhEpBzwTCAmY49BRIKfAcO4ZZRsHatvc0DUhrlt9kL/cvBp13CiDXKVEL7zp5qfq7l2GbA==@lfdr.de
X-Gm-Message-State: AOJu0YzWUERxgIQQaLrbZgmgyxuVXUL1dE2fHiD/rPzhzh42/T0yRolw
	IOvvw4qkQK8RvzZLctftGwth1oHIYH6AoviQRgJr5P5s2CzGi5/3leY9
X-Google-Smtp-Source: AGHT+IH3C5jUicL/LwDjh0obVhxmivtIrhFrqGt4Gan6DYvjKu8mZLByF3ko15tq7QJcUqN8PISO+Q==
X-Received: by 2002:a05:6a00:ad6:b0:748:9d26:bb0a with SMTP id d2e1a72fcca58-76ab307a7cdmr1290733b3a.18.1753820099933;
        Tue, 29 Jul 2025 13:14:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdEtelUHfySBNUV7DPvL+DBhkZD1D6f9wTjqchNB+nKaA==
Received: by 2002:a05:6a00:1391:b0:76a:8a79:4fa4 with SMTP id
 d2e1a72fcca58-76a8a795149ls416744b3a.0.-pod-prod-07-us; Tue, 29 Jul 2025
 13:14:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVjII3sZSya//zjwo2qVw8hLnA0u4nu8lw0Y7LkIr57bDGsuw3Pd9zFi07nyxkL80L8jNWgGUTbA6w=@googlegroups.com
X-Received: by 2002:a05:6300:210c:b0:234:8b24:1088 with SMTP id adf61e73a8af0-23dc0cfde36mr1043345637.3.1753820098490;
        Tue, 29 Jul 2025 13:14:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753820098; cv=none;
        d=google.com; s=arc-20240605;
        b=Rkcrhu6vFRfVQ+hm9AwGlBP9WjgONhB1y39KbLuf60KP7BCqMMqh204ORaPsChfB5f
         ZGmfkPG2p7VKACdd6T9c3rVkKpHLYYiY2HVkd/2i3u0cRvsB1JYKNSel4g0EVdrv0s99
         f8qEjY0ryU7uDs35jx2jFqKjyP4JYKa8NRVE3pn27gx6yI7dpIrA7HJYhBF/3rXNEI/d
         XhedoamuWrjuLNaHSkaC8iNlSYbBGhMum2sij02JAXSh+ya8a5lqtAjmEdsw0WXL1cpb
         Q4A75Lk/chg6i/UVi9yLXmFIlEpRL/xvZ11jiYjKUFBLVLXopD3uhFjKaKuvF1tfHVol
         BT/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OSnWvLIZJHusV5qXMM/Z1MPamN78DUoFkI8w/hNGO08=;
        fh=0TkwpFrvZJ7lcDK5sMX3Ffuxd7fQUjAeuRqQn7TddYg=;
        b=Vuao1uPnqCMQrfIg8o4ZBny5KTAlRERZt9EBC85OWsQpmzUtjbw/ugweGsSj87kkb4
         Cuy4pvBuUBI4Cxif14BhzDT7uhnFTWRcA7aKadIsMVSQohuj6FUbUtYAVRpmcnMgVdYj
         q9QkCAV7ZNRTqRN6VBOHmT9Yojt8r+pVPoiciDvd1gK7x8iBjRtJ0QmJPus8aNe9cfVx
         4nFEmukovnq/IfM3SLJw2hrN+NZsjFPdvde1jykzjCoHiPvM3M5eRCzxNCeHorwKY3IM
         1xVsPPHl/MFsasOcy2DWDBG0KPeZRvfIqjsdrGPc5VwM6cjKXHRkfF/yppCk8ECrV0o2
         CzqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="RGzQdi/N";
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7640b1decfesi330853b3a.4.2025.07.29.13.14.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 13:14:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-70749eac23dso19547156d6.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 13:14:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUeckvNH/FEqd4Kq+2ZQumwIwsw+DhrsEqsPChXJZVNnWOfwXu8SrF8XoWGMMSG6eZrDIKt597Avr4=@googlegroups.com
X-Gm-Gg: ASbGnctcWJmr3ufIk8VoT8ob/h1BKUW2dbmzwRy6x3qy5rOVMaGjJxWUCe03kniDQRa
	BEvXuo2a04E3OaJEJnV5XITuzGkY2/FIRwOY5+VYl2XSWK9W+vyVBBFtxbvr5+gxKUFZ1no2o0c
	SFhee7bnnK/1hM9yRR4rX6dfIZ/g6jIpwn8d6EVHyfB27AqurbhfrCUPR7rkQ+NXHF3SIHaSmtG
	HuJLZYTex7gH3KRyCqqQQZj3fr1+3Eg9lytgg==
X-Received: by 2002:ad4:5cae:0:b0:705:11dc:546c with SMTP id
 6a1803df08f44-707674da9c4mr12811666d6.37.1753820097172; Tue, 29 Jul 2025
 13:14:57 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-7-marievic@google.com>
In-Reply-To: <20250729193647.3410634-7-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Jul 2025 16:14:46 -0400
X-Gm-Features: Ac12FXxmZ42K4shP8Mq6epf9R75hJmaK1TQ-k_VZv48ddvB09KJQMcLmT_EDWjs
Message-ID: <CA+GJov7gQMughx7wR5J_BGqo7FaPhEPF-OHaCg3OuuL17X5vpA@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b="RGzQdi/N";       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f33 as
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

Hello!

Thanks for sending out this series! I will do a full review of it. For
now, I noticed that I get an error when I try to run KUnit tests as
modules. I get the following error: "ERROR: modpost:
"kunit_get_next_param_and_desc" [lib/kunit/kunit-example-test.ko]
undefined!". As a possible fix, I suggest moving the function
definition into the header file and making it a static inline
function.

Thanks!
-Rae

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
A%2BGJov7gQMughx7wR5J_BGqo7FaPhEPF-OHaCg3OuuL17X5vpA%40mail.gmail.com.
