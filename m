Return-Path: <kasan-dev+bncBDQ67ZGAXYCBB6NC2XCAMGQEXHFAURI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 817A6B1E025
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 03:23:07 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-459e4b85895sf8472595e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 18:23:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754616187; cv=pass;
        d=google.com; s=arc-20240605;
        b=EAkpJ+IJjE2SmoAjB//8Pbbix5U9C0FvWp+/36hwypdZyURcOmzdC+j13oqUdfdapB
         ZRBbVVgtXYwVQjCB8bn2qXqRtHFtc5xywYMLVPBtnTUwwZ/5Wv/WUB8aQGPDJhp56lsM
         +093JlXg8Qkfxj1ilJ6IMWelwxGCXsdMDniieBilsLWPs56saMzzPl3c+uIUNXAZkNYd
         5JOXbpHnQ7vLDlGyViwh4lRcjIzUdFI3OrnVgTgdrNQ/E+m9p2XWMIu46PRTSyIYrRCK
         m7exACG+l8/tR/9MFk+OP6Dyi6eG52O3VoBnANnf4l7dfF+TtymJx36z/xODT+q8+6fB
         xdKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=02ozxyJCSljRHxQtwTzNTRDrKggKSVU9iB8mkhPMXek=;
        fh=+z1OWJuACvwJQsPND7+ke0nZM6y2jJloaaR9TBtWC4I=;
        b=XV9IOppFzdaetEFR0VZ/1dYuVG0Qvluwd/tFDYe73XPoX+RHs2+AduGcfQCTR3GG1a
         RESlQzyt1RpysFx0Zo2JEtsYTt+Km6El64dl2hSb6V2SYWoPY6gFxnXVFlj+8DhkCSDv
         R6DD+oMkcNEISufoogABKr2xFDJYF9w+m+vDFhnyrnDTSZNUxJUdpseR3XbNE3LrAWHm
         3FUeZLhzhYkHChXO2X6Z8Q7EREM9Qsi+b/Savvd0nmXa9fT3KPWc85QZDBmigP/iusTs
         emIdy6J6VZo3dtPv9cg62V+rqt57nsdsjXfryB+Q6EAnu+/lmrWKHTALLo/Lyy89am1b
         DvJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kRmSvGJe;
       spf=pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=marievic@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754616187; x=1755220987; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=02ozxyJCSljRHxQtwTzNTRDrKggKSVU9iB8mkhPMXek=;
        b=KzYTJqNNOUTaQ0B/ofMF9cwFUV68HgzXIeYOQkwpmUdWt456w7GAdkVSheDqWy0fTs
         6gSvWtNXrtOEZRrohLgSaKWZlfzWGdUt5RyEsr5LyNbeYIhxiPKMGiE2ALdFCwDXRO/i
         qmAz2wylSbVGOpqBUUTCJ8SPEi5jtGWx7VlQDJIceQ1jkQw/M42Ig43NR8NKiSX6oYwi
         WcN5j6QxuroJsG3BspcoxGQ/Va3quV64/N5bDzhuowW2VXBOZagf1mL/XowcH/GHvfCi
         Jtw+jVpNuZ5Duw9NWlcSZbNSlKpifglnDoBmtMeEzkpQ1cpCmPD4q7ghpXVglasC4h4n
         xKOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754616187; x=1755220987;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=02ozxyJCSljRHxQtwTzNTRDrKggKSVU9iB8mkhPMXek=;
        b=er2vsjNUfxBRcy+weYWJOL1FIJaLzYpwsUJ6WqW54XCFEewya2D4bn/F28A21AuPTG
         UrGB/X8et68a18qaCjW7gk7ncSj6MlfbWFqJpDDDoGZJ+smYIIagTDy6IW2O/f8WvfUd
         X0Qah7qIuCy+HXGzokP0UzBMG04bjMA8v1e1iYSa0gpotiawoXNIxQrT/RTUK42FfhL9
         yt3JqlOl38TljZ4ZZjp2R0lq5UvpxR3IfakuJNQDJOXXz7rqNJnf43xPKQbbCirbp4qD
         WsjN7iUlSUrX5GnHEnyu2S1vMNFiZvfUW9yb845SYgxA/y8hgvptIHx/0scyij+vMS6N
         CV4Q==
X-Forwarded-Encrypted: i=2; AJvYcCX6Ivtq9Js/4tUl+tDtw9G/wf+WLc1DPAOnd+eJ2C37MUY7VUce128m+NIGfoCWNvb9UMvJ+w==@lfdr.de
X-Gm-Message-State: AOJu0YysqG1hXoXsSkyX16ocNdVbqZmmFwpT3V3Ep4/68OtXqGRUWjgB
	CZtK7QE5nrw6x2QgdVGPecxyI2Z3fVX08trtL1hsVEVOJFjkhQalY+pq
X-Google-Smtp-Source: AGHT+IE/39q4+bYUN2Q+0tOYAvHubxGHWjAsJMUTcE3VspEDmLC9unAJPFKCKitnjfaUbk6tVyJ2YQ==
X-Received: by 2002:a05:600c:354d:b0:458:be44:357b with SMTP id 5b1f17b1804b1-459f4ed2360mr7346975e9.15.1754616186655;
        Thu, 07 Aug 2025 18:23:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf9LNwgOeQ9joXgNK4UonhwZc3/ZjYER291TAj6xaw9zQ==
Received: by 2002:a05:600c:3b8c:b0:456:241d:50c3 with SMTP id
 5b1f17b1804b1-459eddfa743ls8133915e9.1.-pod-prod-08-eu; Thu, 07 Aug 2025
 18:23:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWx5x2m5L6bPrOwcakE7ff7QcfyhwxUzwzsENDYXCpXkUxmqiFjgAmjOZd/UOdkFo1xWangjHvthWI=@googlegroups.com
X-Received: by 2002:a05:600c:46cb:b0:456:f00:4b5d with SMTP id 5b1f17b1804b1-459f4f11e37mr6183465e9.22.1754616183125;
        Thu, 07 Aug 2025 18:23:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754616183; cv=none;
        d=google.com; s=arc-20240605;
        b=jgSGoiYrvKeeX9jVU2BFoUCFQs51Ix+S7MgU5Rm7o2IXiCNTP0Ds8Wo9uZIi6LfPOC
         crvujNA8/OJzhh+0iJmN1t4rf/NrZMAcVWHyPPf/JIGZLfwiLJzS1ZCIu7GH52Xsk9Yr
         60uvohe+UlxGcp34ljoDT3z7mT7A7RAci1UABB6tYN+m/buZycZd8yho7BZyW92E6aIP
         rosZFj196SA2MRiquiDKLEUuM0EdUWQ3XigPPOUKkatMekcQVdSQH1IObMEfJia/juaj
         ip3QPHqz8i2xMMMgcW9Z56bK6WPfDRmSw3BLPYwClujd0c2Dzdx8YGrfqtayHVKd7VGv
         zaAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2D00aj35qn0lgLEWR00CYBcQuTXDPk0GIrAj2AelFpM=;
        fh=o/gMsdiwu70zbvWfnAqa8hMfsNfSnd81tCuqBsHGmlo=;
        b=FSaOZRnZ/agRNjbymPWw6d9uDJj1fbpWvfRdHJTC+eJe33mm51DRBzhCIZPZU+aCMZ
         Y5WAXp9KiuvSy9CzQaWCM9tmKNatZqWwVPwLUkvYPov/INNPtbk1NbQTaIFziFg5dEZs
         Zxb0kQmqpEqEqczyeU8UEweix15nqf4P8zkPSjwQODDwR0Pd5+KCRmhH25S/lLJO9ady
         5KPpEtrM/N4fiq6GN5P+xPSuWGIf+VfdHS/CGp2X0K/vqscsYdtWCjvFxNMEw6dZj72c
         1OZ9JPFu8M2HssS5fcQMidCjRdCZnlxYWytUqfkeJ0tHYQyzNOcC0pAvpBMa0kYYxgi3
         781w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kRmSvGJe;
       spf=pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=marievic@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b8fa67b1f3si54181f8f.3.2025.08.07.18.23.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Aug 2025 18:23:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id 4fb4d7f45d1cf-61543b05b7cso5849a12.0
        for <kasan-dev@googlegroups.com>; Thu, 07 Aug 2025 18:23:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXRgqLUVvHYiPA+PujWWFaYwMlBtPMQ8RVtA5/qooPuXrM+2o4TbrafsmbV0jCNhKHfG+QZ7pJYJF8=@googlegroups.com
X-Gm-Gg: ASbGncs3iAwVFlxFvtNM5eH23Vmt5CqlYmrNaEHdSyKmcrGlJ1jR61D1N9yYQdvTZaI
	TmP3al5+QGLqbwk3hBI4YvwqhGGhI1NhWvIMjDQ8W97HMadGRM37EbxsjTd6umzEhuuIgIOZq1p
	LvyvO+PDshTB8j4kvBYIFBjqOVmTH5PAaoIZW2stCGj0Q4q1Q+0LKcOjOxUU+x5Cey3P6ZlEqeR
	wC9bEtF
X-Received: by 2002:a50:8ac9:0:b0:615:6167:4835 with SMTP id
 4fb4d7f45d1cf-617e4938cc5mr22550a12.7.1754616182348; Thu, 07 Aug 2025
 18:23:02 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-7-marievic@google.com>
 <CA+GJov7AH5Qyiaua7LKZjVNRoUd==DiSXvd1UP7TcSzvn5JZtQ@mail.gmail.com>
In-Reply-To: <CA+GJov7AH5Qyiaua7LKZjVNRoUd==DiSXvd1UP7TcSzvn5JZtQ@mail.gmail.com>
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Aug 2025 21:22:50 -0400
X-Gm-Features: Ac12FXy83TfjpYK_0eq_uQ1ZcPI2DWSWUtOe3NX9vC6swmGOuFsU9to_-ct3_vs
Message-ID: <CAAkQn5LUA-gRj9nypcf0jE+gjRwN2axkJ4KO14Aj8AB3dhZHsw@mail.gmail.com>
Subject: Re: [PATCH 6/9] kunit: Enable direct registration of parameter arrays
 to a KUnit test
To: Rae Moar <rmoar@google.com>
Cc: davidgow@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: marievic@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=kRmSvGJe;       spf=pass
 (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::534
 as permitted sender) smtp.mailfrom=marievic@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marie Zhussupova <marievic@google.com>
Reply-To: Marie Zhussupova <marievic@google.com>
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

On Tue, Aug 5, 2025 at 11:18=E2=80=AFAM Rae Moar <rmoar@google.com> wrote:
>
> On Tue, Jul 29, 2025 at 3:37=E2=80=AFPM Marie Zhussupova <marievic@google=
.com> wrote:
> >
> > KUnit parameterized tests currently support two
> > primary methods for getting parameters:
> > 1.  Defining custom logic within a `generate_params`
> >     function.
> > 2.  Using the KUNIT_ARRAY_PARAM and KUNIT_ARRAY_PARAM_DESC
> >     macros with pre-defined static arrays.
> >
> > These methods present limitations when dealing with
> > dynamically generated parameter arrays, or in scenarios
> > where populating parameters sequentially via
> > `generate_params` is inefficient or overly complex.
> >
> > This patch addresses these limitations by adding a new
> > `params_data` field to `struct kunit`, of the type
> > `kunit_params`. The struct `kunit_params` is designed to
> > store the parameter array itself, along with essential metadata
> > including the parameter count, parameter size, and a
> > `get_description` function for providing custom descriptions
> > for individual parameters.
> >
> > The `params_data` field can be populated by calling the new
> > `kunit_register_params_array` macro from within a
> > `param_init` function. By attaching the parameter array
> > directly to the parent kunit test instance, these parameters
> > can be iterated over in kunit_run_tests() behind the scenes.
> >
> > This modification provides greater flexibility to the
> > KUnit framework, allowing testers to easily register and
> > utilize both dynamic and static parameter arrays.
> >
> > Signed-off-by: Marie Zhussupova <marievic@google.com>
>
> Hello!
>
> Very excited by the prospect of setting up an array dynamically
> instead of statically for parameterized tests. In general, I am happy
> to see this framework is becoming more flexible and therefore more
> tailored to our test author's needs.
>
> I already commented on the modpost error but I have a few more
> comments and ideas below. Let me know what you think.
>
> Thanks!
> -Rae
>

Hello Rae,

I have added replies to your comments below.

Thank you,
-Marie

> > ---
> >  include/kunit/test.h | 54 ++++++++++++++++++++++++++++++++++++++++----
> >  lib/kunit/test.c     | 26 ++++++++++++++++++++-
> >  2 files changed, 75 insertions(+), 5 deletions(-)
> >
> > diff --git a/include/kunit/test.h b/include/kunit/test.h
> > index 4ba65dc35710..9143f0e22323 100644
> > --- a/include/kunit/test.h
> > +++ b/include/kunit/test.h
> > @@ -245,7 +245,8 @@ static inline char *kunit_status_to_ok_not_ok(enum =
kunit_status status)
> >   */
> >  #define KUNIT_CASE_PARAM_WITH_INIT(test_name, gen_params, init, exit) =
         \
> >                 { .run_case =3D test_name, .name =3D #test_name,       =
             \
> > -                 .generate_params =3D gen_params,                     =
           \
> > +                 .generate_params =3D (gen_params)                    =
           \
> > +                  ?: kunit_get_next_param_and_desc,                   =
         \
> >                   .param_init =3D init, .param_exit =3D exit,          =
             \
> >                   .module_name =3D KBUILD_MODNAME}
> >
> > @@ -294,6 +295,21 @@ struct kunit_suite_set {
> >         struct kunit_suite * const *end;
> >  };
> >
> > +/* Stores the pointer to the parameter array and its metadata. */
> > +struct kunit_params {
> > +       /*
> > +        * Reference to the parameter array for the parameterized tests=
. This
> > +        * is NULL if a parameter array wasn't directly passed to the
> > +        * parent kunit struct via the kunit_register_params_array macr=
o.
> > +        */
> > +       const void *params;
> > +       /* Reference to a function that gets the description of a param=
eter. */
> > +       void (*get_description)(const void *param, char *desc);
> > +
> > +       int num_params;
>
> Since in some cases we know the number of params within a series/suite
> of the parameterized tests, is it possible for us to print a test plan
> line in KTAP when this number is known? This would be helpful for
> reading test results but also the parser could verify the number of
> subtests is the number expected.

This sounds like a great idea. My initial worry was that the availability
of the test plan would be inconsistent since there would be no parameter
count information when the parameters are generated using a custom
generate_params function unless a test user provides them.
However, it is good to provide any information that we have.

>
> > +       size_t elem_size;
> > +};
> > +
> >  /**
> >   * struct kunit - represents a running instance of a test.
> >   *
> > @@ -302,12 +318,14 @@ struct kunit_suite_set {
> >   * @parent: for user to store data that they want to shared across
> >   *         parameterized tests. Typically, the data is provided in
> >   *         the param_init function (see &struct kunit_case).
> > + * @params_data: for users to directly store the parameter array.
> >   *
> >   * Used to store information about the current context under which the=
 test
> >   * is running. Most of this data is private and should only be accesse=
d
> > - * indirectly via public functions; the two exceptions are @priv and @=
parent
> > - * which can be used by the test writer to store arbitrary data or dat=
a that is
> > - * available to all parameter test executions, respectively.
> > + * indirectly via public functions. There are three exceptions to this=
: @priv,
> > + * @parent, and @params_data. These members can be used by the test wr=
iter to
> > + * store arbitrary data, data available to all parameter test executio=
ns, and
> > + * the parameter array, respectively.
> >   */
> >  struct kunit {
> >         void *priv;
> > @@ -316,6 +334,8 @@ struct kunit {
> >          * during parameterized testing.
> >          */
> >         struct kunit *parent;
> > +       /* Stores the params array and all data related to it. */
> > +       struct kunit_params params_data;
>
> I might slightly prefer the term params_array rather than params_data.
> Up to what you prefer.

I like params_array because it's a naming convention similar
to what object-oriented programming (OOP) languages like
Java use. For instance, an ArrayList object encapsulates
both an array and its size. I will make this change in v2.

>
> >
> >         /* private: internal use only. */
> >         const char *name; /* Read only after initialization! */
> > @@ -386,6 +406,8 @@ void kunit_exec_list_tests(struct kunit_suite_set *=
suite_set, bool include_attr)
> >  struct kunit_suite_set kunit_merge_suite_sets(struct kunit_suite_set i=
nit_suite_set,
> >                 struct kunit_suite_set suite_set);
> >
> > +const void *kunit_get_next_param_and_desc(struct kunit *test, const vo=
id *prev, char *desc);
> > +
> >  #if IS_BUILTIN(CONFIG_KUNIT)
> >  int kunit_run_all_tests(void);
> >  #else
> > @@ -1735,6 +1757,30 @@ do {                                            =
                                \
> >                 return NULL;                                           =
                         \
> >         }
> >
> > +/**
> > + * kunit_register_params_array() - Register parameters for a KUnit tes=
t.
> > + * @test: The KUnit test structure to which parameters will be added.
> > + * @params_arr: An array of test parameters.
> > + * @param_cnt: Number of parameters.
> > + * @get_desc: A pointer to a function that generates a string descript=
ion for
> > + * a given parameter element.
> > + *
> > + * This macro initializes the @test's parameter array data, storing in=
formation
> > + * including the parameter array, its count, the element size, and the=
 parameter
> > + * description function within `test->params_data`. KUnit's built-in
> > + * `kunit_get_next_param_and_desc` function will automatically read th=
is
> > + * data when a custom `generate_params` function isn't provided.
> > + */
> > +#define kunit_register_params_array(test, params_arr, param_cnt, get_d=
esc)                     \
>
> I also might slightly prefer params_array and param_count here instead
> of params_arr and param_cnt. Again this is definitely a nitpick so up
> to you.

I will do params_arr and param_cnt in v2, it definitely looks better.

>
> > +       do {                                                           =
                         \
> > +               struct kunit *_test =3D (test);                        =
                   \
> > +               const typeof((params_arr)[0]) * _params_ptr =3D &(param=
s_arr)[0];                 \
> > +               _test->params_data.params =3D _params_ptr;             =
                           \
> > +               _test->params_data.num_params =3D (param_cnt);         =
                           \
> > +               _test->params_data.elem_size =3D sizeof(*_params_ptr); =
                           \
> > +               _test->params_data.get_description =3D (get_desc);     =
                           \
> > +       } while (0)
> > +
> >  // TODO(dlatypov@google.com): consider eventually migrating users to e=
xplicitly
> >  // include resource.h themselves if they need it.
> >  #include <kunit/resource.h>
> > diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> > index f50ef82179c4..2f4b7087db3f 100644
> > --- a/lib/kunit/test.c
> > +++ b/lib/kunit/test.c
> > @@ -337,6 +337,13 @@ void __kunit_do_failed_assertion(struct kunit *tes=
t,
> >  }
> >  EXPORT_SYMBOL_GPL(__kunit_do_failed_assertion);
> >
> > +static void __kunit_init_params(struct kunit *test)
> > +{
> > +       test->params_data.params =3D NULL;
> > +       test->params_data.num_params =3D 0;
> > +       test->params_data.elem_size =3D 0;
> > +}
> > +
> >  void kunit_init_test(struct kunit *test, const char *name, struct stri=
ng_stream *log)
> >  {
> >         spin_lock_init(&test->lock);
> > @@ -347,6 +354,7 @@ void kunit_init_test(struct kunit *test, const char=
 *name, struct string_stream
> >                 string_stream_clear(log);
> >         test->status =3D KUNIT_SUCCESS;
> >         test->status_comment[0] =3D '\0';
> > +       __kunit_init_params(test);
> >  }
> >  EXPORT_SYMBOL_GPL(kunit_init_test);
> >
> > @@ -641,6 +649,22 @@ static void kunit_accumulate_stats(struct kunit_re=
sult_stats *total,
> >         total->total +=3D add.total;
> >  }
> >
> > +const void *kunit_get_next_param_and_desc(struct kunit *test, const vo=
id *prev, char *desc)
> > +{
> > +       struct kunit_params *params_arr =3D &test->params_data;
> > +       const void *param;
> > +
> > +       if (test->param_index < params_arr->num_params) {
> > +               param =3D (char *)params_arr->params
> > +                       + test->param_index * params_arr->elem_size;
> > +
> > +               if (params_arr->get_description)
> > +                       params_arr->get_description(param, desc);
> > +               return param;
> > +       }
> > +       return NULL;
> > +}
>
> I also agree with David that it should definitely be considered: 1 -
> whether to utilize struct kunit_params for the case of using
> KUNIT_ARRAY_PARAM and 2 - whether the user should actively input this
> function instead of setting generate_params to NULL.
>
> Another idea that just popped into my head is if we have access to
> struct kunit* test now in all of the generate_params functions,
> instead of setting a "desc" could we just set the test->name field?
>

Utilizing struct kunit_params in KUNIT_ARRAY_PARAM is a great idea
as that would mean greater test plan availability as well as the consistenc=
y
of storing parameter array information in struct kunit_params.

To the second point, I think the user being asked to explicitly input
kunit_get_next_param_and_desc if they are registering a parameter
array in param_init is a good solution. It would make the code easier
as there would be no extra logic happening behind the scenes.
Moreover, we would always know that if it's a parameterized
test then the generate_params function is not NULL. The only thing
is that we would have to document it really well.

Another potential solution could be to assign the
kunit_get_next_param_and_desc function to generate_params
in the  __kunit_init_parent_test function that runs param_init, if we
keep its run before we determine that a test
is parameterized (I know you commented on this here:
https://lore.kernel.org/all/CA+GJov5R2GnBfxXR=3D28vS3F4b1E-=3DWLDXpgdJo0SpK=
AXb1dpsw@mail.gmail.com/).

__kunit_init_parent_test could set generate_params to
kunit_get_next_param_and_desc if generate_params is NULL
and kunit_params is non NULL, after the param_init call.
What are your thoughts?

Finally, utilizing test->name could be something to do in a future patch.
First, we wouldn't need to pass char *desc as an argument to
generate_params and second, the variable naming would be better
as we are using the test name for KTAP output for regular tests.
The downside would be having to change existing implementations
that use char *desc and to explicitly specify to use test->name to users.

> > +
> >  static void __kunit_init_parent_test(struct kunit_case *test_case, str=
uct kunit *test)
> >  {
> >         if (test_case->param_init) {
> > @@ -687,7 +711,7 @@ int kunit_run_tests(struct kunit_suite *suite)
> >                         /* Test marked as skip */
> >                         test.status =3D KUNIT_SKIPPED;
> >                         kunit_update_stats(&param_stats, test.status);
> > -               } else if (!test_case->generate_params) {
> > +               } else if (!test_case->generate_params && !test.params_=
data.params) {
>
> I agree with David that it is helpful to have one check for whether a
> test is a parameterized test rather than two. My instinct is that if
> test_case->generate_params is NULL it should be safe to assume the
> test isn't a parameterized test.

Agreed.

>
> However, as an alternative or even as a helpful addition, I like the
> idea of a simple kunit_test_is_param function that can pass in the
> test and it will return a bool whether the test is parameterized or
> not.
>
That could be a good idea. At the same time, if it remains true
that generate_params being NULL implies that it's not a
parameterized test, I think a simple check would be enough.

>
>
>
> >                         /* Non-parameterised test. */
> >                         test_case->status =3D KUNIT_SKIPPED;
> >                         kunit_run_case_catch_errors(suite, test_case, &=
test);
> > --
> > 2.50.1.552.g942d659e1b-goog
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAkQn5LUA-gRj9nypcf0jE%2BgjRwN2axkJ4KO14Aj8AB3dhZHsw%40mail.gmail.com.
