Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBKHK27CAMGQEOKOIRZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 4370FB1E8D3
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 15:01:41 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-617f32a55a9sf344807a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 06:01:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754658089; cv=pass;
        d=google.com; s=arc-20240605;
        b=JtFOyYAG++PsLI0+uE/avTP3jfndLV3ChCt1wv67ysy86xOZSb4BmpKO6v133W3tRd
         em8pgpSbiXiwLNcUW/kp1pA2ZPUIXTaDbkIi1fyhUdOc4c8TbtUDOo3v5LIkJRoDupB8
         eabsyFywjLYCKHr3AhgImdPEcsXj+lwc7eVYQIJj2+MukmB1GMZWcM3QEu2MMlHzYkWm
         YmLN/AduSb/UIjilGlv5ZXJeg+qCRWzZrB3L9ldvCRDy9QeqYy3AbeF7jVMjazMjYwH0
         r6RhmBo/mWrlMCAjABxGJxUFHG71fKnFwlqlHqZdsVyqtdt88fZSfyz362VAKzrrdZgZ
         sImg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MEqqrbMFVUYHUpITB2c8Tukss9VnSOZgALZ9VZVyF2w=;
        fh=BateZOp4u+e8BqhF8xzUFuPjSIUGNQq1wgVQmP6sm4Q=;
        b=cjd7YveDlsFsPRomyRgO/idwkO9Qt2moqePQxqeeB3Tdwd2uXN72pIvjcxLO4d/4J0
         p2RliZQGyOhnNepOsE/8JKuE1NPWumuDHmgCD5Q/dZDIoC0YDYcyJMLaORJPSJd/H1Ff
         TEcMX3nZjo6Qbeufesec8zOwtvANQV+OiNOS48krgNNlAekCbTGl5NN+YaDOn/wlLk3F
         Y2RpVg1EzK5AZr9BOdW8ogF0WgRom1LJwaMGG2EVonfuSfljRwLq5OogYGs+Inr0SHp9
         y9oxr7Y7JCw9s+rcc1zb3/KZGMZU4fQdaA5+cRf2FKakELyjFynqKtpCW7w2s/p7PNZs
         ve4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LH5PiDgI;
       spf=pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=marievic@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754658089; x=1755262889; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MEqqrbMFVUYHUpITB2c8Tukss9VnSOZgALZ9VZVyF2w=;
        b=UXDsrITJw6v8oMOf73VbkVCIkFAR1BGR2i8cypP1T9O+jIcNzIgdZFfHgmKTofhxtt
         QpV3WlRHdORy/FW3jYpd832yvOb7o1QGLsklJ9Z2G3+sp0ubZdmOAIbSfeq0I85QiyhQ
         P2t2FvsMj194qh7uT6pFb5LMs4BFy9tcIvQEGlVaeJ6hzQFuD/26RPz8RDihV8AQO1LA
         onZIT2Wvmfm4ht89Hd9UB5c8MVWhXYDOPggk52AgiCKEwQitqFAvBEA7JwgP9g6oKBNq
         5L0grfyoG9HPE/7mF0KHTCe8CBicntbgwPVbBVGBGhO5o07XUQDGNXsEY7DqDGoW/KQB
         P6gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754658089; x=1755262889;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MEqqrbMFVUYHUpITB2c8Tukss9VnSOZgALZ9VZVyF2w=;
        b=tl7z7AH1/l3edY7r1KtYsEo/DLmr14Bx9zm+mDLWx/mLsJ3dEEcdM1sgLMhWN5rlNS
         sBaXgmp47trtzTEvkfPUQ88lqVLfVrBk1ZEv14XL90UpKqEzpTZ/QxCwz0uqD8Im5hPu
         vPz0Fo6nRQH5xPTVN5ZEOaXnFTiDlqEPGI7UUHIPkG6NTxAuu3+OTo/+E24xX2Q0xBl7
         5LkEQKwWFMfgECASKxzvny/gHyvgv4tCkzSyUDaEEdWsGOfbHWCgFL5VZvisW3qAzb6H
         fo1rCqjhfJisj6KMLuV75zwOB7H73lubMvzwNP+o4ohSRQEclcBYRCvdP/s8JC73Agrw
         XoKA==
X-Forwarded-Encrypted: i=2; AJvYcCWge9X960n2idufvT/b2gcsWbMcu3UWGBP5rcMBR5X2FSX1Tc3md2dzwLp1nC2jCmHaWdB91w==@lfdr.de
X-Gm-Message-State: AOJu0YyspRrlh2JmYw/3V092QE2+f9fpSV5Jb50bAeEUDy4jtnLe5mal
	8EP48lgU45md2huwjw8Jqd1uoP7azeTU+ktRxTz2rIrmAgLy7lDB1ZKW
X-Google-Smtp-Source: AGHT+IFPLqYAzs5H2+K/8rzaljLmtEOBWXmd14m2C2NOzVExSemsMLr5SM6QXZzKjydeUXux2OVB+g==
X-Received: by 2002:a05:6402:5108:b0:615:8b0b:7c6b with SMTP id 4fb4d7f45d1cf-617e2becb29mr2183916a12.13.1754658088795;
        Fri, 08 Aug 2025 06:01:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc9MNMW5JFnEkN89FQcWVTj4jTTdeB3Qx695pb/VArAoA==
Received: by 2002:a05:6402:1d53:b0:615:5579:e16f with SMTP id
 4fb4d7f45d1cf-617b1cdbb6bls2055619a12.1.-pod-prod-08-eu; Fri, 08 Aug 2025
 06:01:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvySdumLJiuxwuWKAYABrXotoVfMtfgi7qDc6/1MeWU87e9iEIX7xycKEUkHvAI4/SsHrGW7PRRcw=@googlegroups.com
X-Received: by 2002:a17:907:741:b0:af9:467d:abc0 with SMTP id a640c23a62f3a-af9c65587e2mr243920966b.50.1754658085665;
        Fri, 08 Aug 2025 06:01:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754658085; cv=none;
        d=google.com; s=arc-20240605;
        b=bbW/Y7KVH2ur6+MSkevgzASMLoy5aohO+HIedQSMZBPViRdX0ASwMOaDHG1TDv//63
         jsumhdwREP08tXWwMyKpl1nEkK1yhmYp1A4UwqKsJ3Y1LDJBmlai8jfb6bKHwuzKtFcS
         Qdz7iHXLVMW/NMocwakAtBwOzFGzip8hy3+7wqhbQte5pvMSu5kN5eBSxxnDRTz2U7oN
         0eYgquzXnPpX3CiH3bINm2OOgPI2wT6FO8ZRp/bCkjAjhOHIz5/6Q0UZspuU/Kxj0NL0
         eupcTfjayVWU4wUa5RSKuRALuuUimxybfwiZWfWNtSAzWX/BXItJ6DDI/52N4vGgwYMq
         O+lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=el10QOQEfFkF9p6pSruNEIfZL6m4W9xzMCWGyL33LoI=;
        fh=F9HJf0QVsVtZ2q5Uchjuscb4tzj+pbHlJnqDAaesGdk=;
        b=liverOxtSz6HK553ewVLboGGXJ4YbDgMOu0HOrkUAluvypEhxgSJeGEARgaBPTNw6X
         dRF+s2AbEWb3jmPclLMxBHk0OgUIk4eExbXpIlRWC3zdIueVwAgQ10rKT63nDEaXTSWR
         Yp9RNj3+jYWjG1wJB5ix923mTMj84JsmoBSaQ+sxefaESYehV87DpNPQqb8TJWGTRq0J
         1esEzSdChox0r/74MQ5RDJg4Vf5UuKrEMx59/BEYExfbrJ7LsilZjinHJwg54hZavOUs
         4/F7qkVNw4Lo49l/MAcHRmUET2U3HXabB+udMNednojw5v7m4meNNAcRgiial6liI/ZE
         QFFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LH5PiDgI;
       spf=pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=marievic@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52a.google.com (mail-ed1-x52a.google.com. [2a00:1450:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-af919eac6c6si48094066b.0.2025.08.08.06.01.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Aug 2025 06:01:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52a as permitted sender) client-ip=2a00:1450:4864:20::52a;
Received: by mail-ed1-x52a.google.com with SMTP id 4fb4d7f45d1cf-6156c3301ccso8641a12.1
        for <kasan-dev@googlegroups.com>; Fri, 08 Aug 2025 06:01:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUrImCPbvZypEd1fKCS0qKoXjlxQStD7fRBuCsX64KKjRitsgFsaRPxHFCumCtvLW/hD0ZOBVG5rfY=@googlegroups.com
X-Gm-Gg: ASbGncv4XX+Z/Kx+06+Pz4i0TJ6KDaq+J8u3K1nT1x4QRTYy+KiqH41aiFBgQ5FlO5l
	f+iRJQsVoc8bbGrzuzFDiijDINigcfSxpKJuUsjHRfkqdckRXAyjz+y2G9rmzd1q+zyekrJBWQk
	Foiz+LAm1Hqw/zhLC8zLJ94InqpFikIC005hlTUvjvb0KAlnZGXYdGT5WzmhbZUzCfKEvdz89Cy
	dJTel+2
X-Received: by 2002:a05:6402:292f:b0:615:63af:84c7 with SMTP id
 4fb4d7f45d1cf-617e0c2fea6mr72212a12.0.1754658084244; Fri, 08 Aug 2025
 06:01:24 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-3-marievic@google.com>
 <CA+GJov5R2GnBfxXR=28vS3F4b1E-=WLDXpgdJo0SpKAXb1dpsw@mail.gmail.com>
In-Reply-To: <CA+GJov5R2GnBfxXR=28vS3F4b1E-=WLDXpgdJo0SpKAXb1dpsw@mail.gmail.com>
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Aug 2025 09:01:11 -0400
X-Gm-Features: Ac12FXyqcN3QWXqYkDaIcNwJHxUBYobG5GbAMtvuIIACGkmsNKYyn--VKTTbYU0
Message-ID: <CAAkQn5JXHFRXRRfUCWZDi+d0mDvGsgKW0poWgj5XCJGz_YTw8w@mail.gmail.com>
Subject: Re: [PATCH 2/9] kunit: Introduce param_init/exit for parameterized
 test shared context management
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
 header.i=@google.com header.s=20230601 header.b=LH5PiDgI;       spf=pass
 (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52a
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
> > Add `param_init` and `param_exit` function pointers to
> > `struct kunit_case`. Users will be able to set them
> > via the new `KUNIT_CASE_PARAM_WITH_INIT` macro.
>
> Hello!
>
> Very intrigued by this idea to add an init and exit function for
> parameterized tests. In a way, this allows parameterized test series
> to act more like suites. Either way I am happy to see more flexibility
> being brought to the parameterized test framework.
>
> I have a few comments below that I would like to discuss before a
> final review. But this patch is looking good.
>
> Thanks!
> -Rae
>
> >
> > These functions are invoked by kunit_run_tests() once before
> > and once after the entire parameterized test series, respectively.
>
> This is a philosophical question but should we refer to a group of
> parameterized tests as a parameterized test series or a parameterized
> test suite? In the KTAP, the appearance is identical to a suite but in
> the running of the tests it acts distinct to a test case or suite.
> Curious on David's opinion here.
>

Thank you for bringing this up! Using the wording of the patch that
introduced the parameterized tests:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/l=
ib/kunit?id=3Dfadb08e7c7501ed42949e646c6865ba4ec5dd948,
"parameterized test" will refer to a group of parameterized tests and
"parameter run" will refer to a single parameter execution. I will also
specify this terminology in the docs for v2.

> > They will receive the parent kunit test instance, allowing users
> > to register and manage shared resources. Resources added to this
> > parent kunit test will be accessible to all individual parameterized
> > tests, facilitating init and exit for shared state.
> >
> > Signed-off-by: Marie Zhussupova <marievic@google.com>
> > ---
> >  include/kunit/test.h | 33 ++++++++++++++++++++++++++++++++-
> >  lib/kunit/test.c     | 23 ++++++++++++++++++++++-
> >  2 files changed, 54 insertions(+), 2 deletions(-)
> >
> > diff --git a/include/kunit/test.h b/include/kunit/test.h
> > index a42d0c8cb985..d8dac7efd745 100644
> > --- a/include/kunit/test.h
> > +++ b/include/kunit/test.h
> > @@ -92,6 +92,8 @@ struct kunit_attributes {
> >   * @name:     the name of the test case.
> >   * @generate_params: the generator function for parameterized tests.
> >   * @attr:     the attributes associated with the test
> > + * @param_init: The init function to run before parameterized tests.
> > + * @param_exit: The exit function to run after parameterized tests.
>
> If we decide on a terminology for the parameterized test group, it
> might be clearer to label these "The init function to run before
> parameterized test [suite/series]." and same for the exit function.
>

Will update this in v2.

> >   *
> >   * A test case is a function with the signature,
> >   * ``void (*)(struct kunit *)``
> > @@ -129,6 +131,13 @@ struct kunit_case {
> >         const void* (*generate_params)(const void *prev, char *desc);
> >         struct kunit_attributes attr;
> >
> > +       /*
> > +        * Optional user-defined functions: one to register shared reso=
urces once
> > +        * before the parameterized test series, and another to release=
 them after.
> > +        */
> > +       int (*param_init)(struct kunit *test);
> > +       void (*param_exit)(struct kunit *test);
> > +
> >         /* private: internal use only. */
> >         enum kunit_status status;
> >         char *module_name;
> > @@ -218,6 +227,27 @@ static inline char *kunit_status_to_ok_not_ok(enum=
 kunit_status status)
> >                   .generate_params =3D gen_params,                     =
           \
> >                   .attr =3D attributes, .module_name =3D KBUILD_MODNAME=
}
> >
> > +/**
> > + * KUNIT_CASE_PARAM_WITH_INIT() - Define a parameterized KUnit test ca=
se with custom
> > + * init and exit functions.
> > + * @test_name: The function implementing the test case.
> > + * @gen_params: The function to generate parameters for the test case.
> > + * @init: The init function to run before parameterized tests.
> > + * @exit: The exit function to run after parameterized tests.
>
> If we do change the description above of param_init/param_exit, it
> might be nice to change it here too.
>

Will update this, as well.

> > + *
> > + * Provides the option to register init and exit functions that take i=
n the
> > + * parent of the parameterized tests and run once before and once afte=
r the
> > + * parameterized test series. The init function can be used to add any=
 resources
> > + * to share between the parameterized tests or to pass parameter array=
s. The
> > + * exit function can be used to clean up any resources that are not ma=
naged by
> > + * the test.
> > + */
> > +#define KUNIT_CASE_PARAM_WITH_INIT(test_name, gen_params, init, exit) =
         \
> > +               { .run_case =3D test_name, .name =3D #test_name,       =
             \
> > +                 .generate_params =3D gen_params,                     =
           \
> > +                 .param_init =3D init, .param_exit =3D exit,          =
             \
> > +                 .module_name =3D KBUILD_MODNAME}
> > +
> >  /**
> >   * struct kunit_suite - describes a related collection of &struct kuni=
t_case
> >   *
> > @@ -269,7 +299,8 @@ struct kunit_suite_set {
> >   * @priv: for user to store arbitrary data. Commonly used to pass data
> >   *       created in the init function (see &struct kunit_suite).
> >   * @parent: for user to store data that they want to shared across
> > - *         parameterized tests.
> > + *         parameterized tests. Typically, the data is provided in
> > + *         the param_init function (see &struct kunit_case).
> >   *
> >   * Used to store information about the current context under which the=
 test
> >   * is running. Most of this data is private and should only be accesse=
d
> > diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> > index 4d6a39eb2c80..d80b5990d85d 100644
> > --- a/lib/kunit/test.c
> > +++ b/lib/kunit/test.c
> > @@ -641,6 +641,19 @@ static void kunit_accumulate_stats(struct kunit_re=
sult_stats *total,
> >         total->total +=3D add.total;
> >  }
> >
> > +static void __kunit_init_parent_test(struct kunit_case *test_case, str=
uct kunit *test)
>
> It would be nice to include "param" in this function name. Currently
> it sounds more like you are initializing the @parent field of struct
> kunit *test.

That is a great suggestion, I will incorporate it in v2.

>
> > +{
> > +       if (test_case->param_init) {
> > +               int err =3D test_case->param_init(test);
> > +
> > +               if (err) {
> > +                       kunit_err(test_case, KUNIT_SUBTEST_INDENT KUNIT=
_SUBTEST_INDENT
> > +                               "# failed to initialize parent paramete=
r test.");
> > +                       test_case->status =3D KUNIT_FAILURE;
> > +               }
> > +       }
> > +}
> > +
> >  int kunit_run_tests(struct kunit_suite *suite)
> >  {
> >         char param_desc[KUNIT_PARAM_DESC_SIZE];
> > @@ -668,6 +681,8 @@ int kunit_run_tests(struct kunit_suite *suite)
> >                 struct kunit_result_stats param_stats =3D { 0 };
> >
> >                 kunit_init_test(&test, test_case->name, test_case->log)=
;
> > +               __kunit_init_parent_test(test_case, &test);
> > +
>
> Is it possible to move this so this function is only called when it is
> a parameterized test? I see the check for KUNIT_FAILURE is useful but
> I think I would still prefer this within the section for parameterized
> tests.

Yes, I will do that, unless we decide to go with the route
to set generate_params to point to kunit_get_next_param_and_desc
in the __kunit_init_parent_test function.

>
> >                 if (test_case->status =3D=3D KUNIT_SKIPPED) {
> >                         /* Test marked as skip */
> >                         test.status =3D KUNIT_SKIPPED;
> > @@ -677,7 +692,7 @@ int kunit_run_tests(struct kunit_suite *suite)
> >                         test_case->status =3D KUNIT_SKIPPED;
> >                         kunit_run_case_catch_errors(suite, test_case, &=
test);
> >                         kunit_update_stats(&param_stats, test.status);
> > -               } else {
> > +               } else if (test_case->status !=3D KUNIT_FAILURE) {
> >                         /* Get initial param. */
> >                         param_desc[0] =3D '\0';
> >                         /* TODO: Make generate_params try-catch */
> > @@ -727,6 +742,12 @@ int kunit_run_tests(struct kunit_suite *suite)
> >
> >                 kunit_update_stats(&suite_stats, test_case->status);
> >                 kunit_accumulate_stats(&total_stats, param_stats);
> > +               /*
> > +                * TODO: Put into a try catch. Since we don't need suit=
e->exit
> > +                * for it we can't reuse kunit_try_run_cleanup for this=
 yet.
> > +                */
> > +               if (test_case->param_exit)
> > +                       test_case->param_exit(&test);
>
> Also here I am not sure why this is done outside of the check for if
> the test is parameterized? Either way this should definitely be done
> before the test stats and ok/not ok line are printed because if there
> is any log output during the param_exit function it is necessary to
> print that before the status line to identify that that log
> corresponds with that test.

Thank you for catching this! Yes, it should be inside the check for if
the test is parameterized.

>
> Also just curious why you chose to implement a function to perform the
> param_init but not the param_exit?

To be consistent with the existing style of "exit" functions in KUnit,
test->param_exit returns void. Therefore, similar to how it's done for
suite->suite_exit
(https://elixir.bootlin.com/linux/v6.16/source/lib/kunit/test.c#L685),
I didn't do extra error handling as the function itself doesn't
indicate an error and
therefore, didn't put it in a separate function. To do error handling
for it, it would
need to be in a try catch, then we could check if the cleanup timed out or
if there was an internal error.

>
>
>
> >                 /* TODO: Put this kunit_cleanup into a try-catch. */
> >                 kunit_cleanup(&test);
> >         }
> > --
> > 2.50.1.552.g942d659e1b-goog
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAkQn5JXHFRXRRfUCWZDi%2Bd0mDvGsgKW0poWgj5XCJGz_YTw8w%40mail.gmail.com.
