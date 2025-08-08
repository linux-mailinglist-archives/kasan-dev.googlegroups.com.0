Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBFGX27CAMGQE7KIHB4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 24195B1E835
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 14:20:38 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-615a06a4bf4sf1973194a12.2
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 05:20:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754655638; cv=pass;
        d=google.com; s=arc-20240605;
        b=TIYUzRX7GQ+/tLgaBpS97MWXpqNTojZt6RR05R08Pg+2CnGNJGAsetWdKJEmN37A0z
         KnWu+SNCGsD0jEGqprq6e72wenDMVNmrN/3JRbHZFZ/QlUlVOKux0SEmCEb46SS2DoVT
         5ou4yhzwTrRFCwCNJvF7vnIMuoi9jxXgtl1slnV0+RBPuw7EJrO/sGG0eq6uWHBOPQFc
         3E+VVYJRHbkV2JtHR64jCxQl1TCj0xWV0w3DuAJPSAAUvdk6eHT5wAyT2ZJubISBlYwY
         FK29fx5O2/7YZVLZF1gIF64PS2FSPzCmaSMm0TOMRiT6OFjfChzjvG0Kk1HCUSOBQ7Lt
         ZqFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NDWzeNkWIomDYip7YiOaOtP7X01hS4BHxpVkzfMl47A=;
        fh=t1gUKlhvaAuE/BJrNBMjB4SKSEIjWxYs9EmUdK/lQwg=;
        b=GxbYkCGqKWSSmIeqrf+KUokxY9H2ws+uQdfo1e4GvGZMJWptAXvwJps8jzjWXdtj/S
         vO5s81bdThdi4JZgSpskD9pjXLDDYTvt+SXUDEPQBbtNf7zycfFRbB00crvHl2MnnS7a
         QJD7cWAcwYTgo2LAgjEigIyDYjpQbaESIcwJZtG9qUMxR2+dflmIjqNkC93v9jqcB7N2
         j+EMBkzMjFJh2KKSaGX/u7xGkDdenrxi2L04Q1RHe08RiCpTQumiH29E/Ihs+rmOYHnu
         lClRsVekudujxlJa8PAboAb/Eo/uOuocp3UG09gyhhkbLXyA1u3+0SVnN0XKom7ASfGK
         YxDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1vhaDgFM;
       spf=pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=marievic@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754655638; x=1755260438; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NDWzeNkWIomDYip7YiOaOtP7X01hS4BHxpVkzfMl47A=;
        b=ouUGEbrlGQDylpeHlwX8mZvj6dF4u9PBrOzxOXGJr+6rAkDq9LkI+IshbJW363fq+b
         C7wb7eaG2ZhFbyEwD+c4PMnAxW/rEqwRuFYCZVlW5UDrduEe+FPjCdc7rNe5Hptxbzh6
         TMZ+dYo0DIS6hHmIps8tzqay6ZSuzs0Ec93xNmT4Ji5Fvu7muRfOLW4uRYu06ffduvyc
         Rq/8AqvdqOwNbod8qhPawc5DizXsHCv+8yiq4vOO6eQWIqR6tqMKmwicx/fY5tmOvNf6
         UVKE6Kjy18QlJ5NWheGBK6Icag0V2xnMtXYkhHUqIvHNtzxheChbm3hTTPos8LbCstCR
         dwhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754655638; x=1755260438;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NDWzeNkWIomDYip7YiOaOtP7X01hS4BHxpVkzfMl47A=;
        b=Bl0CgN8TS6qfCcbolY/+rzOh/Pvn5ac8RMXT6hf5Tkqxc6yMjtCISaBQPd/Z+0scxa
         7Bouvl9A34LNqpK1XY4FQjSaBRetSi1H1IcZdw9gtwO2NXBuP28EW7HrhHMlj4mwc5Nk
         2h4deEuZRnuf8tdCDyDwzSF+P1c1Mo16tyDD+pQlzXtfo8mVmbNPq1eBkHm0MsfwwYCO
         sGnBa7AJvGO1GH998kHOZqlDvc1wUuIIziBm7OmCY/ChrFlIe8Qh2uAhgUiN5Il2GW6J
         nQoFuXZb9GTiCE5eNDisr9nwTmP064EuXcc4oGBvrXMNtjwY5SEdRc9VonHq3io5khm8
         Cy2A==
X-Forwarded-Encrypted: i=2; AJvYcCXKA7UMifxpgd34D6/KkQRJQq8ezwEnO0JRxashccJ3Lq1F/xQW58jaENwnbumel8GVUGkSbw==@lfdr.de
X-Gm-Message-State: AOJu0YyWqCpe2QnF5n6YGIEDmsV5mdsvmi34ix3iLXQ80l1T0u+W26zA
	NdvSxThrAb/LJmzXcM6eQrl93w3UGyDJyNc0mF/sA4ofXUkydjYNKUKz
X-Google-Smtp-Source: AGHT+IGDPCNFgoHOotuoePFb0W5KGizC2laYeb2ykhWux1xQDcKMVFTsnMyjF6NpK3cuf737PKfLYA==
X-Received: by 2002:a05:6402:2712:b0:615:9c88:59ef with SMTP id 4fb4d7f45d1cf-617e2e56f46mr1761202a12.20.1754655637326;
        Fri, 08 Aug 2025 05:20:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdAZ2WbkkprmRiwqJUdKhn9ChHFgeY/MAaKXLOMBEdBzQ==
Received: by 2002:a05:6402:2747:b0:607:2358:a312 with SMTP id
 4fb4d7f45d1cf-617b1ef4766ls1876754a12.2.-pod-prod-08-eu; Fri, 08 Aug 2025
 05:20:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXx4CH79el4kA9KiNmPCTKhVFPQtk7YczeURVkKHeHToJK/GMt6HBHwIUff1OuEf3ouZNmBiQvldRI=@googlegroups.com
X-Received: by 2002:a17:907:1ca1:b0:af9:3ed3:eda2 with SMTP id a640c23a62f3a-af9c65b2721mr233821366b.60.1754655634533;
        Fri, 08 Aug 2025 05:20:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754655634; cv=none;
        d=google.com; s=arc-20240605;
        b=UhHppi/nh5++k0JLlZYoMKHVA9mr6r6hiwBuIE+miBNI/DI1fQpvLyvohUCeIHlYO1
         MY22p7mSi4zBz7Ni/HRhuA8BlGNw8qAYRUGuvJ/l9oGKbnenBJ6v9Phfn04IVA+VLkt8
         SO1HTi1rXAgSVN3DWAsgLmGwoUQvrX4a/XT2qTKsV2TgiexPP5s4jwyf1yTBuX1kp5yZ
         xlWw/MmlF0bUu0W+9NRx1sOvK+8oJpUfIjx3pg3h7y9IqccyrEhEt2tKQyGzvYhHew/Z
         DqthF2p4AlyKvvqiJeYTVEyZj9R1Q9D1P1SaYL6L+t57PXzMT83gIcU2YI19uvsxSFQt
         bmmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3rzYVptOKE6RcZ0qvjvmsPnga1215NKTSv+ot9kbgm8=;
        fh=xMDkOygbugOsBDtoHDDrE8aSnVQaZH0M6n05BfxSpXc=;
        b=GtJKP9mWIthc1CO2f43eRh7MnoX/fpkhcLQ4v0CojuEVA3a1bmBqdxeWkNFS1Ys0G9
         BoXF6/hntoR7BzUOzHgkpaxaBp9lWrbgalInNwqxWecH9m9QsLxkLdZitNdSyCiPZF5Y
         4VcFlCwPGn5em3M8HcX63UulT0V20r/mJ4wUblfFlf5Lxwf9JlOUMeIUfLKmsJZU8L8t
         aWLIifP2NToUAPxD71RL8WXSJEmI+Fl/OlM41OL7FEJs5edXhYkIpGVld/FYgjGeUO3F
         gUhA/Wwem/4pQHDJmrtigP2xifWnQSaCbnn6iNIHrK0WLUs2PA4T4uSVD1AwCvaAPPcY
         5w2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1vhaDgFM;
       spf=pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=marievic@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-615a9135373si413323a12.5.2025.08.08.05.20.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Aug 2025 05:20:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id 4fb4d7f45d1cf-5f438523d6fso7866a12.1
        for <kasan-dev@googlegroups.com>; Fri, 08 Aug 2025 05:20:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW2lc80Tvt8mOFUNvIQHprG5jsp1AHBksoic9X+vf4peiBOghpsUBSdMfs18ecU3LrRlVjtsnIS8hs=@googlegroups.com
X-Gm-Gg: ASbGncs6XnzsMT6z42iSLq5EOXArpIFIg3tr2WtdkwCjFsJX03vDAHF6YnrlTFy+vHs
	RjgOk0wzSWOOXLcgrXZ+sjYCr5ETttP98M3YRY5coUptkP1eC6ssdrsXuoXxPgbtHGJBdknxc4l
	0E1Ex8usshEr8iMQMN7dNA/E7s/x5FV4JE5X0fqHjHqAQduBaHDcwx8oSLRIX5eTLFs+JErg+NY
	tFaqDht
X-Received: by 2002:a50:9351:0:b0:615:60d2:c013 with SMTP id
 4fb4d7f45d1cf-617e48ffd8cmr60281a12.3.1754655633629; Fri, 08 Aug 2025
 05:20:33 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-2-marievic@google.com>
 <CA+GJov4BQ1mRa-JaHoML+gF7rk=XY=hCRL+Shag6Aj6VbUgUeg@mail.gmail.com>
In-Reply-To: <CA+GJov4BQ1mRa-JaHoML+gF7rk=XY=hCRL+Shag6Aj6VbUgUeg@mail.gmail.com>
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Aug 2025 08:20:20 -0400
X-Gm-Features: Ac12FXxk_i-p3y5IMbqA_cUeg1wd-aJHm01gFGsskeUDN6bJI53lY7PD-TwOzYw
Message-ID: <CAAkQn5JNmbuv=nj3Z5hDQNE0sAzrRNE_rJXrZVN4EqUDikV9=Q@mail.gmail.com>
Subject: Re: [PATCH 1/9] kunit: Add parent kunit for parameterized test context
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
 header.i=@google.com header.s=20230601 header.b=1vhaDgFM;       spf=pass
 (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52c
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

On Tue, Aug 5, 2025 at 11:17=E2=80=AFAM Rae Moar <rmoar@google.com> wrote:
>
> On Tue, Jul 29, 2025 at 3:37=E2=80=AFPM Marie Zhussupova <marievic@google=
.com> wrote:
> >
> > Currently, KUnit parameterized tests lack a mechanism
> > to share resources across individual test invocations
> > because the same `struct kunit` instance is reused for
> > each test.
> >
> > This patch refactors kunit_run_tests() to provide each
> > parameterized test with its own `struct kunit` instance.
> > A new parent pointer is added to `struct kunit`, allowing
> > individual parameterized tests to reference a shared
> > parent kunit instance. Resources added to this parent
> > will then be accessible to all individual parameter
> > test executions.
> >
> > Signed-off-by: Marie Zhussupova <marievic@google.com>
>
> Hello!
>
> Thank you so much for sending out this series. I have wanted to see an
> update of our parameterized test framework for a while. I have a few
> comments below for this patch. But otherwise it is looking good.
>
> Reviewed-by: Rae Moar <rmoar@google.com>
>
> Thanks!
> -Rae
>
> > ---
> >  include/kunit/test.h | 12 ++++++++++--
> >  lib/kunit/test.c     | 32 +++++++++++++++++++-------------
> >  2 files changed, 29 insertions(+), 15 deletions(-)
> >
> > diff --git a/include/kunit/test.h b/include/kunit/test.h
> > index 39c768f87dc9..a42d0c8cb985 100644
> > --- a/include/kunit/test.h
> > +++ b/include/kunit/test.h
> > @@ -268,14 +268,22 @@ struct kunit_suite_set {
> >   *
> >   * @priv: for user to store arbitrary data. Commonly used to pass data
> >   *       created in the init function (see &struct kunit_suite).
> > + * @parent: for user to store data that they want to shared across
> > + *         parameterized tests.
> >   *
>
> As David mentioned, I would also prefer that this provides a more
> general description of the @parent field here. Although this is
> currently only used for parameterized tests, it could have other use
> cases in the future.
>

Will edit this in v2.

> >   * Used to store information about the current context under which the=
 test
> >   * is running. Most of this data is private and should only be accesse=
d
> > - * indirectly via public functions; the one exception is @priv which c=
an be
> > - * used by the test writer to store arbitrary data.
> > + * indirectly via public functions; the two exceptions are @priv and @=
parent
> > + * which can be used by the test writer to store arbitrary data or dat=
a that is
> > + * available to all parameter test executions, respectively.
>
> In addition, I would prefer that the call out to @parent here is also
> changed to a more general description of the @parent field. However,
> feel free to also include the description of the use case for the
> parameterized tests.
>

I will edit this in v2, as well.

> >   */
> >  struct kunit {
> >         void *priv;
> > +       /*
> > +        * Reference to the parent struct kunit for storing shared reso=
urces
> > +        * during parameterized testing.
> > +        */
>
> I am more 50/50 on changing this description. Could change it just to:
> "Reference to the parent struct kunit for storing shared resources."

Thank you for the suggestion! The description would sound good.

>
> > +       struct kunit *parent;
> >
> >         /* private: internal use only. */
> >         const char *name; /* Read only after initialization! */
> > diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> > index f3c6b11f12b8..4d6a39eb2c80 100644
> > --- a/lib/kunit/test.c
> > +++ b/lib/kunit/test.c
> > @@ -647,6 +647,7 @@ int kunit_run_tests(struct kunit_suite *suite)
> >         struct kunit_case *test_case;
> >         struct kunit_result_stats suite_stats =3D { 0 };
> >         struct kunit_result_stats total_stats =3D { 0 };
> > +       const void *curr_param;
> >
> >         /* Taint the kernel so we know we've run tests. */
> >         add_taint(TAINT_TEST, LOCKDEP_STILL_OK);
> > @@ -679,36 +680,39 @@ int kunit_run_tests(struct kunit_suite *suite)
> >                 } else {
> >                         /* Get initial param. */
> >                         param_desc[0] =3D '\0';
> > -                       test.param_value =3D test_case->generate_params=
(NULL, param_desc);
> > +                       /* TODO: Make generate_params try-catch */
> > +                       curr_param =3D test_case->generate_params(NULL,=
 param_desc);
> >                         test_case->status =3D KUNIT_SKIPPED;
> >                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDEN=
T KUNIT_SUBTEST_INDENT
> >                                   "KTAP version 1\n");
> >                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDEN=
T KUNIT_SUBTEST_INDENT
> >                                   "# Subtest: %s", test_case->name);
> >
> > -                       while (test.param_value) {
> > -                               kunit_run_case_catch_errors(suite, test=
_case, &test);
> > +                       while (curr_param) {
> > +                               struct kunit param_test =3D {
> > +                                       .param_value =3D curr_param,
> > +                                       .param_index =3D ++test.param_i=
ndex,
> > +                                       .parent =3D &test,
> > +                               };
> > +                               kunit_init_test(&param_test, test_case-=
>name, test_case->log);
> > +                               kunit_run_case_catch_errors(suite, test=
_case, &param_test);
> >
> >                                 if (param_desc[0] =3D=3D '\0') {
> >                                         snprintf(param_desc, sizeof(par=
am_desc),
> >                                                  "param-%d", test.param=
_index);
>
> This probably doesn't matter too much either way but should this be
> param_test.param_index instead? This would cover the case where the
> param_index is changed during the test run even though it shouldn't.
>

Thank you for catching this!

> >                                 }
> >
> > -                               kunit_print_ok_not_ok(&test, KUNIT_LEVE=
L_CASE_PARAM,
> > -                                                     test.status,
> > -                                                     test.param_index =
+ 1,
> > +                               kunit_print_ok_not_ok(&param_test, KUNI=
T_LEVEL_CASE_PARAM,
> > +                                                     param_test.status=
,
> > +                                                     param_test.param_=
index,
> >                                                       param_desc,
> > -                                                     test.status_comme=
nt);
> > +                                                     param_test.status=
_comment);
> >
> > -                               kunit_update_stats(&param_stats, test.s=
tatus);
> > +                               kunit_update_stats(&param_stats, param_=
test.status);
> >
> >                                 /* Get next param. */
> >                                 param_desc[0] =3D '\0';
> > -                               test.param_value =3D test_case->generat=
e_params(test.param_value, param_desc);
> > -                               test.param_index++;
> > -                               test.status =3D KUNIT_SUCCESS;
> > -                               test.status_comment[0] =3D '\0';
> > -                               test.priv =3D NULL;
> > +                               curr_param =3D test_case->generate_para=
ms(curr_param, param_desc);
> >                         }
> >                 }
> >
> > @@ -723,6 +727,8 @@ int kunit_run_tests(struct kunit_suite *suite)
> >
> >                 kunit_update_stats(&suite_stats, test_case->status);
> >                 kunit_accumulate_stats(&total_stats, param_stats);
> > +               /* TODO: Put this kunit_cleanup into a try-catch. */
> > +               kunit_cleanup(&test);
>
> I might be missing something here but why not do this cleanup before
> the printing stage and only if the test was a parent param test?
>

Thank you for catching this too, it should be only for the parent param tes=
t.

>
>
> >         }
> >
> >         if (suite->suite_exit)
> > --
> > 2.50.1.552.g942d659e1b-goog
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAkQn5JNmbuv%3Dnj3Z5hDQNE0sAzrRNE_rJXrZVN4EqUDikV9%3DQ%40mail.gmail.com.
