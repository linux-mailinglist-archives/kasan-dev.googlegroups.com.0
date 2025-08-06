Return-Path: <kasan-dev+bncBDQ67ZGAXYCBB5VLZ3CAMGQEZ5VDIGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 14640B1CB6F
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 19:50:48 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-458bf93f729sf800645e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 10:50:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754502647; cv=pass;
        d=google.com; s=arc-20240605;
        b=OhG0t7xLRGcVX7Y5buDHNI5uaxUjLH4m/4EFCWb2gbVEsir+F7itXdFgKcyapkckvZ
         b0kmHq1m23zvFYqBQVyOWCrivFpbE0A8gUm524T9r6Wn7KRcb6PuYneM+vKMWtC4LJGV
         OB6GbmelOpYvaiw/OqwYuA+HpABdRlPt0FHK0/Ilg4WcMb7b7cyctfm3SVtrP02EJFtc
         he2+1twe25yoMRXNpumBFhuE4Ylk9TBUkY2HexM7Kh5iOMrroEK7bQvCu4g54fG3kFUS
         kSaaPJdHFkdND1MQxLH/14MZ5yexiYAlbBdFdt3K+JlomxJsa4VOpv6MQfKgqzpnWX+v
         YvjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UzkSVoKNLRWNYJL7PAo+uoa3IUgdbKuNRMfIC0zf4q4=;
        fh=JAb0VdjXnWH7nvW2rC1ZvFJiMbJOmXn09tTkqjsd04s=;
        b=T6noh0xpiqjrn9RvebZAwlzvSg+6FTEd3msHni3sl54tSZEIC4qAKQcMvPOQJkOpEr
         4HIsXMvMcNz4xZW4QgVtExMrycAdryASQLSyBRWN0rT2tNTheGZxol62H3A3JvM6n9Ra
         QgecOkwK8iNsP0TzZtrx5zfJwUvLy5aEeUOh3fMCz8OrBL3Iz9f0bGiiRoN+IPto0w0w
         jqvugxsfiIBlH7wnRK3G4iJtMMe5r8tpHjt+FqL+Aa49h9m1rcjXcCi1Wzgrw7S9MHza
         WbvC7Gpq3baM/mvs6O2fLoAdkn7RaC/g//e/D9PBdmxuEIXTHtGxBsrbAvMePISR4KuN
         Dy9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IihsZHi5;
       spf=pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=marievic@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754502647; x=1755107447; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UzkSVoKNLRWNYJL7PAo+uoa3IUgdbKuNRMfIC0zf4q4=;
        b=Qg5vBYOXNBEI+QR6pvYSpA5UHYDwN3XcRz684tXc29n21CUV9VKtF7d2WVctT125pI
         aPltXRgSD8fV7QjuQz4/qMFueZkk9bW2gbJ8TRQ4oPjU997vnZITHui0uDCk2Q9qfuIO
         mX6xhKmuZkyZdTgLQ58jUq/TQCRfOPNd0q/JFVb9YKzfjOHInbThljCh18tJlQq2oqJS
         VbDakLhZUA2B0wU4W6j1X9bCzY/U3TRcEoX8PbxI+aLX1u0qtf8q5oak5rVhnFms8qz/
         R4QphUQj0IgkSFp0XMkee/mFc6MiRSwYFD7oR26B8cLbzMgee/kQ41d2Luk9ov8prCwh
         rkyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754502647; x=1755107447;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UzkSVoKNLRWNYJL7PAo+uoa3IUgdbKuNRMfIC0zf4q4=;
        b=QEpcQcz1Q1UqemEwpQKypXA8rufMdirvQ60JUsBsRnBJnzgthmzLWFQXdrRgiX+gpu
         xn3/xRHgOfH7QszA+imYapUEeAbqs82AnqYQPzJ/DJ+AHwwtQHqMqY3He3nOqH3m6vaD
         TBqUG2ufAgn6o/8Y9DIettYP+HnvQZDX+JUQHHOsrEPCW8ARjbUvMaeUsn28eeI8by7X
         7q5j4exRG4/sJKx5emyvgxSAso4UHs+cXCdZ+Xid9WMsryuUGGpBCNU3dJ1mP2y4thFA
         iHoKTf9P06MRYAEYCLLr/54pmGtA4UiEBTQiC02fLakdvgjL+rNnepRJ9PwjI3oCfVbK
         CL9A==
X-Forwarded-Encrypted: i=2; AJvYcCV/L2JJDYcKExmE/ykuuV+x3f9bPYIYkksTTmOx9B6w9bAh/OSet7S5LGkj9wKBs0l6Wxlyeg==@lfdr.de
X-Gm-Message-State: AOJu0YzZ7d5vUAk+427lBLGAQIFGe79mJq+BHrbioCfTMA8HF0ckm8p6
	jkeFxYkPd99lcpHBYJNFkM2oAXoVWplsawBy6KySoSdrRDumWai2zofE
X-Google-Smtp-Source: AGHT+IFa4Y5kbMxxXKGTfqoaSk6HPKBdVevEXPeYCtpL1ob3qcHFAby29GBqZzsHzY17cD/85v4kVg==
X-Received: by 2002:a05:600c:a692:b0:459:d616:25c5 with SMTP id 5b1f17b1804b1-459e709acf3mr25057945e9.12.1754502647115;
        Wed, 06 Aug 2025 10:50:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZevWz6wEFO1hxthDmco5tHzwI9rON4O9MvnIiFvKlR+Lg==
Received: by 2002:a05:600c:4f49:b0:459:ebdf:b560 with SMTP id
 5b1f17b1804b1-459edcf9ff2ls933625e9.1.-pod-prod-04-eu; Wed, 06 Aug 2025
 10:50:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWtOYAChtN0IGFz+XQcbEh/HlazfkWzQG3odUOtT2T2aBHC1FHVhC3FMCJysbbKKDZV5PsmgigKqIs=@googlegroups.com
X-Received: by 2002:a05:600c:6cf:b0:456:191b:9e8d with SMTP id 5b1f17b1804b1-459e709ac79mr22811775e9.11.1754502643894;
        Wed, 06 Aug 2025 10:50:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754502643; cv=none;
        d=google.com; s=arc-20240605;
        b=SEcEp2AB9M58/caT+uqgVhM3nmjy1HnRqJxwIbSN9Ni3/EWfsRGlnnVtWelCTg9iDk
         YszXLAyhpHvUDHiZwkhIUA52As8Rwnn2deRypwGy+5SFbD2qtwP3DI4wSSINN3JlBWEW
         +NI9p3i/rklbZ7HvNDVjF3rfGZ9GL7B4pAq/VH0DmkLQJwY0PmhQQuORJLUKc8AunuBl
         m0Kz7fyVpK5x7U6bkOPfk4AF+fx0c2vZmeq7savlk5Q7ITiTw9kTwxXfuoqrlD8bX1Rz
         KUEkespIRyE9xRZxDj61qWVAaj6dWr6Lff3lhyCTHH3KBLvGhvhGoRsJD7Z7FD01gDqi
         TkXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=O6ZQ/5BaV6mQdffgVaaglAdkdHfzgWg/eTO8QxYBPeU=;
        fh=Hpa8i024gUYJaeRLzBDx8UPweunZLlFObdOpgDecTrM=;
        b=SGxJFYG5r4EDcURtYf/5UDMLyiHEOKpp64qZD6ZbWtaZ8kOmm/mXJHthWXymWe0l6d
         QMH+KjHdn5SZfY/+XOiw7Zx0B1w9evCHHQ4r9TEJjatN83txBJWmlzh7DiU9yrTJ9R3N
         2+WpIS/2SyWFNo3nv8lwwFoBpBZGRK78SWmE9eD2GNWxa/iF5N5pdoci9MGsERqNzE+5
         hIOcrzX/80vasfEzsQmurjDe2UDmMOrUy0+2FkPUyft8AZBY9PAnhlmalhWTULPz7lal
         XtaYHIzwZ9lVWImgbUr+++H3lltElgeYqxu+5lcEMVch3Ucl29yg32+2QQ0KlxJDY+kN
         3PdA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IihsZHi5;
       spf=pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=marievic@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-458bb081c37si3706225e9.1.2025.08.06.10.50.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 10:50:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id 4fb4d7f45d1cf-61543b05b7cso1044a12.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Aug 2025 10:50:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXQt0Khtk0DAEys9xQHE5dZcFBzYBM9F2NdY2drmbDJ8QO4BV322ffyIe8fVD+xRNTcoUVLyUs7o/E=@googlegroups.com
X-Gm-Gg: ASbGncslEPdkaqE4unyNNXmpblZgUZGhy9rOvb/T6Did3XooSZU63/9V1R2bljpR3Um
	SRJCemIhMK21c6fX2IEmz0j7FU+eCDHSr9C4cXnHQyi/+FLlp9a5S4BXs6WRA+pdwT6SbuUVhv3
	9oYPVIyA0s0lXYvLVSLEWOXbrS9zf+CkTyMJZXfxOtEbSPR3qArqwwHIAinuWOBsbJtqEXtAoTZ
	FNyloe3Zgk9VzAgRRk=
X-Received: by 2002:a05:6402:4c1:b0:615:6167:4835 with SMTP id
 4fb4d7f45d1cf-61797ec0988mr91110a12.7.1754502642599; Wed, 06 Aug 2025
 10:50:42 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-8-marievic@google.com>
 <CABVgOSmBssmMz3qQi+TdEoaGQJNXaSVBrsO8RSW0MjLUUHPakg@mail.gmail.com>
In-Reply-To: <CABVgOSmBssmMz3qQi+TdEoaGQJNXaSVBrsO8RSW0MjLUUHPakg@mail.gmail.com>
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Aug 2025 13:50:31 -0400
X-Gm-Features: Ac12FXxZ0gzQXyQ3JCYs61KiK41rHInNvNCX1ufle-31wpGuIXR7lV23iXdDrBU
Message-ID: <CAAkQn5KnBZ7O6TkHL8UR0UaJ-v0P51TjtEwoRu7VWaPYd8oeSg@mail.gmail.com>
Subject: Re: [PATCH 7/9] kunit: Add example parameterized test with shared
 resources and direct static parameter array setup
To: David Gow <davidgow@google.com>
Cc: rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: marievic@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=IihsZHi5;       spf=pass
 (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::533
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

On Sat, Aug 2, 2025 at 5:45=E2=80=AFAM David Gow <davidgow@google.com> wrot=
e:
>
> On Wed, 30 Jul 2025 at 03:37, Marie Zhussupova <marievic@google.com> wrot=
e:
> >
> > Add `example_params_test_with_init` to illustrate how to manage
> > shared resources across parameterized KUnit tests. This example
> > showcases the use of the new `param_init` function and its registration
> > to a test using the `KUNIT_CASE_PARAM_WITH_INIT` macro.
> >
> > Additionally, the test demonstrates:
> > - How to directly assign a static parameter array to a test via
> >   `kunit_register_params_array`.
> > - Leveraging the Resource API for test resource management.
> >
> > Signed-off-by: Marie Zhussupova <marievic@google.com>
> > ---
>
> Thanks for writing some examples! This is great, and makes the rest of
> the series much easier to understand.
>
> (It also reminds me how much I hate the verbose parts of the resource
> API, but it's definitely out of scope to refactor that here. :-))
>
> It does seem like this is a lot of effort to go through for one shared
> integer, though. In the real world, I'd suggest using
> kunit->parent->priv here. As an example, though, it's fine (though
> maybe using a named resource or even kunit_kzalloc() or similar would
> give a better example of how convenient this could be.
>
> It's also not entirely clear why we're using
> kunit_register_params_array() for a static array, when
> KUNIT_ARRAY_PARAM() exists. (This is clearly because the latter
> doesn't support init functions; and I see why we don't necessarily
> want to make the number of macros explode through adding
> KUNIT_ARRAY_PARAM_WITH_INIT() et al, but maybe we should note that in
> the commit description, either here or before.)
>
> Actual test looks fine, though:
>
> Reviewed-by: David Gow <davidgow@google.com>
>
> Cheers,
> -- David
>

Hello David,

I agree that using the Resource API for a single integer is a bit extra.
My idea behind this test was to demonstrate that the Resource API
could be used for managing shared resources and to have the
style of the existing example tests that do simple things with integers.

Using kunit_kzalloc() would be a great simplification. As for a named
resource, we don't have a function to allocate named resources yet
as would be needed here, but that sounds like a great future patch.

We can actually use the KUNIT_ARRAY_PARAM() macro with
KUNIT_CASE_PARAM_WITH_INIT(). We would just pass that created
`*_gen_params` function to KUNIT_CASE_PARAM_WITH_INIT()
instead of NULL. The reason I used kunit_register_params_array() with
the static array was to show that test users can pass a static array
this way, as well, and also to avoid making the test too long with the
dynamic array
creation. But I do like the consistency of using KUNIT_ARRAY_PARAM()
for static arrays and kunit_register_params_array() only for
dynamic ones.

Thank you,
-Marie

>
> >  lib/kunit/kunit-example-test.c | 112 +++++++++++++++++++++++++++++++++
> >  1 file changed, 112 insertions(+)
> >
> > diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-t=
est.c
> > index 3056d6bc705d..5bf559e243f6 100644
> > --- a/lib/kunit/kunit-example-test.c
> > +++ b/lib/kunit/kunit-example-test.c
> > @@ -277,6 +277,116 @@ static void example_slow_test(struct kunit *test)
> >         KUNIT_EXPECT_EQ(test, 1 + 1, 2);
> >  }
> >
> > +/*
> > + * This custom function allocates memory for the kunit_resource data f=
ield.
> > + * The function is passed to kunit_alloc_resource() and executed once
> > + * by the internal helper __kunit_add_resource().
> > + */
> > +static int example_resource_init(struct kunit_resource *res, void *con=
text)
> > +{
> > +       int *info =3D kmalloc(sizeof(*info), GFP_KERNEL);
> > +
> > +       if (!info)
> > +               return -ENOMEM;
> > +       *info =3D *(int *)context;
> > +       res->data =3D info;
> > +       return 0;
> > +}
> > +
> > +/*
> > + * This function deallocates memory for the 'kunit_resource' data fiel=
d.
> > + * The function is passed to kunit_alloc_resource() and automatically
> > + * executes within kunit_release_resource() when the resource's refere=
nce
> > + * count, via kunit_put_resource(), drops to zero. KUnit uses referenc=
e
> > + * counting to ensure that resources are not freed prematurely.
> > + */
> > +static void example_resource_free(struct kunit_resource *res)
> > +{
> > +       kfree(res->data);
> > +}
> > +
> > +/*
> > + * This match function is invoked by kunit_find_resource() to locate
> > + * a test resource based on defined criteria. The current example
> > + * uniquely identifies the resource by its free function; however,
> > + * alternative custom criteria can be implemented. Refer to
> > + * lib/kunit/platform.c and lib/kunit/static_stub.c for further exampl=
es.
> > + */
> > +static bool example_resource_alloc_match(struct kunit *test,
> > +                                        struct kunit_resource *res,
> > +                                        void *match_data)
> > +{
> > +       return res->data && res->free =3D=3D example_resource_free;
> > +}
> > +
> > +/*
> > + * This is an example of a function that provides a description for ea=
ch of the
> > + * parameters.
> > + */
> > +static void example_param_array_get_desc(const void *p, char *desc)
> > +{
> > +       const struct example_param *param =3D p;
> > +
> > +       snprintf(desc, KUNIT_PARAM_DESC_SIZE,
> > +                "example check if %d is less than or equal to 3", para=
m->value);
> > +}
> > +
> > +/*
> > + * Initializes the parent kunit struct for parameterized KUnit tests.
> > + * This function enables sharing resources across all parameterized
> > + * tests by adding them to the `parent` kunit test struct. It also sup=
ports
> > + * registering either static or dynamic arrays of test parameters.
> > + */
> > +static int example_param_init(struct kunit *test)
> > +{
> > +       int ctx =3D 3; /* Data to be stored. */
> > +       int arr_size =3D ARRAY_SIZE(example_params_array);
> > +
> > +       /*
> > +        * This allocates a struct kunit_resource, sets its data field =
to
> > +        * ctx, and adds it to the kunit struct's resources list. Note =
that
> > +        * this is test managed so we don't need to have a custom exit =
function
> > +        * to free it.
> > +        */
> > +       void *data =3D kunit_alloc_resource(test, example_resource_init=
, example_resource_free,
> > +                                         GFP_KERNEL, &ctx);
> > +
> > +       if (!data)
> > +               return -ENOMEM;
> > +       /* Pass the static param array information to the parent struct=
 kunit. */
> > +       kunit_register_params_array(test, example_params_array, arr_siz=
e,
> > +                                   example_param_array_get_desc);
> > +       return 0;
> > +}
> > +
> > +/*
> > + * This is an example of a parameterized test that uses shared resourc=
es
> > + * available from the struct kunit parent field of the kunit struct.
> > + */
> > +static void example_params_test_with_init(struct kunit *test)
> > +{
> > +       int threshold;
> > +       struct kunit_resource *res;
> > +       const struct example_param *param =3D test->param_value;
> > +
> > +       /* By design, param pointer will not be NULL. */
> > +       KUNIT_ASSERT_NOT_NULL(test, param);
> > +
> > +       /* Here we access the parent pointer of the test to find the sh=
ared resource. */
> > +       res =3D kunit_find_resource(test->parent, example_resource_allo=
c_match, NULL);
> > +
> > +       KUNIT_ASSERT_NOT_NULL(test, res);
> > +
> > +       /* Since the data field in kunit_resource is a void pointer we =
need to typecast it. */
> > +       threshold =3D *((int *)res->data);
> > +
> > +       /* Assert that the parameter is less than or equal to a certain=
 threshold. */
> > +       KUNIT_ASSERT_LE(test, param->value, threshold);
> > +
> > +       /* This decreases the reference count after calling kunit_find_=
resource(). */
> > +       kunit_put_resource(res);
> > +}
> > +
> >  /*
> >   * Here we make a list of all the test cases we want to add to the tes=
t suite
> >   * below.
> > @@ -296,6 +406,8 @@ static struct kunit_case example_test_cases[] =3D {
> >         KUNIT_CASE(example_static_stub_using_fn_ptr_test),
> >         KUNIT_CASE(example_priv_test),
> >         KUNIT_CASE_PARAM(example_params_test, example_gen_params),
> > +       KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, NULL,
> > +                                  example_param_init, NULL),
> >         KUNIT_CASE_SLOW(example_slow_test),
> >         {}
> >  };
> > --
> > 2.50.1.552.g942d659e1b-goog
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAkQn5KnBZ7O6TkHL8UR0UaJ-v0P51TjtEwoRu7VWaPYd8oeSg%40mail.gmail.com.
