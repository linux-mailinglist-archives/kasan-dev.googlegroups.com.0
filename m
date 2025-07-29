Return-Path: <kasan-dev+bncBDPPVSUFVUPBB664UTCAMGQEKPWNXHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 300DAB1544F
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 22:26:37 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3e05997f731sf132599085ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 13:26:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753820796; cv=pass;
        d=google.com; s=arc-20240605;
        b=TQ3WLkRu9J+65Hkv1IvFouFDwA7iVMeVkW97Thvs2LUJVxD87vobCwlt5jSB08Vd0n
         YNlZ00adJblTqZKyj5W0eMuDgb7YB/OsAgxa+3foaRLSSB/B4k7BN4rxZ2xTPGuFzZFm
         WBCTALDLvBSaAmlP/P3wizyQv+dgsWgHCggcwYuiTvkHabRVCoLgip2il3DgLjrb/bD4
         yTbw6zVb3xpZvWzKsW10h/WcNA8PLuS5KEzqQjtyVLjnUB4ZEmASCS4T1EyLxKuuQiBp
         5K124+OoAkSNqxp1Vc1KGFkJB29woKmaDKCS/owfF4sNpyKCP2c+ENYBPLO1zbNAs8cD
         2cvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ahrlZyLcB86+5lexJREt41GqKKsgxoiwf+ZJpR4KZfw=;
        fh=jI6w8A9ofj07AbVrcbW5ob2OK7XcB0LZnQIseZrf4cc=;
        b=QjdH7EBsL2bTs5nlXIr+j7N8oJY4NTYDUZRtDFu1TXakZmoB3DZUyO1CxCiuVS5XSC
         M7SJdvnhhkJucgf56rhwTzey4Xo88z5sXl2SmbmD5FUUnMiYUUUeuK5zK0i437HCzGP1
         YdQ/MxWSJdPhgGfakS+i5YBbglYEzsVgzZzBSfip9kgZEdedoMRe5fU1rQFxYmZlUpAi
         Crw2pz04iVw98w++ZgIJzBijHVSlQrrpvq/ynH4XMYLENCDrKVdL9RSDYJB5N+3q4t4v
         J41ywMgHgxK6oZHVmtDsD3U8CallVuCWPVHGSKbRhR9ak/ARX2xZ1IYZ5XVoJVz1hhBL
         iWrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jIFwOzmW;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753820796; x=1754425596; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ahrlZyLcB86+5lexJREt41GqKKsgxoiwf+ZJpR4KZfw=;
        b=YJ/nWEPz3qcmSHdEWD4gU1rWVgC5WA9hiJMQi0UGR++nMteuhbAhLzNueQKi07jl8a
         4DLsFm3M/a2oH/BnzkOTlMfc/0e30R+Gg39cVXGspe0rIHfJHgPd7c7RD5iyFBDsknX+
         0DKwaD9OSpm3BT2+QTGYrbYXUF0ZjMulAAKioqH5hHg3yQlwrURuZhPSi4IsYle3sysc
         cGSD2jqLYs1YWE0MbxWNxb+YHCLmllh1pbzQ8bq5G8Pz6hUilk8MbkF2267L5ie2HW+T
         rmrRipoADKMHhhUFGbbThsCspWPJk8N7jmtsV1NHJi+gSXMlD+8ZLPBQwlAidjmPWaZX
         S50w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753820796; x=1754425596;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ahrlZyLcB86+5lexJREt41GqKKsgxoiwf+ZJpR4KZfw=;
        b=Tz17DNRwTfp0U9dkCNa9t7sAv7p6I5/HvazhtXlmSaVuWg7lHebuCvnG2epuETNFBK
         UY4REPRsO2vH2Z8vR7Nx+WBTqiQic4I+3I6vrZuidJDx2OE6PG/TjgeeuN3cHksSD0x4
         O+7WlAE3rnDLlNkdL45QvuSwfTo15vddK0aMRY0qoJx8GDqkA5etHwYOviizqUfDGf+3
         d92IgBsO9KyPL3Zuag5FhJ3ZcMHdXIvpU3LmCpopV5FarPZW2Fkqefy8l/ZppRGIRtOg
         9U6nOvqGh12bRImQCBbYrymlAm8byoh+ngcKcja6fn1KxSDVxMHRG2n3JLh8Rul2DWiw
         H9fg==
X-Forwarded-Encrypted: i=2; AJvYcCXy1XwndyXPVt8CceE32KPxaYjpVoAGPzTGtBUMAf94yH9PczZUn5Yz1WwLebvJ/sFK4IeGOA==@lfdr.de
X-Gm-Message-State: AOJu0YxIP9+8q20RzRXkweXrqmjp76FFBt+SWrMJnudIuIEmQot971QB
	z18Y0oLBaJz87rMHXh35s6orIJYTDY2+HLLYUD9MddfWYgTA6uZ5IAIb
X-Google-Smtp-Source: AGHT+IFUOTDB0s0ElaCXqgFk4hmmwjhYePE7DA4JbBaOA5IlMc6d8XJ6+XGN3GawuFLYf0U6YbfvGA==
X-Received: by 2002:a05:6e02:2388:b0:3df:347f:ff3e with SMTP id e9e14a558f8ab-3e3f60df47fmr14674855ab.7.1753820795800;
        Tue, 29 Jul 2025 13:26:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZetWemjlZ0SzpDf58/Py7UG2OPzdooe1OfsbbJFkjgnUg==
Received: by 2002:a05:6e02:4701:b0:3dd:bfcd:edd6 with SMTP id
 e9e14a558f8ab-3e3b517af0dls60109335ab.1.-pod-prod-08-us; Tue, 29 Jul 2025
 13:26:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWHq6bhKwlt+1qKuGTxiGhaW8tmHUWxhnzK2uMTJXar9+hl29X7zlXM7rDWWa4bxuKC0ofZLXBweaM=@googlegroups.com
X-Received: by 2002:a05:6602:2dc6:b0:87c:5e79:203 with SMTP id ca18e2360f4ac-881375f425dmr164406339f.4.1753820794838;
        Tue, 29 Jul 2025 13:26:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753820794; cv=none;
        d=google.com; s=arc-20240605;
        b=KPQLctBbgg6OKJv7WcslX6MXB9OEeButkoHCiUe8pdXY5Ofa9LxDDdNmhKB5D+/wHK
         9hnJ/dQAACeFRFtAPcY3rII9KfEB+8auleZpLDdDZd3CmJ85ot6vQAr9owKoc8B+W7jL
         EpBbk8+tLyZ2FNQWj1bqUXZrwJObA1BvKT+hhOd1VTLyocPtssneB3LugiHlFNa9MG7B
         MU2zxJywnxzRwkCCbjF44IoIkGXeMiSgxfgE+zIj4tjackfQJjJneQ9GAyERj64bNU0X
         yy3BH9mgkTRmyV4XbyCeoLpPGvwuSGQ/foffmRZ5W6mqMTQ1ScnT7WVNe1738fi1L1rJ
         qI8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lUba6K8jqFTo7PyTbrkud2zkkQZs/3cD7l8HjP/HFnw=;
        fh=m/xyyfIQ+VhQe0WOU9EuTaWRnrTKmq2tLwR+X+LAa3w=;
        b=LeIyWWNZDBcyl/tBusHaPfKKYnssIs/06c8Mg2497oQeZ6JHvnSq2OPpMSmBPdVSMc
         wHAyxGJ0upxvpuvsLif+gOupGqxln0pk8WbHhsdur31L/3r+y+qv1m19i14rSPfIvqEr
         xLgtdNAj5ScmBxpsUCb0ovBdrnWPoSUKL/bUWfhNmAF0xKjrJPW7uDo30ZoixBh+u2c2
         4whScWDSY+bI3CY90zRZTPe9BVBO4bMEAIdbOdHbaIBD8VkDCCa0zdGoRpq3vIsnppn3
         I6Yfq3p+uaLQoDqS48wbGzVpTDWezkbX6a4dAqdDfKko3JwxblIKsk8LKmQXtvLBYYHE
         BICw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jIFwOzmW;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-508c91d2086si510230173.2.2025.07.29.13.26.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 13:26:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-6faf66905adso34810876d6.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 13:26:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUI1LGZNUTo6WifzBPuV4DZrBp1MvPLVoAi7E4Haflx1Qw9hNhsOi+xQ8bRPXMAUV5QzOAsI0FG35Q=@googlegroups.com
X-Gm-Gg: ASbGncsCCvMaiYCt5YYyoMome4w4wl7esd8ehJ9FbsKjrXPSgoMvLHGdmGBwh7wweIY
	Eh6ov6zW0gBdzHKnFTTQxzvFIFrDQBq+k9/ins9CqIVsig+eO2IEiEv3v//CAqQpdNym/L2zw38
	lEey1rqSWZK+Cu/fAG+XW/EwJPwak3Lvtv651MrUJIvw2GNEaYDDxGAy658yR/q95HLsVnN8hKM
	oIEN082fJ9URrmXIfkUdW8MMgBKTWbV/9jlgQ24FuyPZKEV
X-Received: by 2002:ad4:5c8d:0:b0:702:d655:f4e9 with SMTP id
 6a1803df08f44-70766e3f302mr12378566d6.18.1753820793697; Tue, 29 Jul 2025
 13:26:33 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-7-marievic@google.com>
 <CA+GJov7gQMughx7wR5J_BGqo7FaPhEPF-OHaCg3OuuL17X5vpA@mail.gmail.com>
In-Reply-To: <CA+GJov7gQMughx7wR5J_BGqo7FaPhEPF-OHaCg3OuuL17X5vpA@mail.gmail.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Jul 2025 16:26:22 -0400
X-Gm-Features: Ac12FXwMXtoJETJwjrpeWEppK8R5hxomMaIXf4G-i3r5Ati6QR7pZQsQ7V97C04
Message-ID: <CA+GJov4SneU9XeKLiACAcO-q5EVe=jo-AfYH4cs87o92MpQ00g@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=jIFwOzmW;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f30 as
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

On Tue, Jul 29, 2025 at 4:14=E2=80=AFPM Rae Moar <rmoar@google.com> wrote:
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
>
> Hello!
>
> Thanks for sending out this series! I will do a full review of it. For
> now, I noticed that I get an error when I try to run KUnit tests as
> modules. I get the following error: "ERROR: modpost:
> "kunit_get_next_param_and_desc" [lib/kunit/kunit-example-test.ko]
> undefined!". As a possible fix, I suggest moving the function
> definition into the header file and making it a static inline
> function.
>
> Thanks!
> -Rae
>

Hello! Feel free to also use EXPORT_SYMBOL_GPL(). Either solution
should work here. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov4SneU9XeKLiACAcO-q5EVe%3Djo-AfYH4cs87o92MpQ00g%40mail.gmail.com.
