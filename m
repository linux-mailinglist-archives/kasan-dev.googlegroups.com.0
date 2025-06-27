Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTOT7LBAMGQEWEA6N6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 37E71AEB9C7
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 16:25:20 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-2e933923303sf1930929fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 07:25:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751034318; cv=pass;
        d=google.com; s=arc-20240605;
        b=ci2f2t/RnDHDXbDUWvinBuzFLC/mBOetSxhdkL1BGfepsUpa2HoKICGjPtsjhPln7k
         tffc8jIMSTNyS0RljOdXS2qf8CDl9PyufEezOodrRFJyN+4QAu1jZ3Iymuj9lTWBBlPJ
         b3pBpg/ZRTP9BfWZGoaXzcyT33n+UnuX+h04IA+nFNUYBkPDN3o/CckbHSczaiSk1mCR
         achs0WGJgusd4MWRVymgOCaZTkWUIoTNRifA5xIvE0/GLn+i1+h5g4fJFZl/TlkFw7+t
         SoL/yp2xCZMBBQkaZAKIMwGYMIZlZvcoGhAPRlocunWJMh4KYrgIQwitFeB5HsVZ9GMv
         EsBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Vp7LzMJTd2V/r7qi9CmBY98bqrz25KzZqoz39Idlx1E=;
        fh=sbnkJUP56IVzTe+m6oGMNQIW31w97ZUb6AHtunPlDuo=;
        b=jSPTRLVo6JUi4O2cf8KJxylPExsdOXs7EQ3IXoPasCx2ksVjZmHY6WQi6WJwOHjiP/
         nBBOZauQ8o2QfWxg4JW9sX0WReDY19b/vhufZ82bDBIAw6laIloDfYHaDEWLH55HV3JR
         14UUcUDWQbOSOUBywgjZcJq7rMs8X+TuE44gifSeqbWcWCbWvzd8aecSnKz/vLbqb1Fn
         7bTlst1t9fTNdnwiFj3cpsXCqdUCGQfRTLgJVBIZI99Vrvdnk6PTHPXQ5oznIKiU8E/x
         H1ihFa0g4seFbFP5R5uA8OI0wTHsOcsk4KVEJkWp1tA8/26YTf1ZY8lJ0yds3EtyEhf1
         s5+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OO7B6odf;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751034318; x=1751639118; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Vp7LzMJTd2V/r7qi9CmBY98bqrz25KzZqoz39Idlx1E=;
        b=AURN89SLRVienTIz244hKGh/COVUff7WZyxaecBy6WY6icZbJ17ppWmL5E4boMPRwU
         JWIFsXpZGaFnLOZqtvXEWL2Ei9R8kzos8KLuvMb0nv5XbJyHwyS1qJsDSjeWfl0sX5z8
         2z1eXYji8FhSRmbxMfTduCnm5OOtMueTK7mV/gB5hj5m5YdxjekQOylCBvXkJ+foyMPp
         TBCHuWW09Os2DrYewepqPE45Ajr5Wz4WNGRWj05SGef63akZxjQk/7dJMd17mkVzi/OS
         PpAki46rdK7sBVFImn64f7XYEZGVxThLw6296UrrOfZbxmvQfRP950EPTHs4SiEQmUWJ
         Eukg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751034318; x=1751639118;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Vp7LzMJTd2V/r7qi9CmBY98bqrz25KzZqoz39Idlx1E=;
        b=L3znefNlCaW2fDFzAnO9Ao/nmgvON4Z4l0Mw4L2Ub9MPsCulJE1RTBYFpjRZU2wXxT
         H9ZuE0+9st3H9KPMhXxg+fskZ3h/f7BQ+cOdJDFgssvxwTI70kdBvoUi/kM1f7Luaag1
         ugUcoYdaX68VvvgicPeXwCAlqsiaGsTskuCz0Qg8NTLS8XpihpaZpQeFle8Cu/o5Uxtp
         IFpwtTxCIl/CmrWrLsU+XaZYq1mtslhDdrmVAM9XwwaCE2POhqBIUFzo8YCuJGSSCNGM
         +F3iZaezGzNafvem5bdbkiECYa8EQM4yFCs6mBeaSB86Wu/K8XRjMqhO6kGpIAFcQ3T3
         hDVA==
X-Forwarded-Encrypted: i=2; AJvYcCXHt64TgbK7iWZmROzh7RUrOIyQo05VGig42hvYksqyfVnpHN3a+DISbyo9VQTrpD7b/zcQYw==@lfdr.de
X-Gm-Message-State: AOJu0YycXLO2Y6j8muLqeQMEIfAfiFPsMddKFvNh2WgZWaWKXUyh+ozV
	hdcPG0JrQUvS6j18mbEGpRCMJ1dDWpJXYr/++WNmELDyqYlScxOQp3eD
X-Google-Smtp-Source: AGHT+IFMUq2IRFN8Z6Nxfc4Z6z9SJQ/cPWzXcYN90JweA7dFbQO/WytoH/k6+XicFFBTfJvuqy6w8w==
X-Received: by 2002:a05:6870:a512:b0:2e9:11d9:f8ad with SMTP id 586e51a60fabf-2efed6aa1bemr2073525fac.24.1751034318072;
        Fri, 27 Jun 2025 07:25:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc9l3lYCoHWDxg2g/Qh5Npz4grWKUN24oz48TvolZoFgA==
Received: by 2002:a05:6871:7893:b0:2ea:72d5:87e8 with SMTP id
 586e51a60fabf-2efcf1d59afls1662838fac.1.-pod-prod-08-us; Fri, 27 Jun 2025
 07:25:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXbJUzhb3OsUF/n8VXCrp4CEnMEnNOnvTZqI9WJT8hLr+qFaJTKRMynWepA+R+y9YiVlOetdA7rd5k=@googlegroups.com
X-Received: by 2002:a05:6808:1b26:b0:40a:52e5:37c9 with SMTP id 5614622812f47-40b33e370c2mr2822189b6e.28.1751034316697;
        Fri, 27 Jun 2025 07:25:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751034316; cv=none;
        d=google.com; s=arc-20240605;
        b=TfSrJS/tMwb/BlZnKUq2cYX08L9n+Ko35cuwlIN9F04wuj1xZN2CMDPu3HQcjl3Up3
         TDMCA85dxPI8K8WNp6bQP7c1OQPVGkE3kJ5USTzaVcpPhK/a0zzdqT3IS6id++gtVV3o
         P+JMu1/hCZZ5VMJwEORNmAuOFTGy5NBIV0jruM+kGLd5XK6Ljuc3gNjctvv2/PYOS/DZ
         ebPgxv71H4N6x3dW+fN87PYeb9d51kuhG6dqpWPjNv8s9jl4zygeVc3O+3BZXZxSYhQY
         dqTWnJs0aF/Wg4PT3xBKTsdnApAXWt/lzLF7tNRjKGlaXFcSPPZ2OuvkoxqJo4uO20mL
         pt/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rWEwwAXq7aUCx39IeLJxT3jNwxQZV+O1CFl/KQTm4BE=;
        fh=RIpI0cPwm7Ju90VfPqyEb/aDgUfz6jlwl64NIwsExU8=;
        b=ONnDS7kT4TLnwja+hyUJNilV6/Pr0uXLcPQ5UAeFvfaDABue7S7fkmvYHnlHh3Vwaj
         x/dL+BRQoZptQ6qbYod0yLp7dBKkaTrhoOb57aZYM6sRi90sDHppxOEJ3vqyvIir99Ia
         psbwkuAU2gShKiyZfX6kXghdoV+aHicFIiwwp9blIPFMdE3ZIUhoYEnGo9dmi6AbfDEw
         kUZyepN6cUxieayc1j5SPAOk3IkHolL1S3E5CxrtDp+/FCt7+dQoZO2DWc7m0AWXhHSA
         XHx7cf4Q0S3+yGV3q0yzfLXNQzP8dMb4C4z2EwNUfCfGDfQl4275Rkw94P7TdAATIKG3
         WCRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OO7B6odf;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-40b32439048si110208b6e.4.2025.06.27.07.25.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Jun 2025 07:25:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id 98e67ed59e1d1-311da0bef4aso2493302a91.3
        for <kasan-dev@googlegroups.com>; Fri, 27 Jun 2025 07:25:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWAlBCGe4ATliP4XYGzfDn7S6vtgsPlCgFucmo56aK8bHC7++WEP+C3ScVeLK3/XCEokZvIihK/L3o=@googlegroups.com
X-Gm-Gg: ASbGnctl7wxx3x6IG4shHQdfJCMUVO1iTQSB50j+7BsfRJc6qleT3MRnkAb5Dx9Kmx9
	g7Caz1NQ7i8CsRfA4UUSZMYxA2cEDMd8uOWijy26Q8+XgXK0dXLjHWimtrGoSprbbzNzYawgW4a
	Ip5fmCrSO8qJNF+nfeO+giDSCYsJxo2c9Uik3ae4yGnr8fg9KA9lSBk7ES6mOgbzJN5hwPl4uNf
	w==
X-Received: by 2002:a17:90b:4e8b:b0:312:1b53:5e9f with SMTP id
 98e67ed59e1d1-318c92e111fmr5023442a91.24.1751034315698; Fri, 27 Jun 2025
 07:25:15 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-7-glider@google.com>
 <20250627081146.GR1613200@noisy.programming.kicks-ass.net>
In-Reply-To: <20250627081146.GR1613200@noisy.programming.kicks-ass.net>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 Jun 2025 16:24:36 +0200
X-Gm-Features: Ac12FXyQawK2wMIbahdpGNOHGjO4VNy-BCPJo06Xuokf1P8k9xJhRjaaDWA72xY
Message-ID: <CAG_fn=UrOBF=hQ5y6VN9VuA67GeVOyaaWtrnaSLz4TnC7u1fiw@mail.gmail.com>
Subject: Re: [PATCH v2 06/11] kcov: x86: introduce CONFIG_KCOV_UNIQUE
To: Peter Zijlstra <peterz@infradead.org>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=OO7B6odf;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1035
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Jun 27, 2025 at 10:11=E2=80=AFAM Peter Zijlstra <peterz@infradead.o=
rg> wrote:
>
> On Thu, Jun 26, 2025 at 03:41:53PM +0200, Alexander Potapenko wrote:
> > The new config switches coverage instrumentation to using
> >   __sanitizer_cov_trace_pc_guard(u32 *guard)
> > instead of
> >   __sanitizer_cov_trace_pc(void)
> >
> > This relies on Clang's -fsanitize-coverage=3Dtrace-pc-guard flag [1].
> >
> > Each callback receives a unique 32-bit guard variable residing in the
> > __sancov_guards section. Those guards can be used by kcov to deduplicat=
e
> > the coverage on the fly.
>
> This sounds like a *LOT* of data; how big is this for a typical kernel
> build?

I have a 1.6Gb sized vmlinux, which has a .text section of 176Mb.
There are 1809419 calls to __sanitizer_cov_trace_pc_guard, and the
__sancov_guards section has a size of 6Mb, which are only allocated at
runtime.

If we take a vmlinux image from syzbot (e.g.
https://storage.googleapis.com/syzbot-assets/dadedf20b2e3/vmlinux-67a99386.=
xz),
its .text section is 166Mb, and there are 1893023 calls to
__sanitizer_cov_trace_pc, which will translate to exactly the same
number of __sanitizer_cov_trace_pc_guard, if we apply the unique
coverage instrumentation.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DUrOBF%3DhQ5y6VN9VuA67GeVOyaaWtrnaSLz4TnC7u1fiw%40mail.gmail.com.
