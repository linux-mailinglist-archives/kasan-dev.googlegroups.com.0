Return-Path: <kasan-dev+bncBCCMH5WKTMGRBS5NR3CAMGQEMDY7GNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C6E0B12033
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 16:38:05 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-b362d101243sf1674080a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 07:38:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753454284; cv=pass;
        d=google.com; s=arc-20240605;
        b=Hg7Mw9bRfm4o4L/+cjrGOPZYLkX6S+eTuix6+TjkWWt7SccsvHNzvzt9SvClZKMBvj
         2FjhbbqjYU/pbp2g2ReNMzlk27z+uO133V386gB4er9lTFKJtww58HkUhw2+dhCUtHAc
         2HR0+o34ks5BIKKoa54pM1ofTGme8g0RfDfL5zizvK+2fwnrTXMS5dza+uFbOPfXOLu1
         cjSGAec9wQZethBvZvKpe13SfDdnhTXzsAYvTprCPLFj6w8faNzQVl77VLD1yCrrpJ8w
         CnyKrfZl97wrcG9dfCLe+GeAGJdIbp4oaZhpouz9rdpr/fWcrif8UWEUhNvxCmKEJ6ox
         BNmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MeUJDBPMwVFTZSLw6+LYAcf0szFx+Kpxn2csfUf9wuQ=;
        fh=0lXCBNZMKAUHB/wJXHPVJOK+fznJdzHXrCRtkKzoOxc=;
        b=H3p45fe6Lf5JueycUg5pG9aYqgLp6/tw/WMskGGmf4ElP5qc0SiAf+wZ8Al5/23oCg
         mMwnS8VltzNk0nSnRrl3erAi1MRKpvvM4AgJK1a/QXBS+PZDby3kAijqMlpV/Wm+qW7E
         MU52HHbnmy2zt717fJPi8TIXP0lCkCkbdLRy7a14vzerXcfBSwPttWOb0KnF6Oor9rdC
         E9EWX70lxMnGywk9KOKk0kcMvyg1TUgk0Ly6N6+Gg4ABJBj+JjC7V5SKGl+FeJ8pvdgJ
         wIL0iNc4NRsX92HX24KCjB/lNRhWCyerrpHmmwJE2FF0srJe4Yfam7HfPSamii62bt42
         vVSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="g370aK4/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753454284; x=1754059084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MeUJDBPMwVFTZSLw6+LYAcf0szFx+Kpxn2csfUf9wuQ=;
        b=CURnECVnQigTepFhmW0Geqq8Mk9zMf4yQkduh6Iwixdw89aUB7Z/znRGywFCWLCzaf
         zLP7Gby96KXTKuDFe66AJ1wYWxO4TZBcjwmC2N/BA9htOQILoil2iVXdf4y9hcVKVH21
         7plzy0Q0yxElTymqCs7HNNKGBpt/+3gMF/PSIcxF7hTwOPJPb6bhvykx1BFjadyZrBm5
         U6lwmUPam1EigVG/9j6pMb8aWoNv4424TXr+VFYAh5M3EEvO8ft8i6jSS9ZMdqTpfM2J
         gQzmVSgEDVzbB7nduw1Xd1ugGsEyhI89rapZ6y1usEjm0pj8JlXND5jCYIH0JOofPgUE
         2EhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753454284; x=1754059084;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MeUJDBPMwVFTZSLw6+LYAcf0szFx+Kpxn2csfUf9wuQ=;
        b=XQWU1HI2IEBIVzCN4yGC9iQ2daq0mLrqAXAB9sQf+ArIpDw3jkhmU9JCJXJmS4c6/t
         nZ6v38sb97KW5cWOYgTXmvs3Xa56HeT1nV1f7qxf8kzl5VDCcirD53KWh0UqEEyNhdy1
         K7BlMpxQ3cGdgtWUYSrgNjSmHk5NfeTSbJ069/L0h8eaRgt3FwIlU8f785Vt0o/5YLtU
         5T3XzZ0whgAOmk4+NZ9X2NrmRYO2ARyecUGsULcog4FhwsmTB9xMplAHa6u87Kqs3a2b
         Dj+x6TPKGmYSE2e6d0unhHIBf0cpZemymf8rMV6kclYRJgWPcFsVoLxOgOsafKwnvFy9
         Wm1g==
X-Forwarded-Encrypted: i=2; AJvYcCWnBkm5TTfjn/J0uJCxKeSfphM3AB4ca/iCvnFHCTLVnzkWx1VMs15liyeHptscxrg3FBvJcg==@lfdr.de
X-Gm-Message-State: AOJu0YzCEh3A1P48XTiVQK7JI3ZAzT4RCZZACPfkqbekyWFwrXGr1ZEC
	GxF+GnAeMvRlNh4dDMhgPKsNKNx0USwJY76X+rqcNj/SSeA8tv++6c8e
X-Google-Smtp-Source: AGHT+IGB4A9MS+xcSJ9jiG3KJMH1xZYKWFaPwfFQTzLstmKnZoIacYMkiZSCc7+17W3KjDtYKgG0yw==
X-Received: by 2002:a17:90b:48ce:b0:311:9c9a:58c5 with SMTP id 98e67ed59e1d1-31e7788c54emr3054829a91.12.1753454283678;
        Fri, 25 Jul 2025 07:38:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZevrEyBVVT3RUATgW3Qld6U8sOV0LFLNpGZT00FCTBGKA==
Received: by 2002:a17:90b:3cc5:b0:31e:2f83:f300 with SMTP id
 98e67ed59e1d1-31e5fac4980ls2147115a91.2.-pod-prod-09-us; Fri, 25 Jul 2025
 07:38:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWArGuw7w+wwEYdf1I2PMrkuxSpLzVcCCcazPFt6UTTLS/iDza6bEUQWLsGcQVHlXMo2cxzoIgpQy0=@googlegroups.com
X-Received: by 2002:a17:90b:2b4d:b0:313:287c:74bd with SMTP id 98e67ed59e1d1-31e77a4b0f3mr3502852a91.33.1753454280393;
        Fri, 25 Jul 2025 07:38:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753454280; cv=none;
        d=google.com; s=arc-20240605;
        b=HGTB6USzk+YPJSq0PtSzYSntnbpxjZwZhKIqJzDLvXwz8aQoJj1QXMHE/h8J4wKsHz
         4MPSTojQv47VIgtZjqhehssGLHtJjBYiG6sPezIaLiJA9Ko8AHrWC/3v79dUJZTua18w
         xYK5zYBvJt/ZLq1KDmGdlvuxEPGLis476+LN6+B9psStMLjhwGnf7GKxU3p87qRsatXt
         Jrnhe3Fnst0t/NQsljHpmzwqw7PMbvn8sDiRm/4XofhpvTjOZXnSZ9o38KoioazH124d
         sjarR4cyEXfkLdvxS1AjY20NCSQexPuQqNPBr3UyGeE0/lTQeeCiLAlTYxptY8X89hEJ
         0N1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=x8Br67kpHlUcVp1I+AlPTk1fWbNSy9YXckgKLzf2oqc=;
        fh=0LgEV4SZDOORcNpVdG1iztMusQCCMEOP0xvhk3tFrSk=;
        b=ItiyrKez8YpxybdU2uDVAU57hGJgvd3s4KvTNT7aAbICWhjaDnMVH6JFsgghY+oV/H
         p6gIo7KxVwHFvtS+l8SHhq8W06Z9MSCGglmgVDtScZCEd3uOhAmUxwVyhJKSEF5MsrBI
         W0BswKK8iuxz6qUqG6BsOCgpc2GZyohACqYy0lMnGByuzlWOQrCvap4M9TmgIGHXNBIL
         AloPs5yRxe9SySAGv21pcamLFOeFNy6zgnSbo1A/6a5wpn6aNpkdK4S9UKiVMOTfVv84
         92SB8ky0T08gHtQlqRZqAJbWMHCqf8U/56M/w+wGLmfSaHUJhorNS6ij/lu3WKnWNa01
         RWUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="g370aK4/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b3f7f4a98d4si4427a12.0.2025.07.25.07.38.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Jul 2025 07:38:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id 6a1803df08f44-707122b5b37so15939056d6.3
        for <kasan-dev@googlegroups.com>; Fri, 25 Jul 2025 07:38:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXDr4cYdO2dBitPuUR2Fw1XRO9hAuUBUKtA3jlqZ5hEtGGkUWQwivQVdApnpzFuY/bnGoM0AuDwrg4=@googlegroups.com
X-Gm-Gg: ASbGnctodOu3J928XmSH5/cZtZgps3EEkSrhUr/wi71gCCNUNXcu6U4uQlz5iHVa8VA
	KFQIu1yNQ3bIR4+uzQh6J6B4HxNGZ21tSo60fSvqwd/ljZmELjROjdLdOMD3NkHmt3edYNkBlMS
	AsbA1AKlhmnk+oH01PGesF7iMplus2n89TCyTYPHmHj4paUKtkygSOjFir/Z0rF755DfYqnT59v
	JAXRIfdigEyLwEmQ2jR0xfApo9KuwxZ4JImSq8LQo8DE0op
X-Received: by 2002:a05:6214:1ccc:b0:705:982:3cb8 with SMTP id
 6a1803df08f44-707204b0ff6mr23039986d6.6.1753454276038; Fri, 25 Jul 2025
 07:37:56 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-11-glider@google.com>
 <CACT4Y+YSfOE6Y9y-8mUwUOyyE-L3PUHUr6PuNX=iu-zyMyv3=A@mail.gmail.com>
In-Reply-To: <CACT4Y+YSfOE6Y9y-8mUwUOyyE-L3PUHUr6PuNX=iu-zyMyv3=A@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Jul 2025 16:37:19 +0200
X-Gm-Features: Ac12FXy-DhcoJp-qiCmwab46NJ0PZ2JSKLIvCIWT-laejPsOjCULrKUtahAig3I
Message-ID: <CAG_fn=WSm=u1zOGaPydq89jSw_iiQdSTPSNsd=WbeByLfTVmtw@mail.gmail.com>
Subject: Re: [PATCH v2 10/11] kcov: selftests: add kcov_test
To: Dmitry Vyukov <dvyukov@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="g370aK4/";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Jul 9, 2025 at 5:15=E2=80=AFPM Dmitry Vyukov <dvyukov@google.com> w=
rote:
>
> On Thu, 26 Jun 2025 at 15:42, Alexander Potapenko <glider@google.com> wro=
te:
> >
> > Implement test fixtures for testing different combinations of coverage
> > collection modes:
> >  - unique and non-unique coverage;
> >  - collecting PCs and comparison arguments;
> >  - mapping the buffer as RO and RW.
> >
> > To build:
> >  $ make -C tools/testing/selftests/kcov kcov_test
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> >  MAINTAINERS                              |   1 +
> >  tools/testing/selftests/kcov/Makefile    |   6 +
> >  tools/testing/selftests/kcov/kcov_test.c | 364 +++++++++++++++++++++++
>
> Let's also add 'config' fragment (see e.g. ./dma/config)
> Otherwise it's impossible to run these tests in automated fashion.
Done in v3.

> > +/* Normally these defines should be provided by linux/kcov.h, but they=
 aren't there yet. */
>
> Then I think we need to do:
> #ifndef KCOV_UNIQUE_ENABLE

Good point!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWSm%3Du1zOGaPydq89jSw_iiQdSTPSNsd%3DWbeByLfTVmtw%40mail.gmail.com.
