Return-Path: <kasan-dev+bncBCMIZB7QWENRBHVVRXCAMGQEUVD5N2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id B67FCB11C29
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 12:21:20 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-6077af4c313sf2291873a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 03:21:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753438880; cv=pass;
        d=google.com; s=arc-20240605;
        b=d+jc/icyJjrAmD2I2hUNNVWIw22q8M4GK/qDEroYkbeK2zqlH28BO8AEiLEoIRfirj
         Fs0IW+w2q1voHyRPu+ty8Q0iImda4He4msVW//bzqkGk/1yQ9KJE66iaquUIrzUrBdvV
         E6EWHTyaxov3LrgX4SAtlbVKfZKmqueWIG1EJMh2XopSzYVKZhfs54BOx8WoZkOHnwsd
         DivvMxFDx265Mp1Xexeg96NMdOijFqzoiyRCxoWJgKWbY7RI1HFA+M/zvTEs5zCMnQXs
         g8Ms307P6XDRYbO82+D2YgQIdHZgR2ZiF/H+5U5g9mAnDY+7G2XWLRdTjlVA5y35MJq3
         RwSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NFbi4TiBqx0YCsKjoOPj1YW6T9yLVXMUf46mbMTe8kE=;
        fh=NOJ+XEv68KH3bRUv/guqNF9em1VQudqG1v37AZlEVBc=;
        b=NFnxz23xfZKZDO8J5qmYkvQjMfGaWpYxy+2mLRP8LYSTjlagD8NLsd7jASemfFCbQq
         WcjXOhcx1Y8AO3rB5lHEiO88es5B0cXrLkLT15Xy43o35x9dAol8f2q6Iozlkrl16ipn
         An0KmuvJzmFI45SQperSlDVKFQKz6bQnSlffaAjL/2Pe8IBuncvx24tm+pKVkMC2b5ah
         N8LaQNnO87Ghz+2kr2Dvt15Qv/GTBk4IclVdXUvS0JYDokJeRNP0FYDVM6m0WFJbt61G
         Y1pGWRNSI4L8RVL9XeL8M9vYPIfBuaiI1E2ECdqi6m+1R2LGrsta6zh0XVcEMFV17eJt
         XfVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HP98N2Dt;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753438880; x=1754043680; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NFbi4TiBqx0YCsKjoOPj1YW6T9yLVXMUf46mbMTe8kE=;
        b=V4YPPAX0laZ9k6AB33IxBd/Z0CVmA1/3Po3+d2fkx32BM49cWKCVrIcr78FvQRNZoj
         dp2MyylxLuMaqMEgURg7kM6Qwbhb5/Fsas9P3Gh1gWAOUrOpgmmFQ3HHEPZ9p/hlGVmY
         OUzXYGSESZE6xoeNn9EuTK0gsgFkgop4VI91AUVSl7d3n4O5RSL9198czhypXmgHv4hV
         8qh3C9FlOtu5BlXt5M/Iq9AlOY7vevxqYts3eogsZj80qKUWHqBOgsTKKKko45SXRIhD
         SxG2L1/TvM/uISPCMf7rYXet2dyi1yO97mQpZ8cP/t68F7JXq3vbdaTHvbtTA3wEK8Yl
         /FWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753438880; x=1754043680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NFbi4TiBqx0YCsKjoOPj1YW6T9yLVXMUf46mbMTe8kE=;
        b=ed3mO/sfQ+31Ti4OgYpqxXN7QM0S9VAmptKP2VPAAUE69CM36Dhc7bppBp80r7NWpZ
         luoI5g9MP0LZTQsVB3bogu0YHS8/5mXScTPz0bcq89PtKmLvAxCzc+t2+WuhEwjhbNSM
         ltTnzQTBKij56Agj05pDXpTKBIMptL2FMSP7NfAR4sKWfOKDgFWoFEXqpxqfMDrWfIpD
         QH43O91gvL5gbhPe8DAcz5lVWGCqHQrllifN5DHWM0V50Y7ocB8WBlgRNJkWosZN83K/
         G1ZB+lUAY3Ko7+wKGnLLLt9y9pEuXsEb4gxefQJR4hrdwnbU2VdLikkvIeUXzN7dFrxC
         UXHw==
X-Forwarded-Encrypted: i=2; AJvYcCUu2TFf8AOO0oRQFltU0uedLwhxHQYwU6A8P+zzH3iDcqJ2xJlLPNkOlHFuMJ0WGjgMw9ZWlg==@lfdr.de
X-Gm-Message-State: AOJu0YygqqYSjAd71XCxcLKNleqnz02YLQT2+hb4pnySvtBG4KS46blf
	6O2Fdq8yC91O1gWMU6d0COJa4VsIWnKLGRq1EMv45v0Zy3G3oj1AZWLR
X-Google-Smtp-Source: AGHT+IG57tBtfOV/k9F/vaK/3hnUcoDFP/fq3sTZlNrvXxrScxvTbngiLE7LIszQj+ELAzRRRupUyQ==
X-Received: by 2002:a05:6402:3587:b0:60e:3f7c:deb2 with SMTP id 4fb4d7f45d1cf-614f03b4a49mr1139091a12.12.1753438879572;
        Fri, 25 Jul 2025 03:21:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdWW/VaZ0JJw0GZMYiuZOXz7zRGyJa758TqN7Zgw/taKQ==
Received: by 2002:a05:6402:26cf:b0:611:d35a:c189 with SMTP id
 4fb4d7f45d1cf-61496f80456ls1530385a12.0.-pod-prod-00-eu-canary; Fri, 25 Jul
 2025 03:21:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLSVMSZZbGhohDUh6Of727G0zod55H+9hYK9M+mw0HV8BniyBLXz//P6zzTY1BDJMbMjZgtWzZLcM=@googlegroups.com
X-Received: by 2002:a17:906:fe0c:b0:ad8:adf3:7d6d with SMTP id a640c23a62f3a-af61e533d5amr146038666b.21.1753438876649;
        Fri, 25 Jul 2025 03:21:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753438876; cv=none;
        d=google.com; s=arc-20240605;
        b=YFHgLEpdqH4mC3JSY15ZTZbbqNe60B3UhnFE+WFRII6MATCnl/Xp6djfYzam+cV+zQ
         ZN0+Nr1TZ/7DUbPJadwSKFl12wZUoCKrkCtKfQvGQVjzQWrI6qQadv6ZxGm1uiNBWvw4
         oEqN9HEfbEdecxHD7mdpMDl5Pdq7OJTa9U5yLd+mkKg7unUFG6+SP1l3pdlO3cqxty/R
         9pn58fZfsHupxG0baE/SuFoBToQdDrDh/p9QzBOhoZlm9thtIbj/K/tbSp0LEuO+wW2z
         Eog8aAJ8PdHTfw4gvmpHVEe0oBzX0NMMhjXdtiCDFokDWYaDu2aaJEQ88snscct8EOpm
         brrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Gp1YEfuqIXq6d0PdrnSf3arbkeHySOCi7PIZYhRL5Sw=;
        fh=V6uwV4kQ0ttbMcYtCjDS4VyLewhT3lUnYnwH/gnMMuw=;
        b=IPQRlDO++0G4fhCHN/SE2yKeN3pjCLfjuvZAltry2yCcuXTAlzppwVylBCMtistJhP
         LtJj3QNHAyXljbozFG34kexwOc7wsb/8Kb2jV86bahrSvA+XrgqAZ7qTZgr7WtFmlK1E
         mpQ1rbemk8av0bNyDBsbxQoBmWF0e0cLX4Tl/T3TVkfbV3uY9IfqeQbWhWI2L7XUJeul
         /fjJtbiBCyUavRDNbKWCESRirCXpPVtBIYl5m75gtFTocn3Nkv98t3P/CtfpriC66uQJ
         UQKAkAR/dYiddUbBDWZzKPyPobgQlhtPQQ9ue6bftyq65g/Vc4LQTj3lo22mFqzExcGU
         hR/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HP98N2Dt;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-af479527469si11909166b.0.2025.07.25.03.21.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Jul 2025 03:21:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id 38308e7fff4ca-32b4876dfecso30502961fa.1
        for <kasan-dev@googlegroups.com>; Fri, 25 Jul 2025 03:21:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUiAXXrVjybyfuyCDvFCYTqTuGukP8dzDJ7ZMRPGaHS/5wBtOjp8u+htHbxyumTfP4G6RkWcwq5gNc=@googlegroups.com
X-Gm-Gg: ASbGncuT6PZXrYAz2cS9u+Tplqeava0SQW7A+DTCpN28d3XibaYGG6KR6WxaCUO2QRb
	Py5kbI1JdnsqVjdB/VDUBsnoXeRGbcDN0QnIRdIZkNnuNybIA1sDRxSltOJ1O74ya9GxlPlHWWb
	vBv4CSn89FRDhick8da9TXC0TYH0/GQlqGtDLRFitMT72LSlPr5VhBc9OJN6zqk+uuWP+5WV9Ed
	VoB999UKO6hOo1EPChIaBNcZO0GofcrfWcwr2sF
X-Received: by 2002:a05:651c:154b:b0:32a:6c39:8939 with SMTP id
 38308e7fff4ca-331ee3a7267mr5616091fa.19.1753438875508; Fri, 25 Jul 2025
 03:21:15 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-7-glider@google.com>
 <CACT4Y+b_KkqF0dm8OM1VUfwzDph6gHisk2amkk9RrLiGV24s9A@mail.gmail.com> <CAG_fn=VymVR+RNeeNOkVaOD3tpY=MFwP-8vU+w0+H5vS7jWMMA@mail.gmail.com>
In-Reply-To: <CAG_fn=VymVR+RNeeNOkVaOD3tpY=MFwP-8vU+w0+H5vS7jWMMA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Jul 2025 12:21:03 +0200
X-Gm-Features: Ac12FXzB-4uT0A5_3McI7aYw4DcEvHFODfUUTellt0zHb6zfyQMlJVZmc60jnmI
Message-ID: <CACT4Y+Zaov2rynD0T_SVbZ4_s+fqMnUg961PcaJ=mg40D34BPQ@mail.gmail.com>
Subject: Re: [PATCH v2 06/11] kcov: x86: introduce CONFIG_KCOV_UNIQUE
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HP98N2Dt;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 25 Jul 2025 at 12:07, Alexander Potapenko <glider@google.com> wrote=
:
>
> On Wed, Jul 9, 2025 at 5:01=E2=80=AFPM Dmitry Vyukov <dvyukov@google.com>=
 wrote:
> >
> > On Thu, 26 Jun 2025 at 15:42, Alexander Potapenko <glider@google.com> w=
rote:
> > >
> > > The new config switches coverage instrumentation to using
> > >   __sanitizer_cov_trace_pc_guard(u32 *guard)
> > > instead of
> > >   __sanitizer_cov_trace_pc(void)
> > >
> > > This relies on Clang's -fsanitize-coverage=3Dtrace-pc-guard flag [1].
> > >
> > > Each callback receives a unique 32-bit guard variable residing in the
> > > __sancov_guards section. Those guards can be used by kcov to deduplic=
ate
> > > the coverage on the fly.
> > >
> > > As a first step, we make the new instrumentation mode 1:1 compatible
> > > with the old one.
> > >
> > > [1] https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-wi=
th-guards
> > >
> > > Cc: x86@kernel.org
> > > Signed-off-by: Alexander Potapenko <glider@google.com>
> > >
> > > ---
> > > Change-Id: Iacb1e71fd061a82c2acadf2347bba4863b9aec39
> > >
> > > v2:
> > >  - Address comments by Dmitry Vyukov
> > >    - rename CONFIG_KCOV_ENABLE_GUARDS to CONFIG_KCOV_UNIQUE
> > >    - update commit description and config description
> > >  - Address comments by Marco Elver
> > >    - rename sanitizer_cov_write_subsequent() to kcov_append_to_buffer=
()
> > >    - make config depend on X86_64 (via ARCH_HAS_KCOV_UNIQUE)
> > >    - swap #ifdef branches
> > >    - tweak config description
> > >    - remove redundant check for CONFIG_CC_HAS_SANCOV_TRACE_PC_GUARD
> > > ---
> > >  arch/x86/Kconfig                  |  1 +
> > >  arch/x86/kernel/vmlinux.lds.S     |  1 +
> > >  include/asm-generic/vmlinux.lds.h | 14 ++++++-
> > >  include/linux/kcov.h              |  2 +
> > >  kernel/kcov.c                     | 61 +++++++++++++++++++++--------=
--
> > >  lib/Kconfig.debug                 | 24 ++++++++++++
> > >  scripts/Makefile.kcov             |  4 ++
> > >  scripts/module.lds.S              | 23 ++++++++++++
> > >  tools/objtool/check.c             |  1 +
> > >  9 files changed, 110 insertions(+), 21 deletions(-)
> > >
> > > diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> > > index e21cca404943e..d104c5a193bdf 100644
> > > --- a/arch/x86/Kconfig
> > > +++ b/arch/x86/Kconfig
> > > @@ -93,6 +93,7 @@ config X86
> > >         select ARCH_HAS_FORTIFY_SOURCE
> > >         select ARCH_HAS_GCOV_PROFILE_ALL
> > >         select ARCH_HAS_KCOV                    if X86_64
> > > +       select ARCH_HAS_KCOV_UNIQUE             if X86_64
> > >         select ARCH_HAS_KERNEL_FPU_SUPPORT
> > >         select ARCH_HAS_MEM_ENCRYPT
> > >         select ARCH_HAS_MEMBARRIER_SYNC_CORE
> > > diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.=
lds.S
> > > index cda5f8362e9da..8076e8953fddc 100644
> > > --- a/arch/x86/kernel/vmlinux.lds.S
> > > +++ b/arch/x86/kernel/vmlinux.lds.S
> > > @@ -372,6 +372,7 @@ SECTIONS
> > >                 . =3D ALIGN(PAGE_SIZE);
> > >                 __bss_stop =3D .;
> > >         }
> > > +       SANCOV_GUARDS_BSS
> > >
> > >         /*
> > >          * The memory occupied from _text to here, __end_of_kernel_re=
serve, is
> > > diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/=
vmlinux.lds.h
> > > index 58a635a6d5bdf..875c4deb66208 100644
> > > --- a/include/asm-generic/vmlinux.lds.h
> > > +++ b/include/asm-generic/vmlinux.lds.h
> > > @@ -102,7 +102,8 @@
> > >   * sections to be brought in with rodata.
> > >   */
> > >  #if defined(CONFIG_LD_DEAD_CODE_DATA_ELIMINATION) || defined(CONFIG_=
LTO_CLANG) || \
> > > -defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
> > > +       defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLA=
NG) || \
> > > +       defined(CONFIG_KCOV_UNIQUE)
> > >  #define TEXT_MAIN .text .text.[0-9a-zA-Z_]*
> > >  #else
> > >  #define TEXT_MAIN .text
> > > @@ -121,6 +122,17 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_=
PROPELLER_CLANG)
> > >  #define SBSS_MAIN .sbss
> > >  #endif
> > >
> > > +#if defined(CONFIG_KCOV_UNIQUE)
> > > +#define SANCOV_GUARDS_BSS                      \
> > > +       __sancov_guards(NOLOAD) : {             \
> > > +               __start___sancov_guards =3D .;    \
> > > +               *(__sancov_guards);             \
> > > +               __stop___sancov_guards =3D .;     \
> > > +       }
> > > +#else
> > > +#define SANCOV_GUARDS_BSS
> > > +#endif
> > > +
> > >  /*
> > >   * GCC 4.5 and later have a 32 bytes section alignment for structure=
s.
> > >   * Except GCC 4.9, that feels the need to align on 64 bytes.
> > > diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> > > index 0e425c3524b86..dd8bbee6fe274 100644
> > > --- a/include/linux/kcov.h
> > > +++ b/include/linux/kcov.h
> > > @@ -107,6 +107,8 @@ typedef unsigned long long kcov_u64;
> > >  #endif
> > >
> > >  void __sanitizer_cov_trace_pc(void);
> > > +void __sanitizer_cov_trace_pc_guard(u32 *guard);
> > > +void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *=
stop);
> > >  void __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2);
> > >  void __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2);
> > >  void __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2);
> > > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > > index ff7f118644f49..8e98ca8d52743 100644
> > > --- a/kernel/kcov.c
> > > +++ b/kernel/kcov.c
> > > @@ -195,27 +195,15 @@ static notrace unsigned long canonicalize_ip(un=
signed long ip)
> > >         return ip;
> > >  }
> > >
> > > -/*
> > > - * Entry point from instrumented code.
> > > - * This is called once per basic-block/edge.
> > > - */
> > > -void notrace __sanitizer_cov_trace_pc(void)
> > > +static notrace void kcov_append_to_buffer(unsigned long *area, int s=
ize,
> > > +                                         unsigned long ip)
> > >  {
> > > -       struct task_struct *t;
> > > -       unsigned long *area;
> > > -       unsigned long ip =3D canonicalize_ip(_RET_IP_);
> > > -       unsigned long pos;
> > > -
> > > -       t =3D current;
> > > -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> > > -               return;
> > > -
> > > -       area =3D t->kcov_state.area;
> > >         /* The first 64-bit word is the number of subsequent PCs. */
> > > -       pos =3D READ_ONCE(area[0]) + 1;
> > > -       if (likely(pos < t->kcov_state.size)) {
> > > -               /* Previously we write pc before updating pos. Howeve=
r, some
> > > -                * early interrupt code could bypass check_kcov_mode(=
) check
> > > +       unsigned long pos =3D READ_ONCE(area[0]) + 1;
> > > +
> > > +       if (likely(pos < size)) {
> > > +               /*
> > > +                * Some early interrupt code could bypass check_kcov_=
mode() check
> > >                  * and invoke __sanitizer_cov_trace_pc(). If such int=
errupt is
> > >                  * raised between writing pc and updating pos, the pc=
 could be
> > >                  * overitten by the recursive __sanitizer_cov_trace_p=
c().
> > > @@ -226,7 +214,40 @@ void notrace __sanitizer_cov_trace_pc(void)
> > >                 area[pos] =3D ip;
> > >         }
> > >  }
> > > +
> > > +/*
> > > + * Entry point from instrumented code.
> > > + * This is called once per basic-block/edge.
> > > + */
> > > +#ifdef CONFIG_KCOV_UNIQUE
> > > +void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
> > > +{
> > > +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> > > +               return;
> > > +
> > > +       kcov_append_to_buffer(current->kcov_state.area,
> > > +                             current->kcov_state.size,
> > > +                             canonicalize_ip(_RET_IP_));
> > > +}
> > > +EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
> > > +
> > > +void notrace __sanitizer_cov_trace_pc_guard_init(uint32_t *start,
> > > +                                                uint32_t *stop)
> > > +{
> > > +}
> > > +EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard_init);
> > > +#else /* !CONFIG_KCOV_UNIQUE */
> > > +void notrace __sanitizer_cov_trace_pc(void)
> > > +{
> > > +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> > > +               return;
> > > +
> > > +       kcov_append_to_buffer(current->kcov_state.area,
> > > +                             current->kcov_state.size,
> > > +                             canonicalize_ip(_RET_IP_));
> > > +}
> > >  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> > > +#endif
> > >
> > >  #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
> > >  static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u6=
4 ip)
> > > @@ -254,7 +275,7 @@ static void notrace write_comp_data(u64 type, u64=
 arg1, u64 arg2, u64 ip)
> > >         start_index =3D 1 + count * KCOV_WORDS_PER_CMP;
> > >         end_pos =3D (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
> > >         if (likely(end_pos <=3D max_pos)) {
> > > -               /* See comment in __sanitizer_cov_trace_pc(). */
> > > +               /* See comment in kcov_append_to_buffer(). */
> > >                 WRITE_ONCE(area[0], count + 1);
> > >                 barrier();
> > >                 area[start_index] =3D type;
> > > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > > index f9051ab610d54..24dcb721dbb0b 100644
> > > --- a/lib/Kconfig.debug
> > > +++ b/lib/Kconfig.debug
> > > @@ -2156,6 +2156,8 @@ config ARCH_HAS_KCOV
> > >  config CC_HAS_SANCOV_TRACE_PC
> > >         def_bool $(cc-option,-fsanitize-coverage=3Dtrace-pc)
> > >
> > > +config CC_HAS_SANCOV_TRACE_PC_GUARD
> > > +       def_bool $(cc-option,-fsanitize-coverage=3Dtrace-pc-guard)
> > >
> > >  config KCOV
> > >         bool "Code coverage for fuzzing"
> > > @@ -2172,6 +2174,28 @@ config KCOV
> > >
> > >           For more details, see Documentation/dev-tools/kcov.rst.
> > >
> > > +config ARCH_HAS_KCOV_UNIQUE
> > > +       bool
> > > +       help
> > > +         An architecture should select this when it can successfully
> > > +         build and run with CONFIG_KCOV_UNIQUE.
> > > +
> > > +config KCOV_UNIQUE
> > > +       depends on KCOV
> > > +       depends on CC_HAS_SANCOV_TRACE_PC_GUARD && ARCH_HAS_KCOV_UNIQ=
UE
> > > +       bool "Use coverage guards for KCOV"
> > > +       help
> > > +         Use coverage guards instrumentation for KCOV, passing
> > > +         -fsanitize-coverage=3Dtrace-pc-guard to the compiler.
> >
> > I think this should talk about the new mode, the new ioctl's, and
> > visible differences for end users first.
>
> Something like this, maybe?
>
>           This option enables KCOV's unique program counter (PC)
> collection mode,
>           which deduplicates PCs on the fly when the KCOV_UNIQUE_ENABLE i=
octl is
>           used.
>
>           This significantly reduces the memory footprint for coverage da=
ta
>           collection compared to trace mode, as it prevents the kernel fr=
om
>           storing the same PC multiple times.
>           Enabling this mode incurs a slight increase in kernel binary si=
ze.
>
>

Looks good to me.

> > > +         Every coverage callback is associated with a global variabl=
e that
> > > +         allows to efficiently deduplicate coverage at collection ti=
me.
> > > +         This drastically reduces the buffer size required for cover=
age
> > > +         collection.
> > > +
> > > +         This config comes at a cost of increased binary size (4 byt=
es of .bss
> > > +         plus 1-2 instructions to pass an extra parameter, per basic=
 block).
> > > +
> > >  config KCOV_ENABLE_COMPARISONS
> > >         bool "Enable comparison operands collection by KCOV"
> > >         depends on KCOV
> > > diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
> > > index 67e8cfe3474b7..0b17533ef35f6 100644
> > > --- a/scripts/Makefile.kcov
> > > +++ b/scripts/Makefile.kcov
> > > @@ -1,5 +1,9 @@
> > >  # SPDX-License-Identifier: GPL-2.0-only
> > > +ifeq ($(CONFIG_KCOV_UNIQUE),y)
> > > +kcov-flags-y                                   +=3D -fsanitize-cover=
age=3Dtrace-pc-guard
> > > +else
> > >  kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)    +=3D -fsanitize-cover=
age=3Dtrace-pc
> > > +endif
> > >  kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)   +=3D -fsanitize-cover=
age=3Dtrace-cmp
> > >  kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)         +=3D -fplugin=3D$(obj=
tree)/scripts/gcc-plugins/sancov_plugin.so
> > >
> > > diff --git a/scripts/module.lds.S b/scripts/module.lds.S
> > > index 450f1088d5fd3..314b56680ea1a 100644
> > > --- a/scripts/module.lds.S
> > > +++ b/scripts/module.lds.S
> > > @@ -64,6 +64,29 @@ SECTIONS {
> > >                 MOD_CODETAG_SECTIONS()
> > >         }
> > >  #endif
> > > +
> > > +#ifdef CONFIG_KCOV_UNIQUE
> > > +       __sancov_guards(NOLOAD) : {
> > > +               __start___sancov_guards =3D .;
> > > +               *(__sancov_guards);
> > > +               __stop___sancov_guards =3D .;
> > > +       }
> > > +
> > > +       .text : {
> > > +               *(.text .text.[0-9a-zA-Z_]*)
> > > +               *(.text..L*)
> > > +       }
> >
> > Why do we need these here? .text does not look specific to CONFIG_KCOV_=
UNIQUE.
> > Is it because of constructors/destructors emitted by the compiler, and
> > .init.text/.exit.text don't work w/o .text?
> > A comment here would be useful.
>
> This is because the compiler creates duplicate .init.text/.exit.text,
> making the module loader unhappy.
> I'll add a comment.

Yes, a comment would help.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACT4Y%2BZaov2rynD0T_SVbZ4_s%2BfqMnUg961PcaJ%3Dmg40D34BPQ%40mail.gmail.com.
