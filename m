Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4VORXCAMGQEBIT2T7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id C7C19B11BAD
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 12:07:53 +0200 (CEST)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-7196c919719sf27848687b3.1
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 03:07:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753438067; cv=pass;
        d=google.com; s=arc-20240605;
        b=TSbEli76XUQhqMKJ6zOcEF7VQURlSOqgLB2TKsmvPnzCC1O7itJbILXkUPecB8GHcA
         0ks4Nv1TEN3TG4f0xvDylPo3OH8w4OvtJRX2+NB+1Ybq9uRqQu1efjDRmyXI2LNKrW85
         /fbqT9wjvCK88IwYuTD1x2SGF73tMcGrg/cvkbWtzZhLQ7rlM5bBKuB4FcNQ+8pHSk0p
         YfuoXK69mb78PPMOhsJmc4esswqQZCqcPXrLqZUWl2jYpDAfU7SmdfzgLPDzRphxDuaK
         dpvVsm3DbXprNULonapFkkuWlTKUOeC3rto+md3DC4EejZOEneMSoOonsEzvsDVJRrXk
         sTew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=42APV1CgY+3XMR3D2um2pFle3lySrNJELPvFbnyt++o=;
        fh=+XUcdACD2bdvSm4H3C27BXdAOE2Fzd6LTYsGCvZXp+I=;
        b=i8/Nb3E5gMgxlXB7woLL6C0z38Dh77p5PJ+Fuluj3N1dZ4YhUT1557X7LySdEHCtWh
         +NO4ZyRHPJzOQlQLJaD3+LA+sHmzz1KXR83DB3GAdSIN3as5/HSPjv75uwpyOQQW9qww
         XzNh1OIGW9hwKUENTMY7hAndSBa+Vpt3CKaD4Li7mK4W1mxJPXreURRLtN6YqVM+Md/8
         25rEnQdo/p6YVFhl1IjOYMfp8NA2f7QvWUfYXsLtui2qpes9TgoLfpn5T/Rm+RuljMVL
         qYgxbPNnnEC3cnwGm52X8AaGnd+T7Mg1eOBguPToUIQ9OMvjn/7NvYEO6lu++3HO0Jtn
         s6GA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tZ5pKbnN;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753438067; x=1754042867; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=42APV1CgY+3XMR3D2um2pFle3lySrNJELPvFbnyt++o=;
        b=FLX1Au0MuWUKuUnpl6LjmMo6lJZOFCu7eD9LFoEZXk57lc3D2vHFrHA8bpD3AveyTx
         hJlFnnnFdB4w1Io0zta6Ubxb8m1dvZuv4B4pSzcVM81AxPcZBZFpPFbZVY0C/W1r+5Tn
         0auAspb+OptgGUDC0aIqDL1jzr2IDrDYGTnxdNM8ePLzqdSokV+ILQezfs67o0edeNK6
         92tS5J8b2QnnkuYiPoDlc8CzGauIIbMtba+v/d5lUxffVtS1UN339pZSlruXJsCba0fv
         oJOF0srR1AVdHF+CdzIEyZS3izemy23VHVvq2VFGMj5wn1yiQOWGGTBA8gG5QktBnlS2
         /D7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753438067; x=1754042867;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=42APV1CgY+3XMR3D2um2pFle3lySrNJELPvFbnyt++o=;
        b=geBa56xnVE/yvTJFJmwUUT1W4dRl33bS2IYJAaJjXxx4k4ll2aiweZ3mO6c8mIjYGE
         GRRT/1xRIq/jQPULG5INiP7PDLDV3WvQDLKg8dmjLRYGutk631cfoLqTpjFabjQ3+3nU
         UuxVaoxMjKh5e5v2RUrkEHw+Y50nhRDOy9oqgw8nasAyUZeu50oCrpPYpt/uJwEpsYAc
         Qf01Cwq/7MUEs2bSl/wQ+p01bmdWb9ZekbuWwlZckm9fsJAGd+DMabl8S7vOBacbmuYN
         znvWJoYuv7gogJfZ1hfUiAptmnTvHIdDucbbBBgJ1c+I+vvOUtEMEZ46OY+Kq0VTZ1gm
         1q+Q==
X-Forwarded-Encrypted: i=2; AJvYcCUbrfrT9md5F4EKJiQcpIIhcyirKlVzi/3DVJafrzIM5n76M7VbaPbqfue3kblAYgHWuzOPqg==@lfdr.de
X-Gm-Message-State: AOJu0YzApH/Re4Ia0EhKTv6mcbbuHJ9mEzs3sYcLdlFAbxzlBGyyL0Wm
	LMYdrO2FqNxWUM+Ua01jCw4k06Qioy7sVWwEa7OwJTfTwR+k+yTk2/X7
X-Google-Smtp-Source: AGHT+IHWhSFNK+mxzj05AMq4l3TaSI36Dq5qnx/V4gZSJKXHs6f95bx0SkBVDub/6fZnIxfZLAyF/g==
X-Received: by 2002:a05:6902:2505:b0:e8d:8bbc:77 with SMTP id 3f1490d57ef6-e8df125913fmr1026041276.34.1753438067135;
        Fri, 25 Jul 2025 03:07:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfOfSs3wunJCwVjy8gxXUjozEU9bLo9QAHE7exgv2w9bw==
Received: by 2002:a25:88a:0:b0:e82:21c7:67f7 with SMTP id 3f1490d57ef6-e8ddc153413ls1894280276.0.-pod-prod-07-us;
 Fri, 25 Jul 2025 03:07:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZQGi7MxjQdF6w1dX4qarnXf6k3CXLwuWfwjBACgX1ezePrrc358wrFhksKXvHOAPdvj2XPWmPpfU=@googlegroups.com
X-Received: by 2002:a05:690c:3341:b0:719:e0de:4d95 with SMTP id 00721157ae682-719e38868bdmr17665387b3.28.1753438065754;
        Fri, 25 Jul 2025 03:07:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753438065; cv=none;
        d=google.com; s=arc-20240605;
        b=flCPyKeKVCycGrU1CWrhaxD6Z05ZRj5dh5dDvxicC98cS0XFmVnpE51tg9Asb5JtOK
         DmdRj8q915cNt5edO8EKSQ88yaddavcf3jbFqjuOoo5vr/Ph4f2M4aOmJmrKW49ifIde
         BnSADEAUkQ/c8azaaFaQFoQW4u3TkfZMnC+7Uq/AmZ4J2UmQP6MiemE+5pD9bYGNqeSe
         e/vWTaBy0XkMaNbE64ux/CT7jtrJ+DdkZqxz+seLDy6eZ/Xmi7monHPBwy34KIXF/+g+
         9KbmZcCgwbTYYon24ynD6tvhV1gP5WVR/HxaNiWoWrvtBjG2sLR4KUXtkAMU3NOZ1VxQ
         grzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Wq57YvRXrwTcYsKh+D33blhDVrknv64jxZ2lz0EJIqo=;
        fh=G8ZhlNvpM8EKY203ePi8MrizBDKaUzTsZ62x86SN4TE=;
        b=lSY4GJX2QZJ3hjR7UceUwa9jmVgnzyo1szlGYVdTgrppAUeqp1i9Gxdmaa5qmeGp1P
         bytaNTGVGK71NhnBw+TZJkxkcXsjoq5Or7FniPH1cwLF5wgHpKLu/6fkZgRL9hTAvo/v
         CTbTeIQU3kCY3mf1wvU31aHhW0Q4JxaMchjN+SR6Z99/fYvrB2sL7+mLQIedWeU8ICzC
         H78QbSQCSLUDY95Lf8hQiYgTBQ9bueSgUoBNL5IIU2cS+MzgYXnoASGUnznukuUq49X7
         6RrW4Dr9bCoJOI64Z8E/xF9Ch/zJfo0yi7WqYBvjUKDccOZtt4sQSEzEUBm4dhS7D3/u
         Whow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tZ5pKbnN;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-719cb906718si1848197b3.4.2025.07.25.03.07.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Jul 2025 03:07:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id 6a1803df08f44-6fad79433bbso17242336d6.0
        for <kasan-dev@googlegroups.com>; Fri, 25 Jul 2025 03:07:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXqikOLGoRu+HD0+cKW/2NHRFE//zbzS6QXRhtGX7ISRvfe7iJEP1QCXpNmaSmkF2qE7rn4f4/1zKs=@googlegroups.com
X-Gm-Gg: ASbGncs7NX3Tys2PRVNpGTSvjmos46DuAXuKMqt9I4QVcqRLCIe+U9mFKqOCf69GPRG
	sjDdWe1yquk+6CsmQKTyKVRCgqeZ1wkUkpfxyeO1f8A9VRmX0XmaIOtGEZgrRxVUpx7oFB6wqaH
	vj74nF2LV71VTicsJoot/4lZ8JrzSnQx+2m30t1K8PtCHlAWQ2dRc5+laFnjs4YqC0WHJF2bhj1
	IxMc3e7yaEv8cMBpBl0wBPdE8EIWlRZiqpWMw==
X-Received: by 2002:a05:6214:f0b:b0:707:bba:40d4 with SMTP id
 6a1803df08f44-7072052762emr19107456d6.11.1753438064731; Fri, 25 Jul 2025
 03:07:44 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-7-glider@google.com>
 <CACT4Y+b_KkqF0dm8OM1VUfwzDph6gHisk2amkk9RrLiGV24s9A@mail.gmail.com>
In-Reply-To: <CACT4Y+b_KkqF0dm8OM1VUfwzDph6gHisk2amkk9RrLiGV24s9A@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Jul 2025 12:07:07 +0200
X-Gm-Features: Ac12FXyiwwfyc1H4wzpo6zW675-o_drEgRHCr_MkKkiDI7okUQOE1MYpFzghCq4
Message-ID: <CAG_fn=VymVR+RNeeNOkVaOD3tpY=MFwP-8vU+w0+H5vS7jWMMA@mail.gmail.com>
Subject: Re: [PATCH v2 06/11] kcov: x86: introduce CONFIG_KCOV_UNIQUE
To: Dmitry Vyukov <dvyukov@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=tZ5pKbnN;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as
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

On Wed, Jul 9, 2025 at 5:01=E2=80=AFPM Dmitry Vyukov <dvyukov@google.com> w=
rote:
>
> On Thu, 26 Jun 2025 at 15:42, Alexander Potapenko <glider@google.com> wro=
te:
> >
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
> >
> > As a first step, we make the new instrumentation mode 1:1 compatible
> > with the old one.
> >
> > [1] https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with=
-guards
> >
> > Cc: x86@kernel.org
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> >
> > ---
> > Change-Id: Iacb1e71fd061a82c2acadf2347bba4863b9aec39
> >
> > v2:
> >  - Address comments by Dmitry Vyukov
> >    - rename CONFIG_KCOV_ENABLE_GUARDS to CONFIG_KCOV_UNIQUE
> >    - update commit description and config description
> >  - Address comments by Marco Elver
> >    - rename sanitizer_cov_write_subsequent() to kcov_append_to_buffer()
> >    - make config depend on X86_64 (via ARCH_HAS_KCOV_UNIQUE)
> >    - swap #ifdef branches
> >    - tweak config description
> >    - remove redundant check for CONFIG_CC_HAS_SANCOV_TRACE_PC_GUARD
> > ---
> >  arch/x86/Kconfig                  |  1 +
> >  arch/x86/kernel/vmlinux.lds.S     |  1 +
> >  include/asm-generic/vmlinux.lds.h | 14 ++++++-
> >  include/linux/kcov.h              |  2 +
> >  kernel/kcov.c                     | 61 +++++++++++++++++++++----------
> >  lib/Kconfig.debug                 | 24 ++++++++++++
> >  scripts/Makefile.kcov             |  4 ++
> >  scripts/module.lds.S              | 23 ++++++++++++
> >  tools/objtool/check.c             |  1 +
> >  9 files changed, 110 insertions(+), 21 deletions(-)
> >
> > diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> > index e21cca404943e..d104c5a193bdf 100644
> > --- a/arch/x86/Kconfig
> > +++ b/arch/x86/Kconfig
> > @@ -93,6 +93,7 @@ config X86
> >         select ARCH_HAS_FORTIFY_SOURCE
> >         select ARCH_HAS_GCOV_PROFILE_ALL
> >         select ARCH_HAS_KCOV                    if X86_64
> > +       select ARCH_HAS_KCOV_UNIQUE             if X86_64
> >         select ARCH_HAS_KERNEL_FPU_SUPPORT
> >         select ARCH_HAS_MEM_ENCRYPT
> >         select ARCH_HAS_MEMBARRIER_SYNC_CORE
> > diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.ld=
s.S
> > index cda5f8362e9da..8076e8953fddc 100644
> > --- a/arch/x86/kernel/vmlinux.lds.S
> > +++ b/arch/x86/kernel/vmlinux.lds.S
> > @@ -372,6 +372,7 @@ SECTIONS
> >                 . =3D ALIGN(PAGE_SIZE);
> >                 __bss_stop =3D .;
> >         }
> > +       SANCOV_GUARDS_BSS
> >
> >         /*
> >          * The memory occupied from _text to here, __end_of_kernel_rese=
rve, is
> > diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vm=
linux.lds.h
> > index 58a635a6d5bdf..875c4deb66208 100644
> > --- a/include/asm-generic/vmlinux.lds.h
> > +++ b/include/asm-generic/vmlinux.lds.h
> > @@ -102,7 +102,8 @@
> >   * sections to be brought in with rodata.
> >   */
> >  #if defined(CONFIG_LD_DEAD_CODE_DATA_ELIMINATION) || defined(CONFIG_LT=
O_CLANG) || \
> > -defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
> > +       defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG=
) || \
> > +       defined(CONFIG_KCOV_UNIQUE)
> >  #define TEXT_MAIN .text .text.[0-9a-zA-Z_]*
> >  #else
> >  #define TEXT_MAIN .text
> > @@ -121,6 +122,17 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PR=
OPELLER_CLANG)
> >  #define SBSS_MAIN .sbss
> >  #endif
> >
> > +#if defined(CONFIG_KCOV_UNIQUE)
> > +#define SANCOV_GUARDS_BSS                      \
> > +       __sancov_guards(NOLOAD) : {             \
> > +               __start___sancov_guards =3D .;    \
> > +               *(__sancov_guards);             \
> > +               __stop___sancov_guards =3D .;     \
> > +       }
> > +#else
> > +#define SANCOV_GUARDS_BSS
> > +#endif
> > +
> >  /*
> >   * GCC 4.5 and later have a 32 bytes section alignment for structures.
> >   * Except GCC 4.9, that feels the need to align on 64 bytes.
> > diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> > index 0e425c3524b86..dd8bbee6fe274 100644
> > --- a/include/linux/kcov.h
> > +++ b/include/linux/kcov.h
> > @@ -107,6 +107,8 @@ typedef unsigned long long kcov_u64;
> >  #endif
> >
> >  void __sanitizer_cov_trace_pc(void);
> > +void __sanitizer_cov_trace_pc_guard(u32 *guard);
> > +void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *st=
op);
> >  void __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2);
> >  void __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2);
> >  void __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2);
> > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > index ff7f118644f49..8e98ca8d52743 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -195,27 +195,15 @@ static notrace unsigned long canonicalize_ip(unsi=
gned long ip)
> >         return ip;
> >  }
> >
> > -/*
> > - * Entry point from instrumented code.
> > - * This is called once per basic-block/edge.
> > - */
> > -void notrace __sanitizer_cov_trace_pc(void)
> > +static notrace void kcov_append_to_buffer(unsigned long *area, int siz=
e,
> > +                                         unsigned long ip)
> >  {
> > -       struct task_struct *t;
> > -       unsigned long *area;
> > -       unsigned long ip =3D canonicalize_ip(_RET_IP_);
> > -       unsigned long pos;
> > -
> > -       t =3D current;
> > -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> > -               return;
> > -
> > -       area =3D t->kcov_state.area;
> >         /* The first 64-bit word is the number of subsequent PCs. */
> > -       pos =3D READ_ONCE(area[0]) + 1;
> > -       if (likely(pos < t->kcov_state.size)) {
> > -               /* Previously we write pc before updating pos. However,=
 some
> > -                * early interrupt code could bypass check_kcov_mode() =
check
> > +       unsigned long pos =3D READ_ONCE(area[0]) + 1;
> > +
> > +       if (likely(pos < size)) {
> > +               /*
> > +                * Some early interrupt code could bypass check_kcov_mo=
de() check
> >                  * and invoke __sanitizer_cov_trace_pc(). If such inter=
rupt is
> >                  * raised between writing pc and updating pos, the pc c=
ould be
> >                  * overitten by the recursive __sanitizer_cov_trace_pc(=
).
> > @@ -226,7 +214,40 @@ void notrace __sanitizer_cov_trace_pc(void)
> >                 area[pos] =3D ip;
> >         }
> >  }
> > +
> > +/*
> > + * Entry point from instrumented code.
> > + * This is called once per basic-block/edge.
> > + */
> > +#ifdef CONFIG_KCOV_UNIQUE
> > +void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
> > +{
> > +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> > +               return;
> > +
> > +       kcov_append_to_buffer(current->kcov_state.area,
> > +                             current->kcov_state.size,
> > +                             canonicalize_ip(_RET_IP_));
> > +}
> > +EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
> > +
> > +void notrace __sanitizer_cov_trace_pc_guard_init(uint32_t *start,
> > +                                                uint32_t *stop)
> > +{
> > +}
> > +EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard_init);
> > +#else /* !CONFIG_KCOV_UNIQUE */
> > +void notrace __sanitizer_cov_trace_pc(void)
> > +{
> > +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> > +               return;
> > +
> > +       kcov_append_to_buffer(current->kcov_state.area,
> > +                             current->kcov_state.size,
> > +                             canonicalize_ip(_RET_IP_));
> > +}
> >  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> > +#endif
> >
> >  #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
> >  static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 =
ip)
> > @@ -254,7 +275,7 @@ static void notrace write_comp_data(u64 type, u64 a=
rg1, u64 arg2, u64 ip)
> >         start_index =3D 1 + count * KCOV_WORDS_PER_CMP;
> >         end_pos =3D (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
> >         if (likely(end_pos <=3D max_pos)) {
> > -               /* See comment in __sanitizer_cov_trace_pc(). */
> > +               /* See comment in kcov_append_to_buffer(). */
> >                 WRITE_ONCE(area[0], count + 1);
> >                 barrier();
> >                 area[start_index] =3D type;
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index f9051ab610d54..24dcb721dbb0b 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -2156,6 +2156,8 @@ config ARCH_HAS_KCOV
> >  config CC_HAS_SANCOV_TRACE_PC
> >         def_bool $(cc-option,-fsanitize-coverage=3Dtrace-pc)
> >
> > +config CC_HAS_SANCOV_TRACE_PC_GUARD
> > +       def_bool $(cc-option,-fsanitize-coverage=3Dtrace-pc-guard)
> >
> >  config KCOV
> >         bool "Code coverage for fuzzing"
> > @@ -2172,6 +2174,28 @@ config KCOV
> >
> >           For more details, see Documentation/dev-tools/kcov.rst.
> >
> > +config ARCH_HAS_KCOV_UNIQUE
> > +       bool
> > +       help
> > +         An architecture should select this when it can successfully
> > +         build and run with CONFIG_KCOV_UNIQUE.
> > +
> > +config KCOV_UNIQUE
> > +       depends on KCOV
> > +       depends on CC_HAS_SANCOV_TRACE_PC_GUARD && ARCH_HAS_KCOV_UNIQUE
> > +       bool "Use coverage guards for KCOV"
> > +       help
> > +         Use coverage guards instrumentation for KCOV, passing
> > +         -fsanitize-coverage=3Dtrace-pc-guard to the compiler.
>
> I think this should talk about the new mode, the new ioctl's, and
> visible differences for end users first.

Something like this, maybe?

          This option enables KCOV's unique program counter (PC)
collection mode,
          which deduplicates PCs on the fly when the KCOV_UNIQUE_ENABLE ioc=
tl is
          used.

          This significantly reduces the memory footprint for coverage data
          collection compared to trace mode, as it prevents the kernel from
          storing the same PC multiple times.
          Enabling this mode incurs a slight increase in kernel binary size=
.


> > +         Every coverage callback is associated with a global variable =
that
> > +         allows to efficiently deduplicate coverage at collection time=
.
> > +         This drastically reduces the buffer size required for coverag=
e
> > +         collection.
> > +
> > +         This config comes at a cost of increased binary size (4 bytes=
 of .bss
> > +         plus 1-2 instructions to pass an extra parameter, per basic b=
lock).
> > +
> >  config KCOV_ENABLE_COMPARISONS
> >         bool "Enable comparison operands collection by KCOV"
> >         depends on KCOV
> > diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
> > index 67e8cfe3474b7..0b17533ef35f6 100644
> > --- a/scripts/Makefile.kcov
> > +++ b/scripts/Makefile.kcov
> > @@ -1,5 +1,9 @@
> >  # SPDX-License-Identifier: GPL-2.0-only
> > +ifeq ($(CONFIG_KCOV_UNIQUE),y)
> > +kcov-flags-y                                   +=3D -fsanitize-coverag=
e=3Dtrace-pc-guard
> > +else
> >  kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)    +=3D -fsanitize-coverag=
e=3Dtrace-pc
> > +endif
> >  kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)   +=3D -fsanitize-coverag=
e=3Dtrace-cmp
> >  kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)         +=3D -fplugin=3D$(objtr=
ee)/scripts/gcc-plugins/sancov_plugin.so
> >
> > diff --git a/scripts/module.lds.S b/scripts/module.lds.S
> > index 450f1088d5fd3..314b56680ea1a 100644
> > --- a/scripts/module.lds.S
> > +++ b/scripts/module.lds.S
> > @@ -64,6 +64,29 @@ SECTIONS {
> >                 MOD_CODETAG_SECTIONS()
> >         }
> >  #endif
> > +
> > +#ifdef CONFIG_KCOV_UNIQUE
> > +       __sancov_guards(NOLOAD) : {
> > +               __start___sancov_guards =3D .;
> > +               *(__sancov_guards);
> > +               __stop___sancov_guards =3D .;
> > +       }
> > +
> > +       .text : {
> > +               *(.text .text.[0-9a-zA-Z_]*)
> > +               *(.text..L*)
> > +       }
>
> Why do we need these here? .text does not look specific to CONFIG_KCOV_UN=
IQUE.
> Is it because of constructors/destructors emitted by the compiler, and
> .init.text/.exit.text don't work w/o .text?
> A comment here would be useful.

This is because the compiler creates duplicate .init.text/.exit.text,
making the module loader unhappy.
I'll add a comment.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVymVR%2BRNeeNOkVaOD3tpY%3DMFwP-8vU%2Bw0%2BH5vS7jWMMA%40mail.gmail.c=
om.
