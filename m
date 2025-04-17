Return-Path: <kasan-dev+bncBCU4TIPXUUFRBB6GQTAAMGQEYWY3ECQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5821FA921F5
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 17:49:29 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4766e03b92bsf18057031cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 08:49:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744904968; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nq6fv+otezQ7erRdRcNTCnepmp4azIBogL7a5Z4KWq2eErHNKP7sUUPu4Q6kmbLhHN
         1h4stejnEmg6UlvrPoI6bu24Gb4lEHipwMwqCgNsr4UtJa26rxuKjg9hdm5OILq0zwAE
         TkY7/G7nRqhL4Nzp08Ej721T75xZk704k2hc4/6FB70JAiXFHd9gZC/XlTc214v3i+ll
         X9z7BuUCDv0fgXpoJI874B2yq8qp2KI84nGQtyaxvk7InhGLoBycJHVAef7bWFHIfePi
         xPSsrU2H5+plVCnXf/dHpnqZL7F5K8feUHiuFX7F0OlAGU17Cx6J8mH2ymE2Y+UGkNx6
         BTmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6TDBPUwR/EyKjqcmIgH0oIEVhH5oajRyH9ceUXxXW2U=;
        fh=0YO0NDU44Hg6NhmNc7BoNrsbrxWB0qNA+Wj+kOp5LNo=;
        b=BU3W1lXoPG00o6KFyMdSOgX1M373JgnOhio1qXMYGHO1VdWp8owtdBCdttWVmuj+k/
         2mD5RbLh2l9ZST+B45SoiCFjX9njs2zhzfGc4DJ8LHEL9e7+qh+o/lTPqV7X4si2QYU0
         qx7kLo34HIbb8CW715YqbjyI9t7BsU3/EDa6h5+97ltthgxeqUw4mgg3dVp3DAuJy9PM
         bjClOMnZHJxGsiwovbgd31FTVgiftlmJpvRW+AKKU8JiTbyV/gB+RWFwPpCsTyakQOEq
         moc5d8xA4NT/RzE0xjR31sCfkrX/+jqW/dW3zWqHbaAhuTJ6YaC76BAMgHvkNdTwzAGe
         ZJtg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=moucwpso;
       spf=pass (google.com: domain of ardb@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744904968; x=1745509768; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6TDBPUwR/EyKjqcmIgH0oIEVhH5oajRyH9ceUXxXW2U=;
        b=bfi3hEAqeoI7GIiHXyZrgEyTwc5ocb02RcqCdpO8WWYa7Gg5bjq69n1BJtLl/SOEfX
         XPW7mwoY0bAd/FFadjn0w/CCJpixvOUmtYilQPJke2mxaOs2MjtuEyFUoaKQQtTZcfON
         XiJzZJflGw2PzbpoeKwPkuM2OBkrp87VCKzU4kgO6gtI6bpO0l3iN9A0W35EM1UYBUro
         rQdQ3GNNgZigLO4z49ws53KMPbTHY59QIu5JZsx7BAs1+O4FZgEeHyOX/mG6/DApF4rb
         8rA3oHRs2PhbVcrKxt+xFe1VwdnFOGG7/vMEhL+f6/Rj1Lefcsg8pGcbU3pEypSqSDcN
         CBlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744904968; x=1745509768;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6TDBPUwR/EyKjqcmIgH0oIEVhH5oajRyH9ceUXxXW2U=;
        b=IfshE39NaYXHUn4k7D3/1RwV94CsoqhNehidXj3E02yDrvrnneEhn3O89TV6fbahvM
         uyyb5d3KR8vJ13lTgvI3GseKXX/eO0yWBgKJqWH4ylXbd2B8EI66igkro12i+S9x0x97
         5IrehApyYGc9LXfmN5hSSoPLvZa6PqimiQl+mp2QmWY6iDPbMtigh9KrV5pA0nYeA5Ii
         Xj1KvuAK+J3cuhAwkwGp9Q+dBnbutslILHHBsk0f/1RwPPNQzdrf55PIK/MmZAukc3BJ
         HBrxx5e+28jKl7d6oltnTaPfl7NBvqML/YbDVVOo4XsWgVri3K9s/96W1jxSth4T5W7X
         kHLg==
X-Forwarded-Encrypted: i=2; AJvYcCW06rVIyyE94K++XKnbqOGFlipP9aj0Y6v+MQ/q3yky85zxfAbNnlMpP3yOlIJUnZfHzvEegA==@lfdr.de
X-Gm-Message-State: AOJu0Yx/uZTJW0BXfrvlUiGAaTvyWgT2gL5y4mq9d9US5q1S244rewrq
	lHjmglZMjG2t0BbFgO5N0Cchko2HvBlBjGshB2eT3P10WTI8E6P8
X-Google-Smtp-Source: AGHT+IEfd4yci3RKwEbjujkW+PJD+qTfv6wZAZmp4lLLcAy5cpVqr6T+KrQLL5Kuj6TFyd5G/qN3RQ==
X-Received: by 2002:ac8:5a54:0:b0:477:6eca:b40c with SMTP id d75a77b69052e-47ad8098948mr107110501cf.1.1744904968024;
        Thu, 17 Apr 2025 08:49:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJaXoJfFRzCj0SmgP320OAYAgYSF6hELcWFcf5bOEL5Nw==
Received: by 2002:a05:622a:268d:b0:477:c8a:e60b with SMTP id
 d75a77b69052e-47addd1f34dls15327281cf.1.-pod-prod-02-us; Thu, 17 Apr 2025
 08:49:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXTGzKNgJCarFimVhZADcDCMKniD51un9Ff5P1Y+OqUjYX+FiDrAEk95OKHU+YSAeMQwbLN1llL5Hs=@googlegroups.com
X-Received: by 2002:ac8:7dcc:0:b0:477:41f1:285d with SMTP id d75a77b69052e-47ad80b478fmr88009531cf.19.1744904966866;
        Thu, 17 Apr 2025 08:49:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744904966; cv=none;
        d=google.com; s=arc-20240605;
        b=R2iUsNH8gQkJhhre47Morugp8UY0i3dSsC6zI32qJTUKvLYxe9yIFw8GbI86hY8l6g
         r08tYr5C9aNHXaYwBvGBp0UuvASVEzaT/gJvXeodFogwhTslmASewRvoCpa5e1FQLJWU
         pv+Z2peeJ6NOI5pXITdV4vneMwraFy/26zpWOD3Whwf1xy7LJbl/QWXhQZkOPHQpOW39
         KD3Nku/jiLxg8E5I7HHGmQP5bm8iXZpW5EIejnGjR20XcfrhTfUmZLmXcdm6T9qoXssy
         P5KxU1PHKPJvRZUPANsCDFRbGZMAd8sikw9tIqN3qAaM/uCX+v6yA+9TfksVcmrpQ++L
         tQew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uGoFegrtK323fTXw1ni/vvAxcbbW6NLUsK1CzocSs0Q=;
        fh=Rg9QPYAh2oD4t1ENChiWg66cRutLPJ78uS1vVE+TZ3g=;
        b=YjJVgz0Bk713ulgUoorM4qf3OQBC0NMBz1+6rrlLRuPiq0OvXWTZMzoCI4dEJ0jXSG
         /jzfIodGVxjrM8AEpG4leVW+n0xA0ZN7x3AtfK9ZdRxg+Ic4TUW6Q3ehA4/UuKSHVKfZ
         Xc5bAXNXKx7r8P7Z7AT1/5J3ccSKOQL7IKgBx6Crh8wO9hRNFEt3jqvpsk1MXslYz8s0
         5irqgq4xmTJJTB0SZcl+U4iNczGFJkd6/8eGhFSZZZu8J4Np4wrdhkOBP6EQbop/dWwT
         HRMpHgDtShPHVdRDhvc66l2sM2Kn14BReMM6CqW8BvkjBTqm42WPBADNLGoG5AfAz097
         45FQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=moucwpso;
       spf=pass (google.com: domain of ardb@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-47ae9c3f7d7si39831cf.1.2025.04.17.08.49.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Apr 2025 08:49:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 46CFCA4B4C0
	for <kasan-dev@googlegroups.com>; Thu, 17 Apr 2025 15:43:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3EF72C4CEEA
	for <kasan-dev@googlegroups.com>; Thu, 17 Apr 2025 15:49:26 +0000 (UTC)
Received: by mail-lf1-f50.google.com with SMTP id 2adb3069b0e04-54b1095625dso1170887e87.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Apr 2025 08:49:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUMvqnZSpM2pp6BWJk+puEi6TG9Y2nZvZ22gn780fnRMMXI0KPmxGoz8bTnL4OxgISINVWEUWHPam0=@googlegroups.com
X-Received: by 2002:a05:6512:3f2a:b0:54a:f76a:6f83 with SMTP id
 2adb3069b0e04-54d6deaf5ffmr8263e87.13.1744904964553; Thu, 17 Apr 2025
 08:49:24 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-7-glider@google.com>
 <cb6d98dc-49e9-2d3b-1acc-f208e4fd13fc@gmail.com> <CAG_fn=W8GDqYy_JV1F=YypD-6qR6vEqMuCi=DKfhdM-5=N3DdA@mail.gmail.com>
In-Reply-To: <CAG_fn=W8GDqYy_JV1F=YypD-6qR6vEqMuCi=DKfhdM-5=N3DdA@mail.gmail.com>
From: "'Ard Biesheuvel' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Apr 2025 17:49:13 +0200
X-Gmail-Original-Message-ID: <CAMj1kXEARA1KnD95RO=huLeQ-8nLsGixg0nOx01k4jgkb-2GYQ@mail.gmail.com>
X-Gm-Features: ATxdqUHMyy9TKm-n_7IAa_RrWRgIKhy0z62cRrwI2HOntcJj5Vopd3FWYI3r-Io
Message-ID: <CAMj1kXEARA1KnD95RO=huLeQ-8nLsGixg0nOx01k4jgkb-2GYQ@mail.gmail.com>
Subject: Re: [PATCH 6/7] x86: objtool: add support for R_X86_64_REX_GOTPCRELX
To: Alexander Potapenko <glider@google.com>
Cc: Uros Bizjak <ubizjak@gmail.com>, quic_jiangenj@quicinc.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, x86@kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=moucwpso;       spf=pass
 (google.com: domain of ardb@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Ard Biesheuvel <ardb@kernel.org>
Reply-To: Ard Biesheuvel <ardb@kernel.org>
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

Hi,

On Thu, 17 Apr 2025 at 17:37, Alexander Potapenko <glider@google.com> wrote=
:
>
> On Wed, Apr 16, 2025 at 4:21=E2=80=AFPM Uros Bizjak <ubizjak@gmail.com> w=
rote:
> >
> >
> >
> > On 16. 04. 25 10:54, Alexander Potapenko wrote:
> > > When compiling modules with -fsanitize-coverage=3Dtrace-pc-guard, Cla=
ng
> > > will emit R_X86_64_REX_GOTPCRELX relocations for the
> > > __start___sancov_guards and __stop___sancov_guards symbols. Although
> > > these relocations can be resolved within the same binary, they are le=
ft
> > > over by the linker because of the --emit-relocs flag.
> > >

Not sure what you mean here - --emit-relocs is not used for modules,
only for vmlinux.

> > > This patch makes it possible to resolve the R_X86_64_REX_GOTPCRELX
> > > relocations at runtime, as doing so does not require a .got section.

Why not? R_X86_64_REX_GOTPCRELX is *not* a PC32 reference to the
symbol, it is a PC32 reference to a 64-bit global variable that
contains the absolute address of the symbol.

> > > In addition, add a missing overflow check to R_X86_64_PC32/R_X86_64_P=
LT32.
> > >
> > > Cc: x86@kernel.org
> > > Signed-off-by: Alexander Potapenko <glider@google.com>
> > > ---
> > >   arch/x86/include/asm/elf.h      | 1 +
> > >   arch/x86/kernel/module.c        | 8 ++++++++
> > >   arch/x86/um/asm/elf.h           | 1 +
> > >   tools/objtool/arch/x86/decode.c | 1 +
> > >   4 files changed, 11 insertions(+)
> > >
> > > diff --git a/arch/x86/include/asm/elf.h b/arch/x86/include/asm/elf.h
> > > index 1fb83d47711f9..15d0438467e94 100644
> > > --- a/arch/x86/include/asm/elf.h
> > > +++ b/arch/x86/include/asm/elf.h
> > > @@ -63,6 +63,7 @@ typedef struct user_i387_struct elf_fpregset_t;
> > >   #define R_X86_64_8          14      /* Direct 8 bit sign extended  =
*/
> > >   #define R_X86_64_PC8                15      /* 8 bit sign extended =
pc relative */
> > >   #define R_X86_64_PC64               24      /* Place relative 64-bi=
t signed */
> > > +#define R_X86_64_REX_GOTPCRELX       42      /* R_X86_64_GOTPCREL wi=
th optimizations */
> > >

Why do you need this? arch/x86/kernel/module.c already has a reference
to R_X86_64_REX_GOTPCRELX so surely it is defined already somewhere.

> > >   /*
> > >    * These are used to set parameters in the core dumps.
> > > diff --git a/arch/x86/kernel/module.c b/arch/x86/kernel/module.c
> > > index 8984abd91c001..6c8b524bfbe3b 100644
> > > --- a/arch/x86/kernel/module.c
> > > +++ b/arch/x86/kernel/module.c
> > > @@ -133,6 +133,14 @@ static int __write_relocate_add(Elf64_Shdr *sech=
drs,
> > >               case R_X86_64_PC32:
> > >               case R_X86_64_PLT32:
> > >                       val -=3D (u64)loc;
> > > +                     if ((s64)val !=3D *(s32 *)&val)
> > > +                             goto overflow;
> > > +                     size =3D 4;
> > > +                     break;
> > > +             case R_X86_64_REX_GOTPCRELX:
> > > +                     val -=3D (u64)loc;
> > > +                     if ((s64)val !=3D *(s32 *)&val)
> > > +                             goto overflow;
> > >                       size =3D 4;
> > >                       break;
> >
> > These two cases are the same. You probably want:
> >
> >                 case R_X86_64_PC32:
> >                 case R_X86_64_PLT32:
> >                 case R_X86_64_REX_GOTPCRELX:
> >                         val -=3D (u64)loc;
> >                         if ((s64)val !=3D *(s32 *)&val)
> >                                 goto overflow;
> >                         size =3D 4;
> >                         break;
> >
>
> You are right, I overlooked this, as well as the other
> R_X86_64_REX_GOTPCRELX case above.

They are most definitely *not* the same.

> Ard, do you think we can relax the code handling __stack_chk_guard to
> accept every R_X86_64_REX_GOTPCRELX relocation?

Isn't it possible to discourage Clang from using
R_X86_64_REX_GOTPCRELX? Does -fdirect-access-external-data make any
difference here?

In any case, to resolve these relocations correctly, the reference
need to be made to point to global variables that carry the absolute
addresses of __start___sancov_guards and __stop___sancov_guards.
Ideally, these variables would be allocated and populated on the fly,
similar to how the linker allocates GOT entries at build time. But
this adds a lot of complexity for something that we don't want to see
in the first place.

Alternatively, the references could be relaxed, i.e., MOV converted to
LEA etc. The x86 ELF psABI describes how this is supposed to work for
R_X86_64_REX_GOTPCRELX but it involves rewriting the instructions so
it is a bit tedious.

But it would be much better to just fix the compiler.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AMj1kXEARA1KnD95RO%3DhuLeQ-8nLsGixg0nOx01k4jgkb-2GYQ%40mail.gmail.com.
