Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTGAQTAAMGQEK6B3TJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 97FF2A921C3
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 17:37:49 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-47699e92ab0sf17050881cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 08:37:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744904268; cv=pass;
        d=google.com; s=arc-20240605;
        b=JXB1fT031EsN/9L/ZitsGOW8ig4s4iO0+asffCEzZR9Gt57SoTbGVhsvQJUZst+btx
         67dSDMZemt9Z+V1CAse4P98/3sYWGLQXC2heGzjRUMicm3FUWOnJ4MyRcVhvzVkTp9yI
         +Q1rEF/XtYrWb4/M+I5VvSfMBYAAcM/gR04KFIOkeDrO96uDTG2IlsMYzDYxJPRd7VpF
         iVZutIIbC04jVrDA9qY68LnRIKANYoSI6XRYbEwxx0KvOTQtpHLTCnUjmT4eyC/XpBWj
         wRCfO2FP6K+DZix34Vlv5C8v4FpmtwI9rM3MSUyq2yKPBCYwQyiLqXmJKAE0WO8L6I2T
         or1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EMu5CHNKj0FsxAIK45XWP+YQ6kQdrPkxD45pMfGa9i4=;
        fh=2cNvRPdX1fR7jP72TrcDk0cGSCZZw8oNIadtJqW7v58=;
        b=atPGlf+Ff0hJE7mdjs5832xE09+wqe0FKLfTN+uWVFT+DevjMQTBXcgF6M2/Bq0kOi
         UPmaCbJTrj7MP9y1nm6ekmR7x46OXV9JSW0O7wgbbL1Rqv7v9Nd3SqZgllcElWG0oogt
         k6CEb6+JCsItJyHYztKSO7yn4w8MztHKtWbmnokkwA+qeFo8jMCe3c1qah4gN9XkghYt
         9Wd+XTSbgMjr0/6SuiuWAo5HLYOny9O+dNxC4ZA0Tw8QXZ0s7S9smPH8Mo2yH6XDUz4t
         UG/lmbQFB5588OZdN0jx/CvtSVT9pxB8uXzRzrXB8+NLbukXoC1J+zVdFfMN9F8MnoQE
         JjQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="1B6H/ovL";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744904268; x=1745509068; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EMu5CHNKj0FsxAIK45XWP+YQ6kQdrPkxD45pMfGa9i4=;
        b=uLa5DY1Rni3rShwT43KTj06vqA1+wiRyygq7eusuhIL00dIdj76TquXqG9sNhknVl3
         vxsZbneiyq9Dsq7nUD10pvTOS0zubSvYzirkdoSmGlatJ/D9FnGacRurPLtwFK2yOAlw
         h56xZKNyw650SsUXsSJv5HOGRdAXvPp9LtduCI1ShHKFmp0JPSNY+BlifWZfZ3Mp2Ndm
         1oGFD7tMXCBLF50Dm5GPYcYLDop4Xp0+2NonMoyhzbkMnC8JyivnnY4vDoKKDd7TIH0a
         7z1m4bStCL3ZfCbhoYZAf6fvh4hl8TYSF4gWFL8+ajFNRklEcZZ6wyJk6a4PQ3xsoEdi
         yhZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744904268; x=1745509068;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=EMu5CHNKj0FsxAIK45XWP+YQ6kQdrPkxD45pMfGa9i4=;
        b=tZ6h8uMm1s/U1P/Able7SyJQaDpWMcULYynFg3zAkYPVTDMJckaPe/qu8M+u97Sih+
         OdqlqvE+jpOsGg/NkPkulCc0YjwlkgbmesWMyouq1CBSNteO66LW4ZS7u+sl51wTZJco
         h+MBF1KfKTQyEzHMIMz2jirznoActlYZR2UqsYl3c9LGOfunfXeuwPogRLQ5l0F12enK
         9OemoacBxPGKmxiPdU+0whujBmzVjd1nnq7cJT4iMZRT6bR6zcYP3BpSzaojQFB7wzjD
         qvi4HGgni2ZQ+eeLDdKb4j99/M+jZV3s45LF1LD1rdek2KyZNBeSvBnMmnM1mpF2MPqb
         oShw==
X-Forwarded-Encrypted: i=2; AJvYcCUS7kc0gGdUgec3hG8DYOg/+YEHG90ESQiirZGr2Rv57b1OWa7SmGfLa7xRpEvsSt+UCCcWrA==@lfdr.de
X-Gm-Message-State: AOJu0YzdvVqWROfwrGP94hMNqz68RsBk6ttyFmzPDwuiQt7ttr6YWtFg
	V2OE3oAVyxencDNzcfx92jyzwNHSXD/3J2tO5XFvbk4VZJA4PmLK
X-Google-Smtp-Source: AGHT+IEGLYv8K+M4LXUrWaTmGpegUHMAO5S5xwjsVis3m6+yce+PryVkaNySuqs5ExtTrDNPk+Lubg==
X-Received: by 2002:a05:622a:178b:b0:476:8e3e:2da4 with SMTP id d75a77b69052e-47ad8115fc2mr99963031cf.38.1744904268254;
        Thu, 17 Apr 2025 08:37:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALIB7kI5Qbm+TiVxDZxXyzgZKChVMXo4r+xhVARQUt73g==
Received: by 2002:a05:622a:28d:b0:476:69c5:ff0b with SMTP id
 d75a77b69052e-47addc6d3bcls22903961cf.1.-pod-prod-09-us; Thu, 17 Apr 2025
 08:37:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpLoDZD4+kuO5Sv7HxqIwjBp/r2j0FXHlgKHDsg7XYe7sFVO6Y/2ElBSrCI2LAxKcZjLAOPtmP9wo=@googlegroups.com
X-Received: by 2002:a05:622a:1354:b0:477:e78:5a14 with SMTP id d75a77b69052e-47ad8097c53mr97028351cf.3.1744904266745;
        Thu, 17 Apr 2025 08:37:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744904266; cv=none;
        d=google.com; s=arc-20240605;
        b=lJyhKzZuPHce7wB5YRxVZz7TfnFSIo8Jsl4+O8x4mW7qLkdNMFYigLY5kOyCWmoPfa
         +RQJzkwo2SRJEc0TsPf/SAcwmdWvJFnGmgzUs7JcuvPnn2VqdOsbHTnEC30iOuzTMF4i
         Zh3Ram5PTAAXmfgyySLcbrZv77Bep+Z+y6OrLyV0LpqrGNrqPin/tPzLrNIbSc1CdVOa
         KlwfjcxhyR3kmmIUIXjVKbim563pAL026gEIv/h0OMhh4nUAMjrsFEiPpiL/cgYNVaJl
         9zsaBLWPW8/ydBlekQrWUAZGP9yjG3mVC3amQyDL3RTB3yZq8Yvs/z7AIoVg+fMTZ8GH
         P1pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1MyAnJTr6eQCZG3FgtbZ7+3YB/W35AyW1Th3bTHG7vk=;
        fh=GiLZEuXiLuoZmrdEW/ynaQWnLATFrou3twlAP79xmXU=;
        b=QWzHAQEVYHHDrLDfFHpBiN+ldykyMVLBgVUek/U5A1AaXBODckQ21nlVXwRMUlRLau
         4XHpsdsyV+i2zPDixUgwWi8wMU244YLKH6dHK5HfY63RvA2837tGn7+Pb1TwK9UHtKG1
         HYehBqXx79sezl7m8YcHtt0oPZsE0LZ2trJSexEPawYyW68VdagOoQ9c0f8eFQ5makds
         vT7lOCfV2x56psH/lBEmv3laN+ZEbk3ZSAsuDfirsPDCxavtOg0bsE7O4ZiOaVb5bTSM
         bVTryPMpZm4tMCQW6qXy6jBcK1/s3mEmeXPcB4/mlzipuxcfFFDVdqjJjnFT5MtKqstc
         wBVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="1B6H/ovL";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-47ae9d14892si28131cf.5.2025.04.17.08.37.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Apr 2025 08:37:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id 6a1803df08f44-6ecfc2cb1aaso9119256d6.3
        for <kasan-dev@googlegroups.com>; Thu, 17 Apr 2025 08:37:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWAXdTVVTlyujE24Dp7PKuPd18N9JIHrea0uBXNlVj2cOhqB+AcDn2G8Wq09j2yiE0TDFqVhXc/9QE=@googlegroups.com
X-Gm-Gg: ASbGnct46knq339n2EWnftmEGWpa1y9Jyi7W6LGmDTsIkgYOm9wKvyOPqENielPjQuV
	z4jalQAFvRX6UtZRdfS+LZOrY8sUiwmbNO0fDV86ys4GP/EHSTvcq//8zuRQgzqJb1ecX07vo/c
	R1Q3z2dY4or0DBEftFRbZ8pmUszVJ++vGNpTuXVCwHEx00lhbp8TTb
X-Received: by 2002:a05:6214:226c:b0:6e8:ed7f:1a79 with SMTP id
 6a1803df08f44-6f2b304be07mr111127706d6.32.1744904266134; Thu, 17 Apr 2025
 08:37:46 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-7-glider@google.com>
 <cb6d98dc-49e9-2d3b-1acc-f208e4fd13fc@gmail.com>
In-Reply-To: <cb6d98dc-49e9-2d3b-1acc-f208e4fd13fc@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Apr 2025 17:37:09 +0200
X-Gm-Features: ATxdqUF6tyoL-d94GB69k__O5KRs0S2IIOkhLY92J9CAUkV5rKaE2SdyZimOJzY
Message-ID: <CAG_fn=W8GDqYy_JV1F=YypD-6qR6vEqMuCi=DKfhdM-5=N3DdA@mail.gmail.com>
Subject: Re: [PATCH 6/7] x86: objtool: add support for R_X86_64_REX_GOTPCRELX
To: Uros Bizjak <ubizjak@gmail.com>, Ard Biesheuvel <ardb@kernel.org>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="1B6H/ovL";       spf=pass
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

On Wed, Apr 16, 2025 at 4:21=E2=80=AFPM Uros Bizjak <ubizjak@gmail.com> wro=
te:
>
>
>
> On 16. 04. 25 10:54, Alexander Potapenko wrote:
> > When compiling modules with -fsanitize-coverage=3Dtrace-pc-guard, Clang
> > will emit R_X86_64_REX_GOTPCRELX relocations for the
> > __start___sancov_guards and __stop___sancov_guards symbols. Although
> > these relocations can be resolved within the same binary, they are left
> > over by the linker because of the --emit-relocs flag.
> >
> > This patch makes it possible to resolve the R_X86_64_REX_GOTPCRELX
> > relocations at runtime, as doing so does not require a .got section.
> > In addition, add a missing overflow check to R_X86_64_PC32/R_X86_64_PLT=
32.
> >
> > Cc: x86@kernel.org
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> >   arch/x86/include/asm/elf.h      | 1 +
> >   arch/x86/kernel/module.c        | 8 ++++++++
> >   arch/x86/um/asm/elf.h           | 1 +
> >   tools/objtool/arch/x86/decode.c | 1 +
> >   4 files changed, 11 insertions(+)
> >
> > diff --git a/arch/x86/include/asm/elf.h b/arch/x86/include/asm/elf.h
> > index 1fb83d47711f9..15d0438467e94 100644
> > --- a/arch/x86/include/asm/elf.h
> > +++ b/arch/x86/include/asm/elf.h
> > @@ -63,6 +63,7 @@ typedef struct user_i387_struct elf_fpregset_t;
> >   #define R_X86_64_8          14      /* Direct 8 bit sign extended  */
> >   #define R_X86_64_PC8                15      /* 8 bit sign extended pc=
 relative */
> >   #define R_X86_64_PC64               24      /* Place relative 64-bit =
signed */
> > +#define R_X86_64_REX_GOTPCRELX       42      /* R_X86_64_GOTPCREL with=
 optimizations */
> >
> >   /*
> >    * These are used to set parameters in the core dumps.
> > diff --git a/arch/x86/kernel/module.c b/arch/x86/kernel/module.c
> > index 8984abd91c001..6c8b524bfbe3b 100644
> > --- a/arch/x86/kernel/module.c
> > +++ b/arch/x86/kernel/module.c
> > @@ -133,6 +133,14 @@ static int __write_relocate_add(Elf64_Shdr *sechdr=
s,
> >               case R_X86_64_PC32:
> >               case R_X86_64_PLT32:
> >                       val -=3D (u64)loc;
> > +                     if ((s64)val !=3D *(s32 *)&val)
> > +                             goto overflow;
> > +                     size =3D 4;
> > +                     break;
> > +             case R_X86_64_REX_GOTPCRELX:
> > +                     val -=3D (u64)loc;
> > +                     if ((s64)val !=3D *(s32 *)&val)
> > +                             goto overflow;
> >                       size =3D 4;
> >                       break;
>
> These two cases are the same. You probably want:
>
>                 case R_X86_64_PC32:
>                 case R_X86_64_PLT32:
>                 case R_X86_64_REX_GOTPCRELX:
>                         val -=3D (u64)loc;
>                         if ((s64)val !=3D *(s32 *)&val)
>                                 goto overflow;
>                         size =3D 4;
>                         break;
>

You are right, I overlooked this, as well as the other
R_X86_64_REX_GOTPCRELX case above.
Ard, do you think we can relax the code handling __stack_chk_guard to
accept every R_X86_64_REX_GOTPCRELX relocation?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DW8GDqYy_JV1F%3DYypD-6qR6vEqMuCi%3DDKfhdM-5%3DN3DdA%40mail.gmail.com=
.
