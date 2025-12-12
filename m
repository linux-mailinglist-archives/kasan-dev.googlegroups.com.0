Return-Path: <kasan-dev+bncBCU4TIPXUUFRB7WY6LEQMGQE6QV6QFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C000ECBA145
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Dec 2025 01:00:00 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-657537cef7csf2292145eaf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 16:00:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765583998; cv=pass;
        d=google.com; s=arc-20240605;
        b=ih1MTBqK0u1cyuHeBaUt+NMEWk5lQGmMgHs7M6LZ2FOWKAwoZtyeh8b0sxZUer0LD7
         I3TN4AgyqzymicrinJzP1JAJ2G0tyLJyp1jkNBmPWiJYwflsIyLygUC4EKB0GZTaou2V
         jYffNZ7oQPsQrNfOlympfrShQ5x7wnttu0HylBRdRexMZ/q1xgsGVccjAro2SSktX8Dm
         SoB0xVW7edNfc8BB3yP1n+mdF0WrlxpKFd8WSMnmdVxe+WcTAG0d33oxhd3JkvCw9ru5
         rcYDpcw4TwywSF+/ow3FHNMA1hN6DtCXcNy+dCLteUPwWDJ17y+T+Su4BhG3Tz47ssFu
         ODTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/q1dKENfVSdn5vW/LALcFHDfcf1I/J/dM+yRE1ehexc=;
        fh=z3/iGVy+QIpY29Kk4uYE7zgda32r0tHts79jN7W0AaA=;
        b=gN7XDhtdJwnTKuWf0OC/Lb2dnZ87eubQ1x10VE23hH/BYEP5kybt6PKOkIg/M7z3k2
         SyCBC66zy3JMzK/nmMLxW5w38j8NvMyR3PcLMO6jvyqRQaH9gzFgjGB2knoMVV3G/FI7
         vSbl3E8ACx6XMYWwntBvF21TJIfvkraVkNTruKzekNP1sBhcbNDxAd1nXVSNchTY6GVz
         YsIU7pKHz5GvC4RBRPAmp0VmZf6Ds9GEKAQER9CbAY0tVzd5JN/cxJ9aaGJ3H0SSaX/7
         DibqOjAw+cRPiOWruG+t4yMS2Eq0ZMX/CAd+NY1mlvJvGsx+4mypyEpoV4dBHjP1zQcG
         C4PA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ikJ+kiUo;
       spf=pass (google.com: domain of ardb@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765583998; x=1766188798; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/q1dKENfVSdn5vW/LALcFHDfcf1I/J/dM+yRE1ehexc=;
        b=Zoif8XtmgljuxbVMcxMCloFpRB353sHfCtt6Nn4u6K23lilJM4FAugIprXLKKcrSou
         FU+Va2k7fkvKVxZfaRuYPqcoNOiXyF+ynXJF6d5Kuro3FYLChnC2gbK1E6ZYZC3wD4Kn
         bA3YJmc9sOiqJHpt7OUC3/w/wKr68XV92o0t/+Lr3Hw8upJF8+SPXzaofRIOtLd9TuK/
         1PxorzAMb+pGrpam0mOfrlQTh6w1y2MFFH1Krp/KFyBPlj9CpMMXU6y/fetIqRTjvMry
         EqlUap1kog88b+1JVDDHR3vv/5PFb85+1zJ91xFB0lZtmde6XhXP+C73g2QqYipFd/q3
         vjHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765583998; x=1766188798;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/q1dKENfVSdn5vW/LALcFHDfcf1I/J/dM+yRE1ehexc=;
        b=GIdPrVBdxqMQieaLpPLnaNLFAitfVEz+bqTUTjtF+TUod9eK/DGmOJgCxU+dfauUGu
         TGSYtbKNXQoBmLfejIiwOS2KvXNICzY2luyEePFI+6uo6lq5pH3CbMpG/wSITpPDVHfq
         91s54TJCLaPT1NCKoDQGPY7ddQiR6sp4JMRZTfQ6mxsdfnViZAo/hcdg/NUYyPXjqlMk
         3M70oUaaimn9MpZO/yASzBZwh1VsS48F1mwAO+B5JdLIBUATeAN1h+ije9KC3n/tIq2d
         kWDNDrcOIeDk4KlawFRxlKIRv8++gzpbN8qCgsh0EPSXA3NTkzQiS4LRIB3TAsMwwdz7
         eU9Q==
X-Forwarded-Encrypted: i=2; AJvYcCUir+NPsf0AamzmHHgq5VHW8uPwg+WqYFCVGYqNaBBl32jSmwksRK6F6E2U3Amcm528/HY4Gw==@lfdr.de
X-Gm-Message-State: AOJu0YzFKp7BAy4IeT36+HhXiFn/B9hzId1e6Uu2fDRwsYP2DcUv3/fQ
	ZldvbDCm8CcEJnxztOm1eK7HzGhAW0ywJS09MA2jvZ/InQ3NyrK399cm
X-Google-Smtp-Source: AGHT+IGyXvkrASzx8d501QEjgiq298ZPUoZT5wY7/l3Ry5gubTcZw9CDQtZMU0HtT4fzrsfKEpl4YQ==
X-Received: by 2002:a05:6820:f003:b0:659:9a49:8ff6 with SMTP id 006d021491bc7-65b451bb1f3mr1954135eaf.35.1765583998502;
        Fri, 12 Dec 2025 15:59:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ6HT2XVqulVHDkyTqpY+uSFl83HxZa/G0vYwZ9zRAweg=="
Received: by 2002:a05:6870:e11:b0:3e8:9f07:3b9 with SMTP id
 586e51a60fabf-3f5f83ed669ls358205fac.0.-pod-prod-03-us; Fri, 12 Dec 2025
 15:59:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVT5f643D4ajx+kU3Vw40L2yJBzcfT5qYCIAlY9GABs6zeJamEMhGSulEgxck/4Pf73xue6ODE4DKc=@googlegroups.com
X-Received: by 2002:a05:6808:1925:b0:450:6eb0:3481 with SMTP id 5614622812f47-455ac960d1emr1644961b6e.43.1765583997668;
        Fri, 12 Dec 2025 15:59:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765583997; cv=none;
        d=google.com; s=arc-20240605;
        b=gqrMbGTkYLaKBM5foP5DKWO4UVllud3eVJADFp2BXVC7F7nV6BhrCZqvabrN71W3cf
         Kv9a4TMYVriFFg8D1F4iojB4NPABOzY8jxafAngx860m40SKdWxm4cYEkk/Oq1KYU9OV
         Co6eMQ1z2iL2hFNzH4DNPWCGVCRf22F7COsPZspT5oQS9qWlr7v8sZ3uu512pATA67PN
         SqjiO35dA3nFjOCgSNYxp/d23OCtp2I+eCvMuKoz3mYLBnGVmj7ftLUY6IwFhJ7Cg9bx
         6tuJAl17UxUGPMHbd+xV1Ac16Pf4ZANwPxraYQ4wGPMPikEuoyNItMRDcUoeRXzKQDfS
         TxWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=x1+3o7VwdcEAm4FpkjeENPemNdiZQPGWHFvr+YWl7g4=;
        fh=EwKyShivbFAXDfqKyLaAX/0AjMVdzaPxnuO/dTfBIcM=;
        b=CTA5QISiXGDigiSTYQVd72dKdlLvsjnrcSgztnkd7e4WugXP3pH/lNc+0/m6HydDOo
         +uq7b6Q5BKa7nbFzl+RSSVp1X0NEEOAWNDQ8DqrIcmc9ZIaHo4p26q4rMoFoNtzVz7fB
         RWyrNqvgUsTqwa8ShbEvIQvQW0jMC3zSbcUq4LCKiXjOiRGooIZBXagv7zlS6xfQDBnG
         zlW3f6l+1SlZ6+K4EtnfDWs6ylNQi2hJCmo0pB6NYFT/4z9UUIMyoupn834tc5DxDv6E
         zdtDtIl7xeFwvs+A3mI2gNC5w8OmkhPXaW7Bbh/41TacwHEkRagCKVMn0e6QD8wkMLdW
         tIxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ikJ+kiUo;
       spf=pass (google.com: domain of ardb@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-45598d0a911si211768b6e.6.2025.12.12.15.59.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Dec 2025 15:59:57 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id D579A4438E
	for <kasan-dev@googlegroups.com>; Fri, 12 Dec 2025 23:59:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BAD93C2BC87
	for <kasan-dev@googlegroups.com>; Fri, 12 Dec 2025 23:59:56 +0000 (UTC)
Received: by mail-pl1-f180.google.com with SMTP id d9443c01a7336-2956d816c10so20875555ad.1
        for <kasan-dev@googlegroups.com>; Fri, 12 Dec 2025 15:59:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXtlIKBNpMWxNqYlCDdKOGnV7YWejOaMzCI9Yh7ON2Uv1YgUleMEJox8EBzBtx+pITLSSd8YmSUn/s=@googlegroups.com
X-Received: by 2002:a17:902:fc4c:b0:295:1aa7:edbe with SMTP id
 d9443c01a7336-29f23ca188fmr37111015ad.41.1765583996150; Fri, 12 Dec 2025
 15:59:56 -0800 (PST)
MIME-Version: 1.0
References: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
 <CANpmjNNK6vRsyQ6SiD3Uy7fNim-wV+KWgbEokOaxbbd02Wa=ew@mail.gmail.com>
 <CANpmjNPizath=-ZUVTDFAdO_RZL1xqnx_o24nHA+3tJ4-FOg+Q@mail.gmail.com>
 <DET8WJDWPV86.MHVBO6ET98LT@google.com> <CANpmjNOpC2kGhfM8k=Y8VfLL0wSTkiOdkfU05tt1xTr+FuMjOQ@mail.gmail.com>
 <DETBVMG30SW8.WBM5TRGF59YZ@google.com> <CANpmjNNc9vRJbD2e5DPPR8SWNSYa=MqTzniARp4UWKBUEdhh_Q@mail.gmail.com>
In-Reply-To: <CANpmjNNc9vRJbD2e5DPPR8SWNSYa=MqTzniARp4UWKBUEdhh_Q@mail.gmail.com>
From: "'Ard Biesheuvel' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 13 Dec 2025 08:59:44 +0900
X-Gmail-Original-Message-ID: <CAMj1kXEE5kD217mY=A7vtbonvLYPN_u5xHMWrr01ec4vvP++4Q@mail.gmail.com>
X-Gm-Features: AQt7F2pV6AiichlcGUp-PKP6XxW3SngZWr029OCwlPj09y9ZFKMh8LrIP1cKnU4
Message-ID: <CAMj1kXEE5kD217mY=A7vtbonvLYPN_u5xHMWrr01ec4vvP++4Q@mail.gmail.com>
Subject: Re: [PATCH 0/2] Noinstr fixes for K[CA]SAN with GCOV
To: Marco Elver <elver@google.com>, Kees Cook <kees@kernel.org>
Cc: Brendan Jackman <jackmanb@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ikJ+kiUo;       spf=pass
 (google.com: domain of ardb@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

(cc Kees)

On Sat, 13 Dec 2025 at 01:11, Marco Elver <elver@google.com> wrote:
>
> On Tue, 9 Dec 2025 at 03:25, Brendan Jackman <jackmanb@google.com> wrote:
> > On Tue Dec 9, 2025 at 12:52 AM UTC, Marco Elver wrote:
> > > On Tue, 9 Dec 2025 at 01:05, Brendan Jackman <jackmanb@google.com> wr=
ote:
> > >> On Mon Dec 8, 2025 at 11:12 AM UTC, Marco Elver wrote:
> > >> > On Mon, 8 Dec 2025 at 10:37, Marco Elver <elver@google.com> wrote:
> > >> >>
> > >> >> On Mon, 8 Dec 2025 at 02:35, Brendan Jackman <jackmanb@google.com=
> wrote:
> > >> >> >
> > >> >> > Details:
> > >> >> >
> > >> >> >  - =E2=9D=AF=E2=9D=AF  clang --version
> > >> >> >    Debian clang version 19.1.7 (3+build5)
> > >> >> >    Target: x86_64-pc-linux-gnu
> > >> >> >    Thread model: posix
> > >> >> >    InstalledDir: /usr/lib/llvm-19/bin
> > >> >> >
> > >> >> >  - Kernel config:
> > >> >> >
> > >> >> >    https://gist.githubusercontent.com/bjackman/bbfdf4ec2e1dfd0e=
18657174f0537e2c/raw/a88dcc6567d14c69445e7928a7d5dfc23ca9f619/gistfile0.txt
> > >> >> >
> > >> >> > Note I also get this error:
> > >> >> >
> > >> >> > vmlinux.o: warning: objtool: set_ftrace_ops_ro+0x3b: relocation=
 to !ENDBR: machine_kexec_prepare+0x810
> > >> >> >
> > >> >> > That one's a total mystery to me. I guess it's better to "fix" =
the SEV
> > >> >> > one independently rather than waiting until I know how to fix t=
hem both.
> > >> >> >
> > >> >> > Note I also mentioned other similar errors in [0]. Those errors=
 don't
> > >> >> > exist in Linus' master and I didn't note down where I saw them.=
 Either
> > >> >> > they have since been fixed, or I observed them in Google's inte=
rnal
> > >> >> > codebase where they were instroduced downstream.
> > >> >> >
> > >> >> > This is a successor to [1] but I haven't called it a v2 because=
 it's a
> > >> >> > totally different solution. Thanks to Ard for the guidance and
> > >> >> > corrections.
> > >> >> >
> > >> >> > [0] https://lore.kernel.org/all/DERNCQGNRITE.139O331ACPKZ9@goog=
le.com/
> > >> >> >
> > >> >> > [1] https://lore.kernel.org/all/20251117-b4-sev-gcov-objtool-v1=
-1-54f7790d54df@google.com/
> > >> >>
> > >> >> Why is [1] not the right solution?
> > >> >> The problem is we have lots of "inline" functions, and any one of=
 them
> > >> >> could cause problems in future.
> > >> >
> > >> > Perhaps I should qualify: lots of *small* inline functions, includ=
ing
> > >> > those stubs.
> > >> >
> > >> >> I don't mind turning "inline" into "__always_inline", but it seem=
s
> > >> >> we're playing whack-a-mole here, and just disabling GCOV entirely
> > >> >> would make this noinstr.c file more robust.
> > >> >
> > >> > To elaborate: `UBSAN_SANITIZE_noinstr.o :=3D n` and
> > >> > `K{A,C}SAN_SANITIZE_noinstr.o :=3D n` is already set on this file.
> > >> > Perhaps adding __always_inline to the stub functions here will be
> > >> > enough today, but might no longer be in future.
> > >>
> > >> Well you can also see it the other way around: disabling GCOV_PROFIL=
E
> > >> might be enough today, but as soon as some other noinstr disables
> > >> __SANITIZE_ADDRESS__ and expects to be able to call instrumented
> > >> helpers, that code will be broken too.
> > >
> > > This itself is a contradiction: a `noinstr` function should not call
> > > instrumented helpers. Normally this all works due to the compiler's
> > > function attributes working as intended for the compiler-inserted
> > > instrumentation, but for explicitly inserted instrumentation it's
> > > obviously not. In otherwise instrumented files with few (not all)
> > > `noinstr` functions, making the stub functions `__always_inline` will
> > > not work, because the preprocessor is applied globally not per
> > > function. In the past, I recall the underlying implementation being
> > > used of e.g. the bitops (arch_foo... or __foo) in `noinstr` functions
> > > to solve that.
> >
> > Sorry I dropped an important word here, I meant to say other noinstr
> > _files_. I.e. anything else similar to SEV's noinstr.c that is doing
> > noinstr at the file level.
>
> Someone at LPC (I couldn't make out who due to technical difficulties)
> mentioned that calling explicitly instrumented helpers from noinstr
> functions is a general problem.
>

That was me.

> After that I sat down and finally got around to implement the builtin
> that should solve this once and for all, regardless of where it's
> called: https://github.com/llvm/llvm-project/pull/172030
> What this will allow us to do is to remove the
> "K[AC]SAN_SANITIZE_noinstr.o :=3D n" lines from the Makefile, and purely
> rely on the noinstr attribute, even in the presence of explicit
> instrumentation calls.
>

Excellent! Thanks for the quick fix. Happy to test and/or look into
the kernel side of this once this lands.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AMj1kXEE5kD217mY%3DA7vtbonvLYPN_u5xHMWrr01ec4vvP%2B%2B4Q%40mail.gmail.com.
