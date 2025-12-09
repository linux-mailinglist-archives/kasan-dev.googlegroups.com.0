Return-Path: <kasan-dev+bncBC7OBJGL2MHBB47F3XEQMGQEW4AI2OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 193C9CAE909
	for <lists+kasan-dev@lfdr.de>; Tue, 09 Dec 2025 01:53:09 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4ed6855557asf122633881cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Dec 2025 16:53:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765241587; cv=pass;
        d=google.com; s=arc-20240605;
        b=LbhzrhTgC0XjZAcZ2/bq4DWvnxL2+m8itgfMH5qvaI2BNiwkSD7GT4K/9tiUQ7hb4S
         7LBc6o7kNEnQV2EibYDgMVRCk5Yla7/arri5eRV/aaBfoNOQks8ImNTMRMIqsa3yRI83
         gJSsZO98U+BXR5J3OooXayASJmDFp7nw3teLJ37FdBertbRzLVNjLLppyamDXI5dgzIo
         EFatLeE1cM8tijtTaD7pT6IqoMpfAEWc0oaqjlwQFYaNpH1Cz/xOuaBbGJguIl5cF2m6
         7MLTWsSDPBn7mW/oOOVVtc/rZJsN8E8UehXbfFkZ4MZtgVvpG4DMteO+K6Tur4NjVjbE
         ra5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lgQ5bO6sefZfm+DCcQbEnlBtK7lGMapq393JUNm7vMs=;
        fh=4ERIiUqGK6wQ+CtrORRfpT0MUVjjWkctduB4K7mZ1WI=;
        b=S4mf3VU4Qo8YaLHUBxJGcDbayIrm2OpxMtdeEmJ0VdjGnVDyyHzgq4iNkDO1GWi+Ei
         UPoe2EzBxVcHe9uieSZk1iripunUo4saVTznh+jUyKLEhdBkr/VKQQ3GolNU/+87fVwE
         0E8t04Vt+TE0xMBQ4jzrM9KbclyhpjGmwl4uyc5FRwTPtyDeq7/sGyzOIBA/g8q0Stxr
         dYxWHH5gfQj9On2tNSWYI4eCDlSVwIdTYspaMSFV1cbvwM1FwvTc38qiN+UEmY9daqTl
         /JBCQDqndlYC5RFyFzKK4mQ96XPUEIKYA7mDxVgU9qgj2tJskcPhC0hdQh7BsuwQCa0I
         WWmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zbUzdzl2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::122a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765241587; x=1765846387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lgQ5bO6sefZfm+DCcQbEnlBtK7lGMapq393JUNm7vMs=;
        b=lJZkAMx0dtODsFMaqEonxK8b17Y91x+62lC66V8igauct+lcIe/Bye3ClJcqsF8OG1
         ncUZ/1piNCIglG+CoKA0YY11SCOXESEH5cRabNhFmoooANQcx6Xm/Lz6aLu900oKPZuF
         LDG3jVanS9oPP1a7RkJLcCZ++/ovlNUPYgexWJfQ1YPJ3UhMxmg9avPU0viHA6KMOdOX
         2WimYoJRhp/iWfjlH5zebtW8XWxufnQXzu7M7Shd6DbMOJza7rgfv0LigbMKbbHPIUlQ
         l/sgjO4N9L9zKajETLYX7hfF4XQoxVI22Q5BFdA6jTURS4ssLrADtnVJhOaTG8t0CWdJ
         8V5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765241587; x=1765846387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=lgQ5bO6sefZfm+DCcQbEnlBtK7lGMapq393JUNm7vMs=;
        b=u/vORVPL/6SIuI+m2rzImoSwz5ms7kLp0oS2Y/DwVty9GUHbSXh0fPmvo5CpxlhSn4
         Wb/1y4LuLcW7ugoiCByt5A/Wc3PZdlCsUDD24XCseY3PfnnrlaXb9Ruk8xkd/zZWAKKi
         8U22vdoXPpQ7SZUJbCEerZJYpaJp0iWzotQKkFSG3qVTCirBevmg0vjoBO12guYSlGrd
         hPDC4bmISkFWIvQD1rkT14gdLzCcgSW/XyjkzYDmQkV6PotSdcYRAqSF1x5E9kgz7S0T
         JEfd/Fcd6ZtZm8EzYUKkYLwUgPtFYhRjSys3NxGQWCVg2FTfgXRcVO4hw9fpmce+dTNA
         Mqrw==
X-Forwarded-Encrypted: i=2; AJvYcCUme3RJPZG0ohkGPUc4itbGPcw1JLyF0EEJ8jPSBtg91sfOA+dQnXcWLHfr+ZR+6hke4c4cnw==@lfdr.de
X-Gm-Message-State: AOJu0YyYdWK8XVBe4Vi6JPAAUoI9QtsNyDnntNwlkIWxk3LkiaTDeBRL
	IqkzpCr6slIxSRD3MXuhjjXV8Tm0FIsRUAIy3vJ9KBhyUZip5uUfAfHC
X-Google-Smtp-Source: AGHT+IFIYP0X3b2Te6ndY3FAgnmFjWJ75aId0I1ZnK3gteyXlHp1+McIQ0n5Ogza2wHBCtigBwJcAA==
X-Received: by 2002:a05:622a:5585:b0:4ed:ba4c:bda8 with SMTP id d75a77b69052e-4f1a41b21e7mr19524621cf.18.1765241587364;
        Mon, 08 Dec 2025 16:53:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZpYcP/tfkx/+80q5ijDvjVn0qcytv4xmVP2aXWLEQVqg=="
Received: by 2002:a05:622a:5c13:b0:4f0:1d7c:6af2 with SMTP id
 d75a77b69052e-4f01d7c77cdls50836451cf.0.-pod-prod-00-us-canary; Mon, 08 Dec
 2025 16:53:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUPbwjBrVCgXp/jV9AXO38UuOU9WqYGE1PhGBIzxfzd8rIlVNx87ZOoeteTlbjfZPRvnVgt5ewdmHE=@googlegroups.com
X-Received: by 2002:a05:620a:294f:b0:89f:5057:9753 with SMTP id af79cd13be357-8b98bbde5d7mr197706685a.41.1765241585984;
        Mon, 08 Dec 2025 16:53:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765241585; cv=none;
        d=google.com; s=arc-20240605;
        b=OmvFhYXbCtHjMQYHsr7yppEIXHvMZNcLpDp/0Ka36I41EdJNjBSoUoM44o1jI/ds2H
         GKstPNMhkqkP3hB+LLyS8xAZQp+RuzJIa2CPXqWGuI2mrWvK2P+LZaXZtDBhr9E8NYAr
         njS306StFlvziC49tV0gnqLNyBri55jzv8vLc9PMfgwQRDn0++2ZCloFkRtrwVZI19j1
         xMtx06utWadqy9lHfVvi1fdLhKZyWPifGWBDGyRqVv8Pg4UiHe1oi4BCN1vMeW0UkusW
         eLTyEZGk3OX+BwiPH3IdblRMVyYaDSUjLrEKuKm7wGQzMcAcfArfPkRU82B4nUnZEs6q
         X2fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OHtLVyHhg3V0rZCxrODXbJ/hrDxeNodJiFxd+ycznTk=;
        fh=DNHhB0XAaQ582Wmj2TCq1sWdcBxXH7xnOKKS/sbRaf0=;
        b=QYHF80a2SM/kIgVwhnkNYNynw3zzAKmpNqGPY5GVWKQE0pyP2xFMeZGcV91ZJpM5Q7
         eYQRiwaOhqFYMQrX+qzZd+izXk6WELR7BKTNDkRWD0RVe3oTQPnAj4uKMcQcAtD95gAc
         Tdg/5NrONxoNouS71paDkbE0rwuw0DiKyyA6dh/b2J3UxKlK8TCliZnjkuYzkDP0Ykse
         Fl+jnz7Uo4pNxaJbytzCx4v70XM7M2m/xf0sjhkEB+aB5RPNxNGbDPFwqHVz27Ckmpzg
         Bu2ayPIoaypZWtClqUu62G69snl6Acxu9lrGTBNRA0SC7UnMX9NlqvOpl4hZmVjYOiOA
         isFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zbUzdzl2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::122a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x122a.google.com (mail-dl1-x122a.google.com. [2607:f8b0:4864:20::122a])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8b627aec0cbsi56713985a.9.2025.12.08.16.53.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Dec 2025 16:53:05 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::122a as permitted sender) client-ip=2607:f8b0:4864:20::122a;
Received: by mail-dl1-x122a.google.com with SMTP id a92af1059eb24-11beb0a7bd6so6852821c88.1
        for <kasan-dev@googlegroups.com>; Mon, 08 Dec 2025 16:53:05 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVVSwPbUaOg8Kc5InqPgJAgr+lE0egcUcs2rk7Vid2NwJyX5ekdDhe0P9gwlwdcoBFDz1CMoGHzd9E=@googlegroups.com
X-Gm-Gg: ASbGnctZ/hceiiPkPh5d0LrW/T8sgWZtNp5LZORWUMHQWOAlNpjQuHYIMsRCsdHvXfA
	ZBzWS8/pqkI4Gugf4VryMNpx8S1jA/bVfQj3SC1njFIvIiZ7ZhJVBDh/golBanTmGPP2iryo2P5
	Lu+kB8/St86vPcxTeX9Nj9ZoJzluhJKgWxSq/Tohww6ZmgbTF9QVYQ0p5KOLqyfT1zKlMsPyMzg
	vvUEFJ4fESs0ciPEqAuTz/JBv5MEMa8vUNRenDaqIob2plCOqRa8ARBOcPCfI9uJWx2aKOl4GZI
	AKFFnSeHIBeBIKD2zOnl5s6VTBULyI/jpl7iRw==
X-Received: by 2002:a05:7022:e14:b0:11b:3eb7:f9d7 with SMTP id
 a92af1059eb24-11f219143a2mr1096456c88.14.1765241584580; Mon, 08 Dec 2025
 16:53:04 -0800 (PST)
MIME-Version: 1.0
References: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
 <CANpmjNNK6vRsyQ6SiD3Uy7fNim-wV+KWgbEokOaxbbd02Wa=ew@mail.gmail.com>
 <CANpmjNPizath=-ZUVTDFAdO_RZL1xqnx_o24nHA+3tJ4-FOg+Q@mail.gmail.com> <DET8WJDWPV86.MHVBO6ET98LT@google.com>
In-Reply-To: <DET8WJDWPV86.MHVBO6ET98LT@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Dec 2025 01:52:28 +0100
X-Gm-Features: AQt7F2rHhSBHxB2x0aGWIzEPzWtAKpDPlFegbOOFvwm7xL52fpEzJ-B0V5xZKGA
Message-ID: <CANpmjNOpC2kGhfM8k=Y8VfLL0wSTkiOdkfU05tt1xTr+FuMjOQ@mail.gmail.com>
Subject: Re: [PATCH 0/2] Noinstr fixes for K[CA]SAN with GCOV
To: Brendan Jackman <jackmanb@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel <ardb@kernel.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zbUzdzl2;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::122a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 9 Dec 2025 at 01:05, Brendan Jackman <jackmanb@google.com> wrote:
>
> On Mon Dec 8, 2025 at 11:12 AM UTC, Marco Elver wrote:
> > On Mon, 8 Dec 2025 at 10:37, Marco Elver <elver@google.com> wrote:
> >>
> >> On Mon, 8 Dec 2025 at 02:35, Brendan Jackman <jackmanb@google.com> wro=
te:
> >> >
> >> > Details:
> >> >
> >> >  - =E2=9D=AF=E2=9D=AF  clang --version
> >> >    Debian clang version 19.1.7 (3+build5)
> >> >    Target: x86_64-pc-linux-gnu
> >> >    Thread model: posix
> >> >    InstalledDir: /usr/lib/llvm-19/bin
> >> >
> >> >  - Kernel config:
> >> >
> >> >    https://gist.githubusercontent.com/bjackman/bbfdf4ec2e1dfd0e18657=
174f0537e2c/raw/a88dcc6567d14c69445e7928a7d5dfc23ca9f619/gistfile0.txt
> >> >
> >> > Note I also get this error:
> >> >
> >> > vmlinux.o: warning: objtool: set_ftrace_ops_ro+0x3b: relocation to !=
ENDBR: machine_kexec_prepare+0x810
> >> >
> >> > That one's a total mystery to me. I guess it's better to "fix" the S=
EV
> >> > one independently rather than waiting until I know how to fix them b=
oth.
> >> >
> >> > Note I also mentioned other similar errors in [0]. Those errors don'=
t
> >> > exist in Linus' master and I didn't note down where I saw them. Eith=
er
> >> > they have since been fixed, or I observed them in Google's internal
> >> > codebase where they were instroduced downstream.
> >> >
> >> > This is a successor to [1] but I haven't called it a v2 because it's=
 a
> >> > totally different solution. Thanks to Ard for the guidance and
> >> > corrections.
> >> >
> >> > [0] https://lore.kernel.org/all/DERNCQGNRITE.139O331ACPKZ9@google.co=
m/
> >> >
> >> > [1] https://lore.kernel.org/all/20251117-b4-sev-gcov-objtool-v1-1-54=
f7790d54df@google.com/
> >>
> >> Why is [1] not the right solution?
> >> The problem is we have lots of "inline" functions, and any one of them
> >> could cause problems in future.
> >
> > Perhaps I should qualify: lots of *small* inline functions, including
> > those stubs.
> >
> >> I don't mind turning "inline" into "__always_inline", but it seems
> >> we're playing whack-a-mole here, and just disabling GCOV entirely
> >> would make this noinstr.c file more robust.
> >
> > To elaborate: `UBSAN_SANITIZE_noinstr.o :=3D n` and
> > `K{A,C}SAN_SANITIZE_noinstr.o :=3D n` is already set on this file.
> > Perhaps adding __always_inline to the stub functions here will be
> > enough today, but might no longer be in future.
>
> Well you can also see it the other way around: disabling GCOV_PROFILE
> might be enough today, but as soon as some other noinstr disables
> __SANITIZE_ADDRESS__ and expects to be able to call instrumented
> helpers, that code will be broken too.

This itself is a contradiction: a `noinstr` function should not call
instrumented helpers. Normally this all works due to the compiler's
function attributes working as intended for the compiler-inserted
instrumentation, but for explicitly inserted instrumentation it's
obviously not. In otherwise instrumented files with few (not all)
`noinstr` functions, making the stub functions `__always_inline` will
not work, because the preprocessor is applied globally not per
function. In the past, I recall the underlying implementation being
used of e.g. the bitops (arch_foo... or __foo) in `noinstr` functions
to solve that.

The other hammer we have is K[ACM]SAN_SANITIZE_foo.o :=3D n,
GCOV_PROFILE_foo.o :=3D n, and KCOV_INSTRUMENT_foo.o :=3D n.

> I don't think we can avoid whack-a-mole here. In fact I think the whole
> noinstr thing is an inevitable game of whack-a-mole unless we can get a
> static anlyzer to find violations at the source level. I suspect there
> are loads of violations in the tree that only show up in objtool if you
> build in weird configs on a full moon.
>
> One argument in favour of `GCOV_PROFILE_noinstr.o :=3D n` would be: "this
> is non-instrumentable code, the issue here is that it is getting
> instrumented, so the fix is surely to stop instrumenting it". But, I
> don't think that's really true, the issue is not with the
> instrumentation but with the out-of-lining. Which highlights another
> point: a sufficiently annoying compiler could out-of-line these
> stub functions even without GCOV, right?

This would be a compiler bug in my book. Without instrumentation a
"static inline" function with nothing in it not being inlined is an
optimization bug. But those things get caught because it'd have made
someone's system slow.

> Still, despite my long-winded arguments I'm not gonna die on this hill,
> I would be OK with both ways.

To some extent I think doing both to reduce the chance of issues in
future might be what you want. On the other hand, avoiding the
Makefile-level opt-out will help catch more corner cases in future,
which may or may not be helpful outside this noinstr.c file.

> > If you look at
> > <linux/instrumented.h>, we also have KMSAN. The KMSAN explicit
> > instrumentation doesn't appear to be invoked on that file today, but
> > given it shouldn't, we might consider:
> >
> > KMSAN_SANITIZE_noinstr.o :=3D n
> > GCOV_PROFILE_noinstr.o :=3D n
>
> This would make sense to me, although as I hinted above I think it's
> sorta orthogonal and we should __always_inline the k[ca]san stubs
> regardless.
>
> > The alternative is to audit the various sanitizer stub functions, and
> > mark all these "inline" stub functions as "__always_inline". The
> > changes made in this series are sufficient for the noinstr.c case, but
> > not complete.
>
> Oh, yeah I should have  done __kcsan_{en,di}able_current() too I think.
>
> Are there other stubs you are thinking of? I think we only care about the
> !__SANITIZE_*__ stubs - we don't need this for !CONFIG_* stubs, right?
> Anything else I'm forgetting?

Initially, I think !__SANITIZE_* stubs are enough. Well, basically
anything that appears in <linux/instrumented.h>, because all those are
__always_inline, we should make the called functions also
__always_inline.

If you think that'll be enough, and the Makefile-level opt-out is
redundant as a result, let's just do that.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANpmjNOpC2kGhfM8k%3DY8VfLL0wSTkiOdkfU05tt1xTr%2BFuMjOQ%40mail.gmail.com.
