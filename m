Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR756DEQMGQEUOZN6UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 94A2BCB93B3
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 17:11:53 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-343823be748sf1393339a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 08:11:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765555912; cv=pass;
        d=google.com; s=arc-20240605;
        b=jzs+ITA5ts8DtGs7od2KuEu6GdmOMVhdCysEGFPvuQdYrgPc/jTILHZXnUJkMv1MHD
         J3vG9ZqbsU6WVOa6RR6MTXaa02FmfhTKqVsgD+4rUZ7E5hUyz9RJYxBwhcn3FShbOqZl
         1akDsZG9eM85s1vhzRoBh+WtfNDSkgNlawwillJV7O8k/AhPepES8fJdYG4m/B4cJr9V
         MFHMUakg5UJLiAlnEys5L4wbIf9i6seTceJohuAa6FqNUn49XJSNfvRBN+g1DhcfJ/mK
         s35w8wJghzWly4SdtTEpT1s9VjmGj6MHZ24n6oKDYi0LVVngfjaA3z61J2rqsxGW3y42
         tQvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=revJy6zWPxeeg3U6CxsPJULtWx8rOVai1Z3OK7G0v8A=;
        fh=xJHLLdVOmVCnEbxH7f20z0U5EzNAuWrYEiJBYP8WZY4=;
        b=ClstvIUz+5mGM4oCsv9ZdXiOowXVPKH/OBXy4aUB8xqrmbpVBxMz6APwhrG8pJjkSU
         3kVt9Y6sFBZxSmVdhCCW5lqFs0vBrI3+6QXmXfgVkNYPoNCd05G7usq17Pg+5y68KIMG
         wFTRdUBLv8i9vBuisTGkOksqKcT0j3JH1yLSojR2jrX8/z6Ffx30UkTqwcD+AJF4X8bb
         KkctP7V2ShNvxdAlb+HzJ7ZSB7JSQsaN4It9wyIeRpArcCGoX6fzPbDgOaZzARIz8wrK
         9d1jnFWBH0lgXZftQcyaib0XeVj7TxUPqVbw7ETQArBBOC8BYoVxVEmbUNb8oWUp0cX7
         z66w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VHJgIjFj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765555912; x=1766160712; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=revJy6zWPxeeg3U6CxsPJULtWx8rOVai1Z3OK7G0v8A=;
        b=eQR8Ym++CXSuKOndLyTf22AyCPhDErXgv1i3/LVyN0Uoba4SwTSuaUswMhkumk9NL6
         XaVKH9GbmIJK8yLORujhrB0bxaXa23y4ZL3+8vU4lXGs4R/laapZgfBHKqXf3vj/J8UB
         In5JBKuQdX1dQE3tIR+KmtnrKFrwMxTq2pOTYWnWq1DOjKCrVUIxHc4QDVcHPA/BiEU5
         jB5zeqlG8y+rftfo8RTpqHD+ABEXYG7EK6z0kLaYnrNd+o4c90okV+j5FNKlH2q2R6bM
         O6CkMuEBX9S2EcfZttiQPfXk0Kas9ksQSW1nNy95xGYxNaQkB7rCFZnR5TD1hrT97D1h
         y5UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765555912; x=1766160712;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=revJy6zWPxeeg3U6CxsPJULtWx8rOVai1Z3OK7G0v8A=;
        b=EtxHXSLN86ywfqsmmlqwSkhlgzJ7Adi6qChrdW3iPofr7AUKU846/QMDLsl0xQo4Ct
         qHw7ZcSoTZXhfkg9c/aQPypE0y3Qqmyn9lE1Bftqts8wRLGgU1ujjBjXXOzDUb9d7Olh
         HL+CbFwdDnj1O0YMk6xPnKI96vhSi7Eh/M+CDTB7dCGj3DCWcu8ouuKPGkFuMor9st4h
         9UYcWv2ej8QZLx67hGDi3Ti1PX0D+qEj1dwsfwUCUQng5uFehMHmyGw5agGW3SCpPEws
         DHa8fX7rH3yLFKqOhcMVDGNyYuyvHKxOeCQJkoWveFvO0j1i7J156gwP2XteqPttbgCx
         0R5w==
X-Forwarded-Encrypted: i=2; AJvYcCVY92Fs1nJBxgndQYBN34e+hFLKt2HMSSahmFOwNu93vrqxAwM3G8eFyA4IJ2AhsxZyQRiZHQ==@lfdr.de
X-Gm-Message-State: AOJu0YwckFXf6VHioV3keufJtx1dpCipay/vI90fNudozX7gWM9Z0r/T
	bdN6mFf9Rjw4SUwBZKMy6jd2k3dDPUFxnkH+gJgk/MQOlqKqgoXoKlg5
X-Google-Smtp-Source: AGHT+IEXmxWDEaA91CEbdHsTqemWGkdO4aB+BuqsGtheC3kFkIBGTaQyfn5Xx1U1bmfu/p+NjlCWCg==
X-Received: by 2002:a17:90b:53c3:b0:327:9e88:7714 with SMTP id 98e67ed59e1d1-34abd78d6d3mr2703746a91.37.1765555911752;
        Fri, 12 Dec 2025 08:11:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZvxOr8R5vbloWhuDY4J3NkZDxbFvaI4Dchv4QITumdIg=="
Received: by 2002:a17:90b:98:b0:349:967e:1491 with SMTP id 98e67ed59e1d1-34abccbc6e9ls768398a91.1.-pod-prod-09-us;
 Fri, 12 Dec 2025 08:11:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWOkaiBgIsNtIxCE/mml1YVJ2D5Wxe7OR7u6riyHSojRMZMBwekQjDJJeYcnMkJnM+sUxcoof8LDzQ=@googlegroups.com
X-Received: by 2002:a17:90b:3910:b0:330:7ff5:2c58 with SMTP id 98e67ed59e1d1-34abd6c76b9mr2735090a91.7.1765555909995;
        Fri, 12 Dec 2025 08:11:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765555909; cv=none;
        d=google.com; s=arc-20240605;
        b=B83adye9XLkqT41GYgH2c5HPDQbw1T9X/y85L/xKT3W9HRIaDG51wkFckqfN0MGTLC
         yA9ib6aFDMAeO3XK6A8THzcdyb2sjqdXSE83Jtlfa24zplWZ1kEdeyulamOgH4je07pq
         hpiE6Wq1CcceTHjAz+xYt9xIJWeZJwzP+L4ILasI9HGFW6+dCKCLLERinAD/qbngUWj1
         jf0iREelwIpRwGFcEvV1IEa496FrSagu1bMSzA8ldNOdXaizPRySnzHGJhUWYztxfVzG
         lbaLQSW8O993tyo7MAheU1H9cH8tiC7GP0EyYUNTowllYvc0cfF+bIXA0cIx+pH+FgtT
         OkIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0lfGqFcmpD2h+aF4SPC/8yp56Ytfk4g6SabzAmz17NA=;
        fh=Nv28GEUeuq3VsC1j1T1sMg0rV/YjgTdu2Jxa5Y2P4/0=;
        b=UTNorFxvgiMiBcmTTXG34yMoK0ryKKhsCp5SSq0QaXcV90J157GHx3nFpxD0sNGFz8
         uER/HcAvqQj7RvhpD1jc8ShphegnPNBr8/JM3iawf4l9cRUTjF2i6JzNGz8QhH5dzqPY
         Hq0/naxbg9Y6Gloy9+xBLxPJquKCKc0TTJgzJWxRNZMm32lAsHW6zV2stUDFGwIJoShg
         vQAG+XQwZ6bN5SiX6Kmq1U9SWJgG1fIc3baDW37QgyBQf/oO1k9rOm5oIbYbzA8yzE7S
         YOqg/RBcpRtl8sOXhWH7JEkf96nSh9KBmo3n8QY9i95j0FX0Xh8qvdTQJJTpQJHZG3SG
         iPkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VHJgIjFj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-34abe285515si19189a91.2.2025.12.12.08.11.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Dec 2025 08:11:49 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 41be03b00d2f7-bc17d39ccd2so869861a12.3
        for <kasan-dev@googlegroups.com>; Fri, 12 Dec 2025 08:11:49 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVmJyd3SekQuD5ozxpBnwI8nEZGlGLcUkkjFyqkTwwSrCqWlEQT5D+rcYSdrJOZxm54rsABi5MA7mE=@googlegroups.com
X-Gm-Gg: AY/fxX7lFWRQpMSmlJE5ChXHcU6iv7Rd9m1l1vpUTsgpPJdPt5gnK6+X2R1Egaxt865
	eZ1Hwrnm+g7QHySMiouwTqQMwWLKc7YwepNX9qX+8Z7IFyclJmPRWezQYYYdAGSwH1poSL/sWrg
	FZh0aPYbtlBatIbTwg6AV83GqDBK3IfKrkonzJyh4bQEwZXHShW5M9YC+j0kqvQj/IcZZftD87C
	DHmZFtb7iumK2Vc8F0wr21/kT7/G1Kzx4MfgFnPEEpfSGpREpWe41ddtTiZgPGR1nhgherDLv1f
	8RoMym6UeT8/wyIqDJGhPvZ0DjE=
X-Received: by 2002:a05:7300:f297:b0:2a4:3593:4684 with SMTP id
 5a478bee46e88-2ac303c5dd4mr1770944eec.32.1765555908735; Fri, 12 Dec 2025
 08:11:48 -0800 (PST)
MIME-Version: 1.0
References: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
 <CANpmjNNK6vRsyQ6SiD3Uy7fNim-wV+KWgbEokOaxbbd02Wa=ew@mail.gmail.com>
 <CANpmjNPizath=-ZUVTDFAdO_RZL1xqnx_o24nHA+3tJ4-FOg+Q@mail.gmail.com>
 <DET8WJDWPV86.MHVBO6ET98LT@google.com> <CANpmjNOpC2kGhfM8k=Y8VfLL0wSTkiOdkfU05tt1xTr+FuMjOQ@mail.gmail.com>
 <DETBVMG30SW8.WBM5TRGF59YZ@google.com>
In-Reply-To: <DETBVMG30SW8.WBM5TRGF59YZ@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Dec 2025 17:11:12 +0100
X-Gm-Features: AQt7F2o2xUOOQk1q229b0oKQ18nDgm1cJmnWfTYfcdxz0SSiFVGJyklPS4Kwu7M
Message-ID: <CANpmjNNc9vRJbD2e5DPPR8SWNSYa=MqTzniARp4UWKBUEdhh_Q@mail.gmail.com>
Subject: Re: [PATCH 0/2] Noinstr fixes for K[CA]SAN with GCOV
To: Brendan Jackman <jackmanb@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel <ardb@kernel.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=VHJgIjFj;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::534 as
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

On Tue, 9 Dec 2025 at 03:25, Brendan Jackman <jackmanb@google.com> wrote:
> On Tue Dec 9, 2025 at 12:52 AM UTC, Marco Elver wrote:
> > On Tue, 9 Dec 2025 at 01:05, Brendan Jackman <jackmanb@google.com> wrot=
e:
> >> On Mon Dec 8, 2025 at 11:12 AM UTC, Marco Elver wrote:
> >> > On Mon, 8 Dec 2025 at 10:37, Marco Elver <elver@google.com> wrote:
> >> >>
> >> >> On Mon, 8 Dec 2025 at 02:35, Brendan Jackman <jackmanb@google.com> =
wrote:
> >> >> >
> >> >> > Details:
> >> >> >
> >> >> >  - =E2=9D=AF=E2=9D=AF  clang --version
> >> >> >    Debian clang version 19.1.7 (3+build5)
> >> >> >    Target: x86_64-pc-linux-gnu
> >> >> >    Thread model: posix
> >> >> >    InstalledDir: /usr/lib/llvm-19/bin
> >> >> >
> >> >> >  - Kernel config:
> >> >> >
> >> >> >    https://gist.githubusercontent.com/bjackman/bbfdf4ec2e1dfd0e18=
657174f0537e2c/raw/a88dcc6567d14c69445e7928a7d5dfc23ca9f619/gistfile0.txt
> >> >> >
> >> >> > Note I also get this error:
> >> >> >
> >> >> > vmlinux.o: warning: objtool: set_ftrace_ops_ro+0x3b: relocation t=
o !ENDBR: machine_kexec_prepare+0x810
> >> >> >
> >> >> > That one's a total mystery to me. I guess it's better to "fix" th=
e SEV
> >> >> > one independently rather than waiting until I know how to fix the=
m both.
> >> >> >
> >> >> > Note I also mentioned other similar errors in [0]. Those errors d=
on't
> >> >> > exist in Linus' master and I didn't note down where I saw them. E=
ither
> >> >> > they have since been fixed, or I observed them in Google's intern=
al
> >> >> > codebase where they were instroduced downstream.
> >> >> >
> >> >> > This is a successor to [1] but I haven't called it a v2 because i=
t's a
> >> >> > totally different solution. Thanks to Ard for the guidance and
> >> >> > corrections.
> >> >> >
> >> >> > [0] https://lore.kernel.org/all/DERNCQGNRITE.139O331ACPKZ9@google=
.com/
> >> >> >
> >> >> > [1] https://lore.kernel.org/all/20251117-b4-sev-gcov-objtool-v1-1=
-54f7790d54df@google.com/
> >> >>
> >> >> Why is [1] not the right solution?
> >> >> The problem is we have lots of "inline" functions, and any one of t=
hem
> >> >> could cause problems in future.
> >> >
> >> > Perhaps I should qualify: lots of *small* inline functions, includin=
g
> >> > those stubs.
> >> >
> >> >> I don't mind turning "inline" into "__always_inline", but it seems
> >> >> we're playing whack-a-mole here, and just disabling GCOV entirely
> >> >> would make this noinstr.c file more robust.
> >> >
> >> > To elaborate: `UBSAN_SANITIZE_noinstr.o :=3D n` and
> >> > `K{A,C}SAN_SANITIZE_noinstr.o :=3D n` is already set on this file.
> >> > Perhaps adding __always_inline to the stub functions here will be
> >> > enough today, but might no longer be in future.
> >>
> >> Well you can also see it the other way around: disabling GCOV_PROFILE
> >> might be enough today, but as soon as some other noinstr disables
> >> __SANITIZE_ADDRESS__ and expects to be able to call instrumented
> >> helpers, that code will be broken too.
> >
> > This itself is a contradiction: a `noinstr` function should not call
> > instrumented helpers. Normally this all works due to the compiler's
> > function attributes working as intended for the compiler-inserted
> > instrumentation, but for explicitly inserted instrumentation it's
> > obviously not. In otherwise instrumented files with few (not all)
> > `noinstr` functions, making the stub functions `__always_inline` will
> > not work, because the preprocessor is applied globally not per
> > function. In the past, I recall the underlying implementation being
> > used of e.g. the bitops (arch_foo... or __foo) in `noinstr` functions
> > to solve that.
>
> Sorry I dropped an important word here, I meant to say other noinstr
> _files_. I.e. anything else similar to SEV's noinstr.c that is doing
> noinstr at the file level.

Someone at LPC (I couldn't make out who due to technical difficulties)
mentioned that calling explicitly instrumented helpers from noinstr
functions is a general problem.

After that I sat down and finally got around to implement the builtin
that should solve this once and for all, regardless of where it's
called: https://github.com/llvm/llvm-project/pull/172030
What this will allow us to do is to remove the
"K[AC]SAN_SANITIZE_noinstr.o :=3D n" lines from the Makefile, and purely
rely on the noinstr attribute, even in the presence of explicit
instrumentation calls.

It will be a while until it's available and the kernel needs patches
to use it, too, but that should be easy enough. Once it lands in
Clang, it'd be nice if GCC could provide the same.

So for the time being, we still need your patches here to work around
the problem.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANpmjNNc9vRJbD2e5DPPR8SWNSYa%3DMqTzniARp4UWKBUEdhh_Q%40mail.gmail.com.
