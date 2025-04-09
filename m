Return-Path: <kasan-dev+bncBDI7FD5TRANRBIWQ3O7QMGQEEA4XZTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id D1A30A83370
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 23:35:32 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-30c2d4271c7sf485521fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 14:35:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744234532; cv=pass;
        d=google.com; s=arc-20240605;
        b=T7muBnsiyVkL1NkewA17vRmqdYDW4vl0/D+DzpDPXjx3iVdmOEulQPzsPE1GUTH/N0
         p1yivbzzQWFsVu5Jon/XMB/wi1S6oz6J0KMRM2rWD9BU9yousi3Tmc1IOKn0NNoFWtHk
         Si21+wk6vr2EtMHKLvAnD2wsUik+qn2JAVpbV/I+gv2dliFmzS3KCMr2GAQOzXWzircG
         Ys7n7gokHEbG/tja56LjTYC+u5SX0lOXGfxI65iIHas+FW4WQGspqwCOvrYAS7o//PsR
         5qqhr/xgJnKFh0Hf5FL1MZcHucJ6fg/Jz+CHvPTbJbq3IXSwAAPyGmQfoGt7Q2IwIy/p
         P6bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gGmhMNiA32ZFr3jtTdQNtekIVTCuFOTQRjt9ZSDYCq4=;
        fh=fBXXjMoZ4fI2Ogn5IGq/3JTavpm5EzFxkhN4lfdczhA=;
        b=XHdHJa7pRlK9N4OHHPE/MfSQbPfyZH7EHrM+PG4Rcwm1+obinPhwKwcqhzz/4ZYu/M
         nLASz7HGyW5TH7ovhzMXPAQzr5QzZkfjt2OtvOzf8ESiYyvpZcsr6PCgCCZGoXzsdV/X
         MTvMwjnQg36/HD7KNtWH/LFjw5SY5JDaLLNvDMJC1rgD1r2g1Sd82pHZh8ZxBdhMuH9p
         +5BxMjeoLAUcUS5+ubVYprHnePwBrXLI2VYA8dkQ1S/XbrdbDIfTZ+PYs8BgAHKD70BV
         IgOm1MX6FTMpuo3+1PN8a6qAFnF08tt3LzvaZG9bIQI6RwlNPJGRePY+CUtW6aLMewPz
         LJxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eDGRRv1w;
       spf=pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=mmaurer@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744234532; x=1744839332; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gGmhMNiA32ZFr3jtTdQNtekIVTCuFOTQRjt9ZSDYCq4=;
        b=U5TOTI5w2nQVMJxBvzP0PEbAlpnT1vBhQweM3EyD22UAVsa/+Y/vayDgPQzuAcmE3f
         mESxRUb5uMRFrVd2K/9WJsTdik0hhZGW8b5bVYhyBwl/2pF4XZcktmj6kdBlzXoys6ET
         3QDDsoMctgzTX/MrC+t63qSq3XjMfMxGYvB1kZV4LQ21sL3DIJlc0ar6n9JqBKbueK6A
         2k5CvaYVWp9qoMlBjMgP1MrIawwXaISm/HfQrx9KWZS22JlUmtZiCvfQCU2NgemQywWe
         wxxRnl61JULPbnGYXhIXQU9bLxRD14lsbrJJDfAnp9dteKDkapI6zTuZB9EG6hZsrNLI
         xIeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744234532; x=1744839332;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gGmhMNiA32ZFr3jtTdQNtekIVTCuFOTQRjt9ZSDYCq4=;
        b=eyU5HEPhfysRfhvXO1QYkTQLY+izdG66EvxqfhC3e2fMZm29EmHAObQhnNYWcpnTbP
         6wtS8N9NyA558S8ud46b3m9zMGA9FgWwoWnR2jHfN8KoZqlTmtIoC+dKTzrlubBtESG+
         8ZjJMwA1PtdlFkXx04X700LfoCOpN9gza8yegYKFAd29jrMYw5ZkKwjKncGlwpJRlu+n
         bnFMqNCC0k4fSsxx9LJzrDInn8x2g2zRD7ak18El6fmkHsH0675XXRtfK/V+SLO1C3DD
         gtHdLSPh0yVkC5hGNkhwzQufyWdrQeHMGyj7S6f/yezEr2EUGZbH8ASfRVoLOXzXTsLW
         wgng==
X-Forwarded-Encrypted: i=2; AJvYcCVYwnHBiheTlyqD0O0+PmTJ2NLllfI9F0qHkpdwoyDmhCOZDSsmiuAI1ykkLbGF8y9n+QnOjw==@lfdr.de
X-Gm-Message-State: AOJu0Yw9P1Aq32JSstnEtiOdZVklnK+ontFFAu9atFPNI1/GivRBd3pO
	t/RFzuQ4XMF/x0ua6tugBQnfg2XngoPqeGhbOoJCKc8RYtg5LEdb
X-Google-Smtp-Source: AGHT+IHC4fTmGmQ/FgZvzN/KS2/7Tu+dPJmYjWZK0uywxbbFvJDo+tE/FmFefkpgblvGPmPKSkwHuw==
X-Received: by 2002:a2e:bcd3:0:b0:30b:cceb:1e71 with SMTP id 38308e7fff4ca-30facc03500mr1871231fa.9.1744234530902;
        Wed, 09 Apr 2025 14:35:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAImR1UdiuQTpoLR9aa5TLLi/y2otWexJXJd5OAcwRVmaw==
Received: by 2002:a2e:94c4:0:b0:30b:cd63:6fc1 with SMTP id 38308e7fff4ca-30f4c976bb3ls692171fa.2.-pod-prod-04-eu;
 Wed, 09 Apr 2025 14:35:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXtPNBhSC/1Q4plG8v0yGDaGIsacpfDIloGkTT1tVtgAFMxP12rSnt4vFY0thLnqZICaPOXzZOZdds=@googlegroups.com
X-Received: by 2002:a2e:a584:0:b0:30d:e104:b593 with SMTP id 38308e7fff4ca-30faccc2cccmr1328761fa.39.1744234527949;
        Wed, 09 Apr 2025 14:35:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744234527; cv=none;
        d=google.com; s=arc-20240605;
        b=DRg96QQcXHuAD8RjOH4hvz5hX6ty0n4MT0AZacbEApBSEcsfrQRj8Es6/vQogWGQgV
         FTCr7TmyxCH3ZK08Rt2tc90Y7mH9ikX0dRoeEsyDOvSz5mosI7naRdpSqyDlbSXHH1op
         vHB+mEwMpGDVF01ltbdfjReK075y8G5Eqat1Djl8socpbnx2z+EsCoF0rxwK63DlGn/n
         ve5Hrc0gFidUzdfVlKxY15ogYPQq+PtY5lpZBivOmSE0cCg5xCfsiZUhE7BnXgytuIJr
         bdh1KUZKgRX2uVgDpBiB7BG1tYmK4IK/frHc4RlZd+azMCKtBoXbh10/uh4DVvQ+h2xO
         xraQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hBtSrPe7WZluOp+nomC0bfsWMrHWKW7U6czDExpfaAo=;
        fh=mT/glK8NlSjrCRAMjT5nXMOO9o2boPbYve8b7N7nczg=;
        b=UB+2HQBHvAZnhiLFU+IxqK5dW1idq9QNUDVkU80irBiQ/oTdWZzYVjjqu6uWZNpsk6
         q/TewL0s3n1+arTXR6TPMy5KBP6zGAbVJ33NdvOZVgXaOHsy3JghTkxpaAVYGXIZhreJ
         SR3mL7ONBGgc5jOekTSkT1QqzoCZnV4R7Oxp07/76hwHqztJONAuoshRqXxZDXPJmbey
         cJvznXLRLaLglk4N8Qd8dE9ImmR4A9qxZxf7ZUzEzZfYNzLP0byJR68YfYsQaL7aiQiN
         gUjF2tvbzjWrmjW9XdZPKg9cVgArBRtbKi2PkrzoUAN631XpKmTyZmPKYHfvwucsoB96
         O9/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eDGRRv1w;
       spf=pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=mmaurer@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30f465d63f6si356181fa.5.2025.04.09.14.35.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Apr 2025 14:35:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id 4fb4d7f45d1cf-5e789411187so1168a12.1
        for <kasan-dev@googlegroups.com>; Wed, 09 Apr 2025 14:35:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU0ywFMjoDNBlMHnIK3fgQ+DSXOoFdu34hoRQYi6tWJacpMInMjOrYptlB9ssh3rnu4y5rM6ToXnwI=@googlegroups.com
X-Gm-Gg: ASbGncvMO+Hi4mim4s7wuBlYx/gSyCBbvlu0a8SzCG70v5wkjGtkhaxo1WUVEcvaJYn
	pYOPwz5SgIGXrqV04OI/kWti+mECTbBonepZTAb061yN92C+n66BaG6mSZ8YkDfYuB2Jq8Y6tek
	Hr4C1NBDy2X/wheJ/Dnk9UxJeFUz18yOgxHXDlF72xMItFlVsVFMJVvOL00aJyjzs=
X-Received: by 2002:a50:99d7:0:b0:5ed:f521:e06c with SMTP id
 4fb4d7f45d1cf-5f3291cd5a2mr14691a12.7.1744234526715; Wed, 09 Apr 2025
 14:35:26 -0700 (PDT)
MIME-Version: 1.0
References: <20250408220311.1033475-1-ojeda@kernel.org>
In-Reply-To: <20250408220311.1033475-1-ojeda@kernel.org>
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Apr 2025 14:35:15 -0700
X-Gm-Features: ATxdqUFhVkSOwO53hFox7UAmqaM-iyfDXe_LO4ZiaZoTyX7HLUuRtwe61t2vc0E
Message-ID: <CAGSQo00QxBbUb8AxwqtRKXy96na_HUVmAG9nWmX=cVvozqwWaA@mail.gmail.com>
Subject: Re: [PATCH] rust: kasan/kbuild: fix missing flags on first build
To: Miguel Ojeda <ojeda@kernel.org>
Cc: Alex Gaynor <alex.gaynor@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Alice Ryhl <aliceryhl@google.com>, Trevor Gross <tmgross@umich.edu>, 
	Danilo Krummrich <dakr@kernel.org>, rust-for-linux@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas@fjasle.eu>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, patches@lists.linux.dev, 
	Sami Tolvanen <samitolvanen@google.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eDGRRv1w;       spf=pass
 (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::52d
 as permitted sender) smtp.mailfrom=mmaurer@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Matthew Maurer <mmaurer@google.com>
Reply-To: Matthew Maurer <mmaurer@google.com>
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

On Tue, Apr 8, 2025 at 3:03=E2=80=AFPM Miguel Ojeda <ojeda@kernel.org> wrot=
e:
>
> If KASAN is enabled, and one runs in a clean repository e.g.:
>
>     make LLVM=3D1 prepare
>     make LLVM=3D1 prepare
>
> Then the Rust code gets rebuilt, which should not happen.
>
> The reason is some of the LLVM KASAN `rustc` flags are added in the
> second run:
>
>     -Cllvm-args=3D-asan-instrumentation-with-call-threshold=3D10000
>     -Cllvm-args=3D-asan-stack=3D0
>     -Cllvm-args=3D-asan-globals=3D1
>     -Cllvm-args=3D-asan-kernel-mem-intrinsic-prefix=3D1
>
> Further runs do not rebuild Rust because the flags do not change anymore.
>
> Rebuilding like that in the second run is bad, even if this just happens
> with KASAN enabled, but missing flags in the first one is even worse.
>
> The root issue is that we pass, for some architectures and for the moment=
,
> a generated `target.json` file. That file is not ready by the time `rustc=
`
> gets called for the flag test, and thus the flag test fails just because
> the file is not available, e.g.:
>
>     $ ... --target=3D./scripts/target.json ... -Cllvm-args=3D...
>     error: target file "./scripts/target.json" does not exist
>
> There are a few approaches we could take here to solve this. For instance=
,
> we could ensure that every time that the config is rebuilt, we regenerate
> the file and recompute the flags. Or we could use the LLVM version to
> check for these flags, instead of testing the flag (which may have other
> advantages, such as allowing us to detect renames on the LLVM side).
>
> However, it may be easier than that: `rustc` is aware of the `-Cllvm-args=
`
> regardless of the `--target` (e.g. I checked that the list printed
> is the same, plus that I can check for these flags even if I pass
> a completely unrelated target), and thus we can just eliminate the
> dependency completely.
>
> Thus filter out the target.
>
> This does mean that `rustc-option` cannot be used to test a flag that
> requires the right target, but we don't have other users yet, it is a
> minimal change and we want to get rid of custom targets in the future.
>
> We could only filter in the case `target.json` is used, to make it work
> in more cases, but then it would be harder to notice that it may not
> work in a couple architectures.
>
> Cc: Matthew Maurer <mmaurer@google.com>
> Cc: Sami Tolvanen <samitolvanen@google.com>
> Cc: stable@vger.kernel.org
> Fixes: e3117404b411 ("kbuild: rust: Enable KASAN support")
> Signed-off-by: Miguel Ojeda <ojeda@kernel.org>
> ---
> By the way, I noticed that we are not getting `asan-instrument-allocas` e=
nabled
> in neither C nor Rust -- upstream LLVM renamed it in commit 8176ee9b5dda =
("[asan]
> Rename asan-instrument-allocas -> asan-instrument-dynamic-allocas")). But=
 it
> happened a very long time ago (9 years ago), and the addition in the kern=
el
> is fairly old too, in 342061ee4ef3 ("kasan: support alloca() poisoning").
> I assume it should either be renamed or removed? Happy to send a patch if=
 so.
>
>  scripts/Makefile.compiler | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/scripts/Makefile.compiler b/scripts/Makefile.compiler
> index 8956587b8547..7ed7f92a7daa 100644
> --- a/scripts/Makefile.compiler
> +++ b/scripts/Makefile.compiler
> @@ -80,7 +80,7 @@ ld-option =3D $(call try-run, $(LD) $(KBUILD_LDFLAGS) $=
(1) -v,$(1),$(2),$(3))
>  # TODO: remove RUSTC_BOOTSTRAP=3D1 when we raise the minimum GNU Make ve=
rsion to 4.4
>  __rustc-option =3D $(call try-run,\
>         echo '#![allow(missing_docs)]#![feature(no_core)]#![no_core]' | R=
USTC_BOOTSTRAP=3D1\
> -       $(1) --sysroot=3D/dev/null $(filter-out --sysroot=3D/dev/null,$(2=
)) $(3)\
> +       $(1) --sysroot=3D/dev/null $(filter-out --sysroot=3D/dev/null --t=
arget=3D%,$(2)) $(3)\
>         --crate-type=3Drlib --out-dir=3D$(TMPOUT) --emit=3Dobj=3D- - >/de=
v/null,$(3),$(4))

The problem with this change is that some `rustc` flags will only be
valid on some platforms. For example, if we check if a
`-Zsanitizer=3Dshadow-call-stack` is available, it will fail for non
aarch64 targets. I don't think we're currently directly detecting any
of these, because all of the stuff we're using is known present by
virtue of minimum compiler version, which means we can possibly get
away with this change for now. That said, this isn't a long term
solution unless we are getting rid of target.json files altogether, as
one of the main adaptations we've been putting in those is to enable
additional target features.

>
>  # rustc-option
>
> base-commit: 0af2f6be1b4281385b618cb86ad946eded089ac8
> --
> 2.49.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AGSQo00QxBbUb8AxwqtRKXy96na_HUVmAG9nWmX%3DcVvozqwWaA%40mail.gmail.com.
