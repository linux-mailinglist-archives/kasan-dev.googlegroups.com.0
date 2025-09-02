Return-Path: <kasan-dev+bncBCG5FM426MMRBLML3PCQMGQEDRVMDXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DFA0B3FC32
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 12:23:43 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-55f6af0b039sf2673756e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 03:23:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756808623; cv=pass;
        d=google.com; s=arc-20240605;
        b=D6WxdbxQA4nqx/dnHxpPNxHYEKevymPtRqu3qhRHaPzC5j6KgwYDt5SVQ/jc9abqtG
         cK1zVf6N3yKoqotSMrlTWuCLulpRQ2ZbQ/9mUV3XpERh/PWe2zfkdmF4LxEHnM3volvi
         UO3ie74N4mirEzcKpetRlgncOCDunZHM4x+rqNmAXNjiEEUPg6tqxt6wxK1IzNXfwZZ7
         LhsrIqLmoYAVazA2iUuZ09CubCFhOvqHPxD1HEaGbGGO42wD18wtvMtyD7zJFfuTMexE
         HlLsQeegNm4wVGg3hDamgVrUB4hXOlWaXE/hb/p9j6nv0vgEL8lHOU1NAVTe3Jxab8MV
         sPtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6GooEApnIQZcsh4xne8oFOyDd0PQAAojc/kJV06AgCI=;
        fh=NUPrSICai/bFtTK5zlMwlW6EKkfwptN1f9nAdP+nsK0=;
        b=EvEsoZTX//zRCF+Y7kODED9uRsBsyhIqYe16YsQKu1MPmW+FTS+WzDugbXDoKT1Pzy
         oEOVbOHj9/k/ivOdtARvCEQZ+iNXPwpFDm9dc672qz8c+HkfPgsnHdnHfVINiTkWJ2VY
         VCZE4ijRCazChvAqOYnlRuCAqfQ31Fb9fRESsCivn9qwkrXx+dW/I0VxFotrD5WYeo0v
         BPg78MUuCKVsya9n47QgurrpkL+kQdBnSsbtbMaK07PWVqnGcpOpFgF6HlEnMIIT+Se0
         6S5mR+yGLbxbZegDk7kDQpZtGw/S5bxRa0j05NaVIlv4Q2eySi/6DQhkiIL7KxKRMvr/
         7mDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QaK5MaBQ;
       spf=pass (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=aliceryhl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756808623; x=1757413423; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6GooEApnIQZcsh4xne8oFOyDd0PQAAojc/kJV06AgCI=;
        b=s+/Vbx4npo3OtDuwvb7Cq98A9Rnc0Hudj7+HHnHZVqnQNSd2DpcFvLd9r+RhuwnlYx
         6L8hSWotGUtqlKXVTbjF2GprRgLVQE4CFJSyicYNX3vhcAWP5VMfSJ3uus2aUlBuknIf
         0VCi2AExnsUjJ/Tp/SO8aYGx+sQBCGtPwiegxghJyOdKSLVEQRZUSH6JkijUx7KLm9Zo
         +EUX3K/TVDU7ye6RMFbHPqSOMOccK77TYm+dxB9JjBnA8xnC4wpv79TnqnHGnOjVIJn6
         DFLiZSniOpcPHMQN8KdcVcxgvHeJ6bimAG5kQRv/L20vZLTTOF3grylWjB+WcOVIrqTK
         WX6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756808623; x=1757413423;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6GooEApnIQZcsh4xne8oFOyDd0PQAAojc/kJV06AgCI=;
        b=wQbrzsoNsOnoaJqj5UUfam4yv93JMqjuPW7t+CBaxGCWwZf8xR2a9aGarMlQ0tKp6o
         8ts73XNlTzr4TO958DmlQYu0sSrp898Bigxkp2WQ29znnnpRuVBFoxUMNyA3L0+5/be1
         XZSIm1HUPchol//tU8fQAxLVt7A0Ih5NbVMr8PtD4O7fZ2qHnsLojowx9HorgIcyvuFp
         kMXR1chYWNzsQZuV/BBcaAynBHBvwdh74S91gxObH9Js5h1v18UOeznwnya+q7gLu8i7
         VWjJxsPLYCq92t1AS92IS4vBe1scWLRLBa07F5vO8COrZbKph9Yt+cjEdMeilk4GItYy
         36FQ==
X-Forwarded-Encrypted: i=2; AJvYcCVAhEZgTkWaZtn+FthdIkISA2Kda4WkULsWm/8L7+vnd4aqjiDtrLWEEhbUeCHA6n6BhJ41jw==@lfdr.de
X-Gm-Message-State: AOJu0YwjsDEi8pZ7pZv6flsYqlvOut+t4FEx7K0tyJ+8MYe2ZkeXuXtv
	DStWoQPXFVNYcyxBTw25I27l5qK34i0hNZ7GHxI6FC67YSNhfWDkNQYf
X-Google-Smtp-Source: AGHT+IHFZIskEgVLfBWVVG1D/O6ndgsuoJWca2NzLppiBcqUi611y3HlZHV3OSCa26FJiMlR/wO2Wg==
X-Received: by 2002:a05:6512:baa:b0:55f:5245:d695 with SMTP id 2adb3069b0e04-55f708a2dc4mr3858363e87.10.1756808622316;
        Tue, 02 Sep 2025 03:23:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfoJn1YZS+n/zlhSqPF2qN5DfzXIGzcC/Q+nQdiqQOfOQ==
Received: by 2002:a05:6512:3f22:b0:55f:65fc:a192 with SMTP id
 2adb3069b0e04-55f65fca228ls1505596e87.2.-pod-prod-06-eu; Tue, 02 Sep 2025
 03:23:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUwSCwlgn/rXhuXY6U/8OScgvEyrIKErP7JzA9kYDjrfW6BpJwYXc6FbI8RazOYZ4qBDhNgrt01x7E=@googlegroups.com
X-Received: by 2002:a05:6512:334f:b0:55f:7193:1e8c with SMTP id 2adb3069b0e04-55f71932078mr2849566e87.31.1756808619658;
        Tue, 02 Sep 2025 03:23:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756808619; cv=none;
        d=google.com; s=arc-20240605;
        b=VbWrqiB+FvB1ChIRWOYw/TAI6NlWvzQxXWmA+YIG+nSh6ISc+t0gP+9ALMwKBGqSrD
         lr6CRuwiJ0P9MIDVAaXKYSIOo1azpf17BOcPblet8Wd0nTUEW4mc24DyaWMe/jgdlVfR
         ASR9wnvPHJY9bvbsOATNYufe0nCMm6aJfNxywd4xySnRFaoloyK306xQ9KCAHr9OMQr0
         ux5YitWQeDb/E6ejwyhTBvCIxPKMIIsvN770yNvlHgdB7oaptyTjvJ9EXUtnYLCxXeKI
         hnMJ5dkGmjBdpus1LuIhtcVIjAP7t58lMVZ+pw4Ag3mF7xuRnzkv0wzePLdF26Qnvuq3
         4rIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jZG75Fyl9tDZ5Dejg8bO+Je0PHBuLoFooUnwuE0fIUk=;
        fh=hsMGImCPGQZElCC6odFA75UIvPRhq1Gxzx9pJOAIZI4=;
        b=VAlE1OAjoLdgInWv5BqQReiN9YlFSUGxHbOFvKN1cMVcxhO7D2xVtcd5llvh937L4s
         FqOYUpYcsWM0Iwp0qlJGr2IvO9TQkTt4PT3ioHvC6hwbjx2zmkxCXrZcSsHfq21lqYzb
         IpKgObof72BAvo2I/jkxsm7gtpztYlM6c60fTkJ38XkCB14CpaB5WeOPJSz1wVQEnvR4
         MksWniRPWQ7tekzIBVk7v/YlfDNDDpDOauSH+vJk0Px5TVp2g6dnB60/b0RyXvcHTb2V
         z/1t6+rYor8ec7PQITZnnSD1ZQdwTH6S+v9lQ+mNvZzyRVGJTH3JjWKif3dkQ16l5cOr
         AMLA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QaK5MaBQ;
       spf=pass (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=aliceryhl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-337f4c2ec8bsi351181fa.1.2025.09.02.03.23.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Sep 2025 03:23:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-3d0b6008a8bso1975403f8f.0
        for <kasan-dev@googlegroups.com>; Tue, 02 Sep 2025 03:23:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXbI/FS9JsJCtMUlRWWG4ULzvpyB1KofBuj8vFIRtDSR6zM+TMgFtcijtJojiXqa477ZDtH9IzwUmU=@googlegroups.com
X-Gm-Gg: ASbGnctVMp7199YVxnrmdikAXCJLbu9ImGVITeUR7/Cgcx0MkqzS8aMpAaJk45ernQh
	CpZ6TwNWL4RosaRJGEPCuqoTsfqoWf/0WezpSk194aSiw9t7aJnWz7X4M2WCKQw9GPLe/qAMdJv
	/JiCcas1pcVKr+Q8/pPgzKi5jPkDVG6J6+ON+1QEW3nQejEtqYFw6p4Bkk6bhwYqQJiaJ1LJv4x
	uuzYw33rG2L+wi+1lg2L7F3hcU+LvfDFR5UPaBoC4z4WyurLnUX1Eo6GI14yZr7DlnYy9aHbGxb
	YDMo//BNFgTjrrpUPCeXsA==
X-Received: by 2002:a5d:64c9:0:b0:3d8:7c6e:8b08 with SMTP id
 ffacd0b85a97d-3d87c6e8edamr3829658f8f.13.1756808618755; Tue, 02 Sep 2025
 03:23:38 -0700 (PDT)
MIME-Version: 1.0
References: <20250408220311.1033475-1-ojeda@kernel.org> <20250901-shrimp-define-9d99cc2a012a@spud>
 <aLaq6TpUtLkqHg_o@google.com> <20250902-crablike-bountiful-eb1c127f024a@spud>
In-Reply-To: <20250902-crablike-bountiful-eb1c127f024a@spud>
From: "'Alice Ryhl' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Sep 2025 12:23:26 +0200
X-Gm-Features: Ac12FXwpn-3-ibRIG1XikBRyRDY3ok1C3LPFFXbq4WkeG6TaAMWRWaWMSctR85g
Message-ID: <CAH5fLggmXaa9JJ-yGdyH06Um8FopvYh97=rANLcoLc+60_HGqA@mail.gmail.com>
Subject: Re: [PATCH] rust: kasan/kbuild: fix missing flags on first build
To: Conor Dooley <conor@kernel.org>
Cc: Miguel Ojeda <ojeda@kernel.org>, Alex Gaynor <alex.gaynor@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Trevor Gross <tmgross@umich.edu>, Danilo Krummrich <dakr@kernel.org>, rust-for-linux@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas@fjasle.eu>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, patches@lists.linux.dev, 
	Matthew Maurer <mmaurer@google.com>, Sami Tolvanen <samitolvanen@google.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: aliceryhl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=QaK5MaBQ;       spf=pass
 (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::42e
 as permitted sender) smtp.mailfrom=aliceryhl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alice Ryhl <aliceryhl@google.com>
Reply-To: Alice Ryhl <aliceryhl@google.com>
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

On Tue, Sep 2, 2025 at 12:12=E2=80=AFPM Conor Dooley <conor@kernel.org> wro=
te:
>
> On Tue, Sep 02, 2025 at 08:29:29AM +0000, Alice Ryhl wrote:
> > On Mon, Sep 01, 2025 at 06:45:54PM +0100, Conor Dooley wrote:
> > > Yo,
> > >
> > > On Wed, Apr 09, 2025 at 12:03:11AM +0200, Miguel Ojeda wrote:
> > > > If KASAN is enabled, and one runs in a clean repository e.g.:
> > > >
> > > >     make LLVM=3D1 prepare
> > > >     make LLVM=3D1 prepare
> > > >
> > > > Then the Rust code gets rebuilt, which should not happen.
> > > >
> > > > The reason is some of the LLVM KASAN `rustc` flags are added in the
> > > > second run:
> > > >
> > > >     -Cllvm-args=3D-asan-instrumentation-with-call-threshold=3D10000
> > > >     -Cllvm-args=3D-asan-stack=3D0
> > > >     -Cllvm-args=3D-asan-globals=3D1
> > > >     -Cllvm-args=3D-asan-kernel-mem-intrinsic-prefix=3D1
> > > >
> > > > Further runs do not rebuild Rust because the flags do not change an=
ymore.
> > > >
> > > > Rebuilding like that in the second run is bad, even if this just ha=
ppens
> > > > with KASAN enabled, but missing flags in the first one is even wors=
e.
> > > >
> > > > The root issue is that we pass, for some architectures and for the =
moment,
> > > > a generated `target.json` file. That file is not ready by the time =
`rustc`
> > > > gets called for the flag test, and thus the flag test fails just be=
cause
> > > > the file is not available, e.g.:
> > > >
> > > >     $ ... --target=3D./scripts/target.json ... -Cllvm-args=3D...
> > > >     error: target file "./scripts/target.json" does not exist
> > > >
> > > > There are a few approaches we could take here to solve this. For in=
stance,
> > > > we could ensure that every time that the config is rebuilt, we rege=
nerate
> > > > the file and recompute the flags. Or we could use the LLVM version =
to
> > > > check for these flags, instead of testing the flag (which may have =
other
> > > > advantages, such as allowing us to detect renames on the LLVM side)=
.
> > > >
> > > > However, it may be easier than that: `rustc` is aware of the `-Cllv=
m-args`
> > > > regardless of the `--target` (e.g. I checked that the list printed
> > > > is the same, plus that I can check for these flags even if I pass
> > > > a completely unrelated target), and thus we can just eliminate the
> > > > dependency completely.
> > > >
> > > > Thus filter out the target.
> > >
> > >
> > >
> > >
> > > > This does mean that `rustc-option` cannot be used to test a flag th=
at
> > > > requires the right target, but we don't have other users yet, it is=
 a
> > > > minimal change and we want to get rid of custom targets in the futu=
re.
> > >
> > > Hmm, while this might be true, I think it should not actually have be=
en
> > > true. Commit ca627e636551e ("rust: cfi: add support for CFI_CLANG wit=
h Rust")
> > > added a cc-option check to the rust kconfig symbol, checking if the c
> > > compiler supports the integer normalisations stuff:
> > >     depends on !CFI_CLANG || RUSTC_VERSION >=3D 107900 && $(cc-option=
,-fsanitize=3Dkcfi -fsanitize-cfi-icall-experimental-normalize-integers)
> > > and also sets the relevant options in the makefile:
> > >     ifdef CONFIG_RUST
> > >            # Always pass -Zsanitizer-cfi-normalize-integers as CONFIG=
_RUST selects
> > >            # CONFIG_CFI_ICALL_NORMALIZE_INTEGERS.
> > >            RUSTC_FLAGS_CFI   :=3D -Zsanitizer=3Dkcfi -Zsanitizer-cfi-=
normalize-integers
> > >            KBUILD_RUSTFLAGS +=3D $(RUSTC_FLAGS_CFI)
> > >            export RUSTC_FLAGS_CFI
> > >     endif
> > > but it should also have added a rustc-option check as, unfortunately,
> > > support for kcfi in rustc is target specific. This results in build
> > > breakages where the arch supports CFI_CLANG and RUST, but the target =
in
> > > use does not have the kcfi flag set.
> > > I attempted to fix this by adding:
> > >     diff --git a/arch/Kconfig b/arch/Kconfig
> > >     index d1b4ffd6e0856..235709fb75152 100644
> > >     --- a/arch/Kconfig
> > >     +++ b/arch/Kconfig
> > >     @@ -916,6 +916,7 @@ config HAVE_CFI_ICALL_NORMALIZE_INTEGERS_CLAN=
G
> > >      config HAVE_CFI_ICALL_NORMALIZE_INTEGERS_RUSTC
> > >             def_bool y
> > >             depends on HAVE_CFI_ICALL_NORMALIZE_INTEGERS_CLANG
> > >     +       depends on $(rustc-option,-C panic=3Dabort -Zsanitizer=3D=
kcfi -Zsanitizer-cfi-normalize-integers)
> > >             depends on RUSTC_VERSION >=3D 107900
> > >             # With GCOV/KASAN we need this fix: https://github.com/ru=
st-lang/rust/pull/129373
> > >             depends on (RUSTC_LLVM_VERSION >=3D 190103 && RUSTC_VERSI=
ON >=3D 108200) || \
> > > but of course this does not work for cross compilation, as you're
> > > stripping the target information out and so the check passes on my ho=
st
> > > even though my intended
> > > RUSTC_BOOTSTRAP=3D1 rustc -C panic=3Dabort -Zsanitizer=3Dkcfi -Zsanit=
izer-cfi-normalize-integers -Ctarget-cpu=3Dgeneric-rv64 --target=3Driscv64i=
mac-unknown-none-elf
> > > is a failure.
> > >
> > > I dunno too much about rustc itself, but I suspect that adding kcfi t=
o
> > > the target there is a "free" win, but that'll take time to trickle do=
wn
> > > and the minimum version rustc version for the kernel isn't going to h=
ave
> > > that.
> > >
> > > I'm not really sure what your target.json suggestion below is, so jus=
t
> > > reporting so that someone that understands the alternative solutions =
can
> > > fix this.
> >
> > Probably right now we have to do this cfg by
> >
> >       depends on CONFIG_ARM
>
> It's valid on x86 too, right?
>
> >
> > to prevent riscv if rustc has the missing setting
> > set on riscv. Once we add it to riscv, we change it to
> >
> >       depends on CONFIG_ARM || (RUSTC_VERSION >=3D ??? || CONFIG_RISCV)
>
> I kinda shied away from something like this since there was already a
> cc-option on the other half and checking different versions per arch
> becomes a mess - but yeah it kinda is a no-brainer to do it here when
> rustc-option is kinda broken.
>
> I guess the temporary fix is then:
>
> config HAVE_CFI_ICALL_NORMALIZE_INTEGERS_RUSTC
>         def_bool y
>         depends on HAVE_CFI_ICALL_NORMALIZE_INTEGERS_CLANG
>         depends on ARM64 || x86_64
>         depends on RUSTC_VERSION >=3D 107900
>         # With GCOV/KASAN we need this fix: https://github.com/rust-lang/=
rust/pull/129373
>         depends on (RUSTC_LLVM_VERSION >=3D 190103 && RUSTC_VERSION >=3D =
108200) || \
>                 (!GCOV_KERNEL && !KASAN_GENERIC && !KASAN_SW_TAGS)
>
> because there's no 32-bit target with SanitizerSet::KCFI in rustc either
> AFAICT. Then later on it'd become more like:
>
> config HAVE_CFI_ICALL_NORMALIZE_INTEGERS_RUSTC
>         def_bool y
>         depends on HAVE_CFI_ICALL_NORMALIZE_INTEGERS_CLANG
>         depends on RISCV || ((ARM64 || x86_64) && RUSTC_VERSION >=3D 1079=
00)
>         depends on (ARM64 || x86_64) || (RISCV && RUSTC_VERSION >=3D 9999=
99)
>         # With GCOV/KASAN we need this fix: https://github.com/rust-lang/=
rust/pull/129373
>         depends on (RUSTC_LLVM_VERSION >=3D 190103 && RUSTC_VERSION >=3D =
108200) || \
>                 (!GCOV_KERNEL && !KASAN_GENERIC && !KASAN_SW_TAGS)
>
> but that exact sort of mess is what becomes unwieldy fast since that
> doesn't even cover 32-bit arm.

I think a better way of writing it is like this:

depends on ARCH1 || ARCH2 || ARCH3
depends on !ARCH1 || RUSTC_VERSION >=3D 000000
depends on !ARCH2 || RUSTC_VERSION >=3D 000000
depends on !ARCH3 || RUSTC_VERSION >=3D 000000

Alice

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AH5fLggmXaa9JJ-yGdyH06Um8FopvYh97%3DrANLcoLc%2B60_HGqA%40mail.gmail.com.
