Return-Path: <kasan-dev+bncBCG5FM426MMRB3OV3LCQMGQE4X4S3EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A46FB3F85A
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 10:29:35 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-336e18c37e2sf9029371fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 01:29:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756801775; cv=pass;
        d=google.com; s=arc-20240605;
        b=efpIna6G5Kojkra2PLv0oFF4H491jO48sLy63D4XonpvjvsO7BM1S0SgAQSaWBI/HJ
         ayrY1K5qEbAa7W7CfZ156PMjzMf/W/dCedpIQwS0DvicCz++4GJCxSgNzsyTolAvgk51
         OjXM++Dj+g5yprWSl41zP5qNIUMqqcWGwBVA7rke4z70q5DQI2EhX2IjIg/tU3mXMJtC
         6mUTlhWrMFT+KIttQ2AUdoQQspqSzkZ+M+GbfIqnuqmEjZJtxkOhTLTBCKN9cPNeihLb
         +JsRtT+M7xGSjGU7yWKhZzKjaDpZ3pxYmB85JWO8jx9d4oR+GtXp2+TKdxjx7XvqMugQ
         2Ecg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=j8fqMOlSaYwmL+ZlmcymRbZNCfGG2BAu7SES23mLVNM=;
        fh=qLNei9AJ5fSU3OKxemSJnfr32RdY629w/ejCZgP0LpA=;
        b=a3J72FOUBGVQGVvj0Lc5QWo0KN0u7BVgT1XKfWQWDoVTtjMAzIpz8U9UYvcmwyespC
         wdCpIGFZ5FyFbSlQAxYu7aZte6Cnsljmv/+VsOqj7qU+OtSdEEcREB80xrCWus5I9L3B
         OXSPXLJXGb66RtHJJ8aLgOlvwZk/bkny0ed5KmLe5kEuwFhBTrDaworAhsBynsQd20Bo
         zWVnc3HxoBqrIiscDse59jaxe3UEkDDua7CNqY4dfh1vYfbS5K+Z301kfSnIy+T84rGH
         ju19Mkn6C9jMmm7QPoEAhhit5bntRUqKpRMHKlPRJE9eQq3jJLgeHSN3OFMZZI78NAaj
         CqeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nbKHNeGC;
       spf=pass (google.com: domain of 36qq2aakkcwcfqnhjwdmqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=36qq2aAkKCWcFQNHJWdMQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756801775; x=1757406575; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=j8fqMOlSaYwmL+ZlmcymRbZNCfGG2BAu7SES23mLVNM=;
        b=cyXKU3VpFk2ALeapUog+yjW4HKspeohR6abcfldnVaBLkS4T57ORcqlTAl3nH6L3iC
         1AgCCALk7r9oy0bA3eV8sLNfX/WsX37rkENDXgpvbsqcuJ15CSgK8e94TjHstbtVyqBv
         JkTp9MFWRuJ9ymjHUTwSMDUyocKYa5SUsPGGxN3pWxslS+ueIdEVbEzxtROcXwB2Txev
         s5HaXbkZ5csb7tiJZYN0ulrM4tHeb5k/TST+1YGADTxKKzfvNq2SIKgBoaeeo/2G/VmY
         mERgkR9VjXMmQwvl3qB47PlidIXiIIgfJo61iLeM6OorNVl+U2zFObno4AJEQyjO5Tw7
         7+pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756801775; x=1757406575;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j8fqMOlSaYwmL+ZlmcymRbZNCfGG2BAu7SES23mLVNM=;
        b=j67hqaqk+R3kx7JhaEhew/RLRsb4ax5NiI22VIPfUnI4ScKiaJCxhhm3+z2Ld2wHc+
         S3bjkUVheR14QwYo1nie6VeakOev4vxCKGqXQzHLW8KaUa0ueNI1Yct8xT7uANLCrWIG
         8YtTuV9ahp59zF2JVQJjJbDOnFZu4/4xCl+uL73bopMfUSDIWGRzNOZJ2gxlvKSJfutF
         /Okymdo6u8VNfosW691jkN4sozZ6T/21E39FskgosvbUH/hfS2vEtu8ba9JfqxCAlTLo
         wcU1mDRzczpKCjxr+HpHIT+mmaXgc3N35yGCYVrb90v/K1EqB6wgUCy3uG2f/GJPZUfg
         5dfw==
X-Forwarded-Encrypted: i=2; AJvYcCXYLMKaj16Qe1BCgOLQCzAd1W8Pgit0ONbnTy64miINd2zRsoSKF3ewCr6a4hoBkVW0JV1EPg==@lfdr.de
X-Gm-Message-State: AOJu0Yy42WnwqYMgrKVuOiAqxMgm13cKHPqtwz6+SnTiFRYilbtJN/BJ
	BOXc2JVcgZt+umfvgHdrHGZoUDtIdDEs5JNzdi4s7IJlv7B94JJUoQgl
X-Google-Smtp-Source: AGHT+IHliQ1WiZgTq89rRpMCVa3EMd7Id/UVR/jm3dK+gB5H3QQOArvUr7fSTBNxGJjXNn3PfzAPxA==
X-Received: by 2002:a05:651c:1547:b0:336:e024:5c3f with SMTP id 38308e7fff4ca-336e0245df9mr21523221fa.30.1756801774350;
        Tue, 02 Sep 2025 01:29:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdFSU8YWmoLrlt8fwvVVY0bjDBcJ3PwGiCVDPlZtvwdLQ==
Received: by 2002:a05:651c:31ce:b0:336:896a:a615 with SMTP id
 38308e7fff4ca-336a0fe147cls10094711fa.1.-pod-prod-05-eu; Tue, 02 Sep 2025
 01:29:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV9hL4c2cecpVbO6gwbVgzWyei34hnBynOusnrMvdi83to4K8/vjY8Y29uH9lTguXBRvJwRYdAvwoA=@googlegroups.com
X-Received: by 2002:a05:651c:1b12:b0:332:2235:911c with SMTP id 38308e7fff4ca-336caf71358mr33342511fa.37.1756801771411;
        Tue, 02 Sep 2025 01:29:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756801771; cv=none;
        d=google.com; s=arc-20240605;
        b=MCbWxkiXl8uxUezwcbCadPxL96itWjMJXvuDt2IjQMi/R6GNpvC3PCZLo0Dhor1VCt
         A5OIeRADVhiZbJGyljWpc2Z8awzwqCOJrOGgCy1nw6xRi0m0q9nNU1TQaIY38XW5d08P
         LO6rRgde+e6u/xJN041fgmPI/tRiyh+SkwN4bT7+BBElqeESSNWJnbwrsOtzOVDHvh+U
         5dnuatlNw8yVvQluUkiXpBf2m8hC14IE6nOTRwttnV+h48OMf2snz26QXOSdRn8ZHRTb
         UhSQaHFMLeMZuLllmEy7mPtPaNeG68wVIOiapMV1aBVNN8IllV5xe/8k9jfG6y3nAFjf
         cr3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=fMrVj7jAgdBMUg6bB9EkBvTIBFRbh5mF4KGnDnI9ZoQ=;
        fh=o/iCLdpc1r5+CNPCfOfVwITeaoDs/rWbFcZx5WKUmLA=;
        b=ifCglPHCYnKdMvhMeXrRNUH/Ut+UZdeIRz6mv0UDVmYHksXIQ4i/1EgH+vZBhvXGGk
         SBWhU70puTN6hOMOEY+m0OhbfA6r1xecHp7UL9sXlmCbWYxpvrWGCZNKxGRxugPnb/ob
         kg8xCVspUcu8RGAKRDRXsZiz20hU1/izN0uUO8W2wNXdj1ow7SVcRLB8AlkhB/l8cSgx
         tIAw5IFV0yhyAi3MKkoOX742UiSUIDU7h0XQIonpysFPHlmO94x6iv0Fypl8MxaHJfUs
         anxGQFoppJXTZRPxPJkcZAD8A3utj9QrlKzFC2Z1isVFzTRkAUBpDU5ThWgl+M/SFFGQ
         MqHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nbKHNeGC;
       spf=pass (google.com: domain of 36qq2aakkcwcfqnhjwdmqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=36qq2aAkKCWcFQNHJWdMQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-337f4f72a71si177851fa.3.2025.09.02.01.29.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Sep 2025 01:29:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36qq2aakkcwcfqnhjwdmqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-45b869d3572so8490105e9.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Sep 2025 01:29:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU7Yi4I9UVxv2bPQLrnLnzR5R9hfI6E8xV4scq9txOV3bruK4kMinK62hD/+0AzYLHyXXK/HpUftwI=@googlegroups.com
X-Received: from wrbbs17.prod.google.com ([2002:a05:6000:711:b0:3b7:8b93:59f4])
 (user=aliceryhl job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6000:1a8c:b0:3c9:24f5:4711 with SMTP id ffacd0b85a97d-3d1def66f6dmr8162944f8f.43.1756801770707;
 Tue, 02 Sep 2025 01:29:30 -0700 (PDT)
Date: Tue, 2 Sep 2025 08:29:29 +0000
In-Reply-To: <20250901-shrimp-define-9d99cc2a012a@spud>
Mime-Version: 1.0
References: <20250408220311.1033475-1-ojeda@kernel.org> <20250901-shrimp-define-9d99cc2a012a@spud>
Message-ID: <aLaq6TpUtLkqHg_o@google.com>
Subject: Re: [PATCH] rust: kasan/kbuild: fix missing flags on first build
From: "'Alice Ryhl' via kasan-dev" <kasan-dev@googlegroups.com>
To: Conor Dooley <conor@kernel.org>
Cc: Miguel Ojeda <ojeda@kernel.org>, Alex Gaynor <alex.gaynor@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?utf-8?B?QmrDtnJu?= Roy Baron" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@kernel.org>, Trevor Gross <tmgross@umich.edu>, 
	Danilo Krummrich <dakr@kernel.org>, rust-for-linux@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas@fjasle.eu>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, patches@lists.linux.dev, 
	Matthew Maurer <mmaurer@google.com>, Sami Tolvanen <samitolvanen@google.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: aliceryhl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nbKHNeGC;       spf=pass
 (google.com: domain of 36qq2aakkcwcfqnhjwdmqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--aliceryhl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=36qq2aAkKCWcFQNHJWdMQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

On Mon, Sep 01, 2025 at 06:45:54PM +0100, Conor Dooley wrote:
> Yo,
> 
> On Wed, Apr 09, 2025 at 12:03:11AM +0200, Miguel Ojeda wrote:
> > If KASAN is enabled, and one runs in a clean repository e.g.:
> > 
> >     make LLVM=1 prepare
> >     make LLVM=1 prepare
> > 
> > Then the Rust code gets rebuilt, which should not happen.
> > 
> > The reason is some of the LLVM KASAN `rustc` flags are added in the
> > second run:
> > 
> >     -Cllvm-args=-asan-instrumentation-with-call-threshold=10000
> >     -Cllvm-args=-asan-stack=0
> >     -Cllvm-args=-asan-globals=1
> >     -Cllvm-args=-asan-kernel-mem-intrinsic-prefix=1
> > 
> > Further runs do not rebuild Rust because the flags do not change anymore.
> > 
> > Rebuilding like that in the second run is bad, even if this just happens
> > with KASAN enabled, but missing flags in the first one is even worse.
> > 
> > The root issue is that we pass, for some architectures and for the moment,
> > a generated `target.json` file. That file is not ready by the time `rustc`
> > gets called for the flag test, and thus the flag test fails just because
> > the file is not available, e.g.:
> > 
> >     $ ... --target=./scripts/target.json ... -Cllvm-args=...
> >     error: target file "./scripts/target.json" does not exist
> > 
> > There are a few approaches we could take here to solve this. For instance,
> > we could ensure that every time that the config is rebuilt, we regenerate
> > the file and recompute the flags. Or we could use the LLVM version to
> > check for these flags, instead of testing the flag (which may have other
> > advantages, such as allowing us to detect renames on the LLVM side).
> > 
> > However, it may be easier than that: `rustc` is aware of the `-Cllvm-args`
> > regardless of the `--target` (e.g. I checked that the list printed
> > is the same, plus that I can check for these flags even if I pass
> > a completely unrelated target), and thus we can just eliminate the
> > dependency completely.
> > 
> > Thus filter out the target.
> 
> 
> 
> 
> > This does mean that `rustc-option` cannot be used to test a flag that
> > requires the right target, but we don't have other users yet, it is a
> > minimal change and we want to get rid of custom targets in the future.
> 
> Hmm, while this might be true, I think it should not actually have been
> true. Commit ca627e636551e ("rust: cfi: add support for CFI_CLANG with Rust")
> added a cc-option check to the rust kconfig symbol, checking if the c
> compiler supports the integer normalisations stuff:
> 	depends on !CFI_CLANG || RUSTC_VERSION >= 107900 && $(cc-option,-fsanitize=kcfi -fsanitize-cfi-icall-experimental-normalize-integers)
> and also sets the relevant options in the makefile:
> 	ifdef CONFIG_RUST
> 	       # Always pass -Zsanitizer-cfi-normalize-integers as CONFIG_RUST selects
> 	       # CONFIG_CFI_ICALL_NORMALIZE_INTEGERS.
> 	       RUSTC_FLAGS_CFI   := -Zsanitizer=kcfi -Zsanitizer-cfi-normalize-integers
> 	       KBUILD_RUSTFLAGS += $(RUSTC_FLAGS_CFI)
> 	       export RUSTC_FLAGS_CFI
> 	endif
> but it should also have added a rustc-option check as, unfortunately,
> support for kcfi in rustc is target specific. This results in build
> breakages where the arch supports CFI_CLANG and RUST, but the target in
> use does not have the kcfi flag set.
> I attempted to fix this by adding:
> 	diff --git a/arch/Kconfig b/arch/Kconfig
> 	index d1b4ffd6e0856..235709fb75152 100644
> 	--- a/arch/Kconfig
> 	+++ b/arch/Kconfig
> 	@@ -916,6 +916,7 @@ config HAVE_CFI_ICALL_NORMALIZE_INTEGERS_CLANG
> 	 config HAVE_CFI_ICALL_NORMALIZE_INTEGERS_RUSTC
> 	        def_bool y
> 	        depends on HAVE_CFI_ICALL_NORMALIZE_INTEGERS_CLANG
> 	+       depends on $(rustc-option,-C panic=abort -Zsanitizer=kcfi -Zsanitizer-cfi-normalize-integers)
> 	        depends on RUSTC_VERSION >= 107900
> 	        # With GCOV/KASAN we need this fix: https://github.com/rust-lang/rust/pull/129373
> 	        depends on (RUSTC_LLVM_VERSION >= 190103 && RUSTC_VERSION >= 108200) || \
> but of course this does not work for cross compilation, as you're
> stripping the target information out and so the check passes on my host
> even though my intended
> RUSTC_BOOTSTRAP=1 rustc -C panic=abort -Zsanitizer=kcfi -Zsanitizer-cfi-normalize-integers -Ctarget-cpu=generic-rv64 --target=riscv64imac-unknown-none-elf
> is a failure.
> 
> I dunno too much about rustc itself, but I suspect that adding kcfi to
> the target there is a "free" win, but that'll take time to trickle down
> and the minimum version rustc version for the kernel isn't going to have
> that.
> 
> I'm not really sure what your target.json suggestion below is, so just
> reporting so that someone that understands the alternative solutions can
> fix this.

Probably right now we have to do this cfg by

	depends on CONFIG_ARM

to prevent riscv if rustc has the missing setting
set on riscv. Once we add it to riscv, we change it to

	depends on CONFIG_ARM || (RUSTC_VERSION >= ??? || CONFIG_RISCV)

Alice

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLaq6TpUtLkqHg_o%40google.com.
