Return-Path: <kasan-dev+bncBDCLJAGETYJBBXFX27CQMGQEOJHIBWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 881E4B3ED77
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 19:46:06 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-24456ebed7bsf60129545ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 10:46:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756748765; cv=pass;
        d=google.com; s=arc-20240605;
        b=cCdWNtkQolZaOb7yhD5NPwweoLFSYXaRlNMXi6bD5JJwdD5WLmiq4I6Sd3Xhbv7D4c
         flL7AkrIgeQtBOyy1Vb/7a1yej1eyob+z77gA4Dm6BViYe/ts5DgTk2yohZmZ2GIMrLc
         B1CEJW7EI+0VAaYlz9JzG7hf4m8iLMvnAQaHQraMmKe/8vOvZHwo067AffhoNMSgbtVK
         DXdUeFQK8BgnHJAXClQUIgZ8pzeBC4pK6qY/E9/cjhcD3yy5r94hiHLbg13Faq8CN2lu
         JJwkVLsx/9T+fbFLLwKjdByT4qcmLQ8EEtlruxBEavhGA3dnZSh2LOjOOVtHfgiwxu+J
         EYzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ui1XmLEJa9NMIirvD6ezYzlUR4BTW/S7llYeaibOgtk=;
        fh=l7H7RmJMCAskvPyxyHQ8EeAwcosUc9MLHPFHK47lB/E=;
        b=JgVYzDyCdVbcXN+rizj5yOndMQUJcK7p7Fbtzn+9RJXVpVzhUg7qZ4z7QmXcak8VQp
         V7CunyyLcnc0+yQQIzk7Z58JcZeTiIp1z7KqIpC+O1cMZ14uM2cdPQspSQeuaNo6JQ4g
         BQFoc3z/DkrGaQiTHJij40eOIYfUgR688VO18Cu+sZKcOEFO2SlCw1UXwIKpjodXFGKg
         nFilrXcneaNMKZdvMF74OftEDgTEpE4suaLVWu6bllWcKnslMJ/t+mivUmNFVQDD4fuN
         P8PBJGK0qqCJsJ8O93ev1bqfjJaP6TqKsmlqzzaLfjjE0l9H/b2NSBixDHkr8CxEpK4P
         41Ew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=f9jzYM2f;
       spf=pass (google.com: domain of conor@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756748765; x=1757353565; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ui1XmLEJa9NMIirvD6ezYzlUR4BTW/S7llYeaibOgtk=;
        b=c6G//2hJ76liPYgS2TITeobMUtCIE32kLcF3Yh6fAMYrkorYYrCQDE3oYj5EhsKdMY
         wjSO/2YA6q4bAS/+k4rL9dafiMxAAAymgDWp8RCHIlXY+I4rTozBCIDqmArU0YjCON2m
         seSdybZRaXhAWEVzF4WZ0Nk928XpIXUkFgwoG3lWKWfZQ0Sji+eXu+evRSMxor41m39K
         2MXXVfYBtVEzK//7ZPd4D53D+bbe3TMh7vzQ/qooi0m6lZ81oHuDhk3L5D4+Bon1pfvA
         bgw5FYXOmyPnfmnBxqxEVc/9gq8t8drEBdaSHpBNExwTd1Q0Pzi6Tt+ktCBLDJsQ30OP
         f4zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756748765; x=1757353565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ui1XmLEJa9NMIirvD6ezYzlUR4BTW/S7llYeaibOgtk=;
        b=siqXk2hQsphuTA06zAAiCrdUWd3QwoVxzWLM1xucLWIOJGuX8nAueRy31MmaLklJr6
         +fm5PtnCwakoscvNzaIMPsYNndOufdhB+khdECPM8KeMc1Xf3mfOmS/6g9bfhX0ohG4u
         V0vb5eaVyhsMAH2/KOeo6TQ096DYuv4VHKzcNFXWuZbGJL3OahUL7/innkPLkFW+4If7
         rzikUx1LuKAn81kfLLlKztJ7z0K+S3qSV+U4/LGBM7abTU874ePXztvK+H6V6PFgcp2f
         9YJvZJOt96nl4Jrzuok4R7qeFZl31AiS0DXpjjVTtrLw357TLKyfTCIM7ulmG44YICcb
         zSZA==
X-Forwarded-Encrypted: i=2; AJvYcCVqH9/H633EYB+1LDrkIJ7M9HOQrBr5qaRq1PUC7MzLUjK2/yvYga1y4z5GbqNyvXmDZQJNVg==@lfdr.de
X-Gm-Message-State: AOJu0YwO+u/br7n9qShZUZIv8cXve05FsKlb4oWfmvtxrYfEj5kCFKSj
	C2cb8KnTxShP+R2A1ErS3J8zjUOowys5RzhVFVP4EYbBJv8VsXljz3I7
X-Google-Smtp-Source: AGHT+IEtTk+H2mNRKvrSpzeiWoO8Ub9QNGJ5xWgIN+Zos56VNT+c9JlpzllThqQT78KEW8hdDBzXQg==
X-Received: by 2002:a17:903:186:b0:246:2cb3:5768 with SMTP id d9443c01a7336-24944b4323fmr125603605ad.30.1756748764939;
        Mon, 01 Sep 2025 10:46:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf4Oiof+Du+7bLiFqAebvI7ftIAjqUoARfCpgtv0cydtA==
Received: by 2002:a17:903:88d:b0:246:8165:f6a4 with SMTP id
 d9443c01a7336-248d4e34f49ls14838685ad.2.-pod-prod-00-us; Mon, 01 Sep 2025
 10:46:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXyZU3ktEQziUJwOkBLvY+eDfztf0cpB2fZSHKKGpASw9L7VtII5pI5oFbJ/uwbqhzKh8hgFhZSCUc=@googlegroups.com
X-Received: by 2002:a17:902:ea01:b0:237:f757:9ad8 with SMTP id d9443c01a7336-2493ee070b1mr114892135ad.1.1756748762055;
        Mon, 01 Sep 2025 10:46:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756748762; cv=none;
        d=google.com; s=arc-20240605;
        b=KkccNiUF/B3jOJGih69R+M1jtmDs1g+aXclSTPJj20UjlldCbXKvKdyEKvIG4Wdxq7
         1r03V+lq8sR9/uZE99E8OesutiekxLWyZrEFqpcM2QvW9g5ysQUGm91QWHHHvGxB7AiX
         d6LlKBdYGXjQfZi6Ppe9wsHD4PjBkii0WG0fZlTNbWxcWjYU1/96fHyd47pfpstexU3i
         Fa/kwWra5I8yHzPfU9tpk+4Ix7LQ9SfD33K8beENbmPZQrEpzj3YjyOht0/lsy6aNPJY
         oIBy5b29pIPhPYI+KZUGdLNtcFZAif5iILYUXk8Ks3J/91kkuYQwioVqNJe4T3SC+2kl
         nHWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=yPJvw1xpuoo7+QV+uZzKeLoKb76bU1oCpJHQYsmsiXM=;
        fh=+BUfGepGCRtlxhjDsxew84gD0OEEtucGegovOTv3jHc=;
        b=EMI9S0GkqTU6UymfL60tjuHik7DGEe6F3HRrUyPPBXC29+utYFJwwVDjf+zm5ZnXD9
         /7CPmVYCw4FxHcHMhdM/1zMi6slHUT0HITZ2bZuATDnvsZXvSJIqMN0Zpcfg7fqdf9+I
         TL/rZdmGHL3/x8E/4kF18oZsf+GQJJcuhE1BLLpXyTxWjGhZ5OQZHO8CYAaRFuLnTcjf
         DfDXq6mfJ1kGNueQsDG8Pc18bVBgUScvEazCJx2GzDi8YNScDfFDCpHjHoLPOLzfpG0j
         qSUyDULWDbF8sfMAKMM5s0l7ffRIIbre2N0om/wKhutIeUsASVGX9apZp0WNODUc1Ef2
         Byig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=f9jzYM2f;
       spf=pass (google.com: domain of conor@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-24b105f38f9si71885ad.4.2025.09.01.10.46.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 10:46:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of conor@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id A39964150E;
	Mon,  1 Sep 2025 17:46:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E4AB5C4CEF0;
	Mon,  1 Sep 2025 17:45:56 +0000 (UTC)
Date: Mon, 1 Sep 2025 18:45:54 +0100
From: "'Conor Dooley' via kasan-dev" <kasan-dev@googlegroups.com>
To: Miguel Ojeda <ojeda@kernel.org>
Cc: Alex Gaynor <alex.gaynor@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>,
	=?iso-8859-1?Q?Bj=F6rn?= Roy Baron <bjorn3_gh@protonmail.com>,
	Benno Lossin <benno.lossin@proton.me>,
	Andreas Hindborg <a.hindborg@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>, Trevor Gross <tmgross@umich.edu>,
	Danilo Krummrich <dakr@kernel.org>, rust-for-linux@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Matthew Maurer <mmaurer@google.com>,
	Sami Tolvanen <samitolvanen@google.com>, stable@vger.kernel.org
Subject: Re: [PATCH] rust: kasan/kbuild: fix missing flags on first build
Message-ID: <20250901-shrimp-define-9d99cc2a012a@spud>
References: <20250408220311.1033475-1-ojeda@kernel.org>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="jV0+S3M+JORbrPCq"
Content-Disposition: inline
In-Reply-To: <20250408220311.1033475-1-ojeda@kernel.org>
X-Original-Sender: conor@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=f9jzYM2f;       spf=pass
 (google.com: domain of conor@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=conor@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Conor Dooley <conor@kernel.org>
Reply-To: Conor Dooley <conor@kernel.org>
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


--jV0+S3M+JORbrPCq
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Yo,

On Wed, Apr 09, 2025 at 12:03:11AM +0200, Miguel Ojeda wrote:
> If KASAN is enabled, and one runs in a clean repository e.g.:
> 
>     make LLVM=1 prepare
>     make LLVM=1 prepare
> 
> Then the Rust code gets rebuilt, which should not happen.
> 
> The reason is some of the LLVM KASAN `rustc` flags are added in the
> second run:
> 
>     -Cllvm-args=-asan-instrumentation-with-call-threshold=10000
>     -Cllvm-args=-asan-stack=0
>     -Cllvm-args=-asan-globals=1
>     -Cllvm-args=-asan-kernel-mem-intrinsic-prefix=1
> 
> Further runs do not rebuild Rust because the flags do not change anymore.
> 
> Rebuilding like that in the second run is bad, even if this just happens
> with KASAN enabled, but missing flags in the first one is even worse.
> 
> The root issue is that we pass, for some architectures and for the moment,
> a generated `target.json` file. That file is not ready by the time `rustc`
> gets called for the flag test, and thus the flag test fails just because
> the file is not available, e.g.:
> 
>     $ ... --target=./scripts/target.json ... -Cllvm-args=...
>     error: target file "./scripts/target.json" does not exist
> 
> There are a few approaches we could take here to solve this. For instance,
> we could ensure that every time that the config is rebuilt, we regenerate
> the file and recompute the flags. Or we could use the LLVM version to
> check for these flags, instead of testing the flag (which may have other
> advantages, such as allowing us to detect renames on the LLVM side).
> 
> However, it may be easier than that: `rustc` is aware of the `-Cllvm-args`
> regardless of the `--target` (e.g. I checked that the list printed
> is the same, plus that I can check for these flags even if I pass
> a completely unrelated target), and thus we can just eliminate the
> dependency completely.
> 
> Thus filter out the target.




> This does mean that `rustc-option` cannot be used to test a flag that
> requires the right target, but we don't have other users yet, it is a
> minimal change and we want to get rid of custom targets in the future.

Hmm, while this might be true, I think it should not actually have been
true. Commit ca627e636551e ("rust: cfi: add support for CFI_CLANG with Rust")
added a cc-option check to the rust kconfig symbol, checking if the c
compiler supports the integer normalisations stuff:
	depends on !CFI_CLANG || RUSTC_VERSION >= 107900 && $(cc-option,-fsanitize=kcfi -fsanitize-cfi-icall-experimental-normalize-integers)
and also sets the relevant options in the makefile:
	ifdef CONFIG_RUST
	       # Always pass -Zsanitizer-cfi-normalize-integers as CONFIG_RUST selects
	       # CONFIG_CFI_ICALL_NORMALIZE_INTEGERS.
	       RUSTC_FLAGS_CFI   := -Zsanitizer=kcfi -Zsanitizer-cfi-normalize-integers
	       KBUILD_RUSTFLAGS += $(RUSTC_FLAGS_CFI)
	       export RUSTC_FLAGS_CFI
	endif
but it should also have added a rustc-option check as, unfortunately,
support for kcfi in rustc is target specific. This results in build
breakages where the arch supports CFI_CLANG and RUST, but the target in
use does not have the kcfi flag set.
I attempted to fix this by adding:
	diff --git a/arch/Kconfig b/arch/Kconfig
	index d1b4ffd6e0856..235709fb75152 100644
	--- a/arch/Kconfig
	+++ b/arch/Kconfig
	@@ -916,6 +916,7 @@ config HAVE_CFI_ICALL_NORMALIZE_INTEGERS_CLANG
	 config HAVE_CFI_ICALL_NORMALIZE_INTEGERS_RUSTC
	        def_bool y
	        depends on HAVE_CFI_ICALL_NORMALIZE_INTEGERS_CLANG
	+       depends on $(rustc-option,-C panic=abort -Zsanitizer=kcfi -Zsanitizer-cfi-normalize-integers)
	        depends on RUSTC_VERSION >= 107900
	        # With GCOV/KASAN we need this fix: https://github.com/rust-lang/rust/pull/129373
	        depends on (RUSTC_LLVM_VERSION >= 190103 && RUSTC_VERSION >= 108200) || \
but of course this does not work for cross compilation, as you're
stripping the target information out and so the check passes on my host
even though my intended
RUSTC_BOOTSTRAP=1 rustc -C panic=abort -Zsanitizer=kcfi -Zsanitizer-cfi-normalize-integers -Ctarget-cpu=generic-rv64 --target=riscv64imac-unknown-none-elf
is a failure.

I dunno too much about rustc itself, but I suspect that adding kcfi to
the target there is a "free" win, but that'll take time to trickle down
and the minimum version rustc version for the kernel isn't going to have
that.

I'm not really sure what your target.json suggestion below is, so just
reporting so that someone that understands the alternative solutions can
fix this.

Cheers,
Conor.

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
> By the way, I noticed that we are not getting `asan-instrument-allocas` enabled
> in neither C nor Rust -- upstream LLVM renamed it in commit 8176ee9b5dda ("[asan]
> Rename asan-instrument-allocas -> asan-instrument-dynamic-allocas")). But it
> happened a very long time ago (9 years ago), and the addition in the kernel
> is fairly old too, in 342061ee4ef3 ("kasan: support alloca() poisoning").
> I assume it should either be renamed or removed? Happy to send a patch if so.
> 
>  scripts/Makefile.compiler | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/scripts/Makefile.compiler b/scripts/Makefile.compiler
> index 8956587b8547..7ed7f92a7daa 100644
> --- a/scripts/Makefile.compiler
> +++ b/scripts/Makefile.compiler
> @@ -80,7 +80,7 @@ ld-option = $(call try-run, $(LD) $(KBUILD_LDFLAGS) $(1) -v,$(1),$(2),$(3))
>  # TODO: remove RUSTC_BOOTSTRAP=1 when we raise the minimum GNU Make version to 4.4
>  __rustc-option = $(call try-run,\
>  	echo '#![allow(missing_docs)]#![feature(no_core)]#![no_core]' | RUSTC_BOOTSTRAP=1\
> -	$(1) --sysroot=/dev/null $(filter-out --sysroot=/dev/null,$(2)) $(3)\
> +	$(1) --sysroot=/dev/null $(filter-out --sysroot=/dev/null --target=%,$(2)) $(3)\
>  	--crate-type=rlib --out-dir=$(TMPOUT) --emit=obj=- - >/dev/null,$(3),$(4))
> 
>  # rustc-option
> 
> base-commit: 0af2f6be1b4281385b618cb86ad946eded089ac8
> --
> 2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901-shrimp-define-9d99cc2a012a%40spud.

--jV0+S3M+JORbrPCq
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYKAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCaLXb0gAKCRB4tDGHoIJi
0r5JAP9stx0TbJREz/W9sAmDo2EJJVmlvCEc0CI4vZzSB2wjKwEA5jtbN7q3rJFE
W/SZOgW6pFQIP1LZGnzYf2uxoNSSzQ0=
=5atv
-----END PGP SIGNATURE-----

--jV0+S3M+JORbrPCq--
