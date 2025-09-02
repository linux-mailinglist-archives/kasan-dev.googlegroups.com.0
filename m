Return-Path: <kasan-dev+bncBDCLJAGETYJBBBMG3PCQMGQEHCANPXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 40023B3FBEF
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 12:12:23 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-3251961140bsf4708175a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 03:12:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756807941; cv=pass;
        d=google.com; s=arc-20240605;
        b=XZg6XHO5kmyus7Ii5/tbvUo3DABoIlcmaHqS2A3GEKogqmtQ2lVADTZRqsr17Q9mVf
         iYpd27f5LU2DcJLcW/KrsAYtehzxeBwRDivYKiKadJLRXWCPhTZ7e7C3YNyHdvIMgAeX
         0Xqvj7OdbVeMd0oCQrPyj9u6WGilEiskHT2Xo4Z4BDDwf9jZyilkqj6EpgJCJh+EsuhH
         uGEdqSbiLhcBDHZ5mTpkngvnfz75+0ubbKTHnEHbcCADPGxVapSTKJ5TfR/YqRZu1Smy
         MHTD0fcclp0hnFOF5rBTxUqvLUMniTqNW4KyfjJ1rI12+xDZ3jTQ1AnyrESOUeuaD9b+
         xMsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=AI7qXJO36yVwGzGNHld0BFc9SCM11WwoTmL5c9RqwXk=;
        fh=/uoO9Jvz3+kfvrVL6TpXOR7QMgoj6cYbsEFLA67IgFg=;
        b=JzJS+qxloHUqYK+S9vQuqM1x+RWepy7Z1p+S5QN1OgokF8p2zBKjEvJKselXJc1mWD
         4iSJpQ7EqyRvWwT8X3MFIEXZ2x36eNzyY31pj8eKfyxM6KT0yoKHrFwtnNPOxgosKRvu
         uPEP0ByLjDDJdKPlvkCBWe7ggOnvRtMfpVqG0n1H/VP1ULq8JnuLOmGy8qKZ1f/GKv3+
         sod7B9ghV4ZM5R1/4WiBZfjCo8BLkFRKery+8ejJJ4YZ4RCHOjvDueCQE+p4OkrDLgwe
         jl5EblDQ42oKlXiJEzyuiMoZlxdxkjc3nwavz6bqtgLUq7Xp6Srgbgn1vep0nd0yzRpc
         UzAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=m0iq12Hp;
       spf=pass (google.com: domain of conor@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756807941; x=1757412741; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=AI7qXJO36yVwGzGNHld0BFc9SCM11WwoTmL5c9RqwXk=;
        b=UrrwxDXqNanDxuZpaRtyum111SzxnCSTIxoKJMrwLu+8rHfJotyJs/bBN+ZZpqzeXu
         tCca2VPvZ2BneXvLqE8gJV5sJUO56zMRLgrHfFu6lMFExFQgSrKCl5reNHevd7oK0GRA
         FQHt/0FmxIrSzWA1DVtc2QfZQTv6uDtD+xkTJwv3nJ9ENmE5ErDNXcpElSCJAsa5vSw+
         yMJgHLpfRUJcgXA19hT89uYlmcyD1PxkmV/QgM5/KfWWKie9z67UCDMytlTxKNYv2xYh
         /vlNj+i13woPWRMNaDk6bYG1r6iuLGthNsHlHcniOzGXmwcaaYX+0rHCHd1gDVrESc/x
         pOXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756807941; x=1757412741;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AI7qXJO36yVwGzGNHld0BFc9SCM11WwoTmL5c9RqwXk=;
        b=lpxIiKrf32uf3BJLwGaaeS8tT6j5YYN8qGEqxJcNCops7PrICtmAuTeJ/pdk9WQfFY
         AJdcD7JE3NtRdy1f30ZvFngmRxZ8U8Be/GfbmkW6GiDfUkI298nbA4Iph1FBAay4Wq0L
         LxCeUEP4+wogxT2rZiCAnZ2iZ1B4//pZuNPWud0ZF98KtrhM4EaXyxZc5koYXN1nbEw3
         HQuHRVUt/C6qcg9QJcuwNfB6ifxjnshOQHSwQQhfijMuEJukmUyWmtQY5x86nJUYB0p3
         LYB2WR2QhSyHMIpK+KUNpQnG00ALVSoycvmN3fzFE7f24W3clOQu+yzgxpbrzYoPARmd
         mZmg==
X-Forwarded-Encrypted: i=2; AJvYcCXXsG2lFxqv2lB9mCrBND1bOa9uniUtcg1vWXzylTdwI4aU9RCQhlAyfy4W/Y8i3VYVMnq5KA==@lfdr.de
X-Gm-Message-State: AOJu0YzwdPLNJmso7EeVKGu0ANHB7AhtcCamQg8KWI1fHGTz4nCnF+EU
	/uoAwXjFW9L5fEo6Qf63Dw118Rwfxu+Kws+/Ai21YFMfcrtjetvK3qYB
X-Google-Smtp-Source: AGHT+IH2lncgp41EIS6AQtSaUS3T/nx8D6ePBRQNnEJ7WxlmFJ9fXfqFbUAyJyVqZCefKWcE+9xRSQ==
X-Received: by 2002:a17:90b:54cc:b0:329:8b65:25b5 with SMTP id 98e67ed59e1d1-3298b652c59mr10200648a91.26.1756807941386;
        Tue, 02 Sep 2025 03:12:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfklFN9pT+IzU8MlCNswXf0TEDthbHFYATnmO6OKB7+hg==
Received: by 2002:a17:90b:5082:b0:325:7c02:d093 with SMTP id
 98e67ed59e1d1-327aac6d100ls4173173a91.1.-pod-prod-04-us; Tue, 02 Sep 2025
 03:12:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/lo8d3KzqQEarvPV4z4cUNDDp6XdMR8b/OuaimCITnf4Rfolcfxvlwl1GdSyntHH8g3/AboxnvMk=@googlegroups.com
X-Received: by 2002:a17:90b:4f85:b0:327:f050:cc6f with SMTP id 98e67ed59e1d1-328156baf71mr15880350a91.20.1756807940069;
        Tue, 02 Sep 2025 03:12:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756807940; cv=none;
        d=google.com; s=arc-20240605;
        b=Le0PzmGbjBRPHL904EutX2Z/ld0Dnou+Fl8Zbqk83T1qSNPio/7Xzy/4J6+eU+Vsph
         QlQkV9yWlc1zRmqAghcqZ1cJYxQyqfNvS7RD0XDsZvj7qmlBcDMlzSp+bDaDlOvwL7Fa
         n82fu6LZK7MttiSoGhKknDqmy3KD3PL5ioVBWqBFFxJA9jCwW9Sl/MgxVKseZ0JJeFXV
         zzGsG1HFystSs8eobvJI4V6dLys8Pn86fbnqlyK3YI6WshFjBJFXgAgKgsXvPIsTPpHF
         hXGFnST0tdHIdZw4ZCdRWQ/fW/Rurrq+DMqTpXXIe+kQaX00npSkzPIczO3q1/dbpi4e
         vqXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Xa0uEfKBsfkPj4ZtbZbe1CxrF/z7/8HDJ21TvMXmU7I=;
        fh=WdaCdXUvygeDtDbpqQbbWMzuA+D1tLJxSssvp4RVw8o=;
        b=WH1x55YXYnhn7R9cRjUBNkSEOQvVwAAOPVbKqIvrCdV4mhtO6JaRBh44PzdYONPTg4
         tcprfHVycu1unc9+EvJMeaH1ObN3bVkJKQHBOUVY4TKyy0Vkd7lRuLjIGvan2f1DT8mE
         Oxa0rYEAkOFaJfXSveofXGCzz5kAVmp3VhqeGwiuhId+7qb4SkroC5Xejg+W4686bxec
         3HrjveN8KDQwg+WcZE7O2iMEZcvdWtFi7OP/Xc/0Uv5wTfpjqjK+OLfsEKAc6oYJ2qm3
         zt1eSoEgRPuC8CjLEtEI0KuiLVBkYUYNmXNMsd0rFN0YmdocR48P3q1wRUqqFizCGFcw
         Ax9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=m0iq12Hp;
       spf=pass (google.com: domain of conor@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-329910e4f2csi239373a91.2.2025.09.02.03.12.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 03:12:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of conor@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 35C28601D3;
	Tue,  2 Sep 2025 10:12:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4683CC4CEED;
	Tue,  2 Sep 2025 10:12:14 +0000 (UTC)
Date: Tue, 2 Sep 2025 11:12:11 +0100
From: "'Conor Dooley' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alice Ryhl <aliceryhl@google.com>
Cc: Miguel Ojeda <ojeda@kernel.org>, Alex Gaynor <alex.gaynor@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>,
	=?iso-8859-1?Q?Bj=F6rn?= Roy Baron <bjorn3_gh@protonmail.com>,
	Benno Lossin <benno.lossin@proton.me>,
	Andreas Hindborg <a.hindborg@kernel.org>,
	Trevor Gross <tmgross@umich.edu>,
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
Message-ID: <20250902-crablike-bountiful-eb1c127f024a@spud>
References: <20250408220311.1033475-1-ojeda@kernel.org>
 <20250901-shrimp-define-9d99cc2a012a@spud>
 <aLaq6TpUtLkqHg_o@google.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="H+VzOpbPUpNEExps"
Content-Disposition: inline
In-Reply-To: <aLaq6TpUtLkqHg_o@google.com>
X-Original-Sender: conor@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=m0iq12Hp;       spf=pass
 (google.com: domain of conor@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=conor@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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


--H+VzOpbPUpNEExps
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Tue, Sep 02, 2025 at 08:29:29AM +0000, Alice Ryhl wrote:
> On Mon, Sep 01, 2025 at 06:45:54PM +0100, Conor Dooley wrote:
> > Yo,
> > 
> > On Wed, Apr 09, 2025 at 12:03:11AM +0200, Miguel Ojeda wrote:
> > > If KASAN is enabled, and one runs in a clean repository e.g.:
> > > 
> > >     make LLVM=1 prepare
> > >     make LLVM=1 prepare
> > > 
> > > Then the Rust code gets rebuilt, which should not happen.
> > > 
> > > The reason is some of the LLVM KASAN `rustc` flags are added in the
> > > second run:
> > > 
> > >     -Cllvm-args=-asan-instrumentation-with-call-threshold=10000
> > >     -Cllvm-args=-asan-stack=0
> > >     -Cllvm-args=-asan-globals=1
> > >     -Cllvm-args=-asan-kernel-mem-intrinsic-prefix=1
> > > 
> > > Further runs do not rebuild Rust because the flags do not change anymore.
> > > 
> > > Rebuilding like that in the second run is bad, even if this just happens
> > > with KASAN enabled, but missing flags in the first one is even worse.
> > > 
> > > The root issue is that we pass, for some architectures and for the moment,
> > > a generated `target.json` file. That file is not ready by the time `rustc`
> > > gets called for the flag test, and thus the flag test fails just because
> > > the file is not available, e.g.:
> > > 
> > >     $ ... --target=./scripts/target.json ... -Cllvm-args=...
> > >     error: target file "./scripts/target.json" does not exist
> > > 
> > > There are a few approaches we could take here to solve this. For instance,
> > > we could ensure that every time that the config is rebuilt, we regenerate
> > > the file and recompute the flags. Or we could use the LLVM version to
> > > check for these flags, instead of testing the flag (which may have other
> > > advantages, such as allowing us to detect renames on the LLVM side).
> > > 
> > > However, it may be easier than that: `rustc` is aware of the `-Cllvm-args`
> > > regardless of the `--target` (e.g. I checked that the list printed
> > > is the same, plus that I can check for these flags even if I pass
> > > a completely unrelated target), and thus we can just eliminate the
> > > dependency completely.
> > > 
> > > Thus filter out the target.
> > 
> > 
> > 
> > 
> > > This does mean that `rustc-option` cannot be used to test a flag that
> > > requires the right target, but we don't have other users yet, it is a
> > > minimal change and we want to get rid of custom targets in the future.
> > 
> > Hmm, while this might be true, I think it should not actually have been
> > true. Commit ca627e636551e ("rust: cfi: add support for CFI_CLANG with Rust")
> > added a cc-option check to the rust kconfig symbol, checking if the c
> > compiler supports the integer normalisations stuff:
> > 	depends on !CFI_CLANG || RUSTC_VERSION >= 107900 && $(cc-option,-fsanitize=kcfi -fsanitize-cfi-icall-experimental-normalize-integers)
> > and also sets the relevant options in the makefile:
> > 	ifdef CONFIG_RUST
> > 	       # Always pass -Zsanitizer-cfi-normalize-integers as CONFIG_RUST selects
> > 	       # CONFIG_CFI_ICALL_NORMALIZE_INTEGERS.
> > 	       RUSTC_FLAGS_CFI   := -Zsanitizer=kcfi -Zsanitizer-cfi-normalize-integers
> > 	       KBUILD_RUSTFLAGS += $(RUSTC_FLAGS_CFI)
> > 	       export RUSTC_FLAGS_CFI
> > 	endif
> > but it should also have added a rustc-option check as, unfortunately,
> > support for kcfi in rustc is target specific. This results in build
> > breakages where the arch supports CFI_CLANG and RUST, but the target in
> > use does not have the kcfi flag set.
> > I attempted to fix this by adding:
> > 	diff --git a/arch/Kconfig b/arch/Kconfig
> > 	index d1b4ffd6e0856..235709fb75152 100644
> > 	--- a/arch/Kconfig
> > 	+++ b/arch/Kconfig
> > 	@@ -916,6 +916,7 @@ config HAVE_CFI_ICALL_NORMALIZE_INTEGERS_CLANG
> > 	 config HAVE_CFI_ICALL_NORMALIZE_INTEGERS_RUSTC
> > 	        def_bool y
> > 	        depends on HAVE_CFI_ICALL_NORMALIZE_INTEGERS_CLANG
> > 	+       depends on $(rustc-option,-C panic=abort -Zsanitizer=kcfi -Zsanitizer-cfi-normalize-integers)
> > 	        depends on RUSTC_VERSION >= 107900
> > 	        # With GCOV/KASAN we need this fix: https://github.com/rust-lang/rust/pull/129373
> > 	        depends on (RUSTC_LLVM_VERSION >= 190103 && RUSTC_VERSION >= 108200) || \
> > but of course this does not work for cross compilation, as you're
> > stripping the target information out and so the check passes on my host
> > even though my intended
> > RUSTC_BOOTSTRAP=1 rustc -C panic=abort -Zsanitizer=kcfi -Zsanitizer-cfi-normalize-integers -Ctarget-cpu=generic-rv64 --target=riscv64imac-unknown-none-elf
> > is a failure.
> > 
> > I dunno too much about rustc itself, but I suspect that adding kcfi to
> > the target there is a "free" win, but that'll take time to trickle down
> > and the minimum version rustc version for the kernel isn't going to have
> > that.
> > 
> > I'm not really sure what your target.json suggestion below is, so just
> > reporting so that someone that understands the alternative solutions can
> > fix this.
> 
> Probably right now we have to do this cfg by
> 
> 	depends on CONFIG_ARM

It's valid on x86 too, right?

> 
> to prevent riscv if rustc has the missing setting
> set on riscv. Once we add it to riscv, we change it to
> 
> 	depends on CONFIG_ARM || (RUSTC_VERSION >= ??? || CONFIG_RISCV)

I kinda shied away from something like this since there was already a
cc-option on the other half and checking different versions per arch
becomes a mess - but yeah it kinda is a no-brainer to do it here when
rustc-option is kinda broken.

I guess the temporary fix is then:

config HAVE_CFI_ICALL_NORMALIZE_INTEGERS_RUSTC
	def_bool y
	depends on HAVE_CFI_ICALL_NORMALIZE_INTEGERS_CLANG
	depends on ARM64 || x86_64
	depends on RUSTC_VERSION >= 107900
	# With GCOV/KASAN we need this fix: https://github.com/rust-lang/rust/pull/129373
	depends on (RUSTC_LLVM_VERSION >= 190103 && RUSTC_VERSION >= 108200) || \
		(!GCOV_KERNEL && !KASAN_GENERIC && !KASAN_SW_TAGS)

because there's no 32-bit target with SanitizerSet::KCFI in rustc either
AFAICT. Then later on it'd become more like:

config HAVE_CFI_ICALL_NORMALIZE_INTEGERS_RUSTC
	def_bool y
	depends on HAVE_CFI_ICALL_NORMALIZE_INTEGERS_CLANG
	depends on RISCV || ((ARM64 || x86_64) && RUSTC_VERSION >= 107900)
	depends on (ARM64 || x86_64) || (RISCV && RUSTC_VERSION >= 999999)
	# With GCOV/KASAN we need this fix: https://github.com/rust-lang/rust/pull/129373
	depends on (RUSTC_LLVM_VERSION >= 190103 && RUSTC_VERSION >= 108200) || \
		(!GCOV_KERNEL && !KASAN_GENERIC && !KASAN_SW_TAGS)

but that exact sort of mess is what becomes unwieldy fast since that
doesn't even cover 32-bit arm.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250902-crablike-bountiful-eb1c127f024a%40spud.

--H+VzOpbPUpNEExps
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYKAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCaLbC+wAKCRB4tDGHoIJi
0hjyAP9tByKVI1IGeavixZ01MOC4OXttf2BTFfivcgVEZF5lAAEA27I7Tv1B7oFK
OTlynfN6TLIg3kRbEhZ4XzMKZVeSLgU=
=lQ9s
-----END PGP SIGNATURE-----

--H+VzOpbPUpNEExps--
