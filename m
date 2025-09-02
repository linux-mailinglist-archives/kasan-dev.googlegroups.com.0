Return-Path: <kasan-dev+bncBDCLJAGETYJBB3FZ3TCQMGQEMEFQU2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 73AE2B40AC1
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 18:35:58 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-3278bb34a68sf5097376a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 09:35:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756830957; cv=pass;
        d=google.com; s=arc-20240605;
        b=hXTYIyUn/fMGe6DrAf6QAI0fKPxZdK7FdmKnehf/R2i9cDa5vswiJMSdOzPzfeETt4
         YD0vIAWZ0GNyb9U7RsiaCRmvGFtQ3M7ugxNB/Cix8pCyK0YvTb+5GfxOgjk/AV6I1S8x
         CVzEXpF/MdGBuPkx+T7gyjQQd0SEnC7FNB0TFkt8Lc9wHmx7EvEPyJdQ7EJWRypZkuwD
         7SCJ0oBDDgUPgEfPC3eHDtM8Wz6GlMgm0eo5h9EHCDvSZca2f0nK/Gqr+opIFRfQ6pEt
         a07Ih3Pi9jUmeHqIiyHxgZRnM9YctjaOZCSL6jqGk6efR33ruBP0lAVp2sjfVJdeEEaT
         Rr7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=zWU2Y1Um2n8MzP4Vmo8er3rybydgv+eYLMyF0R94prM=;
        fh=usqd2r9cIxhlP0cvuiu+tqRQnMLl5cG3URtC4wPbyUo=;
        b=ajpBDzXm8JYz6P5RnsVkxKnROSXBxh3YGbRI9j6HFg9orEOmG930zx8phLzBiQ8X8R
         JJuIptujxdAWvju+7giaKVk+cnRbWDC8PKKRgnj0y/qkql6vhAqz+k24xQ6uTE3v9a2L
         GXrz7hUrCugCPT0/bMywktvpndK+Q2we61YTtXUw/mY8tuX60gzOb4+Wu3nZVXfmnYOO
         UYfEjaDh4yBlQ9o9iMJkQkpBzKXeD14rHIxcvu886hR3N+Zs45UPGaSCP3ENYNgu+BUx
         byejoS8S/HO/NSzgPunvYPOAYfmJjQ/i27nwXDYboZVY26qL3T8rEeOk2QH5JTZe53IV
         +HBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rBh3Pmjc;
       spf=pass (google.com: domain of conor@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756830957; x=1757435757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=zWU2Y1Um2n8MzP4Vmo8er3rybydgv+eYLMyF0R94prM=;
        b=GjnyFubEG/mGBJZv0ikx7lVx4gxArS2zPqgxek0ebMyhzeFLM8mwqH69wNPu9/zdQ/
         WGk9UtCb5EqaydVaOMvcvB8x9ZSmZrsUpvlsSUBzV6SzGnrxzJKuTIdx5OAxC9fetAPa
         CN/HT+Jn5H1er+Sr50WNMJi374eJS1jCj8kCJsaMdUv2vhDuWUsT3ONRY39uRrP/Z/GO
         Ts9QPRlqDehiAcwN6RmgRpFboMTz1xFUmNAP+jjLANhamKwXS3zJgjj8b1D5em1KygX9
         jAlK8kbB5Of+1B3ybEZLv/3Rk8Le5fhPwvexFfvE0Jy6lCSftYNm4x5F2GLT64P0H0zh
         HT0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756830957; x=1757435757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zWU2Y1Um2n8MzP4Vmo8er3rybydgv+eYLMyF0R94prM=;
        b=WYPXVzPSPv0CMQ3/5gjuHFToJ7fCdLYXXdlMi25DbnT5CYSh961EpM6ijJmyRZfE0o
         AasQjusC3+HWv0vkjMJqxT6XkdskZG9aW1f8/+TcsuzbBx//Q75w3hHCOF+RLuqnpYlB
         u/e7kQ+VZiB62JvZBA7NtEvadv1zqJKuPamBWLFZo2C1EH4AWtCDG1UipSi4YcxhKOKG
         owLYtBbrBMp/eZGA6ZXr3lNV1qr5QTUJeAcQExxZeND25vgH/FapbgqQ61G5thkoVljG
         IlmZe9cjRlEmI9v1uGHw7ipHzijVnPWn9t0dxIjTCK2Ejiua0FjcRqMaeV8IMDVUFW7g
         OJjA==
X-Forwarded-Encrypted: i=2; AJvYcCUwjwPybD/aUxQYeWKWsQhWVERKo/eIhh9nJAT/iKipjSX4K+JMQZ1H7yuaesZBl0tQD4HS5w==@lfdr.de
X-Gm-Message-State: AOJu0Yz6uu4ulogrQjr4Hlf1kMYEUeRQKmi+7RkImDmSTKkRk9h3TQBP
	/9dH0L4JdNqx3MKtc+We6FNJIeTAeGpvRobg1VJJdwETiiRzCRy4HFjH
X-Google-Smtp-Source: AGHT+IFQUvxvzOePEEXR5IA5Wza2mkaH0u5U9C4jzL79EYpu9tgMSLnrIHVPrQ4rjGqD/CiWyaGhDg==
X-Received: by 2002:a17:90b:5190:b0:327:734a:ae7a with SMTP id 98e67ed59e1d1-32815436057mr14355230a91.11.1756830956665;
        Tue, 02 Sep 2025 09:35:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeLDi31ubo2ct5Xti9F/MIn7C5btz4+cTesLG+FKFIcjw==
Received: by 2002:a17:90a:6c89:b0:327:6f3a:16ba with SMTP id
 98e67ed59e1d1-327aac842fals3612938a91.2.-pod-prod-04-us; Tue, 02 Sep 2025
 09:35:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4hvZqCey/8oLNTSmShI8yDfXOye00mn3dh6fPgyacyJqtQWBl5ovpQUCNHFBKSc5mS+LyHUXXuiM=@googlegroups.com
X-Received: by 2002:a05:6a21:3286:b0:243:ab0c:f0ed with SMTP id adf61e73a8af0-243d6dff541mr18047727637.20.1756830955050;
        Tue, 02 Sep 2025 09:35:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756830955; cv=none;
        d=google.com; s=arc-20240605;
        b=HcVNFGK8GJPO0QDr86vd1XzPZK0qguPknm7YF4UJGlQ9RZNaM5PCo2A4Ld1M1Rq2Uz
         lA/EcQdJI8vA5ErUdPonkFS47nwxEZf44SWiNlQ5h45xj7GXC7Z0ib7hdnbW2pYKcovo
         k5n6KBV8gKtgVWIiH7pmxkPcHx54yaGJpkEkg47DMle6vr9VRFbJidwia8UkAFqt4WuZ
         p9MMZFL+PY1J29AUfG/vGbxil9ZyOkabn51h/U7590GXpYHG0iOwFb5u9yq6dWROSZz5
         l96DyLYKhwobKdthzMtYsoG+J10TqnnXcljyYlPsjNEytedWiQx2ZhKhxsC394y5zHh4
         IRqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Jjr31NJe0R9JcmsKP/qYp8PKElGPE4HCW8gm9buEg4U=;
        fh=WdaCdXUvygeDtDbpqQbbWMzuA+D1tLJxSssvp4RVw8o=;
        b=FRkSkA7Wtla6cSSa0xEKrbbbnKO9SDktaDOZJwETpZEN0ivjaoMte8EkBNoVI+hTU1
         XjfuIAUtnoLYzwy3mXV/i89LnMAd/tF+a8JOp0ljlHOPS2M8Rpae28UyXwo0fteHFmHr
         zh0nZYrh1/3R9TivQAijZs0gdQkw+jMo85o8KY4QG2Or9Ia3I3Y4wIYtpaNGol916avR
         HeqFpJRmWSZx8gNtSbkvsW/XvynLIhO2l9iRv37Uea404uHod6z8rpTsiLo3lkx8XIhC
         J8jqD8+7OWdATKJKPC3VM3ts8pvLDIBy/ybNB6LyfZqa8p7hwxXdTj3/3NkRmpRliqmw
         rtow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rBh3Pmjc;
       spf=pass (google.com: domain of conor@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4e61004f72si398931a12.5.2025.09.02.09.35.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 09:35:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of conor@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id F12CE60055;
	Tue,  2 Sep 2025 16:35:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0CCAEC4CEED;
	Tue,  2 Sep 2025 16:35:48 +0000 (UTC)
Date: Tue, 2 Sep 2025 17:35:46 +0100
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
Message-ID: <20250902-gown-relapse-8fd3978c1ea0@spud>
References: <20250408220311.1033475-1-ojeda@kernel.org>
 <20250901-shrimp-define-9d99cc2a012a@spud>
 <aLaq6TpUtLkqHg_o@google.com>
 <20250902-crablike-bountiful-eb1c127f024a@spud>
 <CAH5fLggmXaa9JJ-yGdyH06Um8FopvYh97=rANLcoLc+60_HGqA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="4EeWks93mszFnPWF"
Content-Disposition: inline
In-Reply-To: <CAH5fLggmXaa9JJ-yGdyH06Um8FopvYh97=rANLcoLc+60_HGqA@mail.gmail.com>
X-Original-Sender: conor@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rBh3Pmjc;       spf=pass
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


--4EeWks93mszFnPWF
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

> > AFAICT. Then later on it'd become more like:
> >
> > config HAVE_CFI_ICALL_NORMALIZE_INTEGERS_RUSTC
> >         def_bool y
> >         depends on HAVE_CFI_ICALL_NORMALIZE_INTEGERS_CLANG
> >         depends on RISCV || ((ARM64 || x86_64) && RUSTC_VERSION >= 107900)
> >         depends on (ARM64 || x86_64) || (RISCV && RUSTC_VERSION >= 999999)
> >         # With GCOV/KASAN we need this fix: https://github.com/rust-lang/rust/pull/129373
> >         depends on (RUSTC_LLVM_VERSION >= 190103 && RUSTC_VERSION >= 108200) || \
> >                 (!GCOV_KERNEL && !KASAN_GENERIC && !KASAN_SW_TAGS)
> >
> > but that exact sort of mess is what becomes unwieldy fast since that
> > doesn't even cover 32-bit arm.
> 
> I think a better way of writing it is like this:
> 
> depends on ARCH1 || ARCH2 || ARCH3
> depends on !ARCH1 || RUSTC_VERSION >= 000000
> depends on !ARCH2 || RUSTC_VERSION >= 000000
> depends on !ARCH3 || RUSTC_VERSION >= 000000


Ye, that's a lot more manageable than what I came up with, shoulda
really done better since the option I used for a reference looks a lot
more like this than what I had... Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250902-gown-relapse-8fd3978c1ea0%40spud.

--4EeWks93mszFnPWF
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYKAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCaLcc3gAKCRB4tDGHoIJi
0jnKAP9LYjFVXcrh5zaOZUH0oAgMo/4x8LRtidC5WGVJnSFzRAEAwRmIFTqnghCO
5eXDhlTuIMYMEiqkRoSEu+mM/OF6PwQ=
=RGAX
-----END PGP SIGNATURE-----

--4EeWks93mszFnPWF--
