Return-Path: <kasan-dev+bncBDW2JDUY5AORBOHKSO3AMGQEJDJ5NVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BFDC958EF4
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 21:57:49 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-4280645e3e0sf48184275e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 12:57:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724183865; cv=pass;
        d=google.com; s=arc-20240605;
        b=JqXZdOsW5wcO2KQhUw4sX5RlkRjKm6F42LlONDHLbFjop5aWd7JQ9rYoGN1KQe80hE
         vYGJs5KsrUayaT1mrVjPdeWUBzgmUL7xkL73u9O9S5JbnCY/AbAJtWt+3+B29FVeLJBg
         iNikcJxJM3Fd8D7ykKqc1GtdgEFLSID/2CZUx92WMEvQE3IDTNWx2BUj3C7STH45KXV1
         etgiBttm8gK2gY9NHsHszszhiOnZnSuV4eQazeV0xWCcAozZHuBASyZ9eQNee0l7Vrtw
         m8rXI3b0vPisUFuDrWKfkRX2bqb9nrJMgT3msICWV8WFB6g+LnDHc4bzmHYY3Pmwyenc
         COeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=TiX2x1C10L8fbXdZF7OJv/1pn0tAsE8ajWKG78el+Rc=;
        fh=o//9vKy3cW55mBDI7pBFhbBEQfi/X3uq9wD2O0elHUY=;
        b=cJ59U08zgjg5B2/4gn6SaQomeWLdkgA4XEqYcU/VBa1zApaMxA9aP82Rzetm55kXqi
         znYHyRt4DQsJhFk/3mh0/nA5bsX6tQdEyWmGiIV3Wopp3ET4dxNH/n6iHGZw9a5buIk4
         oDuV16BaM3QUUqEThz5Efl4OyLuAiCUvVd6NruYlv0P0d/OcY9l/q4whsowxmhgmsKgu
         +LyLaxSo7/DBKeupRdwIhnBOXf2IQsdDYZhZgo/ZKCXUuXgYUsPeBrumxrQz7W1P7zrG
         40QtBezL+Lc0ol8KaJMgBSqX41MR7rKNSCj95qvWmhbFrahifWTppSbObKPKWEqv1cBm
         WEUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="HuAxkD/D";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724183865; x=1724788665; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TiX2x1C10L8fbXdZF7OJv/1pn0tAsE8ajWKG78el+Rc=;
        b=S9RIlu+BgbUFobgpWDbTmaINkLbhlhmt+gZ7A3I/8WIn3go5SK6EqZy6nXRyVtcplu
         /sGsIe/4mrHNS6I/tW28K8COL9ZMj8G/ZosfFLeski07yAU5T2lGF0IHHtwWse4ToAda
         NbUrvtjUG7ynySzO7KOw+YZY4xI8/wpyM1AXfrKA3rH7hYTF+NEKb250pMfkGP301iW6
         O8tezaUVWN4d35xUbVIaoSolGPzf6HM9fLvCisuDC6hKBaWc36namjvBQ2vjIaEPyCDh
         vSJQiyQriuxvw384MV5UIF6eYU/lTFoLRbKlk5VsFiHLV6aiJBKNrzlz0SQUW7P0NpcU
         V26Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724183865; x=1724788665; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TiX2x1C10L8fbXdZF7OJv/1pn0tAsE8ajWKG78el+Rc=;
        b=FTz+UPjim/poMjFk/fWcQLduc2CcHD6tB5PZsIPquMX//O16YQZqQ2irzqLdW2EXUJ
         YmTZy/TXX2h4udC3fcWqjp1GJtsQfqbDPrAqrZIuVyHKjgkdUwI5iplxVciVlR0OnqpG
         DpqSE9fyWdN8p2vbrs09nE/+5pKg/zrHEEe++4eUMOoBao3EQ7DTj8X9k7dnxXZissLc
         fDZFtE76WdYiwad1rYWgee/oq0NnoBwttW036sFBbvxC+3tlP+vjNWiNIMEG205f/id7
         9B/PMaLQcViYPNyF8CqYh+DmGwJmIS4SJdjz7jJ+NnQkrrPHPjrndww711nNzdcUvP+z
         o6eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724183865; x=1724788665;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TiX2x1C10L8fbXdZF7OJv/1pn0tAsE8ajWKG78el+Rc=;
        b=NL9jNDzElPbc9FKW3rp7DgOzx706M6VY1dpxxw7rfJ5WUdchD2HzLXhYU+m9Dt0yzH
         p3oxGQCpZdFQUKBJ0tSoLV+czGlc8+EzG+mx8hNM0AWv/PHvADynsGdBfEV7kdtPTUw8
         8WViE7ZUDioVJMYXl8aYvgHR2xR3kQ6zfi7Gf+jSDumLKgU5A7qJNkQU+St5pXDhmhZz
         ktImKwMg0ExtmwXUopp6ZpUmflNakavCoO24NNJ2AdPPmSEnZmGy4CM85b1HNGdd8OqO
         4gDW+IeJ9zD8h3dG9+6Q3c6UzmCMLdjpM7YRp1CQrXYytQk6FmDAfIGxTv973FV6izCK
         DSEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6OMsvD2q819FDsmm6LRAdtWfIhH+71IMFKOy/FaREeQbhhatgnHbWFa/ZBMYhpFYWZLEaaA==@lfdr.de
X-Gm-Message-State: AOJu0YzzD4BHE76nD6nc+1UyfSC6QOqkl6iWErWychF9eryTWgQ5kdp/
	vTdhSZoLF5CcxXQESlijyjGo/2e2ANWxNh4ySfop/MhmxRXUEvPD
X-Google-Smtp-Source: AGHT+IFTryulsR2Nx5iWY6UIUIz/Hehs0p1uen0al9cNm4NHeX2efkOA022K0GjDTsxd/Evz39ngyQ==
X-Received: by 2002:a05:600c:5247:b0:426:6153:5318 with SMTP id 5b1f17b1804b1-42abd23c28cmr2569115e9.19.1724183864434;
        Tue, 20 Aug 2024 12:57:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b8b:b0:428:e09e:e808 with SMTP id
 5b1f17b1804b1-429e22709b8ls1162775e9.0.-pod-prod-01-eu; Tue, 20 Aug 2024
 12:57:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQcMIaSkw2ac1CtA6vDBNMou2Gj0nh2D4lEtF+WIG+/fV1MCJHgbBfw1L8jHNsCSTWo0+AhN09Y3M=@googlegroups.com
X-Received: by 2002:a05:600c:1d81:b0:42a:b62c:8c86 with SMTP id 5b1f17b1804b1-42abd2640c0mr2666625e9.32.1724183862478;
        Tue, 20 Aug 2024 12:57:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724183862; cv=none;
        d=google.com; s=arc-20240605;
        b=I5B4jAwE3ko6cnEBYu5j1JCfgqa12cSa+Vp3riaIk0/V8RFPpB5a1aT/s2Lo1sriJo
         Ugwiiqb5eCl1EVwe3GvhXyaV98BXQ51Eov7p/0a/pdB2t3e6PxnKwdDCVebTLlAotJYH
         4oMjikiPnVO8HEEVQYuH4PY0PSl9+DkVpS9qKapezblpODtA1I+5T4XY+viEZPaS7WP2
         v97+vs9pl5Y5Whjn1qsNqlLyfzR8i3JM7ucsqA1EX6jFgXt6pJUxxu3F87QYL25QwnyX
         urXCqyKx6Q9B7sVt9mXjRlyn4jU63zU1tFwtjdm0mcIqDR3YiRu/T/q+EV6al5LAgpMA
         7KWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=I04d+UCyEJKSGzYujs6lGhbuTD9A1sKvAATpdsPOPRs=;
        fh=kqYbrOkvpGL7RBe9PMymm4YK8pKoX+ty3f9w/FzPLww=;
        b=gsmKoPGFat1RBoHeB6BzSVE6Yl0OFnMc7wqXVE6tk6eA4udYnSuCCi3c4JydipzVQe
         6uSJeN/qOY0ubk4xGUvRj1HMDUw4TY9C7goJhSF39atT3IlAndpSyomWaLaJ9evBEILo
         7X+pyLKfQdhhcd5NnZXn6He1ZsWYcPIQKNU+Uevd701ewO1bxfDrDlNWMPVZ7xjQsKCO
         MgqHkmxlzX0b6K84TGOfPAdhCo7FHuhqQ/Ahyz6yZCseNTq8JU0ASPkK0+3gHFGM1uns
         LOeg7XPXJeyXMrLAqCgzUt1ZvywsRKSuG2/UvSZA11oPBPrtHhFJj2Ef4/EjQJ6FoqPR
         BE5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="HuAxkD/D";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429ded6ff60si2764415e9.1.2024.08.20.12.57.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 12:57:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-427fc97a88cso50133445e9.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 12:57:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUbF0n/k0BEmHnzNuvv1/eOb3BOHc9YFUaou3YE0ORC8ZA/+tOnmlE41OKLeQz8fX35rnkWbFaWqkc=@googlegroups.com
X-Received: by 2002:a05:600c:3b83:b0:426:5ee3:728b with SMTP id
 5b1f17b1804b1-42abd2300d2mr2526935e9.13.1724183861809; Tue, 20 Aug 2024
 12:57:41 -0700 (PDT)
MIME-Version: 1.0
References: <20240820194910.187826-1-mmaurer@google.com>
In-Reply-To: <20240820194910.187826-1-mmaurer@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Aug 2024 21:57:31 +0200
Message-ID: <CA+fCnZcowB4=AQO=mEDNgKb8ES5unewQdHkPMLXYwvcxaDMthg@mail.gmail.com>
Subject: Re: [PATCH v4 0/4] Rust KASAN Support
To: Matthew Maurer <mmaurer@google.com>
Cc: ojeda@kernel.org, Alex Gaynor <alex.gaynor@gmail.com>, 
	Wedson Almeida Filho <wedsonaf@gmail.com>, Nathan Chancellor <nathan@kernel.org>, dvyukov@google.com, 
	aliceryhl@google.com, samitolvanen@google.com, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, glider@google.com, ryabinin.a.a@gmail.com, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="HuAxkD/D";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Aug 20, 2024 at 9:49=E2=80=AFPM Matthew Maurer <mmaurer@google.com>=
 wrote:
>
> Right now, if we turn on KASAN, Rust code will cause violations because
> it's not enabled properly.
>
> This series:
> 1. Adds flag probe macros for Rust - now that we're setting a minimum rus=
tc
>    version instead of an exact one, these could be useful in general. We =
need
>    them in this patch because we don't set a restriction on which LLVM ru=
stc
>    is using, which is what KASAN actually cares about.
> 2. Makes `rustc` enable the relevant KASAN sanitizer flags when C does.
> 3. Adds a smoke test to the `kasan_test` KUnit suite to check basic
>    integration.
>
> This patch series requires the target.json array support patch [1] as
> the x86_64 target.json file currently produced does not mark itself as KA=
SAN
> capable, and is rebased on top of the KASAN Makefile rewrite [2].
>
> Differences from v3 [3]:
> * Probing macro comments made more accurate
> * Probing macros now set --out-dir to avoid potential read-only fs
>   issues
> * Reordered KHWASAN explicit disablement patch to come before KASAN
>   enablement
> * Comment/ordering cleanup in KASAN makefile
> * Ensured KASAN tests work with and without CONFIG_RUST enabled
>
> [1] https://lore.kernel.org/lkml/20240730-target-json-arrays-v1-1-2b376fd=
0ecf4@google.com/
> [2] https://lore.kernel.org/all/20240813224027.84503-1-andrey.konovalov@l=
inux.dev
> [3] https://lore.kernel.org/all/20240819213534.4080408-1-mmaurer@google.c=
om/
>
> Matthew Maurer (4):
>   kbuild: rust: Define probing macros for rustc
>   rust: kasan: Rust does not support KHWASAN
>   kbuild: rust: Enable KASAN support
>   kasan: rust: Add KASAN smoke test via UAF
>
>  init/Kconfig                              |  1 +
>  mm/kasan/Makefile                         |  7 ++-
>  mm/kasan/kasan.h                          |  6 +++
>  mm/kasan/{kasan_test.c =3D> kasan_test_c.c} | 12 +++++
>  mm/kasan/kasan_test_rust.rs               | 19 ++++++++
>  scripts/Kconfig.include                   |  8 ++++
>  scripts/Makefile.compiler                 | 15 ++++++
>  scripts/Makefile.kasan                    | 57 ++++++++++++++++-------
>  scripts/Makefile.lib                      |  3 ++
>  scripts/generate_rust_target.rs           |  1 +
>  10 files changed, 112 insertions(+), 17 deletions(-)
>  rename mm/kasan/{kasan_test.c =3D> kasan_test_c.c} (99%)
>  create mode 100644 mm/kasan/kasan_test_rust.rs
>
> --
> 2.46.0.184.g6999bdac58-goog
>

Left a couple of nit comments - feel free to ignore if you don't end
up sending v5.

Otherwise, for patches 2-4:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcowB4%3DAQO%3DmEDNgKb8ES5unewQdHkPMLXYwvcxaDMthg%40mail.=
gmail.com.
