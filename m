Return-Path: <kasan-dev+bncBDW2JDUY5AORBZOH562QMGQE7HKLFNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AFEA950FE8
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 00:53:27 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-52eff10441fsf6495868e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 15:53:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723589606; cv=pass;
        d=google.com; s=arc-20160816;
        b=fsacIvOnjb/HPeWXDC3k8abCCLEzZxYQcY1GkP63jHQFDvqUCIN6/vpF5y0WBsdyii
         zwJjdZozFqyT0R0DchsHI0PGoSbOaigk9TNsqV82WeWH5SSG6XRGpLZAiD0132hzA6sB
         XeZ84YtlkhdezW8xF42NxYyqipotXDME2eZT+AyP9vVczluJC0neyiQ3hKwaf0gaE7ND
         8X+jTl/AWxkjRMOuWITexv/4gMVxaWiDD70vvJAFuiOfWqDnjhItAnY1aIOfvTks5ShV
         AIQqpEflG5iNfEqSKW8jcl8JBAKGa6NvvkvjAC/+oWcpuV//AYPhFoWpax+alNXk4OZD
         TyQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=vB1Ms7QkRBrzn0P+WU+OEPKm6VrnIhhY5wr47Q0CFU8=;
        fh=KidRJaqJoTmzG/8G/5RcjLhUinvnmOvZt0P3YLa/yIg=;
        b=yDKKUdV3DYMg0dhNaVz0/NtyLHY7cLW8bqaqtg4SoRYWokTDUO3tChp/akmo4cXSvx
         54ynDMk6QW0vYhS/x67QCnvgkbtuN/yS1nn4NL8GvxwT8otyROJIfysA0G85CeSGVfmQ
         RoO9XdpNloK3xnnfWgTSQzSFQZfsihl5Y6Pkh6Y/paf0gzSETag504Sn/LCrtotRxQk+
         xxWuXmLGkv4ZyRpvqu+HSyErkI0BGlH6KMijpCX5tZhhtfUOmhLWmXYte2FhwSnMnbFj
         9kTWZZlsz51F2zbwPxOYCPOpj9QdPmFIx1MrqCB19SIeEzuU5pSU740zqY5WeHlayfOi
         jP+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gvCGgPBp;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723589606; x=1724194406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vB1Ms7QkRBrzn0P+WU+OEPKm6VrnIhhY5wr47Q0CFU8=;
        b=jnFEYJPC3wZGXByzrLOxOqJVjAJwF8iCr1AI1tJGCj7TsR6h1mv+N1shznxVgLdS3+
         V3JGNJYINaQ2phuGuHpbzqNArD56yLNwLClTH0DwwhWa5oVupzu9XrGFOjoe+vzx2qaE
         YvTaBl/Btv33EEYTfl6KguIvp0y+EBPmuXTobpzk9lfH2aT01XwPt05DnpEB6wWCwl9a
         3CzuiermCK2qmgoguF2zr9/jZCNdl9NPrDVnfOif1cR4TKtVxo7f4EpLt8iJfUXi8M4e
         DWGj4Fp8g/rKromTbh6cMfWyiisCsnnXaFCpskXYm+BW3TWFpMc++ni/Ogh4aRBaw23f
         iCuQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723589606; x=1724194406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vB1Ms7QkRBrzn0P+WU+OEPKm6VrnIhhY5wr47Q0CFU8=;
        b=C96SxWri2lvgEJXeuvV1aS3ccX21BhqUakZ0HkIXBzFGmo4rjijtYDqpDJRFvPcsTT
         6QOB65vuNeluupnuxzKwYnCAfvaFAvUMtzKACtJugqa65XhEYiv+om8e0a+xf6OxXSzq
         Hb95SbHdhjX1nt4u43ft2ePFGxLyfRRIXtdaMXMpBICA1IEeDSO+Ynu/vd101olqKjRD
         pX55krlRdWbbhZrn55ysuL22MKMbFtm+iEdETF4vVKJjfNJHtss2sVLR1onKWMPeViD6
         drwhbS0iSeD2M32tzhQ0N0NAVlixs5hn/BdXGqSjFKgvA3LqRC23XZ5l6toHDn+owrnt
         zyfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723589606; x=1724194406;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vB1Ms7QkRBrzn0P+WU+OEPKm6VrnIhhY5wr47Q0CFU8=;
        b=aRqalAJsv3amyH8Fu00YWsiJwx4q4iDPgOGz3txDphmSv7oAsdhRkjbqnWtFJBBaBB
         3Fgxfr0TruXZjB2uTWuWj/DTOySCst+CyRdj/kYB3/lkGZvIxdKGwzz9tqFROc6yqiYI
         +YeyAnNfNHokT41A42SHvlp1lPL8f/cKed7rvnkFjhbNQInMmOwRyy2V7Jjf9LTlwChg
         l6WVV0eCRjsxpUsQDsbVk5SYVm+b5Gly6RxoXucy5TqzHy13CmYRYEvsb4JlLsDzTN/p
         JGgujZ40/Q6xhfha2HZ+ppWM6MzZM6oXXr1nGn/Q428K+pq1pO51QgO9WYDmjCLkSR/W
         moaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXjr5/HQc6T0llYt91bgXKBUzG1DkJ2B4hSFCu6iBdi5apcgqWkNomo42dvqDOFrdhwmafg1g==@lfdr.de
X-Gm-Message-State: AOJu0Yxw4TlvnYyCip8q7jguZYPEyL2QqY3YIezLL1YkujPxL+9UsMgI
	mebNzFvZOwQ0Opls/p7/DmXlLclfQ0d7p4jOnO1QOraJV2nLg8qr
X-Google-Smtp-Source: AGHT+IHRLGK11NXXv+RbvUACsGk0Wn+xJJdG559/wkMiXYFva6Udfby3RqgDgDppGG/kVycK9Nlw4g==
X-Received: by 2002:a05:6512:68b:b0:52f:eb:aaca with SMTP id 2adb3069b0e04-532eda81f62mr415174e87.32.1723589605677;
        Tue, 13 Aug 2024 15:53:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f0e:b0:52e:fa14:cc9d with SMTP id
 2adb3069b0e04-530e395086fls1068680e87.0.-pod-prod-01-eu; Tue, 13 Aug 2024
 15:53:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXupMhaqIl7N13ya071odGHTmzvRYXMWuhKMt68LBhQtK+fAdizSWZdfrPoysNBiJYk5ra+km1tBHg=@googlegroups.com
X-Received: by 2002:a05:6512:3c89:b0:52e:9b4f:dd8c with SMTP id 2adb3069b0e04-532eda8d63bmr518887e87.35.1723589603471;
        Tue, 13 Aug 2024 15:53:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723589603; cv=none;
        d=google.com; s=arc-20160816;
        b=Kov2vpSlf8UcU18LSQDWq9m+ov2A5g7HMpgD0wg24DFpdgjgaI8NCG8V98jhOijKWR
         EPvSpg71OqudGldGQjPFjGIOKBMJt8xuz9LhCxHsp900NlQmHQV8XFgEKdaIVZcxlNkc
         UgcidF4+xXswya1mcM0UZcaM/eDLC3FCR8v43nIT+8r4jJOM/HUXse3nPijuG4K+8ulT
         XItK1D5nojQTTjk2Cj60pBE3IBDx55bFubLAbXmDWTyuJz/YVBN7/NWAZ1rhlyespmbX
         PnaYZDzgsNFhwG/0zaIFL+1M3ypPtKjYJmHdTtXzhOyuX+kSFWk1AYKwTwKFTLT8L4N7
         T1SA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=otYKhkTTVwFrNMc4y8Lo3x+9H/dZK04aKqqwJVfyjXE=;
        fh=EVrdWM6IOaH1sFENz7/zjq1dmISwW+t3TIWHT1rbXps=;
        b=peErHBU/lR5wLo9hoPGGXjbGkFc9l2crkXsppk1Fb2UKosX2AIHlc7zqlHvZoC8Kwq
         fBwP2iPFmKW7+5dt+9ZTNkjaU24CH4TenF0s00DlYb359ofkLlnQagS2ClBQqZ/K05db
         rRy6XT2foSGu8dGzn4Ykh9PpYZfnuyyFAkiTqRYFrwWKxVEhIKH/HRzZZppzXnqaVNQK
         KaETtJTpYl9zhkxMyN7mQ/QrPbN4mZi/6+8eXqWohMhpf+3iLdGX+VdEybTRRnyjj2BM
         hLZwKrF+VsWiPYjBDrdigeZOnQk8KVA2Hm/TC+IhCgCvlHL8QB+Eq3hzCxR1p6kaMRlz
         8o2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gvCGgPBp;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53200e91918si162342e87.2.2024.08.13.15.53.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Aug 2024 15:53:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-42816ca782dso46022465e9.2
        for <kasan-dev@googlegroups.com>; Tue, 13 Aug 2024 15:53:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVVL6TTwq3bIGUvD2t9njVYR0HlH39AWM9Qvo1jddeo1ZB/35e4kivj15jCn5jDjmZQ92UKsFaB9Yo=@googlegroups.com
X-Received: by 2002:a05:600c:3b18:b0:426:60bc:8f4e with SMTP id
 5b1f17b1804b1-429dd22ee6amr5734115e9.5.1723589602277; Tue, 13 Aug 2024
 15:53:22 -0700 (PDT)
MIME-Version: 1.0
References: <20240812232910.2026387-1-mmaurer@google.com> <20240812232910.2026387-3-mmaurer@google.com>
In-Reply-To: <20240812232910.2026387-3-mmaurer@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 14 Aug 2024 00:53:11 +0200
Message-ID: <CA+fCnZcVEp7Jc3kKPv59oqOxjGguV54ZaCcb1eX=Gx6ehSWHUw@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kbuild: rust: Enable KASAN support
To: Matthew Maurer <mmaurer@google.com>
Cc: dvyukov@google.com, ojeda@kernel.org, 
	Masahiro Yamada <masahiroy@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, aliceryhl@google.com, samitolvanen@google.com, 
	Nicolas Schier <nicolas@fjasle.eu>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gvCGgPBp;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335
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

On Tue, Aug 13, 2024 at 1:29=E2=80=AFAM Matthew Maurer <mmaurer@google.com>=
 wrote:
>
> Rust supports KASAN via LLVM, but prior to this patch, the flags aren't
> set properly.
>
> Suggested-by: Miguel Ojeda <ojeda@kernel.org>
> Signed-off-by: Matthew Maurer <mmaurer@google.com>
> ---
>  scripts/Makefile.kasan          | 51 +++++++++++++++++++++++----------
>  scripts/Makefile.lib            |  3 ++
>  scripts/generate_rust_target.rs |  1 +
>  3 files changed, 40 insertions(+), 15 deletions(-)
>
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index 390658a2d5b7..bfd37be9cc45 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -12,6 +12,9 @@ endif
>  KASAN_SHADOW_OFFSET ?=3D $(CONFIG_KASAN_SHADOW_OFFSET)
>
>  cc-param =3D $(call cc-option, -mllvm -$(1), $(call cc-option, --param $=
(1)))
> +rustc-param =3D $(call rustc-option, -Cllvm-args=3D-$(1),)
> +
> +check-args =3D $(foreach arg,$(2),$(call $(1),$(arg)))
>
>  ifdef CONFIG_KASAN_STACK
>         stack_enable :=3D 1
> @@ -28,6 +31,7 @@ else
>  endif
>
>  CFLAGS_KASAN_MINIMAL :=3D -fsanitize=3Dkernel-address
> +RUSTFLAGS_KASAN_MINIMAL :=3D -Zsanitizer=3Dkernel-address -Zsanitizer-re=
cover=3Dkernel-address
>
>  # -fasan-shadow-offset fails without -fsanitize
>  CFLAGS_KASAN_SHADOW :=3D $(call cc-option, -fsanitize=3Dkernel-address \
> @@ -35,44 +39,61 @@ CFLAGS_KASAN_SHADOW :=3D $(call cc-option, -fsanitize=
=3Dkernel-address \
>                         $(call cc-option, -fsanitize=3Dkernel-address \
>                         -mllvm -asan-mapping-offset=3D$(KASAN_SHADOW_OFFS=
ET)))
>
> +# The minimum supported `rustc` version has a minimum supported LLVM
> +# version late enough that we can assume support for -asan-mapping-offse=
t
> +RUSTFLAGS_KASAN_SHADOW :=3D $(RUSTFLAGS_KASAN_MINIMAL) \
> +                         -Cllvm-args=3D-asan-mapping-offset=3D$(KASAN_SH=
ADOW_OFFSET)
> +
> +KASAN_PARAMS :=3D
> +
>  ifeq ($(strip $(CFLAGS_KASAN_SHADOW)),)
>         CFLAGS_KASAN :=3D $(CFLAGS_KASAN_MINIMAL)
> +       # We still need to consider this case for Rust because we want Ru=
st code
> +       # to match the behavior of possibly old C compilers when linked t=
ogether.
> +       ifdef CONFIG_RUST
> +               RUSTFLAGS_KASAN :=3D $(RUSTFLAGS_KASAN_MINIMAL)
> +       endif

Eh, this is getting ugly. I sent a patch that simplifies the KASAN
Makefile, please rebase your changes on top of it.

>  else
> -       # Now add all the compiler specific options that are valid standa=
lone
> -       CFLAGS_KASAN :=3D $(CFLAGS_KASAN_SHADOW) \
> -        $(call cc-param,asan-globals=3D1) \
> -        $(call cc-param,asan-instrumentation-with-call-threshold=3D$(cal=
l_threshold)) \
> -        $(call cc-param,asan-instrument-allocas=3D1)
> +       KASAN_PARAMS +=3D asan-globals=3D1 asan-instrumentation-with-call=
-threshold=3D$(call_threshold) asan-instrument-allocas=3D1
> +       CFLAGS_KASAN :=3D $(CFLAGS_KASAN_SHADOW)
> +       ifdef CONFIG_RUST
> +               RUSTFLAGS_KASAN :=3D $(RUSTFLAGS_KASAN_SHADOW)
> +       endif
>  endif
>
> -CFLAGS_KASAN +=3D $(call cc-param,asan-stack=3D$(stack_enable))
> +KASAN_PARAMS +=3D asan-stack=3D$(stack_enable)
>
>  # Instrument memcpy/memset/memmove calls by using instrumented __asan_me=
m*()
>  # instead. With compilers that don't support this option, compiler-inser=
ted
>  # memintrinsics won't be checked by KASAN on GENERIC_ENTRY architectures=
.
> -CFLAGS_KASAN +=3D $(call cc-param,asan-kernel-mem-intrinsic-prefix=3D1)
> +KASAN_PARAMS +=3D asan-kernel-mem-intrinsic-prefix=3D1
>
>  endif # CONFIG_KASAN_GENERIC
>
>  ifdef CONFIG_KASAN_SW_TAGS
>
>  ifdef CONFIG_KASAN_INLINE
> -    instrumentation_flags :=3D $(call cc-param,hwasan-mapping-offset=3D$=
(KASAN_SHADOW_OFFSET))
> +    KASAN_PARAMS +=3D hwasan-mapping-offset=3D$(KASAN_SHADOW_OFFSET)
>  else
> -    instrumentation_flags :=3D $(call cc-param,hwasan-instrument-with-ca=
lls=3D1)
> +    KASAN_PARAMS +=3D hwasan-instrument-with-calls=3D1
>  endif
>
> -CFLAGS_KASAN :=3D -fsanitize=3Dkernel-hwaddress \
> -               $(call cc-param,hwasan-instrument-stack=3D$(stack_enable)=
) \
> -               $(call cc-param,hwasan-use-short-granules=3D0) \
> -               $(call cc-param,hwasan-inline-all-checks=3D0) \
> -               $(instrumentation_flags)
> +KASAN_PARAMS +=3D hwasan-instrument-stack=3D$(stack_enable) hwasan-use-s=
hort-granules=3D0 hwasan-inline-all-checks=3D0 $(instrumentation_params)

What are instrumentation_params? instrumentation_flags? They are not
defined in the Makefile anymore.

> +CFLAGS_KASAN :=3D -fsanitize=3Dkernel-hwaddress
>
>  # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_=
mem*().
>  ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y=
)
>  CFLAGS_KASAN +=3D $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=3D1=
)
>  endif
>
> +ifdef CONFIG_RUST
> +       RUSTFLAGS_KASAN :=3D -Zsanitizer=3Dkernel-hwaddress -Zsanitizer-r=
ecover=3Dkernel-hwaddress
> +endif

Let's change the order of the definitions to:

1. CFLAGS_KASAN
2. RUSTFLAGS_KASAN
3. KASAN_PARAMS


> +
>  endif # CONFIG_KASAN_SW_TAGS
>
> -export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE
> +# Add all as-supported KASAN LLVM parameters requested by the configurat=
ion
> +CFLAGS_KASAN +=3D $(call check-args, cc-param, $(KASAN_PARAMS))
> +RUSTFLAGS_KASAN +=3D $(call check-args, rustc-param, $(KASAN_PARAMS))
> +
> +export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE RUSTFLAGS_KASAN
> diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
> index fe3668dc4954..27999da3d382 100644
> --- a/scripts/Makefile.lib
> +++ b/scripts/Makefile.lib
> @@ -167,6 +167,9 @@ ifneq ($(CONFIG_KASAN_HW_TAGS),y)
>  _c_flags +=3D $(if $(patsubst n%,, \
>                 $(KASAN_SANITIZE_$(target-stem).o)$(KASAN_SANITIZE)$(is-k=
ernel-object)), \
>                 $(CFLAGS_KASAN), $(CFLAGS_KASAN_NOSANITIZE))
> +_rust_flags +=3D $(if $(patsubst n%,, \
> +               $(KASAN_SANITIZE_$(target-stem).o)$(KASAN_SANITIZE)$(is-k=
ernel-object)), \
> +               $(RUSTFLAGS_KASAN))
>  endif
>  endif
>
> diff --git a/scripts/generate_rust_target.rs b/scripts/generate_rust_targ=
et.rs
> index 8a0644c0beed..1a4d468c575f 100644
> --- a/scripts/generate_rust_target.rs
> +++ b/scripts/generate_rust_target.rs
> @@ -187,6 +187,7 @@ fn main() {
>          }
>          ts.push("features", features);
>          ts.push("llvm-target", "x86_64-linux-gnu");
> +        ts.push("supported-sanitizers", ["kernel-address"]);
>          ts.push("target-pointer-width", "64");
>      } else if cfg.has("X86_32") {
>          // This only works on UML, as i386 otherwise needs regparm suppo=
rt in rustc
> --
> 2.46.0.76.ge559c4bf1a-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcVEp7Jc3kKPv59oqOxjGguV54ZaCcb1eX%3DGx6ehSWHUw%40mail.gm=
ail.com.
