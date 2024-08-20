Return-Path: <kasan-dev+bncBDW2JDUY5AORBT5FSO3AMGQEGPBYRQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 52119958D70
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 19:30:57 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2f3f48c355fsf3749161fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 10:30:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724175056; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mfys2HVHL9+ci36ulyoJpocqOJTfc0q/02fylKpRkbdN5ceKl5/lJXX3/bG3SePjGY
         +Vp/Ui0QC6u5+YNw5RIJgsxbyWwGTO3ZO2G+a3gh8gWMfTuLCpdtNA9Ivab5X1GFpaKO
         Uash4NHtghYcUf/TT0wEycfV6mhdaJTHi3NMm3/VmGjkIg9Ly/Ltj+ZbT2/tE0vVxzSo
         DYwAARcwaXLVZIIONjsjvFNG9pL7bOWIRToumsAwO3Yovpu2gUp2VEWYDFXb1l3nZOQn
         5ncFeaSxgpAlcu4ChUMY8KbtwCOYbPpt6SBpps0kVLTfH/M7aWYlrr+oFcE4lSuakCjm
         TPaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=uxG4NBYivAVjmyPygikGFQS+KsDUU/fVp7yD8JH+eXo=;
        fh=nwhCjN2t89tOey18U7JW8xRTvJjnCiP8yPy900lVi+Y=;
        b=a8GP2i14Est21yKbS6mTVPCrFQHeP99WTm1qV0fh77+mRSFiUNuu8NHyL4iOBCQr8U
         FtiQiDmrEr7bAR+DK04xhTNrqpaYAXJHNYpJ1Glyr1OW6pyWQVSiUgLVwJpyiO4JzVx/
         cXE+E/7v5F/6CbiiPCbtjP3foL/toXMtye8QOf1+Qa6RuK59aitDUeSY/k4O0jy7QOuY
         z2jdqGpMHz1/PiIQjg190rMN318M1rtElvQf2UtJ+PYRpglCTr7zusWKtWR6aoVFnCdi
         SJVXYb8Q2DN28riqYkIqxYlsJpWpf7nUVQ8VVjS4W2YRsA29NppmmuEa2sA+JRbgLGyQ
         YyeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Qa9YNKWa;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724175056; x=1724779856; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uxG4NBYivAVjmyPygikGFQS+KsDUU/fVp7yD8JH+eXo=;
        b=OzGMztYi7WD3D/QFDwT8cYSknIp1FYEy+4lNPXwyWuBwOAGcUPRWbEe3MEEd1Ryj0n
         xbY7dyPotA2G1VMRaV9Gpfavv4T280wiN/tHFM4Tq0UfnbtPcBqnHECa5hjpLeKQt2HK
         2qrhzrvcqv7pFsX7mXkFg1aPTkk3NZdkv3npkMA8/NKGeyMXJRrQBg8K8/SQb+pkQ0ED
         7WsKxIQ1AXou7lYX/h42HukM+HuDK3s+z0xh8b576CMoNhaOHijrnUQl4IhLqbEf1HmC
         Hzth4haVgQipZVQc5ttERdJ4y3Vlmx/IFhNY2R/ashdg1+aIVUnBPuihqY4K5dArtW4S
         e5Lw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724175056; x=1724779856; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uxG4NBYivAVjmyPygikGFQS+KsDUU/fVp7yD8JH+eXo=;
        b=SUj+VOX/ytz9DokcWAeVipW191PI71n7zKHMUhU8a5yVGNN1gv14XQCCP9JCc3UJFq
         twD9Hq4QdXXrt4c0GMjr7qyd7renqtErCoAqMx+wnbhnVFYsBLNVWw9JfHU5x/bd04S4
         W5GSvoyrqV6Qul9YlmrSuFtx6sd9VwmaXengLdtP4+D9+vUQ5Bs6CBfwRke3bGs+L4+s
         Y9GNV7sNtEOSwtKaZTbY7i2h0qF8OpEoGsUoTWGflfd/g4TqnsZyw2YH8uSc831DZK+o
         UBD/po/YyjMSEtJqkXqQF2m/nP5KBb7LD3TmGTAw26Askr2GBTSvdal3AERVfbgHF2gF
         MTbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724175056; x=1724779856;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uxG4NBYivAVjmyPygikGFQS+KsDUU/fVp7yD8JH+eXo=;
        b=UUvEa22vNhAjSxPOTCPbNYJaJNDJ5EiEvQVJVduXjV7yNMCGbxqArRH502C/5g11O/
         q+BKBsdOw1AnklYONEPdq7E9S3ozpaqXpZok1XA5wQfGqjuAv2vu05E9IS6C6XZdomuT
         sYC00+DGtcZrMkryKwzzZ2neDjBqGUjrmJa3MZHx8hUHAUDVDTPHDEBzI7puMvWFdL69
         H92kJ/+YZdAcEUh8qL8Wq/WxzQnCLTgQuWz3YEzbxxteEd1DnoyUaBUFs9cV2WKsiodF
         2q2LRPO3DJxJImhCSK3zNhpYzHCJZlKQ5r0YGe/+zf48QbczvkzikS3jdHe50bf4wIBG
         8aOA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXG3cBRw+RlzId0J5y7Ayelk90Os7RhlDr6HXOKmeSXU8Ja0nt1p78m4bcmw7agInKTkriG+5PQ1l7nQY7ANTHzpOK2AEu8iQ==
X-Gm-Message-State: AOJu0YzuqzVJRze2DhU3TeKenFRFuP7MfUAKX6yT/wsoBGMn5fettPAN
	ptB6pFjvAE1+O2ad3HJ1qBs2HN+AIS6dAFVo5N5gVBwF6vnsZ6Mj
X-Google-Smtp-Source: AGHT+IH1aSecZ2B1ERNihuE9TPc/WAOnJD9iS4wU9wIHkqP5oFQ/gWbkiJzbn1fmLNSkJ1LhaYm6Cw==
X-Received: by 2002:a05:651c:54b:b0:2ef:26dc:efbe with SMTP id 38308e7fff4ca-2f3e9fdb1eamr25451611fa.42.1724175055698;
        Tue, 20 Aug 2024 10:30:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:30a:0:b0:2ef:1eb3:4741 with SMTP id 38308e7fff4ca-2f3b3588d08ls1321941fa.0.-pod-prod-01-eu;
 Tue, 20 Aug 2024 10:30:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVaVdN9n55IzFhF08e372jDfbHsdRt2/WBVSv17GiBSwf/ck9bxVRE/YpKRRsM0F6xhTUTBJxBSaqLzY1yerFhEqe9AneIZni0tiw==
X-Received: by 2002:a2e:9991:0:b0:2ef:2543:457c with SMTP id 38308e7fff4ca-2f3e9fa3a9emr18063761fa.24.1724175053499;
        Tue, 20 Aug 2024 10:30:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724175053; cv=none;
        d=google.com; s=arc-20160816;
        b=PeGAO204r6bCX323ISdzrHtwdiIrYAq3MaRG3ZFkf2UBG+IsRGoWrv5EQ7qHa69Uii
         MCn3dES/Riz+XdOPFN03xb+holvrLsa+zgJwOAZGICNLupUPVSbCew2apSrYH5MrMJfZ
         as3svshKPSm98c3HKJSAVF6q3ASUsoJ3BltDPSHz05cooY/VMNjOrw2kmAY4e7ziGuuP
         fGZ4aqgnCvYy/Kn8SumejMNORkRnaORQheH05Y51r2qehUv6B1e4ONQjMJKINXaPFYPF
         lBMQDlGWGzCUUGCa2+UyjpUYv19BASTsu3ly/qdscXZ8IBgWSfCwpjsoUkHmK2Z3Wwf9
         dPHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7wISXuCBhmhFmaFFKaHK4h6CHKUfKYQSgO+IzNbasqs=;
        fh=Ugp6aZmiCkiF2g7FDanUwnocOheS7YSuzA5ktK85nC0=;
        b=JniAYCZRn/F7gD0Jk5FSiN2Fg2T0nXmzw5MMf41ET10+e9eJjafFyKskc9Ocx2MBVu
         b0DHG3YK5ELEC0+FM0w0FcovW3MQ9ZftToK3Fu5/sfhM5vEKjVVEvoVWaqffZJn0yUy5
         nix5a6mQ4ikDgR8z5N90RabK/AmnqeFqXTVVKvhuNNY8HVLZZW2xBajeeUNvbh6YdO/b
         PUOv06KcnQSuyyfydWpAQgEtxUZNLHaU4lZ9ec1bI0l0sk+BTDJkgVIy9AwEgfMT652c
         Pwd6ldW4iGFyLSOU/1GJRX+W3IrECmBezFFwsc/ccoSt2RSPx4rCcgXmfu9OSXuxihwl
         zxAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Qa9YNKWa;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5bebbbeb7edsi281221a12.1.2024.08.20.10.30.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 10:30:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-3719896b7c8so2456878f8f.3
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 10:30:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXPSJjOg+f8GWutiSP3ZY1sSnSDA9CW7vhN6rAoly19WZhaebAzkdXtnEcDXEqqOhg4rV0HVKsT5YhUIExM3Z7umcvFUh0aqHKDVg==
X-Received: by 2002:a5d:4386:0:b0:362:b906:99c4 with SMTP id
 ffacd0b85a97d-371c6060c90mr1694765f8f.58.1724175052539; Tue, 20 Aug 2024
 10:30:52 -0700 (PDT)
MIME-Version: 1.0
References: <20240819213534.4080408-1-mmaurer@google.com> <20240819213534.4080408-3-mmaurer@google.com>
In-Reply-To: <20240819213534.4080408-3-mmaurer@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Aug 2024 19:30:41 +0200
Message-ID: <CA+fCnZeA_GOdqidEhP81TvwiSSgJNEoXa85ooqVpfPOk3v4S0w@mail.gmail.com>
Subject: Re: [PATCH v3 2/4] kbuild: rust: Enable KASAN support
To: Matthew Maurer <mmaurer@google.com>
Cc: dvyukov@google.com, ojeda@kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, aliceryhl@google.com, samitolvanen@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, glider@google.com, 
	Nicolas Schier <nicolas@fjasle.eu>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Qa9YNKWa;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f
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

On Mon, Aug 19, 2024 at 11:35=E2=80=AFPM Matthew Maurer <mmaurer@google.com=
> wrote:
>
> Rust supports KASAN via LLVM, but prior to this patch, the flags aren't
> set properly.
>
> Rust hasn't yet enabled software-tagged KWHASAN (only regular HWASAN),
> so explicitly prevent Rust from being selected when it is enabled.

This is done in the next patch, not in this one.

> Suggested-by: Miguel Ojeda <ojeda@kernel.org>
> Signed-off-by: Matthew Maurer <mmaurer@google.com>
> ---
>  scripts/Makefile.kasan          | 54 +++++++++++++++++++++++----------
>  scripts/Makefile.lib            |  3 ++
>  scripts/generate_rust_target.rs |  1 +
>  3 files changed, 42 insertions(+), 16 deletions(-)
>
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index aab4154af00a..163640fdefa0 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -12,6 +12,11 @@ endif
>  KASAN_SHADOW_OFFSET ?=3D $(CONFIG_KASAN_SHADOW_OFFSET)
>
>  cc-param =3D $(call cc-option, -mllvm -$(1), $(call cc-option, --param $=
(1)))
> +rustc-param =3D $(call rustc-option, -Cllvm-args=3D-$(1),)
> +
> +check-args =3D $(foreach arg,$(2),$(call $(1),$(arg)))
> +
> +kasan_params :=3D
>
>  ifdef CONFIG_KASAN_STACK
>         stack_enable :=3D 1
> @@ -41,39 +46,56 @@ CFLAGS_KASAN :=3D $(call cc-option, -fsanitize=3Dkern=
el-address \
>                 $(call cc-option, -fsanitize=3Dkernel-address \
>                 -mllvm -asan-mapping-offset=3D$(KASAN_SHADOW_OFFSET)))
>
> -# Now, add other parameters enabled similarly in both GCC and Clang.
> -# As some of them are not supported by older compilers, use cc-param.
> -CFLAGS_KASAN +=3D $(call cc-param,asan-instrumentation-with-call-thresho=
ld=3D$(call_threshold)) \
> -               $(call cc-param,asan-stack=3D$(stack_enable)) \
> -               $(call cc-param,asan-instrument-allocas=3D1) \
> -               $(call cc-param,asan-globals=3D1)
> +# The minimum supported `rustc` version has a minimum supported LLVM
> +# version late enough that we can assume support for -asan-mapping-offse=
t

Nit: dot at the end.

> +RUSTFLAGS_KASAN :=3D -Zsanitizer=3Dkernel-address \
> +                  -Zsanitizer-recover=3Dkernel-address \
> +                  -Cllvm-args=3D-asan-mapping-offset=3D$(KASAN_SHADOW_OF=
FSET)
> +
> +# Now, add other parameters enabled similarly in GCC, Clang, and rustc.
> +# As some of them are not supported by older compilers, these will be fi=
ltered
> +# through `cc-param` or `rust-param` as applicable.
> +kasan_params +=3D asan-instrumentation-with-call-threshold=3D$(call_thre=
shold) \
> +               asan-stack=3D$(stack_enable) \
> +               asan-instrument-allocas=3D1 \
> +               asan-globals=3D1
>
>  # Instrument memcpy/memset/memmove calls by using instrumented __asan_me=
m*()
>  # instead. With compilers that don't support this option, compiler-inser=
ted
>  # memintrinsics won't be checked by KASAN on GENERIC_ENTRY architectures=
.
> -CFLAGS_KASAN +=3D $(call cc-param,asan-kernel-mem-intrinsic-prefix=3D1)
> +kasan_params +=3D asan-kernel-mem-intrinsic-prefix=3D1
>
>  endif # CONFIG_KASAN_GENERIC
>
>  ifdef CONFIG_KASAN_SW_TAGS
>
>  ifdef CONFIG_KASAN_INLINE
> -       instrumentation_flags :=3D $(call cc-param,hwasan-mapping-offset=
=3D$(KASAN_SHADOW_OFFSET))
> +       kasan_params +=3D hwasan-mapping-offset=3D$(KASAN_SHADOW_OFFSET)
>  else
> -       instrumentation_flags :=3D $(call cc-param,hwasan-instrument-with=
-calls=3D1)
> +       kasan_params +=3D hwasan-instrument-with-calls=3D1
>  endif
>
> -CFLAGS_KASAN :=3D -fsanitize=3Dkernel-hwaddress \
> -               $(call cc-param,hwasan-instrument-stack=3D$(stack_enable)=
) \
> -               $(call cc-param,hwasan-use-short-granules=3D0) \
> -               $(call cc-param,hwasan-inline-all-checks=3D0) \
> -               $(instrumentation_flags)
> +kasan_params +=3D hwasan-instrument-stack=3D$(stack_enable) \
> +               hwasan-use-short-granules=3D0 \
> +               hwasan-inline-all-checks=3D0

Let's put these kasan_params parts after CFLAGS_KASAN.

> +
> +CFLAGS_KASAN :=3D -fsanitize=3Dkernel-hwaddress
> +RUSTFLAGS_KASAN :=3D -Zsanitizer=3Dkernel-hwaddress \
> +                  -Zsanitizer-recover=3Dkernel-hwaddress

What's the intention of defining RUSTFLAGS_KASAN for SW_TAGS if it's
not supported by Rust? Should this be removed?

If this is just a foundation for potential future support of
Rust+SW_TAGS, please add a comment explaining this. And also please
put the patch that disallows Rust+SW_TAGS before this one, if you keep
RUSTFLAGS_KASAN.

>  # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_=
mem*().
>  ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y=
)
> -       CFLAGS_KASAN +=3D $(call cc-param,hwasan-kernel-mem-intrinsic-pre=
fix=3D1)
> +       kasan_params +=3D hwasan-kernel-mem-intrinsic-prefix=3D1
>  endif
>
>  endif # CONFIG_KASAN_SW_TAGS
>
> -export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE
> +# Add all as-supported KASAN LLVM parameters requested by the configurat=
ion

Nit: dot at the end.


> +CFLAGS_KASAN +=3D $(call check-args, cc-param, $(kasan_params))
> +
> +ifdef CONFIG_RUST
> +       # Avoid calling `rustc-param` unless Rust is enabled.
> +       RUSTFLAGS_KASAN +=3D $(call check-args, rustc-param, $(kasan_para=
ms))
> +endif # CONFIG_RUST
> +
> +export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE RUSTFLAGS_KASAN
> diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
> index 9f06f6aaf7fc..4a58636705e0 100644
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
> index ced405d35c5d..c24c2abd67db 100644
> --- a/scripts/generate_rust_target.rs
> +++ b/scripts/generate_rust_target.rs
> @@ -192,6 +192,7 @@ fn main() {
>          }
>          ts.push("features", features);
>          ts.push("llvm-target", "x86_64-linux-gnu");
> +        ts.push("supported-sanitizers", ["kernel-address"]);
>          ts.push("target-pointer-width", "64");
>      } else if cfg.has("LOONGARCH") {
>          panic!("loongarch uses the builtin rustc loongarch64-unknown-non=
e-softfloat target");
> --
> 2.46.0.184.g6999bdac58-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeA_GOdqidEhP81TvwiSSgJNEoXa85ooqVpfPOk3v4S0w%40mail.gmai=
l.com.
