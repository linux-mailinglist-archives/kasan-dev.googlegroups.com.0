Return-Path: <kasan-dev+bncBDW2JDUY5AORBMHKSO3AMGQEXVMHDTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 35364958EF2
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 21:57:38 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2f1752568cfsf53551461fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 12:57:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724183857; cv=pass;
        d=google.com; s=arc-20160816;
        b=uyaUeNYxmPJNK9EAB8Tt6oT3ry/V0iUANk4pNbPuthaiAbNgN2BZCG6pDMtKuh/jGe
         3bMMK1BOqXTQ35hkO2EPUW8uUTCrsAs4Bkc81eMlrh+WyKtMs4SDTjzAGEKcR/mI8glN
         KZPbNjMVIqflXwVK9pq7qWTrevuYL8q7V500lczFlzxAbQHvoXPfzb5+phfrxLMXUKF2
         BUGCxKj5+2CTMcVbcwaiB0IULWJCJwSakDL/JGPjbmMrLq1YbPmqYd9Zt2nWxvbDCFbA
         782nO3Kjqgg+/Dar3dFmtt6kH8clobi0dKXuOtooWVJrHiTzki2NE9PzHZ4z+KNnMEzB
         SKpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=vc5EEcbWvzxplVXKzo9CT2KcsLtcHvk6Lmf2D+oMU68=;
        fh=27Zawu4uvTSV2QNhaH0zHNZUFtJB5oo734Vrwd8W4fk=;
        b=kadHlS6zDHShl6zLaJDVAbPyaclRJE4mRcpDTFJXRJUW7kOMJ7tgerEaL4Ozn7SxhH
         2IsoOg2Q8QfBSpnNV4rwkTRp3buZK+GYCfu3WMVHKV/OzTLyxThf0NL8pstxshgpfb1P
         V8k+q737NCNMVGywfT5bPb+kRKc9bUtfyQMpySRTujmFgU/8v7PvOEkbhMBkrZEVM7aN
         lyc+dSp5wPOggTuvLhxwz6NiOCx1nFl1oCdxWYWTSHnqkEu5Ud24SsQex7x6zZL7zykU
         jDuGErS5gdkxh75TMUH14+KoyL4DZ6tHQADgfoIQsIY71m6cLpW0bS/I1g5mSbTItHgC
         4X5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EcIf0c1A;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724183857; x=1724788657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vc5EEcbWvzxplVXKzo9CT2KcsLtcHvk6Lmf2D+oMU68=;
        b=B1fca8r+y/iGn1ld3RHDlLkcn8rLKC6UDRwJQiKhoNUxv4GyENI/T3s5SaBjKt9nsk
         540WO0C7Vu6HSlXCv7l+ChVVcPwc6Y6Vt/+TYK5ka/eNkSxVDMBUKJQwRiDy2zL8GkUc
         xs2dJxZ1cvXW1KzZrfN4+iYGgbYukFJXXhVORh1uxTdgge1XLTvCGbcAROEST2mpsIjU
         mBFwMaiwtWteRs6buYtVNaI8p9h0yf+IOarhKQBdFvkwx8ypr1F2XQtkXLJRIzH+3Odj
         k+ZgWcW8NdaXtbByJZXu+qpF2NDkAlC3b1WWIDUlXMfr08tk3MrJzpxb3o9STl+rjQ/H
         Wtxg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724183857; x=1724788657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vc5EEcbWvzxplVXKzo9CT2KcsLtcHvk6Lmf2D+oMU68=;
        b=lkzJzjZjgZIpEJCZv+5U09klxgVPGN0dnYIFX0cOjB7+a18x+KZQxsA6qOsOAWmIoQ
         MM0dhcWF9RTpx6xkdBl1DRxUcwd8NYuaBj/GgaczTnZOqrTT10AFL7c0FmN707n/QOMb
         HjWXauaGsyevzfzeNIgPwliPoul0sxaV8Wo3eR/ynYJaKUaSk8YVxzNj2ifyvPAz5XPt
         7TLjWnDRZY6D0JaDrCQUpcdmN6ShKotyvLVksXSuASPdEOTubvbIaEHp5wL9vXPwDopN
         4lC6kbOd0gazQSHqDTGtAZPtwQI18YW41yjy3kheIyLLYxd3Nm4qAGSiz181Juf8kKje
         4CJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724183857; x=1724788657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vc5EEcbWvzxplVXKzo9CT2KcsLtcHvk6Lmf2D+oMU68=;
        b=WbdAdJ/eP8TWpRMZcTmrJaR8aDAfYpP1/qMDRW8w3mc5fYF4mPHKsm4us+IuSUdbJI
         L/zN9NhB1Wgu1O8oLU/+mqhPJWq7SE85etU/cgN3yMi5zKwcVZ9X1gs4eKR82l1nCSsS
         s6nhYLwgiNyW0HQwnSZ9VeBwoLf/2Tmv5ZI9uCcZPI9GaiZdRw8BaZUnvRAH5gUb0ZX6
         fUcJmOFytOZlaKubEdFyY/6n0GcjXERNN6ShMUoiQxGB7eRyYYxzw0eaKQnwAGIl4bkm
         Y8LHfeBWzQXkUDbIsxpXysuCzNemBAVK6XLovNHmu6VnQjVw3hRCr4DqKvPv23jtxszg
         /v1w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV7QWFgr/LY19eOXI54seiXeeuMz6zdUFOT0rPHDVsOzawuR6TjjduHaATjVKSBfeo2x6OeGQ==@lfdr.de
X-Gm-Message-State: AOJu0YwpIkv9S491KqMqyq8uFUm++P0fjvAAGP5T+J6E7st9X90/p39C
	/GAIRBI79jfHLeBf9T+SkNo2vKRx2Vf9A0ruYMVFiaoKrRGuI9r9
X-Google-Smtp-Source: AGHT+IFvrkbM+xpXih01Xubiy3hHgA8JhKgeLwv2bMrJyTcyu3fWitYIMweALRNKEI+ktv9BNBVCGg==
X-Received: by 2002:a05:6512:ac6:b0:52e:74f5:d13 with SMTP id 2adb3069b0e04-5331c6b0586mr11523164e87.30.1724183856767;
        Tue, 20 Aug 2024 12:57:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e0e:b0:52e:9923:a1c2 with SMTP id
 2adb3069b0e04-53307d3960als883741e87.1.-pod-prod-03-eu; Tue, 20 Aug 2024
 12:57:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2KOYaZq4uZvwy049J198koXCdhzkUwflHLa9yRJ4haVIx1+/6utB+H+RC5aYP2bpjpq0+ZnuUxo0=@googlegroups.com
X-Received: by 2002:a2e:4e1a:0:b0:2ef:1bbb:b6f8 with SMTP id 38308e7fff4ca-2f3f8953891mr420111fa.32.1724183854394;
        Tue, 20 Aug 2024 12:57:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724183854; cv=none;
        d=google.com; s=arc-20160816;
        b=Ala019d4VUE12bbapolM4LG4AIjsG3x6DNcbixtqYhRUjMVp2L8I1Ea1IE6ET+pqkC
         9XTOZEtHzuP92lMLkzg4Qbyck1HM/KdCDh8Mva9tI9hQIlX5LzkeDOQMdkJ4DAHTFxOX
         c+tWfklJGlhvUXsLyShMYOMMzMwYTkhaBM7AeSnt9DDYbENPSl15FHYx4u+oq0MNPdLr
         kL66SjizyBQmEAMWTl+xckXmoYKowVp/tSUFfTacWfnwM42/2GabLCTUwJbmowHx2orF
         zbZ01o/RrnMqI4cB4EqnAdDPoNwBo5aM1PcJVjDxLC1QRmxH3ExHuZ8O556jS/8URTZu
         WAQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/KPBbBX5wpC6PVE5IR8WFqGQpyvLg+k2OvzqLlHMens=;
        fh=Dxm+wd4Y2vuyOdxlIK398Zqhnq6FSWo1NBW51OtcDk8=;
        b=s4FqOBTtKhklpAYtv2VzPHOz0yPxewb3kvDOqclVkn1GUZkPggtjxPrgLm7yQ0ZknC
         NIFb6/oLHKxc2d4S7AV2d/A3c23svrGbQnEdkegEqgRBWWRrevp5iVHn0VMZpm5tUUTw
         QMGWbrdS1tHUU8J78GGkyF2BDoFZ6v2E+HeJfzM9VvZZ252Nr4HUnzz2O1yWRC4219Qq
         nUVkjqNLOB6XBLfHfhsjhyk9pj0Rj5bBLnYAchMb0Euy6yY95qQPMLVwqJQKNxbGicD1
         2vEcLZVZ80o+Jaqox38C++DMdDpXDblsOUcTMG1KwOjOyE+7MMUigglM4BLaOUrCYgY9
         rPsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EcIf0c1A;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f3b77063fdsi3068801fa.4.2024.08.20.12.57.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 12:57:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-3718b5e9c4fso3030256f8f.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 12:57:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU2PDJajhENN9uqsymWqORC3Q7S3e/UQNuPmljaV52ffZPt+tOqUKEcFXCvOWz50kbLlAQ6UZ05Ae4=@googlegroups.com
X-Received: by 2002:a5d:408f:0:b0:367:958e:9821 with SMTP id
 ffacd0b85a97d-372fd5b8d37mr64604f8f.29.1724183853281; Tue, 20 Aug 2024
 12:57:33 -0700 (PDT)
MIME-Version: 1.0
References: <20240820194910.187826-1-mmaurer@google.com> <20240820194910.187826-4-mmaurer@google.com>
In-Reply-To: <20240820194910.187826-4-mmaurer@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Aug 2024 21:57:22 +0200
Message-ID: <CA+fCnZeQ1d3chWWCxYwPY=WPfPs12kXTBDgbfE9c1t=HADGYRw@mail.gmail.com>
Subject: Re: [PATCH v4 3/4] kbuild: rust: Enable KASAN support
To: Matthew Maurer <mmaurer@google.com>
Cc: ojeda@kernel.org, Masahiro Yamada <masahiroy@kernel.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alex Gaynor <alex.gaynor@gmail.com>, 
	Wedson Almeida Filho <wedsonaf@gmail.com>, Nathan Chancellor <nathan@kernel.org>, dvyukov@google.com, 
	aliceryhl@google.com, samitolvanen@google.com, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, glider@google.com, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Nicolas Schier <nicolas@fjasle.eu>, 
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
 header.i=@gmail.com header.s=20230601 header.b=EcIf0c1A;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b
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
> Rust supports KASAN via LLVM, but prior to this patch, the flags aren't
> set properly.
>
> Suggested-by: Miguel Ojeda <ojeda@kernel.org>
> Signed-off-by: Matthew Maurer <mmaurer@google.com>
> ---
>  scripts/Makefile.kasan          | 57 ++++++++++++++++++++++++---------
>  scripts/Makefile.lib            |  3 ++
>  scripts/generate_rust_target.rs |  1 +
>  3 files changed, 45 insertions(+), 16 deletions(-)
>
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index aab4154af00a..97570df40a98 100644
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
> @@ -41,39 +46,59 @@ CFLAGS_KASAN :=3D $(call cc-option, -fsanitize=3Dkern=
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
t.
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
> +CFLAGS_KASAN :=3D -fsanitize=3Dkernel-hwaddress
> +
> +# This sets flags that will enable KHWASAN once enabled in Rust. These w=
ill

Nit: the kernel doesn't use the term KHWASAN, it's SW_TAGS KASAN or
Software Tag-Based KASAN.


> +# not work today, and is guarded against in dependencies for CONFIG_RUST=
.
> +RUSTFLAGS_KASAN :=3D -Zsanitizer=3Dkernel-hwaddress \
> +                  -Zsanitizer-recover=3Dkernel-hwaddress
> +
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
>
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
ion.
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
kasan-dev/CA%2BfCnZeQ1d3chWWCxYwPY%3DWPfPs12kXTBDgbfE9c1t%3DHADGYRw%40mail.=
gmail.com.
