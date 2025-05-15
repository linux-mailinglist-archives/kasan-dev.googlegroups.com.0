Return-Path: <kasan-dev+bncBCMIZB7QWENRBM5PS7AQMGQEE44U3DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 93FF1AB858B
	for <lists+kasan-dev@lfdr.de>; Thu, 15 May 2025 14:01:57 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-54c2a5fd572sf359639e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 May 2025 05:01:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747310517; cv=pass;
        d=google.com; s=arc-20240605;
        b=dUT9yG/VIDGS0K2atBD0SlX8ki6WdGTwaF9UmlI5XYJ7Aj0Eq19a95SOnQSGweZdMa
         JBQXQnXqB0W62zFrkj/863x1FHJqFKbfICcavtdEusov2/s5PepVEWTNuxMTg/qL4rEa
         3c4e9o/Xr4gXUl8WViEkgPbqWHww8Kc0LYGiGwGrLaZX8ubcyi8Kqnvc0OtZZAQEddA2
         LR6l137DY8aMe4gk90WnqR19TJSXwC8i81GG/xxGAhq8iKSUxyyg092quktUyACY5ya/
         6RyjNQLaQ8hZFcc5lfbECK4sKz6vsUzN/RQIu87PKvyrRx/6L+W0eMSE9aarGEkUYQ6W
         rzbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QZi3WpO4DtMKD3eB7RcjZoXoNNpH/Jo5tQ+CvKMtSf4=;
        fh=xES7aVhB/pandwZdLXV/v+fag54os6mOc5gV2eTTL40=;
        b=gr66dj1puuzp19ifc0SRvlBFxRpaFrUyRJjvlRq6lbnBA9+2fYsWAmW40dILlbemsy
         807NpecKkN3xkdnOy86SEL7y7BOdNGpF9Ocv315XDw/RRWGb5a4TKg86h4sQlMAphcNs
         QlFZsENWK1t6HUeqd8jhAv9gGxnHVcqul3E7YuaJOZSVSFUdelnN91ttCWCJFbV7jFDK
         8Ms3G/LDRIFLwgX1Ecy/pNlenVUy4IfZ6F9T1HttSlBne4cCS8FWAd2Yzh+gIwvYayE4
         sw7o1pzyiTJ/TgzRbdj72G/1mGSCi2Jcka/81edhihv57zwTTuWkJuK+sF05GxOqUSrj
         CJ6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TBedqrj3;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747310517; x=1747915317; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QZi3WpO4DtMKD3eB7RcjZoXoNNpH/Jo5tQ+CvKMtSf4=;
        b=IVEwqXeamJpDeyM1CuwxkG5WrCnmEU8sfJFM516UptnSOqd/kT1Rk0nNqyGvcqgZ+c
         er+Na1gm58U3mLfD5Q38DipBpjA+aL3Kdet7pEX/PysQ1gQ63ZO5rAp53lelMjUBww1z
         Zeivazm2IMXGFYIw/sYy4adMxv4xQIipSVe4ongeDwQl2ippXgd9DpXJAdlrCEBrhMDO
         8Zq9Z5RApUd2Fz52zjdIgEp/cZBfHeHmrdB5YkKczIMTLMMJ66KX4BfvATNiiY5ljFYg
         rGE7l+EYaMbIfMcECGPdOUsdllWNbAcunyz/OE3zWHHAWVfWLW4ks2P6sU6BV4tzR3P0
         ilXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747310517; x=1747915317;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QZi3WpO4DtMKD3eB7RcjZoXoNNpH/Jo5tQ+CvKMtSf4=;
        b=btUhtG0djz4xtZRwOXgsEa081AeNR9Q/aGKh3oC5BqgiyJd1hjkTCDXQ9QrXDuiepc
         i7rBirfXXpofWQaimYo3bV9+/V57/pbRgC4IzbQwSqnUNN+w+uGbMhKEjezlUyrwMijo
         Q/loNzrOLJCc40T/259XoyC7o9TfwZkjvaOVcfStwaHf8sTh33oundfJoe5Wmy/Br0KK
         l3dTiwuPDd1XYwVKcvI3MDiMqdLr6UIVZ6bCaaFj8EDa68Wzm/vANPZv964hGap5jxoj
         eZP2KTT5WcRRyvsnu9VgaggcMWMW0Rbh1qcjDNqDNyx2ODCi2wP5JuLLxjXrr2MIRW1h
         3KRw==
X-Forwarded-Encrypted: i=2; AJvYcCWFVVbMGSFq3FgtpG5JhsKwV+7lT6EWRZOycyW1LEMrQiOw9LDF5L0isCFlgGW06iakMwfvKQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywv98cbS7gpOD2gSykhxmT0wVR4/MNS4Hj7hBysYOiZDyTyZ9W9
	ruU9DgqD6B8zReCOUAEfQajsv+szC0tSvRkdNRQivP9+DZmKkevp
X-Google-Smtp-Source: AGHT+IHNKthX7t15mPExhirKOevRHOL/zuMozWe2+T1f7SkCKaP78urj3vaYDyuRv4+/vBzykXAHjA==
X-Received: by 2002:a05:6512:6201:b0:54e:9cb0:5008 with SMTP id 2adb3069b0e04-550d5fa612amr3001864e87.32.1747310515993;
        Thu, 15 May 2025 05:01:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHnxVjN2ZFZ7dvr3yMmu1sblXVYIBtisnf5CT+ZIOHf0Q==
Received: by 2002:a19:8c44:0:b0:54d:6636:3b22 with SMTP id 2adb3069b0e04-550dbe61595ls189985e87.1.-pod-prod-01-eu;
 Thu, 15 May 2025 05:01:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV0y2AYDOqcgYW/QeFUbtzarkT3bxWCBK/pd8++jxRY+kr53RlH6pCJEkbwFd1MwKqHYIUYbZdAKyI=@googlegroups.com
X-Received: by 2002:a05:6512:6508:b0:549:8f49:3414 with SMTP id 2adb3069b0e04-550d5f7ad36mr2319390e87.6.1747310512949;
        Thu, 15 May 2025 05:01:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747310512; cv=none;
        d=google.com; s=arc-20240605;
        b=GxvW0I0yeF7DsHLZfU3SHrcQYXt1iw49KuM2bbX2clUr9DwCExY8sl1Q0m41daajr0
         B37j+c0YvJ1tZjmAHyUzLtlCi/uBjByr8OZHou6U19v1hnn42jehroTTvtpubjRLdQSW
         JQDMiWOQPkIV7C8ouNps/H+p2ozZK+WVUWP8id6rjkl+LuKiAuZnShYwofFMBraSPg31
         u4oa0CHH+njh2LYqacU04i3M9ydpnGbEBW+FGeO42tZSY0Dom8mUDUlAmMO65EbKC/6c
         sTMVaEHvf3t4L7TIFV3KWwiLd3seUe4yV3PkQP4F5NHC+pHeBxmdc9jb7/grDS2yAcwy
         0qbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SnTjnlgUmpVWJ6YWjJU//zRxWhIuxh7JMTjWe20f0OY=;
        fh=Bc3F9dKz5csgFzAVP/ia4Wzjvx6/s+S+UZcFxhTfxzE=;
        b=WsC9nw7Cmz9mjVLP/I3+p+J2Opv1PrliHiG9iBN45OoY4NDtfmbObrby8FWTv2ag37
         njjtK3c8vidBeJ4vS3JCl/fWINPYEG4zgCw3TBQYGScDbxr0Wa94tgFoS9w8PaOiP08V
         JUTWJgiDS8Jih3d7pLihLJ2WaTBqVdeWSQg9FuFPaljSga9FByezhP8Fnlz3tA2rBv1x
         KKiT6/PtHHrvd4PCdn9SX5M7UpKruq4TR82xg8K2WH5Fgq8kjyiWn+f91XyxoMm7UKRQ
         Ui+BZrk/rbpOkE20LH3OI6Fs7hFb7HsVN4D/SwNK/ZnaAHovM3JTfw8BvvCBwXYbsxlt
         KBxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TBedqrj3;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54fc64d5ae7si210227e87.8.2025.05.15.05.01.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 May 2025 05:01:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id 38308e7fff4ca-326ca53a7f1so8495201fa.2
        for <kasan-dev@googlegroups.com>; Thu, 15 May 2025 05:01:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW0pjrb/bY7Bkn9cUpsWpQdRk8XpdwKONtIO76LYNo3IMJP+bjoS4zbmdQwBzDCCzHw4yvxlouEArA=@googlegroups.com
X-Gm-Gg: ASbGncvHlZmODNp2Zwy5P0CKAiAM3yHvSX+N14fjyJgefC8Fe6Vtu634zVp2HCd+9/e
	Yi6LzOoWs0wdlYmn7PPJqWmH6V/H47QgYGNfYVg0K3mJBir776vJa/mYwS2TkDfZ8U9SoW21cNW
	bhm8ex6SS7Otpg7neW2GJzuCglF0PLjYy0gLy8MiDf1ggqCSt+Jf3z28eDMwWooNywmA==
X-Received: by 2002:a2e:a542:0:b0:326:c07e:b0a4 with SMTP id
 38308e7fff4ca-327ed0de53bmr28047271fa.11.1747310510182; Thu, 15 May 2025
 05:01:50 -0700 (PDT)
MIME-Version: 1.0
References: <20250501-rust-kcov-v2-1-b71e83e9779f@google.com>
In-Reply-To: <20250501-rust-kcov-v2-1-b71e83e9779f@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 May 2025 14:01:39 +0200
X-Gm-Features: AX0GCFuQowmy9iaNX31ALvCLpL5T4nDokRyS7Qih7uVxXxqrT3ubbzv9Q8-xB8w
Message-ID: <CACT4Y+Yzmd7BtrpqUPrbXAAGzMnO0YKZnhVxLgyyXEftscEUnQ@mail.gmail.com>
Subject: Re: [PATCH v2] kcov: rust: add flags for KCOV with Rust
To: Alice Ryhl <aliceryhl@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Miguel Ojeda <ojeda@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Trevor Gross <tmgross@umich.edu>, Danilo Krummrich <dakr@kernel.org>, 
	Aleksandr Nogikh <nogikh@google.com>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev, 
	Matthew Maurer <mmaurer@google.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TBedqrj3;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, 1 May 2025 at 14:16, Alice Ryhl <aliceryhl@google.com> wrote:
>
> Rust code is currently not instrumented properly when KCOV is enabled.
> Thus, add the relevant flags to perform instrumentation correctly. This
> is necessary for efficient fuzzing of Rust code.
>
> The sanitizer-coverage features of LLVM have existed for long enough
> that they are available on any LLVM version supported by rustc, so we do
> not need any Kconfig feature detection. The coverage level is set to 3,
> as that is the level needed by trace-pc.
>
> We do not instrument `core` since when we fuzz the kernel, we are
> looking for bugs in the kernel, not the Rust stdlib.
>
> Co-developed-by: Matthew Maurer <mmaurer@google.com>
> Signed-off-by: Matthew Maurer <mmaurer@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Alice Ryhl <aliceryhl@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> I did not pick up the Tested-by due to the changes. I verified that it
> looks right under objdump, but I don't have a syzkaller setup I can try
> it with.
> ---
> Changes in v2:
> - Ignore `core` in KCOV.
> - Link to v1: https://lore.kernel.org/r/20250430-rust-kcov-v1-1-b9ae94148175@google.com
> ---
>  rust/Makefile         | 1 +
>  scripts/Makefile.kcov | 6 ++++++
>  scripts/Makefile.lib  | 3 +++
>  3 files changed, 10 insertions(+)
>
> diff --git a/rust/Makefile b/rust/Makefile
> index 3aca903a7d08cfbf4d4e0f172dab66e9115001e3..80c84749d734842774a3ac2aabbc944a68d02484 100644
> --- a/rust/Makefile
> +++ b/rust/Makefile
> @@ -492,6 +492,7 @@ $(obj)/core.o: $(RUST_LIB_SRC)/core/src/lib.rs \
>  ifneq ($(or $(CONFIG_X86_64),$(CONFIG_X86_32)),)
>  $(obj)/core.o: scripts/target.json
>  endif
> +KCOV_INSTRUMENT_core.o := n
>
>  $(obj)/compiler_builtins.o: private skip_gendwarfksyms = 1
>  $(obj)/compiler_builtins.o: private rustc_objcopy = -w -W '__*'
> diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
> index 67e8cfe3474b7dcf7552e675cffe356788e6c3a2..ddcc3c6dc513e1988aeaf07b8efa106e8dffa640 100644
> --- a/scripts/Makefile.kcov
> +++ b/scripts/Makefile.kcov
> @@ -3,4 +3,10 @@ kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)    += -fsanitize-coverage=trace-pc
>  kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)   += -fsanitize-coverage=trace-cmp
>  kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)         += -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so
>
> +kcov-rflags-y                                  += -Cpasses=sancov-module
> +kcov-rflags-y                                  += -Cllvm-args=-sanitizer-coverage-level=3
> +kcov-rflags-y                                  += -Cllvm-args=-sanitizer-coverage-trace-pc
> +kcov-rflags-$(CONFIG_KCOV_ENABLE_COMPARISONS)  += -Cllvm-args=-sanitizer-coverage-trace-compares
> +
>  export CFLAGS_KCOV := $(kcov-flags-y)
> +export RUSTFLAGS_KCOV := $(kcov-rflags-y)
> diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
> index 2fe73cda0bddb9dcf709d0a9ae541318d54754d2..520905f19a9b19631394cfb5e129effb8846d5b8 100644
> --- a/scripts/Makefile.lib
> +++ b/scripts/Makefile.lib
> @@ -169,6 +169,9 @@ ifeq ($(CONFIG_KCOV),y)
>  _c_flags += $(if $(patsubst n%,, \
>         $(KCOV_INSTRUMENT_$(target-stem).o)$(KCOV_INSTRUMENT)$(if $(is-kernel-object),$(CONFIG_KCOV_INSTRUMENT_ALL))), \
>         $(CFLAGS_KCOV))
> +_rust_flags += $(if $(patsubst n%,, \
> +       $(KCOV_INSTRUMENT_$(target-stem).o)$(KCOV_INSTRUMENT)$(if $(is-kernel-object),$(CONFIG_KCOV_INSTRUMENT_ALL))), \
> +       $(RUSTFLAGS_KCOV))
>  endif
>
>  #
>
> ---
> base-commit: 9c32cda43eb78f78c73aee4aa344b777714e259b
> change-id: 20250430-rust-kcov-6c74fd0f1f06
>
> Best regards,
> --
> Alice Ryhl <aliceryhl@google.com>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYzmd7BtrpqUPrbXAAGzMnO0YKZnhVxLgyyXEftscEUnQ%40mail.gmail.com.
