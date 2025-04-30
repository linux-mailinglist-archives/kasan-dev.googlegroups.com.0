Return-Path: <kasan-dev+bncBCXKTJ63SAARBKM7ZDAAMGQEE7FI5EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id A18C2AA4A63
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 13:55:23 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2ff7cf599besf6608077a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 04:55:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746014122; cv=pass;
        d=google.com; s=arc-20240605;
        b=YtEvzakw3phaPsOmfXd87aGrj+6GOzyfiN0YcM32U4ieiLm2MqSsyRNDRTXiHLXiM/
         9EqMW0K07fWC0e1NVj2SN7LNBbWd2JnYpaHwTQREgIIYq408GkEvQp1T98tTEADX0SXX
         YB4aHIKLWjkbi/+kSYUzwRK5cx+mkVKkoLIA8FpbOL8tsAyidT7TAyKLqIIf0QIFui2S
         6wkv/vhk4VhfZTp3bQ5Zupl7brJyZlc3CxarWC4FWiW9zePhP8i5Ad1p9EqWkYDZqmj1
         NHvNpomNkXu+/cBFlapMu9peR3SIP4Grj8Njcn+/bTBXL6CylbBY6ybmcojvqht8VSpE
         S3dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=udOjUqfwQ0Ne63SgHjV7DJBmJeny2sL5pp02LeKNbXs=;
        fh=UT+6LfOoL/muBFcWucQWfqqp9XPVnRs7k3cX2fBvLJQ=;
        b=MqyCYveIwUjpsCaalLI7H/fCzfH5gWGFviiKuFuHtw24mZJtyroFzHbnTf5xNRRGdT
         aW4qpIK75AJSeMH8TVenuuoczKi69/Dtxg9sqFS04wS8juxr8nT16GldxPdSe5Tl1lCF
         PSD9mVKD1fTUA0hcLDTClyrkWXE/kEbEYnF6ssv7RjZRHTAOdaOoTAgDuL4HMIwPl6ek
         Pb+q1nMtfddKzgsqp1JmEnxbSFi5pXuY1OibUR5dW1Dypc3Fki5f5enlgQ7VSQ62sK0c
         91FFq1aum+MdB5Cxwj2qSQNTRwVqjBiYadIZwOtCMNtGLM0zdxIXJq8MM1VWtQ/mC+40
         NKSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3NX5jCyt;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746014122; x=1746618922; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=udOjUqfwQ0Ne63SgHjV7DJBmJeny2sL5pp02LeKNbXs=;
        b=XZ6hyQH32tnp9MJCqYoEIW6zxKgWmRb5iFXjiE/gwTGMmzQtXUM10FXgxlo6kr2Xlo
         fKA9PxEa2lhaq4djwDBe5mU8TcEn5oCJaODqCwmPoIkaAbNCLZq//TJmLSg+nnhNIReU
         U/Dv8oSPtLpxuvFqIZTF/htC9xMOzlRHQiEXeAonK5Nq9V6GqMn9OXwQbq+ySGQ7seRs
         /QhlQuBSXUUiHxGtj0agcpdltf9ZOB71rxxge0e2oqadoqNDd3akCbS2VO9opfKidOpG
         7nuchw+oVw0/Jk9Wq5QSztGRRT2OOHaIWfQGHj2olJszzKt640YH69t1XXP/Ddrf2ub7
         QZIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746014122; x=1746618922;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=udOjUqfwQ0Ne63SgHjV7DJBmJeny2sL5pp02LeKNbXs=;
        b=IYOjnulYePipWX3yo+zSlZeeHfg1yg6uUJgbR3HMlfLc/8kFcY66H6+W0TrO21weeY
         LX4Z5VtMvbdYk7Z3vWCcRJ4oifGv5IURNznhl5sstjpSIEi9HSqDJJ+2OtZ8HoT87ZPI
         gW8wfMcPY5IR3OsPu6Qp8oLSkkvt6viREqEeHu1SCxne+UCp2IOoW8A5jDfvSlMUZ7Tv
         aYanYiFxzJKEpcmqz93dPxcjXE4rSC6WdigYIWOxd5+gQtm+ZA3ZV3FkoovGNdVQhXIr
         13QVUcNeo53CBC2J+2IUK7erHtZHwLDtvlMQl3bzAR0m4oYQwlLaW0aBObTT1cPsdrwH
         poRw==
X-Forwarded-Encrypted: i=2; AJvYcCX+mvGc6uSyBDlFOsOve+r07jd7SOvOpk9PgG0IRQLywlHPr2x8hrpndppofdttfoDoqDPN1g==@lfdr.de
X-Gm-Message-State: AOJu0YzwGA6qL19b1KcNLh0LczmKGZ9yWH51pPK5W3cwhCsD/UnvPEIG
	5T7uOA/ActB5Z4upp4J4GI1Mm6KXpzie9JCcqg8uCBpZnn6U5Six
X-Google-Smtp-Source: AGHT+IE6bWpXXfZCK2T/NZ+Q84Dj4DBI6O5Nth8A5ypL4FS5JqU3jHJfj7FuE7/lrfygYUrePTlXAQ==
X-Received: by 2002:a17:90b:2744:b0:2fa:e9b:33b8 with SMTP id 98e67ed59e1d1-30a3331f0e1mr4297888a91.18.1746014121724;
        Wed, 30 Apr 2025 04:55:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHqRjDsZjCWAHBTUMpywrqnOsgpfUl0139RAYuXjwKkdA==
Received: by 2002:a17:90b:5210:b0:301:1dae:af6 with SMTP id
 98e67ed59e1d1-309ebe2f227ls344591a91.2.-pod-prod-02-us; Wed, 30 Apr 2025
 04:55:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXOVsnB1jvuiSvHi77mb7wtnaOzYBx6iNL5VfTk1E7s1frIlM5WAbbPBE6pfWuDYW1WIlFuEtreTs0=@googlegroups.com
X-Received: by 2002:a17:90a:d883:b0:2ee:b4bf:2d06 with SMTP id 98e67ed59e1d1-30a3331ef58mr3716396a91.19.1746014120524;
        Wed, 30 Apr 2025 04:55:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746014120; cv=none;
        d=google.com; s=arc-20240605;
        b=ZCZO9s+3tWMGkNkaACygo1lQyEdaPF/19PZdS0vNKoxx7PLapHKKqawc71WrQyPBa0
         wFtohJdPX7iippne+he4SC1E2rf+eX7L22JMPCs7x+kweMxqQYS86YVBn8dVlN9n9/Jq
         bWhwigWKtuueLKeI3uyCTPQnwQKNWZrOFK6uft2sXtOTZM1tAJ7zdMJiDCJXDgDropwt
         rzrUB/wxyr3fqOQqdYTI5F9JmlVxESaOmrREanbrOHCHdpq5XYsH0Qe9L9Li6bKjHbHC
         ArmqI25Gdzi/VpxpE/FA+MqyaNwml6LBz7rhrpKMCWpuR/6mi4p8MT2m6JYgP6pUNeg6
         BtuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XuyGNzxgDiOkjQwKgLR+DPXNIJCg0WiL8KUtY79VEQs=;
        fh=Wh814Aixvye5WbLRe7XrdO699rnKzQjGJWTLE+c0to8=;
        b=EwNIYd5I6qKWwt+lVNaiw+0F1fEEROcs+YnBWeqllCXpzTDM+Hs3yPHs7Rliey0SWV
         AisljeMUwbK4zd+YaB2VIou/spWiVfnOTNKb9WqGU8rGnAC8pGede+u2cGt2iq+N90fY
         kD341NXExBWWjHKFQ9bKHVfQ7vAVFEXATYUmL6VoTDF0Ei8kOP/x5PMZLqR2vbpSE72j
         EvXo64TY6xx/rAnScxQhxcOJhRC30FT4yElocL612effvv0iydaQJzWilyhRJQDglMRH
         kQtRb1KmQBWAKmgArcxkZQUpeQvuowqjvLpqSIKXX+nPujWNx2L8+n82bozJaC8naJfE
         SpYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3NX5jCyt;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30a263eacdfsi253568a91.1.2025.04.30.04.55.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Apr 2025 04:55:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id 98e67ed59e1d1-3015001f862so5892277a91.3
        for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 04:55:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXsXHgwXzLCqq/Q9qRCsxkh6qfTDtTq/AyiY6k3Ge4VMK2giBa1uc3cOdg925dOUVyafvQaxtXgh0o=@googlegroups.com
X-Gm-Gg: ASbGncu8dZYThRDgnSPFPXxF2cKYlSAzdVV5SIibIlHZAhazay7xbSSMJU24J96YnIl
	RYiNBe3E21bUY+hmtxBkV3Or/fEjO8CDWApV32prRkTNbgQuMwxGu6x412k6vP3MsdlrVNg7Spc
	nXxQBtssAe3/ebJnkVwRoUU5gej2A/ZQkIB8hzTRfMGUARQtT0B/Fd
X-Received: by 2002:a17:90a:da83:b0:305:2d27:7c9f with SMTP id
 98e67ed59e1d1-30a3331eebbmr4689528a91.16.1746014119912; Wed, 30 Apr 2025
 04:55:19 -0700 (PDT)
MIME-Version: 1.0
References: <20250430-rust-kcov-v1-1-b9ae94148175@google.com>
In-Reply-To: <20250430-rust-kcov-v1-1-b9ae94148175@google.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Apr 2025 13:55:06 +0200
X-Gm-Features: ATxdqUGMpC2B1RGjyZnHvqdqDFG5FAFUqW_p8EIC04ZX-V4PP8t0Bammv6S-GJE
Message-ID: <CANp29Y4o8o6gz6GbM6NhP9sJUi94q29=aa+tLc1aCk0UVpgj0w@mail.gmail.com>
Subject: Re: [PATCH] kcov: rust: add flags for KCOV with Rust
To: Alice Ryhl <aliceryhl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Miguel Ojeda <ojeda@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Trevor Gross <tmgross@umich.edu>, Danilo Krummrich <dakr@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev, 
	Matthew Maurer <mmaurer@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3NX5jCyt;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::1034
 as permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

On Wed, Apr 30, 2025 at 10:04=E2=80=AFAM Alice Ryhl <aliceryhl@google.com> =
wrote:
>
> Rust code is currently not instrumented properly when KCOV is enabled.
> Thus, add the relevant flags to perform instrumentation correctly. This
> is necessary for efficient fuzzing of Rust code.
>
> The sanitizer-coverage features of LLVM have existed for long enough
> that they are available on any LLVM version supported by rustc, so we do
> not need any Kconfig feature detection.
>
> The coverage level is set to 3, as that is the level needed by trace-pc.
>
> Co-developed-by: Matthew Maurer <mmaurer@google.com>
> Signed-off-by: Matthew Maurer <mmaurer@google.com>
> Signed-off-by: Alice Ryhl <aliceryhl@google.com>

Thanks!

I've run syzkaller against a kernel built with the patch applied and
the tool was able to successfully obtain coverage feedback from the
Rust code, so
Tested-by: Aleksandr Nogikh <nogikh@google.com>

As a side note, in the resulting code coverage I also see a lot of PCs
from rustlib, which isn't the primary target when fuzzing the kernel.
Do you find it reasonable not to instrument rustlib with coverage
callbacks? For C code, there do exist some exceptions for KCOV, see
e.g. lib/Makefile.

> ---
>  scripts/Makefile.kcov | 6 ++++++
>  scripts/Makefile.lib  | 3 +++
>  2 files changed, 9 insertions(+)
>
> diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
> index 67e8cfe3474b7dcf7552e675cffe356788e6c3a2..ddcc3c6dc513e1988aeaf07b8=
efa106e8dffa640 100644
> --- a/scripts/Makefile.kcov
> +++ b/scripts/Makefile.kcov
> @@ -3,4 +3,10 @@ kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)    +=3D -fsa=
nitize-coverage=3Dtrace-pc
>  kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)   +=3D -fsanitize-coverage=
=3Dtrace-cmp
>  kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)         +=3D -fplugin=3D$(objtree=
)/scripts/gcc-plugins/sancov_plugin.so
>
> +kcov-rflags-y                                  +=3D -Cpasses=3Dsancov-mo=
dule
> +kcov-rflags-y                                  +=3D -Cllvm-args=3D-sanit=
izer-coverage-level=3D3
> +kcov-rflags-y                                  +=3D -Cllvm-args=3D-sanit=
izer-coverage-trace-pc
> +kcov-rflags-$(CONFIG_KCOV_ENABLE_COMPARISONS)  +=3D -Cllvm-args=3D-sanit=
izer-coverage-trace-compares
> +
>  export CFLAGS_KCOV :=3D $(kcov-flags-y)
> +export RUSTFLAGS_KCOV :=3D $(kcov-rflags-y)
> diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
> index 2fe73cda0bddb9dcf709d0a9ae541318d54754d2..520905f19a9b19631394cfb5e=
129effb8846d5b8 100644
> --- a/scripts/Makefile.lib
> +++ b/scripts/Makefile.lib
> @@ -169,6 +169,9 @@ ifeq ($(CONFIG_KCOV),y)
>  _c_flags +=3D $(if $(patsubst n%,, \
>         $(KCOV_INSTRUMENT_$(target-stem).o)$(KCOV_INSTRUMENT)$(if $(is-ke=
rnel-object),$(CONFIG_KCOV_INSTRUMENT_ALL))), \
>         $(CFLAGS_KCOV))
> +_rust_flags +=3D $(if $(patsubst n%,, \
> +       $(KCOV_INSTRUMENT_$(target-stem).o)$(KCOV_INSTRUMENT)$(if $(is-ke=
rnel-object),$(CONFIG_KCOV_INSTRUMENT_ALL))), \
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

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANp29Y4o8o6gz6GbM6NhP9sJUi94q29%3Daa%2BtLc1aCk0UVpgj0w%40mail.gmail.com.
