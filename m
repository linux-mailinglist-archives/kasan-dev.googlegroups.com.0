Return-Path: <kasan-dev+bncBCXKTJ63SAARBPPY2LAAMGQEMMAK6DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BDF9AA722F
	for <lists+kasan-dev@lfdr.de>; Fri,  2 May 2025 14:36:15 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6e905e89798sf37974086d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 05:36:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746189374; cv=pass;
        d=google.com; s=arc-20240605;
        b=P1upfpMdf+j1U6xCzZjwZtyO2ikQS9SFKnb2VBOUR+2kZeoEYqaIySEnfDCcslfDOH
         Os2I+6CFkLBSQx2W28qgIBssnS7XeX/EYcP77EpL+9tqnzO2JbJOhKkvpkwOMjTPJ53j
         LJyepu4WEnxkVdKrerND9Bu+LeX4XnFY/oOQ1omybEfN3GR57/zQrdnNQJoJvqC0PVUN
         zZrS8OJsEFiuoqNu/jXA+m/9DhtG2if/ct7xCp996LyTGJ4ZK8RmVyobqbvQxtpdUiGS
         XLMkLibInd5QQsSC/pPkciskUw4V+pUpzJmjWwnaI3A2urapUVKlkBh7MxOscmzi2+iW
         p26A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BxeCTapB0rQc8GP/bg5VqHpNaXE1IuOm9YA+3rE4DVg=;
        fh=rA5PC52btETUrv+rn6l6TA3e1nPduur3GvnkWxBZvyM=;
        b=f/zhDyEXWcBFScLgoqcyMR4qVshH1HmL4Tleco1QxEF+xrXxTDoyEqBChxmx8EsgSG
         GUYBcFT9LxCTh2oqcw53ec2Ghn2E0GcbGe72iLGYEpfzs7rO0jl7gCBRlmgMIZD/Sbg/
         qmKRu6N5X2r/K9TwCOOBHn1+t7UAYSId7jU9iPAPGG6Lew7NsUgPsoBzAqtnKeAP0ZPH
         /WncWRdegFYvv64qInqQ2t7Dmv1Kr5L6P/sul48v4j14LkZ+qBWrxMB+gqAHqEGo1CIB
         qyawQBL52p+AatATIdw9s/+fCZT7GA6uvvxCBGFHJPWaKdKR3XMBo1ItPhZ9TIa/kLB2
         hNRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NEmg2smp;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746189374; x=1746794174; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BxeCTapB0rQc8GP/bg5VqHpNaXE1IuOm9YA+3rE4DVg=;
        b=LkTDp9m0A6V9egh8ikYl5HDl2v84ZwV1XcYUxgqn7U4T4kkN4hNtxnCi9HUHnUsQhB
         AWx748DL3B3sZge/U7QLbCaV8s3ZXgodCZ1Ti3nMDxPrL0AXEkxqOFA0xkqqbwtF/ztN
         Hlt46dOtUBQMWYwWIq4j94T7SDWoViSaaJyj+GPtOf2eBTDbi+fKD/QDpGwQZ1+CjZvk
         qjrtLGnJipMSFszuSHNEwqMYbam44myU92d/khLE+doy6wXJJpcT0LdnAu59AdapIrKE
         VuE3FvI77ksvb8FSPHfGOgswUPmd8tamdEEt0s76ex6lt+GyoJ9s4BjCYbV2PBcWfNDh
         DytQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746189374; x=1746794174;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BxeCTapB0rQc8GP/bg5VqHpNaXE1IuOm9YA+3rE4DVg=;
        b=lzTLTT8HhsG4/u6h3a2fxZTMHvkP7CPz6MqG/3hLDFILvLsU87mjN1ksueYPhm+SK1
         A0i5mqKM1PoYI0earzROzWNphtcn6eTNceekRFb+v1SEdmyT9jTHr1xhpzyi3T+idFQD
         tzYK/yLnYnGG26e9ZgGebfXiFGKrg3cX2iJud3f8nfGmrz0Uht6hcGkZvLK2IfJJ7aRx
         3RamB2q/Po6BzBETyA1g0j0DK7EzZWulu/2pmV4krknUoe2T5VWWEAwGIJryZZUeCDYo
         RbpFQZnFC1r730mxTxlJEVxPi4szBn56VYT4IqtOcf3s5pOKcZc/IonDvREt+nUY92QF
         IUHQ==
X-Forwarded-Encrypted: i=2; AJvYcCWgFTMO5L0H+hdiak4UbZ1/ljQZW1w1x1OrJr3gPJxM1nNmhP7JvyOiRmupJgp7T+rNKuxhDw==@lfdr.de
X-Gm-Message-State: AOJu0YwDH1b5m4s2pMNNNu5zg4xt0FofOaV9tOAxzydnvL7EsqI5P0no
	FHNJn0iSR+cauKbuVSVOm+lLYMftLwxCrp2rAmZLu7n3H1eX+Hu0
X-Google-Smtp-Source: AGHT+IErQyPjb8i38KRrdvpP0VLDOSi6LDq/FxBkqXsFZr7wWqhT1SBbqKS5zWKRtzSYQI5e2pMxzg==
X-Received: by 2002:a05:6214:d4b:b0:6f4:7779:62 with SMTP id 6a1803df08f44-6f51562e894mr40059326d6.40.1746189373827;
        Fri, 02 May 2025 05:36:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGwjFMrmQy2riwgs3KpQ1v+qkStzyIhDj0yz/bRXRLUew==
Received: by 2002:ad4:5ae2:0:b0:6f2:b7d7:a7c6 with SMTP id 6a1803df08f44-6f5083e4fdbls30407786d6.0.-pod-prod-03-us;
 Fri, 02 May 2025 05:36:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXI6WFR9gTn81pxZDFDz/x5NHrD8/4R4w7/n0te2zrroafSemRHvVKIEwaigBT6HVF0SDnE1ZgDjnM=@googlegroups.com
X-Received: by 2002:a05:6122:3c44:b0:52a:791f:7e20 with SMTP id 71dfb90a1353d-52aed6a6fcfmr1602567e0c.4.1746189372975;
        Fri, 02 May 2025 05:36:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746189372; cv=none;
        d=google.com; s=arc-20240605;
        b=krbycXjdSOAcFDNYluAIrs0NXUq6nV1tJJvWzEZvzOwanntAre0vyJUiwsyyan3ouD
         FjOdi8UbY/Gv6qMSCz6fV5FDWg1YFh2yTRh34fyAoyBrx6TuFX5IBaKhpc/9mtN0rPH6
         R6LQJcNo9CCHjQOPn7jbG78OoxwX1aHoXwzRDuRHZ375V6LpgUh+OOVQosg4Gt0rtQcP
         Xh1AqKzN0WkN0anbyg5BiU4LRE0U0Lud8i8A4lTQLQl6+PT6TcBKMK6xXXnCyDOYX5M3
         EigJJmNUHD3r0BKCWp02o7xy2HyULdXh1h/jZu6hu0HI7fEfc47CNishBN6zZTl2b9AK
         E2JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2bWVNZpDPjN8he9HssEtQl6bUgAXH/F4pjykOH4GCkk=;
        fh=hwRGrp330dqw7LV+KDyBmCmJsOyCY/j1MJCnfaJxUHc=;
        b=Yhr5jrxhTlfA1TOjJsvpHfdpst6fnsKLMGwcFzgST6vm3NemL7wip7uUak03xQlJqN
         /a40JZcQpAGxur5cvfXEeRYp/HgggrNZ4NDHfgLxwdf72gg8Le/1upyTopGZlYAteYx4
         1ZH9ydOdiuA2Xv8uyHBooiiSHgHTcOoFmMwR3S4uGwtDMjET7FgMkmpXb2l2QTUzN4ui
         GgavbcMBbvvGqM74kJOTfdYTZRrsYeAPocBwptIAJ3K96T9X/3Vrb7/1CiIBJVe0J5dc
         3vfH/nBs5s2vfSQDssvT8jDC917AqdB32YfZnobLw3Zjrx2KFEIEdvn2+NwCZtlAql3x
         0Xaw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NEmg2smp;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-52ae41366d0si10918e0c.3.2025.05.02.05.36.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 May 2025 05:36:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id 41be03b00d2f7-b0db0b6a677so1968952a12.2
        for <kasan-dev@googlegroups.com>; Fri, 02 May 2025 05:36:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXxTIxatuRVnnRxBkdPvIVdylRSr29KwFshRcTql9tbo8YL4Ox62eqaeGqUqse6+ArANxNi7kUu3XA=@googlegroups.com
X-Gm-Gg: ASbGncvWGBwFwHpOwJUle5ky9JMmTNW6bVrdWZ3D4A/8bDOfid/krRhFgmeHrhdhX64
	UfhKmfy9rEDOULgT1HRxynGTFPw/F3+iyFbU8mFEftpLcN3Y/V71FhKG9bcZkEcy01tYc+EmH7V
	e8Lzd298n4AhVf9D2pMqlY34vj3kICKWgogPPFSMG4m33ujnn5DJE=
X-Received: by 2002:a17:90b:544c:b0:2fe:a79e:f56f with SMTP id
 98e67ed59e1d1-30a4e5aa034mr3940014a91.13.1746189371395; Fri, 02 May 2025
 05:36:11 -0700 (PDT)
MIME-Version: 1.0
References: <20250501-rust-kcov-v2-1-b71e83e9779f@google.com>
In-Reply-To: <20250501-rust-kcov-v2-1-b71e83e9779f@google.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 May 2025 14:36:00 +0200
X-Gm-Features: ATxdqUEo80l6Wmog53pGJlK7MMSvohTGvruUy1uyoixwHojHfstDErpJeGH-R1I
Message-ID: <CANp29Y41LKZg-kSP+j5hjUKMNeWnPsVd8VvDnOpN8+4WHHjEgQ@mail.gmail.com>
Subject: Re: [PATCH v2] kcov: rust: add flags for KCOV with Rust
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
	Matthew Maurer <mmaurer@google.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=NEmg2smp;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::535 as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, May 1, 2025 at 2:16=E2=80=AFPM Alice Ryhl <aliceryhl@google.com> wr=
ote:
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
> ---
> I did not pick up the Tested-by due to the changes. I verified that it
> looks right under objdump, but I don't have a syzkaller setup I can try
> it with.

Thanks for incorporating the core.o change!
I've tested the v2 patch on my local setup and it works well.

Tested-by: Aleksandr Nogikh <nogikh@google.com>

> ---
> Changes in v2:
> - Ignore `core` in KCOV.
> - Link to v1: https://lore.kernel.org/r/20250430-rust-kcov-v1-1-b9ae94148=
175@google.com
> ---
>  rust/Makefile         | 1 +
>  scripts/Makefile.kcov | 6 ++++++
>  scripts/Makefile.lib  | 3 +++
>  3 files changed, 10 insertions(+)
>
> diff --git a/rust/Makefile b/rust/Makefile
> index 3aca903a7d08cfbf4d4e0f172dab66e9115001e3..80c84749d734842774a3ac2aa=
bbc944a68d02484 100644
> --- a/rust/Makefile
> +++ b/rust/Makefile
> @@ -492,6 +492,7 @@ $(obj)/core.o: $(RUST_LIB_SRC)/core/src/lib.rs \
>  ifneq ($(or $(CONFIG_X86_64),$(CONFIG_X86_32)),)
>  $(obj)/core.o: scripts/target.json
>  endif
> +KCOV_INSTRUMENT_core.o :=3D n
>
>  $(obj)/compiler_builtins.o: private skip_gendwarfksyms =3D 1
>  $(obj)/compiler_builtins.o: private rustc_objcopy =3D -w -W '__*'
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
ANp29Y41LKZg-kSP%2Bj5hjUKMNeWnPsVd8VvDnOpN8%2B4WHHjEgQ%40mail.gmail.com.
