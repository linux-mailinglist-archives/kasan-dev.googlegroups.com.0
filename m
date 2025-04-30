Return-Path: <kasan-dev+bncBDI7FD5TRANRBN4OZHAAMGQEQALDD5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 7528CAA50D7
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 17:52:26 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-3912539665csf469974f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 08:52:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746028345; cv=pass;
        d=google.com; s=arc-20240605;
        b=HGZ78M6KMXR1feAh+R0VMBss6qnniAhxJrdSpNdzb+YJBQSk2b/XXkPp59tHmi2eVP
         63z7O1r8OWiduvBagxkRkjzqO59zw581mmEc131T4/tChJk4NPK9DFhPBezimBndQxsG
         LeW1o/OL9eE5Tr4UbpoRuCjnTfxprtjciQEji4JDF2huoAMRoorUZIe378HWT6wUkAmx
         65W9z99t8llJA5jxHIS058xiABSnXr5XGryK1MFWbkl+8H+VPYGc7MbmW2hoA5ks+WY2
         BodfiUUnx47qq/Rkffk/Uu/b6Hsy3cn9/oJaMt+e3ytAwTm9P/0s6a1o6OxdUzReBPc5
         R5IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IQKlO2LtLm8dw1g1phZdtgcTkVewVUg7ADEabi1700A=;
        fh=0CIWys4Fw4UKBH9NPfqAmjbW1K47WefEZcjBAsBf+eg=;
        b=bfl/moUjLKlVDgAxAWZAzpKU6I3NoH9RP7hpuPndtuUzaI4TbStsjCmt1Lw/oucfFn
         PGFGuO9mfsDDoFuYCqbkNi2ln+bG015Zw7zKBgIJAqPdCmsw+iRjCcBgCAsq1yNgJzAR
         dd4wwrvKv+ma0K85hcuEE5Lv+oKeatuGUFELa8muLqkGw3aY9NHSyGYXkbEutoIIZikl
         SpnL8YCqsXKTMV532XLmdR/TuR2mspeZi+U1a0kaDb1LwIEMyz3FSRW+uKRcgsYvygwV
         BYJBfN1TgV5W2+xvBglZkd4QFRswy0jZ2b1d5GJ8JQXq9Fmgoq0KC5o7U5W4KIJpaWao
         6rqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=poJw7JW5;
       spf=pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=mmaurer@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746028345; x=1746633145; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IQKlO2LtLm8dw1g1phZdtgcTkVewVUg7ADEabi1700A=;
        b=Y92o4J7Bi41Xnzv0hle2TEmtme9wu/e8C/4nZUsgAKMMZGdySoJ41tpLAE16EQB+ep
         P0+fMEJjXq2oULu/W4eYa1k1QnF8e5JjEAkq2wj7llS7U2qgjIAA3WGsmo3h67Ps8NIX
         5QJwhwUJmBmT6RmvoODJGHqHV3TinSv7KQCdDa46tES/9ddq8E/ogFh+PB72ycygMBeh
         DpGlQIPQA9YyD7ZQl05SfCKwGRQ5d/lLB1urStPP2esmv+GgH+9yB4GlKNWNBzVW45nO
         lnOCNWc/B7dDDAmpiXapasX2FBdZlXh38W6Fbn6+/rUzwccd5Gna5TJ7D8uF2z1cN/k3
         axQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746028345; x=1746633145;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IQKlO2LtLm8dw1g1phZdtgcTkVewVUg7ADEabi1700A=;
        b=JnM6S0YqBlV/Qwm6tB4SXAyYOkEO29hIlUSNadx9tdWVaVllFgbGXpCB6Jsn0PdxHQ
         8ylfiSomdYajqh4ujD9mpRVvXcrc4+F/iI+pKXvJNXFfvy731/qWM8TaRBU+qnfI67Zb
         CpfHCos1chFYYgsqLZ17AhTGguz2V7zV+B9dMxWI43OZvAim2BYZ6GvwF8KKl+1HiQ/I
         YgC8gPiN7GwiTNzgExlkuKQkCTLH3YCJhPybdisAt4OZYxGipMSmCOmYUitDageQJy7u
         OKkULIW1bIRnrHH2vFJUo8J64jVKHd5VHg62v7AQQRr43N2z6j+2+YsG+FIdpT8JT3bN
         1KjA==
X-Forwarded-Encrypted: i=2; AJvYcCWgXSrEaco7OG3YxQlI2TlooBTFFcA5pTtvarsG8IVxNQpn6XI18zc8AF+aWJ3UJQQtrx8PnA==@lfdr.de
X-Gm-Message-State: AOJu0YxjCCornQ2nNMFG2mokcoxm2V9y/w8XabNylpDklgW5nb/m/zwz
	2fWUOhJe42saoQHdL+kT/zupwfPEmiJ7eSRfu8hYIUhrSoTNJl+6
X-Google-Smtp-Source: AGHT+IHn2D96PjbXHpPKBfEafwC1EXvX5X8azX5mKWgiRKOee+VRR8W0OD6/DuKR1DyVLB6J396GHA==
X-Received: by 2002:a05:6000:3112:b0:39f:cf7:2127 with SMTP id ffacd0b85a97d-3a08fb52992mr3067707f8f.14.1746028344302;
        Wed, 30 Apr 2025 08:52:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHSc0k59Ph5ZPkvKmEkyYvTyT9SPJmjngszDbSpCwpddQ==
Received: by 2002:a05:6000:220e:b0:38f:2037:b82c with SMTP id
 ffacd0b85a97d-3a092c4869als4257f8f.1.-pod-prod-00-eu; Wed, 30 Apr 2025
 08:52:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzbKFFvYVAzLTEPibYyavX5eVxBRnLmvHk4evSSDY2SdpsA2hVzLeIEQSCd9CAKRBjoUVJkF2Rq5o=@googlegroups.com
X-Received: by 2002:a05:6000:4203:b0:3a0:8011:54ca with SMTP id ffacd0b85a97d-3a08fb692cemr3045717f8f.18.1746028341718;
        Wed, 30 Apr 2025 08:52:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746028341; cv=none;
        d=google.com; s=arc-20240605;
        b=TRid1Sul1gO1LK6F1sS4pAwd62EY3RDN+gjVVNriAWAWZVQKVUhrvZTddEo3s0GkpM
         h1bjqbHl/KcKOEQGfuZJ+vF3CJ48xBXLl8qU2AOqxHFYJzJmHOb0hKXPbEcAAPvLWqk/
         W+ZnOyE1oX+L79h6DCsU5YdTSr8AP4esQzLx/1kt6/v93G1y4AowQFapv6RoFiU7umc3
         qNAqTk7h2D916LpSEfB33LWZGLhm0hXp/xb6YrjVesT99o/OmwVNXtNdJIor67Q8FQ0b
         MpC+QaV3EFR737N4jYztYdd4IlwuRQYihkKVqda3MR7YJvZyzPBub/fC7s2Lc4D98ltN
         Tu2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UUgz0lHIM9AvqVgwegmtWsNz7YXlDr9Kk1u0gwL4TQ8=;
        fh=FM0SSnQLDrzs/EeEtDYuMhMLUOK3ZQyxl1eAbh2kro0=;
        b=imCXu5zhfM/kqBgQTEOaD/ZaYm6Qe3Fj5qlvXtYj/hdoX5hhbLY+Ry1fNa8r7f9cLP
         Rx5dHT7mjm78AT24+Dl08o5XAC/0GZACy7D3I7fwhmhOPO5+VUouZSTouhA5C/FQkWxp
         T+BeIOPh+R2IBzPm2+Z6x0ORUpi9wqsRSo36g0Aww9uxhDzgVF6+SFBUZwHqHM5zK38k
         MjaOL6E47mvBHEVjecCJ7dDM2EHBW2Ig1DitlMgl9xOU5KEiPh1G0hPq9lunUfZa4ZOj
         X4Pwv1OFsVlDKSqjsp6JrIM3MTObKbrLWXRAte8YHTNX8g3FNekujhaJBbmczYblI4N2
         VFfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=poJw7JW5;
       spf=pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=mmaurer@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a073e0a28csi413746f8f.8.2025.04.30.08.52.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Apr 2025 08:52:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id 4fb4d7f45d1cf-5dbfc122b82so151a12.0
        for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 08:52:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWMpEtL5J7DNGSoGp5wbKiWtQ8HbkyZTFrREWlF4F54LZVb7vf2g8yYQbXfzWVVRT1LJoSS9UgYyVs=@googlegroups.com
X-Gm-Gg: ASbGncvbg7Tbsah+TSQeEiwFa4ObSC1J5PZjUWf2FDb4xmMabTDoplHRfwNIwvgKxxa
	G44Ue85ULp+vC5P2APBMNf+wZhM+GKyD7NQikPeADLEPqCQEZdpXwte4ak1ddY4BIRkF3/BFhqN
	oTJMMa/K9oIjlpGRoBfpLQmTXLccuCLgdq+lgRNl1MRiUzQB0roWKV4l0WiB8SKg==
X-Received: by 2002:a05:6402:30b1:b0:5ed:f521:e06c with SMTP id
 4fb4d7f45d1cf-5f8aac01ebdmr113976a12.7.1746028341167; Wed, 30 Apr 2025
 08:52:21 -0700 (PDT)
MIME-Version: 1.0
References: <20250430-rust-kcov-v1-1-b9ae94148175@google.com> <CANp29Y4o8o6gz6GbM6NhP9sJUi94q29=aa+tLc1aCk0UVpgj0w@mail.gmail.com>
In-Reply-To: <CANp29Y4o8o6gz6GbM6NhP9sJUi94q29=aa+tLc1aCk0UVpgj0w@mail.gmail.com>
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Apr 2025 08:52:09 -0700
X-Gm-Features: ATxdqUFfWkFt2krZSEThZVrbRM32DbyGd7csCuhOc9hU0LccEz016XDL5xHWJ3s
Message-ID: <CAGSQo01gLXKWLWcrxSytmCB4YmRnGDX++ZizTws0bEjJ1amWtA@mail.gmail.com>
Subject: Re: [PATCH] kcov: rust: add flags for KCOV with Rust
To: Aleksandr Nogikh <nogikh@google.com>
Cc: Alice Ryhl <aliceryhl@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Miguel Ojeda <ojeda@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Trevor Gross <tmgross@umich.edu>, Danilo Krummrich <dakr@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=poJw7JW5;       spf=pass
 (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::533
 as permitted sender) smtp.mailfrom=mmaurer@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Matthew Maurer <mmaurer@google.com>
Reply-To: Matthew Maurer <mmaurer@google.com>
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

On Wed, Apr 30, 2025 at 4:55=E2=80=AFAM Aleksandr Nogikh <nogikh@google.com=
> wrote:
>
> On Wed, Apr 30, 2025 at 10:04=E2=80=AFAM Alice Ryhl <aliceryhl@google.com=
> wrote:
> >
> > Rust code is currently not instrumented properly when KCOV is enabled.
> > Thus, add the relevant flags to perform instrumentation correctly. This
> > is necessary for efficient fuzzing of Rust code.
> >
> > The sanitizer-coverage features of LLVM have existed for long enough
> > that they are available on any LLVM version supported by rustc, so we d=
o
> > not need any Kconfig feature detection.
> >
> > The coverage level is set to 3, as that is the level needed by trace-pc=
.
> >
> > Co-developed-by: Matthew Maurer <mmaurer@google.com>
> > Signed-off-by: Matthew Maurer <mmaurer@google.com>
> > Signed-off-by: Alice Ryhl <aliceryhl@google.com>
>
> Thanks!
>
> I've run syzkaller against a kernel built with the patch applied and
> the tool was able to successfully obtain coverage feedback from the
> Rust code, so
> Tested-by: Aleksandr Nogikh <nogikh@google.com>
>
> As a side note, in the resulting code coverage I also see a lot of PCs
> from rustlib, which isn't the primary target when fuzzing the kernel.
> Do you find it reasonable not to instrument rustlib with coverage
> callbacks? For C code, there do exist some exceptions for KCOV, see
> e.g. lib/Makefile.

I think filtering out `core.o` and `compiler_builtins.o` would make
sense, as those are not kernel-originals. Filtering `pin_init.o`
probably makes sense too.

`kernel.o` I think we should probably keep at least for now, because
it's kernel-created source that we'd still like proved out. In a
theoretical world where Rust has become more normalized in a decade,
we could filter it out to refocus fuzzers on driver code rather than
bindings, but right now the bindings themselves are worth fuzzing IMO.

>
> > ---
> >  scripts/Makefile.kcov | 6 ++++++
> >  scripts/Makefile.lib  | 3 +++
> >  2 files changed, 9 insertions(+)
> >
> > diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
> > index 67e8cfe3474b7dcf7552e675cffe356788e6c3a2..ddcc3c6dc513e1988aeaf07=
b8efa106e8dffa640 100644
> > --- a/scripts/Makefile.kcov
> > +++ b/scripts/Makefile.kcov
> > @@ -3,4 +3,10 @@ kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)    +=3D -f=
sanitize-coverage=3Dtrace-pc
> >  kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)   +=3D -fsanitize-coverag=
e=3Dtrace-cmp
> >  kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)         +=3D -fplugin=3D$(objtr=
ee)/scripts/gcc-plugins/sancov_plugin.so
> >
> > +kcov-rflags-y                                  +=3D -Cpasses=3Dsancov-=
module
> > +kcov-rflags-y                                  +=3D -Cllvm-args=3D-san=
itizer-coverage-level=3D3
> > +kcov-rflags-y                                  +=3D -Cllvm-args=3D-san=
itizer-coverage-trace-pc
> > +kcov-rflags-$(CONFIG_KCOV_ENABLE_COMPARISONS)  +=3D -Cllvm-args=3D-san=
itizer-coverage-trace-compares
> > +
> >  export CFLAGS_KCOV :=3D $(kcov-flags-y)
> > +export RUSTFLAGS_KCOV :=3D $(kcov-rflags-y)
> > diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
> > index 2fe73cda0bddb9dcf709d0a9ae541318d54754d2..520905f19a9b19631394cfb=
5e129effb8846d5b8 100644
> > --- a/scripts/Makefile.lib
> > +++ b/scripts/Makefile.lib
> > @@ -169,6 +169,9 @@ ifeq ($(CONFIG_KCOV),y)
> >  _c_flags +=3D $(if $(patsubst n%,, \
> >         $(KCOV_INSTRUMENT_$(target-stem).o)$(KCOV_INSTRUMENT)$(if $(is-=
kernel-object),$(CONFIG_KCOV_INSTRUMENT_ALL))), \
> >         $(CFLAGS_KCOV))
> > +_rust_flags +=3D $(if $(patsubst n%,, \
> > +       $(KCOV_INSTRUMENT_$(target-stem).o)$(KCOV_INSTRUMENT)$(if $(is-=
kernel-object),$(CONFIG_KCOV_INSTRUMENT_ALL))), \
> > +       $(RUSTFLAGS_KCOV))
> >  endif
> >
> >  #
> >
> > ---
> > base-commit: 9c32cda43eb78f78c73aee4aa344b777714e259b
> > change-id: 20250430-rust-kcov-6c74fd0f1f06
> >
> > Best regards,
> > --
> > Alice Ryhl <aliceryhl@google.com>
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AGSQo01gLXKWLWcrxSytmCB4YmRnGDX%2B%2BZizTws0bEjJ1amWtA%40mail.gmail.com.
