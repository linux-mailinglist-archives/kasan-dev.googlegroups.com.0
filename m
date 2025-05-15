Return-Path: <kasan-dev+bncBCXKTJ63SAARBI5QS7AQMGQEXM5W42I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B978AB8597
	for <lists+kasan-dev@lfdr.de>; Thu, 15 May 2025 14:03:50 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-22aa75e6653sf6945215ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 May 2025 05:03:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747310628; cv=pass;
        d=google.com; s=arc-20240605;
        b=ke3LJ8TffNcSPDRvmG/OYxtPqrgWARLqJND2Pmvqj0opMxa8NDqRy32pb2fnQqBsg9
         8f1MIM1UfjbSTIjcQ2qqFJVwr4tcfwS93wCRL4WaSSbegp7VKpJFJe5B6ietQYM0oRJd
         LcCxYDjMz88e2HCr1YAh2TP/bIPSYfXtQxG3J76kg2XzlddyL/LuL8Ex5/5sERP1GZHj
         pr2zVcFmuGSQd4CWfoBGXNhCbcAVjQDbvGNzi63ORjARrHU6jKn8hldmZX/dE9Ors7eD
         cykb6X3zva3Zg5zDo5H94qGLwqIMZmz+AkO89WMtkb3NoJD3S2+S2n0LF0bE8xY+7WxF
         IhDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qOfVtHuQT6JTry0j63wSn3e08AAIu4utW94bqaK9IE4=;
        fh=FCGKRKBeLuoqx53RK8WA7yWun7iBZg7zlosG3rD6BzU=;
        b=lh96LBM2uQ6E27SG0yoLdyTgfbenDTEK7xXmL7G8rcjJIKNxsOqbPb7QFbMpDo7Hku
         OMgmo8CRg2xpdEV1xcL80ix5TtPGPhlWaKVfEqjzD7G+JLu+iuaWmHGXtDBBvX2wlpl8
         QKAUjL9dgmJSthIWZ9uLvxq8jhHkduhTJUTCJTRACCI+NOf1+waHaLEkgKLKRGRcQt8T
         RizXhbj9eR2DYSo0v8hQ/1NqtUTOL5MFrn1ajX+MonhgMvrVUbHWz2L58eh0Sv7jHeA8
         1xCk4h+p1LdhPtyGt8o0Si8Z9GB44Jg4c7YWIg3whqfeRtiBUv3zPLGoHhV+28uK/PuS
         FQlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="boON20Y/";
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747310628; x=1747915428; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qOfVtHuQT6JTry0j63wSn3e08AAIu4utW94bqaK9IE4=;
        b=B7jZExrFwKZNZPtLYwFDYKWLLmrDR0WaYPT0lmXB4S6SN6UAe4MVwKFtxhrIOGXg8p
         ePuMqGyICA9Kb0Jzgr0en5NLrt+v+qd5UgtoF8pz1JtT3cnfmy6HohtmbiFuO4dl9x9/
         VhrJzmLyHQ8VBs5k3Z7/5Jfl1jVOTbh/uApPBd0tZ/k5h8BYtdjP3Pk5If6qLZsXdngU
         51aCVcGszYNx0CMxigQADJZpbbSzsk38w6Bw/u7yFBIkZpEQTPJ6gE15g6/GKOHW2FBk
         ggta0iJj2SmAE8B3f6voaF2bk3jZBU7SB72bp2g4NFQsA00lWKE8A8/vyzO7lq0wASKb
         uFiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747310628; x=1747915428;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qOfVtHuQT6JTry0j63wSn3e08AAIu4utW94bqaK9IE4=;
        b=r7zEQ9+YND13WEBkwa3rKPPbhvAC5PPjhgAD1oQAw+NWjQgqs38UVuRxizHMp5/9FA
         UADA4xlkC0mR3yMggHKDxvyODVR9jN+B1O76PRIy5WM2NsS4FmYjB9HD7GzhIME78B1M
         KcM9fVsZsILApYGylZJvZ9GsF2XEgaDvhCzgigLW8guDRJt6ph2bSM0I+W9EL5QG7OnK
         1W/2WBPeSjQTgz67jeFBv3ATaesLMKmni/yzVYFmBpehuM5WlhsuxZMzMbZAYne8ZPGP
         D8pRh3VVODOWtDk+UuRSfHTmdDocLOX/e5OR/6Gsiv10EiLKDTp7ogJqcB1BcWwLuu5w
         wVSg==
X-Forwarded-Encrypted: i=2; AJvYcCXB9eVhcrR9eJzuXoAXMFnLQKrbgS21xM2sHtTjNzBxg6ZCRWNd6KgD9Rh1SexgazqS1/CPMQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy4+02j2yR2bNIPsYj0zf3C5Z2vvwlcu8xFRagthwALzkVOyxQx
	2Dk68m4YiYywPVGFRepZGLPvEzRYQm8kIxxZqJ4CpPLFa5IV4tSj
X-Google-Smtp-Source: AGHT+IGixTMErCFzbTugfTsemQq1HWBahmwEJG+Vo583+Vc3hq2LDU4p+HNTjLaQt7uCTO9tcu5JLA==
X-Received: by 2002:a17:902:db03:b0:22e:60b9:ac99 with SMTP id d9443c01a7336-231981ab9f3mr112381415ad.34.1747310627921;
        Thu, 15 May 2025 05:03:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFSYtzf+cMVFQvcu2m1xSPIXIwQuL6PDYM02eDEdoNzpQ==
Received: by 2002:a17:903:2f4b:b0:231:b7a6:dcb7 with SMTP id
 d9443c01a7336-231b7a6dd03ls5271605ad.0.-pod-prod-07-us; Thu, 15 May 2025
 05:03:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQDJhnBM2LJQ5vufe8OfY/WBrg+ldww9+GQKymRnbhtU+UXN3hFgZ6JRVf32QfTIxcMwGsO+75gxQ=@googlegroups.com
X-Received: by 2002:a17:903:98d:b0:21a:8300:b9d5 with SMTP id d9443c01a7336-2319815e15emr105181155ad.23.1747310626528;
        Thu, 15 May 2025 05:03:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747310626; cv=none;
        d=google.com; s=arc-20240605;
        b=auXXu8otsNxTPX8i5dwTnHjSa5bXhVL6ehCfWKelQVbN45NBVK1DifESjvuERZC4m+
         IlPpuO/4GL2QdZsw5JnW/8b8IyCOi69zpISQ6ZLCI6WB9kyAGxkpIEGbJeHfqa88SjnD
         Lm8DzsuZL/HEpl3mUdSR6iB2SxB6pDZ60iql/qPVT5cO4eQrgO8W0oa+hu4vrA2dbkQU
         UXjuE9C9Aufs3zNfIJjdfYCFxTbMlNDYYHsVZ0eN4WOEbCFbOk31FWISYAq2oEhsO3u9
         GAAV//6MKKBodpcCAJnyVOoeb7bjrQNu6DyjLwshSLqf7hHc40IKFzozb9xw3y+V+Xxy
         9ahw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3wJvNJM3iWYUox8bI9g2NYJL06xVVnQ0A08ak76PpHM=;
        fh=AWinIgfRIdgJgY2FNPB8/IcOAnRPH9hzqlR6osoSQaE=;
        b=DS13J2VMTcGphY72naDD3YWlt4X/Nf1RoXXiuOkM0JLtljwpCedklChG190WM6fbYu
         JvXMmL7/HPzQ4+8YsgbwVeovkFAhK7ge99g1/zus84HhRgsrRIvI87uDKf7fzH3+NGE2
         0NxQ/ujqTuZQdPbjn29kT4eAYiG1riBaiPvR/XV4RpsQGitTeucBuoI+l/loxNB6iA1k
         S2Fxe1+tN9nlamq1fW1C19OjblAUaVhH6W/KfWcUtIQjgqrFLz7mEKkpH1nwVtRwIYRp
         P+6Wyh8Vgs95Y0n19na+/o26DiMx+WlJ4c+xNsRMy00/StB7/aTxTfMwbjPzxsTm/dDi
         cVqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="boON20Y/";
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22fc8225d00si4637715ad.11.2025.05.15.05.03.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 May 2025 05:03:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-e78e38934baso826419276.1
        for <kasan-dev@googlegroups.com>; Thu, 15 May 2025 05:03:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUy9gRziglfh+PIDbjKOpyY/k/FAePXIOZuxgZ0Zk2nJEOE5MjGIjmSH+vAB2OVkt+4UquGTqpHUJ8=@googlegroups.com
X-Gm-Gg: ASbGncvK95dlLhnbCGX/H5xYnHsthk/zwnWQfP4WV19J2I2N4U6LT+36yNUU4ZRvWzp
	Kz7cjGhffmfdSiNk+Jv4x8d5HwFiBn2EmIVvMMRrSB4DK8bz89XpJjEQCG5ISwwvgEJaciWXmY0
	Qs6+5mgo8dL52OXI3UWGmRIZpApRPmZoU4p+8Q47Em5M+oXmUd5epBG7izpKJ98Jg=
X-Received: by 2002:a17:903:1b0f:b0:22e:3b65:9265 with SMTP id
 d9443c01a7336-2319810fdcbmr77926775ad.8.1747310614801; Thu, 15 May 2025
 05:03:34 -0700 (PDT)
MIME-Version: 1.0
References: <20250501-rust-kcov-v2-1-b71e83e9779f@google.com> <CACT4Y+Yzmd7BtrpqUPrbXAAGzMnO0YKZnhVxLgyyXEftscEUnQ@mail.gmail.com>
In-Reply-To: <CACT4Y+Yzmd7BtrpqUPrbXAAGzMnO0YKZnhVxLgyyXEftscEUnQ@mail.gmail.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 May 2025 14:03:22 +0200
X-Gm-Features: AX0GCFstD_4uJYWfNb5g_AdONBqYpFEcU11UPC3GcRCSjJ-WcVpH60WtoBj7ozc
Message-ID: <CANp29Y7+7Fa5_rAEwJYoWnKHXy+BS4mFWoMe=1J4ocnCuqYtfQ@mail.gmail.com>
Subject: Re: [PATCH v2] kcov: rust: add flags for KCOV with Rust
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Alice Ryhl <aliceryhl@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
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
	Matthew Maurer <mmaurer@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="boON20Y/";       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::b2c as
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

+mm

On Thu, May 15, 2025 at 2:01=E2=80=AFPM Dmitry Vyukov <dvyukov@google.com> =
wrote:
>
> On Thu, 1 May 2025 at 14:16, Alice Ryhl <aliceryhl@google.com> wrote:
> >
> > Rust code is currently not instrumented properly when KCOV is enabled.
> > Thus, add the relevant flags to perform instrumentation correctly. This
> > is necessary for efficient fuzzing of Rust code.
> >
> > The sanitizer-coverage features of LLVM have existed for long enough
> > that they are available on any LLVM version supported by rustc, so we d=
o
> > not need any Kconfig feature detection. The coverage level is set to 3,
> > as that is the level needed by trace-pc.
> >
> > We do not instrument `core` since when we fuzz the kernel, we are
> > looking for bugs in the kernel, not the Rust stdlib.
> >
> > Co-developed-by: Matthew Maurer <mmaurer@google.com>
> > Signed-off-by: Matthew Maurer <mmaurer@google.com>
> > Reviewed-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Alice Ryhl <aliceryhl@google.com>
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>
> > ---
> > I did not pick up the Tested-by due to the changes. I verified that it
> > looks right under objdump, but I don't have a syzkaller setup I can try
> > it with.
> > ---
> > Changes in v2:
> > - Ignore `core` in KCOV.
> > - Link to v1: https://lore.kernel.org/r/20250430-rust-kcov-v1-1-b9ae941=
48175@google.com
> > ---
> >  rust/Makefile         | 1 +
> >  scripts/Makefile.kcov | 6 ++++++
> >  scripts/Makefile.lib  | 3 +++
> >  3 files changed, 10 insertions(+)
> >
> > diff --git a/rust/Makefile b/rust/Makefile
> > index 3aca903a7d08cfbf4d4e0f172dab66e9115001e3..80c84749d734842774a3ac2=
aabbc944a68d02484 100644
> > --- a/rust/Makefile
> > +++ b/rust/Makefile
> > @@ -492,6 +492,7 @@ $(obj)/core.o: $(RUST_LIB_SRC)/core/src/lib.rs \
> >  ifneq ($(or $(CONFIG_X86_64),$(CONFIG_X86_32)),)
> >  $(obj)/core.o: scripts/target.json
> >  endif
> > +KCOV_INSTRUMENT_core.o :=3D n
> >
> >  $(obj)/compiler_builtins.o: private skip_gendwarfksyms =3D 1
> >  $(obj)/compiler_builtins.o: private rustc_objcopy =3D -w -W '__*'
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
ANp29Y7%2B7Fa5_rAEwJYoWnKHXy%2BBS4mFWoMe%3D1J4ocnCuqYtfQ%40mail.gmail.com.
