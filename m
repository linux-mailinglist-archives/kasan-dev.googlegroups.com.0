Return-Path: <kasan-dev+bncBCMIZB7QWENRBE7SRW2QMGQEL2FP5EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id ED10093D10B
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 12:23:16 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-427df7c3a2asf13973095e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 03:23:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721989396; cv=pass;
        d=google.com; s=arc-20160816;
        b=pCvRmZH+Yk0opQF7dzIRy7cd2Kn7kQOSYSbHPoJKOx3wpVTZptvIVG9kuB1BwpGoeb
         kYWhX1J6ECmfZFuRWdJFeZP0BnWtgTiTudQtlwmS9SpoLrKvJxR5Fo0OIE754Kkh+7ff
         +FMIc434lkziuZ62wjLwgG+HHlwTSTN/0APQ0O3JWHaR/tC6/ZPiwqE5cSEUMOAtrHVV
         Md9W4se2mBMz/0qTZC/iStkHfsBFAZFC08xm7cwoV52ebKvIHZwOprDzLmTN8CaNqEXC
         oe7qrWsJOvcYHSlfQjvYspNoRKxpvsODsMJFalGtAbzk8TU8KEbRKHClg617RMNGWBm0
         n3YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NAy+X70q7Fq7XOCpiG5yLhp3mBtr29Uv12T0faNWnHo=;
        fh=UjHTakilj6u/mW2+DSRPL6eKTNvQGhnl9xx0wPVjysw=;
        b=ZPDkSmwLkoRy6/FDK0F3I1wR3+cLUIM9NDjuyT+mBcWQ98NbfaP6tDlAEoAmTSjv+J
         AdYUOZCbo+mbj5wlxHqRfGGZ6p/GksvKV4GxL1HdOv/Me6T8IZYJO96ZrpvnAqwJlDKb
         X844fMgMeS/lNFehnqA6dghmqg7DvWUAWbl1WnoG1aS5cBdfzuryYpeSOr+VARaPeyk7
         kJRbWGt2RJi51tjrUXNdz7R6Rvq2crOqyu+q5pU27M+1/g9ileQRoZnjQF7dPyMbYbUE
         I31rNk0DCVwddpzEqFWt5CE4xt5QQG/O89we6JqBlZgaGbQe2jXwaykQWGpkYqxkJQ5Q
         On2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wM9b0RqF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721989396; x=1722594196; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NAy+X70q7Fq7XOCpiG5yLhp3mBtr29Uv12T0faNWnHo=;
        b=Oe0i4rtH3ymIEGW0KyuMhlqxlsjRQFKc14SpQUAcZepAhVVE5BoOwZFGuc6koN0Tor
         nedrEVa/BauXY07j0zjN1ErfKyn9u1cU2Mvig9Z5ev8Un+I4SQWSSmBPejvdRRQBcPWz
         Y2SqWykymSH8sO8NIOmuFVyp8oA/EjRyNC/KIyPfuvO9aI520tsB24hSVxaWq7i7gyK+
         u/6IPyAaqrWWmUS3+mWiD7DESxfkV6ygsoPXmgLqVJ8b8kwVIu5FGEnoJUIf96VDvssW
         RE5YdfYoDj3d51nQWykx74qNP32Tn9MwMbeg7mZVH6FXoqKWmN27mg3LYH6RGmw8ybi2
         FXtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721989396; x=1722594196;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NAy+X70q7Fq7XOCpiG5yLhp3mBtr29Uv12T0faNWnHo=;
        b=JbYBkor1L9nOamkrhD2BfGBa20W9xJzC0R+RwS/Gt/D/BpG7fguIrkUb6U3Jrcyep8
         QKclq/fEkLOy5ddm5vUxibXr7xPpHYVa+2o/HgG2DFmRTXo7bV4bI84ZYQvT0UGGdY3Y
         eapA0I46HukFdjdgcH9GULmHmLEii8Yss8xaKqQDkXMBxtBPZDcTRmuOgayTFdF0OoAs
         G6wHk/U+iRizeS+mR4kkwxBHQ7sTZP7jFqi3nliyT4FXsUXJ2BCcUlQVQNRHKrtV5+7Q
         SPlz8zd71wANhdXAPYAX3vfh/PbYEHXN880BC/Q3wR9X1P2yIKv1sFSpi7P9zIUELVy7
         6+Yg==
X-Forwarded-Encrypted: i=2; AJvYcCVi+ftsBct2QZaq8DLPtywnFwTDyatVEez+arTtZCttJmfXUHLABT5Cnlyud0fzPyGOD65P3ebrlUsqHUTYgZPAweVFJMKTLQ==
X-Gm-Message-State: AOJu0YwqTqcd0bV2lSKfdp4WCQC3QHL2V+GRNJDfTXPp1ozX8ZX76ZvC
	A2psG89HZO21ggYl/OubtV7lsnEpJzz0i1XUyrQ2sVNcEOz88R0z
X-Google-Smtp-Source: AGHT+IETHzgtHBk+ke7cGQ5tTeFSX/DNXJh/7Q0TqcNzhy+TPU9dUGYfn5XW3+dURXQTDOTns8JPoQ==
X-Received: by 2002:a05:600c:4451:b0:426:593c:935d with SMTP id 5b1f17b1804b1-42806b5c4f8mr34890205e9.5.1721989395821;
        Fri, 26 Jul 2024 03:23:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4443:b0:428:7aa:daa9 with SMTP id
 5b1f17b1804b1-42807aadd05ls6525705e9.0.-pod-prod-06-eu; Fri, 26 Jul 2024
 03:23:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUkZoqXGoNW6IoYe/IY+b4Xx6aZJUFV0giJEQDNi0sebpxWMY4rz6qZpAuD2YGxZnUxs9BPfYRCxfdnpnQPqTJfpLVPZCNZ4T6a/Q==
X-Received: by 2002:a05:600c:45c7:b0:426:6f27:379a with SMTP id 5b1f17b1804b1-42806b7e54amr32781965e9.13.1721989393924;
        Fri, 26 Jul 2024 03:23:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721989393; cv=none;
        d=google.com; s=arc-20160816;
        b=CbqBqMVHDG2rKaXYuUNc5ecCwsWlzDT38liL1a7n1S+vu37n28m8k2GhN3iBV/mO+1
         xYQ1nT+lD03TZONjkHrgen3PkdfTkl1vdvaq/r+9aMuTgbWzAvJeKPtuww+OdJCkXajP
         pSQR/EEQeJAi8Tk5aSJbxnxXwYWGRV1aCXMcs1+vJc+1k1wIiA9TndZYDRkVUymMORRt
         IerT3Tf9Igc8xbDx5UGOpCvuwQxHOLTjJn768Nf1DhlCvDmIeUgraYhsDNPHC1LQQUJM
         Hmle0H0UwihuIdsVCxG6YIpJUUdQwsO2c29QdXQK2vLF6Dsxx/beCbSM2IGEX/5HKmND
         NvYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NOFadCdnFUNbKiegYZZRp810q0uwCcDa0ulZ63Y8FbI=;
        fh=Td89xObtasUU85CTddus3vX8eBuoFNDhxMuhLkBpY3M=;
        b=rMpY6g/sdAF/xALUcRoAaTXWSrTKKyzHruPkdzvmSYPZSE8wbdoHal94BUWY/t7ciI
         t9e4ZjGPj4HPPOvx2r8TV+v0yg46pG+LW8mh4JHsF2sb+TBmfS5lIFDCx3qOgkGN2fQZ
         ubYYfqjAxpL0tXcWfqaQYXaB5oEH5pGAxO5PVF4iEMH3fuYqNCyrQGYRRYQDyVQoaFnv
         dB9CBxf4WxbWzDoc3+YzlqWG6EteVGoLLoIc3DJIF5VrN7wt25s5KCFP+iXP3aWzxci3
         Ak3ZAjM9ApPsfu0ffLZ0gMJuW++PZdpmqghqHosw2qn/l5HEvhWAu286nWcQU7naurQw
         rG2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wM9b0RqF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x136.google.com (mail-lf1-x136.google.com. [2a00:1450:4864:20::136])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-427ff751fadsi3584325e9.1.2024.07.26.03.23.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Jul 2024 03:23:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) client-ip=2a00:1450:4864:20::136;
Received: by mail-lf1-x136.google.com with SMTP id 2adb3069b0e04-52fc14aa5f5so2691e87.0
        for <kasan-dev@googlegroups.com>; Fri, 26 Jul 2024 03:23:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVQ6EmjbZ1d3bRh9TGSDp306G4LiZn1MG1FE3GW2yA40XfJp9HiEFKszx6DJXqXgcsHMRPudNChSkso+Y/f7VkIN9xeRi8yiHXjmA==
X-Received: by 2002:a05:6512:3e21:b0:52c:cc9b:be20 with SMTP id
 2adb3069b0e04-52fdb52d825mr121406e87.1.1721989392884; Fri, 26 Jul 2024
 03:23:12 -0700 (PDT)
MIME-Version: 1.0
References: <20240725232126.1996981-1-mmaurer@google.com> <20240725232126.1996981-3-mmaurer@google.com>
 <CA+fCnZdwRcdOig0u-D0vnFz937hRufTQOpCqGiMeo5B+-1iRVA@mail.gmail.com>
In-Reply-To: <CA+fCnZdwRcdOig0u-D0vnFz937hRufTQOpCqGiMeo5B+-1iRVA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 26 Jul 2024 12:23:01 +0200
Message-ID: <CACT4Y+Y+XmdNervhF5WAEyVwprJ32m7Pd8FF2fKy3K9FiTpJtQ@mail.gmail.com>
Subject: Re: [PATCH 2/2] kbuild: rust: Enable KASAN support
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Matthew Maurer <mmaurer@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Miguel Ojeda <ojeda@kernel.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Nicolas Schier <nicolas@fjasle.eu>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Alice Ryhl <aliceryhl@google.com>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev, 
	Brendan Higgins <brendanhiggins@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=wM9b0RqF;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136
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

On Fri, 26 Jul 2024 at 01:57, Andrey Konovalov <andreyknvl@gmail.com> wrote=
:
>
> On Fri, Jul 26, 2024 at 1:21=E2=80=AFAM Matthew Maurer <mmaurer@google.co=
m> wrote:
> >
> > Rust supports KASAN via LLVM, but prior to this patch, the flags aren't
> > set properly.

This is great, thanks, Matthew!

Does Rust support KUnit tests?
It would be good to add at least a simple positive test similar to the
existing ones so that the support does not get rotten soon.
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/=
kasan/kasan_test.c



> > Suggested-by: Miguel Ojeda <ojeda@kernel.org>
> > Signed-off-by: Matthew Maurer <mmaurer@google.com>
>
> Hi Matthew,
>
> >  CFLAGS_KASAN_MINIMAL :=3D -fsanitize=3Dkernel-address
> > +RUSTFLAGS_KASAN_MINIMAL :=3D -Zsanitizer=3Dkernel-address -Zsanitizer-=
recover=3Dkernel-address
>
> If I recall correctly, the reason we need CFLAGS_KASAN_MINIMAL is
> because older compilers don't support some of the additional options.
> With Rust, this shouldn't be needed, as it requires a modern compiler
> that does support all needed options. E.g., for CONFIG_KASAN_SW_TAGS,
> we also don't have the MINIMAL thing for the same reason. (Possibly,
> we also already don't need this for GENERIC KASAN, as the GCC version
> requirement was raised a few times since KASAN was introduced.)
>
> >         # Now add all the compiler specific options that are valid stan=
dalone
> >         CFLAGS_KASAN :=3D $(CFLAGS_KASAN_SHADOW) \
> >          $(call cc-param,asan-globals=3D1) \
> >          $(call cc-param,asan-instrumentation-with-call-threshold=3D$(c=
all_threshold)) \
> >          $(call cc-param,asan-instrument-allocas=3D1)
> > +       ifdef CONFIG_RUST
> > +               RUSTFLAGS_KASAN :=3D $(RUSTFLAGS_KASAN_SHADOW) \
> > +                $(call rustc-param,asan-globals=3D1) \
> > +                $(call rustc-param,asan-instrumentation-with-call-thre=
shold=3D$(call_threshold)) \
> > +                $(call rustc-param,asan-instrument-allocas=3D1)
>
> I'm wondering if there's a way to avoid duplicating all options for
> Rust. Perhaps, some kind of macro?
>
> Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BY%2BXmdNervhF5WAEyVwprJ32m7Pd8FF2fKy3K9FiTpJtQ%40mail.gm=
ail.com.
