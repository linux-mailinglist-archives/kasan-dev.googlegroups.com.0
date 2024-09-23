Return-Path: <kasan-dev+bncBDW2JDUY5AORBREXY63QMGQE4G6LGQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id D472F97F18B
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 22:12:53 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2f760dce28bsf27634731fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 13:12:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727122373; cv=pass;
        d=google.com; s=arc-20240605;
        b=lC/6uZu2Lfto/HOrFt3woKAEtK2wEuZJvdn48r8C02aL+3dj7qoB/y503wunQ2A2g7
         0Z9hetwxC2sZi3WWmDW9/0cve1TwEhRY2mh2qrH/bAbO+e1LzmWS5zKYok6RAk74fx4L
         ihwnYZP9ib8xteMSPmMHhoyl0229AbiKDWP7clzcgADLXghFTK6xQSR5F0WP+rcsFY0X
         7CkRTcuRlxUJAOavdS+QiHisNpp+Jc1ea40/Jp+JFfEgwsB/E84ZV0GIb0nhpKGPQ38x
         NStj0E03AO68+HL+VHNN5ipSqTA3VXXY39QxvIHyMTT87Lb1Ovb31tNFQah6SIuU8aAs
         z2Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=oYS0kYUiHT/SkcynsbjN4msqBo/RRmIU7KDWIfwLdIE=;
        fh=XhQaWkiRcsQwKgVwPZLpANrL6UusqdRUwzFV4NkcbZE=;
        b=h+kgwShuRXY5Hevqe4aVdrv+sWliIawaqostZFs1D3BepN7NQWX2KYga7MMn5J2zma
         U4JutOEyNQtRpVQyYHarCuBkL9Bi9q4PkT5dmH3Jp0vTtUmZQWi6FDB1B3u2q1HtKN9O
         dG+nEQQJfxCl6gw6S9sWIMTL9zL98TursB60lgbStFH84m9r2O1NcOzaS1/FrsD8PTIm
         rbw0ZIWx/33fqNAZV7vlqD9yi0IyfU+ZZrv4D1yXPqXnTmV8fncX1s/ityYmCyqOxtgb
         jSouiIeh9zxXwlo6l6a9/n2Zr3YNRie/EVUPZm4DHRnhQf1otc23unULtUDcClUG5IyG
         uPbQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=e5gkhTfe;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727122373; x=1727727173; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oYS0kYUiHT/SkcynsbjN4msqBo/RRmIU7KDWIfwLdIE=;
        b=x2N9l4ONMdeHPsRJhfMPE5WqUr55bymFxfRgcOJLT9S+WlzaOrTEcS2g/T4Qf+S2pn
         EGBTXmrcy9qaIUowaOxUExKeNkGPQX1aaA77G1VVNWeM31vhO9JcP78CgcuMlnOsbLXb
         7b7ke2RqdHBQc2fFR1vdUNPXTKGAcPM5S8DhJFZ1fgtPX2ACticMBYZ3b+b9PLsvvICl
         okjhKo9aXOn2JnlB5nViQPizdyK6lyWUiz1eqDDHT1/pXEJxJwP9p2n5FLudfbkeHJm6
         ysj9IcT9+hOQgxMtL2AT1+27qbP1Jwtj0W8SGUUILsDsp8SjubCWEcwBsjhnf3oz949z
         CbYQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727122373; x=1727727173; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oYS0kYUiHT/SkcynsbjN4msqBo/RRmIU7KDWIfwLdIE=;
        b=SwbiN8qRTSpRTIXslohsd85heMKr2D/X5ahS8yb0Wp+STJAprAo3vkQd3sp6Qwthpd
         9Liu3Y9gmOFtCo6w3sNCRgGmM+ACsnu/jawYfw4ijjqwshcPn3cYZ9rvWExxqOSVEfFT
         T9gyyv7cPz+fncFD8h7knPncHiza/eDfkulFKr6LrACYSk08VujlUv7D0+Riug/bp8GG
         OUECQonm+MACLZocbsQxcrW+q9glUYeFYvuuVAnTWDAj73+xoC6FPP4Gjy9okXUofaCS
         cI639B4b2Op2N+oqmGlbQskIyTodqhK/NSN+6BuUsCJmO77I5hd8YR7eltLUg5Ppu9l4
         WjfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727122373; x=1727727173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oYS0kYUiHT/SkcynsbjN4msqBo/RRmIU7KDWIfwLdIE=;
        b=ibZtjslCnOW4kO06xaOxLj76wpkHxbBb8M3G/Lo1LEwxG9lrGRERIE+GHBNNarcoQU
         rWJNivJU15R9A8NmZkvy4m5khooLzc5i/0ERWgSCVW5UMds/DJlVMAemZs5oEjcMBv+u
         T6pi6TiPNmEDs8+vCcTRfT4kM3YrwyKHnjYb9VOCsZjewoLcQB3ZhJin7xytk0h/XfJJ
         Bmz3IFgNPDNsaXIfHWTf+O8gebNs6jCqzoYgf7ZanQvWaC5BlCzNhTjP8xgEPO7mh8ar
         vkHZpshOvS1SAxNTkDizmphPc3cLG6MUZi8A0r0fJ6RPKtn6YyG7BWy+9oRx2+wAQd3I
         YlnA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUKTw2v3v7yPgtQpOWJ0SVInInPq4EggIY/h00rUwkWkOUqYd2c2dtrfNbcFmA7ICKDso8GIg==@lfdr.de
X-Gm-Message-State: AOJu0YxepiG/yruavnMjufGIQ+w67E36NRQL3U+cD2s8Ebo8H+nB83md
	HJOsoM0WXKwc61hTNXUavorN1umu4+MQFSHjVjtQ+MudxBiHaOJY
X-Google-Smtp-Source: AGHT+IGmHLNhtKdDHQ8lj4C7+Cv+jf9CFPAVCuMi3tpk30KcJhyG2MuMEZziPmo4+lqgBjU6VaZGqg==
X-Received: by 2002:a05:651c:2122:b0:2f6:6202:bfd5 with SMTP id 38308e7fff4ca-2f7cb335da1mr69463761fa.34.1727122372424;
        Mon, 23 Sep 2024 13:12:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:22c3:0:b0:2ee:de96:7d96 with SMTP id 38308e7fff4ca-2f7c3f7637els5662191fa.1.-pod-prod-01-eu;
 Mon, 23 Sep 2024 13:12:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUgxbOY17O9HxwI2LImWUP+2DYQSRQu20BFQfs2dDD6UYS/B0sOdAoX7VtquTeeE8J3dMJofaFcrCs=@googlegroups.com
X-Received: by 2002:a2e:8607:0:b0:2f4:1e6:5f57 with SMTP id 38308e7fff4ca-2f7cb35e5f4mr42547321fa.45.1727122370401;
        Mon, 23 Sep 2024 13:12:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727122370; cv=none;
        d=google.com; s=arc-20240605;
        b=S5AE3ax06xctVS+6a0l2+gLU2yyfwKhQiG2/oGUyQnLGc3RXEvjm8Lfyo05UmIkNCp
         i/sXSyjHqLMh/I2yiOVOx1Zh3zEP2RxqjKBd9dLv265smtlpMHcJpRJxozVWrAWtiyrZ
         mOZFxcRRw/P0Fba8K6+r3RP/bGSRXEvf22rdb7xjni6vwJUB2D5GTabZZmpXpXctoMJe
         0+82rj88kkDfPcfhP8pBhkwH0CmIMAAkbr67Tl0As8wJ8uniMG5tu/hZv3kS4PmKE2h2
         bOrInVrQ6vDyUQLrtyvOp4y/5luRPJFLY4/lo31HODlsc2C16HivdO8qsuw3MaJWy94a
         iXcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=CPBdIEyeOYukTmx0CMqxttQN8aHSVJKCKKsgOqt2gfY=;
        fh=gQEHGMBqEVkcJVTshV7CwpVdhAnhfpK7SQSmobDF8TY=;
        b=KcLu7faHtefa5rqOD8Hw25EshycSFFBXQvO6rGkrAJyPl/iOi9s0k3JE3kdqoPlFMx
         t2loIU8bThiRs6lWS4I+jmhUsl7eE6B6EfDLzZwrzzbgX88slrz0/W8jiG1reyOIW4XO
         a1v+tAf4wI/N+JmhSVu2SDBLveDoJbhcXZ/Rzy+PP0pmchJp24oKib1YYXvzfQe6XjNI
         qh+LwOhhq+8wdaHogkoVOlnzpHKE7YznRHDV21IZWxYDYaIdojoO1NkTe1plUl6RNc9N
         mKXFWIIq+YTJFlwT8CqHZ95NE2OQ2lZ7i45xF4HgQtzQsVs5Vrnu8AfyV/kzgllOmwPE
         NlXw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=e5gkhTfe;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f8d288b134si8221fa.4.2024.09.23.13.12.50
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Sep 2024 13:12:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-374c84dcc90so2841536f8f.1;
        Mon, 23 Sep 2024 13:12:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWEpDaZpcI0H5nuI2RAAMscPfMNO/QQ30IjWsRA5x8J6JwCZxTBZmjEdLVoAUi1n33YBI3bBpliDrTmnOMzOtw=@googlegroups.com, AJvYcCWnBDkfK+xRXdw1rw7O3E7q5i1xndNjhl/AzmPfkh3U7XNp05b+CGLmE4ypB/d0vbpMJmr1NqaMMCg=@googlegroups.com
X-Received: by 2002:adf:ed52:0:b0:374:c6b8:50c3 with SMTP id
 ffacd0b85a97d-37a422bf1camr6629942f8f.32.1727122369599; Mon, 23 Sep 2024
 13:12:49 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000f362e80620e27859@google.com> <20240830095254.GA7769@willie-the-truck>
 <86wmjwvatn.wl-maz@kernel.org> <ZvFGwKfoC4yVjN_X@J2N7QTR9R3>
In-Reply-To: <ZvFGwKfoC4yVjN_X@J2N7QTR9R3>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 23 Sep 2024 22:12:38 +0200
Message-ID: <CA+fCnZd6gXtwjBKSnChpT+dF9u8u68q2jVmR=MQHe4JhPBuvtw@mail.gmail.com>
Subject: Re: [syzbot] [arm?] upstream test error: KASAN: invalid-access Write
 in setup_arch
To: Mark Rutland <mark.rutland@arm.com>, Alexander Potapenko <glider@google.com>
Cc: Marc Zyngier <maz@kernel.org>, Will Deacon <will@kernel.org>, 
	syzbot <syzbot+908886656a02769af987@syzkaller.appspotmail.com>, 
	catalin.marinas@arm.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com, 
	kasan-dev <kasan-dev@googlegroups.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=e5gkhTfe;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429
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

On Mon, Sep 23, 2024 at 12:46=E2=80=AFPM Mark Rutland <mark.rutland@arm.com=
> wrote:
>
> > > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > BUG: KASAN: invalid-access in smp_build_mpidr_hash arch/arm64/kerne=
l/setup.c:133 [inline]
> > > > BUG: KASAN: invalid-access in setup_arch+0x984/0xd60 arch/arm64/ker=
nel/setup.c:356
> > > > Write of size 4 at addr 03ff800086867e00 by task swapper/0
> > > > Pointer tag: [03], memory tag: [fe]
> > > >
> > > > CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainted 6.11.0-rc5-syzkaller=
-g33faa93bc856 #0
> > > > Hardware name: linux,dummy-virt (DT)
> > > > Call trace:
> > > >  dump_backtrace+0x204/0x3b8 arch/arm64/kernel/stacktrace.c:317
> > > >  show_stack+0x2c/0x3c arch/arm64/kernel/stacktrace.c:324
> > > >  __dump_stack lib/dump_stack.c:93 [inline]
> > > >  dump_stack_lvl+0x260/0x3b4 lib/dump_stack.c:119
> > > >  print_address_description mm/kasan/report.c:377 [inline]
> > > >  print_report+0x118/0x5ac mm/kasan/report.c:488
> > > >  kasan_report+0xc8/0x108 mm/kasan/report.c:601
> > > >  kasan_check_range+0x94/0xb8 mm/kasan/sw_tags.c:84
> > > >  __hwasan_store4_noabort+0x20/0x2c mm/kasan/sw_tags.c:149
> > > >  smp_build_mpidr_hash arch/arm64/kernel/setup.c:133 [inline]
> > > >  setup_arch+0x984/0xd60 arch/arm64/kernel/setup.c:356
> > > >  start_kernel+0xe0/0xff0 init/main.c:926
> > > >  __primary_switched+0x84/0x8c arch/arm64/kernel/head.S:243
> > > >
> > > > The buggy address belongs to stack of task swapper/0
> > > >
> > > > Memory state around the buggy address:
> > > >  ffff800086867c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > > >  ffff800086867d00: 00 fe fe 00 00 00 fe fe fe fe fe fe fe fe fe fe
> > > > >ffff800086867e00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> > > >                    ^
> > > >  ffff800086867f00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> > > >  ffff800086868000: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> > > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > >
> > > I can't spot the issue here. We have a couple of fixed-length
> > > (4 element) arrays on the stack and they're indexed by a simple loop
> > > counter that runs from 0-3.
> >
> > Having trimmed the config to the extreme, I can only trigger the
> > warning with CONFIG_KASAN_SW_TAGS (CONFIG_KASAN_GENERIC does not
> > scream). Same thing if I use gcc 14.2.0.
> >
> > However, compiling with clang 14 (Debian clang version 14.0.6) does
> > *not* result in a screaming kernel, even with KASAN_SW_TAGS.

Yeah, this is #1 from https://bugzilla.kernel.org/show_bug.cgi?id=3D218854.

> > So I can see two possibilities here:
> >
> > - either gcc is incompatible with KASAN_SW_TAGS and the generic
> >   version is the only one that works
> >
> > - or we have a compiler bug on our hands.
> >
> > Frankly, I can't believe the later, as the code is so daft that I
> > can't imagine gcc getting it *that* wrong.
>
> It looks like what's happening here is:
>
> (1) With CONFIG_KASAN_SW_TAGS=3Dy we pass the compiler
>     `-fsanitize=3Dkernel-hwaddress`.
>
> (2) When GCC is passed `-fsanitize=3Dhwaddress` or
>     `-fsanitize=3Dkernel-hwaddress` it ignores
>     `__attribute__((no_sanitize_address))`, and instruments functions we
>     require are not instrumented.
>
>     I believe this is a compiler bug, as there doesn't seem to be a
>     separate attribute to prevent instrumentation in this mode.
>
> (3) In this config, smp_build_mpidr_hash() gets inlined into
>     setup_arch(), and as setup_arch() is instrumented, all of the stack
>     variables for smp_build_mpidr_hash() are initialized at the start of
>     setup_arch(), with calls to __hwasan_tag_memory().
>
>     At this point, we are using the early shadow (where a single page of
>     shadow is used for all memory).
>
> (4) In setup_arch(), we call kasan_init() to transition from the early
>     shadow to the runtime shadow. This replaces the early shadow memory
>     with new shadow memory initialized to KASAN_SHADOW_INIT (0xFE AKA
>     KASAN_TAG_INVALID), including the shadow for the stack.
>
> (5) Once the CPU returns back into setup_arch(), it's using the new
>     shadow initialized to 0xFE. Subsequent stack accesses which check
>     the shadow see 0xFE in the shadow, and fault. Note that in the dump
>     of the shadow above, the shadow around ffff800086867d80 and above is
>     all 0xFE, while below that functions have managed to clear the
>     shadow.
>
> Compiler test case below. Note that this demonstrates the compiler
> ignores  `__attribute__((no_sanitize_address))` regardless of
> KASAN_STACK, so KASAN_SW_TAGS is generally broken with GCC. All versions
> I tried were broken, from 11.3.0 to 14.2.0 inclusive.

Thank you for the detailed investigation report!

> I think we have to disable KASAN_SW_TAGS with GCC until this is fixed.

Sounds good to me.

Please reference https://bugzilla.kernel.org/show_bug.cgi?id=3D218854 if
you end up sending a patch for this.

Also the syzbot's kvm instance should probably be switched to Clang
(@Alexander).

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZd6gXtwjBKSnChpT%2BdF9u8u68q2jVmR%3DMQHe4JhPBuvtw%40mail.=
gmail.com.
