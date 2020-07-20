Return-Path: <kasan-dev+bncBDE6RCFOWIARBHGN2X4AKGQELQGVQZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 93AC5225BDF
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jul 2020 11:40:44 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id i10sf11887219wrn.21
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jul 2020 02:40:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595238044; cv=pass;
        d=google.com; s=arc-20160816;
        b=KBahAZWHDbkaSagl44/A7jZ/Np7B9jVdXSUGC3RJ4kEqPi5+RoGzjUG9pivExZr4RR
         Qgm5GSSBDVTuZ2OS3KdZNMq811gBE2CHKJnDjeCQeiVQmclrZwc68C6ie45nOvhQrKSL
         xrH6KHVppOgv5FiW6wjZ2DoMMHiJOA4TBrSVBhc7H/KqmxaJ6cpyg8EvrGEUnJeJ1CCP
         ZOx2yQ50kQ2pJzGnXjgW+LLZE94t3lPAGCP5wP4G4XWRixIje8MfQj63H6sj9Fkc8owD
         Qs3ZUR6S6Kv+v7LGdnWKdX+fgelJoQdemdGdfe3jClXty+YasvvA9jWiEmgbMqtyu3B3
         3xYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature;
        bh=ceiG2Dj7XteIBOTw8Tq/0J2zV/tHrrPpEuevRb8ZumA=;
        b=VeCkTsUtcr9qErvelS2Rvplgcj2TTLLjf7lmATPo4mcmu+fRrtPArjg8tkmjGWrSPm
         V3PS+kRApG0+WgHrZOSLwESFb4tnPu234G/CgwZkBuZLD+P5XMF0KGEaqSV/yzyU0uFS
         EeBdsGtxVj6C74eZvzjIVqzfJOQyfqj9SYDpqyZxyc6NPsg2nEoKMESmuIOdeT7h32d7
         ya1FJradOLuWFxsWC8Mskxo9CtkZ2jXTXdAlYzDEHU7ZHi87bt8b8OLGtSBCTMjebWY5
         HFpaNX1CRlmFYcdQTrb9YJfnvEBY+TX+7Qo7isWEj+zW3/4KSC2ym/J1bFBQUcOAS53Q
         SdvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=PJ7as5lT;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ceiG2Dj7XteIBOTw8Tq/0J2zV/tHrrPpEuevRb8ZumA=;
        b=ZvAsCj04M3T2GoaxHxlD5pPkM3l9ayrmsfIlUwJESePMfl16H9Zd0o6erK/JwMaJst
         5zsw5ZgjABKs+BuCy4S11eNkPXI0o7oQWxRMNpq7DHAypuMJ8MnUYA+0qi+f+Sv1fxeP
         jYVdNApeYebHEQYupYwhfNNJztHY+NeU07h8iwwXlQtCTJTcUYelY8OHPmc4HJWi+bi4
         urM+UCc4edlIFZiKPNCH0+lFrrYmAugL1+tVmRjHlUmp/RbfFEQaVXquKhdUqYvXxY3B
         KS6YefyQAj21hcvir7brxeaNkiIJwpVoaiJZuVCC+8qErxuzALuJT2JwIp+mYQWXTcq8
         qcMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ceiG2Dj7XteIBOTw8Tq/0J2zV/tHrrPpEuevRb8ZumA=;
        b=abC3/Ey6WeGas6WCMUTTgxhGr4T6X9PEIclOZXhwwMusBaG2DpKVs+tpCL/QpI6U4O
         fZAElszdQ5liOzIES2b3iyO0KiKS8JINYAU8vsFhq+9mFjZI4AKZfSMgOtticHPSf22W
         VAn8SiO/JN/hvBIyHdCPiiLNP+Jpm/mpMscYLBxc+nOu//ce1lvMhk//NBm1tmKALfJ7
         lWGwPojtGA1MVEtIZAlxYq+FKkhAu69/UPX7HguS3/z8/B41Vlvj+PdVVjcFvzgMnHG0
         pPQPG1gRXlBktGis0E6xw8Ch6yWZO9mathL6ER1c+XXJnYIcOxdhKY5ouOvvzR3L0jyz
         BDew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zCQDDHQRv1E6hoppsQVG2Et7M4Gx/TrLghZiK1plCukEC6IZ7
	8Gh/fpc7uzyD8T+A5OAyAcs=
X-Google-Smtp-Source: ABdhPJypQLgauNJPGsl+FxkJsZenvNAv2pwf/wtE5jUbWHCOARAjIgeLWjW3Q0jh9tWytTcceaw12g==
X-Received: by 2002:a7b:cc92:: with SMTP id p18mr21557823wma.4.1595238044265;
        Mon, 20 Jul 2020 02:40:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:b445:: with SMTP id v5ls5025849wrd.1.gmail; Mon, 20 Jul
 2020 02:40:43 -0700 (PDT)
X-Received: by 2002:adf:f682:: with SMTP id v2mr9844028wrp.90.1595238043784;
        Mon, 20 Jul 2020 02:40:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595238043; cv=none;
        d=google.com; s=arc-20160816;
        b=kgfeyX/Sp/p8oJVB+9NVdnDV6iNR3Udzb1yKeFs/jTq5O2+leL6pyH+0/qwmxb/S0M
         jR4crf/U8CZDkmfXpnznKPbV1qqUuYRKBsuL4Xnp+0kZW5dLUkOWOfLDHfOLWWcfVBce
         p/XuyG+eDEdC+4r9k7B9p9dPXSebdVNhUYtm7yUli5l0xmhha/wY0h229oT/Tsdaybq1
         Q0GexrQOl6kWe6w63FWvafbO+M0KVjVH2nGlrxSYtIiGt2+W2q+Y3xw3ihkjiNJzJlt+
         sqU4IeaPTAeyLdsLE2Gri0kwr/0Bul6/fVoHFjr3dkGG02RmEk3wBBva18+kjESBLxfh
         ZR/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=J5+cpk78RQDatxKOYprm8R+FizAj2MbQYctVJ1smedA=;
        b=COCNimHJf6/jajnDHqrEZyZCPNZHlh2XVeK30fArUNBVakrISpC6goy1JJSHyD7Brn
         SpYX/ZtB0le2VVIpuZYtqPTVChKPEzgdMiv4oNtiRjRiUXdJJO3uZTwaIJP9WOsIuYOE
         k8vMLhteMy/8VQVeJDkJwhTxrKWDp7H0a+gvvljRK5xU/Hn5iKAgeYMarHGynhPBHSxY
         qQmDZy5a9Z5FJVNyqIjeJVowF/QjKyJCPd09sUAM5vIa5os9J1KxudKpSTMHH3IrjvFk
         7dCrDOCwV2AAPIxDyh9QDH6IeCmn0PEnIH8mmOYOFf9WBJfcbs6KPgcf8peeqE5cB+0g
         oyuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=PJ7as5lT;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id y12si165362wrt.1.2020.07.20.02.40.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jul 2020 02:40:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id i19so4110767lfj.8
        for <kasan-dev@googlegroups.com>; Mon, 20 Jul 2020 02:40:43 -0700 (PDT)
X-Received: by 2002:ac2:5dc1:: with SMTP id x1mr543538lfq.217.1595238043423;
 Mon, 20 Jul 2020 02:40:43 -0700 (PDT)
MIME-Version: 1.0
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 20 Jul 2020 11:40:32 +0200
Message-ID: <CACRpkdYbbtJFcAugz6rBMHNihz3pnY9O4mVzwLsFY_CjBb9K=A@mail.gmail.com>
Subject: [GIT PULL] KASan for Arm, v12
To: Russell King <linux@armlinux.org.uk>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=PJ7as5lT;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Hi Russell,

please consider pulling in these changes to bring KASan
support to Arm.

Certainly there will be bugs like with all new code, but I
think we are in such good shape that in-tree development
is the best way to go from now so that interested people
can test this out.

I have tested it extensively on classic MMUs from ARMv4
to ARMv7 and also on LPAE. But now I need the help of
linux-next and the broader community to iron out any
remaining corner cases.

I will of course respect a "no" but then some direction would
be sweet. I could for example ask linux-next to include
this branch separately from v5.9-rc1 or so to get some
coverage.

Thanks!
Linus Walleij

The following changes since commit b3a9e3b9622ae10064826dccb4f7a52bd88c7407:

  Linux 5.8-rc1 (2020-06-14 12:45:04 -0700)

are available in the Git repository at:

  git://git.kernel.org/pub/scm/linux/kernel/git/linusw/linux-integrator.git
tags/kasan-for-rmk

for you to fetch changes up to 5ebcc6d74e3b7791e3b1c3411a62d216fc5c5230:

  ARM: Enable KASan for ARM (2020-07-20 11:29:31 +0200)

----------------------------------------------------------------
KASan support for ARM, the v12 patch series.

----------------------------------------------------------------
Abbott Liu (1):
      ARM: Define the virtual space of KASan's shadow region

Andrey Ryabinin (3):
      ARM: Disable KASan instrumentation for some code
      ARM: Replace string mem* functions for KASan
      ARM: Enable KASan for ARM

Linus Walleij (1):
      ARM: Initialize the mapping of KASan shadow memory

 Documentation/arm/memory.rst                       |   5 +
 Documentation/dev-tools/kasan.rst                  |   4 +-
 .../features/debug/KASAN/arch-support.txt          |   2 +-
 arch/arm/Kconfig                                   |  10 +
 arch/arm/boot/compressed/Makefile                  |   1 +
 arch/arm/boot/compressed/string.c                  |  19 ++
 arch/arm/include/asm/kasan.h                       |  32 +++
 arch/arm/include/asm/kasan_def.h                   |  81 +++++++
 arch/arm/include/asm/memory.h                      |   5 +
 arch/arm/include/asm/pgalloc.h                     |   8 +-
 arch/arm/include/asm/string.h                      |  21 ++
 arch/arm/include/asm/thread_info.h                 |   8 +
 arch/arm/include/asm/uaccess-asm.h                 |   2 +-
 arch/arm/kernel/entry-armv.S                       |   3 +-
 arch/arm/kernel/entry-common.S                     |   9 +-
 arch/arm/kernel/head-common.S                      |   7 +-
 arch/arm/kernel/setup.c                            |   2 +
 arch/arm/kernel/unwind.c                           |   6 +-
 arch/arm/lib/memcpy.S                              |   3 +
 arch/arm/lib/memmove.S                             |   5 +-
 arch/arm/lib/memset.S                              |   3 +
 arch/arm/mm/Makefile                               |   5 +
 arch/arm/mm/kasan_init.c                           | 264 +++++++++++++++++++++
 arch/arm/mm/mmu.c                                  |  18 ++
 arch/arm/mm/pgd.c                                  |  16 +-
 arch/arm/vdso/Makefile                             |   2 +
 26 files changed, 527 insertions(+), 14 deletions(-)
 create mode 100644 arch/arm/include/asm/kasan.h
 create mode 100644 arch/arm/include/asm/kasan_def.h
 create mode 100644 arch/arm/mm/kasan_init.c

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYbbtJFcAugz6rBMHNihz3pnY9O4mVzwLsFY_CjBb9K%3DA%40mail.gmail.com.
