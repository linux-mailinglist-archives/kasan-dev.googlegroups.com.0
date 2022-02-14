Return-Path: <kasan-dev+bncBCRKNY4WZECBBTOWVOIAMGQER4T4JTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 38D1D4B5E75
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 00:52:47 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id 2-20020a251302000000b006118f867dadsf37170954ybt.12
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Feb 2022 15:52:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644882766; cv=pass;
        d=google.com; s=arc-20160816;
        b=E1uZQ62kC8++IOMfz0efXGYg5/o9cWqr2ZQ0ZT1QbWNAipb2wlwhFhzx4N7GOFJzWP
         Ala+W9SXUnoF7xnp9gmP9dQowcxkPL+gMgLHsPf0mTV2LTcqfUf8N+u95cXw3b0yEu7U
         X1pg4uItykJAbiqvRp1sfQxQbYVEsoEr9U1ZdeHsCCOXUxZdgFXv4K0HGXzve8ot4Oze
         cNUOllyeE3Aqj6yc569CO5baymuO/b0qvzDBcD2VKepTYsk/+1gOvCIg67V0xT0JvIXV
         SzC9XAHJDhNNVmGoZoasDS/QlwlLoaZbDUu49+b8Hne+vpJ1mqhKYTBWHocj6Y6JbHlS
         ImPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=m2wHRXIeE8QV+RV6JgOoBVboj6sZfrhU+APKfXRYaOo=;
        b=CrLjS6+1b7rjFufkwvDw9JXGMZNj/R+NCr06sx+PW/OiIqNL9R+/x+bp7/nTfwdC0C
         22H86j/m6qK9UuSzqFEf4IIMnkllp2u/tb6gCxWCnbI0haxl0BDBpKNxWXO2z3PWYAP6
         X1BB9DBDoWn5mHfXW2r7HIf/rU+A75BbXmjdHAzWtV1pSV9m+08sRsHigUQ0zY6GKwJj
         2CFqMCbHdO0XvG7jtPAp96fNwX/wb/u8X+RLnLnLn6mxgwWktunQIYTrHZtCrKuNBO9R
         UzyXa6fF7YMKjo9xFvJ6xXxpp6vTnzZHER6UxVgBI38C6QR04qL6UXXmyYH/VQib1ibY
         IBIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b="B7/gLLy6";
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m2wHRXIeE8QV+RV6JgOoBVboj6sZfrhU+APKfXRYaOo=;
        b=btsytal14fwmoRwJbIZ0X+VchZq4WKvBPSMBRbS8AXSBrcw3kQCz2YTGJ/L1G+7/Wo
         QlqmnQHaiBFO5Ho68BSL6RqmkwS0qWnRkL57VwlwpEI1jyJR3a3FyoguKB9hZ4taeM25
         UfhOqkU2hSWoNOUjeaz63d/gy6H3DHkqgbqL/d6EUVx6ezP6OosYrV5xh4OREy2q8Rvw
         FT1WXEVSKyxtTf3fJL1m3BsyMNl+0T4P6EQfZQu+jOBDj/7zTHB+Vh0vF+WZaFlgt15U
         s0oJc7olq3pBnGnfW58cngQkjQnuw5N0/+vo2VJX+bNFan/L3tR1MFITs13naNQ3Kcmu
         f8Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m2wHRXIeE8QV+RV6JgOoBVboj6sZfrhU+APKfXRYaOo=;
        b=DuaD8QTaRay2/D8bLBJZW+otP8P7rdMwK4i9+7TQfRalvkEciIlRLwNdL7PseqNGgU
         c2G5baq70oI0fTisz+1Se9Ftif7PcnVYemBiSNfI7bjKY+the8z0QtJjjOXgewJI6y96
         7x0oQ2NBLsIdI3G0kDRxBPHe8UrijmPEwsgXZs4t6NxW7apNbrPgZLkKWLo7g4Mz+nQ+
         XB2Az62Dq1njrTdnBLjQ0aEFiWlf0E/vi1Ue9Jq4ofKv8PYLiMKw4ZEG2jD3NaAR8VsQ
         UESV5vea6GLdSdpcbZ7soJMHcCO0VYej+85hNKwLAn4KC1bXANsiWkuNwNUTf1fMIoM6
         WzKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531mrmmjfvbwN6+hcoWmyQzUunDtQx1pWtQFPA7ixzQDcbiNRTNs
	2AaXHiMMZqoLgEMPFzWvhYM=
X-Google-Smtp-Source: ABdhPJzOALUp3Zs7v1Frw8VNMQkUZnxhjR0ZhkLM8KgOOfwgnSb1rHGI7pL7FNqWhm0xVF6jVZzxnw==
X-Received: by 2002:a25:2fcd:: with SMTP id v196mr1580273ybv.411.1644882766094;
        Mon, 14 Feb 2022 15:52:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:22d5:: with SMTP id i204ls1099171ybi.11.gmail; Mon, 14
 Feb 2022 15:52:45 -0800 (PST)
X-Received: by 2002:a25:6a55:: with SMTP id f82mr1472842ybc.1.1644882765664;
        Mon, 14 Feb 2022 15:52:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644882765; cv=none;
        d=google.com; s=arc-20160816;
        b=HWVV2CAHY6twRJAmH/nbxP5pG6wec5kMWUKl37vwWT48exsbTBvdJdE1n8kTIsbq2q
         MvhsaWaAUC28AG9xensNlImgBObae1+bQ+vZQpp6x7iUbIIcH8UuXnSuNdOLE4B66NlS
         5ZeQkJgBhLqFsoYhHVnt/CwkFpHj1dgd1IYygavYAib314gdt3ZKf09U/MQq3qzQrZsB
         G4KBHaIkwVbQgADtVnNV3bQiXWtsyHYoqNdkn2wPv3YdKdTe5QlXXT6+BR9F3J9ooHON
         djzhXhxz4H2SeFGyZPNi1tWppxmHm85cR2bUyfSLfzWHoL3GE5+Pd8Idv7bh+nqpE430
         XzQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=q/68wf5KGxajLpQXjSmh69B044maP9rOcGCawmFkP2M=;
        b=fp1Egu80qOaB9NeuPHQr+HfgAbVk2X/qJJfVkoNqmnCvmhQM3Q2xKHtUicv2ql2lZs
         VFK1BYF8fVpNqtspUihJ20ZPPdxPgYAoq5tJnfBu2BoNQLhT8h6Qid1yFx2CLeEi3dtn
         D2NZBv3oZt3Q+H7A2g/rcM6GHaBs5dNgrJosDFnNGIPVLcgOop+6V/LZSyeT16r5devH
         E3CttWQRUpz+FQPKoF+7hWq4/z8IPSNraU/bc6hlL4norsNlgg18R1vrcrxoPZSRip+R
         NUOIRai8Ol4bUPvnM5gpEfZvdqXNYu3XJY++p26RdNXN4qeDN4a4c+XK487tGN5APcqG
         KepQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b="B7/gLLy6";
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id h5si3039159ywm.1.2022.02.14.15.52.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Feb 2022 15:52:45 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id l19so26127720pfu.2
        for <kasan-dev@googlegroups.com>; Mon, 14 Feb 2022 15:52:45 -0800 (PST)
X-Received: by 2002:a63:b17:: with SMTP id 23mr1249158pgl.103.1644882765243;
        Mon, 14 Feb 2022 15:52:45 -0800 (PST)
Received: from localhost ([12.3.194.138])
        by smtp.gmail.com with ESMTPSA id q26sm540251pgt.67.2022.02.14.15.52.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Feb 2022 15:52:44 -0800 (PST)
Date: Mon, 14 Feb 2022 15:52:44 -0800 (PST)
Subject: Re: [PATCH 0/3] unified way to use static key and optimize pgtable_l4_enabled
In-Reply-To: <20220125165036.987-1-jszhang@kernel.org>
CC: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
  alexandre.ghiti@canonical.com, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: jszhang@kernel.org
Message-ID: <mhng-41f2520d-7583-41b3-ae7a-95e74117676a@palmer-ri-x1c9>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b="B7/gLLy6";       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Tue, 25 Jan 2022 08:50:33 PST (-0800), jszhang@kernel.org wrote:
> Currently, riscv has several features why may not be supported on all
> riscv platforms, for example, FPU, SV48 and so on. To support unified
> kernel Image style, we need to check whether the feature is suportted
> or not. If the check sits at hot code path, then performance will be
> impacted a lot. static key can be used to solve the issue. In the
> past FPU support has been converted to use static key mechanism. I
> believe we will have similar cases in the future. For example, the
> SV48 support can take advantage of static key[1].
>
> patch1 introduces an unified mechanism to use static key for riscv cpu
> features.
> patch2 converts has_cpu() to use the mechanism.
> patch3 uses the mechanism to optimize pgtable_l4_enabled.
>
> [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
>
> Jisheng Zhang (3):
>   riscv: introduce unified static key mechanism for CPU features
>   riscv: replace has_fpu() with system_supports_fpu()
>   riscv: convert pgtable_l4_enabled to static key

I see some build failures from LKP, but I don't see a v2.  LMK if I 
missed it.

>
>  arch/riscv/Makefile                 |   3 +
>  arch/riscv/include/asm/cpufeature.h | 105 ++++++++++++++++++++++++++++
>  arch/riscv/include/asm/pgalloc.h    |   8 +--
>  arch/riscv/include/asm/pgtable-64.h |  21 +++---
>  arch/riscv/include/asm/pgtable.h    |   3 +-
>  arch/riscv/include/asm/switch_to.h  |   9 +--
>  arch/riscv/kernel/cpu.c             |   2 +-
>  arch/riscv/kernel/cpufeature.c      |  29 ++++++--
>  arch/riscv/kernel/process.c         |   2 +-
>  arch/riscv/kernel/signal.c          |   4 +-
>  arch/riscv/mm/init.c                |  23 +++---
>  arch/riscv/mm/kasan_init.c          |   6 +-
>  arch/riscv/tools/Makefile           |  22 ++++++
>  arch/riscv/tools/cpucaps            |   6 ++
>  arch/riscv/tools/gen-cpucaps.awk    |  40 +++++++++++
>  15 files changed, 234 insertions(+), 49 deletions(-)
>  create mode 100644 arch/riscv/include/asm/cpufeature.h
>  create mode 100644 arch/riscv/tools/Makefile
>  create mode 100644 arch/riscv/tools/cpucaps
>  create mode 100755 arch/riscv/tools/gen-cpucaps.awk

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-41f2520d-7583-41b3-ae7a-95e74117676a%40palmer-ri-x1c9.
