Return-Path: <kasan-dev+bncBDXY7I6V6AMRB45ZXGPAMGQEAT2G5IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 49F23677889
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:09:56 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id b23-20020a05651c033700b0028473c6cc7bsf2448124ljp.6
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:09:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674468595; cv=pass;
        d=google.com; s=arc-20160816;
        b=FNl9+fsVQmoL2BZSLtm2FfbxzaOX0BsSCjLa6ntZUqvU0mxYhLoM/8Yz6CcoSAgYhH
         hxhhZNz23iGseBjCSYF0LK7mTEfjOsJwEU09sW1rK7t5WM+1Pv2+83ygbJ1KyIq83/zv
         6ze08pCW8RJHcnZfZ82W9rZOrMlkf0sVX12NxevLQLWbAb4snfMIrIp+JQqpB50dfBSq
         3H6TrE8g/+uUzQjJ4cQ9XYJoOXaHW2I28R6Y46JuMPzPmikJdPY6r1LY2WxUMeXA8we+
         EhBE69qlaBnkXlGBJ0pBbZceZFtG0w3GPoLK6aqWy032u1TDfPiLPeucotPSMSPbSuhy
         rfsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=YF2BLVdvMAk8F8g3aDFMNZ7DTy9U1WAy0HTMjns0zM8=;
        b=U3pa1s2w43Evkx1Z1bXb1uQQIQu5Ad1AsYciMhfNpome/p3iH4pCPBh3TslhPYRt6v
         Z9MlOQ/QhJHCFJ2qeLwNvSVI1/zIvN/ePTIKVmoaycOxgWbNVW/ak52J6Gd+KJV5D0OP
         lgCJRsQqgqeTjd9CQlrmQQ6xtE9hDPhTtikVZhugY5xe7rd6/hUlw6FaxN0lEPOqf8RF
         6zXK0kmjuaieRVCcizwyq+0v4SUrfiymQe8oeIWXB/alQT7k2Q+gQNcd/AivkChisx56
         4WgDG+KOXGIxIWiqOh5Mcs7QTwnGPd0SMnfxagyjzj2VByriiQ+uKnkQzpCnI+NvUJ2t
         fn1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=dOwqxgrV;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YF2BLVdvMAk8F8g3aDFMNZ7DTy9U1WAy0HTMjns0zM8=;
        b=T9WBSa+QL/GojBHct6D6WE9F+YxG83ky8a8A6LPf4cZAdssvatew8CkSs5CH2pJr8Q
         djXZe7oW2wMgt1ZJR42rJpIHxnRbBz1/MmPrUAme0xMrZzUl89h7Fsuy6ePIqUCtrzDy
         2tc0YxxbbxjoxvGrTlHKxgOHX0kWjX7Z2Z6lNP8kqKJ4JUCQ3rn3JCytsXHFVEmpGGql
         fWNXK9jMRrQ3yyP3+r5RB/ku+EyKvXzi2ynvj4w0b9U/fq6SWpYdeVpE7WfY/O4pOc3N
         VMpjct4W+22Iw3/njTQnSViupeRkFwESzxHmHxb4sq2eEbFOSe8US44WRMdeo85gv/rx
         xdEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=YF2BLVdvMAk8F8g3aDFMNZ7DTy9U1WAy0HTMjns0zM8=;
        b=uHIExyT4Q5C0gqkuT+AvJhIf+gI+lpk40ObqpRPI06Tr4f7IMbhHqGxmAO9iKi3pqK
         LPeXHqO0vjN6i4fIS5Ehxo7UkGFBHAAW9Xcj2UXzgkBxIt68DGYHM1lrTh3y2xFUpCmj
         Ur32UaGKfkuxLDP0XoZXBKR+N3Os4/UFh6JKkDHFpd2yGdpYGYca0XOtZMxkP0aq/TSN
         B2rZkUGZYqWuvAoahJCbSEhmuwvtRliBUzqScGzAjrSTl/uuhG/bnPT+D6nH2ADQ+Knm
         jIv4xnFraHuUID6JVPc4qUGSE9n6wav6M/0XcLjgp7IrXXQkA2CyCPgiP++h+7VPTexU
         YAvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koT0n8rIAaYGR6n1k5HYaMaGt7wkzlE2GZ6IZhMTL6vDgFDiIzP
	/53kPgwJImJQO+5kiFdFJi0=
X-Google-Smtp-Source: AMrXdXstFmgwRqMV1GNGf6r34vi3t7QmdwXcarqtgavzT1GyRQEAX8+AIb3m/bjhAQK5WEfUMZ3mmA==
X-Received: by 2002:a19:ee03:0:b0:4cc:83a5:e64d with SMTP id g3-20020a19ee03000000b004cc83a5e64dmr2300046lfb.455.1674468595293;
        Mon, 23 Jan 2023 02:09:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8743:0:b0:280:210:b2fc with SMTP id q3-20020a2e8743000000b002800210b2fcls1447445ljj.4.-pod-prod-gmail;
 Mon, 23 Jan 2023 02:09:54 -0800 (PST)
X-Received: by 2002:a05:651c:118:b0:280:11c:c28 with SMTP id a24-20020a05651c011800b00280011c0c28mr5262051ljb.33.1674468594031;
        Mon, 23 Jan 2023 02:09:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674468594; cv=none;
        d=google.com; s=arc-20160816;
        b=JOg5Iulh/JOGpUbRinSD7+jxlyB2McCJCFCylOB9qCkfK6WdKWrrm21Eu9QchL4JlP
         uX69XliNsw6O60Vgq/40vma7ddOhcxsaHuSIGuIuwgBmTLVJXiweMAJFI9HpTnDeixCs
         IW01FISg4/vkLwU7aBQkeoY6ct21iO2kkai0wdxWekzCBCiFDn9pTRl2tjdfxcIQuAy7
         Hv733K63J0oMbcjQkVoihxE4dZxqAMSd2ARfOe/qSNLXbPIGumz6sfgjLPcmLpedoMyU
         qYiwicwPDHaBekFJY89rLPRo5PCKsTHEvkuxRZQ0cTj+oftf5i7NDdjezBAJhfzPbhsv
         FCVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=BowUBQydnAafqAai7xO8TqOkM+didbH9IqQu35TSCq4=;
        b=aweUhOH5q75lrQPL4LjQuG5I3+3cFjoBKk98g/P/GONTyk33XAKSmMsZ3OEm0m5nHA
         6uXpAj5zjW5z04Sv6rxtaaTjYPqetbje52pCXrmukzw6VJ9Lhu2BTw4Z6S4wjaGkECtV
         IkyCTCT1rAYXWTLyALWZJNMFx1hMeeylNd0ZiyJAw3C1Uiy9uwZ19G22KQr/7G9Gpj+F
         lrY7+ghNUxDzmVqIC+WDcMRkJDEEri2FUjnTNp/BUavElKXhPijVDdsRT4BYXaao2l3c
         qxltODqhAcuHLdyliQIAa1xrd6fPKz9gTpOb917PAwib2iVOYkEyH9kgYdgT3JY538tJ
         nXVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=dOwqxgrV;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id i28-20020a2ea37c000000b00279a2f014e6si2096029ljn.0.2023.01.23.02.09.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:09:53 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id f12-20020a7bc8cc000000b003daf6b2f9b9so10182482wml.3
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:09:53 -0800 (PST)
X-Received: by 2002:a05:600c:1c01:b0:3c6:e63e:23e9 with SMTP id j1-20020a05600c1c0100b003c6e63e23e9mr23745245wms.24.1674468593747;
        Mon, 23 Jan 2023 02:09:53 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id bi16-20020a05600c3d9000b003daf89e01d3sm10170407wmb.11.2023.01.23.02.09.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Jan 2023 02:09:53 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v2 0/6] RISC-V kasan rework
Date: Mon, 23 Jan 2023 11:09:45 +0100
Message-Id: <20230123100951.810807-1-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=dOwqxgrV;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Content-Type: text/plain; charset="UTF-8"
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

As described in patch 2, our current kasan implementation is intricate,
so I tried to simplify the implementation and mimic what arm64/x86 are
doing.

In addition it fixes UEFI bootflow with a kasan kernel and kasan inline
instrumentation: all kasan configurations were tested on a large ubuntu
kernel with success with KASAN_KUNIT_TEST and KASAN_MODULE_TEST.

inline ubuntu config + uefi:
 sv39: OK
 sv48: OK
 sv57: OK

outline ubuntu config + uefi:
 sv39: OK
 sv48: OK
 sv57: OK

Actually 1 test always fails with KASAN_KUNIT_TEST that I have to check:
# kasan_bitops_generic: EXPECTATION FAILED at mm/kasan/kasan__test.c:1020
KASAN failure expected in "set_bit(nr, addr)", but none occurrred

Note that Palmer recently proposed to remove COMMAND_LINE_SIZE from the
userspace abi
https://lore.kernel.org/lkml/20221211061358.28035-1-palmer@rivosinc.com/T/
so that we can finally increase the command line to fit all kasan kernel
parameters.

All of this should hopefully fix the syzkaller riscv build that has been
failing for a few months now, any test is appreciated and if I can help
in any way, please ask.

v2:
- Rebase on top of v6.2-rc3
- patch 4 is now way simpler than it used to be since Ard already moved
  the string functions into the efistub.

Alexandre Ghiti (6):
  riscv: Split early and final KASAN population functions
  riscv: Rework kasan population functions
  riscv: Move DTB_EARLY_BASE_VA to the kernel address space
  riscv: Fix EFI stub usage of KASAN instrumented strcmp function
  riscv: Fix ptdump when KASAN is enabled
  riscv: Unconditionnally select KASAN_VMALLOC if KASAN

 arch/riscv/Kconfig             |   1 +
 arch/riscv/kernel/image-vars.h |   2 -
 arch/riscv/mm/init.c           |   2 +-
 arch/riscv/mm/kasan_init.c     | 516 ++++++++++++++++++---------------
 arch/riscv/mm/ptdump.c         |  24 +-
 5 files changed, 298 insertions(+), 247 deletions(-)

-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230123100951.810807-1-alexghiti%40rivosinc.com.
