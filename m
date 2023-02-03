Return-Path: <kasan-dev+bncBDXY7I6V6AMRBRH26KPAMGQEMIX6SHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F529689141
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 08:52:37 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id o8-20020a05600c510800b003dfdf09ffc2sf1828657wms.5
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 23:52:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675410757; cv=pass;
        d=google.com; s=arc-20160816;
        b=wmD0vH9K4KpC9mtOm7nSvGVjDPVBeCEc5MCcn1YHtbF5LGpj1ayOe4WNV9SY4ywydI
         oki9WvG4r9SuDzpwxid+aFdTLmoniysTWTdyDcUcCs/8x+fC6ixa31nodGpaCN6KzcZX
         Z2XUlyX44WY361v7G2c9RcNQBqDNIF81guZvBHCPcvcVueKG+W8Vuh7SPrhyK/RwEVny
         A+mzxieJ+8HrEfrjIPgfqDzNNerkhUmtE8lnV0ND8TPE1DUMrv6WXYNF+5bSSFmdEf1r
         cAnLMuxx+/9j2Dk4iHvCQsaY2jEd4tUoFRnjPl19PBWaAobiwP5qpTi5rBiG+X9VABaJ
         SD6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=bz/J1U9iytLmj9t4HJ46cg4XICO2qqg61NC3/lv82I0=;
        b=u1Cpq4Ql4XybOlp5LOy6lwFoEwmeppPCUjb8uG57qx9bBBEJST922G72h7JZoLtrcr
         6CdVZ3djpRY7WTDi3o+l7HvmngARCV0U35xyM9J9DRx4EUlHGPdEKIOargIdNmWjLxCH
         gxJtdJ5YhGiL1nzQLqBM2VBAOc4vhlGNInngwMlOTawv9DXwJPN6KsUiyQQEhcmQ7BPj
         2k/Em+I3sTL138dogwxpILLjipWL7W21/lndJpQeydWkPmQGUOjkttoO/KoMnM//38D7
         fIzMi7wDdJrkSqG4U7815kc8/Mz/NaeEVRByFEC7tcgpm6+OnCViP3npH/bpG04TkbaF
         rm3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=qQ4IzbW+;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bz/J1U9iytLmj9t4HJ46cg4XICO2qqg61NC3/lv82I0=;
        b=ANUgJZ5siYaDL2VdB913l/LgYWCnzE2V8ebtPIuUkq5qt3yQMvBr9zbnppCb9PKD3x
         ngo033R0+eDQ9q3qUNOPs3w9jK3wBTkrnS4+Po1cCVxOZWek8W3LuHEMZmssFDftnxV/
         56fMV9h+vZbwmfXn/zn18C6N9fZuhFAE+WQiqSwSo6uC8vXHA6m4p4nIyHfm3vOJeBHn
         iz93xcEyvp0q0YNsHoFSn/2uqpHvu/6pMZ8ZOUZDqISSb13U5dstIaC161mVtRRiGu+B
         H2dDIFCYCtXRQjlPEzGz+F/8FD1WDDsecFFzYZJS/plgLxQj/OMagalvlgsi8KbgF4Ru
         9pKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=bz/J1U9iytLmj9t4HJ46cg4XICO2qqg61NC3/lv82I0=;
        b=bShI+ws/V3SDJ4AlSPks7JGWll07JHvOeyDmHs6ufdeFH+6iij5GCZCp1Df285XRVY
         cCUU2I820IfFlk3XxEM7YlJUEBuoB2/DqPC5NJMhrCshTbG6FVCZl2S6XXiRTJi5EXtr
         SZ1GnNBHoaYNeBXbnVukPua6E22zK1/cUGZ9XeXs4WQ+RNKJParvEphDyYez8gGcE3o7
         YTGA3+lFCHvcdd4gTV/5zwOeBzcXPJ8uRggwwhb2niIOlyO+S48FIyN5VCb9dl13tdn1
         7y69l5T7ZY0N2ivKCFuGTMCS0WRDwvGavfr9kTKq6nvPcZU0Nw6T5BAVIeroXxFH14V2
         q6EA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKU/PNWuv/w6RjEOqnViLA+28XFsxxSDU4uWySIaUIVpW129OB92
	02nofAx3hxrYgOvj1AqdCxw=
X-Google-Smtp-Source: AK7set/fjjGEZMnLLNCOAmeYFeeDnnZFEJ4WhW/WpwB2sdFxnFlMZgTr42ys3rPmfLc2YbHyczELqA==
X-Received: by 2002:adf:d4c1:0:b0:2c3:d35c:c1d8 with SMTP id w1-20020adfd4c1000000b002c3d35cc1d8mr50530wrk.317.1675410757007;
        Thu, 02 Feb 2023 23:52:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:35cc:b0:3cf:9be3:73dd with SMTP id
 r12-20020a05600c35cc00b003cf9be373ddls4252003wmq.3.-pod-canary-gmail; Thu, 02
 Feb 2023 23:52:35 -0800 (PST)
X-Received: by 2002:a05:600c:3b26:b0:3de:3ee3:4f6f with SMTP id m38-20020a05600c3b2600b003de3ee34f6fmr8769612wms.8.1675410755712;
        Thu, 02 Feb 2023 23:52:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675410755; cv=none;
        d=google.com; s=arc-20160816;
        b=qk4npXTdF8URzvtr2GbI0d9+MmoN5nSHMlOoHJy0AXZs06Z+BuxV8ZHwKwZMOAw7fO
         WVFcZfxoM3GRv1eJ8UeSSgh/h6tQZNU0xNJMrttGY+EadDVD9lWVrYOOL5t8iL1a2Chu
         LZVBZekCndmnbkWGBrI1vn8YWuCUNFJW1aJ+xuz9drmtMuAo13As/NFXpY4Ds8rjXB4l
         pGe5DTpTVf2WyvHXkVHMtq1/cb5XO/49hjXrX4qj+6QPG9qE5FDn9Nc0g/mzRqj0ZZhP
         cLe/BQSRMl7Tf3hVqXTBZ7rQr43ho3WWBrgxqm2SdwjXwU2ifpmDU3U98flXlDWCDNSM
         l0Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=NlhJRyLGWhYCTglJAyNtdlMktkkn7B+K+8DalaA2gVM=;
        b=YP8h0FpXAhXoJQWIksSyni1q+pxKJm8QLWEZZS/4S71wFkOc4R1HSPCpli88qMQz+O
         +3QBRYKxZJkNlXuWmaZkhDuuNY5S2pNPN50ZgwLJm3WYKCo1eid29lr+0aIcBZrY+Ny2
         qxNdzMSmpdZWqKYx9ACg8ct1kd3Y5WytMQUsl6tNUyDEU47+S/lQ/ZSD4jpL/I7aGBP4
         NC/DCWIAGSsbFyx7SI57/1eQtnpt+zKHVXJjJiODT1mdOxEcT+jrrji2L81/9PYEdV0P
         oJkF1j8Esn4ofDN51LJBEIX+IT9mw1gDKzo/LRdciZ0SD1vQoetmXkIWKpYgWZHd2Jvy
         DBxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=qQ4IzbW+;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id n23-20020a7bc5d7000000b003db0d2c3d6esi368861wmk.0.2023.02.02.23.52.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Feb 2023 23:52:35 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id k16so3203536wms.2
        for <kasan-dev@googlegroups.com>; Thu, 02 Feb 2023 23:52:35 -0800 (PST)
X-Received: by 2002:a05:600c:1e19:b0:3dc:52fc:7f06 with SMTP id ay25-20020a05600c1e1900b003dc52fc7f06mr8189377wmb.41.1675410755367;
        Thu, 02 Feb 2023 23:52:35 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id v17-20020a05600c445100b003dc433355aasm2020861wmn.18.2023.02.02.23.52.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Feb 2023 23:52:35 -0800 (PST)
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
	Conor Dooley <conor@kernel.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v4 0/6] RISC-V kasan rework
Date: Fri,  3 Feb 2023 08:52:26 +0100
Message-Id: <20230203075232.274282-1-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=qQ4IzbW+;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

base-commit-tag: v6.2-rc6

v4:
- Fix build warning by declaring create_tmp_mapping as static, kernel
  test robot

v3:
- Add AB from Ard in patch 4, thanks
- Fix checkpatch issues in patch 1, thanks Conor

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230203075232.274282-1-alexghiti%40rivosinc.com.
