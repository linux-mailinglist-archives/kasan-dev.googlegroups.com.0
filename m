Return-Path: <kasan-dev+bncBDXY7I6V6AMRBEGOYOPAMGQEOWFUDEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id E970467AB83
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:23:44 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id h9-20020a1ccc09000000b003db1c488826sf725555wmb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:23:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674635024; cv=pass;
        d=google.com; s=arc-20160816;
        b=lhZ4RDCrbOqt4ERRHEq8uCxiLTblowPAmXXegP9JHZgogeuP/wVRes+qUBV17xqxFp
         W0k+KgWVUDYwB0zCzV/kRi87GFoFgCnq/m+7a0/fnbRnQSMAsJuaa+V3cJbI7iJmywwo
         vc/EwZH+utmgPSnuNioRWO8FMGP5XR67ZVX3gzMaNcXBSd05T45/VJhBQ3aVPtIAKJrK
         cgXboMK1jaG4E/JJS4YHJfaDR1rosTo12ck0NH1ok+pFpxVapBcepSsfUtZalgnhFdVS
         eMSokkig5isklH3ENs5vuGO1iRz6HdzP5Unmoe3TLWV9tC8I4iUf1gJPTgxuN6Eq+seD
         c16Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=mH9yHiOIxf2ygaCpctzHzcvQOEYD2o6nOX0ZEMPUOY4=;
        b=KKY1RiWRuRZMloKfzuThv9VnCWy8bKFlKH8/bBrj7qlM4Xqnc7sOUzO8zAmvDfG0Ve
         WaIo5WCdNTjccggj9sHZZTFxgLTr0gC2n0eq2/ye9PlCNdqL2c5euiSq8CWi0s73yaoP
         zMVHc3a1MIr90LjiUA+cDk92x4L675ZZC73OILF6Wjss6yb6QY0Kt1oiSbRA592O71Cy
         44pURbcrBfEBjUGYg7DmD6EI/vlodCSejFdH26Z8VjtiyZ+YwP1B7sm+fTNpPexxR/F+
         sCdkwyTXy+hpk6HiPcWkH1p7vrFmO3cKHOcUjFUdnreZkIR0EeA12e7fd7m9I096JbLc
         sGXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=kcqF6iq5;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mH9yHiOIxf2ygaCpctzHzcvQOEYD2o6nOX0ZEMPUOY4=;
        b=JmotI0Jhhx0GgNQNMudLNDRdR8q8dk77HPEsSypFP+/XzakK56YS/xBqWk5f3n7amY
         1NNoel5XGDgnhS0hTxdANLR+dU/rcuXYtmB08hiNq/5/0X2tictd8roLYUgZ9hyAvtk5
         oQCbQAKakXP1zZ7OlboXXdRxg+z4i5lXSfmz6cJAgqpmJOeq69JoCYNkbTkYcjX1Bzgu
         Av7Kbllre9Dw/meLKc4ltZjfEXKxzpIxmN3K67Ph7L8/nW9zuLyIzDqNz1gFXJO7oYmb
         7kPO/Z/5vm5CKseCIZusTRTCav65SRXnWll7E/pzXphrKbTE190RxNtWINoEbD6Tr61p
         pclA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=mH9yHiOIxf2ygaCpctzHzcvQOEYD2o6nOX0ZEMPUOY4=;
        b=C2HqVL/H1q9Go4SrYDWjp9WvXh/3RcI/WPAuGPyjlOgcncmSoPHq9UlHWhaE2BcXU8
         7z1Hpg+6VyFFzRExGZxFc9Yac1Bi0rf1XNAYw1YFpFr2Eg1djv9ah07MaqspTwxbDunv
         atXLrThAKRPfyhHoPIrRzw2N26xjKGdrSlB0XosYFed67mIciI280/r+hy/0uS0O0r64
         vnULTinjAepdxcs+H2PYWTKcg1ZpAIDsygy930EwjzKeWr1zep6O4oLiVc/aecVNOts1
         G2oXg/+NV3lkjxZFHzvxU10QsJcd0OyVDO5fozsBixF/2DH2gqpxYBD1Ow+Aaiws/dnB
         xCTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kp9Okhaw8iFYQ24ndbj9brHOTWTsFo8Peqf5DjFYP1M0a9valsf
	8BV031/ZOBiG/7CHQZD5tBo=
X-Google-Smtp-Source: AMrXdXva7/TzBSFbV0b4mAt2fhNcTWMhO8H8oq4bufM0aqiE2O2kPBtsqV0/bTPbHAKa5ymQkce2Lg==
X-Received: by 2002:a5d:6b85:0:b0:2bd:dac3:db20 with SMTP id n5-20020a5d6b85000000b002bddac3db20mr975365wrx.152.1674635024572;
        Wed, 25 Jan 2023 00:23:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d06:b0:3cf:9be3:73dd with SMTP id
 bh6-20020a05600c3d0600b003cf9be373ddls637189wmb.3.-pod-canary-gmail; Wed, 25
 Jan 2023 00:23:43 -0800 (PST)
X-Received: by 2002:a05:600c:3ac8:b0:3da:270b:ba6b with SMTP id d8-20020a05600c3ac800b003da270bba6bmr32076514wms.41.1674635023556;
        Wed, 25 Jan 2023 00:23:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674635023; cv=none;
        d=google.com; s=arc-20160816;
        b=FSuYhnEsrlSpmoFUBrx9mmV9skSHXiXRp9U00dYBq1JQeD0xnksFKGQe6AteRsDJic
         DaJvgotO5IRbAJTUC3/FH2C/CWFeMooeQzsfk1DLJHDaesOw/p2jO1u7qP/glvF7RMUs
         EvhdczSJfcHyjTvJSEm3T8CeQUDRjy+XJ9cjS7oQQigHw7RAgQVmMm6oiBkRDdTM8kBg
         JFoyR4S7C3mhMNUwsyXcmN6CzQKfbOgYX+WaVITWCXK0NewdVYAOpxRby5/25keRm+5t
         A3H6CA30M8+uhcKL2vV/JRHKrg5qMOSXjSgwIWjoeF1ksfGwo+hk6o59Q33hNwlVSyT7
         0JYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5YDvDkWAbLDWKsnQUnWtcsgg0pzlyYSw3Ro2XkM1b1U=;
        b=fZtFmjZXu7YmRhmhvFwW7L08+313a4ivLlBVBkFAFfBuVZ0pWRczPe7sAqQ7sds3oL
         GCfWUmQdsI1dg5Rx5j/HABkzXJoxhwdVGd/AS4NNqRec8ABUrEaE9L2s1r3IqCLF1jYX
         U8N9VwEDKKSWks3dxavpKhL1UVz5Dpeli/57lpfbiyNLqsvUtnb3EunA8Edza/gSPhvi
         xaRavTlFzD60EERbsh5fgO50qhCQKpE+fBDyeWaD641B5IUJQnHiyo4MUTaDLIkoUxKI
         dY9r5+4ZFWT9Bj5/ZvVJWFpc9q9wjV/Ie0foBxWcn6vb/NWB/fPbViRs1w2B/P5XR236
         1+IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=kcqF6iq5;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id g17-20020a05600c4ed100b003c4ecff4e2bsi71120wmq.1.2023.01.25.00.23.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 00:23:43 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id m7so2550147wru.8
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 00:23:43 -0800 (PST)
X-Received: by 2002:a5d:42cd:0:b0:2bf:81eb:dc26 with SMTP id t13-20020a5d42cd000000b002bf81ebdc26mr7593494wrr.37.1674635023170;
        Wed, 25 Jan 2023 00:23:43 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id a18-20020a056000101200b002be25db0b7bsm3821071wrx.10.2023.01.25.00.23.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 00:23:42 -0800 (PST)
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
Subject: [PATCH v3 0/6] RISC-V kasan rework
Date: Wed, 25 Jan 2023 09:23:27 +0100
Message-Id: <20230125082333.1577572-1-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=kcqF6iq5;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125082333.1577572-1-alexghiti%40rivosinc.com.
