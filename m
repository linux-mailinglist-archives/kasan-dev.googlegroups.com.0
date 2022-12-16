Return-Path: <kasan-dev+bncBDXY7I6V6AMRBINW6KOAMGQE6D4F62Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8ABBF64EEE3
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 17:21:54 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id d14-20020a196b0e000000b004b562e4bfedsf1196464lfa.19
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 08:21:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671207714; cv=pass;
        d=google.com; s=arc-20160816;
        b=qZ6rGHzzSl/DvaDpjp3DLOObOpl0MgWaRMZOI8ga2iqulH9ZXweCeIqgpwHf3G2+vq
         j0W6GvfHvs2PFbujf5nir/wkcGWNm3hw+dvmtkCa22lwLOXiM8fDxaWU62u5edHayQLV
         DGgrXw7jix6sja3q2SkGIXKFVzvVUMTJ2YgYwt4FxWbcq3plNkGuC2VOoHS6+aUXFrF+
         100Ga3Rbkuvi8FwyWU2hPQ1FfRx6pa9C8Fkz9vy5/XQxYBpKkrihVKqLSXMR9IxsOHQc
         rCUPNYab5mb95L8fJBb8QdmYufurDZqSnzZcZ00jjZD+50HVd0FthFW3D6pgIimYdXQm
         88og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=KmyQA0XCZb1wKODbQnMwXw5ybLO6I1paKoDzXh27Tx8=;
        b=I+H5tjo4+dd/o//Ig6wKPyCrrqU2Rj1YVEpNn8XJ+EWuZvOa5aFgnmv6v4dWM3DesF
         PMK5gLAa2RRTBsZSzXBjWnrKfNb81DUZwSivt7R7em60zCpvDZpsKfxYjFcyz0ae1XzG
         q1DDoZcG/nmqFgfkIEaJbf6aG/1F1KAwYGuZT4j1XMV1kIcyu6/tT56CZXtSudL6M3UP
         rCp+t2X2CyzzhwI7baqeqBUgPihzWL/qJhvlv7CIc6zW/OZkJNxHhex72KmeId4kudwv
         AsAUgRKusrwOmhoJqXC980qv/Vk44er+z/M8thHlbuOgyjFn7qntCG3QHTxeNynZWxbU
         cgaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=tMy2czpc;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KmyQA0XCZb1wKODbQnMwXw5ybLO6I1paKoDzXh27Tx8=;
        b=fjocA4PTD3wOTjYfLvXCWPKczrG1EnInVJylUQpVTY73BCSwCngP2BktRU4bVdh4G6
         49/uMdH5gu+hDoSb2G8NFa0nbU70AQ7+WnKTZc/v7O6txj1xmlMtRALt+gWpuLNHF30U
         rDqWNJyosJICRhk5EtG8t+sQtZTgNnsAQb2kI8MKscdH8UjUeOCGCpasuIPPWzXND3z2
         Us71r2bAQwJH5c4EX2joxmIwl6InRYA20m3NhfkVv0T3kybVUijypISOPfHZIa494SZP
         3+A/7RqUIbaRpUDtywfcKS747/LhaR5NlNsZft6I2CgnWNEar0xKziOueMz9wCTD0ioF
         7UJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=KmyQA0XCZb1wKODbQnMwXw5ybLO6I1paKoDzXh27Tx8=;
        b=zk98amBcj9ZH2uRqtjQkEo0Vo/u2IdgQaYpzkpHfsM+Rwyrg7SLkeX3aUBMtuZWZrg
         F+rEWz3/TgrDrpRVtQNhugpSfcsA+XRwe2e1zUJLxRqChdg5MgnuGGkKEqNIxA1YYhPq
         VK40z/AmLYV4KBc/X2v4Oo50zLktuBrrWYt+zOEWOEedasUVsSxjqxq5foieKAno1/TV
         Fcm/ZcwKtNJFwe8s2f+nmaBTUOe877BWBX/9f6lfRahXratdnjQ5VdZvv0Hil50L5d0/
         hL3hJMRPW82Cc8oplCz/rmGy/e5nJzhjOihYoR0VJ1De24BVNTgYuYTBEIkW4Uv4uZ7z
         6V0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmQXHaixXyoYumyvBK+u/Av3ZiAXwrw9QmdJex3Lqxsl4KsKnzY
	7k+M9Vyo7qfyZTGAzQZWNvA=
X-Google-Smtp-Source: AA0mqf444SavcgKerAxoa6/k3P8m+6NMRT1zM4C07VYjgKxkWXFiMEC0pKlM87BymY4ZMI5E2IJveA==
X-Received: by 2002:ac2:4104:0:b0:4ac:102e:5c93 with SMTP id b4-20020ac24104000000b004ac102e5c93mr32633584lfi.352.1671207713649;
        Fri, 16 Dec 2022 08:21:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b115:0:b0:277:22e9:929f with SMTP id p21-20020a2eb115000000b0027722e9929fls438875ljl.5.-pod-prod-gmail;
 Fri, 16 Dec 2022 08:21:52 -0800 (PST)
X-Received: by 2002:a2e:bd07:0:b0:277:2123:123b with SMTP id n7-20020a2ebd07000000b002772123123bmr7962419ljq.6.1671207712512;
        Fri, 16 Dec 2022 08:21:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671207712; cv=none;
        d=google.com; s=arc-20160816;
        b=uQpd8Zatv49DVpPwK1A47+e3x33EG0E2vPiUZKpDpKMGQR/9sAILEFryo4RYnHN9GY
         Ut401F84axdRXC3Eega4NXzkhqeSP3U5v1kqYEpdKkmF9GEDvrC2cR+noTzIvrwNW11A
         EtxdRl2gwut+bmecx45KgHYK2wqFB9zIGEby33wXStGounV52i8PlzVlOkjWM06lEJBl
         AUtYQE0YIuIfFooIU+7rEbWs/T+q5a5ayUiDj3nPJ4MIp8bTA6u6JilG+zQVe4gAsEIa
         DWzydlG+kKr+pLJFeEteIgsOVzqABTw0Z0ZuJLwkApyXIqt5QeYVBmC7KKVBQQk8VJ0r
         7AOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=G6XB8sFEdgRyJHccqiCj1UYEgQGTrZTp9EBrE9hoiO8=;
        b=NHAIiAsN0+aLV6s6juSSyypSc9rtIeHDg9C/9sSH+Dk5LL/6Mxp0mq+WWzjWyVBnT8
         vgUz7EarsfZ16z1bsO/fGNGCLhb2LvUrF7qBAF6vw56WTONjFQ6LsAi4hpN4cy6DzRCL
         gkGsaqC2gB+dJnnaJpHkBnGXOWjGun01K0EKlrkbnk7HUG5/y7uy+02LIVUJouhLm/I3
         8TJR2wHMoA1/xWyzr8XzhjUHb0VxeNhxFPuImoAPsrnhB5s/rq92d+AV+wGqdbiM3vMO
         7s24ikETIxudjZ5JpbkMAzivTC2XhTKOnwHkkfSyEjFTFJDWtqerOA+JPT7FsVGcJXjW
         i5Fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=tMy2czpc;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id f27-20020a05651c02db00b0027976ad74c9si127769ljo.5.2022.12.16.08.21.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Dec 2022 08:21:52 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id m5-20020a7bca45000000b003d2fbab35c6so2147621wml.4
        for <kasan-dev@googlegroups.com>; Fri, 16 Dec 2022 08:21:52 -0800 (PST)
X-Received: by 2002:a05:600c:1e8a:b0:3d1:bd81:b1b1 with SMTP id be10-20020a05600c1e8a00b003d1bd81b1b1mr24959580wmb.18.1671207712025;
        Fri, 16 Dec 2022 08:21:52 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id z19-20020a05600c221300b003a3170a7af9sm3027506wml.4.2022.12.16.08.21.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Dec 2022 08:21:51 -0800 (PST)
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
Subject: [PATCH 0/6] RISC-V kasan rework
Date: Fri, 16 Dec 2022 17:21:35 +0100
Message-Id: <20221216162141.1701255-1-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=tMy2czpc;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Alexandre Ghiti (6):
  riscv: Split early and final KASAN population functions
  riscv: Rework kasan population functions
  riscv: Move DTB_EARLY_BASE_VA to the kernel address space
  riscv: Fix EFI stub usage of KASAN instrumented string functions
  riscv: Fix ptdump when KASAN is enabled
  riscv: Unconditionnally select KASAN_VMALLOC if KASAN

 arch/riscv/Kconfig                    |   1 +
 arch/riscv/kernel/image-vars.h        |   8 -
 arch/riscv/mm/init.c                  |   2 +-
 arch/riscv/mm/kasan_init.c            | 511 ++++++++++++++------------
 arch/riscv/mm/ptdump.c                |  24 +-
 drivers/firmware/efi/libstub/Makefile |   7 +-
 drivers/firmware/efi/libstub/string.c | 133 +++++++
 7 files changed, 435 insertions(+), 251 deletions(-)

-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221216162141.1701255-1-alexghiti%40rivosinc.com.
