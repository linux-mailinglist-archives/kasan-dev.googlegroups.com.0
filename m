Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBFPUZ2IAMGQESO2WSSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id C94164BDAC2
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 17:13:09 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id e10-20020a056402190a00b00410f20467absf10369217edz.14
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 08:13:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645459989; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ir44oAD6XCTUoI0HKlU8J2UUXwPivxU6Bx8vFK6FJnNk0n5TokcrAMi+MyRNqahU7/
         yn03IhVBN0ebFBC3QPR3W69iq8yfnr6Xez9AnHZmdq08S8ez2zNw67W2lSDMN7F50w+X
         h+YU3pd2Qwd1rK4SgkTh9QevfRO4owhDbPZkh5UV8Ga4xaxBgXSGafyHOuFNFD/zapYZ
         a//Wm/ylczi/P5fUbWBV1RDVSyL0mhQcqCO62Caz113tazhhls/laHJ1KHtAyJWzWV8B
         U+BPTAJ4t8B5QgPxCQCB30om6ZjRSfgC2/m2ypjgSYdteW+HX8ckRNFrsZyJeyQqMT0X
         w8fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:to:from:sender:dkim-signature;
        bh=7PfiLfx9P/KQIA69wvA+JARPbXLItKpel1nTAi8MYtM=;
        b=ax8Ak46ysnZLshP9oeINrlFSZeoMoPCQx42fC5Nz4vMifLeAJM3NYk3OskPufABc19
         60zaNbPJD7t6df8hYwnywEfhf/B0iTfWxqTYG7RMCVBP63WEasQpxhJShkkHTBt8VYIr
         raVnJ90nRlLnFnc1DqVTtH5vqBKEVwU1g1RArz4HDlosNgy/B8xxVBm5JVwh1uQQ3uZq
         +Q+6sZLakBjRWEIL8Ne0i3UUzaNw5YgkLFEuuXqHSqNM9RU0z8JzlZKc3sU8TWJbg37D
         lnewz/wGL/a8xchHqKYHdObGo+jORJvX32IYFLCg/T9KoBglvGF7HjdKFjj1j0OeItJZ
         yw2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=v6CNC7BZ;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7PfiLfx9P/KQIA69wvA+JARPbXLItKpel1nTAi8MYtM=;
        b=Jyiep80EQ4MMWaKrOllyi7f49UMae9Y1ojtdGXesSwl0odFIBPm/olmsJiy2yUAYBJ
         XV2JEX8CcuH7A/DZZKWvuyMbiWwaBkOihA8mo6HrsSlJ+1RLKtCB7NTYzsc7tFm30n5l
         Ip7yQV/5bTV++I1VlGqASc2invbqXjRj4i+pcEFoPz1Bg58mQlsyzI4p1xfeTN4GtEar
         X1W/axXitMch+DxqMi8T7ZNCDmSTR+a7Xn16dQmWmW6YwMBZA2L2/AMKuBGOrE8DRiXK
         ZH5hzFYKjd+qvW+W4UL4e5X5wKc6wLMCtjmhI6XrFQaNCHzc1j3gk2vr4rgivyMO6JXH
         RHgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7PfiLfx9P/KQIA69wvA+JARPbXLItKpel1nTAi8MYtM=;
        b=AX0CcYQctABRG1KfKG4HYx1TuSdR1AA4dTojyAl81Fyw2oB1CEBA9s3fV0rB0teEcw
         pHk6uk1viuHgKgZeIC+9YNu64cY0b+edtfYLXXS8iNpb/eCn75mEdgyeT92F2ju18AeQ
         BL4nW386uy3w19eMmb6yquAqkLp5G+g9eq8w9qbHYubb03OgRGXgXAkPiJJU52NqbDe3
         Pqu6XrdQP+ilZsBVbLUtDucnoSXvPL64ZOFZF6IDeXUIoRZiF4h23Iw5KUYk3MQeIz69
         H98itG22X0+8S0bQgKN61t/jIlMol3SOvW/nmLACZTNQrCFXRlOX8SZXijcb/G3Cq3zR
         Wbzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532QUMvWWGW8AADxqgKlYN4rsiAhk2Os1qIVmnqiJZ/aAnT9lHq+
	5iJc0vpnR8O8J2tknW33SSg=
X-Google-Smtp-Source: ABdhPJyREffIopuyU/Mlqek2WpxdwaibgVH/Acc/77t0SOFJI+V4TH4DGL9chdxoDJdPn/J13oCeZA==
X-Received: by 2002:a05:6402:90b:b0:412:a7cc:f5f9 with SMTP id g11-20020a056402090b00b00412a7ccf5f9mr20944753edz.136.1645459989390;
        Mon, 21 Feb 2022 08:13:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c45a:0:b0:410:98bf:fa0c with SMTP id n26-20020aa7c45a000000b0041098bffa0cls548361edr.2.gmail;
 Mon, 21 Feb 2022 08:13:08 -0800 (PST)
X-Received: by 2002:a05:6402:2074:b0:410:81bf:ff3b with SMTP id bd20-20020a056402207400b0041081bfff3bmr22278784edb.326.1645459988490;
        Mon, 21 Feb 2022 08:13:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645459988; cv=none;
        d=google.com; s=arc-20160816;
        b=Wl0vYbS68Lrd8wRXFebr0Utnv0Jg715jguhZFxFHFR9E7rtF2x/PxiOKIYmTUpR9hr
         YAr6C5rY3XtErzRqHS7jZQxS86qkVqx+JlrKSeLYmX3LswPrIBQ+c9hP7gtnaq8DQwNJ
         Lq3feGIA1Ul53Q2ltIdciDQsdF3MvEkPSZQdO5j3Ra+MN/RFAT8dnusIgcYLRd+AlbSE
         foTfud8Vbk7iJyc2u+9biSJpiHZMMqQUdUqgrIMn+AlpQzB57ZZF25sOfuDxK/9d6teN
         lZK9Sl9yTqfGUO+D+t7ahaHn96uFqxee+pvkCzcsdES9ls5TLsICWqU4/Hyt0eTb1NT6
         NOTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:dkim-signature;
        bh=vRzNDqjN6ajBEKsUVpfuJLu9ktKbrLjh36kCMNlOgAc=;
        b=lX9zbAYYzWDYUKvYTrz/vl4sYDwrYeiVUi9+AdRV7i5uGQvsC3EV7cQjpClzwOGziU
         WeO0gJf3+Kwq7IQRWsN7IXKjBWLs4SByekhftJBkzgjoxxTJlBZRB17tb7o1TzxskoX3
         2+SLvS09+dyQFXhqqlO4ByJ7Rpb2Hdu4vu4CICcUczb6Dumk3ja9bKhTztRMVq0jAS/D
         YOW3jBHwwToITbq/geKc0mxzuV5M5XRAxjamWjKV6hbOv32KTTy2hNL/CeU+QlIv3/aL
         iHI6F9Z8u6le4+t+yLNJinpYAVgZQFSRa5QykijlMuV5IuG9Jf+rWyDbZv5MRWGBAgws
         uzxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=v6CNC7BZ;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id d13si966066ede.0.2022.02.21.08.13.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Feb 2022 08:13:08 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com [209.85.221.71])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 144003F1D0
	for <kasan-dev@googlegroups.com>; Mon, 21 Feb 2022 16:13:08 +0000 (UTC)
Received: by mail-wr1-f71.google.com with SMTP id e11-20020adf9bcb000000b001e316b01456so7586265wrc.21
        for <kasan-dev@googlegroups.com>; Mon, 21 Feb 2022 08:13:08 -0800 (PST)
X-Received: by 2002:a5d:5546:0:b0:1e7:39f7:92b9 with SMTP id g6-20020a5d5546000000b001e739f792b9mr16109065wrw.5.1645459986981;
        Mon, 21 Feb 2022 08:13:06 -0800 (PST)
X-Received: by 2002:a5d:5546:0:b0:1e7:39f7:92b9 with SMTP id g6-20020a5d5546000000b001e739f792b9mr16109052wrw.5.1645459986740;
        Mon, 21 Feb 2022 08:13:06 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id n7sm7976623wmd.30.2022.02.21.08.13.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Feb 2022 08:13:06 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Nick Hu <nickhu@andestech.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH -fixes v2 0/4] Fixes KASAN and other along the way
Date: Mon, 21 Feb 2022 17:12:28 +0100
Message-Id: <20220221161232.2168364-1-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=v6CNC7BZ;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

As reported by Aleksandr, syzbot riscv is broken since commit
54c5639d8f50 ("riscv: Fix asan-stack clang build"). This commit actually
breaks KASAN_INLINE which is not fixed in this series, that will come later
when found.

Nevertheless, this series fixes small things that made the syzbot
configuration + KASAN_OUTLINE fail to boot.

Note that even though the config at [1] boots fine with this series, I
was not able to boot the small config at [2] which fails because
kasan_poison receives a really weird address 0x4075706301000000 (maybe a
kasan person could provide some hint about what happens below in
do_ctors -> __asan_register_globals):

Thread 2 hit Breakpoint 1, kasan_poison (addr=<optimized out>, size=<optimized out>, value=<optimized out>, init=<optimized out>) at /home/alex/work/linux/mm/kasan/shadow.c:90
90		if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
1: x/i $pc
=> 0xffffffff80261712 <kasan_poison>:	andi	a4,a0,7
5: /x $a0 = 0x4075706301000000

Thread 2 hit Breakpoint 2, handle_exception () at /home/alex/work/linux/arch/riscv/kernel/entry.S:27
27		csrrw tp, CSR_SCRATCH, tp
1: x/i $pc
=> 0xffffffff80004098 <handle_exception>:	csrrw	tp,sscratch,tp
5: /x $a0 = 0xe80eae0b60200000
(gdb) bt
#0  handle_exception () at /home/alex/work/linux/arch/riscv/kernel/entry.S:27
#1  0xffffffff80261746 in kasan_poison (addr=<optimized out>, size=<optimized out>, value=<optimized out>, init=<optimized out>)
    at /home/alex/work/linux/mm/kasan/shadow.c:98
#2  0xffffffff802618b4 in kasan_unpoison (addr=<optimized out>, size=<optimized out>, init=<optimized out>)
    at /home/alex/work/linux/mm/kasan/shadow.c:138
#3  0xffffffff80260876 in register_global (global=<optimized out>) at /home/alex/work/linux/mm/kasan/generic.c:214
#4  __asan_register_globals (globals=<optimized out>, size=<optimized out>) at /home/alex/work/linux/mm/kasan/generic.c:226
#5  0xffffffff8125efac in _sub_I_65535_1 ()
#6  0xffffffff81201b32 in do_ctors () at /home/alex/work/linux/init/main.c:1156
#7  do_basic_setup () at /home/alex/work/linux/init/main.c:1407
#8  kernel_init_freeable () at /home/alex/work/linux/init/main.c:1613
#9  0xffffffff81153ddc in kernel_init (unused=<optimized out>) at /home/alex/work/linux/init/main.c:1502
#10 0xffffffff800041c0 in handle_exception () at /home/alex/work/linux/arch/riscv/kernel/entry.S:231


Thanks again to Aleksandr for narrowing down the issues fixed here.


[1] https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
[2] https://gist.github.com/AlexGhiti/a5a0cab0227e2bf38f9d12232591c0e4


Changes in v2:
- Fix kernel test robot failure regarding KERN_VIRT_SIZE that is
  undefined for nommu config

Alexandre Ghiti (4):
  riscv: Fix is_linear_mapping with recent move of KASAN region
  riscv: Fix config KASAN && SPARSEMEM && !SPARSE_VMEMMAP
  riscv: Fix DEBUG_VIRTUAL false warnings
  riscv: Fix config KASAN && DEBUG_VIRTUAL

 arch/riscv/include/asm/page.h    | 2 +-
 arch/riscv/include/asm/pgtable.h | 1 +
 arch/riscv/mm/Makefile           | 3 +++
 arch/riscv/mm/kasan_init.c       | 3 +--
 arch/riscv/mm/physaddr.c         | 4 +---
 5 files changed, 7 insertions(+), 6 deletions(-)

-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220221161232.2168364-1-alexandre.ghiti%40canonical.com.
