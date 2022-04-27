Return-Path: <kasan-dev+bncBCN7B3VUS4CRBEFIUSJQMGQECZA3HEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 200CE51149A
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 11:59:46 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id g89-20020a9d12e2000000b0060217f298e4sf129242otg.13
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 02:59:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651053585; cv=pass;
        d=google.com; s=arc-20160816;
        b=JutwcT/KueqR0WYT3kscKOPSC9Wj9xnPZHx//2MVQatj7HbPgElt3pCYXGlzDmoppX
         TdIU8lp9Taf7FIJ9cxhk9t7m1Qr94AxLRNU6L1Q05BHDZOR20BJZKfkZZalRIR85Sq4+
         0Bnb/jivwgV5EbGVQd1BriQ5IbcAo5GTjH3R4wRV2VgWRfO7GppHFWa+bEk6OhNbCQVc
         UhEKDYiU5aY+PPIeA8U6HDBop2vPy9+tkvYPsvt5SgsIDZxxvmF87YAfBOANaQqKvQp4
         ZbQEVTkMIci1Ef5jq7bxq2Bry+pneDoRPxgAAUE6iixouI7B4WoWDXdPQ3oD6H1V3GLv
         8Ymg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=w4Wf52BrRO6QrW0O1b2brO4aMjRCXquZjxSgz2PabUo=;
        b=gXLk2g/YGrMugqKASgcIYdkWrcMNNXbDJitLIKb1FQo3Zh0LEAan9K4Y7QUHPvnxox
         tparI712bCRSYChv+PDxwFo+AJ3qZB0raLFFziiTP3qblBYKe1/ETOjPEquoJXDV2fTz
         LUMGZ40E8uo+ToWLgVa8oLrjYoyOFX9Zcvl085vj1UDnJeoJve9brfI7WQXVoK+1n+jD
         e3r9NLdNoIq1zhBGsrGeX0Ki7oaLXkbQZVPOrHGzqgXXG+etVsFYjTawlADoh0lbPfUR
         s/M64o/XkfsckbzoM6jBSIrNvlgU1+HFtUk4e7MLsA12mf4NNOzPc2z4+yI3OWrj9MxK
         9Lmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=w4Wf52BrRO6QrW0O1b2brO4aMjRCXquZjxSgz2PabUo=;
        b=aUd5pGZxnz2HYhqnhyt31/Lv0vyG02dCaRvRydd9Qmhp5ud0BFFwl0OMOT13bjE4B4
         ImSPhq8dOwPtdQeUa+vnhJk1PDONMXCpOOJmkjYjHKaAqUa5htyDp9E5gy++Z/6EGhxk
         Fbmh4lUdPfBpShKKr3Hp+UZ2e4BsiTPdKITMu8IevKUSOqtwAzmhWdem7Iov6BsM+qO1
         exAljP6z/w/susCAXQOtys9hfDErlIAfksIXsCwJdPm+y6fIL28QUu24E4fAdoMcLX7e
         wRSfRFXrMtxuKrk/kXRH9qyM6S1FLqdVnt1Jp6HXp/jdNlb1oXzuean9PC+f3hFM7GKF
         iu5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w4Wf52BrRO6QrW0O1b2brO4aMjRCXquZjxSgz2PabUo=;
        b=0cZPRRFN/2fcAQDe0+fCTip5TEsUiXA+JcLXq6sqfw3FZhmjLZtkN3cLE+QRbsRGxB
         87j5AsFLKT0oy0q3NIRSTDM3ErXqX94NYWwT3+7qwy9n5mOLNr38VtxcKB1VbvTGwFrO
         tQ/xiH1UmLRMDE9MRYRGOt1vwiO1cIzRaqNAdkOmNH+Uk9vog7/zCl5qAwO5HbpxCNnE
         fE2aSY+6lJVXRQiACbcKYpS1ISUECZqLno98XWKoCIozThzvkLh4gBX6GevbcYOo9+yt
         wym38E71RrGviM1hU9lIDkqcBEkD9Krju9W1uhOkZR7T5vrA10h9J8D/Jjtv85ytK7Rx
         95Zw==
X-Gm-Message-State: AOAM533N9abR4B/xhXJCTTSjZouPD1WJKVk6FaaiSaw3GzU1Y553EB6Y
	zm7AzCg+mBjLjjcY2QBl1qo=
X-Google-Smtp-Source: ABdhPJwjYVNcX+HgG1vr3w4EwSLr4X9Gm7ocJRDqA+OkpN/Tj0pQknFhCoOA/lO+vX2TZcIFuqvYoA==
X-Received: by 2002:a05:6808:2114:b0:325:7ad8:1a00 with SMTP id r20-20020a056808211400b003257ad81a00mr1131747oiw.90.1651053584891;
        Wed, 27 Apr 2022 02:59:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5f14:0:b0:605:db7c:b604 with SMTP id f20-20020a9d5f14000000b00605db7cb604ls416080oti.9.gmail;
 Wed, 27 Apr 2022 02:59:44 -0700 (PDT)
X-Received: by 2002:a05:6830:1404:b0:605:46c8:3b4e with SMTP id v4-20020a056830140400b0060546c83b4emr9598618otp.293.1651053584419;
        Wed, 27 Apr 2022 02:59:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651053584; cv=none;
        d=google.com; s=arc-20160816;
        b=bONrFkHtmwN1U1YSFBZViNF6JajbLKP9Lh1C05WON+y48fqJkmSi6940pbmGvgbSRx
         jtmzW9MMK77GHufIlSPPja7hZLXUegjXOLv7qSKzPzI6Wa4CCyhv512iVg3H2Y5yWqgP
         P2/E292L3kfbWkVH6ER1n8F/S/JFQzUamrS4SnPeIxs/oBxvEWma/WrXoBRoGDtEQbNX
         kbuP+X6LVa6mukoBErsg7KAf/Co360fj8U3LtTdHD6goDDQB2h1ayjd7aO7OFc+DWCRo
         jjIMUOb4IdLadHrLmMolhaBtSrApfKMoPbmQUoyEfmn/ig/E+3bFwiLqBnw9MMj/xT6Y
         x7MQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=7O7DBPMPgf69eJ/yZK8jVPIP/fu5v/hEePi0lzeNdjw=;
        b=xtMSqerxEwcLWFxm8qRmYaj6KR9D2+v6WzMgZGKgVeKFevA2XDhSX93csqYa8bpD9Y
         fk8td46ymL73jn3UOhhdtiDYN5rs+61frL5y7aFlQZ8I2y0aecmgz3x6HYZ+WZxcgyKO
         O2i2CD7IZSm/LLkFNlh5V8osufh4X38iY5bSuXs8i5PcLMm/rdNLOwkd00lGG+oudkEM
         07wyMJ1alEPVzS005YohBVMWWGMFczkvXkajg/W5bxGED4ocg+rs3NaJOO5YOofv8Gz7
         AUZbvbCNX85cJ0MQRPX1eexqfCW4AqWNZtODX8xxIB1ApVXxcDF4ZwleMjxlfGZJrgz7
         tHtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id s18-20020a05680810d200b003227a4ecc4asi46942ois.3.2022.04.27.02.59.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Apr 2022 02:59:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: ecc8a55e2a0a449e90f7df4136eaacc7-20220427
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.4,REQID:f5180c4b-399c-4bd5-80e6-58fb4287062a,OB:0,LO
	B:10,IP:0,URL:0,TC:0,Content:-20,EDM:0,RT:0,SF:95,FILE:0,RULE:Release_Ham,
	ACTION:release,TS:75
X-CID-INFO: VERSION:1.1.4,REQID:f5180c4b-399c-4bd5-80e6-58fb4287062a,OB:0,LOB:
	10,IP:0,URL:0,TC:0,Content:-20,EDM:0,RT:0,SF:95,FILE:0,RULE:Spam_GS981B3D,
	ACTION:quarantine,TS:75
X-CID-META: VersionHash:faefae9,CLOUDID:995bacc6-85ee-4ac1-ac05-bd3f1e72e732,C
	OID:610a85c4e598,Recheck:0,SF:28|17|19|48,TC:nil,Content:0,EDM:-3,File:nil
	,QS:0,BEC:nil
X-UUID: ecc8a55e2a0a449e90f7df4136eaacc7-20220427
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 81934200; Wed, 27 Apr 2022 17:59:36 +0800
Received: from mtkexhb02.mediatek.inc (172.21.101.103) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.2.792.3;
 Wed, 27 Apr 2022 17:59:35 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by mtkexhb02.mediatek.inc
 (172.21.101.103) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Wed, 27 Apr
 2022 17:59:35 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 27 Apr 2022 17:59:35 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linus.walleij@linaro.org>, <linux@armlinux.org.uk>
CC: <lecopzer.chen@mediatek.com>, <andreyknvl@gmail.com>,
	<anshuman.khandual@arm.com>, <ardb@kernel.org>, <arnd@arndb.de>,
	<dvyukov@google.com>, <geert+renesas@glider.be>, <glider@google.com>,
	<kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <lukas.bulwahn@gmail.com>,
	<mark.rutland@arm.com>, <masahiroy@kernel.org>, <matthias.bgg@gmail.com>,
	<rmk+kernel@armlinux.org.uk>, <ryabinin.a.a@gmail.com>,
	<yj.chiang@mediatek.com>
Subject: [PATCH v5 2/2] arm: kconfig: fix MODULE_PLTS for KASAN with KASAN_VMALLOC
Date: Wed, 27 Apr 2022 17:59:16 +0800
Message-ID: <20220427095916.17515-3-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20220427095916.17515-1-lecopzer.chen@mediatek.com>
References: <20220427095916.17515-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Lecopzer Chen <lecopzer.chen@mediatek.com>
Reply-To: Lecopzer Chen <lecopzer.chen@mediatek.com>
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

When we run out of module space address with ko insertion,
and with MODULE_PLTS, module would turn to try to find memory
from VMALLOC address space.

Unfortunately, with KASAN enabled, VMALLOC doesn't work without
KASAN_VMALLOC, thus select KASAN_VMALLOC by default.

8<--- cut here ---
 Unable to handle kernel paging request at virtual address bd300860
 [bd300860] *pgd=41cf1811, *pte=41cf26df, *ppte=41cf265f
 Internal error: Oops: 80f [#1] PREEMPT SMP ARM
 Modules linked in: hello(O+)
 CPU: 0 PID: 89 Comm: insmod Tainted: G           O      5.16.0-rc6+ #19
 Hardware name: Generic DT based system
 PC is at mmioset+0x30/0xa8
 LR is at 0x0
 pc : [<c077ed30>]    lr : [<00000000>]    psr: 20000013
 sp : c451fc18  ip : bd300860  fp : c451fc2c
 r10: f18042cc  r9 : f18042d0  r8 : 00000000
 r7 : 00000001  r6 : 00000003  r5 : 01312d00  r4 : f1804300
 r3 : 00000000  r2 : 00262560  r1 : 00000000  r0 : bd300860
 Flags: nzCv  IRQs on  FIQs on  Mode SVC_32  ISA ARM  Segment none
 Control: 10c5387d  Table: 43e9406a  DAC: 00000051
 Register r0 information: non-paged memory
 Register r1 information: NULL pointer
 Register r2 information: non-paged memory
 Register r3 information: NULL pointer
 Register r4 information: 4887-page vmalloc region starting at 0xf1802000 allocated at load_module+0x14f4/0x32a8
 Register r5 information: non-paged memory
 Register r6 information: non-paged memory
 Register r7 information: non-paged memory
 Register r8 information: NULL pointer
 Register r9 information: 4887-page vmalloc region starting at 0xf1802000 allocated at load_module+0x14f4/0x32a8
 Register r10 information: 4887-page vmalloc region starting at 0xf1802000 allocated at load_module+0x14f4/0x32a8
 Register r11 information: non-slab/vmalloc memory
 Register r12 information: non-paged memory
 Process insmod (pid: 89, stack limit = 0xc451c000)
 Stack: (0xc451fc18 to 0xc4520000)
 fc00:                                                       f18041f0 c04803a4
 fc20: c451fc44 c451fc30 c048053c c0480358 f1804030 01312cff c451fc64 c451fc48
 fc40: c047f330 c0480500 f18040c0 c1b52ccc 00000001 c5be7700 c451fc74 c451fc68
 fc60: f1802098 c047f300 c451fcb4 c451fc78 c026106c f180208c c4880004 00000000
 fc80: c451fcb4 bf001000 c044ff48 c451fec0 f18040c0 00000000 c1b54cc4 00000000
 fca0: c451fdf0 f1804268 c451fe64 c451fcb8 c0264e88 c0260d48 ffff8000 00007fff
 fcc0: f18040c0 c025cd00 c451fd14 00000003 0157f008 f1804258 f180425c f1804174
 fce0: f1804154 f180424c f18041f0 f180414c f1804178 f18041c0 bf0025d4 188a3fa8
 fd00: 0000009e f1804170 f2b18000 c451ff10 c0d92e40 f180416c c451feec 00000001
 fd20: 00000000 c451fec8 c451fe20 c451fed0 f18040cc 00000000 f17ea000 c451fdc0
 fd40: 41b58ab3 c1387729 c0261c28 c047fb5c c451fe2c c451fd60 c0525308 c048033c
 fd60: 188a3fb4 c3ccb090 c451fe00 c3ccb080 00000000 00000000 00016920 00000000
 fd80: c02d0388 c047f55c c02d0388 00000000 c451fddc c451fda0 c02d0388 00000000
 fda0: 41b58ab3 c13a72d0 c0524ff0 c1705f48 c451fdfc c451fdc0 c02d0388 c047f55c
 fdc0: 00016920 00000000 00000003 c1bb2384 c451fdfc c3ccb080 c1bb2384 00000000
 fde0: 00000000 00000000 00000000 00000000 c451fe1c c451fe00 c04e9d70 c1705f48
 fe00: c1b54cc4 c1bbc71c c3ccb080 00000000 c3ccb080 00000000 00000003 c451fec0
 fe20: c451fe64 c451fe30 c0525918 c0524ffc c451feb0 c1705f48 00000000 c1b54cc4
 fe40: b78a3fd0 c451ff60 00000000 0157f008 00000003 c451fec0 c451ffa4 c451fe68
 fe60: c0265480 c0261c34 c451feb0 7fffffff 00000000 00000002 00000000 c4880000
 fe80: 41b58ab3 c138777b c02652cc c04803ec 000a0000 c451ff00 ffffff9c b6ac9f60
 fea0: c451fed4 c1705f48 c04a4a90 b78a3fdc f17ea000 ffffff9c b6ac9f60 c0100244
 fec0: f17ea21a f17ea300 f17ea000 00016920 f1800240 f18000ac f17fb7dc 01316000
 fee0: 013161b0 00002590 01316250 00000000 00000000 00000000 00002580 00000029
 ff00: 0000002a 00000013 00000000 0000000c 00000000 00000000 0157f004 c451ffb0
 ff20: c1719be0 aed6f410 c451ff74 c451ff38 c0c4103c c0c407d0 c451ff84 c451ff48
 ff40: 00000805 c02c8658 c1604230 c1719c30 00000805 0157f004 00000005 c451ffb0
 ff60: c1719be0 aed6f410 c451ffac c451ff78 c0122130 c1705f48 c451ffac 0157f008
 ff80: 00000006 0000005f 0000017b c0100244 c4880000 0000017b 00000000 c451ffa8
 ffa0: c0100060 c02652d8 0157f008 00000006 00000003 0157f008 00000000 b6ac9f60
 ffc0: 0157f008 00000006 0000005f 0000017b 00000000 00000000 aed85f74 00000000
 ffe0: b6ac9cd8 b6ac9cc8 00030200 aecf2d60 a0000010 00000003 00000000 00000000
 Backtrace:
 [<c048034c>] (kasan_poison) from [<c048053c>] (kasan_unpoison+0x48/0x5c)
 [<c04804f4>] (kasan_unpoison) from [<c047f330>] (__asan_register_globals+0x3c/0x64)
  r5:01312cff r4:f1804030
 [<c047f2f4>] (__asan_register_globals) from [<f1802098>] (_sub_I_65535_1+0x18/0xf80 [hello])
  r7:c5be7700 r6:00000001 r5:c1b52ccc r4:f18040c0
 [<f1802080>] (_sub_I_65535_1 [hello]) from [<c026106c>] (do_init_module+0x330/0x72c)
 [<c0260d3c>] (do_init_module) from [<c0264e88>] (load_module+0x3260/0x32a8)
  r10:f1804268 r9:c451fdf0 r8:00000000 r7:c1b54cc4 r6:00000000 r5:f18040c0
  r4:c451fec0
 [<c0261c28>] (load_module) from [<c0265480>] (sys_finit_module+0x1b4/0x1e8)
  r10:c451fec0 r9:00000003 r8:0157f008 r7:00000000 r6:c451ff60 r5:b78a3fd0
  r4:c1b54cc4
 [<c02652cc>] (sys_finit_module) from [<c0100060>] (ret_fast_syscall+0x0/0x1c)
 Exception stack(0xc451ffa8 to 0xc451fff0)
 ffa0:                   0157f008 00000006 00000003 0157f008 00000000 b6ac9f60
 ffc0: 0157f008 00000006 0000005f 0000017b 00000000 00000000 aed85f74 00000000
 ffe0: b6ac9cd8 b6ac9cc8 00030200 aecf2d60
  r10:0000017b r9:c4880000 r8:c0100244 r7:0000017b r6:0000005f r5:00000006
  r4:0157f008
 Code: e92d4100 e1a08001 e1a0e003 e2522040 (a8ac410a)
 ---[ end trace df6e12843197b6f5 ]---

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
Tested-by: Linus Walleij <linus.walleij@linaro.org>
Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
---
 arch/arm/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index f440cf59cea1..d9d60a3a5600 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -1519,6 +1519,7 @@ config HW_PERF_EVENTS
 config ARM_MODULE_PLTS
 	bool "Use PLTs to allow module memory to spill over into vmalloc area"
 	depends on MODULES
+	select KASAN_VMALLOC if KASAN
 	default y
 	help
 	  Allocate PLTs when loading modules so that jumps and calls whose
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220427095916.17515-3-lecopzer.chen%40mediatek.com.
