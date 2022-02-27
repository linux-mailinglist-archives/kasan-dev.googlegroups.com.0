Return-Path: <kasan-dev+bncBCN7B3VUS4CRBIEC52IAMGQEZDYYBVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 39A694C5B63
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Feb 2022 14:48:18 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id p74-20020a4a2f4d000000b0031cacd53c70sf6757684oop.10
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Feb 2022 05:48:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645969697; cv=pass;
        d=google.com; s=arc-20160816;
        b=TBXcwq+f5YIk6gvx8Ncfa3HjAuV9ZAj87z1xOFEREz9RJIxuisma42AhIMysl27DV9
         clskbp54hqgTAfJEgH/tP/OQBAYY5fwj0KOv1lIG8QEZaC3/GUHJup86FogX4hSPYFbG
         9IdlvN5Y9a8RyH+5qFlBzlUf7OU9Asfe2SMKNFldJVDStZ/U+9EvZfxdCfrluOKIhDoG
         U1J7RYxQcyVUx7HSUIFvK8HrsvDywP7Uw+H96jIIvH4VkDvyKQcjF1WykMZtGi5FKUu3
         nhRVZ1rsxxBHpsUFVa0UZi6a26IFP1irp+2dL+SDz2TpxUOSDySApuTcysmFtCOgqUjV
         OrsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=vm30o+k0DsKFrv0Y3TvNkc9LfLjrVFEJv1Zbe7dbhXU=;
        b=NCKWLnsfIntbHO7H5z1Cgz7k9WfTCNG49JNLdKQeHMYyjU+N0LBtITHZiD6jUASWgT
         ObD5T8K63pGejsQrlt5ogB97NHqQiR7hR3mo/zabRsVcsttU6wljNzaArpAnKPrs6wkm
         xJ/OXyy3iKvIbQS9O3/mnCFUR7Q33jbiUqBX252Z379FuHXwtuAQCiUg1ZjSu/GSIrox
         rpgAnNAYns3JzrDN1XCPWKlwR2LKxh3KEc5R8wmu8EnMPmiDqF+K5dvXonrSivg9507H
         pkUPQ6yr15ZTRaF1WLoCEHNTwb52Q2BnIzIYBpTau1mwcsRzmzScjmaUzerocAoB70Yz
         Yk3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vm30o+k0DsKFrv0Y3TvNkc9LfLjrVFEJv1Zbe7dbhXU=;
        b=QvNanBJ3V6wJkslKusauwHv7K9l2JT/zJG7hSGOAR8XLOoPhK/Hm4zOwFt17a46U+U
         xQ8Tg/9PbEhA6WyLdzaWsa/q6wW/BOLxGnvp25sNv6Gf2yizgY9PqFiCkGDNydhs0GMD
         0EfeMKuFkka+2zbK47mgCH3jy7cldcBtAkESNiT9l13LiiRI3Lzc2awBcyjinPeoAt3B
         9lb6kDpSDn1prQf64Wio+QxjqMGQo85acVfZz5FoooubZyU94vTg3h56D9KZhLci9XcV
         kO9Goi5MaIWhhOH9NTiyWrH1eiJMgadS/+9vwTWLWZCgE9W30GH+/CGMclwhGfDjG/OQ
         aEzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vm30o+k0DsKFrv0Y3TvNkc9LfLjrVFEJv1Zbe7dbhXU=;
        b=NHD8ewBMGeb5dWMY1m+JPvq1M2itB+Xw6AiBE/N1/G7BgtsLGDw9vgTD2CGIPPTTBg
         60UMqAPm7VlwmAJTdoamjOz8OAKpAFD92Elm5tjm8KUjXgXpbe0AeDdlPo4mX7Ib1KoW
         GT/NfGcixsD7+eyc2xgsNB7gM4j0dRemi0umoBMZ1oVOBd6hQHTQP0QuKUlAEKd0slSm
         UCBkJZQ/UXgpkqNCPlJgwBgL+TxARAiVFDVpfZeDIp7mWtAdjvvIKaLjPeJlkri94VH+
         iv8DKlUlHvKbcKrLKOEShHKVlgLTb6U1Cec5U2+aXz1z7j21US2yJ/6lTFtEta02eFK9
         dPOw==
X-Gm-Message-State: AOAM532Cy8EKUoyuUwE48Itnyox27e4HEl6b5LRWqJcDxk6Jc3WmpnZ3
	Dfs7Q8OXYW6h2nyEWptYhjg=
X-Google-Smtp-Source: ABdhPJy4mHP2W/vMS9gX7nAej2exV+o2foKmQRD7RiFD4LJgO6Z+jJjrUckOrpkjva7kNuW0soAyWQ==
X-Received: by 2002:a4a:c719:0:b0:2eb:c34a:2ba7 with SMTP id n25-20020a4ac719000000b002ebc34a2ba7mr6730046ooq.98.1645969696962;
        Sun, 27 Feb 2022 05:48:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:34a7:b0:5af:544c:fc2a with SMTP id
 c39-20020a05683034a700b005af544cfc2als1832636otu.6.gmail; Sun, 27 Feb 2022
 05:48:16 -0800 (PST)
X-Received: by 2002:a9d:60cd:0:b0:5ad:4854:747c with SMTP id b13-20020a9d60cd000000b005ad4854747cmr7037286otk.240.1645969696596;
        Sun, 27 Feb 2022 05:48:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645969696; cv=none;
        d=google.com; s=arc-20160816;
        b=AI4lu4R6SU4tT/w9c+89USsXoQRw2NZCId5oTUQl0RCZTlOIlDm9WZRnr4U9mjYxOA
         lC4+0umm8fZpHzjLlhonnOTWIX/9RY28hGqP0kGbs5DMpqpbJz2zYLK3lS4+jJF8NJU0
         CQJ+71yYSglGuQgRvM/Cp5vTVxEGW2ur9Wx1k7xbNjC4NhUj/6HihyuF8+YBamgbIsqZ
         Y7bK96HXfkdPjC8kcQUmKp2hqUhuN9AJ7CQHGOBUMug4zvvBA+gr2/i1QDTp1VI05Y40
         kHGjgoDrC2Dakt9MDO0A2sO54W60g2y3csV2B95bTuF4n0Kh3EbIQCdp8FhGTfoucxGf
         4kOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=xgpq/ToyYzNTiA9t4Lita5h+XMP36pNEZ0fv9N8tUyM=;
        b=YiKJrn1jL7kmXvz9DIw4I0zSBGpZaMO9Ey1hB1XAKppq3LprceIuVwb2+DcvE0g7Sh
         4s8YzaspObrduRkpfbRUtMtRf57/g6vGXiOq+mOjeX4+ZtTtG+wDKUeWdmF696Gk2A8/
         TZ9QnpJehnZWC6oOAGWkpLqwrvSDuaXyoqrijpKOS3rdEkXffoo2dSQHnWQHsdUovYcR
         fcAqOJmz/NaKka00E1L7vozGgBZW7Vmt4RqGbnDBmak1rPbJ+VJV758jV+7XiikaQmTM
         A1iiZgLo9np/I7FnjdMTueCQxNxs6sQiBjWg1D4jdpP8pLiaMG0vEYfTZMUjBKMWET8w
         wCNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id r128-20020aca5d86000000b002d62816075bsi927775oib.2.2022.02.27.05.48.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Feb 2022 05:48:16 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: b1d397b1a95b4ba4b9027d39a7c1790d-20220227
X-UUID: b1d397b1a95b4ba4b9027d39a7c1790d-20220227
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 377687631; Sun, 27 Feb 2022 21:48:11 +0800
Received: from mtkexhb02.mediatek.inc (172.21.101.103) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sun, 27 Feb 2022 21:48:09 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by mtkexhb02.mediatek.inc
 (172.21.101.103) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Sun, 27 Feb
 2022 21:48:04 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sun, 27 Feb 2022 21:48:04 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linus.walleij@linaro.org>, <linux-kernel@vger.kernel.org>
CC: <andreyknvl@gmail.com>, <anshuman.khandual@arm.com>, <ardb@kernel.org>,
	<arnd@arndb.de>, <dvyukov@google.com>, <geert+renesas@glider.be>,
	<glider@google.com>, <kasan-dev@googlegroups.com>,
	<lecopzer.chen@mediatek.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux@armlinux.org.uk>, <lukas.bulwahn@gmail.com>, <mark.rutland@arm.com>,
	<masahiroy@kernel.org>, <matthias.bgg@gmail.com>,
	<rmk+kernel@armlinux.org.uk>, <ryabinin.a.a@gmail.com>,
	<yj.chiang@mediatek.com>
Subject: [PATCH v3 2/2] arm: kconfig: fix MODULE_PLTS for KASAN with KASAN_VMALLOC
Date: Sun, 27 Feb 2022 21:47:26 +0800
Message-ID: <20220227134726.27584-3-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20220227134726.27584-1-lecopzer.chen@mediatek.com>
References: <20220227134726.27584-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
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
---
 arch/arm/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 78250e246cc6..d797a3699959 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -1515,6 +1515,7 @@ config ARCH_WANT_GENERAL_HUGETLB
 config ARM_MODULE_PLTS
 	bool "Use PLTs to allow module memory to spill over into vmalloc area"
 	depends on MODULES
+	select KASAN_VMALLOC if KASAN
 	default y
 	help
 	  Allocate PLTs when loading modules so that jumps and calls whose
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220227134726.27584-3-lecopzer.chen%40mediatek.com.
