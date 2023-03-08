Return-Path: <kasan-dev+bncBAABBE7CT6QAMGQESPNEIOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AF376AFCD8
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Mar 2023 03:21:09 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id k13-20020a056e021a8d00b0031bae68b383sf6886852ilv.18
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Mar 2023 18:21:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678242067; cv=pass;
        d=google.com; s=arc-20160816;
        b=tE3c3Zu0KNYzqCnVOIT3h4bnWePbV+/f8hoHwxtfv2GlQCauSQIT7R1F9x3lXNvFeY
         BWngJdvxsQFMONG+7IQcgpS+dDzcM+ioCSqW95H8WWj3IOgrbKjDWjNukmvT3w6sloEJ
         2Eh9pxlK5tAXnteQU8K3MWK1hxV1UDMPGwd1ScQBRQHEHxvGfpu7zN0zLB45ic8E9WU4
         jO5IGQ7YN5NzUo01s+3eDTXOpDjP5XR8dxJ7Lko/mcSLi8rbE05Cf5o3bAeSrQ+TaFMq
         8izXyYoF4Z8GQXOqlO79lhUpEQx2I9CPIwvCcwEaktmmFlrEsYuWbtuxo3p+vvI5rL8Y
         KZ3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=o+cfRCj6rqKdA++83zPvxR9gN6fyP9x3sqLSTg5Za8g=;
        b=jlkWKJYcGqjtDXg6EinBhsQNztqaoW+B9DvW0W0AWoCJn4px2rgoOPs4Li7rd2Kt0o
         2b/tBNUztJJUqd02orlOUmlekGMDxNrKM2qRm+JdUG9wSzQFB4MY+jTs2anblZVVLGwL
         vArANVTa1fK0IWHEg+iRsqqf3MGu6C2AQU9gJh+ExvlR5K0C584UTs+6tX49NojMkb8F
         LXc75ncALfWbcScSFpXm9Hx/pZOhv3Xjp4yQAwmVH0Y5FQRBdW7N2EX0w2f8FiR9YWZw
         TaJ/5fUFN60wG5zPgnYPVSBX7jdsQeGvoKo6WsHGzkKFH7R8lEpNI6Hl5fNgqJSJ6tB1
         tx9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=p9xVSjlu;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678242067;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=o+cfRCj6rqKdA++83zPvxR9gN6fyP9x3sqLSTg5Za8g=;
        b=t7TfV2L0ORDUa0b3mppGtPZwEC28RUFFAaGHE5tkkCdA/FbSCDdv8rGQsE4UZ6U11T
         hxROVOsjyQRkDD7tEmUlDTxdv2ErDghNIJMoXQ6JTaqE0NRkCcD1D8HgeHkajS2BtAyC
         a2QvfLXcnAk3Ex5b9UofF3yVNllZZar39hfJkWurzqW9QnD0PSDi/MNOIDMduLVNokCn
         4u3Q6mV9XOIUQvsbOJhn6pBG1xvdIDPccXdliL8SjMHTH+7KwBeZ6cVT1jB3j14FUbsD
         S5E1vVBkdGvekvciP2oi1fJBzIgVsRyW//FM+zKHuD4sIWxCBkQPJaFd68LRzenuQIe+
         dcog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678242067;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=o+cfRCj6rqKdA++83zPvxR9gN6fyP9x3sqLSTg5Za8g=;
        b=lHxZ+DiaRJEgSLx7i4BsBbvNJlde4hpeztaw4RhH982Nkygad7ppJH7x5tkq1FEJiS
         2SfGMJpJnkCAnlGYLf1+XzWNJ1q2hJ6debeM3UdsVRZA0XwDL8HOVKQ4XCUBaTdSxfqk
         vRmGs/5ZVyf58y0XoSibqlmCSbyhWx/0No+QLI002z0kUU5D9oTMUOFGx+fIONCIN2Rb
         4NdPel9bacqkcG6lYSRWYZ9q9RlDv3h+y/Yzaqk5oVAHRCdVSBlWATZKME8sLbGMAl8w
         DlTQHsqo825FG1gtHpCPSbrcdhIfhwKl5CIRTsxE+aJBdHgkZN5B9ZR3E39EhV2+xb1r
         ockw==
X-Gm-Message-State: AO0yUKU/A3DGF095DhzE2/ecRKGz/z6/z8bTyR7MXK4p15sCJDFxN+Li
	w0/Q315Y04v2kt89DkSBDb0=
X-Google-Smtp-Source: AK7set8s9JiJqklV7YtA+WDL87bHtYeHM1oQRiuJOit3/IMKN53UGJwH54+uhfX8yKL8FYApXFK8/Q==
X-Received: by 2002:a02:620f:0:b0:3c9:562:1366 with SMTP id d15-20020a02620f000000b003c905621366mr8220945jac.3.1678242067685;
        Tue, 07 Mar 2023 18:21:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d302:0:b0:317:96aa:2fb8 with SMTP id x2-20020a92d302000000b0031796aa2fb8ls4276903ila.11.-pod-prod-gmail;
 Tue, 07 Mar 2023 18:21:07 -0800 (PST)
X-Received: by 2002:a05:6e02:1489:b0:314:110d:ab69 with SMTP id n9-20020a056e02148900b00314110dab69mr14833719ilk.6.1678242067240;
        Tue, 07 Mar 2023 18:21:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678242067; cv=none;
        d=google.com; s=arc-20160816;
        b=whb43l8URfQ3HpqYoZ9OyNHRifGLGuIn/XWouT28WzqAW/dNLysQI6SnFjltIakx8E
         JJIcZXayEVYKOXj8X8lcXONvigmgnT7+b4Wj9DNT0idTOUyhVkvcLRBxUBrqvXnCf4dN
         l8ccSvvfPl1AgctxxgXowtQAzaF0JkYlWddltlS27V6LuRt2aK32kNAEAutRul3uJUFT
         Dd0jUOe9R401xPSs5yIxqvpEEOQIGy4BsDxuveUp8gbTsO8MfbV+WL5f6t3JzxXIY6T3
         vo6a0H8f7zeYUWbK8Dj79MaZ2W6zINf9Saiw/n4Mf45H2eOCcI4SJyV4j1HR95Ojllu0
         6Vsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=13Wy0Ed++1zXh0KzmnLa4BZ0fSU9hMpfdWuFisECxUA=;
        b=CP2fZlcxDApxZ7c7GeNS6jgYXbAzHlWtk9snCYzNBNogyZUz/8Uk13vu14cWLdEtLs
         15cvmEO648kFWB1iQbV3kUbstfetk8LJxonPwfAXj/XTfJwStiW8BMfqWHIhKSBx9DY3
         L69Wlz0ry/RvvlSXDa9p1tFiMHYT58frndZWG4tdeKYdQcZTMg+ee9o5J90P13BT7IQp
         qRZ7XnLxI9NdPnzsex/slUeKMlnuGHF2+f54x93evuRKbZc09NZebKYO0820a23FqDlU
         yGsFZquYDYFJlli+/IAC1iJqmffHsje1+asHlqmewhlqe3D9sYTySwVdmb9ntdurGi4S
         3o2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=p9xVSjlu;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id l15-20020a05663814cf00b003e7efb1d848si1827324jak.3.2023.03.07.18.21.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 07 Mar 2023 18:21:06 -0800 (PST)
Received-SPF: pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: ddc234eabd5711eda06fc9ecc4dadd91-20230308
X-CID-CACHE: Type:Local,Time:202303081011+08,HitQuantity:1
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.20,REQID:52d32188-1362-4898-a3a5-ebd9b2f65e21,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:25b5999,CLOUDID:57e616f5-ddba-41c3-91d9-10eeade8eac7,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:11|1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0
X-CID-BVR: 0,NGT
X-UUID: ddc234eabd5711eda06fc9ecc4dadd91-20230308
Received: from mtkmbs11n1.mediatek.inc [(172.21.101.185)] by mailgw01.mediatek.com
	(envelope-from <haibo.li@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1123491311; Wed, 08 Mar 2023 10:20:59 +0800
Received: from mtkmbs11n2.mediatek.inc (172.21.101.187) by
 mtkmbs13n2.mediatek.inc (172.21.101.108) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.25; Wed, 8 Mar 2023 10:20:59 +0800
Received: from mszsdtlt102.gcn.mediatek.inc (10.16.4.142) by
 mtkmbs11n2.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.25 via Frontend Transport; Wed, 8 Mar 2023 10:20:58 +0800
From: "'Haibo Li' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
CC: Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, AngeloGioacchino Del Regno
	<angelogioacchino.delregno@collabora.com>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <xiaoming.yu@mediatek.com>,
	<haibo.li@mediatek.com>
Subject: [PATCH] kcsan:fix alignment_fault when read unaligned instrumented memory
Date: Wed, 8 Mar 2023 10:20:57 +0800
Message-ID: <20230308022057.151078-1-haibo.li@mediatek.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: haibo.li@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=p9xVSjlu;       spf=pass
 (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as
 permitted sender) smtp.mailfrom=haibo.li@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Haibo Li <haibo.li@mediatek.com>
Reply-To: Haibo Li <haibo.li@mediatek.com>
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

After enable kcsan on arm64+linux-5.15,it reports alignment_fault
when access unaligned address.
Here is the oops log:
"
Trying to unpack rootfs image as initramfs.....
Unable to handle kernel paging request at virtual address
  ffffff802a0d8d7171
Mem abort info:o:
  ESR = 0x9600002121
  EC = 0x25: DABT (current EL), IL = 32 bitsts
  SET = 0, FnV = 0 0
  EA = 0, S1PTW = 0 0
  FSC = 0x21: alignment fault
Data abort info:o:
  ISV = 0, ISS = 0x0000002121
  CM = 0, WnR = 0 0
swapper pgtable: 4k pages, 39-bit VAs, pgdp=000000002835200000
[ffffff802a0d8d71] pgd=180000005fbf9003, p4d=180000005fbf9003,
pud=180000005fbf9003, pmd=180000005fbe8003, pte=006800002a0d8707
Internal error: Oops: 96000021 [#1] PREEMPT SMP
Modules linked in:
CPU: 2 PID: 45 Comm: kworker/u8:2 Not tainted
  5.15.78-android13-8-g63561175bbda-dirty #1
...
pc : kcsan_setup_watchpoint+0x26c/0x6bc
lr : kcsan_setup_watchpoint+0x88/0x6bc
sp : ffffffc00ab4b7f0
x29: ffffffc00ab4b800 x28: ffffff80294fe588 x27: 0000000000000001
x26: 0000000000000019 x25: 0000000000000001 x24: ffffff80294fdb80
x23: 0000000000000000 x22: ffffffc00a70fb68 x21: ffffff802a0d8d71
x20: 0000000000000002 x19: 0000000000000000 x18: ffffffc00a9bd060
x17: 0000000000000001 x16: 0000000000000000 x15: ffffffc00a59f000
x14: 0000000000000001 x13: 0000000000000000 x12: ffffffc00a70faa0
x11: 00000000aaaaaaab x10: 0000000000000054 x9 : ffffffc00839adf8
x8 : ffffffc009b4cf00 x7 : 0000000000000000 x6 : 0000000000000007
x5 : 0000000000000000 x4 : 0000000000000000 x3 : ffffffc00a70fb70
x2 : 0005ff802a0d8d71 x1 : 0000000000000000 x0 : 0000000000000000
Call trace:
 kcsan_setup_watchpoint+0x26c/0x6bc
 __tsan_read2+0x1f0/0x234
 inflate_fast+0x498/0x750
 zlib_inflate+0x1304/0x2384
 __gunzip+0x3a0/0x45c
 gunzip+0x20/0x30
 unpack_to_rootfs+0x2a8/0x3fc
 do_populate_rootfs+0xe8/0x11c
 async_run_entry_fn+0x58/0x1bc
 process_one_work+0x3ec/0x738
 worker_thread+0x4c4/0x838
 kthread+0x20c/0x258
 ret_from_fork+0x10/0x20
Code: b8bfc2a8 2a0803f7 14000007 d503249f (78bfc2a8) )
---[ end trace 613a943cb0a572b6 ]-----
"

After checking linux 6.3-rc1 on QEMU arm64,it still has the possibility
to read unaligned address in read_instrumented_memory(qemu can not
emulate alignment fault)

To fix alignment fault and read the value of instrumented memory
more effective,bypass the unaligned access in read_instrumented_memory.

Signed-off-by: Haibo Li <haibo.li@mediatek.com>
---
 kernel/kcsan/core.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 54d077e1a2dc..88e75d7d85d2 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -337,6 +337,11 @@ static void delay_access(int type)
  */
 static __always_inline u64 read_instrumented_memory(const volatile void *ptr, size_t size)
 {
+	bool aligned_read = (size == 1) || IS_ALIGNED((unsigned long)ptr, size);
+
+	if (!aligned_read)
+		return 0;
+
 	switch (size) {
 	case 1:  return READ_ONCE(*(const u8 *)ptr);
 	case 2:  return READ_ONCE(*(const u16 *)ptr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230308022057.151078-1-haibo.li%40mediatek.com.
