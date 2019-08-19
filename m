Return-Path: <kasan-dev+bncBAABBNEX5LVAKGQEMXIDG6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 10A46922A9
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 13:44:54 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id k13sf3804242ioh.16
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 04:44:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566215093; cv=pass;
        d=google.com; s=arc-20160816;
        b=U2LPgS6aa6CiDjmBBCKGtVd35Olcz9IZ2ASIpdLxLEZ0kBcWFWdIqNtCWzhKv7f8Y1
         wQ6VuHnFdUCoMrq0Znlu6WhYb24bulLEI98fbFouT/U7EsbF5pPAciovFB7kEocZkAkV
         y8M52gVl/BwCRjDOQfE4Z1rjgvu5CSp1IcCqwbg6Bj5oFuZhTtfDoMgOwoDUMGlirdSX
         aviKvwHezpl6QSnKFv6a+1grB1vU3+wbH8deN9ZbHJV1fIM/wFMRqbPNqmzsD1GOfvzf
         jkC9PHzw602/FgrTGWUTEEFoOKKVSkAnHjyfqCQNRNuQfBm0TN1iQKRJLfjW0Ze3Ox2E
         prBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=7rrtbtWYOSCgWNfaEEEoqQG4ybmuhby2uodRvKydTgk=;
        b=rg9JAhPMEr9H71BzgJNCjY3KPMqB6gBqK0Yj5lsATRK/omS16ay9Okxukv5VXtSUXc
         2M2rJCpPS09qGoQC9H5tvUpsmOaX/Sim+AHRHbB9dbiOmMQnuqlI95A2hqSuR6250kOD
         5/jUDRpy3yylOuX1dlq9iOqpbGNiZ+Dt9GJwZ0cafl1cAid9zvDj9XHuuUlMVxtciZKY
         GYnOXwx+Bsd7sLEfPqYtfk/U1uB9rsLH/1vglhlbwosS1zMF9wE5AWFR7FOzcCm57a9G
         DRE9aq5VnDzye9Wn7ai46B8Bv+n+ASrb45BAAjg5UkwY61NgY6bMTYjdpslr8ZDVNIuM
         W9/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7rrtbtWYOSCgWNfaEEEoqQG4ybmuhby2uodRvKydTgk=;
        b=Sa0QRJSgN8eU0tdpYis0QX1s5N1NNiWzEDMIGbsCXBQSSXxuoMShG/IJrOwJXy30M1
         0zRsyIrySucbwDttTEkMGTuVvVKTJcCgsiXDICkktwsnajnmt08sD6JwDFIXC3j9o2IA
         Qf8K02YVZrPq6LMT55EykBGrJ2ruLct/FrmU0pbIRPeB/vzBOgnIOppQ+M1TRK9zT2qY
         93BphvVQ1n49bEvdp5u25ake2VCm2GQnvjIUMuBCR9Ib2yyL3rXXoD+GHMntCX2gwgqp
         NunZ7uBcwbCH5DaEfhGrHa4GT2+zyt3uPgTjHuXhRM/KD21/2AL1PGwtebe+j6VshW3P
         rxcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7rrtbtWYOSCgWNfaEEEoqQG4ybmuhby2uodRvKydTgk=;
        b=At28+6VhY+I/ZzO6HuyXo+D6Q/88m/RNKWPh6VyEsnEc3ODMsuI1OBgnsqYrRWMc9l
         f5su63khiY+u4vqBjp7z/M/MA2yDPC/KBiNGboZV+TjXgCkPuYXV5fgSkIjC+u9n8ZB+
         bjKQTott3onNFMZwvidFM72SyljQKZj3c8eQucecRARWk1hp8b7KXVeoPF7hDQ5Kn//p
         uCIzbFbq1Y+EOO7pBkMsEsO9D1lacnUeOXrjMcXDadVED0/wOfV+/iCR7/8VU32CoL9F
         lxn/339H9tstQxxuXC90VJPkxfVfdjqH6cfIfnTxMwzApWcEY9VZY92nIqblkVrzslcZ
         /Pgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVN25njas7vc7lfqJuFzqnm/fe29GXvCxRXlNwxIatKBpKPkfbW
	hwd3mYyMHdTDHTwF5AOELdA=
X-Google-Smtp-Source: APXvYqzAB0xPp8sMq8f4m/U2+bWPiytmTwe7Fp8Tiq3OzxrCnaqmCsANOk9ZeGF4CiIWu2Lt9M0BGg==
X-Received: by 2002:a6b:dd18:: with SMTP id f24mr2152887ioc.97.1566215092856;
        Mon, 19 Aug 2019 04:44:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:d018:: with SMTP id x24ls3876546ioa.6.gmail; Mon, 19 Aug
 2019 04:44:52 -0700 (PDT)
X-Received: by 2002:a5d:8885:: with SMTP id d5mr15124491ioo.181.1566215092649;
        Mon, 19 Aug 2019 04:44:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566215092; cv=none;
        d=google.com; s=arc-20160816;
        b=efbcbfa6TiEN04urSheeaFS3rKetUije16pMycmmt+YwfvixTSn6yA1CpQw9zB8Te7
         ZHWqwbvyicpxeTnG+XymY0d9UM+8M7roV0p3rU+M18YoZSXf+uObyysUys3kXP1cv4EQ
         3j2xKnkMI7h9xkzH5nLZ1m4EyHmCFbpV+WW/WBijy93XQxwdW2rnlsXZ/7V12eLN7ebK
         iN1pemMTbm2DYEVyMqJPz8xy/jPSOhCAT11z0q/luuOfZNSgJAo5sNQuk+fIlTT12NsF
         4gx26qfHRqNLFWYTivtk4445nru8pZtHE9BhigOXmXgFhhouf/Ipcpey0WRMhENnm36A
         AAJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=r+ZYVTBc0GCOEYs5DW8XZF5fLl5SZrJ/bAuhiY6pKME=;
        b=uenn0JmmxxH4iRz4ctiDqnn7D09b2JH3DY6aAFS5/0124775jW8oAHiQEFmIi2GmRu
         Vtj5AJcsWvvDK0kw2apBySVKxRZLb3wZ4wzExB8Hy0nB1JWT+Z17ZX3EZzP8P6MhZXVy
         TckaozQ9zp5jM3vhn9fC5hfmB2J12pcWZDqueFOmfhNr4gKZ0U8B6FEm00wASdMD7T4v
         okUILpQDV9Os6nLs8j5GBA/WGXZKZdjQPPl3TNcUnxPuzKO3fhkGbaxJ7fet2cXyCaEK
         ImBk+OhDqW2QGaRwk1soN3f19gQjGfIN12ZjTmBn6yEZhZQTtMpTNWdZf9fwbdb0YrYL
         7z1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id e23si686982ioe.5.2019.08.19.04.44.51
        for <kasan-dev@googlegroups.com>;
        Mon, 19 Aug 2019 04:44:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 5c5b18c1eaff4ff3965997d79be92ffe-20190819
X-UUID: 5c5b18c1eaff4ff3965997d79be92ffe-20190819
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0707 with TLS)
	with ESMTP id 1040434438; Mon, 19 Aug 2019 19:44:45 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 19 Aug 2019 19:44:46 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 19 Aug 2019 19:44:47 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Catalin Marinas
	<catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, Matthias
 Brugger <matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>
CC: <kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux-mediatek@lists.infradead.org>,
	<wsd_upstream@mediatek.com>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH] arm64: kasan: fix phys_to_virt() false positive on tag-based kasan
Date: Mon, 19 Aug 2019 19:44:20 +0800
Message-ID: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

__arm_v7s_unmap() call iopte_deref() to translate pyh_to_virt address,
but it will modify pointer tag into 0xff, so there is a false positive.

When enable tag-based kasan, phys_to_virt() function need to rewrite
its original pointer tag in order to avoid kasan report an incorrect
memory corruption.

BUG: KASAN: double-free or invalid-free in __arm_v7s_unmap+0x720/0xda4
Pointer tag: [ff], memory tag: [c1]

Call trace:
 dump_backtrace+0x0/0x1d4
 show_stack+0x14/0x1c
 dump_stack+0xe8/0x140
 print_address_description+0x80/0x2f0
 kasan_report_invalid_free+0x58/0x74
 __kasan_slab_free+0x1e4/0x220
 kasan_slab_free+0xc/0x18
 kmem_cache_free+0xfc/0x884
 __arm_v7s_unmap+0x720/0xda4
 __arm_v7s_map+0xc8/0x774
 arm_v7s_map+0x80/0x158
 mtk_iommu_map+0xb4/0xe0
 iommu_map+0x154/0x450
 iommu_map_sg+0xe4/0x150
 iommu_dma_map_sg+0x214/0x4ec
 __iommu_map_sg_attrs+0xf0/0x110
 ion_map_dma_buf+0xe8/0x114
 dma_buf_map_attachment+0x4c/0x80
 disp_sync_prepare_buf+0x378/0x820
 _ioctl_prepare_buffer+0x130/0x870
 mtk_disp_mgr_ioctl+0x5c4/0xab0
 do_vfs_ioctl+0x8e0/0x15a4
 __arm64_sys_ioctl+0x8c/0xb4
 el0_svc_common+0xe4/0x1e0
 el0_svc_handler+0x30/0x3c
 el0_svc+0x8/0xc

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
---
 arch/arm64/include/asm/kasan.h  |  1 -
 arch/arm64/include/asm/memory.h | 10 ++++++++++
 2 files changed, 10 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index b52aacd2c526..59894cafad60 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -5,7 +5,6 @@
 #ifndef __ASSEMBLY__
 
 #include <linux/linkage.h>
-#include <asm/memory.h>
 #include <asm/pgtable-types.h>
 
 #define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 8ffcf5a512bb..75af5ba9ff22 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -171,6 +171,7 @@
 
 #include <linux/bitops.h>
 #include <linux/mmdebug.h>
+#include <asm/kasan.h>
 
 extern s64			memstart_addr;
 /* PHYS_OFFSET - the physical address of the start of memory. */
@@ -282,7 +283,16 @@ static inline phys_addr_t virt_to_phys(const volatile void *x)
 #define phys_to_virt phys_to_virt
 static inline void *phys_to_virt(phys_addr_t x)
 {
+#ifdef CONFIG_KASAN_SW_TAGS
+	unsigned long addr = __phys_to_virt(x);
+	u8 *tag = (void *)(addr >> KASAN_SHADOW_SCALE_SHIFT)
+				+ KASAN_SHADOW_OFFSET;
+
+	addr = __tag_set(addr, *tag);
+	return (void *)addr;
+#else
 	return (void *)(__phys_to_virt(x));
+#endif
 }
 
 /*
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190819114420.2535-1-walter-zh.wu%40mediatek.com.
