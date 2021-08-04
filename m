Return-Path: <kasan-dev+bncBDY7XDHKR4OBBAFTVGEAMGQE3HKW3NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id CA95E3DFDB7
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Aug 2021 11:10:25 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id k16-20020a170902ba90b029012c06f217cdsf1666001pls.14
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Aug 2021 02:10:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628068224; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bac/7zyr7G7P/3QoWoQeWsAPjtBM+aVLmrkkpERDfDOSBcWnosP/j0fTcAgWYfzfsK
         nq9wB9UhzR8SnHWuzp9osz2tz8UB4VraVIBzRieD2o2OIQD6nNetED0r+LSu1XpTcv2j
         UelnMbCi7m1DcJ8066F10ODfgBL5V9PoBLxzFWLzo0AF+TlO7PoZrwSrcQu6L5puh3se
         MwMgKBBM3k+v8XN53OlZxV/tzGQKzF5GD6mgZgXAfePGs85XEYs53qjfTKDRRFiecjtg
         R/LC0di9sb5I+j0rpQmy4VNk+ZpuTmhnmwFIxwLiIcN/Ebl6X5kC2eye19Nf6covvVf3
         ORqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YXMNApZK4PKk5xg4CDM5cs1NxSFy2uBVt4SSyYxzjSs=;
        b=Q3QSo2gfByXk/qb+gxwXUY9dgzYwwzvbTfi3jOuyFQeK3JiMgCXbTmPXB2CMdYAnqs
         K21IlBuHs2IeAObqOdVziL4JAMol3ovEO03GmM3Ok+jjUUaeoze3WjVmaN+hE1uRu8SB
         rfhwlmAifrFBjwRIEX83FfwuT/ZJA50cFMBCo68/rWObW+FJUGEyTbp2pAsF87ga1QnQ
         DG+9X1Ntn+UFhPkQhOGQ+Px0l15qvczyacDzKvJ9Vjfe3btinXbZnelgGbEtOwby2d3z
         8Mjcr+I7RBWuWOXMxGzuyHT2Bpbpc/rYWaZUWvRVgMlJ47NYKmBjaXYFt1zj9+DYGRCG
         YaxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YXMNApZK4PKk5xg4CDM5cs1NxSFy2uBVt4SSyYxzjSs=;
        b=OTjZ0c/Q56KBoebHBh842NDGx4pR1cGPpljZ2BXdYfkGImZkcQAtkjjjGqJCXpj+Pb
         w7w6WU6G8PLHaqpX9h1f01hmRtXy1jWaMvuxCW3WthiraI03s41x89pHeHWicEkgHkJ5
         CmXtAtJR3KTQ60/rFiRGwUN+CRFMAD0rvDFn8ppuFwsC+tsItEtKwtc1YY4caG5psb99
         H4qSKUDGSgMaZSsf9ROfbqyDqhJbnjtUO6g1CvzDTX4vdU3wSI3Um6BDHwyWL1V1lbO8
         2fwWLhsw2b/xvMbugM/sICVzckBEmGF5xoszq2Qleu4JOzFOvkMCbcl82PMhghaQylEt
         10eQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YXMNApZK4PKk5xg4CDM5cs1NxSFy2uBVt4SSyYxzjSs=;
        b=Ts1q1QQ9n68pRa5tVGI4lM/5uK8zDm+o2LomcEFaIxMMaAh4ElGd2vXZyOnUHCTCxp
         /KiXoikq9gtqP90pb3hRdVhdtEX7Yqde4FcSxN2YSJbAdmeADjrm0DVU5aYmouSSbWRw
         hq+g2UPeduo32O+fa+j6j81d1XOtKq4i6ompXhMqKaXw/C67F4gzEpatXqLNICMCBs3/
         AjHcr7FM+MUVXIWb1oL+2X6kjjRewQxacGnecKDME5IOyrQY3DxEBmr9nBTCcZmuoSKc
         rBXcUMXZcmL+MqLXoYLIgcYVkyoTpFNsa3ya8aVa/PvfCdxHIrwkjtoyQlUvLOavFYKh
         zItA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/mj4bf6zRshp8H5n81Hz6vearI4+MGfjCvi3ZyqWe/7LOIIrL
	AMWltsbCntnB3kKUHSzgW4w=
X-Google-Smtp-Source: ABdhPJwlz7xMDNVzPZAHdcWesqbbvbTDSbMMn6trkJaj8Z8jhtaxNUdp2ot74pPFDP/QjAbi90fczw==
X-Received: by 2002:a17:90a:ad85:: with SMTP id s5mr26485282pjq.187.1628068224471;
        Wed, 04 Aug 2021 02:10:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1c7:: with SMTP id e7ls891423plh.5.gmail; Wed, 04
 Aug 2021 02:10:23 -0700 (PDT)
X-Received: by 2002:a17:90a:9f91:: with SMTP id o17mr8745967pjp.29.1628068223785;
        Wed, 04 Aug 2021 02:10:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628068223; cv=none;
        d=google.com; s=arc-20160816;
        b=J5bg2xVnPZeInReJ5sGXQdoW1U/lQsgrKxOs3RrktwA2Rar2bEWwmtdRQK3uvIZQ9Y
         6LvVls8Sr957Pz/wJ5Tng8CLWxhT+xCPMEqokgeZwlcurXHczXM9ARV9onwBeQhORN/E
         I2YC4qeU9i6dg8boJv3XVoc4B4GMba0pXQNLDCiF1oBL+UkXkK7bfkqDJ2RxsGfJS76V
         7kBGfhNR1ScOy29LHV7FPmAOMtEJ1D8Z3NH1NIyB3oaRP8X9dAqgRuRStWoKKx/K2sKv
         pV/WasNENvSg9OvX0eGcyCOZtnycRFGWXxlDm5xd4NpbXJJf18u45nSwXYdrY4utqtdC
         XgOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=k/+4DISTs33DUyaJMcpqMOaLpJjJDZ4AdaIDr/yOO4Q=;
        b=PPiffiYY1R8kTFUmsfMXIFaS+iqYHdc2pMTU69KW0iGvZz9XOR+kmdNbws//7Ty/8u
         CUp75idz+e//1aiLmJQyyfYdAh4WyoiHio7ct36ptToxWcj9HvVlwhR2wWr0aBMEMCjV
         UjcEFfcUUacFB2Z/OAB2MI0Jb2vpjgC7HOtudzsJKt9cQNbOvHw0as3t9Cs7XAOJwaJi
         OT6CoZtoLtsrPKhAHc1e8tbRfU0obtM9Qvz9on0VgbMsPfD0fMTPD0veDCsH1L0AliCb
         RQItVKu85B2F/YoF4ZPZ5lhxLCvnj5L5798TDi3hKzLmIHN9LujUIAdSbghkhbMYD64M
         UWFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id g4si80297pjt.3.2021.08.04.02.10.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Aug 2021 02:10:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 5f44e41515834fad9bb660dadc3ef2a9-20210804
X-UUID: 5f44e41515834fad9bb660dadc3ef2a9-20210804
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1472033690; Wed, 04 Aug 2021 17:10:18 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs02n1.mediatek.inc (172.21.101.77) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 4 Aug 2021 17:10:17 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 4 Aug 2021 17:10:17 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang
	<andrew.yang@mediatek.com>, Andrey Konovalov <andreyknvl@gmail.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
	Chinwen Chang <chinwen.chang@mediatek.com>, Andrew Morton
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v3 1/2] kasan, kmemleak: reset tags when scanning block
Date: Wed, 4 Aug 2021 17:09:56 +0800
Message-ID: <20210804090957.12393-2-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210804090957.12393-1-Kuan-Ying.Lee@mediatek.com>
References: <20210804090957.12393-1-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
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

Kmemleak need to scan kernel memory to check memory leak.
With hardware tag-based kasan enabled, when it scans on
the invalid slab and dereference, the issue will occur
as below.

Hardware tag-based KASAN doesn't use compiler instrumentation, we
can not use kasan_disable_current() to ignore tag check.

Based on the below report, there are 11 0xf7 granules, which amounts to
176 bytes, and the object is allocated from the kmalloc-256 cache. So
when kmemleak accesses the last 256-176 bytes, it causes faults, as
those are marked with KASAN_KMALLOC_REDZONE == KASAN_TAG_INVALID ==
0xfe.

Thus, we reset tags before accessing metadata to avoid from false positives.

[  151.905804] ==================================================================
[  151.907120] BUG: KASAN: out-of-bounds in scan_block+0x58/0x170
[  151.908773] Read at addr f7ff0000c0074eb0 by task kmemleak/138
[  151.909656] Pointer tag: [f7], memory tag: [fe]
[  151.910195]
[  151.910876] CPU: 7 PID: 138 Comm: kmemleak Not tainted 5.14.0-rc2-00001-g8cae8cd89f05-dirty #134
[  151.912085] Hardware name: linux,dummy-virt (DT)
[  151.912868] Call trace:
[  151.913211]  dump_backtrace+0x0/0x1b0
[  151.913796]  show_stack+0x1c/0x30
[  151.914248]  dump_stack_lvl+0x68/0x84
[  151.914778]  print_address_description+0x7c/0x2b4
[  151.915340]  kasan_report+0x138/0x38c
[  151.915804]  __do_kernel_fault+0x190/0x1c4
[  151.916386]  do_tag_check_fault+0x78/0x90
[  151.916856]  do_mem_abort+0x44/0xb4
[  151.917308]  el1_abort+0x40/0x60
[  151.917754]  el1h_64_sync_handler+0xb4/0xd0
[  151.918270]  el1h_64_sync+0x78/0x7c
[  151.918714]  scan_block+0x58/0x170
[  151.919157]  scan_gray_list+0xdc/0x1a0
[  151.919626]  kmemleak_scan+0x2ac/0x560
[  151.920129]  kmemleak_scan_thread+0xb0/0xe0
[  151.920635]  kthread+0x154/0x160
[  151.921115]  ret_from_fork+0x10/0x18
[  151.921717]
[  151.922077] Allocated by task 0:
[  151.922523]  kasan_save_stack+0x2c/0x60
[  151.923099]  __kasan_kmalloc+0xec/0x104
[  151.923502]  __kmalloc+0x224/0x3c4
[  151.924172]  __register_sysctl_paths+0x200/0x290
[  151.924709]  register_sysctl_table+0x2c/0x40
[  151.925175]  sysctl_init+0x20/0x34
[  151.925665]  proc_sys_init+0x3c/0x48
[  151.926136]  proc_root_init+0x80/0x9c
[  151.926547]  start_kernel+0x648/0x6a4
[  151.926987]  __primary_switched+0xc0/0xc8
[  151.927557]
[  151.927994] Freed by task 0:
[  151.928340]  kasan_save_stack+0x2c/0x60
[  151.928766]  kasan_set_track+0x2c/0x40
[  151.929173]  kasan_set_free_info+0x44/0x54
[  151.929568]  ____kasan_slab_free.constprop.0+0x150/0x1b0
[  151.930063]  __kasan_slab_free+0x14/0x20
[  151.930449]  slab_free_freelist_hook+0xa4/0x1fc
[  151.930924]  kfree+0x1e8/0x30c
[  151.931285]  put_fs_context+0x124/0x220
[  151.931731]  vfs_kern_mount.part.0+0x60/0xd4
[  151.932280]  kern_mount+0x24/0x4c
[  151.932686]  bdev_cache_init+0x70/0x9c
[  151.933122]  vfs_caches_init+0xdc/0xf4
[  151.933578]  start_kernel+0x638/0x6a4
[  151.934014]  __primary_switched+0xc0/0xc8
[  151.934478]
[  151.934757] The buggy address belongs to the object at ffff0000c0074e00
[  151.934757]  which belongs to the cache kmalloc-256 of size 256
[  151.935744] The buggy address is located 176 bytes inside of
[  151.935744]  256-byte region [ffff0000c0074e00, ffff0000c0074f00)
[  151.936702] The buggy address belongs to the page:
[  151.937378] page:(____ptrval____) refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x100074
[  151.938682] head:(____ptrval____) order:2 compound_mapcount:0 compound_pincount:0
[  151.939440] flags: 0xbfffc0000010200(slab|head|node=0|zone=2|lastcpupid=0xffff|kasantag=0x0)
[  151.940886] raw: 0bfffc0000010200 0000000000000000 dead000000000122 f5ff0000c0002300
[  151.941634] raw: 0000000000000000 0000000000200020 00000001ffffffff 0000000000000000
[  151.942353] page dumped because: kasan: bad access detected
[  151.942923]
[  151.943214] Memory state around the buggy address:
[  151.943896]  ffff0000c0074c00: f0 f0 f0 f0 f0 f0 f0 f0 f0 fe fe fe fe fe fe fe
[  151.944857]  ffff0000c0074d00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
[  151.945892] >ffff0000c0074e00: f7 f7 f7 f7 f7 f7 f7 f7 f7 f7 f7 fe fe fe fe fe
[  151.946407]                                                     ^
[  151.946939]  ffff0000c0074f00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
[  151.947445]  ffff0000c0075000: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[  151.947999] ==================================================================
[  151.948524] Disabling lock debugging due to kernel taint
[  156.434569] kmemleak: 181 new suspected memory leaks (see /sys/kernel/debug/kmemleak)

Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
---
 mm/kmemleak.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kmemleak.c b/mm/kmemleak.c
index 228a2fbe0657..73d46d16d575 100644
--- a/mm/kmemleak.c
+++ b/mm/kmemleak.c
@@ -290,7 +290,7 @@ static void hex_dump_object(struct seq_file *seq,
 	warn_or_seq_printf(seq, "  hex dump (first %zu bytes):\n", len);
 	kasan_disable_current();
 	warn_or_seq_hex_dump(seq, DUMP_PREFIX_NONE, HEX_ROW_SIZE,
-			     HEX_GROUP_SIZE, ptr, len, HEX_ASCII);
+			     HEX_GROUP_SIZE, kasan_reset_tag((void *)ptr), len, HEX_ASCII);
 	kasan_enable_current();
 }
 
@@ -1171,7 +1171,7 @@ static bool update_checksum(struct kmemleak_object *object)
 
 	kasan_disable_current();
 	kcsan_disable_current();
-	object->checksum = crc32(0, (void *)object->pointer, object->size);
+	object->checksum = crc32(0, kasan_reset_tag((void *)object->pointer), object->size);
 	kasan_enable_current();
 	kcsan_enable_current();
 
@@ -1246,7 +1246,7 @@ static void scan_block(void *_start, void *_end,
 			break;
 
 		kasan_disable_current();
-		pointer = *ptr;
+		pointer = *(unsigned long *)kasan_reset_tag((void *)ptr);
 		kasan_enable_current();
 
 		untagged_ptr = (unsigned long)kasan_reset_tag((void *)pointer);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210804090957.12393-2-Kuan-Ying.Lee%40mediatek.com.
