Return-Path: <kasan-dev+bncBDY7XDHKR4OBB5E4VGEAMGQEHNVHCNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A7AFF3DFCB4
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Aug 2021 10:23:17 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 16-20020a250b100000b029055791ebe1e6sf2134190ybl.20
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Aug 2021 01:23:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628065396; cv=pass;
        d=google.com; s=arc-20160816;
        b=q6j48f0DXP001rX6CzB3OxhB0NwpS8c27mAiurLr9EwURaCdERZqNtMsp5mGBc0pEX
         HuJ/kuh9d8WF0OdA2PrLSajsfafqnUBTuXIoDPoBrrWveRnPZSfYN9uA/+zyKz5OzeFN
         UvxCoULDQxy3N5XWIrV6rc3reJSs0gPxVpmTwYVE0u7sSrNoivd8uN5hBi9z0fINeKf8
         /S/wMDH+HFAqhU0leCo9jviW5u02iLVL6cBWB2hWvGdt8+oFQEGSAoVUUntiA5Y7r5DL
         7x3hy5Sassxn2+mllreRZaAGto8TDeC6KgyrVlFtaQaTZzDCB3F4tR/Qg+YuruAZwoPX
         jAvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=S/fAsuKrDmkH4uT7R3HutSXBb0TgeB/U99oe+KcKwBY=;
        b=s2+ZYY+UkSt5VvFuzZjmNSRvo+3Ffe5Uq8EmmVWw/eyvWE4EZXRQIJp+5m/WqfhDko
         qdHQxTlBPUKjDpvawDDOLGWG+kHqLA0PpNdtvCYg5D87jT0dKQ748qmv3bBzSM+0b7qp
         Ayv/+tJpaQbnA/1UX7BrOuN6qhcfUBIAz4ym0GJ6/n/hi8J6jjkbjo2P3t/oCt33S0wA
         S26KGLWK7uvPc1MZaZPmMJPy3wnDybOQburIOwzNDX4uiinGwRwD6lhIhFn4CfxYiOtq
         Ae91GDxOFOGRZrOvDmo8P96O0mvc2oYI3YlTZd+BlbC5AttJO+SOEsIzeKSxaR4WnnjO
         6uTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S/fAsuKrDmkH4uT7R3HutSXBb0TgeB/U99oe+KcKwBY=;
        b=X7bJsi5RmFd+Ve/zx/HJjwV8TxJ3D1EYcGIYG+rSW5xOAv0aJuCdaan8pgxEy0iD1o
         snsfN4oVP1/0xIb7duTiKNAoc1Tgst4SncmNcw0r4Udy7CO1gV/zzrYiQYofXV/6gySB
         gw4gGEn9cFJYX6D7DNbpQ/rv6C8nb5ExU4VhDyhRSXNXQJgolrJTqIlrfrpTqChVnr35
         Q8I6FxYGDR5/t5HCUFyxhQqNGALnMccYMJgYVrD9Cl4IsiWgZfxNbx0sX38iDNd94YM7
         WYK5T5aB/lDx3d4J5w9lGMrpqOobHQyZOfPaHEMkFvWDSkisGJJ09YZ+/X6ghZnLCMp1
         3rMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S/fAsuKrDmkH4uT7R3HutSXBb0TgeB/U99oe+KcKwBY=;
        b=DuksG9RtImbft+wcxa3Dyw+Y7J/aWhPsWbToLLjmLlPssKkxGaHxavBfkUck/hSITV
         JeXSl3h1kC9US3TSFsO8nrn3ROcyD2apjduDBF1aZGE7kxeZrwQiULp+7gqlsQVRAA0J
         WLyWVTG+VBvxf8yn1tC0KpA3qBVtEmnheRc/tL4cJi+AwiUvdDmstqlGmuzWMtpwXZHV
         6lb8c6gtTSdgVPLOpbV2kL470EMe1yX1igDy0yzQRZmxQ8QV1HRAO1tb7Hc/CivKh1vW
         kRgpFtqKXJOdxtKLYCAbrCk8T6hwwrkxAtDEno/y4/H6TNJ6ii7tTQEWw9Mg1/XI7nek
         Rtag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532muZSN8viR5I+RC5rWBtMpSxrefmBDUnccCfjY04R6qbxepM5O
	H8Y+ZXrPxkOuYak70xJyaFU=
X-Google-Smtp-Source: ABdhPJx47TaTXCoONqKP5NA+ny63HqjIUiY4FG5TDJTH9G6PO6ufFi7gK8jTARgYbQHFvZTlDlbQLw==
X-Received: by 2002:a25:fc0a:: with SMTP id v10mr34776581ybd.85.1628065396549;
        Wed, 04 Aug 2021 01:23:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9307:: with SMTP id f7ls603769ybo.10.gmail; Wed, 04 Aug
 2021 01:23:16 -0700 (PDT)
X-Received: by 2002:a25:5086:: with SMTP id e128mr34336607ybb.223.1628065396070;
        Wed, 04 Aug 2021 01:23:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628065396; cv=none;
        d=google.com; s=arc-20160816;
        b=i4hMNWbCX+/DKaWlDEhHSXAOVuV1BNqsNMeiCP1VOZlt46Hwwaqo1lO5BJbXis4AXe
         hckQM1/TMmyFyl1B3N3DSxE6pdxPmihhR0tvspzXWALMGn9dxt4EKE3Oxb4R+9I4jb8F
         n/yuIv1Fqca0icao0N7wjbHpzN8ZgCCcdoEA5O95iYm2v7RjIptxFQk67LzX61j9ScS+
         tbcUFE1aK89dd7zdA0IuCwKTzyyKjDuh67sayH6Pw037A3pfMRpJ883goSPA8bG7U4K/
         jSno+Iw2beR4GPYbi+hRCKwlgLRaLAhEhstZhRvqBRdfuWzuci1X9MunftUpNCr1iNs4
         PPtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=k/+4DISTs33DUyaJMcpqMOaLpJjJDZ4AdaIDr/yOO4Q=;
        b=USv0OcZbJYE+McFtAImsouAL3qt+C6RIMqg5UOYENVoOAosIubzOAo7E0U2kxHwgaT
         3FY/u5Gn9nXH/80P7cexXpcWYGt8kahCSj9er/wYn4kPMEBaEPqiyJE5qf8aTgna5KaD
         Oy5UNErDSPNyVxwXNMkfvVBjSlT5Iz6h/B0uhXHO89+1Km6HAV7qqt/Gk9TQ3RLevbV0
         dqFASW80yL5ND4b8ggCiBv/3Rim2Jf5uxZHs0s/6RYIwTEiC9/ASYoC7ycl0pVAK2n5k
         i8RXvxgajCcioze63fFr7utiFRgg5t+ZMQbOBOUtiYoKN8iwpAymdC6cKpTrA2EeWh4D
         YZGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id z205si93555ybb.0.2021.08.04.01.23.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Aug 2021 01:23:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 5e5cc4f52d974484bce8ecced68553a4-20210804
X-UUID: 5e5cc4f52d974484bce8ecced68553a4-20210804
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1411928504; Wed, 04 Aug 2021 16:23:13 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 4 Aug 2021 16:23:11 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 4 Aug 2021 16:23:11 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang
	<andrew.tang@mediatek.com>, Andrey Konovalov <andreyknvl@gmail.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
	Chinwen Chang <chinwen.chang@mediatek.com>, Andrew Morton
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v2 1/2] kasan, kmemleak: reset tags when scanning block
Date: Wed, 4 Aug 2021 16:22:29 +0800
Message-ID: <20210804082230.10837-2-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210804082230.10837-1-Kuan-Ying.Lee@mediatek.com>
References: <20210804082230.10837-1-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210804082230.10837-2-Kuan-Ying.Lee%40mediatek.com.
