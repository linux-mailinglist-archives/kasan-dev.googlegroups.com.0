Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3GR52LQMGQED72GJQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 146A3595E48
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 16:25:49 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id o3-20020adfa103000000b0022514e8e99bsf523632wro.19
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 07:25:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660659948; cv=pass;
        d=google.com; s=arc-20160816;
        b=kbORYDB0SSVGFQA0OpFyUlzs0/S9kAnYB8oR82Dyo+jCLZ2oTnM/8wAD2vFtHiX2YK
         XUeHqPhy4mwY5PNpoZM3M4c5mrXHe31TdesxiKzGQftMFgIftb4UGYECdp5bhRXm64An
         DPMjUuCgruKQpBSK5JrvofWnt76ZgAmjc7d3P7pH22VLs2Yinp6qK3X2zcWrzlwV1l7O
         ozLKyUsLRnDXZgB85NRje9Z6UmxV9oxtEHVMmfgpcXR1X45FVp4CQcmsp524cNgu50ft
         f/uu8/pQuWoSNKcAd2C+UXSu7lHYpweMuVK+DyxQs5TbgmAb+AhkG3DDU3X55OcOwzbA
         z88g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=VSleNYvgJ8/F++VgWCZoqfoMl75dXijdaaUqG9e/skU=;
        b=wz/WMxHSGVHk5WMtaxL9TPYwOenNjjGt/JC4Eer9eTNLq/Dk+sQri1Mu4MbMG/xy11
         +f2W9iGTMkWHtinLodrlfVMOx1rN9QX5te+dzzmRQodXUBguaQgo4dmCyshO0QIgT0xt
         PXW5dmMCOwLtBjzsUDH2ustoFD3Ur+mT8SrkTqcdI9GvCa1LYzBX3OLOU6kN5iYui+gz
         cL1WyakXj3wi8fF+ld17K6gqV1JU6QYtYS9AnPttnozXwQCVC7hkKt18K6rFpsKNlQJQ
         U7LFrCE2UtBEJWJ82tT/YbzBdWbwywkLmhXo8Npukc0zBpD1ryYfo8Se5F8qgtP+sJCL
         VsAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nQ93mu+9;
       spf=pass (google.com: domain of 36qj7ygukcukpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=36qj7YgUKCUkpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc;
        bh=VSleNYvgJ8/F++VgWCZoqfoMl75dXijdaaUqG9e/skU=;
        b=iSd3KVsuYjqWJMBOLDWZojFJxzcqIOWl8YWyh/sZBCldVDEszAdOCApgh2NdS2KjSP
         wlOlB7lyqb48Lux5Vv7Olva4R/HnMOogb5bjmSZyaqhRMPEHYvc9vcLQcpKyuhAwQCb7
         7KHBgSL4NYiug7qX9Ogh83lwcpI3103Yo4kk2SIFOP+7+dBwxKlAuD7RXYHRe1JAcHBp
         eizZo/AV3V1nGC/q3XAZDLombuA5vYa6rObqIdosKK7ME+gyG7HAvGxQjQKRcRZVnyPl
         P7WVtxEmLIrmaZDYGDymX6+QwUPgXc81IJXrjKxlbf5DoXQ/LMSrNvfw6YiWRGO3UrQh
         Nl7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-gm-message-state:from:to:cc;
        bh=VSleNYvgJ8/F++VgWCZoqfoMl75dXijdaaUqG9e/skU=;
        b=Fga58qC2nfk/VMkMabTtJc+EhgvL+ergPCr/8Vw8p7WS1JcCH6hANSWge1FHHvgDsy
         2SyvAtohiDB0oCxaV+bCslLWuFWmD4IMmJ/LOnlOzNLpJant1VgcLIy5MkJGUITYj13T
         rIWShbL+4f6pvBGvHSELJ/LF4R42sh47WufuoDdQ4Urgzk9o9ELBiDMrqFRNZtvLtEa9
         owRBiFC7W4/EVKsvYvQ0wzwTkX2wkkIeLpYl7PZ13YWZHUc/nuP59Z9i7/wjrzdq0Y2k
         59VM3kjInTSWSwmvF4HH2hmR1u/xinNs2wR9W80jn/zSrPtF+lFPBPBJzj3yaO8ABRDE
         m2+A==
X-Gm-Message-State: ACgBeo1poLPUav5iGYzgbIjm1cEFW+9IWiYihpCxhPRqaxJQvLO4JssQ
	GJT7PLitdbGEz5Y7XtbQs38=
X-Google-Smtp-Source: AA6agR6sIsayWAtN/k3zc8vvQ9GooZWNO+ER7FwZB3O5ERyfiYICXDXh1m3Juc09MsDNOh84sLlxqg==
X-Received: by 2002:a05:6000:a09:b0:220:638f:3b4a with SMTP id co9-20020a0560000a0900b00220638f3b4amr11853293wrb.626.1660659948565;
        Tue, 16 Aug 2022 07:25:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3c1:b0:220:80cc:8add with SMTP id
 b1-20020a05600003c100b0022080cc8addls19795079wrg.2.-pod-prod-gmail; Tue, 16
 Aug 2022 07:25:47 -0700 (PDT)
X-Received: by 2002:a5d:4c82:0:b0:21f:1404:1606 with SMTP id z2-20020a5d4c82000000b0021f14041606mr11630333wrs.642.1660659947260;
        Tue, 16 Aug 2022 07:25:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660659947; cv=none;
        d=google.com; s=arc-20160816;
        b=F1bzAQOhp1GqE2QhfGA7NJqbEf4ZJ0c3DxWix1CW/HAwAwNfAUiVIE2ZmxSH8R5xR6
         FKD4ICYJTH8z8Yal+Y1bXMT7k5mMjV6N1IZQfRzqLxcw98eK3lOB+RJMQ/KLIbcfi/Fr
         l3M442ndw6bkqe83qi9HfE+Ip4ZwVF8P+uVywwEqFQWIiX+D5wKinRD7CPPTPgHnhxqM
         5bKYt4opgN1MptmTXrs0P3PzG/3DbyU/H6pzyvbSzcQn+pH54fYvcmCdGMRl/1f0BO57
         jG2rYr3sRBRLA3g/31Fz8IAwyzP9lJZImE2E0vaOuSQMltFoPdQx3gH7Abt/LkwoI8k5
         z80g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=hy9UEqt4hbmFGdzKrmujqIQhaC8w3Q92dlmS+f+lkQs=;
        b=l35/BWAuCxK4C23McSv2bwWjw/Qlc2hEBtD/AA/TYmd1Ht0Wx0PTz8idPgfryqyFZy
         uJT3aNtmfocIFAUEXkAiO4z114axXotJdY3lshJ3Qbre5v6IfWzJYvsbNom1RP8R/BEW
         DaX6gvE6GmzL4HD4xKqLlJad/b+9RISoR40Hn8FDqT9zhQax9Z8CMCcqYETQEZUnzEzy
         tFo4ll8FZB8gx96pPsTOTAwcC5MNCA68AxYE1MakImAIfSjBs1nVs4HrgP8GzEwrJ53i
         nU6x9DdLX00eqCTuoWOHzqG3RJaMl4Yd//UCDYtS6RxFXCGWtbF0vKiia63hd4QjAC9t
         OXKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nQ93mu+9;
       spf=pass (google.com: domain of 36qj7ygukcukpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=36qj7YgUKCUkpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id e35-20020a5d5963000000b0021d91e1ca87si825758wri.1.2022.08.16.07.25.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Aug 2022 07:25:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36qj7ygukcukpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id qf23-20020a1709077f1700b007308a195618so1825358ejc.7
        for <kasan-dev@googlegroups.com>; Tue, 16 Aug 2022 07:25:47 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:b8f6:52b8:6a74:6073])
 (user=elver job=sendgmr) by 2002:a05:6402:428a:b0:42e:8f7e:1638 with SMTP id
 g10-20020a056402428a00b0042e8f7e1638mr19083589edc.228.1660659946902; Tue, 16
 Aug 2022 07:25:46 -0700 (PDT)
Date: Tue, 16 Aug 2022 16:25:29 +0200
Message-Id: <20220816142529.1919543-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.1.595.g718a3a8f04-goog
Subject: [PATCH] kfence: free instead of ignore pool from kmemleak
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Max Schulze <max.schulze@online.de>, Will Deacon <will@kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Yee Lee <yee.lee@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=nQ93mu+9;       spf=pass
 (google.com: domain of 36qj7ygukcukpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=36qj7YgUKCUkpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Due to recent changes to kmemleak and how memblock allocated memory is
stored in the phys object tree of kmemleak, 07313a2b29ed ("mm: kfence:
apply kmemleak_ignore_phys on early allocated pool") tried to fix KFENCE
compatibility.

KFENCE's memory can't simply be ignored, but must be freed completely
due to it being handed out on slab allocations, and the slab post-alloc
hook attempting to insert the object to the kmemleak object tree.

Without this fix, reports like the below will appear during boot, and
kmemleak is effectively rendered useless when KFENCE is enabled:

 | kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
 | CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.19.0-v8-0815+ #5
 | Hardware name: Raspberry Pi Compute Module 4 Rev 1.0 (DT)
 | Call trace:
 |  dump_backtrace.part.0+0x1dc/0x1ec
 |  show_stack+0x24/0x80
 |  dump_stack_lvl+0x8c/0xb8
 |  dump_stack+0x1c/0x38
 |  create_object.isra.0+0x490/0x4b0
 |  kmemleak_alloc+0x3c/0x50
 |  kmem_cache_alloc+0x2f8/0x450
 |  __proc_create+0x18c/0x400
 |  proc_create_reg+0x54/0xd0
 |  proc_create_seq_private+0x94/0x120
 |  init_mm_internals+0x1d8/0x248
 |  kernel_init_freeable+0x188/0x388
 |  kernel_init+0x30/0x150
 |  ret_from_fork+0x10/0x20
 | kmemleak: Kernel memory leak detector disabled
 | kmemleak: Object 0xffffff806e24d000 (size 2097152):
 | kmemleak:   comm "swapper", pid 0, jiffies 4294892296
 | kmemleak:   min_count = -1
 | kmemleak:   count = 0
 | kmemleak:   flags = 0x5
 | kmemleak:   checksum = 0
 | kmemleak:   backtrace:
 |      kmemleak_alloc_phys+0x94/0xb0
 |      memblock_alloc_range_nid+0x1c0/0x20c
 |      memblock_alloc_internal+0x88/0x100
 |      memblock_alloc_try_nid+0x148/0x1ac
 |      kfence_alloc_pool+0x44/0x6c
 |      mm_init+0x28/0x98
 |      start_kernel+0x178/0x3e8
 |      __primary_switched+0xc4/0xcc

Reported-by: Max Schulze <max.schulze@online.de>
Fixes: 07313a2b29ed ("mm: kfence: apply kmemleak_ignore_phys on early allocated pool")
Fixes: 0c24e061196c ("mm: kmemleak: add rbtree and store physical address for objects allocated with PA")
Signed-off-by: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Yee Lee <yee.lee@mediatek.com>
---

Note: This easily reproduces on v5.19, but on 6.0-rc1 the issue is
hidden by yet more kmemleak changes, but properly freeing the pool is
the correct thing to do either way, given the post-alloc slab hooks.
---
 mm/kfence/core.c | 11 ++++++-----
 1 file changed, 6 insertions(+), 5 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index c252081b11df..9e52f2b87374 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -617,12 +617,13 @@ static bool __init kfence_init_pool_early(void)
 
 	if (!addr) {
 		/*
-		 * The pool is live and will never be deallocated from this point on.
-		 * Ignore the pool object from the kmemleak phys object tree, as it would
-		 * otherwise overlap with allocations returned by kfence_alloc(), which
-		 * are registered with kmemleak through the slab post-alloc hook.
+		 * The pool is live and will never be deallocated from this
+		 * point on. Remove the pool object from the kmemleak phys
+		 * object tree, as it would otherwise overlap with allocations
+		 * returned by kfence_alloc(), which are registered with
+		 * kmemleak through the slab post-alloc hook.
 		 */
-		kmemleak_ignore_phys(__pa(__kfence_pool));
+		kmemleak_free_part_phys(__pa(__kfence_pool), KFENCE_POOL_SIZE);
 		return true;
 	}
 
-- 
2.37.1.595.g718a3a8f04-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220816142529.1919543-1-elver%40google.com.
