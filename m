Return-Path: <kasan-dev+bncBD6PZLHGTICRBSEA3GYAMGQE3YSQFHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C85789EC12
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 09:31:22 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-6e6b285aaa4sf5596667b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 00:31:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712734280; cv=pass;
        d=google.com; s=arc-20160816;
        b=PiHm2HuJv/sTH8TmyKQpm0IoSWXM5qLqyCaHYIcup5P05lCuCNaId/DWJ8+cahmdrg
         oXiS0YmEcQ7hkdvIw+kFjRXz3A7wUP+fw1mC+k/k51hgk6FSc8A4S5b/0aLZVaMVY9g9
         yvKTVDikq+YnRylLIRmPXgjHxqymai4kUbaJblEXW/YJ99yzm8BS/3lzSA/Tppjbrfba
         FV80hRLh/Co621h6xFqMRb2PHN4Pb96EPJcyUKILaNc84PEq0fmKAnBtgmW7vElTAf0p
         qWR08LLWVVh/0I98l4Re1icxNsbgoN7j9RSLuEla3siJ79iCqMcmc6nrfkFA6FEhYOiu
         wrfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=PDJTQhJo1apA8W601tjRBS0UdvA4cJjo8dKWx/kDvzU=;
        fh=+Szk6crm82IdGbPbHrQWhZXMsKxxuUIUQrs5cRoXXvQ=;
        b=EgMxFYp4zgnR80+xHAhOwT6ZNcp8G8X/Q0/0bPI1DLOWg4jit6EniIwtUzfdmYuo9e
         n9gHw+HF24vbD4FPbrsN/CdA0974N/tri4QesZPB54euzmCPSOSNjYah7yHoIVRF6i3a
         KEuuCu6LYkOF1XIT73hpNn58TgOgOD3+iNSfVFV9csCwNDrBSV6ACdG3n5oOlVYisGIQ
         Ibf6lIKB0DAeu/4Blg2IipTjVZe0cO0lOH1PQyxTDmS9SdX6ePlky+rg6gGYLgQBoc3K
         /oSNrc6ANP94Uh+FvA5QRUZ/bhrHxqrUqpa750tk5C2HwceSa9qHLQ9TWbDcgtHb6x9I
         VBJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=HgIK9aLy;
       spf=pass (google.com: domain of boy.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=boy.wu@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712734280; x=1713339080; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PDJTQhJo1apA8W601tjRBS0UdvA4cJjo8dKWx/kDvzU=;
        b=LCkEHoQ/ZsXkkWUYirtBu/8+z49b/77YGXrDI+k0DVtkgVa3o6subPGU6OenTnSMk9
         7Fq4rMQ7Tv3i+eU4LktuwWw/rV1nCsW36nvfM3iewynumpB8bUWD7AS9at4Rtasx0gWG
         6Bahrgmathsh7Lo4JFDkO8tL8EufHd3GzblxJb4NTD3cjXCF2VWcPA+cX6KEI7Sin/PI
         UAMYDU1lNXq9JFQXhG8Y9kjd03zSCYZgxO+JgrL/J8VkcNMJkjbrRVoTvGZV33S67hC0
         Gmbh0uPuOwK7YCigMFRkTofrzk4YfJ7SNVZLHsG83cJaz4968yoGo3MDkAO+Y9NjNonk
         NZAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712734280; x=1713339080;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PDJTQhJo1apA8W601tjRBS0UdvA4cJjo8dKWx/kDvzU=;
        b=UyZexIu6eey4fwqEdXociA8MrSUJ9QiKNrOvTMrUdWZXHysU16D4P92clpS7hNUFz1
         H3fxW0xvrfg55P7Kq/XEmtwJN55adndxNZ9N9JLEgb8kXf25xlR38iULQHSj/JmIoLf5
         B4KWIY1aK29aQapLpOXAVF1YVZye97fvwt1hkZUr0cOi5aQT4+qyIH3vp3jNqnv1FT2r
         0oaqDVeIVZKkO8Kpogy8kPLyYWbe2BMNZgi+0uuJtahYNHXZomZr+muqHqCHwRj0qkwo
         RqhPM0GlaahMBnw3CFyekQ4VkFijsc1ivGfPopVgpUKGl+fIPrJAMnVt+FpXZqLR8+a5
         Aj8A==
X-Forwarded-Encrypted: i=2; AJvYcCWZ/uN/kXtQNQ1CtprwL0x4ld1uB0vqyU9Gg2awTUd2FbVb1J3gtqvGC+aFbayFBQ4/rrLDJMbCnLwBuJHV0P+6N+qVx/Pq/A==
X-Gm-Message-State: AOJu0Yy5SrMWrg76NLFjqXgU/kYnqrb+pgG/CnDwVd93uZf4aRKpw6bm
	+8+2aVpJtpim9hQHjHEdbU5/v9mQ/y6krDHFlscCEYA9qHMyTYUy
X-Google-Smtp-Source: AGHT+IFVBp91wYu1c44sIwVDTtaOmJk4G2nX+QgOxNOexy8yjqRcsEXjWE0Lz9d4pcf24IhTykguuw==
X-Received: by 2002:a05:6a20:7f8b:b0:1a3:e64f:ea8d with SMTP id d11-20020a056a207f8b00b001a3e64fea8dmr2090126pzj.20.1712734280321;
        Wed, 10 Apr 2024 00:31:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:300c:b0:6ed:41e2:9c9e with SMTP id
 ay12-20020a056a00300c00b006ed41e29c9els1709323pfb.2.-pod-prod-05-us; Wed, 10
 Apr 2024 00:31:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTQvxI7WtgjAYNGOCFX2UbCjazgWZK5U8tWVT4x4nhSuTdJY+iC6cc8yV018gAi9Hqb3KyTVbbGKBf21YpPBOZ2K9i2G8+xZENeg==
X-Received: by 2002:a05:6a00:4f89:b0:6eb:4:3f26 with SMTP id ld9-20020a056a004f8900b006eb00043f26mr2238429pfb.18.1712734279122;
        Wed, 10 Apr 2024 00:31:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712734279; cv=none;
        d=google.com; s=arc-20160816;
        b=cqTZlhwQ5MljKJrWLYtPe0QeufFwevEB47aC7vIFQZ1m8NsyaEsrNP6bGRjxq4VB1j
         JoVhs1y2J7vUzSNGqlRRNu53VSUocBC/MzEBDAlDUVAozAgFZYIXGG8rGXWo3PkyZx5X
         FYrKpo1v+ne6/f7loK/mCGsLLf3NnK0FhzkZ8pR+0p9326p0CrJUMX+gZd6lRelpk5K/
         SdVpKxwVtlZhPEQtzACADD6nUoVOWLSy9DPy98TT6AbRZ7alM/xmmx8myvdmkckXHelD
         TF9hwId4SEd0d97dXI1pt/dP1ZBWRKcaTD37qYtS3XfOWgCTMGprQhIrVZoVDlsOWx/c
         3ULQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=hirxOWkyWCim2+ODFEmbXTRJuf23a8yt89BscoqEckY=;
        fh=D//uTkmxbCpjoTfYv/bxS0hQL5xufqtWUmY+vFM1CcM=;
        b=jM2G2waGaR0El/s9tyKRcQb+lLl1IBRktxQ5624u8Hxhdp12aYu7CZUFxnz2DA9E0d
         B5BhTIZugnIB0XHlkH+Oe9qffMl12gp7e9sINYNXX+7/zLrcZ+VXfNOujrud8uWY+QYp
         1UYQ+b7KnrSZfYRZaSrz+GUuRQ5qg4l/i1BYxTUjnpVZOJxxHqRYrPGa7+1R6V2lze3J
         ADIufxHVgi+bRsiY3NBiptPaKONMP/Su5+X6DUCYqbEtRKtYjOcVfFs0nBx6lgix1Crz
         pG4TKjScRyMCH/SQdUemgSNVcltD1gB+qmpjIg+b1eyFhzlnJgzJYAUPdI51E/FISo4U
         vQtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=HgIK9aLy;
       spf=pass (google.com: domain of boy.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=boy.wu@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id k196-20020a6284cd000000b006eac41e9673si1199058pfd.2.2024.04.10.00.31.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Apr 2024 00:31:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of boy.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 4f3e4fe8f70c11ee935d6952f98a51a9-20240410
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.37,REQID:f5891a29-3ac3-4a25-8710-5d4487c60482,IP:0,U
	RL:0,TC:0,Content:-25,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTIO
	N:release,TS:-25
X-CID-META: VersionHash:6f543d0,CLOUDID:bbb58082-4f93-4875-95e7-8c66ea833d57,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:0,File:nil,RT:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,
	SPR:NO,DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 0,NGT
X-CID-BAS: 0,NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR
X-UUID: 4f3e4fe8f70c11ee935d6952f98a51a9-20240410
Received: from mtkmbs11n1.mediatek.inc [(172.21.101.185)] by mailgw02.mediatek.com
	(envelope-from <boy.wu@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1938894362; Wed, 10 Apr 2024 15:31:13 +0800
Received: from mtkmbs13n1.mediatek.inc (172.21.101.193) by
 MTKMBS09N1.mediatek.inc (172.21.101.35) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Wed, 10 Apr 2024 00:31:12 -0700
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by
 mtkmbs13n1.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Wed, 10 Apr 2024 15:31:12 +0800
From: "'boy.wu' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mark Rutland <mark.rutland@arm.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Linus Walleij <linus.walleij@linaro.org>
CC: Alexander Potapenko <glider@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, <kasan-dev@googlegroups.com>, Russell King
	<linux@armlinux.org.uk>, Matthias Brugger <matthias.bgg@gmail.com>,
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, Boy Wu
	<boy.wu@mediatek.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux-mediatek@lists.infradead.org>, Iverlin
 Wang <iverlin.wang@mediatek.com>, Light Chen <light.chen@mediatek.com>
Subject: [PATCH v2] arm: kasan: clear stale stack poison
Date: Wed, 10 Apr 2024 15:30:44 +0800
Message-ID: <20240410073044.23294-1-boy.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: boy.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=HgIK9aLy;       spf=pass
 (google.com: domain of boy.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=boy.wu@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: boy.wu <boy.wu@mediatek.com>
Reply-To: boy.wu <boy.wu@mediatek.com>
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

From: Boy Wu <boy.wu@mediatek.com>

We found below OOB crash:

[   33.452494] ==================================================================
[   33.453513] BUG: KASAN: stack-out-of-bounds in refresh_cpu_vm_stats.constprop.0+0xcc/0x2ec
[   33.454660] Write of size 164 at addr c1d03d30 by task swapper/0/0
[   33.455515]
[   33.455767] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G           O       6.1.25-mainline #1
[   33.456880] Hardware name: Generic DT based system
[   33.457555]  unwind_backtrace from show_stack+0x18/0x1c
[   33.458326]  show_stack from dump_stack_lvl+0x40/0x4c
[   33.459072]  dump_stack_lvl from print_report+0x158/0x4a4
[   33.459863]  print_report from kasan_report+0x9c/0x148
[   33.460616]  kasan_report from kasan_check_range+0x94/0x1a0
[   33.461424]  kasan_check_range from memset+0x20/0x3c
[   33.462157]  memset from refresh_cpu_vm_stats.constprop.0+0xcc/0x2ec
[   33.463064]  refresh_cpu_vm_stats.constprop.0 from tick_nohz_idle_stop_tick+0x180/0x53c
[   33.464181]  tick_nohz_idle_stop_tick from do_idle+0x264/0x354
[   33.465029]  do_idle from cpu_startup_entry+0x20/0x24
[   33.465769]  cpu_startup_entry from rest_init+0xf0/0xf4
[   33.466528]  rest_init from arch_post_acpi_subsys_init+0x0/0x18
[   33.467397]
[   33.467644] The buggy address belongs to stack of task swapper/0/0
[   33.468493]  and is located at offset 112 in frame:
[   33.469172]  refresh_cpu_vm_stats.constprop.0+0x0/0x2ec
[   33.469917]
[   33.470165] This frame has 2 objects:
[   33.470696]  [32, 76) 'global_zone_diff'
[   33.470729]  [112, 276) 'global_node_diff'
[   33.471294]
[   33.472095] The buggy address belongs to the physical page:
[   33.472862] page:3cd72da8 refcount:1 mapcount:0 mapping:00000000 index:0x0 pfn:0x41d03
[   33.473944] flags: 0x1000(reserved|zone=0)
[   33.474565] raw: 00001000 ed741470 ed741470 00000000 00000000 00000000 ffffffff 00000001
[   33.475656] raw: 00000000
[   33.476050] page dumped because: kasan: bad access detected
[   33.476816]
[   33.477061] Memory state around the buggy address:
[   33.477732]  c1d03c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[   33.478630]  c1d03c80: 00 00 00 00 00 00 00 00 f1 f1 f1 f1 00 00 00 00
[   33.479526] >c1d03d00: 00 04 f2 f2 f2 f2 00 00 00 00 00 00 f1 f1 f1 f1
[   33.480415]                                                ^
[   33.481195]  c1d03d80: 00 00 00 00 00 00 00 00 00 00 04 f3 f3 f3 f3 f3
[   33.482088]  c1d03e00: f3 f3 f3 f3 00 00 00 00 00 00 00 00 00 00 00 00
[   33.482978] ==================================================================

We find the root cause of this OOB is that arm does not clear stale stack
poison in the case of cpuidle.

This patch refer to arch/arm64/kernel/sleep.S to resolve this issue.

From cited commit [1] that explain the problem

Functions which the compiler has instrumented for KASAN place poison on
the stack shadow upon entry and remove this poison prior to returning.

In the case of cpuidle, CPUs exit the kernel a number of levels deep in
C code.  Any instrumented functions on this critical path will leave
portions of the stack shadow poisoned.

If CPUs lose context and return to the kernel via a cold path, we
restore a prior context saved in __cpu_suspend_enter are forgotten, and
we never remove the poison they placed in the stack shadow area by
functions calls between this and the actual exit of the kernel.

Thus, (depending on stackframe layout) subsequent calls to instrumented
functions may hit this stale poison, resulting in (spurious) KASAN
splats to the console.

To avoid this, clear any stale poison from the idle thread for a CPU
prior to bringing a CPU online.

From cited commit [2]

Extend to check for CONFIG_KASAN_STACK

[1] commit 0d97e6d8024c ("arm64: kasan: clear stale stack poison")
[2] commit d56a9ef84bd0 ("kasan, arm64: unpoison stack only with CONFIG_KASAN_STACK")

Signed-off-by: Boy Wu <boy.wu@mediatek.com>
Reviewed-by: Mark Rutland <mark.rutland@arm.com>
Acked-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
---
v2 - Add commit message that reviewer mention
---
 arch/arm/kernel/sleep.S | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/arm/kernel/sleep.S b/arch/arm/kernel/sleep.S
index a86a1d4f3461..93afd1005b43 100644
--- a/arch/arm/kernel/sleep.S
+++ b/arch/arm/kernel/sleep.S
@@ -127,6 +127,10 @@ cpu_resume_after_mmu:
 	instr_sync
 #endif
 	bl	cpu_init		@ restore the und/abt/irq banked regs
+#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
+	mov	r0, sp
+	bl	kasan_unpoison_task_stack_below
+#endif
 	mov	r0, #0			@ return zero on success
 	ldmfd	sp!, {r4 - r11, pc}
 ENDPROC(cpu_resume_after_mmu)
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240410073044.23294-1-boy.wu%40mediatek.com.
