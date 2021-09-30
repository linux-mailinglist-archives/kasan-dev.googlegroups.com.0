Return-Path: <kasan-dev+bncBDOY5FWKT4KRBCMO3CFAMGQEG7VE7AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id A54D741E170
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 20:50:51 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id t70-20020a637849000000b002879991cd1dsf4774970pgc.20
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 11:50:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633027850; cv=pass;
        d=google.com; s=arc-20160816;
        b=il41E6bK9oiOU1lF8r7vM3oVSIkbMLpJ+nRWQhfxkcuNNg1+qyUQvD6gCDEzMA5MjY
         /Tl7HOIIbMGhYFaT9OnL/qMaEgoQOKsWFIbMb1pvHReRppEKmXQb60LiAOX+HB3R1uW2
         /QvrvCvT/t5anQIRQDbXyaLDYIatW3nyEYToY7u/1pWVxzjt5cnQU/bFS3uPbrPpMnVp
         8cTy+1b4Jfh2DAftRIaBS58VqLLS9mtwrI7b3fVOxqLsNfLMyGFCnj5HO0WnS9v/bz7W
         Zx1zWRJztEF3210Cm7vVJKRkSYNfC9KmCI0aWXLPwc0/yFjaKdX4wvJHwJf1uSdxmUuA
         Ulrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rfF/z4zJh3Uq4FMmAV5hfHwJ6kxvXEMZbBOyuXknQ1c=;
        b=YY245BotrPMcVgd6MTQsMaOjaAyeabpefTWCTAcV4RoyhJIN0B2yUH5Od7SfvC5xh2
         3z22OKBZJASUAJYRxGngWLMXxi3Hne71I0Pi7V1mPelyayasUz5DkqVVUUumFU/6i3fH
         QKpvLUIw4JvPwe/zj/fl3Jc5oJELQUP7eyeHYoD3NqjHsHUmyXyPNHQyi0Z02vp40qJV
         7X+DEuLoZglnrK2OwITFfbmIJftCserXofbJfNxMDvNyJtmwA7wFX6jbz74vefQZZ/Lu
         hC/kqGjj1F2WA1MJzvp9bztL2jE9h1V+UgxgIEyvmrVzOen9OPVNqbWebWWdehZAI2XW
         B/0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="s/nujFn9";
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rfF/z4zJh3Uq4FMmAV5hfHwJ6kxvXEMZbBOyuXknQ1c=;
        b=j9O1sI1Olgpds1jTIrYfLlabN1vzJfXU8MIapBEjjrChSYPrLSw1zpRVVvZ/plEuxW
         nTQnH4IV+guMnh4ZBzneeTdcVVKdHCwInsQMGanlTbaiqus3mMNlgCv4GsnlxODKOTMx
         L4D3+vZgX/uItdyu003OHKWaZFdsyQ5muw7bruZ83rrtfYNENl+jJPFdVYh4QS/CMvyB
         wXal7AaaQ66ULQWXQc2n/4gQBF8hPjWeww9lp7vho/LDKfmK2vZFKYsF/5NIIiOcqRGl
         3vzM3VcK4dwjjs7Wrx9EJ2CT74r/VlJXQaREiTAPjeQCX1wjiY0nNN8gGKmWCTXSZj/G
         QJ5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rfF/z4zJh3Uq4FMmAV5hfHwJ6kxvXEMZbBOyuXknQ1c=;
        b=0lidN4qdZC2hfsgvV9+PkCbAbhmNfXHaaXlyqjagzv78zmUDpf/drahdSOO6kt0/WH
         VmyHFGteAMl1w6bIuayKeroB84v/b6H6fUixM27F5IYnVtQWOaEL+DsiXH41f/p9xKXD
         K4Tmve3mBEgi58Y+abzy5UyxJNamPt9UmTAEIN4vaXcbRuRaGTlliWTT73d9Zt9LAuO4
         av+uajbaQ+70YB/7aBHX31cELug9uDcQeelW6YyTZOmoA74sdNpWd822uHD0lvYfhBmh
         UTOdvZOMOr+gVmYpzaN20kMPtSRAS/0B3KMZ/HAJUAhjoWzIIZ9+12DOYPKg533rcPze
         3xSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313fP87M2hjf1mbA5CAGJ9Ye+3y2TZubGxI8uM3CmIdRIRbfWDd
	jkSLC8Fus4fun2Ttuj7rtOQ=
X-Google-Smtp-Source: ABdhPJzgRgt0R732Luqn5cvPMscbPsV1kiGQ/lkOhN/sZ6VzXOJVkhgGmbXhYAXvfuIlR67OgKlrOQ==
X-Received: by 2002:a17:90b:4b48:: with SMTP id mi8mr8031050pjb.132.1633027849848;
        Thu, 30 Sep 2021 11:50:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:854:: with SMTP id q20ls2909444pfk.6.gmail; Thu, 30
 Sep 2021 11:50:49 -0700 (PDT)
X-Received: by 2002:a63:561a:: with SMTP id k26mr6305537pgb.144.1633027849257;
        Thu, 30 Sep 2021 11:50:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633027849; cv=none;
        d=google.com; s=arc-20160816;
        b=LHZgRCZHZ3yu+mboE9Ejse1200uqZr5YhvgIQfMUVh7t0iLimb1mYHIPWfFDI4nMFL
         Dea0ml0NeMKHAAEq4aMHPARib1th/ffuT5zSLniMB9m4XnbYlE/GT0C6/QP434aC4abD
         89vNTostaePiH4KZYgNvoM/nTu+ikKEBUJMccy4TVKFihcaqibU/g75EaPrwpcjhT8Mh
         CveMCeNyJ3xJaWZ4s8mG42qA6Ip/NZHkEDa+syK5g+qo1xBZ9LLMHqY9KguQ5zM1gglJ
         UxvGrVxEqzh4VRFG1aN/eOU8+RRuU2Ef54C9lMJsEa5AGzdOYA/DBIPGP23rEOSw7ZOM
         6M/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=50WKWg0QVg2XKrZsOyYgqolyS73RGVick6G3Z4q2Xag=;
        b=zEAwx77nkI6tS2esnjAh/FcLb18iNUznbeN2C6KiUBUo04fAFfaMpgQyG/MYWIRo59
         f1gG9/0/0rpGqUYmQzfOmcM5TgKYOhtpuRumJw2nGnJg87dWp9OV1rn3N+i1xv+An5O0
         1m10v1FsZhPuTnThGsE6pSD746zAjcqajKxN0v1eBQZuzDOUBHLs9QfN6G7dcbGKuxa+
         Cz+tgEjUDPDYTM4zC4rJ9ccjQo7oOi4vfnlJ5SiA43Gkn5ERtE97V5WpzHMLNPL7DZE7
         PIRol2AnSfynVfrWH4sEbUFeWL2oVBC86XTCfmFZvq2ur/aj7dG5kdsNMwhwIIQujZtM
         eB7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="s/nujFn9";
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v66si308525pfc.1.2021.09.30.11.50.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Sep 2021 11:50:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8637261350;
	Thu, 30 Sep 2021 18:50:42 +0000 (UTC)
From: Mike Rapoport <rppt@kernel.org>
To: linux-kernel@vger.kernel.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Juergen Gross <jgross@suse.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Mike Rapoport <rppt@kernel.org>,
	Mike Rapoport <rppt@linux.ibm.com>,
	Shahab Vahedi <Shahab.Vahedi@synopsys.com>,
	devicetree@vger.kernel.org,
	iommu@lists.linux-foundation.org,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	linux-alpha@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-efi@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-sh@vger.kernel.org,
	linux-snps-arc@lists.infradead.org,
	linux-um@lists.infradead.org,
	linux-usb@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	sparclinux@vger.kernel.org,
	xen-devel@lists.xenproject.org
Subject: [PATCH v2 1/6] arch_numa: simplify numa_distance allocation
Date: Thu, 30 Sep 2021 21:50:26 +0300
Message-Id: <20210930185031.18648-2-rppt@kernel.org>
X-Mailer: git-send-email 2.28.0
In-Reply-To: <20210930185031.18648-1-rppt@kernel.org>
References: <20210930185031.18648-1-rppt@kernel.org>
MIME-Version: 1.0
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="s/nujFn9";       spf=pass
 (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Mike Rapoport <rppt@linux.ibm.com>

Memory allocation of numa_distance uses memblock_phys_alloc_range() without
actual range limits, converts the returned physical address to virtual and
then only uses the virtual address for further initialization.

Simplify this by replacing memblock_phys_alloc_range() with
memblock_alloc().

Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>
---
 drivers/base/arch_numa.c | 6 ++----
 1 file changed, 2 insertions(+), 4 deletions(-)

diff --git a/drivers/base/arch_numa.c b/drivers/base/arch_numa.c
index 00fb4120a5b3..f6d0efd01188 100644
--- a/drivers/base/arch_numa.c
+++ b/drivers/base/arch_numa.c
@@ -275,15 +275,13 @@ void __init numa_free_distance(void)
 static int __init numa_alloc_distance(void)
 {
 	size_t size;
-	u64 phys;
 	int i, j;
 
 	size = nr_node_ids * nr_node_ids * sizeof(numa_distance[0]);
-	phys = memblock_phys_alloc_range(size, PAGE_SIZE, 0, PFN_PHYS(max_pfn));
-	if (WARN_ON(!phys))
+	numa_distance = memblock_alloc(size, PAGE_SIZE);
+	if (WARN_ON(!numa_distance))
 		return -ENOMEM;
 
-	numa_distance = __va(phys);
 	numa_distance_cnt = nr_node_ids;
 
 	/* fill with the default distances */
-- 
2.28.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210930185031.18648-2-rppt%40kernel.org.
