Return-Path: <kasan-dev+bncBC447XVYUEMRB5NJ3WAQMGQELBSHNPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 05F1A324B5E
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 08:42:46 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id ch30sf2229439edb.14
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Feb 2021 23:42:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614238965; cv=pass;
        d=google.com; s=arc-20160816;
        b=aUpX6u+p8Rjwa7LMOuiv9V42lb8/74IL2UJIZ0x1UPvxCnEE61ECt7IRuHwTu5qv0J
         bWsCRf5iEYq2qRIyF5GhdjEpEjWg+Sy3FtVYnJCTgVspSfgGas5cTFBkJOnz7YZl1AcQ
         nTGl0KImqhombnuYHv89hx1y40Z+8fWKnY9Rq8kLEmNR3m5wzA/6WozkBnLCt7daEZJQ
         WtBSnHpoQFp6jLIfNnfriOUGLU7VILEcayEHJrZIrfCuKmfQh/e+HzWKRbHNRkQ3luQB
         Y4YltMcPL/aslbBInjVgeOx7aCyjmXT/y2YyPawbaUxNbbfz9ejbiTPxJevl5sYR8/HJ
         r8Iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=XinY/iQiCpZwkxBGWwEG2YOPP9anA+3FSxFHYjYce/8=;
        b=L67hKO32naTr8LxEh3Ti+PfPwha0pEfKoJRJWwgVssAnjfPEhlIff64erla9E7Rln1
         Tb0dlbxB2YmhuRHFSOJxAAsqw+I38WqZb7ORT2WzVgY0LJBq7V1325ZI2wqeZfnL57CJ
         iO7A1KgAWIE/J8/PS4VMImCR3B2g5kEko8jHHoRVXTG7OxKYXyL+n6+MfHeUFMUfSZn5
         2PxQ1Hn/IEDkJZxyfKDVCv0Bs9puHUK2Zt9MuBR2iskVRUl4TXtYaxEAnMZKgul/9qZU
         OJhRmv6dLHkOhKvH6aDMIB6AjX6p8Wo+hHoL02cT5sGSuTafdBkRI0ZQtWr4xhjB4CAC
         QJkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XinY/iQiCpZwkxBGWwEG2YOPP9anA+3FSxFHYjYce/8=;
        b=g/if6dchmBkR3nDVhL0+5+bT7jEivOE6u4abjrH/EtlaTdGYAAPwXHPitOh5W2WMpN
         lRVfod1CHZcFPU116oHoD0TcQL/v0IKRUfxCYcQZJE3CnQDZeECATssIySvfy9AEjFlK
         nUgPOwFXpOB68EmiFDd/nbMXtJaEgjz8x+cxxZ6rvBUH333kzIONNBAAEw8E4p36KOik
         ZWffe3Sq8JkGKiZyxBYdcqEV/Mi2n82iFO0OFwXHklO+7l11ssaMqVUFWncGB6VRwIQE
         AWaZHTXTiO8vUKLnJUc3fIGILELu0li0wo29bseUEoDD5j7i3MXnqSd9qFTxTyLiTopC
         UxVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XinY/iQiCpZwkxBGWwEG2YOPP9anA+3FSxFHYjYce/8=;
        b=aTVRcaJ1T9UUB0JxLYUVXal3AE+IwTr8DRKGGFTsPgH4dbI1HRMsTA3KDUPilrzykt
         JBLl/zirD2+uqA/Nf1D5F9jknLHkjM0feUSgHZzopmXHyDQSjhlhQuVfqrsImu9KbC9S
         qRnAUu2ES+e42bC0EdHNR4XZjIC06nyLrwzXZHIHHoeQ49vF/CZ2CeCeBMEu+FaQQozq
         v2iKvyJmAwwo1ZbwDZ/A0GyBepNzKOvAboFmfe10SmeiuSXoqjn3ntiQ6WfMQtp+zV/o
         5hxmg7LEM31Ss3QGytxnVGMLL8k3Fhit8oLbewRAFKhSAPIucP5EpBj5vema9SiRcsGv
         MMag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Qlu8pRcCLsP0DLYlQs+fgThMp+pps9NAcGLdILdYVk0Urk4oC
	ll17o68oEIV+luAu4wjRGpc=
X-Google-Smtp-Source: ABdhPJzyBspkOoBOfui9FrPBHEpnIyDpPI98xuk99+TAzEjJcXkx9xEJBEf6i64QiRhEnzcE/dkK7w==
X-Received: by 2002:aa7:c80a:: with SMTP id a10mr1601821edt.380.1614238965794;
        Wed, 24 Feb 2021 23:42:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c192:: with SMTP id g18ls2254217ejz.10.gmail; Wed,
 24 Feb 2021 23:42:44 -0800 (PST)
X-Received: by 2002:a17:906:a1c2:: with SMTP id bx2mr1507160ejb.138.1614238964896;
        Wed, 24 Feb 2021 23:42:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614238964; cv=none;
        d=google.com; s=arc-20160816;
        b=xXujiCwl7FHGgXfyXg9ccUJ1ZEFRr0BzdENMBpJ6Hp5ed/IrH2w9M7mOJO+sQK6Hzo
         F12PfzO8MVEImo3Eqn/U3VvGVgkOV34XoBPnrfvlHRPMeVd/kQsxFj02FDOXUV65EZcL
         azpuKm2vdXCBNOYyfUWH1jyRXvStJIBWanLlvQK1IabFbiVLqTfVCwCj6KdBXBIdzVqH
         010a2LyH6Ty32Fen3wQ9BmjwIGLyXf3RGqAJ2GG9P33G+Yk6SpJfJCBzJTt2rTKgQmoc
         1KoQnFuIC3Ll6Nq8BGByAr6WCLHubuMKabfvEj8X/mjX9r2Bmpfk+HLS18jgnXUK4JTG
         UWlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=WtLdaRsQDtf5KNwEcl19eocGURxt4ezGs033OQAILNY=;
        b=K1P8WStvuqsILI8ce456t622CFvgcTfTCIvGDar4WS6Mz2I0zAhxpPXB9Ur/HsbfXp
         oFfmRVnfayA/EYNpNtnFkNychEAe5ckXMmaC0XW4HkUapPMs6BudWboc4ODd6x4AYXvj
         nvq6VsZUzINR/LpcJnU2Jm1AC5dQ5LfUtVE5WFYveTSSx7julSU6GRK7QFiv7Q7nyiUv
         AnjbYx0lRzoOtXk4PpCfgmpPRyYJK4NGxHFa2RRkNAuymCdY9Zdcsr93F039toNIsPRz
         Z1oWIGPFskcuUE0YFILv0xiGrnXzdNxU3eFwY+OTUXrgWxL5IpnGA7rhH7GlPYGk1Z3g
         puDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay7-d.mail.gandi.net (relay7-d.mail.gandi.net. [217.70.183.200])
        by gmr-mx.google.com with ESMTPS id w12si168211edj.2.2021.02.24.23.42.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 24 Feb 2021 23:42:44 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.200;
X-Originating-IP: 81.185.161.35
Received: from localhost.localdomain (35.161.185.81.rev.sfr.net [81.185.161.35])
	(Authenticated sender: alex@ghiti.fr)
	by relay7-d.mail.gandi.net (Postfix) with ESMTPSA id 5FF4F20003;
	Thu, 25 Feb 2021 07:42:39 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Nylon Chen <nylon7@andestech.com>,
	Nick Hu <nickhu@andestech.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH] riscv: Add KASAN_VMALLOC support
Date: Thu, 25 Feb 2021 02:42:27 -0500
Message-Id: <20210225074227.3176-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.200 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Populate the top-level of the kernel page table to implement KASAN_VMALLOC,
lower levels are filled dynamically upon memory allocation at runtime.

Co-developed-by: Nylon Chen <nylon7@andestech.com>
Signed-off-by: Nylon Chen <nylon7@andestech.com>
Co-developed-by: Nick Hu <nickhu@andestech.com>
Signed-off-by: Nick Hu <nickhu@andestech.com>
Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
---
 arch/riscv/Kconfig         |  1 +
 arch/riscv/mm/kasan_init.c | 35 ++++++++++++++++++++++++++++++++++-
 2 files changed, 35 insertions(+), 1 deletion(-)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 8eadd1cbd524..3832a537c5d6 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -57,6 +57,7 @@ config RISCV
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if MMU && 64BIT
+	select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_KGDB_QXFER_PKT
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 719b6e4d6075..171569df4334 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -142,6 +142,31 @@ static void __init kasan_populate(void *start, void *end)
 	memset(start, KASAN_SHADOW_INIT, end - start);
 }
 
+void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned long end)
+{
+	unsigned long next;
+	void *p;
+	pgd_t *pgd_k = pgd_offset_k(vaddr);
+
+	do {
+		next = pgd_addr_end(vaddr, end);
+		if (pgd_page_vaddr(*pgd_k) == (unsigned long)lm_alias(kasan_early_shadow_pmd)) {
+			p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
+			set_pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
+		}
+	} while (pgd_k++, vaddr = next, vaddr != end);
+}
+
+void __init kasan_shallow_populate(void *start, void *end)
+{
+	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
+	unsigned long vend = PAGE_ALIGN((unsigned long)end);
+
+	kasan_shallow_populate_pgd(vaddr, vend);
+
+	local_flush_tlb_all();
+}
+
 void __init kasan_init(void)
 {
 	phys_addr_t _start, _end;
@@ -149,7 +174,15 @@ void __init kasan_init(void)
 
 	kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
 				    (void *)kasan_mem_to_shadow((void *)
-								VMALLOC_END));
+								VMEMMAP_END));
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		kasan_shallow_populate(
+			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
+			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
+	else
+		kasan_populate_early_shadow(
+			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
+			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
 
 	for_each_mem_range(i, &_start, &_end) {
 		void *start = (void *)_start;
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210225074227.3176-1-alex%40ghiti.fr.
