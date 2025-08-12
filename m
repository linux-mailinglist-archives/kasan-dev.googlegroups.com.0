Return-Path: <kasan-dev+bncBCKPFB7SXUERBLP25TCAMGQEFEL64ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id EFFE8B227D4
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:10:10 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id af79cd13be357-7e82b8ea647sf1140496085a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:10:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755004206; cv=pass;
        d=google.com; s=arc-20240605;
        b=SsIPqKn38sI9CY8VssWtC+0gQq6Nf48B7nsTpqN19FJPwTRyPeVIyIlEdQCAhylsgz
         JGtptGVNO9hVz3XJSvp28+sNmG/tSSwVusG+PT5FTE/GbfvmlEebcdKoglD5744681O4
         aCft6p1b6tAsFpFuBMPuuMiSILKAkC5Dtyz+V+YqRIxNcUNn9ASghkaeWWlWKbGC4Pip
         /x47wLta66XJ7y9IKVdNisfATske/jI+CtyiI/YfHq0kKt8u+sJy5wTRlClQ5iOrSf1F
         +Rls3yv+3c8Wkb2JN/Qi+vVUd+2KLoVRiej2sWlwjurvJw4f+YKtn0IxLJJ7i52B6JCN
         NG9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=xgINJa3hOQCho8kwLGaVlPrlfKmkNbvjjfnSS5Bklrg=;
        fh=kL+eKcLhVNMNgBJWnsAY6GzwjYv791kKIFxk//jFFKA=;
        b=Kt1KOA3i9akwnq1HUZgg4vQxRzLz6q+69cLT4EFvq66HLBWoY3hHR+CDckoWZad2xS
         e49MF2sOHzAqMCpPc6O/Qq3bTRB5ilNkbiQkGkI7B2dtIycw18krHw9jHXs1KxKKyxD0
         KtevvGa2m7pZhgJ3AH5h0I6bKsB40Pe2kiTAY3fqDvNjburgRJrh0rOwM4XncIfXL3NK
         sGxtfYERycGhT3XntuqCPeQ2Z26EQCxSMt7ao2OMt6alWgDnrUYbDkmJyazsJKzEW+tf
         HRP/90hX0QOI9XghiN7HA2F0woMYUgDj6zbRQgzGuvOLg14g7wxRm7QtSDoQ4Hh6rsmi
         zjPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f8Y9Q27W;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755004206; x=1755609006; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xgINJa3hOQCho8kwLGaVlPrlfKmkNbvjjfnSS5Bklrg=;
        b=DiWPUN4h+Dn8GTCSy6BYR/1HO79DSBEA5CXs2xpvu7vb0p7C8mwR7sE3DCtGhP0ps4
         KRU/iintNgiqm9CSjE+1kyWqOp3zlLOmAe/ASqY8OgXbMgtNb8VnIoCUV8Hjy2k9B+Nz
         MyuHevePhFJL3oXoD1XR4cn8yr6haPbwqQ1h7A1OBiX6muTzq5Hi6kcTtRslJvZxhUiH
         EWrJeg9kaxcnJ1Ux+OmcriH3DOOYK/+Nk2ZNJypa/8ONjuQZsUaVRh7kEVcucAt1B/mz
         LN1AePdU/9TuWdsm2YxUgrOaCjFYs1Wa4NF9NCp7nUGKOCLFM0U1zaOb+jd1WK3ixCxs
         oSug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755004206; x=1755609006;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xgINJa3hOQCho8kwLGaVlPrlfKmkNbvjjfnSS5Bklrg=;
        b=CYBjBTM5zLp0ggN+6Pfzoghdw9kQGsLVFv7efTOxhq8sowaDr8FtIUC041OpQF08b5
         r55QSD6t9+Gg+ew7x3etiqI/r0P+p9DbUqt/CL5Sqp9MK3ikVkdFp1qF9MEMijHjd/jx
         E6qKHJHWGBTRyHpB4euxbF+JF1AyvIPSJZWK3+7mzL8t9dMIWij/CTKCXXMJXbwaVoFN
         XeRyCNX49jgp6+LHs6OGSat2xUNyVD+On/3OcQMmHnaES53/IYNh577nwmCmYn1U6OTI
         CuU+jCcu+RxtYu3luVN7ZIlvPy9ESLhnpJjYLOa0YmrjSyvnSRToGP4QsOUX3QJFYlIA
         b7ZA==
X-Forwarded-Encrypted: i=2; AJvYcCWrvG8MBic2mIgmjfSB653qsdC0fuXowuMO44MxkjKC/AGOWVZk9a1YRGfVbqESDgt8XPRJdA==@lfdr.de
X-Gm-Message-State: AOJu0YwgTp+2bQ80LRuapTONnoE6Vm9HrBcKBpy45qFog7+QsPgB+CFX
	+TyjjhzYJ80rRLX95ZyHgD65cvmvt+Mo4mf2J75ZKgeZw7lHM0bIZX5c
X-Google-Smtp-Source: AGHT+IHhTKuSqNeEIHhsPaNAUKFJPkSXhg6enLVnXvF1e4eyPcYuS00PZXEmfmsKdaLGrYP3+edjcg==
X-Received: by 2002:a05:620a:2a0f:b0:7e8:1879:4bc6 with SMTP id af79cd13be357-7e858e617e5mr389650785a.24.1755004206022;
        Tue, 12 Aug 2025 06:10:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfjM+XAQBQLvCOvfoq4ZiYcggT9/dsaRvNeb7tp3ELt1A==
Received: by 2002:a05:6214:2585:b0:707:1f59:62a2 with SMTP id
 6a1803df08f44-709883baf8fls46897836d6.1.-pod-prod-00-us; Tue, 12 Aug 2025
 06:10:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWNf5miyRXaUTyr/FjlxGP9LgiCzDDO2K25NrVzoOTKVmvkJA6cWjuJMJxLKFtwShNXv+IFxjgP5H0=@googlegroups.com
X-Received: by 2002:ad4:5766:0:b0:707:4aae:9a06 with SMTP id 6a1803df08f44-709d69119a5mr48844486d6.19.1755004205014;
        Tue, 12 Aug 2025 06:10:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755004204; cv=none;
        d=google.com; s=arc-20240605;
        b=Bauo8U3lfb9HNMHOjQQ0g9XLi9z95FZ9YVNJOf+/XmyJzouazdulqA+4bTV8Cgz8b8
         L+mhyVDTYdD8Cf3V3nvMK/78ewdW7AIWvl4Rn+Wj97/u9Qk+YPschR4NksmJBgCsEJpr
         KPhUP6ZTzXRzKMDooiwgr+YB0JfnoUDpqDtS2IRDGeNPURfvJqou+4Y797poDF45edML
         zr3+PBjI1JklfhxeFR1ifJXnJXceiQTdLaXfNcPXBOjAxG51Rg3bLBsmTk3bdaHv8gv4
         eJHPxC9XJSMveR7bygKpzcrlkuY2WGhOhmDUQ0RoyblH/tFD9+t0pUgasS7NjA/FFL2K
         nFKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KrKPnao6QnTzTb2pG0ayBWIzuAufBFmMDXfM7PPaads=;
        fh=tJzQ5qxkJm0zG4QpcVmXzoBYu5DFFVue0Z3QtfeLqEI=;
        b=bVm0QzAtOqQ1GLLTzjZbpm3l8V6zcqkcPj+kYAb7JqTJGbmCEWD183GQloz5kmZBa1
         tdaqPPf20/vsR42qxQAw8mrPxe9grF8Wytj0GCP+1Du4kJCdKcCCCRJjA/kcP4pn93LT
         +keSQMPRbYDpXNeuO4ZrdWXsn+EjYHzNAqQMUBaB7zTipFaHQPoSULBSWH5Xf7gSCY/V
         FDctoNuZFng5iwDcZCXXePbdwRaxRMaeVHIGLib607yOkKkdELhYfszeFBs66+BFsCtu
         Cjmw99x9Lt1hSfPNCXMuPxV3tV9TNyuPLmwGq8AcG3MTuvaHkgY3+QT5fwBrjzetG/Ne
         lbZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f8Y9Q27W;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7077c3b7ba9si5627246d6.0.2025.08.12.06.10.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 06:10:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-81-ZtSTzWdEPtKWugn1Y9IMQQ-1; Tue,
 12 Aug 2025 09:10:00 -0400
X-MC-Unique: ZtSTzWdEPtKWugn1Y9IMQQ-1
X-Mimecast-MFC-AGG-ID: ZtSTzWdEPtKWugn1Y9IMQQ_1755004197
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id EF7B21800352;
	Tue, 12 Aug 2025 13:09:55 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id D4231195608F;
	Tue, 12 Aug 2025 13:09:45 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: snovitoll@gmail.com,
	ryabinin.a.a@gmail.com,
	christophe.leroy@csgroup.eu,
	hca@linux.ibm.com,
	andreyknvl@gmail.com,
	akpm@linux-foundation.org,
	chenhuacai@loongson.cn,
	davidgow@google.com,
	glider@google.com,
	dvyukov@google.com,
	alexghiti@rivosinc.com,
	kasan-dev@googlegroups.com,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-um@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	agordeev@linux.ibm.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH 1/4] arch/loongarch: remove kasan_arch_is_ready()
Date: Tue, 12 Aug 2025 21:09:30 +0800
Message-ID: <20250812130933.71593-2-bhe@redhat.com>
In-Reply-To: <20250812130933.71593-1-bhe@redhat.com>
References: <20250812130933.71593-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=f8Y9Q27W;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>

With the help of static key kasan_flag_enabled, kasan_arch_is_ready()
is not needed any more. So reomve the unneeded kasan_arch_is_ready() and
the relevant codes.

Here, move kasan_flag_enabled enabling before populating shadow of
liner mapping regions so that kasan_mem_to_shadow() can function well
just as the old variable 'kasan_early_stage' is located.

Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Signed-off-by: Baoquan He <bhe@redhat.com>
---
 arch/loongarch/include/asm/kasan.h |  7 -------
 arch/loongarch/mm/kasan_init.c     | 10 +++-------
 2 files changed, 3 insertions(+), 14 deletions(-)

diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/asm/kasan.h
index 62f139a9c87d..0e50e5b5e056 100644
--- a/arch/loongarch/include/asm/kasan.h
+++ b/arch/loongarch/include/asm/kasan.h
@@ -66,7 +66,6 @@
 #define XKPRANGE_WC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKPRANGE_WC_KASAN_OFFSET)
 #define XKVRANGE_VC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKVRANGE_VC_KASAN_OFFSET)
 
-extern bool kasan_early_stage;
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 
 #define kasan_mem_to_shadow kasan_mem_to_shadow
@@ -75,12 +74,6 @@ void *kasan_mem_to_shadow(const void *addr);
 #define kasan_shadow_to_mem kasan_shadow_to_mem
 const void *kasan_shadow_to_mem(const void *shadow_addr);
 
-#define kasan_arch_is_ready kasan_arch_is_ready
-static __always_inline bool kasan_arch_is_ready(void)
-{
-	return !kasan_early_stage;
-}
-
 #define addr_has_metadata addr_has_metadata
 static __always_inline bool addr_has_metadata(const void *addr)
 {
diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
index 0c32eee6910f..f156cba818e6 100644
--- a/arch/loongarch/mm/kasan_init.c
+++ b/arch/loongarch/mm/kasan_init.c
@@ -40,11 +40,9 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);
 #define __pte_none(early, pte) (early ? pte_none(pte) : \
 ((pte_val(pte) & _PFN_MASK) == (unsigned long)__pa(kasan_early_shadow_page)))
 
-bool kasan_early_stage = true;
-
 void *kasan_mem_to_shadow(const void *addr)
 {
-	if (!kasan_arch_is_ready()) {
+	if (!kasan_enabled()) {
 		return (void *)(kasan_early_shadow_page);
 	} else {
 		unsigned long maddr = (unsigned long)addr;
@@ -300,7 +298,8 @@ void __init kasan_init(void)
 	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
 					kasan_mem_to_shadow((void *)KFENCE_AREA_END));
 
-	kasan_early_stage = false;
+	/* Enable KASAN here before kasan_mem_to_shadow(). */
+	static_branch_enable(&kasan_flag_enabled);
 
 	/* Populate the linear mapping */
 	for_each_mem_range(i, &pa_start, &pa_end) {
@@ -329,9 +328,6 @@ void __init kasan_init(void)
 	csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PGDH);
 	local_flush_tlb_all();
 
-	/* KASAN is now initialized, enable it. */
-	static_branch_enable(&kasan_flag_enabled);
-
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
 	pr_info("KernelAddressSanitizer initialized.\n");
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812130933.71593-2-bhe%40redhat.com.
