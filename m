Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBFMNW64AMGQEVCYE44A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D27699DB92
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:34:37 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2e295559c37sf3843820a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:34:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956053; cv=pass;
        d=google.com; s=arc-20240605;
        b=eDm9vADj5mVI/2HOuBq3Op3EMntDtDQ4kdVZ3mcmV23AzarEfQN3pyGTks4cdqVB0W
         iicyQwRVVONhFdOY8GPcP2EGnHp25VyBbVtCyY/SpScsti/ydTPmfuGBaLVYxae8Eh3y
         M48DxJ+FdRi/vvFUSg/MAm5JchnBryVU5y/MiLtialgiDsBl+fCbbyylhRlbsF99f+4w
         VO9REyo2RZAJrQHDFSdghK610uga95/RT01PyJs94MshvC8uJfbW9VuZyvv8xmrQIvE1
         Gx/LAnGbfWuZ3SlE8PjAr/8L3eeCuFbmLIBADVKlSpliVdDvDe4iBbkPdwIm3Mf5s8ES
         T/pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Qb9zogP/QSZSUo1F5GEf22NSq07nqzKxobZq3DA1jN8=;
        fh=eMeYVwilmF3tfRiwQ5qInwStTtxGlcY4tDpRq9mqQnI=;
        b=aTuQUUmY4SPFzTvKk/y9PAP8bnLklTjxlqVLU0XEhLKf77bKDq4T5yslGU3EtCa4C8
         9xRDWE3Fgw1RKzN83Jq2NaYf/vJCM+Naex0VdAzMN2cnPMvrolQJd71mMNwxB622RrjQ
         6mcOIu94Vh1XZMyemSddCDjgYM2YBjdiScMQfatsLlY0rAzNrQ8LxHpSWjEs26p0L5v/
         GK7449F6nRlUTfMhOwixGIS0swVB9/DD3tO3v9XxmjpwO+u5GjwsOfZySwsyu+aqBCgZ
         XT4NPPBlAVeCZXKDmmCRxCUZJMmofgFhVCY4VKymuGUgABXajkCu6jtPxc22ZyDz5YzA
         vSIg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Ue99L/U+";
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956053; x=1729560853; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Qb9zogP/QSZSUo1F5GEf22NSq07nqzKxobZq3DA1jN8=;
        b=N5FaqdmA97vIy547akLEm/e5kP1bAHjOuoSqQbKWYPl2aLyuceOLOteX5Dc1PpA1OE
         aHohtSdcvwEKw01ta7XH86Rl7Y2GmgUMjq7dMTm6N4oPCxC3ouXcFP0zXJAJAOqETJa8
         yBmVmHxOCToxvfB6VHJqVThWV4LK8izKRVqM84pA9HaehncJUYl8RZMzY4vTVy2mvdnT
         JyPYDlPTw1QHzVRlUIE7cVCCULl5sV0HBgCaN7MXcaANBCmDGuw/agcYvBemiZTl3TBR
         bR2a9lLC7H8BWirqgvPIkYXYdiG/HmRCxfMyHo1MwntkBMHIFLVSNJBmeJm+9IEWeEWF
         gy5Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956053; x=1729560853; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Qb9zogP/QSZSUo1F5GEf22NSq07nqzKxobZq3DA1jN8=;
        b=Q4rndfkpfqwF+DTwQ26oPIUZX5EMo8TyH4vpl6dkZpid8dQ6H3+amW9d+sF2kkHpzY
         If9pKT0pAXG7jfSZai4uf6NVRvgLxbZtkIkT7SDUE4QHiesI36dI4fm3g24LGb2ak7Zb
         3WTUq2wgltDNueakkf5wrvfwPv7FaUMdeLZCpkwZGggi5iPsiU/wW8LATYoAsMxeJkfa
         BsDfiBt4gXjKBItlDe2DVsykdy50Wx0LYEaRmI03OQmX+gn+KwbwK+Sq7oq6YKq7JYIt
         VXKrHNBUrqdt3eeOMDr9yDFFfrDdIdAmGHXeII/c3PwBUm1zH3y9m/RcKI86EafqjZd4
         Dw1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956053; x=1729560853;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Qb9zogP/QSZSUo1F5GEf22NSq07nqzKxobZq3DA1jN8=;
        b=SGE+2BhTzRrSDvQZD9Qx0sVUR8y6aDsU3geBuAvcHoIYZvQuiuV4rO6/rpLpMYOIrr
         Si8SllpGV3rBbNu0NADqCRVkH7ktb5XqLhc5/nfSUe5Z+Tky9hJLQnIO7hj7gUOTUg/L
         IyzQ3hLeGw9SAcNn49N7pAzHltEelCInA29gA4ICQvI0wCg7fiJ+ZWN8kbWdAShGh7Hs
         fC+lS5jQqlETNKZ7Q8iHXli/cQeddvfSSWczax1wnBAHMzQT8vkOS3usHp5BxAIB2x45
         lFBROKkS721JoPGczohZb1urHutcb+8MQvXaSmoyeSA7Fynf9iM5XgPyj04vY6e95Os8
         /ONw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVmznzrJCax5PSvnQokKFcJSy+J1X98Vn06CKA9a7Qo75Nsn1hkSFfDsyIbsugXg9G8A4K6Og==@lfdr.de
X-Gm-Message-State: AOJu0YyLletv9Q3Uc55IhKya8DCkDGLWS1x4VCJ4kqLyVGHtm8FtgLi5
	Zu1cpRKoJx8s93+R7NH2mbBtb30/+cR28f/KKqeUEGek6tbGcHGK
X-Google-Smtp-Source: AGHT+IFPvSBVc8nGguz5NmMIg4t6Iq9HSMhTIukH1RjdgxNAsrRx/WdLSuHbl3NcushZ0mL2hSQBfQ==
X-Received: by 2002:a17:90a:a00b:b0:2e2:ba35:356c with SMTP id 98e67ed59e1d1-2e2f0dc659emr15988138a91.39.1728956053175;
        Mon, 14 Oct 2024 18:34:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c291:b0:2e2:c774:2b42 with SMTP id
 98e67ed59e1d1-2e2c81bd3b9ls2001489a91.0.-pod-prod-09-us; Mon, 14 Oct 2024
 18:34:12 -0700 (PDT)
X-Received: by 2002:a17:90a:db8a:b0:2e2:d61d:60e6 with SMTP id 98e67ed59e1d1-2e2f0aa3dccmr16478067a91.17.1728956051854;
        Mon, 14 Oct 2024 18:34:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956051; cv=none;
        d=google.com; s=arc-20240605;
        b=YfMV6U28+W1a7mFBRESQxK+GUHX75SwI7gtIX0MbqWEgYrl+LKmNUKGn8aDJ7BrM22
         D375Mm9FQ0KNVt9j3U1mU335GWmd9BlXg55tvA2FPGEHHxal0rHX39YPW79M25a4xqm3
         IRcup7swkjyNIVOb1aveBbNI7iMi2N7bP5ycTczQUkZtu4k4nW7mWiUU9BwKy4hgIvMZ
         PPGF5ZjJBLOEZ72OTedjsqahkXd0iQgW2s5BC0FSFyVLJRJzTpKv4vHPg4V5bTDgSnKy
         qtbz/4GTeNF3GUa5BHcF4hP9X7VVDw4M5tx8E3qOsSxmrx9tl0BoooBPY+7lBH8LShs1
         3YzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=U+q0qzhvgy5Htf+jNoj0jpwh62QEw37SjQucvD3DcJc=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=RrmM63Rt7sTmfG15jS+JR//yvROar6TSiXbkraB3aHLIUtNqGGl+UeXnDS+BzTpdDl
         1suAxv608YJPX/a5/zaFO/iV67e5HHgJ4i5b6wdZRobfh6/lWQwBCyV55LOY54eZX+Em
         G3R6dmP05uaCUsR17shVW+INyoE5xl0W2XtU7a6JooJCaQFZcEkb5OGF82YRRWrS97Lo
         1Hv4CGUYpD4y6CRR4elSomvG/LLRwyLQb0b/T1xbvAaPOJ5qceaMWCMhRW+lX3aRHNHy
         gdvX6IJ/w8StEGAPhUmsPuoSRjokWAAR9G+LPdVyIRbjt61RRlRChmUxW/zCS0GlmIgf
         hmAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Ue99L/U+";
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e2c08ade3esi936531a91.1.2024.10.14.18.34.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:34:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id 41be03b00d2f7-7d4fa972cbeso3595508a12.2
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:34:11 -0700 (PDT)
X-Received: by 2002:a05:6a21:710a:b0:1cf:9a86:6cb7 with SMTP id adf61e73a8af0-1d8bcf2c37bmr19861897637.20.1728956051333;
        Mon, 14 Oct 2024 18:34:11 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.34.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:34:10 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC RESEND v2 05/13] book3s64/hash: Add hash_debug_pagealloc_add_slot() function
Date: Tue, 15 Oct 2024 07:03:28 +0530
Message-ID: <7fc9a78423fceda0bfd07f80583a7c9c0938e339.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1728954719.git.ritesh.list@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Ue99L/U+";       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::532
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

This adds hash_debug_pagealloc_add_slot() function instead of open
coding that in htab_bolt_mapping(). This is required since we will be
separating kfence functionality to not depend upon debug_pagealloc.

No functionality change in this patch.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 13 ++++++++++---
 1 file changed, 10 insertions(+), 3 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 82151fff9648..6e3860224351 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -328,6 +328,14 @@ static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long lmi)
 				     mmu_kernel_ssize, 0);
 }
 
+static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot)
+{
+	if (!debug_pagealloc_enabled())
+		return;
+	if ((paddr >> PAGE_SHIFT) < linear_map_hash_count)
+		linear_map_hash_slots[paddr >> PAGE_SHIFT] = slot | 0x80;
+}
+
 int hash__kernel_map_pages(struct page *page, int numpages, int enable)
 {
 	unsigned long flags, vaddr, lmi;
@@ -353,6 +361,7 @@ int hash__kernel_map_pages(struct page *page, int numpages,
 {
 	return 0;
 }
+static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot) {}
 #endif /* CONFIG_DEBUG_PAGEALLOC */
 
 /*
@@ -513,9 +522,7 @@ int htab_bolt_mapping(unsigned long vstart, unsigned long vend,
 			break;
 
 		cond_resched();
-		if (debug_pagealloc_enabled() &&
-			(paddr >> PAGE_SHIFT) < linear_map_hash_count)
-			linear_map_hash_slots[paddr >> PAGE_SHIFT] = ret | 0x80;
+		hash_debug_pagealloc_add_slot(paddr, ret);
 	}
 	return ret < 0 ? ret : 0;
 }
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7fc9a78423fceda0bfd07f80583a7c9c0938e339.1728954719.git.ritesh.list%40gmail.com.
