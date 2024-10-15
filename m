Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBO4NW64AMGQELAGL6OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id A30E699DBA5
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:34:53 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-20c8a637b77sf65646045ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:34:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956092; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kv1g3gEuWucfacbCtApgamP0ESOFpzcZi/QKbBds7zTnUfW4fJoERLW+UlYkzLYXEc
         bjEDTWA+2Um7y0X+ioVdOE8W/pnon3fD4iUSBKsdQNsQL5jzZbUWDkRd3XqAczRYMq5E
         ANux4d+gEidfAnUT8ma0RR+yyGREigAORLVjQ5uFjEnyiXEuLRJkXjYSVDccGCHYpG2d
         E1VnyYsdHGWUS2Vjr2YaL4r6a5QPGI50PxooHAc63HpLCXlecVADOTTnidXsnEkpSrVn
         CPfYtk4+wXbIFIDUFr7EbmLE0rHWlgfWxqTR38fjEtGcig1j+Nfg9hpD5K8k6MnYqiDO
         tNWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=sHv5G1ACXmAt+nzkP1lOt2DjB1zer2RRKeINKPSttiM=;
        fh=imEehDqhHDcvMcsF8y1vfddsvRrVkzRVJqqsFvzOvaw=;
        b=JSBzcs0bR2/uMGvPPn1qAqXkFqR8mbIH+gv08PMI+glCc6bzjKmJGQvd+kQG4+G365
         /cGSM+cHpPmXPtNTNDhpd8DzTYTYWQgfpVy0TbHk2QVq0Ei2lw5NGqZ4XDzlSBEDPpJU
         XNqnxMpat+cZ6rLKI49bjYLfnxvNLcthQOvH+kYzIQZGz2ODQ7HwgrRFveoZx1sfCH+a
         NnDb3jm5VoM4R2/DM2WB6q3VfDA09XXWCtbaIfPahUzs5VNt0oTtqjlUFQ5b5x85+63j
         PoVDJ9tN64WZ8Witi1HtS1cP5mYtRAMvCp3i8LN/ENUB3YuAId0v2OBLwR2PS6BpG4EX
         z+Gg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HTop9ibh;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956092; x=1729560892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sHv5G1ACXmAt+nzkP1lOt2DjB1zer2RRKeINKPSttiM=;
        b=HuRZ2EEa5fixlqD6xhtb9IVzQZEN84KMgkfmrbjR+HT6rdw4d+lPAB2o6k5g8Ifn2o
         k/ZNGgSoZtZsdJ7Ou3y6astm1auJNuJrmMTpnkl3laqBSeoYPluHM9DYXqZaUyFIW+fE
         tozmnVSGVUEhihIrJ9I70VyKyegnVajIaS3H3t8zbjad3ONBE6+bUmWpVcBUB3Nud0On
         QUbVIasnVAqNmTqBXdLiWDtZVn3tujSKPERDEFTubPHJhP3wmm4jGKc27Csb4j2uS6lj
         Cb9ogUDuG4/nXLR7goYV81O9qyabSNgmn2OLzvpwyDz7r0yo/NDeWsaI+xkGTey1JvM1
         4ckw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956092; x=1729560892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=sHv5G1ACXmAt+nzkP1lOt2DjB1zer2RRKeINKPSttiM=;
        b=Ty40jVZRmT68Z0ahAY7YqnCu0RDBKjae/8qov1RePdb3whnHR4JSe3RMI+fe6Ecr4R
         72yHLSrZCkGKoNk6A2zjW0jvCmKIVf3yUsq6gOO/5+WsnCgFabwAYKxK+ueEpOOmS7zq
         LPjhMUmrZ44sJP9Az2ZJVVOMdqUXzObmAw8cp6p+SexDB27inKD0v4OS0fTwSmX6WDCp
         JuTLKmBiZaqwK3XA9RXFb/iv4q+qsCT/7dGdCrnQQzln3lWrp/xIa33UviLUaJvEndBm
         WH1tYZO7bIc5qHCVbadHneC2MOwhBoDx21iBNjeOL3E/aGO/iZ1jD0I0+GDHXjSKJ6tc
         6Ayg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956092; x=1729560892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sHv5G1ACXmAt+nzkP1lOt2DjB1zer2RRKeINKPSttiM=;
        b=fM3hUFf77Hp/P5fJLWcyxJM/PPF9gKIW152Irk2bLvdBK2RNENxiOErW1JraG0k/wN
         jBeHksyojk/c/L+xSAqzhY8CWgyDAF/9v+BWWtaE626jZaYwTB0ACYIJSdWyynwE8Tmd
         8n2INTO33OpFgQdBzlqYPlUUP8ADeM+LhWrzK6QP3hyyLSAW9FYhem5r/6ObYRa5T5t2
         SutNQqjwJ2hBsXF3/Jcz/h6TeKlvsus3sUlM5zWsn48u6Yol3lVGwbNZbr7VbWw0P99G
         TlAEPDeXq3sqvLNvPLRk5uofOkMpWIDfybXvVZk1L6gew84lN+tNZssOcM008rluSNoO
         IeLQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXQJoDDpL1aEXRUkUfgZ7l9kwt6Io3KjYJSvbYHD0HdaSkGjs64iRdYiUCYJKaGHbtG9Gt0wA==@lfdr.de
X-Gm-Message-State: AOJu0Yw4KuXxvsEBh2t9f2U9+MTh2xyfXE/kN1nq4O3ip0g6ejOtp9S/
	N9iXzXlSiI3ieHaDtaGhV+1pFb5zGVSZ6QWTpDaApamDU2hafT+j
X-Google-Smtp-Source: AGHT+IGYpruTrCkGMlExmp5wdqOHJD6/ZYEj6TS61kMulPX1mBEoTDzHPGD+GHt/mZd87P+9ygeBNA==
X-Received: by 2002:a17:902:fc50:b0:20c:ceb4:aa7f with SMTP id d9443c01a7336-20cceb4bd6emr125907265ad.11.1728956092094;
        Mon, 14 Oct 2024 18:34:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:440b:b0:1f2:eff5:fd69 with SMTP id
 d9443c01a7336-20c8069d4f1ls43486955ad.0.-pod-prod-08-us; Mon, 14 Oct 2024
 18:34:50 -0700 (PDT)
X-Received: by 2002:a17:903:11d1:b0:20c:95d9:25e6 with SMTP id d9443c01a7336-20ca16774a2mr202848755ad.34.1728956090611;
        Mon, 14 Oct 2024 18:34:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956090; cv=none;
        d=google.com; s=arc-20240605;
        b=WA8V++LD/BE0uHqMIQI6VCuS6/c7lIt6fTbqMP66V0GTdanLLDpYNyHjjtsFWvxMtu
         nlkuWUyH82gJuiA1asCGEZvF77fonQ8R0ZBz5NLCrEpHMBFPeE2kE7IT7D7jeN9CKj+o
         0K1ZvSjzcDcdeecEvW6H3g5YLRknE1a5LYXmNJMRrK8tzmkj2GSA/hvHSqMMaj17ridM
         NDnIVqbikR2bYvhTi0T6ecgSFTfAkr5wIYzYM6WmY4rwmKn+AtNQG9cm++gwaxvVc9Li
         YwbqC5C5VbyRgHMbURudKAG7FVRR+ZVMa6PiQ79QceCNaaP/Gb9l8Vk/xPqt/Sxpa4Kb
         dzkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rG0rlJ7RpNnGy840avhtCY+OIP6FbV4qxEoUkbOoVC0=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=jUIvDyRStCkbBpKgya4qOpye3sSljB9daoSU80oxanNoFCwEgMy+GpnE29Kd4TfbAS
         jRoF5Sz4eUCI4nbveM169sxuz0S3Kc4fV67dRCSFEzbIrWkA1Dc6Arau/SON8zbLcOap
         a2kOS07RysUfCpYTyj/gRlBdlEM3epZKsCxyPHB9oZ8vKaFZKyZ+QJKmd76MBUkigiTJ
         dcLXgBWHd6hx+S4Rk+cD/qnVmDepHE2a5ZVXwS6xYuCAwSk9aQo/H9R4ofB7slA5tPw4
         /6gR5QKzlFGZcyP5VPhPu/pETfNsdgWrcuWxZoGbxg/mY8DMO3vG+6mBkLl/2Fj6IO7O
         MNTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HTop9ibh;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20d180b7afasi130495ad.12.2024.10.14.18.34.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:34:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id d2e1a72fcca58-71e483c83dbso2992966b3a.3
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:34:50 -0700 (PDT)
X-Received: by 2002:a05:6a00:1404:b0:71e:5033:c5 with SMTP id d2e1a72fcca58-71e50330377mr13492824b3a.14.1728956090001;
        Mon, 14 Oct 2024 18:34:50 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.34.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:34:49 -0700 (PDT)
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
Subject: [RFC RESEND v2 13/13] book3s64/hash: Early detect debug_pagealloc size requirement
Date: Tue, 15 Oct 2024 07:03:36 +0530
Message-ID: <6b5deb16494e80703577e20fbb150789c83076a9.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1728954719.git.ritesh.list@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HTop9ibh;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::434
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

Add hash_supports_debug_pagealloc() helper to detect whether
debug_pagealloc can be supported on hash or not. This checks for both,
whether debug_pagealloc config is enabled and the linear map should
fit within rma_size/4 region size.

This can then be used early during htab_init_page_sizes() to decide
linear map pagesize if hash supports either debug_pagealloc or
kfence.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 25 +++++++++++++------------
 1 file changed, 13 insertions(+), 12 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index b6da25719e37..3ffc98b3deb1 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -329,25 +329,26 @@ static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long idx,
 }
 #endif
 
+static inline bool hash_supports_debug_pagealloc(void)
+{
+	unsigned long max_hash_count = ppc64_rma_size / 4;
+	unsigned long linear_map_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
+
+	if (!debug_pagealloc_enabled() || linear_map_count > max_hash_count)
+		return false;
+	return true;
+}
+
 #ifdef CONFIG_DEBUG_PAGEALLOC
 static u8 *linear_map_hash_slots;
 static unsigned long linear_map_hash_count;
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
 static void hash_debug_pagealloc_alloc_slots(void)
 {
-	unsigned long max_hash_count = ppc64_rma_size / 4;
-
-	if (!debug_pagealloc_enabled())
-		return;
-	linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
-	if (unlikely(linear_map_hash_count > max_hash_count)) {
-		pr_info("linear map size (%llu) greater than 4 times RMA region (%llu). Disabling debug_pagealloc\n",
-			((u64)linear_map_hash_count << PAGE_SHIFT),
-			ppc64_rma_size);
-		linear_map_hash_count = 0;
+	if (!hash_supports_debug_pagealloc())
 		return;
-	}
 
+	linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
 	linear_map_hash_slots = memblock_alloc_try_nid(
 			linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
 			ppc64_rma_size,	NUMA_NO_NODE);
@@ -1076,7 +1077,7 @@ static void __init htab_init_page_sizes(void)
 	bool aligned = true;
 	init_hpte_page_sizes();
 
-	if (!debug_pagealloc_enabled() && !kfence_early_init_enabled()) {
+	if (!hash_supports_debug_pagealloc() && !kfence_early_init_enabled()) {
 		/*
 		 * Pick a size for the linear mapping. Currently, we only
 		 * support 16M, 1M and 4K which is the default
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6b5deb16494e80703577e20fbb150789c83076a9.1728954719.git.ritesh.list%40gmail.com.
