Return-Path: <kasan-dev+bncBDS6NZUJ6ILRB6FFV23QMGQEN6X7O4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 115B697C2ED
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:56:58 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id ca18e2360f4ac-82ced069d94sf73908939f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:56:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714616; cv=pass;
        d=google.com; s=arc-20240605;
        b=BI+zh33Nk3eJjaDOOAYGOg463E3tGgPffsMhNqLNCvTKqHoaCR4XUh92ZJtcOo8rlj
         HXNYooHjrfaqVXCdS2kgPCWsSDq+jdGexp97z/Y7Fooyc5jvuetR5uuOajCjLQEUCLBm
         A4vPunDEpasdpE2SgmXGAo1W3WSYdiH6/JFsnwm33G3/ja/X/+OtGhfsycEQnNYXudSQ
         KMX4ukuivcLPvm8rWsDH5qs8YAnPVFeKfQCwBryUddWDboEkxW+ARjCunv1XDIg+f1xC
         wFH6jeV7JnhJMt6q0JlXchWUMZaBmhy9KwDcm0vpVUWQ5GsPZv79aO3fCD+gFkV4PzOM
         fZGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=voFyK/FrIfGaq7/elTcevJr6uBafy24C2jFfTtZ0GZY=;
        fh=7FF7LxHMbiMOd570sUm6nQQbuMw9iUt9KRD614Q0rXw=;
        b=huOjRK8to5jW/kl55FsMeJjfapV76/r4xrOlkjzZPif+UDPFvKtPSg21mmS2F0X/+e
         dkBnkZQb3dfP0C3RLn4l0HfDJcYBRaHN4ht35th++wp2KvzcRTznD4QcsQcWDygjoSr0
         FC8mc6kjqx3XxZlpDJvYuVxmoT1MKN8Lo8AekmrUV3eesdsrqssx4UASs3rHgq3yiToa
         8zAHOJ7unAGLHTSCrSMRLYW8YLAAv+YkprXhY5ncTFx2f4J8MWK4Mnmcih6ri9qN0taN
         kmqoy0bGbaGof9wfXYYVfytJKSpEqmxnCclruewwFy4/2Al+GAfCPsCG5cmGwzhqBR8N
         r4bw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hPq4kiml;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714616; x=1727319416; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=voFyK/FrIfGaq7/elTcevJr6uBafy24C2jFfTtZ0GZY=;
        b=nsDDmCo9KwzyhFNRNPJZpZf4b8pJVFBWG7axJIA+StTT6+kW3XuAk3F6tzIXwbysfo
         a7un5AIm9Kf0Lj4bCl8cr3Dszf6BswKYRK84xyI6TE0Q2G7SL4uxLuva4BjMvXzm4Kpc
         IOZzAuI6CCUwGSvrQG3DJicfU7r6yBTXTCNFU9fmwtpQaVtvoQTJy4lqAlCxhCVtrMk0
         SmXnvDXxuE/O4axU8/7VmxH1/wSws35f/i4NgAZ6YkmxGZ4jhHi3/kSzijA3FkMFH6qY
         z+ac8a2ZaQ1ndVsIUn8gJfHgEGJ5M8nLi16ea57GNGdwas9cSiXKQ5YplZNMTBNsZXJH
         RakQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714616; x=1727319416; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=voFyK/FrIfGaq7/elTcevJr6uBafy24C2jFfTtZ0GZY=;
        b=F24f47DPAh5k0Oj/6MF29do7Ze1nXa/zmvVReq7PSwW2v5wwpzAV5r+STQuHPluOta
         bZ3ga/5pZ5fGOzArZkXTE0qDUWfHy4TrCc29qTzwP2Az8pVJMqrLyEQrvPBbqmcAZ3wq
         y9M5AMTozuAvDbHOzJySITuRTzxwQK5wJTZgcY0B7KFPkEJZ765McI52QP2Ub+xPqKGE
         ngCfyFAjgw6NHP2dk+yAJJ9xvHaKBBsAqbT+Xm/tKAaDlaA8JqZm6ZTMqqIu4FQbrLzz
         85igdJfwNQSxKrELFQ8plSkjUmbi2g0e0OxjMgRrdRP40+8nd3MXCCzEnxaSXiNfpPc2
         D1sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714616; x=1727319416;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=voFyK/FrIfGaq7/elTcevJr6uBafy24C2jFfTtZ0GZY=;
        b=kzB487fVyfdET7ZTp+eGbRDXidyY0fDSE6b5zZXVNthw4rpFaozHEaZ3Fq1X9sCUBw
         K+rNI076JVYhXVUV05TmlBHU9X5yL2DfjFi3BnlaaLDSXDIV/z3Kwhmx2ODK5Lq+B/UN
         qmw4Q7WXoyNEWezqTUvyaHkVvspUI4QmKLvdSqHw8hnvM2yxrWOYsD0vzJ+NpRzlnfOI
         6FGB4vDJRjUBanlzht6fB52VmayQQ98KkNnxcnzszQmmSAyDZMfse4iKLs6NATy9FHpA
         q1GU93zLTLNZNaxiAB08Y3cCpoy5m3imsksXLyHA22vBL3fFQesdPtCTC4WYSwqipisZ
         a9AQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV0hhgFkLkKoR62eUOezyKrp0HNksJKtbow9JTxCFwvXdNQSF5RgG9ci5AgaoCzENQ+wYSv1A==@lfdr.de
X-Gm-Message-State: AOJu0YzPrigU7xF0rxmk9XzbCFfD+PTSEat6stCzQPpw5anAxRE+miaR
	vOifkijdNqMhkjJKDN+s2iPJ/jEnfrKt92RA/N+iXfj6dQ5wiJLE
X-Google-Smtp-Source: AGHT+IERjTwadBazRX2aeWtvMMZq9dCy+AOlVrlcuacHPUN5750bTULfr7T6wUqAf9iie9pznFLFbQ==
X-Received: by 2002:a05:6e02:1fc2:b0:3a0:5642:c78 with SMTP id e9e14a558f8ab-3a08491ddcbmr225405895ab.15.1726714616349;
        Wed, 18 Sep 2024 19:56:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:156d:b0:3a0:9043:59b0 with SMTP id
 e9e14a558f8ab-3a0bf13cdc6ls3411445ab.1.-pod-prod-01-us; Wed, 18 Sep 2024
 19:56:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU8sh/8MiSQa/3ROz3nQ6bMz6cUib+u2KWY8rpOmvm0f1/F1uUVhe2x1VYTQQt1BerQKqZkXo5pBJE=@googlegroups.com
X-Received: by 2002:a05:6602:2c81:b0:82c:f05f:6c7a with SMTP id ca18e2360f4ac-82d1f80a692mr2714444539f.0.1726714615485;
        Wed, 18 Sep 2024 19:56:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714615; cv=none;
        d=google.com; s=arc-20240605;
        b=Y8RBHB3QoMOjoyyQHqJEIO9jyHZp7M34B5mjBYtd3N0w8VGN78hq3ERLNDVFeeWfGy
         JIKaCXkDeYLzqLmR68gssrsNTmFxQfX9hN3HmzK2XHXSzAjhM/+JYsXxnFGX14ckvz0m
         XHkv/myvIhft0egktaRJDMqt5QjrXA2wRvBlbNP0LrFY2jxgpAzw6JMrzByKDcmWEdLa
         Hiqaq5+o3ll5BlGVkeQNI3Z8GrnxO3csNzjMfqdh+SFUeFCGvo0Uft5E2ejG2cTwZCKu
         fzo88T34BVSJwqF057o47psfy1xoPwMm8npHhXKF5ZwHBLVpZaRZOGpnd87SYsi98B8t
         jAhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/MHsxmP9bN1bxx4msR28qZ2la9zK0wSY8EDrce3K+zQ=;
        fh=ooYiF4pcnoe5r2kL9+n1ADwQ+zwnDT3NGB93xp8v/G0=;
        b=idG9zLStXv31mS0ok7nIMnCKNllSBRoxbheTG8jSZ9CsfWJxOFuraFCbN4l5oa11hX
         CDvzcMnuGONg5os1lilbUR0EdGL5uu/uFa0tNj72Ak3fjwzS684YlHl2gq4AAdUBe6nq
         aOGASMuTbEuTi7MyQ7FgeheplTX3CjEc0AQWIpPPbtt2GSL+aCNjmVqAOpdpGs93qEu/
         c5IUdPptm+iucIvWjwOcWNWHVcDPI1PITitZNQgRGwlolzrGdu94/D2xDYpyN6OCCR3W
         V/Z9vz0Vka8PFfKBf2Sx+lE9ptKRwP0EJrxMDt1CM659ryynoqQGhCEsTBzaRYl9UFmQ
         Hb8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hPq4kiml;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-82d4935ecd7si42097039f.4.2024.09.18.19.56.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:56:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-2068acc8b98so4135195ad.3
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:56:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWT/Jzmf7Rv1xrGnOCX0nem3fcRHVF07EO5FRtDPhbEtQlYjjO2iCT8oqYqMcF5WvtcKGDOl2vTqlQ=@googlegroups.com
X-Received: by 2002:a17:902:f70c:b0:206:8acc:8871 with SMTP id d9443c01a7336-2076e39c331mr311700805ad.31.1726714614667;
        Wed, 18 Sep 2024 19:56:54 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.56.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:56:54 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	Nirjhar Roy <nirjhar@linux.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC v2 06/13] book3s64/hash: Add hash_debug_pagealloc_alloc_slots() function
Date: Thu, 19 Sep 2024 08:26:04 +0530
Message-ID: <47af6bef68ce0a82da4694174f004d11519e8757.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1726571179.git.ritesh.list@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hPq4kiml;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636
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

This adds hash_debug_pagealloc_alloc_slots() function instead of open
coding that in htab_initialize(). This is required since we will be
separating the kfence functionality to not depend upon debug_pagealloc.

Now that everything required for debug_pagealloc is under a #ifdef
config. Bring in linear_map_hash_slots and linear_map_hash_count
variables under the same config too.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 29 ++++++++++++++++-----------
 1 file changed, 17 insertions(+), 12 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 6e3860224351..030c120d1399 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -123,8 +123,6 @@ EXPORT_SYMBOL_GPL(mmu_slb_size);
 #ifdef CONFIG_PPC_64K_PAGES
 int mmu_ci_restrictions;
 #endif
-static u8 *linear_map_hash_slots;
-static unsigned long linear_map_hash_count;
 struct mmu_hash_ops mmu_hash_ops __ro_after_init;
 EXPORT_SYMBOL(mmu_hash_ops);
 
@@ -274,6 +272,8 @@ void hash__tlbiel_all(unsigned int action)
 }
 
 #ifdef CONFIG_DEBUG_PAGEALLOC
+static u8 *linear_map_hash_slots;
+static unsigned long linear_map_hash_count;
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
 
 static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
@@ -328,6 +328,19 @@ static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long lmi)
 				     mmu_kernel_ssize, 0);
 }
 
+static inline void hash_debug_pagealloc_alloc_slots(void)
+{
+	if (!debug_pagealloc_enabled())
+		return;
+	linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
+	linear_map_hash_slots = memblock_alloc_try_nid(
+			linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
+			ppc64_rma_size,	NUMA_NO_NODE);
+	if (!linear_map_hash_slots)
+		panic("%s: Failed to allocate %lu bytes max_addr=%pa\n",
+		      __func__, linear_map_hash_count, &ppc64_rma_size);
+}
+
 static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot)
 {
 	if (!debug_pagealloc_enabled())
@@ -361,6 +374,7 @@ int hash__kernel_map_pages(struct page *page, int numpages,
 {
 	return 0;
 }
+static inline void hash_debug_pagealloc_alloc_slots(void) {}
 static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot) {}
 #endif /* CONFIG_DEBUG_PAGEALLOC */
 
@@ -1223,16 +1237,7 @@ static void __init htab_initialize(void)
 
 	prot = pgprot_val(PAGE_KERNEL);
 
-	if (debug_pagealloc_enabled()) {
-		linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
-		linear_map_hash_slots = memblock_alloc_try_nid(
-				linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
-				ppc64_rma_size,	NUMA_NO_NODE);
-		if (!linear_map_hash_slots)
-			panic("%s: Failed to allocate %lu bytes max_addr=%pa\n",
-			      __func__, linear_map_hash_count, &ppc64_rma_size);
-	}
-
+	hash_debug_pagealloc_alloc_slots();
 	/* create bolted the linear mapping in the hash table */
 	for_each_mem_range(i, &base, &end) {
 		size = end - base;
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/47af6bef68ce0a82da4694174f004d11519e8757.1726571179.git.ritesh.list%40gmail.com.
