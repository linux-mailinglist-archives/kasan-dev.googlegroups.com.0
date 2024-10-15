Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBI4NW64AMGQEOWX3HZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0175F99DB97
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:34:38 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-3e5d8cf7088sf1594772b6e.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:34:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956067; cv=pass;
        d=google.com; s=arc-20240605;
        b=eVRRs07WMQxLRu22v48gw9zPEZi4NSBFm3CTJzANuV7FbPoE8LYn/umtDmLpPSsXy8
         eg/+pVaXhv8NM2LGlVcozs28q3g2d1+UoVoChM5C3jj4Z1pCqjKIoK76blTfPTfi3BVi
         VYbYRIvacRsY6M2E0I0ZE6/1E8Vxb1TRtWUWZ3EhzW2h04nkbRcPmjuXlZS/kng9qAFE
         mzevBQn7wFNdetTa96/KR5IGjYbjj8VlyNL49aM6xpHbuPfoOSclsAqKYcEhHtXh7MFk
         7X96GaBtuOuLZsHAwpey9gTctMM9FRE7OuZSWD7Y+fYkPJQJ/ynA1mDsbDdCa0PdKAGY
         BKhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=K/1FbNbj8xMG8ujcYcdr30sXvR9sVWOlYF4SHhQ8pmc=;
        fh=6NJ3F+qO+KPirHh8o4esGOivu7T8jHJGjNYu+reqgyw=;
        b=OMXTS2Hg6YR+rvH23loEQ0Hdc1MDn9jPIA6xLmpulbAlqe84XNaDlfwGmmej0iMIg8
         T4bzw+Rn22W5k9y6LfYxj30L7CZbRkyuZmTBuzppIRHGodI7hDx2h2oRNQ+3/Owm7Wu7
         8NCZmufN9i0o1qM5c0ikiUnoTrDTeD0hLn8Yg/5eC0Mt8msH9bFGqf5UpqgU5t+0F+VN
         l5VNinS+yXbwLJiODQyw0aS6wG4t6HgK53S0AFfRkdDvbaS8fQIex7T0BEItgxY2zwNV
         fmpfTPUwDFjRKm0J8wjJzVR7ae/sbYV7M9zvVd+SC0EuowIkK8XBolb4SHxt5xwOG1Fb
         sqRw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ISIFPGCD;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956067; x=1729560867; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K/1FbNbj8xMG8ujcYcdr30sXvR9sVWOlYF4SHhQ8pmc=;
        b=moBaupl3vDLQKhN88LnhdVTj1cY9NMZkm1C8XP6KwFZAMm8wKahUM7PW4EPD8HQhPL
         9R/9aM9hjRCTdWj9wxyz15HC28Eo5wmDleJtWBVmWuIfE8MHBOhxpCBFhyV/wfl15fCU
         199Vj4AeOWhnATnuYrtB8rG2Zf9LFIzs1ImN5oYEJanTVXoyvVmN5HM5n0Hs4nmglZ8L
         o7Gg5ibBLwQOwYyf+XDhVSL48U2ojUjTQIjaGgWy0DkY3Ei3xzI3drCjxvvTGVmJDQr1
         J4ZfJNDWT2D7mTYgfmZuck61AS9ty6ZhyNaXCOLzS+MtPDf7/aeko9adm0phrklXI9Ro
         GwJg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956067; x=1729560867; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=K/1FbNbj8xMG8ujcYcdr30sXvR9sVWOlYF4SHhQ8pmc=;
        b=UGiAGalXCEEUbvlORD2s6Gn+LSde/ii7ibUTZwdtI3rh7nSiHyhyjdRot8tGVYL8Ir
         cmqq8rJGCg6Npio5dFRCcHXTKPh7OcAcINc6EgZjISSfjwsBUER0JrtrOS7EhkeCMvFN
         gQhamFAXZPSdPEI3xk2L83M264huqMemNRR5+BKx7CZh8U4TOzz4WvjqajVE2rhunul2
         BK91J8LgJOqoMH657FPVLI+ZQc8S5n78TCxS9kLooQElYDgf1rXdm5lc1aJpSsX62qkh
         K5OT8axXm5hUUGFsyyOmpxZ8D4RWw6xsZBios+AURxIJs/hPi4qDYkGzPXmlTkZdoZzc
         BrTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956067; x=1729560867;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=K/1FbNbj8xMG8ujcYcdr30sXvR9sVWOlYF4SHhQ8pmc=;
        b=Ctm3zvG52M4O0ra023wJhbLeUaeDpk2vnJNncBh+PNLzuAujDmeDVF2jiiq8RtQRJ7
         YpFT9RXKwkJyX+CpDaj6HHA8/5ZH9vpzqwtvP/PA7sjxmD7U2aYYRg3FrjYbV3wGejoA
         qkampZX9FIbsWRj0DOUJHDetRKD2ZrisoVbfshhwIBtrkdoNRIODIVBLCNcWXtNBqIKl
         smnYPNttYNbshROGYJylV2uj9H/tEngwQ1/RzU8s9wXFoQF0wCysPv3xS5FI0RbYrRok
         VDzsKhyK0eppzyqHvLahW67u7OT7gq0MXwOCTsNcodh3K2QyoGfJ73anBoyJZYkOJZ1E
         okZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVPYrLxMQ0Gel9XjhuLWKBmwOBSKfP7c2a9GnXc3wvETtiFxwX5OSY0mrjlTQdcpY8d2Dacfg==@lfdr.de
X-Gm-Message-State: AOJu0YxPA9nySX0k8fP5vPLXnBh7YoC2i/3Of1JCJhCG4uKWJ78HYzfF
	qcMjlv+vjTTgFGpAgcf9yYbWKUSATtbJ1nvzj9zI0h6LDfT8iWip
X-Google-Smtp-Source: AGHT+IErKU6cZ0lCnKzCtA/S0/R+jiO5mWYuReWAGLPrq1M6zzuDAUAOcGHQfUPQ5YzdmymHrtZTMA==
X-Received: by 2002:a05:6808:1525:b0:3e4:411e:a9a1 with SMTP id 5614622812f47-3e5c91196cdmr9297622b6e.34.1728956067523;
        Mon, 14 Oct 2024 18:34:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:cb92:0:b0:5e9:88aa:e437 with SMTP id 006d021491bc7-5e990b2032als15619eaf.0.-pod-prod-01-us;
 Mon, 14 Oct 2024 18:34:26 -0700 (PDT)
X-Received: by 2002:a05:6808:3a18:b0:3e5:df4c:bf98 with SMTP id 5614622812f47-3e5df4cc039mr4010537b6e.20.1728956066778;
        Mon, 14 Oct 2024 18:34:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956066; cv=none;
        d=google.com; s=arc-20240605;
        b=dSlzhrdhlKbSGSsFc/+rijY/vkN8SybIGeJzGVYvlqzCdywwPm6RuEOst6UqZPrbuq
         tSm9L+Qe4S2Hl7YmlfqNcOmBtOLQzPstJwcoJbz2TGYfwUr3F2UgHa/0KOdfPI/sbNdB
         d5yI4PZ5zdnqM/HChomEyCMgMkAIyKkq+dulIZBD+DygO5zEbBhnevr2ONIgX12J6dVo
         W/66yR7tvoLUP5o0b8wCXKMk+P22HQfTGRxeh7sPjB8WJ6qofmp6FO+uQhOUQmZw0Kug
         wkpMY5Ww0NTrHS8fLE82glqjriFFFzCJpla3w+r/s1PBjFHu9Aq2XMxPYWAkY/3amuA6
         L99w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ww6ZbzhcNbPuRWG0GzwKnAEreEL780mKVa0cmRg0+f0=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=G66Ea60tTbTFuuhHlAbw5DZIKpxV39rDrSVkHiUfTjD3pAxErWpzG1V9Fdz6pC7/LI
         cfEJ9yQ3UWHSb7R1QVnzx41lFDVRpCqFK4mCKzrRDwk81X/zx4A8WlDGeNK+0AIrAc/q
         4Bt0C+eDcQ6UXDDTXo7DdUFaH9xadQpHFtY2WlVLDOoD6AX6SgyZLn2WGt0f9XccKpJl
         6ZmORL9JYXqpx7rF6a/j8zKaJ6T3tbcmNJjKxvOs2KM6Kocp83gERwToVc6yLDmTr8qF
         XeuogZtXeeKMHW1ld4uk3miy6AOM+qW/PM5n+59JodtPrVGK8p3hhL5RfqeYyJN0l9BC
         AW6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ISIFPGCD;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3e5e862c0c2si12594b6e.4.2024.10.14.18.34.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:34:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 41be03b00d2f7-7cd8803fe0aso3293437a12.0
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:34:26 -0700 (PDT)
X-Received: by 2002:a05:6a20:2d0b:b0:1d8:b060:37c6 with SMTP id adf61e73a8af0-1d8bce4272amr19010970637.0.1728956065840;
        Mon, 14 Oct 2024 18:34:25 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.34.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:34:25 -0700 (PDT)
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
Subject: [RFC RESEND v2 08/13] book3s64/hash: Make kernel_map_linear_page() generic
Date: Tue, 15 Oct 2024 07:03:31 +0530
Message-ID: <0ecad6f4f0d71fd8eb92b437315e981d23a14bca.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1728954719.git.ritesh.list@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ISIFPGCD;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::534
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

Currently kernel_map_linear_page() function assumes to be working on
linear_map_hash_slots array. But since in later patches we need a
separate linear map array for kfence, hence make
kernel_map_linear_page() take a linear map array and lock in it's
function argument.

This is needed to separate out kfence from debug_pagealloc
infrastructure.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 47 ++++++++++++++-------------
 1 file changed, 25 insertions(+), 22 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index da9b089c8e8b..cc2eaa97982c 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -272,11 +272,8 @@ void hash__tlbiel_all(unsigned int action)
 }
 
 #ifdef CONFIG_DEBUG_PAGEALLOC
-static u8 *linear_map_hash_slots;
-static unsigned long linear_map_hash_count;
-static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
-
-static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
+static void kernel_map_linear_page(unsigned long vaddr, unsigned long idx,
+				   u8 *slots, raw_spinlock_t *lock)
 {
 	unsigned long hash;
 	unsigned long vsid = get_kernel_vsid(vaddr, mmu_kernel_ssize);
@@ -290,7 +287,7 @@ static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
 	if (!vsid)
 		return;
 
-	if (linear_map_hash_slots[lmi] & 0x80)
+	if (slots[idx] & 0x80)
 		return;
 
 	ret = hpte_insert_repeating(hash, vpn, __pa(vaddr), mode,
@@ -298,36 +295,40 @@ static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
 				    mmu_linear_psize, mmu_kernel_ssize);
 
 	BUG_ON (ret < 0);
-	raw_spin_lock(&linear_map_hash_lock);
-	BUG_ON(linear_map_hash_slots[lmi] & 0x80);
-	linear_map_hash_slots[lmi] = ret | 0x80;
-	raw_spin_unlock(&linear_map_hash_lock);
+	raw_spin_lock(lock);
+	BUG_ON(slots[idx] & 0x80);
+	slots[idx] = ret | 0x80;
+	raw_spin_unlock(lock);
 }
 
-static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long lmi)
+static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long idx,
+				     u8 *slots, raw_spinlock_t *lock)
 {
-	unsigned long hash, hidx, slot;
+	unsigned long hash, hslot, slot;
 	unsigned long vsid = get_kernel_vsid(vaddr, mmu_kernel_ssize);
 	unsigned long vpn = hpt_vpn(vaddr, vsid, mmu_kernel_ssize);
 
 	hash = hpt_hash(vpn, PAGE_SHIFT, mmu_kernel_ssize);
-	raw_spin_lock(&linear_map_hash_lock);
-	if (!(linear_map_hash_slots[lmi] & 0x80)) {
-		raw_spin_unlock(&linear_map_hash_lock);
+	raw_spin_lock(lock);
+	if (!(slots[idx] & 0x80)) {
+		raw_spin_unlock(lock);
 		return;
 	}
-	hidx = linear_map_hash_slots[lmi] & 0x7f;
-	linear_map_hash_slots[lmi] = 0;
-	raw_spin_unlock(&linear_map_hash_lock);
-	if (hidx & _PTEIDX_SECONDARY)
+	hslot = slots[idx] & 0x7f;
+	slots[idx] = 0;
+	raw_spin_unlock(lock);
+	if (hslot & _PTEIDX_SECONDARY)
 		hash = ~hash;
 	slot = (hash & htab_hash_mask) * HPTES_PER_GROUP;
-	slot += hidx & _PTEIDX_GROUP_IX;
+	slot += hslot & _PTEIDX_GROUP_IX;
 	mmu_hash_ops.hpte_invalidate(slot, vpn, mmu_linear_psize,
 				     mmu_linear_psize,
 				     mmu_kernel_ssize, 0);
 }
 
+static u8 *linear_map_hash_slots;
+static unsigned long linear_map_hash_count;
+static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
 static inline void hash_debug_pagealloc_alloc_slots(void)
 {
 	if (!debug_pagealloc_enabled())
@@ -362,9 +363,11 @@ static int hash_debug_pagealloc_map_pages(struct page *page, int numpages,
 		if (lmi >= linear_map_hash_count)
 			continue;
 		if (enable)
-			kernel_map_linear_page(vaddr, lmi);
+			kernel_map_linear_page(vaddr, lmi,
+				linear_map_hash_slots, &linear_map_hash_lock);
 		else
-			kernel_unmap_linear_page(vaddr, lmi);
+			kernel_unmap_linear_page(vaddr, lmi,
+				linear_map_hash_slots, &linear_map_hash_lock);
 	}
 	local_irq_restore(flags);
 	return 0;
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0ecad6f4f0d71fd8eb92b437315e981d23a14bca.1728954719.git.ritesh.list%40gmail.com.
