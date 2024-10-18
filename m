Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBPFWZK4AMGQEG4PLESA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B9989A44A1
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:30:37 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e28edea9af6sf3324698276.3
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:30:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729272636; cv=pass;
        d=google.com; s=arc-20240605;
        b=CPYm8wCsvCd48Kl8uZOVu0YvYPlxMURBt2SIQarnTa1QLk+wwEoq+s1G01puVFvU/R
         JFuiOAzyA+HDzy9wppdyAKftgPTkSONVuuJmZUhefd6EdvDbAlmg2EyFIAkibmK8bjZu
         k5IeEMRUad/COEZTjqwfvv/+5BjRfvsYy1gx9J6u3IkV7EHG9cKMrq8Ak2nx/Bha0ryI
         Lq47ztdwrwguT7bjLXmwLS64gXUBh0GIJLw7H4TQEXQef8wyjDQKT5X6A3oPMmuKRqHM
         EPYxgZK6iDDuNlIu7AQnr23fuGDe4cymSkF+IDuxXra48LsBvUaX+cCOUsxFBbt6gQwa
         VxTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=64WGkYKicUUSQIkmBlsXuwoVZVzDbWNEh2ay/FI9LtA=;
        fh=AMipD/LIaryP0/VVl/jHtHOy5qokyf2sxa1Xa4jcTuY=;
        b=UtgQKLmq9bBrf4n1EnJ/E/mcd1RDn5MQAgKiW3Ff/qEatVdk5M6ia+quUVUfyWwwv6
         xqK/5tZhTiU1R6cAK1EI4+UpKcgQEPCU0vayXHESJJnMkschWiXajmwgUxrkC+zWL79h
         fFzAIzbkSXWZf5+D6CZihuy0BOBymwKm9KqIeYVMm2EUYGbCznh1kxMTAYBggGRBHVVk
         FcxQVBG63DpWT1zWCYX3oJ7jBLwRflsfGxT9K17/x0Kgv0jSX+7rLy1cHbvwimyY1CiN
         12w4kRVr7RuQJ89HUMSwZ+i9HcOYCk+L13Ato+GjKtRChjEA5IC0ejoEoDxp8Kobre2J
         dArw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=h8rwNlnb;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729272636; x=1729877436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=64WGkYKicUUSQIkmBlsXuwoVZVzDbWNEh2ay/FI9LtA=;
        b=qBuil+GEOCZG7R/vwt+7lYWISoJFJx0xAz5vClir6k643q8h5K6De2B/2VRFnWA8wd
         6aLQeJSH0cvpKTd7pIVuN2a1WRARNaVsip1bFN+nhrc0/mNPe3jmI10/NAfyKOkrChCb
         1DRiKnDC5e6SAyRzKuPTJwvkbxIjpzL+K0KG8bZyfVg25rjzzJQHnaqI11zZKWQ7pJZZ
         MNEjjAykHxUWp4ukYbJetYtGfxxupgMyCmb1wCA15S1Sdp1myUTh7Ur17g2EPXv3MyLY
         D1S97cQtYQvVhWvdVjxaNp2pxo8+Pob30BitkGv+ZhMePYmIFdxwXBuPCtsMUQ89sBYg
         ojzw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729272636; x=1729877436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=64WGkYKicUUSQIkmBlsXuwoVZVzDbWNEh2ay/FI9LtA=;
        b=kpekUdfY7ndfIcYbNk/1oAZ4u4KNOOB95lKc9L/mSD5OY8cRWfF2muwC8j7j28eVMR
         xiCBT7K3dT2VVNq/F9FeU+dReJVAdctx/KU4wASU4kwPGcn6t8ndnSP2QtGStfTYszme
         MSIe+7Aeja4ZjonZTgkK7z016esk/lCcdGNhqAIHsZzdWJ0QbFFO7FTt8WaSnskk0A25
         nUn+tLzYFQVteYZ7ITAGN+1JzfnDTsohX+k+sPy3k3aYqbV1eRXYjhsWoXx90UcDBPmQ
         D11wI7alq5YkmKPxOoAI6Z5hVu9jG3YT9PA3XtbmiG7QfSYIxzAjtEoATJXeOBoEhqhA
         KfvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729272636; x=1729877436;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=64WGkYKicUUSQIkmBlsXuwoVZVzDbWNEh2ay/FI9LtA=;
        b=kb5h4c9pYHvIMXUZxVn4DhPusR0E/W2VFrEx/bs0rHf9u++AOBH2JoD8FfsWwDVOxv
         bk6Zpn1k4ZV7soBzoGqzkKpKyi8vjfoeahEoErBGDKI8D6wAa7zAoWs28et38GGRjVAE
         GnGiQF7ULoAi/vwNFQgJsSsV/4PakWAUDWKxZJKcxo5yBTqNZusQvBUYMjgJtTgWMfIi
         cXyAxCLwHBYXlfDGmUm/cEKa6AdhKCKTqkVbAw5Pu1ExSbxCK9uBdmjPhq8sRlQR6mc7
         UJzbGgs5nqjSmbLLz1XIY80+2M4R8HpKJjbQnWJXm5k/ZCh9k4VkkpxOKXQnNKJipqIa
         zMhQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVR6pwqe/6WgL3YYQqncIPmS6GTjYfw9GpqNoyUVAsIJvzx+mGYCQUtivcpvgqWKV4q26j9DQ==@lfdr.de
X-Gm-Message-State: AOJu0YyH8fJGk+l8I1JkIBBWMaMitFow2mKyx7oZCfj22Wx+aUkZUX0K
	lwOLQvL7d/CHw7NpiC/FJfGyJu6KKEXRk1Lnnv6RrXUu+xWPU/eA
X-Google-Smtp-Source: AGHT+IEuvIFvGhp/sVssOLtvf747YLJXkhkSnvGFW3zCQoLybyMocTFzuiSo4gAma3RCEmi83OjlIw==
X-Received: by 2002:a05:6902:2491:b0:e28:eaed:3244 with SMTP id 3f1490d57ef6-e2bb16d5e8cmr2006264276.55.1729272636163;
        Fri, 18 Oct 2024 10:30:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1243:b0:e29:2bfb:85f6 with SMTP id
 3f1490d57ef6-e2b9cdfb313ls2427346276.1.-pod-prod-07-us; Fri, 18 Oct 2024
 10:30:35 -0700 (PDT)
X-Received: by 2002:a05:6902:12ce:b0:e11:6348:5d95 with SMTP id 3f1490d57ef6-e2bb11decb1mr2887344276.7.1729272635416;
        Fri, 18 Oct 2024 10:30:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729272635; cv=none;
        d=google.com; s=arc-20240605;
        b=RsN035u2xZ8RrH4Aj87szopGKe1TqXeKeZf+g5mDReehidpEGHbyIebdRvGaFHVdqB
         27q543GQQZBAVmmeyMFFYFlit3+BKCfjNnmEzQbSGqZKAotFGAw4hGDfYkdAU4R3uM96
         99IzoG5fIMR1Dfs+ANJoE4VRJtEtRVaF9Z/5nZtSt+vw2KNassp359sUNvKomiNlvCfq
         NaGeYllF2sTNiAqjFLQwSZ9X9y/h5PvyRDt54l/DaiiKShdDta6is8vOir91xFw1RaJH
         CB/DMZXcU7MADmSEEVJi/6n5a2usQj4nzzfPGCxm/r/DfD+zEQOcOeEioa1GBPeodxTv
         LdwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PKeOGzBwhkORap+bFaXRZ5k5ETEZTGkTXkc6r1BfTnM=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=Ut66+w/m9FjgEk4Xbm0+R7mbnonPM4uIbbdRBlOiRKE+sPwOzy28BW5rVw+GQo/O3C
         We6GXWKlT3zCcuIF8w38PRuD/0+ixQgmj/agHd7km5abgFb1kOPnTbn8yAO0/ZHNGJcE
         T3XKfM6/YVRbpESQz0zbRnxgm/8rKL2CgrpY3RI56g4XpFwvnwgWzPPNJ/g+vvvGqcSQ
         0gu3OTkC74UaTaKOVD+HVRLr023MIQHx88H+pA9GmGLk3Pv9soKrVE9rVRrT7y1o+xUr
         RftlqjSk+UdM3WB7wHDUSoBAEFpT5l6bvGGKnlp855M/dYNaEWtkzVBm5G1R6jPWK74V
         R50A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=h8rwNlnb;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e2bb03fbe9bsi101851276.3.2024.10.18.10.30.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:30:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id 41be03b00d2f7-7d916b6a73aso1549223a12.1
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:30:35 -0700 (PDT)
X-Received: by 2002:a05:6a20:d98:b0:1cf:38b0:57ff with SMTP id adf61e73a8af0-1d92c5ac311mr4139493637.48.1729272634341;
        Fri, 18 Oct 2024 10:30:34 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea3311f51sm1725242b3a.36.2024.10.18.10.30.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:30:33 -0700 (PDT)
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
Subject: [PATCH v3 03/12] book3s64/hash: Refactor kernel linear map related calls
Date: Fri, 18 Oct 2024 22:59:44 +0530
Message-ID: <56c610310aa50b5417976a39c5f15b78bc76c764.1729271995.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=h8rwNlnb;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52a
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

This just brings all linear map related handling at one place instead of
having those functions scattered in hash_utils file.
Makes it easy for review.

No functionality changes in this patch.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 164 +++++++++++++-------------
 1 file changed, 82 insertions(+), 82 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index e22a8f540193..fb2f717e9e74 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -273,6 +273,88 @@ void hash__tlbiel_all(unsigned int action)
 		WARN(1, "%s called on pre-POWER7 CPU\n", __func__);
 }
 
+#ifdef CONFIG_DEBUG_PAGEALLOC
+static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
+
+static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
+{
+	unsigned long hash;
+	unsigned long vsid = get_kernel_vsid(vaddr, mmu_kernel_ssize);
+	unsigned long vpn = hpt_vpn(vaddr, vsid, mmu_kernel_ssize);
+	unsigned long mode = htab_convert_pte_flags(pgprot_val(PAGE_KERNEL), HPTE_USE_KERNEL_KEY);
+	long ret;
+
+	hash = hpt_hash(vpn, PAGE_SHIFT, mmu_kernel_ssize);
+
+	/* Don't create HPTE entries for bad address */
+	if (!vsid)
+		return;
+
+	if (linear_map_hash_slots[lmi] & 0x80)
+		return;
+
+	ret = hpte_insert_repeating(hash, vpn, __pa(vaddr), mode,
+				    HPTE_V_BOLTED,
+				    mmu_linear_psize, mmu_kernel_ssize);
+
+	BUG_ON (ret < 0);
+	raw_spin_lock(&linear_map_hash_lock);
+	BUG_ON(linear_map_hash_slots[lmi] & 0x80);
+	linear_map_hash_slots[lmi] = ret | 0x80;
+	raw_spin_unlock(&linear_map_hash_lock);
+}
+
+static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long lmi)
+{
+	unsigned long hash, hidx, slot;
+	unsigned long vsid = get_kernel_vsid(vaddr, mmu_kernel_ssize);
+	unsigned long vpn = hpt_vpn(vaddr, vsid, mmu_kernel_ssize);
+
+	hash = hpt_hash(vpn, PAGE_SHIFT, mmu_kernel_ssize);
+	raw_spin_lock(&linear_map_hash_lock);
+	if (!(linear_map_hash_slots[lmi] & 0x80)) {
+		raw_spin_unlock(&linear_map_hash_lock);
+		return;
+	}
+	hidx = linear_map_hash_slots[lmi] & 0x7f;
+	linear_map_hash_slots[lmi] = 0;
+	raw_spin_unlock(&linear_map_hash_lock);
+	if (hidx & _PTEIDX_SECONDARY)
+		hash = ~hash;
+	slot = (hash & htab_hash_mask) * HPTES_PER_GROUP;
+	slot += hidx & _PTEIDX_GROUP_IX;
+	mmu_hash_ops.hpte_invalidate(slot, vpn, mmu_linear_psize,
+				     mmu_linear_psize,
+				     mmu_kernel_ssize, 0);
+}
+
+int hash__kernel_map_pages(struct page *page, int numpages, int enable)
+{
+	unsigned long flags, vaddr, lmi;
+	int i;
+
+	local_irq_save(flags);
+	for (i = 0; i < numpages; i++, page++) {
+		vaddr = (unsigned long)page_address(page);
+		lmi = __pa(vaddr) >> PAGE_SHIFT;
+		if (lmi >= linear_map_hash_count)
+			continue;
+		if (enable)
+			kernel_map_linear_page(vaddr, lmi);
+		else
+			kernel_unmap_linear_page(vaddr, lmi);
+	}
+	local_irq_restore(flags);
+	return 0;
+}
+#else /* CONFIG_DEBUG_PAGEALLOC */
+int hash__kernel_map_pages(struct page *page, int numpages,
+					 int enable)
+{
+	return 0;
+}
+#endif /* CONFIG_DEBUG_PAGEALLOC */
+
 /*
  * 'R' and 'C' update notes:
  *  - Under pHyp or KVM, the updatepp path will not set C, thus it *will*
@@ -2120,88 +2202,6 @@ void hpt_do_stress(unsigned long ea, unsigned long hpte_group)
 	}
 }
 
-#ifdef CONFIG_DEBUG_PAGEALLOC
-static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
-
-static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
-{
-	unsigned long hash;
-	unsigned long vsid = get_kernel_vsid(vaddr, mmu_kernel_ssize);
-	unsigned long vpn = hpt_vpn(vaddr, vsid, mmu_kernel_ssize);
-	unsigned long mode = htab_convert_pte_flags(pgprot_val(PAGE_KERNEL), HPTE_USE_KERNEL_KEY);
-	long ret;
-
-	hash = hpt_hash(vpn, PAGE_SHIFT, mmu_kernel_ssize);
-
-	/* Don't create HPTE entries for bad address */
-	if (!vsid)
-		return;
-
-	if (linear_map_hash_slots[lmi] & 0x80)
-		return;
-
-	ret = hpte_insert_repeating(hash, vpn, __pa(vaddr), mode,
-				    HPTE_V_BOLTED,
-				    mmu_linear_psize, mmu_kernel_ssize);
-
-	BUG_ON (ret < 0);
-	raw_spin_lock(&linear_map_hash_lock);
-	BUG_ON(linear_map_hash_slots[lmi] & 0x80);
-	linear_map_hash_slots[lmi] = ret | 0x80;
-	raw_spin_unlock(&linear_map_hash_lock);
-}
-
-static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long lmi)
-{
-	unsigned long hash, hidx, slot;
-	unsigned long vsid = get_kernel_vsid(vaddr, mmu_kernel_ssize);
-	unsigned long vpn = hpt_vpn(vaddr, vsid, mmu_kernel_ssize);
-
-	hash = hpt_hash(vpn, PAGE_SHIFT, mmu_kernel_ssize);
-	raw_spin_lock(&linear_map_hash_lock);
-	if (!(linear_map_hash_slots[lmi] & 0x80)) {
-		raw_spin_unlock(&linear_map_hash_lock);
-		return;
-	}
-	hidx = linear_map_hash_slots[lmi] & 0x7f;
-	linear_map_hash_slots[lmi] = 0;
-	raw_spin_unlock(&linear_map_hash_lock);
-	if (hidx & _PTEIDX_SECONDARY)
-		hash = ~hash;
-	slot = (hash & htab_hash_mask) * HPTES_PER_GROUP;
-	slot += hidx & _PTEIDX_GROUP_IX;
-	mmu_hash_ops.hpte_invalidate(slot, vpn, mmu_linear_psize,
-				     mmu_linear_psize,
-				     mmu_kernel_ssize, 0);
-}
-
-int hash__kernel_map_pages(struct page *page, int numpages, int enable)
-{
-	unsigned long flags, vaddr, lmi;
-	int i;
-
-	local_irq_save(flags);
-	for (i = 0; i < numpages; i++, page++) {
-		vaddr = (unsigned long)page_address(page);
-		lmi = __pa(vaddr) >> PAGE_SHIFT;
-		if (lmi >= linear_map_hash_count)
-			continue;
-		if (enable)
-			kernel_map_linear_page(vaddr, lmi);
-		else
-			kernel_unmap_linear_page(vaddr, lmi);
-	}
-	local_irq_restore(flags);
-	return 0;
-}
-#else /* CONFIG_DEBUG_PAGEALLOC */
-int hash__kernel_map_pages(struct page *page, int numpages,
-					 int enable)
-{
-	return 0;
-}
-#endif /* CONFIG_DEBUG_PAGEALLOC */
-
 void hash__setup_initial_memory_limit(phys_addr_t first_memblock_base,
 				phys_addr_t first_memblock_size)
 {
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/56c610310aa50b5417976a39c5f15b78bc76c764.1729271995.git.ritesh.list%40gmail.com.
