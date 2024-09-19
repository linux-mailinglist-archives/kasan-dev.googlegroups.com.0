Return-Path: <kasan-dev+bncBDS6NZUJ6ILRB35FV23QMGQEBFYPH5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 241E497C2E9
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:56:49 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-7db8197d431sf489690a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:56:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714607; cv=pass;
        d=google.com; s=arc-20240605;
        b=PksMeB2r+fythHhz1aqEOhZultPg1FvNEhnQOKaxNKnvOH+lkwqhJPsPoL1NsJClzH
         5BZUMUY6X2Ts5XVVAT+Yxq1oWlnfzZkiS6goHizeUXXtzTCY/kqP4TAsmWWfOQHpbzFv
         r20qlrvabgWviguwr16L5uAGFI3zD6wgAfDfuH0xOAdI07nBIw6TgEGOD2/DNOgH5X6k
         pU/9UkmyJ6nTuO1oTz/xs29h4qb+Eb0c9Vk4r5tFmZrHByuQiwFVTzIwD5HK+25kXvTo
         ceNvhlIaRGB1GOkuoamOkg79EVlrRtzVcTPNckdLsSxT4GJxRvQhhQ24IoIhCB2tm1IK
         f7eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=v+2m+uQzwz0FIHXhGJLAhDI0jNsSAymhXuqrWRj3lyU=;
        fh=5XjembURiJ3fSM21xk0sUi4dlmJfl5HLs9V8G+la/Io=;
        b=Omjdxh+/ScIOK4JK54HjlDYJy1VaoxDL6CzDN0WKL9lyFukdDkzuXInVClyQb6iFmk
         QpD/bZhoHhv1FnrO6l3FqLYBMLh4cgHVwabMx6M4u9fs1prx6q0UbgEDBcADShlS+Tn/
         jMPmpdrhbwf0tnZrrxlOm6eG2py+dSrvjWn9WDLF/HQriL70m/S0etRNey9vVSPj64i9
         h3GV1KUMziDCjWPi/KelXiQibuD+OY/CyzEFalc6ZkwpH4eAAapqn+0nPy3bTCpkf7s9
         YmDX7FgSpjQLrnMmZupbcELKRrjf5P7msBViF9fv9uAUw3bwzi7imti1ZuEBku9cvy7Q
         80lQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a0vI1wIe;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714607; x=1727319407; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=v+2m+uQzwz0FIHXhGJLAhDI0jNsSAymhXuqrWRj3lyU=;
        b=d2tuuy8GQ4PjvoXuAVaiLqT3xdoQYLZ5TSIVTAa4c+GNSHGft41cQnY5dflQlcrX96
         0NyIeh8P6BA7X6Nhn5vqgKLdq4Oibqee7NJ1KrOtyDdzAiSXNVyc6KrJ8Aqi0C978fD0
         6DBB6Hq75K35Shz8G6SJhig8YvMfEJCIOK4DH9W/04KEGDP565JhBn/hpEVTbdWV+vKW
         2a60/NMTkCr2wH+hbFmGB39kXnuC90yJ5CXRHOWR6xVKh5bpbbw0xLRnrLqSDxKkoVnA
         ddc3xcdDeouzEA9u4Ooz3eK0M7uKwH72+0+OYEYXQd7H/8sqFnUo7kw1MaiMu8qEjkrG
         2evA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714607; x=1727319407; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=v+2m+uQzwz0FIHXhGJLAhDI0jNsSAymhXuqrWRj3lyU=;
        b=XSD0JrFkxAP3TqFYShR/mtMQ/r+CZpBLK6CosRpDR5fpAqpZ8SFpi/UhjysCKpY8wd
         KsZ/7dh7NSDxbgqJZ1YNABG2ITghT96oZRGHlxYP4YnpoEqDjIYung4F0jGcjGP90bjs
         mZ7FBORfKnPOiD8dO+4bl5fzlcNHTSrha8n50ZTqbL701acSnlrGM2oFbGpWKY0QalyA
         XXFZ4D/S/FZi1mQAIEQTcpHq80PQEjpTE6ofiSGgCFbu8gvPQbIOMbKlaiAyNxzMmGWM
         yMf868TWiYsXB1i6nmPHG7KPco7szUuNVUzV79lMUJji6Snr6Wzmt2GpFK8ZU756q0/4
         gnpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714607; x=1727319407;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=v+2m+uQzwz0FIHXhGJLAhDI0jNsSAymhXuqrWRj3lyU=;
        b=MTsCbsjcIGrlNQT8Vtj4NVKcJws4ARBFivtQwiuBm7d6VK314K+tAPV4/v1TW2Ui+x
         KZr1ZmtOJcLYLc3ks9HgNJAfatOK02a0M1H/UxBm9Ci7d7dGeLxhVVMdJ+7gdZaUX3mR
         GyMWrU1TwIjte7e9pk5TFHus2kR9KNyEFOXGQbCYlooa/wzlMGc3uhPPlrOvx8UgD1qE
         kBGR820rcg5ok58PWOFZwMVn11DMkyvq2eM3Bs1sRiss7ffyFxuBt7KMyNc+3bZtvu2x
         y8aERH5ac1ZPzBu/EPQ2z8gwLg5JGXOmeeICj0N8BFvLsx3H7LwY4ZxQys0me4ZnPuTd
         CDkg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVKSDTcNtQ0xl7n4Zh+vX01W0ZhLwWOf7gnS5rw/JWDQ1QdVacvhxv3he3m1ijDRKMx1qS2lQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw0E27RZ0KlJ9yw6gVTTyrXkltaBFc0Dz0BQ7iWzvMdqT3OClfG
	1NhMVtS01A8+BU9UeiU1Lt9oxODszBt8eqA67gFBY1UuWqgW1CTA
X-Google-Smtp-Source: AGHT+IGSsqiLekleM4Whw3V4fyEUIdP2A6GETmu8ZAqUel4OZAB3A7bzbzApJc8MtFbR5AF4mBrJCA==
X-Received: by 2002:a17:902:f60e:b0:205:809c:d490 with SMTP id d9443c01a7336-20781d61d67mr326034645ad.16.1726714607393;
        Wed, 18 Sep 2024 19:56:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22d1:b0:1eb:1517:836a with SMTP id
 d9443c01a7336-208cb9087dcls4591785ad.0.-pod-prod-06-us; Wed, 18 Sep 2024
 19:56:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVx4ONfyTdMhZGQgYoLG8IorqZWuOAaaegSmPCNLbnRVYhQdKiFsmlxvMuleWf+rHl9d8u3L7eiSjQ=@googlegroups.com
X-Received: by 2002:a17:903:283:b0:205:5410:5738 with SMTP id d9443c01a7336-2078224472cmr286142405ad.27.1726714605634;
        Wed, 18 Sep 2024 19:56:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714605; cv=none;
        d=google.com; s=arc-20240605;
        b=djrItY8iR4erHrYT1wCUACnEYPICsWxW+WN9zvRudrzH5M3mx6PND+xDrvx3P+02x7
         DcDB+CW6sYEIRZLqqrgzxU5eInW3jtO7YA41v4Zgmt3QV0jy+ZlCZ9NwhLHkDNdz5vZg
         D8uDM8vEim5LU1KsPBvzbBXQZVIh4fVAsSy3Rgo2bty3aNymJz0olSawmOkAxp51lRBI
         +CNPwvqwrt1hjp7MqeaYcQnTJNGa2qV/Rcy/byHSWkzyG/vf4g2DJn4qQC5v8CZo/jh3
         iVx63q745Zg8wEWtyVWr50TlgqPgJkQhXU8erzy489kNWT2LgLD/lpzDbSUB95CNwcXl
         Erow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=axWsqNzIpvlhLR7DqrnxUdvbHKQsISEkZ4mTeZAqu9w=;
        fh=yM210Ao/s+XOe+PhKE2NsTw0EszX6z/k2k8aVSqbWLA=;
        b=KUbVGz/AlbscvNUwhfv2YvKzt6J7yTxYHVqT9NffwmW0IkWjX3nocvbKZs9HhF3obd
         O5CkFKrJyBw0k5kUTm28jpVopzahfGuLGDsSfj/EKnR87fZQoSMKWMoK1mJViFsCiHIw
         zOMdj9A+YUUC5Z4pzSmWEKc8nXvDNShmd+YbWfozRa2ssJjuVDAT0nOU7YAy8IitRwUU
         foRg3zg4rXEesCqAhBFAH6NeTdHUHL2wr4xC+NH1YHRMtEG9LffGXE8CpKdl9W2LhmyI
         yvnL+fJFD7XguvI5FfOlBHEfhXhTZ5POEDxboGxbBvEDTbxw6bRzuuqDYmMiB21Ik1ux
         a0YA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a0vI1wIe;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20794611769si4018055ad.5.2024.09.18.19.56.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:56:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-20551e2f1f8so4668485ad.2
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:56:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXc4iG+gbZeQNZGpxikAF4WzIuR78O2lDjV7/nBTv5Had0018kVM5Ic6ZqoFNNvyC/XQ7ulVZ5dIyM=@googlegroups.com
X-Received: by 2002:a17:902:d4d2:b0:206:f065:f45d with SMTP id d9443c01a7336-2078252bd1emr238945975ad.31.1726714605103;
        Wed, 18 Sep 2024 19:56:45 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.56.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:56:44 -0700 (PDT)
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
Subject: [RFC v2 04/13] book3s64/hash: Refactor kernel linear map related calls
Date: Thu, 19 Sep 2024 08:26:02 +0530
Message-ID: <ee519d5927ca4e141d2b1570384ebe39e0ca850a.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1726571179.git.ritesh.list@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=a0vI1wIe;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::633
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
index 296bb74dbf40..82151fff9648 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ee519d5927ca4e141d2b1570384ebe39e0ca850a.1726571179.git.ritesh.list%40gmail.com.
