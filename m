Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBAVGV23QMGQE4ZNUQLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 219ED97C2F1
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:57:08 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-458373c736fsf9583711cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:57:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714626; cv=pass;
        d=google.com; s=arc-20240605;
        b=eHZv3INoHYlBIm/q9KuWeNY27YaqRNkoAvAvKIDVOnVW/zRgJeRtD9E9S692nXgoDS
         yqejhNCaOpV6IEO3oJxAUo2r/PmU5KUwHe2mOb0UQxzDcMg75ndmnD6jKC4sTY51YuPe
         AycIqNAo36QIdpDel9+ZzpwuJPTYeNC78ROmrSKUO9aW5iyXQWlmh44Qen+KDqcwav8z
         druz2QlSIKZrZZSB/jzGE8aS3XODzXYfqte6ubl21rDRfQ2oFhA2CqiwJFgx0Ey9o2OY
         j6GGVtc1WTuOcfEyNWI6EP9F4scTExA643hiKxqsSRcC5AQEiZeyTecCxbcGF9lqBadW
         Sc6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=O5CS805E7ss5E8h99jxBSYo5KV7ofXagVlrJ6eC83tY=;
        fh=89CIrSmyVzykFAtUUU3c4DJ4K/AmQPR/ttHsLvFQv9E=;
        b=EL3PJhrCUGE0VgkJwjl1Ac3TX0VvW/zK2GoF0V6m5q6vEbJkH5Xe1+Ly+j1dxLtVst
         qVWxbEXLu2IlLw8xrAY8LmG4OtBabLYMO1e9o15wes3Ch2NhJJulSYWpN1wZSlyWNwXx
         uZajU001u61JCOrtGuHyAurzx0dX5QSPdBcRcKP/Ba/v1vQL2voC4MqbRy0X2ASogelu
         8Qo2TdCqpXUCFfr7Q/mMbTy49gSEHhxsTEJO8Yw0FvqCXCXgiHhM0YnxucpIj/LLtr03
         iVaKke7Tw5UWl9VoXRPVdCTBN95soxYV/cEGFDFiZolGLKcQe9TnZTyySO80Y5+HHcRK
         Q5tQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ja88EkSU;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714626; x=1727319426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=O5CS805E7ss5E8h99jxBSYo5KV7ofXagVlrJ6eC83tY=;
        b=dj4gEGONs3yItFZTOWF8vnvfZI+1zlCOUB9HPOrjcMlnWbqoGXCIRuKuLgVRcXOvoS
         grUjB9Z0uxTYaN3IEkt+5wc3GAxyivg1/81W0xInDhNMtq6cQ0ijfZYdRBT5vtXhvjDQ
         d/3DFv+4uAUK9UkbIOSu50TECT+uBCE3GIdfspSN8SBMx2ecIPcnw1gvazWclURHbmQx
         ZFoNTzloH11t5ouKET1wiIB3xSG/BnEJCG27TtPipzNEp4nLjrUhQU/HWGZj+i3coM5R
         l5I/M+/dR0UaFXvdMZYMifEERTbQQKs3T4+m8JE4eLhODePY8cl07drNG+MpWz7wUdDo
         VLPQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714626; x=1727319426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=O5CS805E7ss5E8h99jxBSYo5KV7ofXagVlrJ6eC83tY=;
        b=DjcInZidPPrbHmhRwm6pP8g6Yu1ZB/i5d7vPcodPVy7tdPoPUqKmLVKU7DR7+tPaYL
         32QjK6X4CDwGOPeQyI5SW4FU8k6cWTPRmrnrZlt8dXlMzCOQ04lbh8PHkY9PDqOfIsRp
         dPOanFgAMAh4F9uhySNgjt5nLn41FEa+7sm/EmrVDlxE3CrxNCi25R2B2nc72jcg7FRS
         HlGQa8ebBeJE39AX2I0F9OGCgvGCbwuf6UmG1HJqVal74QjkLhdj4B4+6ULXy0f892Zu
         Fdp2zhaiU7aNc3R1Tq7gxmfF1gjb5j8MjwfvRWXSL3o3125bzz5D96kbQKJm4YGI9H1Z
         ogbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714626; x=1727319426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=O5CS805E7ss5E8h99jxBSYo5KV7ofXagVlrJ6eC83tY=;
        b=H+PMuZP6XFQ70Ag93ddp94PtDKG41h7s1JEEqrnAEBk613sNcokkuw9A/Zsc8HcUeO
         sLBX2Q68AkKy3fX1tmsvq00Xu5kxsvtztnhykSSdJXb+XAO+yEW+Pr+KTpM0XWnWtOBf
         9NyDfxentIll/8yE/KUv7syWInr8/n6QD0MKznRJT0CNr413qHaBscJNhlwtqwE94aUq
         1WITxRR7fxdvrjSjigkeEXk13qH2NZqtg9CFAwpuhL2XXwIC9RxC5oLEwR5mtiVNNIKa
         NF1mDiVeETxGtLqmYf6OpgvtzSjLCV5WWxXEWSd4P1bQlPR6S35XCLbiq9BSY5KundOh
         qxLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQepeEmlTW8KIjiUdAK6FiK1tSjv9/28OhpLVSBxr/Fm5zJmERHWg/BvqHkk+gMGVECGcmBg==@lfdr.de
X-Gm-Message-State: AOJu0YwjLZJIAe31du33L0VNtplsGiHEdS3/PjANzxG/Ohy1nOwSuxFo
	gefR4Ysz5J8svZRU7VFeqKf+xJARvEMy4c/2PIGjBh7snuc4RBoY
X-Google-Smtp-Source: AGHT+IHH3Xa3oAeYxFEP7In8m17Lmi9ehEtmkeSWyHVYh9T3nnAcrwO8AEHZl2Jdr6coHX86S0T8BQ==
X-Received: by 2002:ac8:7d02:0:b0:456:959d:ec34 with SMTP id d75a77b69052e-458603f9f61mr454674401cf.45.1726714626434;
        Wed, 18 Sep 2024 19:57:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:203:b0:458:2dcf:c764 with SMTP id
 d75a77b69052e-45b166bd515ls8092201cf.2.-pod-prod-03-us; Wed, 18 Sep 2024
 19:57:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWzR3TViiQ+Ix9OQCgNztjJIwTl+0JxcX+5KF52SL27bYECkOp1uJi8ZCIc5MXVphSWp70FqOWuC1M=@googlegroups.com
X-Received: by 2002:a05:622a:3c8:b0:458:a70:d9b5 with SMTP id d75a77b69052e-45860304676mr394296941cf.15.1726714625609;
        Wed, 18 Sep 2024 19:57:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714625; cv=none;
        d=google.com; s=arc-20240605;
        b=BOItvSfgp578hScj0xBpcx28/HJEoKzn1MnHugIZF11MryARtRpVYGSuI0HpkoCxKz
         oGOUCl37Q6K1HtS/NfxjqmLQxuHACqYjkrKEc+QZ8Pl1/f4X/+L0KB8u02C6bi79Fonk
         FSINCWCbNPcSv/x5w7SVuVcYq3cVhZdFY0yV4Js5LG6iVXER3kkVu3vjHEMcI13mlpYY
         k1KUmeeqwLRN772/DlOXFvVaYfvweSlpLLwXAnJyPb0jleTFEMKZJrWqBH4MQgeclhR4
         o63rUguZ0LYskx/av4qUoCect4bV+wCaPHg8OGeHkOXADHxiHCVifndPx2kVaBHUgb/y
         azRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ww6ZbzhcNbPuRWG0GzwKnAEreEL780mKVa0cmRg0+f0=;
        fh=XqMB247JT/A6Ru5eeCP16pMRZbcBbE9Xn86FF7kmmtY=;
        b=Fog1rfJvwh++AS3Q5C/YZvs4MRBmhbbXdCqmyGcVPHByHxb/gH1ImnISfoSZKFQeWA
         gk0mhJTRXzDEfiD9wxG6L0UJvG0R2St1j1LXBRsehAxc7mslZ0ruaHp7fkWhbOTiHhT2
         Y3bSvt1FgXR2zYVdRApya/gZXpTrYWyjrRfu+0fVEvDZ117OTZEj4b8YmfDo/r4xOYN9
         qofL/MtLOfc/rgxZGPLVp4mpLDO4ii85G3Inuk0tXgPzNuW+4yVKYbBe3nFK/Cw4IiJk
         +vpW4yYSA4LAwyy6AcJp1Lrp7NibPqeQdZKlvykzFGqTqLngW31J3fuJ7H+zbd5zTc0G
         IeqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ja88EkSU;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-45b17868094si422471cf.1.2024.09.18.19.57.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:57:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-205909afad3so4715625ad.2
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:57:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX/nyqdnH4/54nCUnE+uvv0Nu3JSCKByTxLRlbn2wyv/TFzTIjqpkYws5/KthLBCaEeDDLIIrQGkSw=@googlegroups.com
X-Received: by 2002:a17:902:f689:b0:206:96bf:b0d6 with SMTP id d9443c01a7336-2076e41703amr412516255ad.51.1726714624534;
        Wed, 18 Sep 2024 19:57:04 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.56.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:57:03 -0700 (PDT)
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
Subject: [RFC v2 08/13] book3s64/hash: Make kernel_map_linear_page() generic
Date: Thu, 19 Sep 2024 08:26:06 +0530
Message-ID: <8d06f263a903b5867fb23c319c4ddf7db7b7a431.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1726571179.git.ritesh.list@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Ja88EkSU;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8d06f263a903b5867fb23c319c4ddf7db7b7a431.1726571179.git.ritesh.list%40gmail.com.
