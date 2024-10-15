Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBEENW64AMGQEF7PHEGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D2F7099DB8F
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:34:09 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e29142c79d6sf4976767276.3
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:34:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956048; cv=pass;
        d=google.com; s=arc-20240605;
        b=A34YSdChuz+M6ytUahp4Kw1hR8Jyyvg+LMt+DS2iIb0UawJfR8PnLLExdykLcnVlpc
         NSwcNkcQnLkjad7EjZLe/vtKDNOqsrx8DWBr/9RUWYlPNAtaN/nn3R1KstM9r6HM8SdH
         GiBmMPZkCRXrzpRUPffifKb+wxB5mOsaN/o4TgKGnoUrr+zyoQMCTK5k0wlwCRw3G30S
         Nzhd4uIZrMXgeLT9g9/xmeZsmRy5XCScSL08oaiUmeeOLx2V5gPUqTxu6Hsey2nG64mX
         sMfHDNNbORw/pa3rENe+zqWjshkbiyYBsLWb3S6PuHazAAtbmGiH1uhCAV6Ad8FPuhPa
         Ieiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=tmjfFmuWhQAS4L8fqq86hy6DBmssOcH6A4TCcs+xbCI=;
        fh=DrYRFYaoWkArSJZdBQYBG7r/b3uqzxPVUXDY/PWqP+k=;
        b=SdJSaex9jsylhTBab3b+tdz0QUxHxh3rqzLgGT/4cBfdEa+C2NgLjU4TQpNo/7OpEf
         b66P/RF2ajVhqnbJoP+4UGO0EdlElYWTUZV29Ql9hMFSdZRc8l8BPlMkqQQc5Lm5xscG
         hx19azPcpTFARK0xxKm1mklFcu+NfCE8FCwWWqWX25q6n7y6qxOYfm1EcZHXuibKGWm9
         4P7U/+51FUFbbpHenL0dQVkvP2Ut5ubqo/Np4CglYD+0A6z+f4meEcnyY490DwcOzbr5
         sqZVBYCMufaGDSsMYB3n7E3PU2W8SQ4fD4xjug2wggWHgildnMUGaJ+c0o1YrHFvnNLe
         YCDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NcLE2dzb;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956048; x=1729560848; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tmjfFmuWhQAS4L8fqq86hy6DBmssOcH6A4TCcs+xbCI=;
        b=smbqjCdaE8bSnWaizd7EpIWd5AWwnjJ9grrJCtr9bH5dfU19spzqk5qpAZZantB5vd
         NiBXdWs+kyxeGirqinHBJQCIWhKcHG4DTsR8UtKZEdcE5u4k/0U+8jKQ36NEXILIhFDa
         WdU+ahCv9ejTNB3qZsq0epHQ9r/U6slCRv96vhp9IB9LUotFlUBigdq7nN6ccje5kcwd
         5cV1y5TKyONArYYFm+kWahAcUpH2sbSFpGC8Vw2RcYjZb5onzyqo+v65EI5asw8Etwpo
         FsOZLzzwe+SInK0Wgkua7u0fNuWJflmyovo6gd2Y/UM9r+QTQ7GULrJQtYBhO2MnuCML
         NP5w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956048; x=1729560848; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=tmjfFmuWhQAS4L8fqq86hy6DBmssOcH6A4TCcs+xbCI=;
        b=PSAAApSlYHPy1A3ldgEeEGonwl6gev/oGrKj7YQ2nstZueVIg2XxJYvTgm6b3l2K49
         1rm7DVXY/ujAGguo/WkKuTvLAZ+tGQ/xwbsSi36jos/e/nlyoxA4GxBhAuBAcYidtY2g
         x0A0GN9tertr7A6ODFjNIe9zoKVGJ6VG0DP6c0P7dhsAqjhittN+bkUMdu4+w79qX1oC
         Omf/ekuVGkgEn3BUzQtZ7ZudJdRCgBJNLmR1ouqqZ0Za21seh09mI76WlBhs3VQRwo2F
         2j4XIQTLYRoOS/YpvekPAcfn/K7ByNPyzyooiZ2c626YcTxs0CjyKutfuT3CQsJbYr+7
         4v6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956048; x=1729560848;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tmjfFmuWhQAS4L8fqq86hy6DBmssOcH6A4TCcs+xbCI=;
        b=pLiz0sJ0EXEzeD6yQPcjOj2XoYPQ3UYdt6qpg98uA3z0Dflbd/yqxxFBvGFXVJvbj2
         k785OYcuDXBeZ2BR4aYR/O9d1rSRy/XkqadK2dS4serLHOMPOV/360EoDNjer9/BO1BV
         LeLvX1D/Y0UfBj+TfEP/A1qxJAWWgSmk/oBKuvXr3q0AkazBwHL1HKegzsBtzxTDb4uC
         49hv9eB+g8wjJc7MYUtsmanchtpKc6m9uVegYoSLaD0CcBOUkgFLI7MA5IHXBR4rwaMk
         AABgmA/fnrdWN0me4AjYxq2LtpcUL7e6X9lMh/I5vUWPwQgc52FfFU39kyLjcSziBfub
         hSsA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWz4VOc2pb6I+IPYIX8utS4I079ec8DpR3e/VVNkX9E5/kuR0Bdl3OfBlVwWa/YVzx6BTSUxQ==@lfdr.de
X-Gm-Message-State: AOJu0YxZpERmwJU3asiorFDdeHxI7P8631RuaJdbXuOfgUb/IEIwKif4
	Dh9XkBe8rC/9svlBxKdcdRj1ltZC2CILfE5y/OZrvzhysPECdgag
X-Google-Smtp-Source: AGHT+IHmFyvaG7fiIh+sM3+L4Um5Xx1X0bVFfDAK6IUv9OKg8bECA/LHsbB/A0XgywH0papB4OsI9g==
X-Received: by 2002:a05:6902:1b86:b0:e29:2ab7:6c03 with SMTP id 3f1490d57ef6-e292ab76c6amr7932690276.33.1728956048256;
        Mon, 14 Oct 2024 18:34:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1241:b0:e28:ff06:8c0b with SMTP id
 3f1490d57ef6-e290b84677bls1536695276.0.-pod-prod-03-us; Mon, 14 Oct 2024
 18:34:07 -0700 (PDT)
X-Received: by 2002:a05:6902:1105:b0:e28:fec0:c673 with SMTP id 3f1490d57ef6-e2919d9f149mr10835197276.31.1728956047455;
        Mon, 14 Oct 2024 18:34:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956047; cv=none;
        d=google.com; s=arc-20240605;
        b=KrJc6A2t+kfu28A/WS31l2ni/J/iYeWEyjOxV3GneHxAdMKenviaM1LyvfP0GIbNW2
         wmwaImxnDg6g+qZRFBE4Txa9IPrYUifJaoV02nG1Cp9AGxdWuKFQaFjtS2JTPuNTx6Ll
         p7AevJ2VHxWHatJNXx5THnTfKqrHQ3Ae0Q6PIon9SZHbkZ288SPyjt6dxh0PgdYz8yWD
         F2cK/NNj+uqYsrSfr8SeIC9izqUpU6ocJncgqkkP3oCAJWjeTJOIAMoTpgRxv8epVkh0
         zmUmgLGRRFlfuzGtbA7h7xxtzm8rjYesTLP+XMkfgqd4MHEn/biNKR8HersG+P2SvSQE
         eRng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=axWsqNzIpvlhLR7DqrnxUdvbHKQsISEkZ4mTeZAqu9w=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=elKi4m6+CYFKWotl8VUKPt3LguVcPfstX8YEL5Nx6jTmuVHTflfQsdr1Xy2Mnzui63
         gnWFi4zOZCy4tGRDLIggKIcP5Qyj+7f/CB+wVQmHOPumTeqspIyi9bvt1C9QPiuMdAVe
         r4taCwOgXfDlUzNleQHtprq3BFQJI/DKf7ZmTlWWj9VvlrXWn8FKy2eAsU6g2pvuxXuo
         bp6llwBLwSbC8n2kBCtMOdd+2YgIvyMKJ9B+9yxFqP1w/kLvD5CoFUXLTEmFwiwBfwL7
         +SyuUqFRnvJtVSE3ziJ8UVV+yI9z5reZ9QA+R6aF9Oxyhlbowj2GpCQzzXJaUCJWyvVX
         pLww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NcLE2dzb;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e296c490ca2si17448276.0.2024.10.14.18.34.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:34:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id 41be03b00d2f7-7ae3d7222d4so4010470a12.3
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:34:07 -0700 (PDT)
X-Received: by 2002:a05:6a20:2d1f:b0:1d8:a899:8899 with SMTP id adf61e73a8af0-1d8bcf561dfmr20114300637.29.1728956046508;
        Mon, 14 Oct 2024 18:34:06 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.34.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:34:05 -0700 (PDT)
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
Subject: [RFC RESEND v2 04/13] book3s64/hash: Refactor kernel linear map related calls
Date: Tue, 15 Oct 2024 07:03:27 +0530
Message-ID: <5a4522af03014d41d98809dd58fab57b187e8b51.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1728954719.git.ritesh.list@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NcLE2dzb;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::531
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5a4522af03014d41d98809dd58fab57b187e8b51.1728954719.git.ritesh.list%40gmail.com.
