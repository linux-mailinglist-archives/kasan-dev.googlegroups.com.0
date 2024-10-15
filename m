Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBKENW64AMGQEZ7DMXWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 588D999DB9A
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:34:38 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2e33e5fc515sf1536790a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:34:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956072; cv=pass;
        d=google.com; s=arc-20240605;
        b=AWm8UeYpGCE6cQiYijk26g5wmJYgBi2iABooPMEk4luvvoxetwrSWpRqZimgg0sF+Y
         OuSZDaJL8PAla8A4UTDKwPLzMPxjEAn2b/5qmZQMymmHXXS+0h2Ki3G0YRRyFM8Cx6AU
         5NZ0zbuImPO5lfSAC5dkjbn/xhXLLJrrCmHCp1QalnqkjWsnMiYfr6hMzydZ4NO1F6t+
         9Z1vFBl74GpFY3SCFzAuNcMAb+7p3Ra7EO8rNfnQhJ9NhGR+HXtvInBdEzpUxJ7wdgUl
         uu6NluXS8HZakMCpU3eXRM98ooJVO20NnlDuDcxxXuCxKJIvtHYR3m2tRWSVfrDmH9Nf
         wUfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=qQfhIHis5W/5NdLZbyz1xdHt9od47gJyR1urq7+4wMw=;
        fh=FPqMJ+ODxkCB0bOgAg6CXqSyOfuER/tMUu5d3GK4xio=;
        b=IRpDIenWU3tMT3y1DlE8lthbl79IrfCtI1cb/Whn/1zGwlFKqIO6YWeRm8ZsqyB+iB
         nBCuHz1p1ggCmyK60xNQyO1BYeHJ+NUxG8XCm3B9QNvNkrGAM/TJ7aSeH7M+/FYl2QBQ
         kf5h/5vgXSLDQiFh4BSr4EEck8/g7TeyQp0iT6VickcxUoubJkmCgnFx7Y2zu3ELvOxT
         tGhVPk6DRDXGauO17TTqSo6BiM45JTt8WbGjKrBkT4/UfCHrQ1cOgZVjYWBxikZjQhiV
         eAMUrXDmhSGUeodFfGJg7A0LjvmjZI78s3SNpk+8XHq+BBtZk0Z96c7sYPf46fhvvdeB
         16Qg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OOeEtdqz;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956072; x=1729560872; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qQfhIHis5W/5NdLZbyz1xdHt9od47gJyR1urq7+4wMw=;
        b=xUFpwhWX1OnxDCi9CDTjg2Fka7xyVF2w15YmShs6+pfWnttwaZgNV6lrmmmc56a5Qq
         WFVkfg9JYNwlaDgPaq5p2QRDCNVv/phZ30IH537m0ZuG6cpYh2zQy/Ws0tBItbuEptf9
         4OUqU3Aff3/KX+AY6ReYz1lEJzGoaguVPMeVyfH7jx0GT2dN0BPt412Nhxxq8Q1XLVoE
         v9YPiPowVbK2sckBx+CDjLD7qed6IgHJUIkw6PsS+uvgaMLPoFlskb88CyMCePqeHnWF
         Vu9sUkTj+880ah4Trl4XcIpJeR0PfJNJV8VdSb6g/NHPDJrXnGczKI7l5l4qbvndvw+z
         9gtA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956072; x=1729560872; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=qQfhIHis5W/5NdLZbyz1xdHt9od47gJyR1urq7+4wMw=;
        b=JY/QNWylegSsg0sBwuC8ZAz4NXMmj1a3XqOwtD3Odml33sZSmL12u7b7/nhB9NDy4Z
         X8Tc4dmtwZTEXKruiSlOWUWBoamFSSpS6n3xPiPFRE4bV6R/VN5pjAgy4M8BVMe85DbB
         7LyyBTCq5DIjq3qw1M14iDCxj2sSxSb9NGXtjvKsqFFkczhmEZ+YyqnhRDLPFp8sdR4i
         TW+RFZSuj3d6n0dd+BHMvIepuPNSqqOzOiciqKrLsMQy504Wg7G52GWjBqyC52NCNBUk
         +JfH1KRmnaJAZMclbkIKn1iimNHOM+DfsNVCEnA36MY/qbjVfEkM28Y8f6m7rC2sZwEu
         kcZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956072; x=1729560872;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qQfhIHis5W/5NdLZbyz1xdHt9od47gJyR1urq7+4wMw=;
        b=PFZmLArNwQMx6uX9lCE9v53spkgp6ARHZOH9IKl43h52VmYX5KGMNX9zpoWLnD7EHt
         cPTpJ+yUcdF/UDj7EiDvUhGMSVONOT8ZKSxT/jGNURWSpLIIpfgm7uC1eMJFtCYgLNr2
         eGOKeWtu5a/Hs6COhMsnN+Nslzxl47MfQYPXcIy8+UGqO6Vc/mEPMli7sCgdNVXNiEEl
         iemZT8sVqn5W7C0ULgDmtRHRjCKPl7+Kzh5FLoKI9HDVsw/d0xtlszcrLKqP1OianYov
         RyaJTvQK3sXx2ghvpsaXMnD0FEcYHWLljArCP10QlXVv0QXJ7jcVH4ZdzKm74vmD3nC0
         6C9Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUjyckGKheQvXMEWvsrjH0oHyaIJ7n/vTY3w+e0sgUKRvyhFgVyyBwBBvabMJxGijnT4jyERQ==@lfdr.de
X-Gm-Message-State: AOJu0YysXlzk0i2QwiFpbgW5KUXFmvlaUneJj7ZQ96U4C7jYQoEzP03X
	C2wgNZCc7nnB5McsAlw0azHHroHgIOXn9hmhdwxd3O0XVThGy43k
X-Google-Smtp-Source: AGHT+IFqArzBPB60yZMrSAEyUK5QF5GSvrZyItEaW3zymb7UhtS0WaPbt1PDd1lkbEJYm7o4KYazYQ==
X-Received: by 2002:a17:90a:b017:b0:2e0:ab57:51ec with SMTP id 98e67ed59e1d1-2e2f0d7c939mr16282774a91.30.1728956072514;
        Mon, 14 Oct 2024 18:34:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e60e:b0:2ca:b919:b4aa with SMTP id
 98e67ed59e1d1-2e2c836e891ls3248894a91.2.-pod-prod-01-us; Mon, 14 Oct 2024
 18:34:31 -0700 (PDT)
X-Received: by 2002:a17:90a:b017:b0:2e0:ab57:51ec with SMTP id 98e67ed59e1d1-2e2f0d7c939mr16282708a91.30.1728956071078;
        Mon, 14 Oct 2024 18:34:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956071; cv=none;
        d=google.com; s=arc-20240605;
        b=foGjl5lo0lUU4xvBSzUak91rsk1TYpQZIqvYWXSA4uH2pNv+2PAxAiADuNbaWLLxuL
         UfY+A8LUwMNTsiipNsyQM5ct58pw2CMtleSzOD2pjLfbbFvY7+wraRJAbsO1IAC1cFsP
         TzfNjTedicoa9kL9TNvwp475Swghm0SskX13HtF1FwKHz8gKuCyM5EesoNWKfE7DDIBp
         SdTs7KiCDDpCxz6nEXV3YmJB3T9CpgxfjZ//R4shuVUoCmxB7GzmbMr/rV1uch6DHyDg
         PpYG3eXtERNFmlOc0uDW9XDhqe2SDgVHPCTsAnydURGD064zmxbgj7gCf3VqF+FJ5yYw
         TXpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jpwPGGqxMjTTALmPRltkI2obnVC0TIxSM0BTVcrrVEU=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=Htz8R6a1jUf3MvfsYMZ6PQahyvJ80xGIqV0IzOGJqn02Ory7kS2xeKTeXnGdBlG8ay
         Ks0dZjQnGbsgHruNKkxjN2kcH975eTrTbseO+hNrHANdmZsyZkGNYKBzzICtPRdG3PFo
         iVJ+JEL2kJPEIKmbruhdxBomjmUMoLfeETuO2QyC7iCKJHjK4ugEhJkczBIwilj6uMvi
         qAg1PGXUXGtCGZYsqVMqndu742jOJ7pg1CuKDX8jndb2MiM+TPKh7rhCLi4ymvA+6xt5
         +MFRasVNWVhBFIgGnqUjG1M2xILojmSrBXoB6DGJyNKaFbMGFOksdvdFiz02k9W5Ylsv
         Ba4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OOeEtdqz;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e2c6a09e29si830834a91.1.2024.10.14.18.34.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:34:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-7ea7d509e61so690184a12.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:34:31 -0700 (PDT)
X-Received: by 2002:a05:6a20:c997:b0:1d8:adea:3f7c with SMTP id adf61e73a8af0-1d8bcf18038mr20979021637.14.1728956070636;
        Mon, 14 Oct 2024 18:34:30 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.34.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:34:30 -0700 (PDT)
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
Subject: [RFC RESEND v2 09/13] book3s64/hash: Disable debug_pagealloc if it requires more memory
Date: Tue, 15 Oct 2024 07:03:32 +0530
Message-ID: <79552bdb6dac0d0a39d9c639bdf92f4e66dcaa55.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1728954719.git.ritesh.list@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OOeEtdqz;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::529
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

Make size of the linear map to be allocated in RMA region to be of
ppc64_rma_size / 4. If debug_pagealloc requires more memory than that
then do not allocate any memory and disable debug_pagealloc.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 15 ++++++++++++++-
 1 file changed, 14 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index cc2eaa97982c..cffbb6499ac4 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -331,9 +331,19 @@ static unsigned long linear_map_hash_count;
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
 static inline void hash_debug_pagealloc_alloc_slots(void)
 {
+	unsigned long max_hash_count = ppc64_rma_size / 4;
+
 	if (!debug_pagealloc_enabled())
 		return;
 	linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
+	if (unlikely(linear_map_hash_count > max_hash_count)) {
+		pr_info("linear map size (%llu) greater than 4 times RMA region (%llu). Disabling debug_pagealloc\n",
+			((u64)linear_map_hash_count << PAGE_SHIFT),
+			ppc64_rma_size);
+		linear_map_hash_count = 0;
+		return;
+	}
+
 	linear_map_hash_slots = memblock_alloc_try_nid(
 			linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
 			ppc64_rma_size,	NUMA_NO_NODE);
@@ -344,7 +354,7 @@ static inline void hash_debug_pagealloc_alloc_slots(void)
 
 static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot)
 {
-	if (!debug_pagealloc_enabled())
+	if (!debug_pagealloc_enabled() || !linear_map_hash_count)
 		return;
 	if ((paddr >> PAGE_SHIFT) < linear_map_hash_count)
 		linear_map_hash_slots[paddr >> PAGE_SHIFT] = slot | 0x80;
@@ -356,6 +366,9 @@ static int hash_debug_pagealloc_map_pages(struct page *page, int numpages,
 	unsigned long flags, vaddr, lmi;
 	int i;
 
+	if (!debug_pagealloc_enabled() || !linear_map_hash_count)
+		return 0;
+
 	local_irq_save(flags);
 	for (i = 0; i < numpages; i++, page++) {
 		vaddr = (unsigned long)page_address(page);
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/79552bdb6dac0d0a39d9c639bdf92f4e66dcaa55.1728954719.git.ritesh.list%40gmail.com.
