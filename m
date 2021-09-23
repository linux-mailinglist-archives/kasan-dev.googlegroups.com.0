Return-Path: <kasan-dev+bncBDOY5FWKT4KRBN7AWCFAMGQELZ2N7FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 844A141594B
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 09:43:53 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id m9-20020a17090ade09b029017903cc8d6csf7114630pjv.4
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 00:43:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632383032; cv=pass;
        d=google.com; s=arc-20160816;
        b=G0K+tcGasTSDIfSalslCrHhgOuKK+22FECUlx+zilYeKRf83nqwmFAOQnq0IHuVXtH
         U7Ykrk/4G4smQF3tEw6CHd81GneAo7KB6A9YYfyPoGOmR1AF25Mgt8h2ToaGTKlWpzVo
         p2cfYCnzCSsSaTANxbtmeqVW8M/s34NxKtZ1iqwjDW/gXerJw1PLkdUI4yKHIFCcFydG
         s07WnHMUy+r4epklHa2Ae6WUH513g1tkfvRWHtmTds6zl7/tBtVqfsiXf+AYcAj4Ax4K
         donLJFAWqUxAlm6NYxx5MXyVnLrB4zLob7WwNpqktSuG1yJXpr6QKk9xojC2MVs8Nqld
         VWQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iMXs4ewQCUofoOi3LKVsWTA5nbvOF61q2mcTsxKYD1M=;
        b=NMJKeVGOsug4aZ5p7PRyJRDEX9DQPIlRJ1oy8ysdTv3j6AwsZp8KV+ASg/lB74ZAnl
         1GdZuRxPJQBFAwSQIcbsrRxQ62auyKEdEamHNaCl0beaX+znC2ZY2g51miG9w7YgaSHm
         umnM2xwkdwLwel6bAO21cAk4jp1b8mkyXPLFQRSEAzpUA3atlz0UMDQxq+MyVjSkKNrN
         XQIQ+dC5eJuyvs56Wg3U6asWSeGZu+6aVTW0NUqaByWxRS1IzgITeR16CEBXd/GdyODH
         mKrFOwps7khn2W25+OXrizricvgta3dtaVflS0iaUSWC/TDyGo11I+YjEZk1x3L6zAso
         7RXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qp4PlSy1;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iMXs4ewQCUofoOi3LKVsWTA5nbvOF61q2mcTsxKYD1M=;
        b=JlkVY8ZuVIsQLqdgY+0+etF0mlWs87mvb5h/UFhrY7CIdWb5Xm1FcG1N+6f1TDpA7R
         kSoEAedQNgFwJXbwXKVqSKOkSDVuI0VuDVSK2pNDNUt1mj61IMZ24e6f3p80aNQ0y67V
         ZMYO3LRkfIHMV4BUei8q7h/wHNXvihcpKYdvqotRd5KcManQ9j5qb92CexJ9MUTwi+hu
         Vb3nFwi2MrIOD56o5ntdvz767piCfdoPnmHjyoLNy5+c71Ls9r6gCdKPvehi4IamxIf6
         89KapiixL8Qzfn+mm7OF/m3sBwWiL6KQjgXS0kYg49CsNJtC6aFXl4ZK4U2Wtw+EWMMe
         DgpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iMXs4ewQCUofoOi3LKVsWTA5nbvOF61q2mcTsxKYD1M=;
        b=z91qBaK9zggQ+lQye7ItykHNwQ1VSAFIKdpHthtb5PI7ZTJbWNbA7pf2sjM5vt36xH
         SSLgP9KuyP0ihNdtYvTTfaaAViAcEd8c0YLQ3L7SOpmsHM5+TcCDacVlTK9M5N8aONEx
         SG9GiDQslo4IKApwn3on9DZoSTZ+2YeuvMhIdgBLTupPuB2lboW/gs8xXf83k5YKpbUn
         mrq7EMXxmKm7q74IqkGz7gz46n7hnsG+VoUVf+YiCdAmItRzLPZZM2QcuTtYBSM4asK8
         Dgf1Yst0P6Mfe9WAHSs1DD2o+yEWsJDR56Lsg07WGePejw8vfxfJHuLLKx3GENI6xPd2
         FX/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532uXaxGqRLylK+OxFTQM1v2PBRCcEY42RieZ8itC6ZCTmTK4bN7
	qSn/keuMD5j1HdvuVwmJCWI=
X-Google-Smtp-Source: ABdhPJxtQpJWBNiNJfBplGa5RgQHJ/s7hizJqdpUmjZi4mto0GLVbM3mq10d3KrhR5wahzsC1Asfdw==
X-Received: by 2002:a17:90a:ba12:: with SMTP id s18mr5405101pjr.60.1632383031876;
        Thu, 23 Sep 2021 00:43:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:eb03:: with SMTP id t3ls2028891pgh.5.gmail; Thu, 23 Sep
 2021 00:43:51 -0700 (PDT)
X-Received: by 2002:a63:f84f:: with SMTP id v15mr2983243pgj.204.1632383031317;
        Thu, 23 Sep 2021 00:43:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632383031; cv=none;
        d=google.com; s=arc-20160816;
        b=0QGwNb5VbH+fpIExGfzO2xhnnzZOzYC3FqWkl1/4vI5nMIWgmvo9Fsojfan7EWDvPa
         WlNnxA1Op/TyF/2VsBwR6qL4czrEHFnb2pB5dbX+vwVRu2/xfkVoCq3O1hv4I+lSCzjk
         DoWqkffyNery83BuHhvLnEPh3GabbcF9vHKBUj4U43ZDP5ELRqt2OW+ggVnbAIkb8PqO
         1nCy69mRfdZoUGkbwgnehvsxQtVpshkLTtyoZ0d+mjHJDAua6vuFgNjMmglLZ3E8PbFK
         CVNPpMghbCLXjYueZITq/QXmcTo/fKgX03qhDT8hRVnMhuVkJL19+/HrQPpk8Izc7+3O
         tdKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=50WKWg0QVg2XKrZsOyYgqolyS73RGVick6G3Z4q2Xag=;
        b=DtqZjL9lV0jq47h83WftnAVAVFm5+7fzTp1t7Ee3sCkTg9Yq/N0GBKuC6XekiN/cat
         QHZOZyEmjzRCtAWsJmgqBb0bWPan+Mo/19KEqUX/XTk7YzwIyqBFwoBZSTcYMd75ZcnX
         HYm7ZuVdp/ChoTyYd6+mmT30S8c+LIo+TXBX/SaapzjGqQjQJ2e+u5Tsaj1irb8/8RN+
         YRY8cAbdmpwa8PYqFFuWYL6go5cALdIlqyioONQtc1VlDtU6Od/JUkqkGU5bSzgLTSLF
         6vblMm2p6gKwgjJt/q2vVl24MNUN18BZrWONqzNPGxxX3i/QZ9z38XZ+D9NdI9e7SZt5
         tRZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qp4PlSy1;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m1si886848pjv.1.2021.09.23.00.43.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Sep 2021 00:43:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E807D61038;
	Thu, 23 Sep 2021 07:43:45 +0000 (UTC)
From: Mike Rapoport <rppt@kernel.org>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	devicetree@vger.kernel.org,
	iommu@lists.linux-foundation.org,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	linux-alpha@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-efi@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-sh@vger.kernel.org,
	linux-snps-arc@lists.infradead.org,
	linux-um@lists.infradead.org,
	linux-usb@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	sparclinux@vger.kernel.org,
	xen-devel@lists.xenproject.org,
	Mike Rapoport <rppt@linux.ibm.com>
Subject: [PATCH 1/3] arch_numa: simplify numa_distance allocation
Date: Thu, 23 Sep 2021 10:43:33 +0300
Message-Id: <20210923074335.12583-2-rppt@kernel.org>
X-Mailer: git-send-email 2.28.0
In-Reply-To: <20210923074335.12583-1-rppt@kernel.org>
References: <20210923074335.12583-1-rppt@kernel.org>
MIME-Version: 1.0
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qp4PlSy1;       spf=pass
 (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Mike Rapoport <rppt@linux.ibm.com>

Memory allocation of numa_distance uses memblock_phys_alloc_range() without
actual range limits, converts the returned physical address to virtual and
then only uses the virtual address for further initialization.

Simplify this by replacing memblock_phys_alloc_range() with
memblock_alloc().

Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>
---
 drivers/base/arch_numa.c | 6 ++----
 1 file changed, 2 insertions(+), 4 deletions(-)

diff --git a/drivers/base/arch_numa.c b/drivers/base/arch_numa.c
index 00fb4120a5b3..f6d0efd01188 100644
--- a/drivers/base/arch_numa.c
+++ b/drivers/base/arch_numa.c
@@ -275,15 +275,13 @@ void __init numa_free_distance(void)
 static int __init numa_alloc_distance(void)
 {
 	size_t size;
-	u64 phys;
 	int i, j;
 
 	size = nr_node_ids * nr_node_ids * sizeof(numa_distance[0]);
-	phys = memblock_phys_alloc_range(size, PAGE_SIZE, 0, PFN_PHYS(max_pfn));
-	if (WARN_ON(!phys))
+	numa_distance = memblock_alloc(size, PAGE_SIZE);
+	if (WARN_ON(!numa_distance))
 		return -ENOMEM;
 
-	numa_distance = __va(phys);
 	numa_distance_cnt = nr_node_ids;
 
 	/* fill with the default distances */
-- 
2.28.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923074335.12583-2-rppt%40kernel.org.
