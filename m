Return-Path: <kasan-dev+bncBDZYPUPHYEJBBWE7Y2PAMGQEELGWOII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 2154E67BC7A
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 21:23:53 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id f17-20020ac25091000000b004b565e69540sf8571057lfm.12
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 12:23:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674678232; cv=pass;
        d=google.com; s=arc-20160816;
        b=TVnk+9Iep6D9iPv6M6TOwdEBMVwr0ssxweAaHSdI8Eqg2ZlZu51jfKD+AGrjZPgdlK
         CbT/4EBpwgchWmzhwo5T0wb6d5j1hAOZ3R+JKDvftW7Qee/hAMGqnoqadqsQXqWcm3wh
         VZpGTWfkOnI3AoT12YHnGoKJ9uxC3utIsG+GG2Og9jLdBvhL85zRkCeImzjjpzoZWLI+
         SW/rlHF1ldlXVZiSs6HTv2Q2mqqRonXrq8vSqRV68Y/igmYGP1ERVwoTOnsn2c5Kc+OS
         SWfrz6FCgJrYnwQWRu/E03QwcrWDqmfOalLQa90hn0Quv3oMDzYgXBPw49ib3Uf3dz8L
         BNtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :date:cc:to:from:subject:sender:dkim-signature;
        bh=aUZYfq3+KfOYJFtneXWGel+ogZgVUF1gWfqnbhp80DA=;
        b=d11RMJrYlkcUDlYPXLa6yBHYN0vvCCo+vjQh73FdH/jR2qS6qjC/gmoJCce0rXGrbO
         VND+pC5+F/+rnApdFv9+Uss7UoPRvvhx0zP03eyoq1T+9ZVLDceKFDOzUZMwtZrXifPf
         IZCYGR7DYI6j/FFqw2kIc3fqfmYFMOlfyL7fIg2oweg6KEI7uuKOU3qH+NymG2CtL2h5
         148FtnHC9QJDPPxxUrWUBNbZIUabMYTOBLkyuSrPAT2iahbgjJvMMX7eEItQAXHLB/L2
         4PDi+DMIA6PLfi8Pg0R1OkvDByroawIAm2O4rchRFoXBV46deLkK6YewG2PVcwWx/AHW
         tM7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=hIR5BfrM;
       spf=pass (google.com: domain of dan.j.williams@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=dan.j.williams@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:date:cc:to
         :from:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aUZYfq3+KfOYJFtneXWGel+ogZgVUF1gWfqnbhp80DA=;
        b=nEZv2Hs1ya17Fqm/wtzpIFfRdpy5iar5EKbLunKILOZqvWCrGgL0k/CjN1WQq/b1ei
         QnsC3BunkpTYCWWJeXrmjV0sta+9HrV8yf0Mreg1qiFAkjCnX/LPTat13YMoZY2n4+SN
         8uqBl+ifR4J5n4Y6weacJCF57hYcs0g5uHc8z2y56ad6iVcC1Fn4UcPBzzrtzzN/dl4y
         7La3lW288IZ5FcgklShSyMC/BmBlW7xMXMmwBYZ0Ddp4ojqF3xDQsjCQLixD6CvPZZe2
         6gJ2NaYEJPTeOPovv+MomQJLakHk1Fi0qBYEYBkjcrAlzmdBY1xYD9zU0GWwVJ/vwe5Y
         IyaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:date:cc:to:from:subject:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aUZYfq3+KfOYJFtneXWGel+ogZgVUF1gWfqnbhp80DA=;
        b=qEg5ePIwkqkNWXHyBu9B3SkhX9BSxndxo6suI3pwsaFJ0n8vpklDLb+cH7XULG4gRf
         DOHwNNVfU28av5Recpzjf9Rh8CI3336ZrfDC7Ge0rRqfXWpN6VrKSmT6grc7oY7oB4Xn
         WyQ2xARnIpgnwIZ0DPlbdlVPK/ujTTEBG5+RNbsi4blXDpQFDSwwu7eEja2AdC7IVACW
         PXKkemYf+U1pPl8NZ5wpzPOIfPFpv9KnnFkJ9SJ+6dMJZ44a1qSb2l/lZV7ASgOroKVO
         lU8k1+UwP00NPNXuWZRwlo2gv+bF2H1Vlc+Dbj+WZtzM+PlXQd6wIs7ZYcTxp//BFidT
         LAQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krfEGjZ24alOnvDrQB8KBhmqC1PUg6xtAzfIWHhC8LcVDsP8w4U
	K9chmZw146ATrYnsS8NxglA=
X-Google-Smtp-Source: AMrXdXvUUZ68DfYZhBa1mZht3uPQcqL8WcKo7+V1mra/cCO3I8QAm7t44/MFN4sXZq8ivo8vROiAdw==
X-Received: by 2002:a05:651c:10ba:b0:28b:8515:e148 with SMTP id k26-20020a05651c10ba00b0028b8515e148mr1779371ljn.62.1674678232330;
        Wed, 25 Jan 2023 12:23:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4891:0:b0:4d1:8575:2d31 with SMTP id x17-20020ac24891000000b004d185752d31ls10278lfc.0.-pod-prod-gmail;
 Wed, 25 Jan 2023 12:23:50 -0800 (PST)
X-Received: by 2002:a05:6512:1051:b0:4d5:a576:c20a with SMTP id c17-20020a056512105100b004d5a576c20amr7495550lfb.49.1674678230770;
        Wed, 25 Jan 2023 12:23:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674678230; cv=none;
        d=google.com; s=arc-20160816;
        b=Z8X5OGMNBoV7bru3puTqTmUHcjX57/Ps8z3s1JHp9QLu+JF0K+/RnDlb2Pi7XX0QzB
         Cw+bwJgc+sq8IiZjhklcJEaD6yHL8hI5dWG3ltlv27xzQYpgC3dvd4ziC1KdhwP5uPN/
         Ci7LK4yc4h71yPRtHIgi54qOtF9krxEYAvoPRNtVTKhFzT1X0KIsVNPGJHI2Zdu/J+6D
         EIxiWn57UST1cOhcbBky3LfkUsGmT2blobU39zDqT3OiKMFyPJ+ZwCwqSu+qMkQsFxWe
         ODd3BOHDx+hEHjkkqBDVxaasXSJV7CHMzbG7UBO/JiO+JiazHr/qOjV6MeFAZcWHbGIZ
         TfGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:message-id:date
         :cc:to:from:subject:dkim-signature;
        bh=o6j1C/IHvbeotIPotqfHYLhvi6MorDeRVA46Mhcvr18=;
        b=pVTsaSvPiR1sxsv82DDg6Z/MQmTFAJGAlt71PnYyT4dtIXHC55wTvSDwSfqYE2n4nS
         /pE6LcPS1bq1RlkTLUHn9RWVbkQB7gMAgMjkCBqhmRmnLM8Ni/wlQb3/KMl8Ak3JyEu7
         Y2aXayZqPqojh+Ni+DOnnPCmwylocXGsn1aml7W/4pGbWtpU89UBYENUZ1Ykbx6vcOpL
         W5YBu3aNpMpa78tJzV2HzgAzbhrsFeliKu+z2IdoMgEKG7RlJKTy5tirbiXFhrvpnAQo
         qntiQIyKtCa7ipy8CYzkg7RzyD8dOq8GiNNHd2rj6HruCol/vT70VGDd/9alA0JtqSxL
         NUtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=hIR5BfrM;
       spf=pass (google.com: domain of dan.j.williams@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=dan.j.williams@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id be40-20020a056512252800b004d5e038aba2si282307lfb.7.2023.01.25.12.23.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Jan 2023 12:23:50 -0800 (PST)
Received-SPF: pass (google.com: domain of dan.j.williams@intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6500,9779,10601"; a="307011724"
X-IronPort-AV: E=Sophos;i="5.97,246,1669104000"; 
   d="scan'208";a="307011724"
Received: from fmsmga001.fm.intel.com ([10.253.24.23])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Jan 2023 12:23:47 -0800
X-IronPort-AV: E=McAfee;i="6500,9779,10601"; a="805126312"
X-IronPort-AV: E=Sophos;i="5.97,246,1669104000"; 
   d="scan'208";a="805126312"
Received: from lwlu-mobl.amr.corp.intel.com (HELO dwillia2-xfh.jf.intel.com) ([10.209.17.213])
  by fmsmga001-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Jan 2023 12:23:46 -0800
Subject: [PATCH v2] nvdimm: Support sizeof(struct page) >
 MAX_STRUCT_PAGE_SIZE
From: Dan Williams <dan.j.williams@intel.com>
To: nvdimm@lists.linux.dev
Cc: stable@vger.kernel.org, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Jeff Moyer <jmoyer@redhat.com>,
 linux-mm@kvack.org, kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
 linux-kernel@vger.kernel.org, gregkh@linuxfoundation.org
Date: Wed, 25 Jan 2023 12:23:46 -0800
Message-ID: <167467815773.463042.7022545814443036382.stgit@dwillia2-xfh.jf.intel.com>
User-Agent: StGit/0.18-3-g996c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dan.j.williams@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=hIR5BfrM;       spf=pass
 (google.com: domain of dan.j.williams@intel.com designates 192.55.52.151 as
 permitted sender) smtp.mailfrom=dan.j.williams@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

Commit 6e9f05dc66f9 ("libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE")

...updated MAX_STRUCT_PAGE_SIZE to account for sizeof(struct page)
potentially doubling in the case of CONFIG_KMSAN=y. Unfortunately this
doubles the amount of capacity stolen from user addressable capacity for
everyone, regardless of whether they are using the debug option. Revert
that change, mandate that MAX_STRUCT_PAGE_SIZE never exceed 64, but
allow for debug scenarios to proceed with creating debug sized page maps
with a compile option to support debug scenarios.

Note that this only applies to cases where the page map is permanent,
i.e. stored in a reservation of the pmem itself ("--map=dev" in "ndctl
create-namespace" terms). For the "--map=mem" case, since the allocation
is ephemeral for the lifespan of the namespace, there are no explicit
restriction. However, the implicit restriction, of having enough
available "System RAM" to store the page map for the typically large
pmem, still applies.

Fixes: 6e9f05dc66f9 ("libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE")
Cc: <stable@vger.kernel.org>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Reported-by: Jeff Moyer <jmoyer@redhat.com>
---
Changes since v1 [1]:
* Replace the module option with a compile option and a description of
  the tradeoffs to consider when running with KMSAN enabled in the
  presence of NVDIMM namespaces and their local reservation of capacity
  for a 'struct page' memmap array. (Greg)

[1]: https://lore.kernel.org/all/63bc8fec4744a_5178e29467@dwillia2-xfh.jf.intel.com.notmuch/

 drivers/nvdimm/Kconfig    |   19 +++++++++++++++++++
 drivers/nvdimm/nd.h       |    2 +-
 drivers/nvdimm/pfn_devs.c |   42 +++++++++++++++++++++++++++---------------
 3 files changed, 47 insertions(+), 16 deletions(-)

diff --git a/drivers/nvdimm/Kconfig b/drivers/nvdimm/Kconfig
index 79d93126453d..77b06d54cc62 100644
--- a/drivers/nvdimm/Kconfig
+++ b/drivers/nvdimm/Kconfig
@@ -102,6 +102,25 @@ config NVDIMM_KEYS
 	depends on ENCRYPTED_KEYS
 	depends on (LIBNVDIMM=ENCRYPTED_KEYS) || LIBNVDIMM=m
 
+config NVDIMM_KMSAN
+	bool
+	depends on KMSAN
+	help
+	  KMSAN, and other memory debug facilities, increase the size of
+	  'struct page' to contain extra metadata. This collides with
+	  the NVDIMM capability to store a potentially
+	  larger-than-"System RAM" size 'struct page' array in a
+	  reservation of persistent memory rather than limited /
+	  precious DRAM. However, that reservation needs to persist for
+	  the life of the given NVDIMM namespace. If you are using KMSAN
+	  to debug an issue unrelated to NVDIMMs or DAX then say N to this
+	  option. Otherwise, say Y but understand that any namespaces
+	  (with the page array stored pmem) created with this build of
+	  the kernel will permanently reserve and strand excess
+	  capacity compared to the CONFIG_KMSAN=n case.
+
+	  Select N if unsure.
+
 config NVDIMM_TEST_BUILD
 	tristate "Build the unit test core"
 	depends on m
diff --git a/drivers/nvdimm/nd.h b/drivers/nvdimm/nd.h
index 85ca5b4da3cf..ec5219680092 100644
--- a/drivers/nvdimm/nd.h
+++ b/drivers/nvdimm/nd.h
@@ -652,7 +652,7 @@ void devm_namespace_disable(struct device *dev,
 		struct nd_namespace_common *ndns);
 #if IS_ENABLED(CONFIG_ND_CLAIM)
 /* max struct page size independent of kernel config */
-#define MAX_STRUCT_PAGE_SIZE 128
+#define MAX_STRUCT_PAGE_SIZE 64
 int nvdimm_setup_pfn(struct nd_pfn *nd_pfn, struct dev_pagemap *pgmap);
 #else
 static inline int nvdimm_setup_pfn(struct nd_pfn *nd_pfn,
diff --git a/drivers/nvdimm/pfn_devs.c b/drivers/nvdimm/pfn_devs.c
index 61af072ac98f..c7655a1fe38c 100644
--- a/drivers/nvdimm/pfn_devs.c
+++ b/drivers/nvdimm/pfn_devs.c
@@ -13,6 +13,8 @@
 #include "pfn.h"
 #include "nd.h"
 
+const static bool page_struct_override = IS_ENABLED(CONFIG_NVDIMM_KMSAN);
+
 static void nd_pfn_release(struct device *dev)
 {
 	struct nd_region *nd_region = to_nd_region(dev->parent);
@@ -758,12 +760,6 @@ static int nd_pfn_init(struct nd_pfn *nd_pfn)
 		return -ENXIO;
 	}
 
-	/*
-	 * Note, we use 64 here for the standard size of struct page,
-	 * debugging options may cause it to be larger in which case the
-	 * implementation will limit the pfns advertised through
-	 * ->direct_access() to those that are included in the memmap.
-	 */
 	start = nsio->res.start;
 	size = resource_size(&nsio->res);
 	npfns = PHYS_PFN(size - SZ_8K);
@@ -782,20 +778,33 @@ static int nd_pfn_init(struct nd_pfn *nd_pfn)
 	}
 	end_trunc = start + size - ALIGN_DOWN(start + size, align);
 	if (nd_pfn->mode == PFN_MODE_PMEM) {
+		unsigned long page_map_size = MAX_STRUCT_PAGE_SIZE * npfns;
+
 		/*
 		 * The altmap should be padded out to the block size used
 		 * when populating the vmemmap. This *should* be equal to
 		 * PMD_SIZE for most architectures.
 		 *
-		 * Also make sure size of struct page is less than 128. We
-		 * want to make sure we use large enough size here so that
-		 * we don't have a dynamic reserve space depending on
-		 * struct page size. But we also want to make sure we notice
-		 * when we end up adding new elements to struct page.
+		 * Also make sure size of struct page is less than
+		 * MAX_STRUCT_PAGE_SIZE. The goal here is compatibility in the
+		 * face of production kernel configurations that reduce the
+		 * 'struct page' size below MAX_STRUCT_PAGE_SIZE. For debug
+		 * kernel configurations that increase the 'struct page' size
+		 * above MAX_STRUCT_PAGE_SIZE, the page_struct_override allows
+		 * for continuing with the capacity that will be wasted when
+		 * reverting to a production kernel configuration. Otherwise,
+		 * those configurations are blocked by default.
 		 */
-		BUILD_BUG_ON(sizeof(struct page) > MAX_STRUCT_PAGE_SIZE);
-		offset = ALIGN(start + SZ_8K + MAX_STRUCT_PAGE_SIZE * npfns, align)
-			- start;
+		if (sizeof(struct page) > MAX_STRUCT_PAGE_SIZE) {
+			if (page_struct_override)
+				page_map_size = sizeof(struct page) * npfns;
+			else {
+				dev_err(&nd_pfn->dev,
+					"Memory debug options prevent using pmem for the page map\n");
+				return -EINVAL;
+			}
+		}
+		offset = ALIGN(start + SZ_8K + page_map_size, align) - start;
 	} else if (nd_pfn->mode == PFN_MODE_RAM)
 		offset = ALIGN(start + SZ_8K, align) - start;
 	else
@@ -818,7 +827,10 @@ static int nd_pfn_init(struct nd_pfn *nd_pfn)
 	pfn_sb->version_minor = cpu_to_le16(4);
 	pfn_sb->end_trunc = cpu_to_le32(end_trunc);
 	pfn_sb->align = cpu_to_le32(nd_pfn->align);
-	pfn_sb->page_struct_size = cpu_to_le16(MAX_STRUCT_PAGE_SIZE);
+	if (sizeof(struct page) > MAX_STRUCT_PAGE_SIZE && page_struct_override)
+		pfn_sb->page_struct_size = cpu_to_le16(sizeof(struct page));
+	else
+		pfn_sb->page_struct_size = cpu_to_le16(MAX_STRUCT_PAGE_SIZE);
 	pfn_sb->page_size = cpu_to_le32(PAGE_SIZE);
 	checksum = nd_sb_checksum((struct nd_gen_sb *) pfn_sb);
 	pfn_sb->checksum = cpu_to_le64(checksum);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/167467815773.463042.7022545814443036382.stgit%40dwillia2-xfh.jf.intel.com.
