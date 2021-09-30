Return-Path: <kasan-dev+bncBDOY5FWKT4KRBHUO3CFAMGQEUIKSG4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F1D341E18F
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 20:51:12 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id k4-20020a170902c40400b0013e3be99481sf3818756plk.23
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 11:51:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633027871; cv=pass;
        d=google.com; s=arc-20160816;
        b=LQLGbdY+6cuufxC4tvI45lgCdOaqFkodoJKytFOZhdIzggfQ9qgPpBlsArJmpeV5VB
         msznCfuqeEVCQrI2NqWQ+jwil0OF6ZF1DNi4GP6KcIQ/IwiITsSMUoDpjQtUw2SEV58l
         lBXBZDyO4LYmWtrQjriLQJaN387ufoe9rgpYH04/DPE90LgMpzUOLCubdkgspk595cfa
         Hocgn7uR5K2O5JvqFwsuGHCe9sMbMJ0pQ0hBvkayKqWtCQ1ZtQo7BGLpAZWarEL0NGXE
         ipD7BKPOFyoPqBkplzqQbw/sLWj5+F6b2FmtqXW5s9/vkYk+arNzAtLMnvAgud1nBv5F
         MwpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=t4dqSoPwR2YeMeYtkpiKTkodp0zmYPCsrx2VWJyufcA=;
        b=PVUYP0UN2j/zyeSXcrUNcDtGJeL1C7JCaKTSDr7YxzT8f/sCkc1uJUbGn0EXSUKT0M
         eNN0/CVE1xwhjC1ZS5X96bhCl3Qwz2bFsVUDh+ZRGiUvVfRDtdy54dBWfcBXxrCPt2Dk
         iVuOVRKcUEKxZxZZpuAxyxuCk4UlHTFVypjMFHrl9SZlF3JDUXqt7tnzt59Bqejl/Kxt
         7KuCDTdWwLVVd14YgReUT5ZhK72QEhQSruliD2hF3c1r/h+xwQvrzw6rgqbv3JjXar0m
         4Q1ZEE0lXIF/LPzbYcDgexWmC4TjwPROyJW7a4Qd4mS56S19eKEQv5YnCVF9o5LgcGXS
         S8Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dXxprhJQ;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t4dqSoPwR2YeMeYtkpiKTkodp0zmYPCsrx2VWJyufcA=;
        b=qAgcCxK/IVsSYz2WHybVzT3dz/y7uUOphGi1KVclX/SxILknhxJE2TxxE2LtcuW1Nn
         5D63jSQrPyJgB300hp1m4FMOZ6BcXBatXAJlHgnrNzX9rduBq3LRcEoVJU7hKuC7hk23
         Ab2GcnfPTn8WyGCGNQlUb/XWWRX9HnzQ0iZ67LhAkZqIXCt/Raco+WbeDjvrkZ44WwzH
         1jsF6ZVSV+tMXRJ+XB8vk4OXLpbTWfWcy3OJ0Z3ZBreGEMcAyQ2gk2YQT7eKtLcx19OC
         YiszQuFYQd0A5fLpNlumBQ0Xx8tSpP1LS3b1ZafoRPIBSdY7UDJhMcCf0LCO7/rmtbr5
         G0BQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t4dqSoPwR2YeMeYtkpiKTkodp0zmYPCsrx2VWJyufcA=;
        b=5Io11KVvDF6PYs4V870BIWvESkVua84m3AKNyUueTarE9TPi8oMQ8t2Cn6hnE+hQYn
         PrXzDQCwQT+K2zB4irHF4u7XrmeuAw1ytF+FCmqCHsmI4RjJr2AxFWAFHgeJz9H5o6P2
         quWcD36eXMSFFY6e3gdgHcrQp4BP8SswAPdhZKk4ozfYFa2wclw2OAVcop7QTGbFbkW9
         ZNjU1+TMYxL0NQxpUJ00c642HTYbloSu7wFXKY3SzHyzZkaQz9toZ0hwzHBhARkIEmK6
         ojMzO00Wx+HR/B1rt2VRMVnWh9xzKLDAChGj92hHb8VlYdUCCNOGLfBvq2q+kxRPDora
         qRYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+uuuyhvdPVR1mGlvRfVcEUEvbObF0m3N1Zqd1Dd9EV6ekI1sZ
	E9q14QPdfZIhl83MF2+3AiU=
X-Google-Smtp-Source: ABdhPJy6+wVeTql826B1fCsXKmGrVBXhzHXsreeHYbn+Lid+jxu5Z9+KrC0T7rBy3UVZU4i9gjSpSQ==
X-Received: by 2002:a63:4e45:: with SMTP id o5mr6393244pgl.191.1633027870877;
        Thu, 30 Sep 2021 11:51:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ac9:: with SMTP id r9ls3924036pje.1.gmail; Thu, 30
 Sep 2021 11:51:10 -0700 (PDT)
X-Received: by 2002:a17:90a:a88a:: with SMTP id h10mr8154059pjq.226.1633027870248;
        Thu, 30 Sep 2021 11:51:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633027870; cv=none;
        d=google.com; s=arc-20160816;
        b=WnUYlLwSZLvxgVW8JE6uzfkQU9ELjxTJQKCUxvIi0W0SHGYGQ+buO+zGxWtAApFsKT
         izx8e2p1nPYGs0aW1XFvqzF/7afwZXzCw+LnQsa9cxVkj9Q5msiDCkIwfOAuzSyiIzBu
         cmi6r+Qwdyw0o6sISJy7GoSmcfA5ViDeggi8mmqS7er4LWKQFkEh2Wy/C5wCzaPafjYK
         6tcVh5wDlxUhQYihDbX+DfC4HckdHvLLjEhAF+LD8yKNy2cI7tncaCeg57jL2agvwftT
         GRqaLFXQq6m5KBTp/9fFnv+UbBnYSPfWMb7xAJYpjUvTCtEO8W9Dkl/IBWPlDmetm6Ly
         HeBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=E2I4OaWVQJ9dQqbw5jho5yXohmBY7XdEVzV4KjJdDgw=;
        b=m+mgi0f3KH2+/4gzmrIqbfvwbJleyjZXk3mMGB/8u5xIj5aAY1Di+X7qz18n47oola
         tdasm9SC1ogkNlwrofiCPXNH8Kbs45TY1DKeXu82hevbgfBzoY7ZrFu4g3qVaqX44gu2
         MbcO6++b0/Xww9LZUu0WyS3epBtYClOFjtWV831shdrMCRXSaO0aCJmmzmWaQW3Gjtoj
         AEigtxKd+P8NXMpC/W57pTYve46Qa8sBgn6oW6BwrJLKm4Vnnd+KAbrRkt2ELMwb+kZf
         UgQm0yG3Vd20DpbFeiMS4hKU+QSN0ccyF4C9aTEscaRyiHIZkEZK2gIv9mc6OtmHR4lx
         /UiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dXxprhJQ;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v7si774864pjk.3.2021.09.30.11.51.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Sep 2021 11:51:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8A2FA613CD;
	Thu, 30 Sep 2021 18:51:03 +0000 (UTC)
From: Mike Rapoport <rppt@kernel.org>
To: linux-kernel@vger.kernel.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Juergen Gross <jgross@suse.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Mike Rapoport <rppt@kernel.org>,
	Mike Rapoport <rppt@linux.ibm.com>,
	Shahab Vahedi <Shahab.Vahedi@synopsys.com>,
	devicetree@vger.kernel.org,
	iommu@lists.linux-foundation.org,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	linux-alpha@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-efi@vger.kernel.org,
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
	xen-devel@lists.xenproject.org
Subject: [PATCH v2 4/6] memblock: stop aliasing __memblock_free_late with memblock_free_late
Date: Thu, 30 Sep 2021 21:50:29 +0300
Message-Id: <20210930185031.18648-5-rppt@kernel.org>
X-Mailer: git-send-email 2.28.0
In-Reply-To: <20210930185031.18648-1-rppt@kernel.org>
References: <20210930185031.18648-1-rppt@kernel.org>
MIME-Version: 1.0
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dXxprhJQ;       spf=pass
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

memblock_free_late() is a NOP wrapper for __memblock_free_late(), there is
no point to keep this indirection.

Drop the wrapper and rename __memblock_free_late() to memblock_free_late().

Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>
---
 include/linux/memblock.h | 7 +------
 mm/memblock.c            | 8 ++++----
 2 files changed, 5 insertions(+), 10 deletions(-)

diff --git a/include/linux/memblock.h b/include/linux/memblock.h
index fc8183be340c..e25f964fdd60 100644
--- a/include/linux/memblock.h
+++ b/include/linux/memblock.h
@@ -133,7 +133,7 @@ void __next_mem_range_rev(u64 *idx, int nid, enum memblock_flags flags,
 			  struct memblock_type *type_b, phys_addr_t *out_start,
 			  phys_addr_t *out_end, int *out_nid);
 
-void __memblock_free_late(phys_addr_t base, phys_addr_t size);
+void memblock_free_late(phys_addr_t base, phys_addr_t size);
 
 #ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
 static inline void __next_physmem_range(u64 *idx, struct memblock_type *type,
@@ -441,11 +441,6 @@ static inline void *memblock_alloc_node(phys_addr_t size,
 				      MEMBLOCK_ALLOC_ACCESSIBLE, nid);
 }
 
-static inline void memblock_free_late(phys_addr_t base, phys_addr_t size)
-{
-	__memblock_free_late(base, size);
-}
-
 /*
  * Set the allocation direction to bottom-up or top-down.
  */
diff --git a/mm/memblock.c b/mm/memblock.c
index 184dcd2e5d99..603f4a02be9b 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -366,14 +366,14 @@ void __init memblock_discard(void)
 		addr = __pa(memblock.reserved.regions);
 		size = PAGE_ALIGN(sizeof(struct memblock_region) *
 				  memblock.reserved.max);
-		__memblock_free_late(addr, size);
+		memblock_free_late(addr, size);
 	}
 
 	if (memblock.memory.regions != memblock_memory_init_regions) {
 		addr = __pa(memblock.memory.regions);
 		size = PAGE_ALIGN(sizeof(struct memblock_region) *
 				  memblock.memory.max);
-		__memblock_free_late(addr, size);
+		memblock_free_late(addr, size);
 	}
 
 	memblock_memory = NULL;
@@ -1586,7 +1586,7 @@ void * __init memblock_alloc_try_nid(
 }
 
 /**
- * __memblock_free_late - free pages directly to buddy allocator
+ * memblock_free_late - free pages directly to buddy allocator
  * @base: phys starting address of the  boot memory block
  * @size: size of the boot memory block in bytes
  *
@@ -1594,7 +1594,7 @@ void * __init memblock_alloc_try_nid(
  * down, but we are still initializing the system.  Pages are released directly
  * to the buddy allocator.
  */
-void __init __memblock_free_late(phys_addr_t base, phys_addr_t size)
+void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
 {
 	phys_addr_t cursor, end;
 
-- 
2.28.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210930185031.18648-5-rppt%40kernel.org.
