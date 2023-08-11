Return-Path: <kasan-dev+bncBDE6RCFOWIARBG5226TAMGQE6GVL6CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 62C777787CA
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 09:02:53 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-4fe275023d4sf1631330e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 00:02:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691737372; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sz5drp5AcKyNetjcxE0tyLpjhH7RcmBfBqriZnbvnZWGMcwmLfWnyua9OVC3cCVmgn
         oTh7Q/pRbp3dKMjfOy64AQWOHW7ejvknkAVMVCElVupUqyrjUzwuG2J341mo++c4cC5b
         85g8HTXkBNS2pVtQjffesQrUTquS5OwWAe/R45jVTNIHAK9/l7FLjDOLEP9yRUz0mpQ2
         kDKC1dJUWlcoEVAKn0yhcmuaz8b3CPkQP1SF3zacBuhMb9r+yP2jLS3ZILnWuMwvB6VQ
         VNskxu7Xf6NvZdlJxQrndQD8va9bs4p0jDXQCsG/CGAyOVH1Dww91i3SyY568a5/dNnH
         Bg7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:message-id:mime-version
         :subject:date:from:sender:dkim-signature;
        bh=RVZN50H2HxH/Sq77l6ryxpIyd+BjWod3Q9iTmmhyAx4=;
        fh=bkz5WMKprMAQgnPwdeYExW2THdr6ufWqpXcv3y7JC7A=;
        b=tTvSqw3v+UdsJKDIuDIZLOjuWvWv3KdEbGeoRTaxIADml33T+tp2LZQKu4G7ADmZQk
         lTEW8xpKPk+cUaLtWu+CaPdX5PQRGplo2xe4xKAEsdmbJyY6fQZCYI0pI5zkQ7Q/ghEf
         23WG6oN2uKxVloYU0XXF2ZsAcGc3S9sX+ivKvHaHGuzIq1iVA3t/WWeq1tEWT9R8udkU
         w7m40e9dHg+lNv4J44qhbVlWEJy50cF2DihzacfKYevEcf6Ad0TIpOp2E4YtvwuMMtGZ
         0J2PZJ92wQpSstRUsTHSFFqcvtBoTcqE0JLrbj8AozaEctzB1yAbMGMW3Uo1G7tJzdvr
         vgmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="P5Uqw3+/";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691737372; x=1692342172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:message-id:mime-version:subject:date:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RVZN50H2HxH/Sq77l6ryxpIyd+BjWod3Q9iTmmhyAx4=;
        b=Xmow9OX97+Z+mhcxM77sMZm5KR1N7Ipg9dO/dL9nyUwfdqnforOLUldBRsCRCo8CRj
         FFAlmLuVUAkgKMh4pWv7AEPnrKBimX37jQ2auUgnB7TtcB7l9b7xN3X9M356UiUEy2D9
         fZKaZj6YMJZ2LGj1mhQE1bj6thNYRKEGdoPTwut9SDOazXdyiCoBx76gpP2D5NSuOqcr
         foYQo3+MLWFl4hMn6IgxPDurjxEMS144Dq1VTuf/kviFJbqb9IFi7r8RMz3ui5POyWJC
         UIKsly83AmsLYzsmI2NqXwJcKR1xBa4ZFMAPxRa9M4SynTahAP4Szlr9Q8LZrFV2SyzO
         GmNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691737372; x=1692342172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RVZN50H2HxH/Sq77l6ryxpIyd+BjWod3Q9iTmmhyAx4=;
        b=fx7Vjjdf7OTIT12uXKrQ8ZSZLYash+IAmstu6ozLE4TVAoJfIt2sLv6/p/ZQhgq4Ih
         I/fTZtc1fsagVOjqhMHdmCWKRFSp4pevkgdHhMUVookw/oZUsUYa9cNlm2tXAKfE9bFO
         FWrJPKAF8Np2EJHH/s/45c08vh7gDoRJ+Cio/BG5rrXnf2lc/eaxNSu5ZGc7w89HNdj2
         cZiV/a7zFTfK53ZwSK0SzVWp8i7ffGSU4vrqeK5uQvmP0exLWP1uuMgMLs3OeNLRIKTU
         1a3Ke9sD69moJH1HSk2ZXdV/7drE2OXtv+XBjpTgYx8tICbRYMnD2MFyc66qa9MdxNls
         oZvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywjirg81CtG6aCYMwRJuKnNhg4rw++Kqj6DtkobR9Y9CIbieiZy
	YMM+Vxz7LO3utd+hayQ+3E0=
X-Google-Smtp-Source: AGHT+IFQIlpH7UMqZnjKf8++vlOkcxPRpI9UniJ3XLhrKDYWsi/Rw4isQlCIhRYCMsB4pQ/RgZwRrQ==
X-Received: by 2002:a05:6512:3da4:b0:4fe:5654:9d00 with SMTP id k36-20020a0565123da400b004fe56549d00mr697348lfv.48.1691737371626;
        Fri, 11 Aug 2023 00:02:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:34c5:b0:3fe:22c6:fcc7 with SMTP id
 d5-20020a05600c34c500b003fe22c6fcc7ls814611wmq.1.-pod-prod-06-eu; Fri, 11 Aug
 2023 00:02:49 -0700 (PDT)
X-Received: by 2002:adf:f788:0:b0:314:dea:f1f8 with SMTP id q8-20020adff788000000b003140deaf1f8mr680428wrp.11.1691737369846;
        Fri, 11 Aug 2023 00:02:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691737369; cv=none;
        d=google.com; s=arc-20160816;
        b=I6M+A14edBMBPELr+JAhCwCVgb47/dgE7z2y1X166YM1tbtwh/WMU4WByChq5ggsFh
         rw5MZAMDSERjF694/AFs8ihQJqYxvZddV55xNz89ZGWVoMvdirYkfHukm09Fyk8yg3ur
         ClxLpk3G+6fMQBE5gRGaoUCRRqd4f4HB98rrK4/6sdhvdL2R2NHjRMyDCYY5A4rhqeAd
         gYezR3twnVtLRmKX1H+JKfQhxdxiIQf0LNhAGBVgr5gZhi49Gy+V34+D+mVmug5s0qDx
         /IGcD/O2KY0U39KJs1HA5eEuTCdJkOtlvd0WAN82GkMu78wCCN2/3ZVz1BYcEhtZPxpB
         EbMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=YNg4syLFgaV0/aVnuzeWWgXpnl+cr4G1njIJ8+UBVvM=;
        fh=bkz5WMKprMAQgnPwdeYExW2THdr6ufWqpXcv3y7JC7A=;
        b=opcrqV3iCs4u35oM/+d1MlVPeqP/P9tuWPqcLu8asGfSNWTpC7OquWudKqYO8HHTUi
         LXxz90AOz/RW8ouSgTMxvcZIyZr4+z2LL6FJlV/5j/b2T1xES5NvC09oLusqPyzVIcsz
         lUAdi6i2RXNvNq5vMBEzkQjlUZPoJCkC2jo+84/P91yX/QvEmuJb9h5Fti4ELH4xM+gv
         BpWRWwhm+3VM5RNTCe1bHjmUCH1A3EFkzc4crz0RG/gKACkomnpT2z49SXJvKsw6EcaF
         8D3GyCT5UGmK7Mq83wUSID7WX8HKfQhxb+bo4B9xehNFuRqC7RQ9J2qijTaqodDS8uEM
         /lzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="P5Uqw3+/";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id k8-20020adfd228000000b0031596f8eeebsi266684wrh.7.2023.08.11.00.02.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Aug 2023 00:02:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id 38308e7fff4ca-2b9ba3d6157so25670401fa.3
        for <kasan-dev@googlegroups.com>; Fri, 11 Aug 2023 00:02:49 -0700 (PDT)
X-Received: by 2002:a05:651c:217:b0:2b6:e78e:1e58 with SMTP id y23-20020a05651c021700b002b6e78e1e58mr863999ljn.5.1691737369167;
        Fri, 11 Aug 2023 00:02:49 -0700 (PDT)
Received: from [127.0.1.1] ([85.235.12.238])
        by smtp.gmail.com with ESMTPSA id h4-20020a2e9ec4000000b002b70aff9a97sm728848ljk.16.2023.08.11.00.02.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Aug 2023 00:02:48 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
Date: Fri, 11 Aug 2023 09:02:47 +0200
Subject: [PATCH] s390/mm: Make virt_to_pfn() a static inline
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20230811-virt-to-phys-s390-v1-1-b661426ca9cd@linaro.org>
X-B4-Tracking: v=1; b=H4sIABbd1WQC/x3MQQqAIBBA0avErBswRbCuEi0sx5xNhRNSRHdPW
 r7F/w8IZSaBoXkgU2Hhfavo2gaW5LeVkEM1aKWNcqrHwvnEc8cj3YJieoU6ehOMm52zFmp3ZIp
 8/c9xet8PXOY11GMAAAA=
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
 Vasily Gorbik <gor@linux.ibm.com>, 
 Alexander Gordeev <agordeev@linux.ibm.com>, 
 Christian Borntraeger <borntraeger@linux.ibm.com>, 
 Sven Schnelle <svens@linux.ibm.com>, 
 Gerald Schaefer <gerald.schaefer@linux.ibm.com>, 
 Vineeth Vijayan <vneethv@linux.ibm.com>
Cc: kasan-dev@googlegroups.com, linux-s390@vger.kernel.org, 
 linux-kernel@vger.kernel.org, Linus Walleij <linus.walleij@linaro.org>
X-Mailer: b4 0.12.3
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="P5Uqw3+/";       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Making virt_to_pfn() a static inline taking a strongly typed
(const void *) makes the contract of a passing a pointer of that
type to the function explicit and exposes any misuse of the
macro virt_to_pfn() acting polymorphic and accepting many types
such as (void *), (unitptr_t) or (unsigned long) as arguments
without warnings.

For symmetry do the same with pfn_to_virt() reflecting the
current layout in asm-generic/page.h.

Doing this reveals a number of offenders in the arch code and
the S390-specific drivers, so just bite the bullet and fix up
all of those as well.

Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
 arch/s390/include/asm/kfence.h |  2 +-
 arch/s390/include/asm/page.h   | 12 ++++++++++--
 arch/s390/mm/cmm.c             |  2 +-
 arch/s390/mm/vmem.c            |  2 +-
 drivers/s390/block/scm_blk.c   |  2 +-
 drivers/s390/char/vmcp.c       |  2 +-
 6 files changed, 15 insertions(+), 7 deletions(-)

diff --git a/arch/s390/include/asm/kfence.h b/arch/s390/include/asm/kfence.h
index d55ba878378b..e47fd8cbe701 100644
--- a/arch/s390/include/asm/kfence.h
+++ b/arch/s390/include/asm/kfence.h
@@ -35,7 +35,7 @@ static __always_inline void kfence_split_mapping(void)
 
 static inline bool kfence_protect_page(unsigned long addr, bool protect)
 {
-	__kernel_map_pages(virt_to_page(addr), 1, !protect);
+	__kernel_map_pages(virt_to_page((void *)addr), 1, !protect);
 	return true;
 }
 
diff --git a/arch/s390/include/asm/page.h b/arch/s390/include/asm/page.h
index a9c138fcd2ad..cfec0743314e 100644
--- a/arch/s390/include/asm/page.h
+++ b/arch/s390/include/asm/page.h
@@ -191,8 +191,16 @@ int arch_make_page_accessible(struct page *page);
 #define phys_to_page(phys)	pfn_to_page(phys_to_pfn(phys))
 #define page_to_phys(page)	pfn_to_phys(page_to_pfn(page))
 
-#define pfn_to_virt(pfn)	__va(pfn_to_phys(pfn))
-#define virt_to_pfn(kaddr)	(phys_to_pfn(__pa(kaddr)))
+static inline void *pfn_to_virt(unsigned long pfn)
+{
+	return __va(pfn_to_phys(pfn));
+}
+
+static inline unsigned long virt_to_pfn(const void *kaddr)
+{
+	return phys_to_pfn(__pa(kaddr));
+}
+
 #define pfn_to_kaddr(pfn)	pfn_to_virt(pfn)
 
 #define virt_to_page(kaddr)	pfn_to_page(virt_to_pfn(kaddr))
diff --git a/arch/s390/mm/cmm.c b/arch/s390/mm/cmm.c
index 5300c6867d5e..f47515313226 100644
--- a/arch/s390/mm/cmm.c
+++ b/arch/s390/mm/cmm.c
@@ -90,7 +90,7 @@ static long cmm_alloc_pages(long nr, long *counter,
 			} else
 				free_page((unsigned long) npa);
 		}
-		diag10_range(virt_to_pfn(addr), 1);
+		diag10_range(virt_to_pfn((void *)addr), 1);
 		pa->pages[pa->index++] = addr;
 		(*counter)++;
 		spin_unlock(&cmm_lock);
diff --git a/arch/s390/mm/vmem.c b/arch/s390/mm/vmem.c
index b26649233d12..30cd6e1be10d 100644
--- a/arch/s390/mm/vmem.c
+++ b/arch/s390/mm/vmem.c
@@ -36,7 +36,7 @@ static void vmem_free_pages(unsigned long addr, int order)
 {
 	/* We don't expect boot memory to be removed ever. */
 	if (!slab_is_available() ||
-	    WARN_ON_ONCE(PageReserved(virt_to_page(addr))))
+	    WARN_ON_ONCE(PageReserved(virt_to_page((void *)addr))))
 		return;
 	free_pages(addr, order);
 }
diff --git a/drivers/s390/block/scm_blk.c b/drivers/s390/block/scm_blk.c
index 0c1df1d5f1ac..3a9cc8a4a230 100644
--- a/drivers/s390/block/scm_blk.c
+++ b/drivers/s390/block/scm_blk.c
@@ -134,7 +134,7 @@ static void scm_request_done(struct scm_request *scmrq)
 
 		if ((msb->flags & MSB_FLAG_IDA) && aidaw &&
 		    IS_ALIGNED(aidaw, PAGE_SIZE))
-			mempool_free(virt_to_page(aidaw), aidaw_pool);
+			mempool_free(virt_to_page((void *)aidaw), aidaw_pool);
 	}
 
 	spin_lock_irqsave(&list_lock, flags);
diff --git a/drivers/s390/char/vmcp.c b/drivers/s390/char/vmcp.c
index 4cebfaaa22b4..f66906da83c4 100644
--- a/drivers/s390/char/vmcp.c
+++ b/drivers/s390/char/vmcp.c
@@ -89,7 +89,7 @@ static void vmcp_response_free(struct vmcp_session *session)
 	order = get_order(session->bufsize);
 	nr_pages = ALIGN(session->bufsize, PAGE_SIZE) >> PAGE_SHIFT;
 	if (session->cma_alloc) {
-		page = virt_to_page((unsigned long)session->response);
+		page = virt_to_page((void *)session->response);
 		cma_release(vmcp_cma, page, nr_pages);
 		session->cma_alloc = 0;
 	} else {

---
base-commit: 06c2afb862f9da8dc5efa4b6076a0e48c3fbaaa5
change-id: 20230809-virt-to-phys-s390-2fa3d38b8855

Best regards,
-- 
Linus Walleij <linus.walleij@linaro.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230811-virt-to-phys-s390-v1-1-b661426ca9cd%40linaro.org.
