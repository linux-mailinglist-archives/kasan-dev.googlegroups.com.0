Return-Path: <kasan-dev+bncBDE6RCFOWIARB6OC32TAMGQEZ6JRX2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E5FF77A0B1
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Aug 2023 17:12:59 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id a640c23a62f3a-99c01c680besf186538766b.2
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Aug 2023 08:12:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691853178; cv=pass;
        d=google.com; s=arc-20160816;
        b=RG2qaBQGAam2ANOnGFjpeXQ6FWX8cTDIGJJTqRur7sSfPll26O9TN7T9pckLfXfuW8
         2d2mZTGaabLYbH3/46s8gxzYd9hNivCALB4HTWFAKAM4mGnh7VJLRfOWwtkY0QRC4d3l
         bsTs5Hn4DzFR4j8cLC6gwsXThrR3PcbEeDxz76xhJa2lx9OtfQsT+1CDrpVuTF7YFkTi
         96ZBnzFdX4brp0UJ3FMtWJppwCdSqXGRcEANa9cx4YpiTRk58p4zjrudoxnWUjEFKsZ0
         xWTA4FQELCdyP9oFljTxqFAsdhEhYnqThSuihy8oFJiCu0stGKud44aTO/e3SfEwsGdu
         j3og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:message-id:mime-version
         :subject:date:from:sender:dkim-signature;
        bh=Ub+ZNTV69ejzd/EiZR2XxMyCQCLmy+0Eahf+TKIeHXc=;
        fh=bkz5WMKprMAQgnPwdeYExW2THdr6ufWqpXcv3y7JC7A=;
        b=vgx6RrOEyrhyxguOr+1OdSm/6xEvNyHKDDdT6FTDc2NBX1KA4Hs2ttjsklUNSNfNwy
         FHDZ8Dsxnsa+DYxokxFaeaXhBOAmNowRIiC5N4pD4P7QcCsqjUXTbYjFt6DFjs6iyhDE
         n6F5x1NPqalYiPheQsoCiW28/Bkydhc9DoMlucNyL9FD5KZApzM8JSyNjPLEXFl4wp3z
         dFWm45w7RDiVABGB0YxwTerSGtwHM8Fhxr8t0N+0Q8YO5BtDiY5Qb8rKC+llsi3mPStB
         s52wEUvuoqMUHHLvK4EI2OdSbLKugLxEQH2zb0qssdj8WdHRH5rFG0W4h8I7rQQ9ppqq
         Pevw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=yEzXdnma;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691853178; x=1692457978;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:message-id:mime-version:subject:date:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ub+ZNTV69ejzd/EiZR2XxMyCQCLmy+0Eahf+TKIeHXc=;
        b=rZ+NBqY2qWRihtCi9mqYt5iWSP/2F41E5vBQ5XseDvVr/AkE53KC5SFR3XNYsmvg6p
         FU6gxqDkARarv48JcBrtmtPOIEUysr0v+K69bBkXz+4kVYeP10AY3UBw/fJYHd8KrxZT
         VWJitSYaLWZ5l96GWVX8UM7yrAIGHdUIr557MkcWIE/OMYUiR2X8BtQ90tCa5ze4SSlv
         tf2JndjpoBALsqpOaWiz62YkLaXI9g/vjWwCTlTckew3rscAAOrQBzSZHYFDeNBfZ59R
         f8kw8zRYTn22tN1RIABdKRh1ByKSvHRoZZ+25sZAE3DtnqjnQfJbHli0zTfE7TurpQWF
         xLIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691853178; x=1692457978;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ub+ZNTV69ejzd/EiZR2XxMyCQCLmy+0Eahf+TKIeHXc=;
        b=PbfDS/xehUjzRWHDWszu8zu8LNLD94XF8ZXDyLZd9sNYzUI+2pWC+vpm2N/Eg8OMyr
         IsWSopEzSrsdOOXvu8tTpYMp+QFw/IVkcTtE2B/zH8R3SgAkPwTpjpLcLtYpYc1KQfd9
         8eZUN3CHln80YVwEisKzDNXIvo3+4m7IUzmXJyh41Yph/q0oVpxmQ1SgMmwRC9MKAC4r
         s8E00f3+/Y8cOG+Jvs7nL1mWiPaKqLRIGDd+XH+0hpCR8cGiMQr1kWtay2ABiNBBn+Y0
         Bk3JRkvsFOZO8jvXG/BUbQBGIsroNpep7upSzPJGAKLZrMcn4nRDM/8cpJATca5c6GB0
         IAtw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwxwTAkaoN5G1kveo+PuVFTlgzyRY3YoUpG3KbGzF8CecXJX4WD
	PS3++vCEux2M3HugFlHvKzk=
X-Google-Smtp-Source: AGHT+IF8cqPFexZuw58XlzatzUs8/1bFZvbCHChm8ayZDoLn8VzM219rTQlmpB0wbaRQahXv/UYpmw==
X-Received: by 2002:aa7:c695:0:b0:523:47b0:9077 with SMTP id n21-20020aa7c695000000b0052347b09077mr4381753edq.38.1691853178190;
        Sat, 12 Aug 2023 08:12:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:ce13:0:b0:522:3a21:f230 with SMTP id d19-20020aa7ce13000000b005223a21f230ls114412edv.1.-pod-prod-09-eu;
 Sat, 12 Aug 2023 08:12:56 -0700 (PDT)
X-Received: by 2002:a17:906:3013:b0:991:d05c:f065 with SMTP id 19-20020a170906301300b00991d05cf065mr4494721ejz.52.1691853176382;
        Sat, 12 Aug 2023 08:12:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691853176; cv=none;
        d=google.com; s=arc-20160816;
        b=l0IVD/ito9eMgqamtZX5sxQeay9pRq6pxaigccf0FVdHFtayxWtdNC2PLK0Yfr/7FJ
         nMZ3CH/EXXZ6IcmPlgDYzd7bwFJPLL8eRg/hDduXtVXmWc2KPIUVClyLP5BSFC6yc5lN
         CNlvtboMKJA/iwjJBcbawYZ9D6Dc1cdUYZYFgRb//LLFinKyzv1zuPYrKmBFMmcT1Iop
         xK7zr/1TW09Br+szMxQKwvLStatJ7/TWy4em+ol2xdeC4XGLgToYgydCFAgt/N6Px6w+
         PblrTXHL/NQKlkWAg8/vRKifKP8XcKkR63JYR/ACSh8rjfvXawSXvLdQVGvw4Ue40jG/
         Unag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=ws6iiiqipdTFS/mQpEmQJn0yYytb6SIvgYMxTasFi7k=;
        fh=bkz5WMKprMAQgnPwdeYExW2THdr6ufWqpXcv3y7JC7A=;
        b=FN65yNQHP3i2mHsuNbwf9OyQe1fZPwPNCW+ypL+rSszmsaUez0qV0eYH7Op4sGM/n3
         /LRLwwzj4V8HVdppNABb+dMV/jp/oONT43ubETTDquA/BXDkDcxrOY2ahYKJZ+knoVJp
         rDGpQjQpGxQ9CUrhWCMI4POQiWHPTsW5Cqd3LCGw8y7hk9CrHLq6sUBn+CEJTkWVMY4X
         vP/WcAKceV7doN3cX0g18khhHuQgR6MeAenSVfAVYmiAWJXLBVx4jvaQpvYQllFJrSZH
         QyeHhxaM1FfXHDK/pfToTblPU/hJtMJN61Lu5Giaczsw4js+dOSljlL5XBJ91FvqFLIB
         iD5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=yEzXdnma;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id ty18-20020a170907c71200b0099c3ca79cd6si596624ejc.2.2023.08.12.08.12.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 12 Aug 2023 08:12:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id 38308e7fff4ca-2b9c907bc68so43325711fa.2
        for <kasan-dev@googlegroups.com>; Sat, 12 Aug 2023 08:12:56 -0700 (PDT)
X-Received: by 2002:a2e:a0c7:0:b0:2b6:9bd3:840e with SMTP id f7-20020a2ea0c7000000b002b69bd3840emr4034308ljm.21.1691853175653;
        Sat, 12 Aug 2023 08:12:55 -0700 (PDT)
Received: from [127.0.1.1] ([85.235.12.238])
        by smtp.gmail.com with ESMTPSA id n15-20020a2e86cf000000b002b9b90474c7sm1396506ljj.129.2023.08.12.08.12.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 12 Aug 2023 08:12:54 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
Date: Sat, 12 Aug 2023 17:12:54 +0200
Subject: [PATCH v2] s390/mm: Make virt_to_pfn() a static inline
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20230812-virt-to-phys-s390-v2-1-6c40f31fe36f@linaro.org>
X-B4-Tracking: v=1; b=H4sIAHWh12QC/22NywqDMBBFf0Vm3Sl51BC76n8UFzFGHShGJhIq4
 r83lS67PAfuuTukwBQS3KsdOGRKFOcC6lKBn9w8BqS+MCihtLCiwUy84hpxmbaESTcC1eB0r21
 nbV1D2S0cBnqfzWdbeKK0Rt7Oiyy/9leT8k8tS5TYGSNvynjX+P7xotlxvEYeoT2O4wNh4g99s
 wAAAA==
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
 header.i=@linaro.org header.s=google header.b=yEzXdnma;       spf=pass
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
Changes in v2:
- Just drop the cast to (unsigned long) in drivers/s390/char/vmcp.c,
  we do not need to cast to (void *) from (char *), a pointer is
  a pointer.
- Link to v1: https://lore.kernel.org/r/20230811-virt-to-phys-s390-v1-1-b661426ca9cd@linaro.org
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
index 4cebfaaa22b4..eb0520a9d4af 100644
--- a/drivers/s390/char/vmcp.c
+++ b/drivers/s390/char/vmcp.c
@@ -89,7 +89,7 @@ static void vmcp_response_free(struct vmcp_session *session)
 	order = get_order(session->bufsize);
 	nr_pages = ALIGN(session->bufsize, PAGE_SIZE) >> PAGE_SHIFT;
 	if (session->cma_alloc) {
-		page = virt_to_page((unsigned long)session->response);
+		page = virt_to_page(session->response);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230812-virt-to-phys-s390-v2-1-6c40f31fe36f%40linaro.org.
