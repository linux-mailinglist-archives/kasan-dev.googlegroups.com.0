Return-Path: <kasan-dev+bncBAABB2X2QOHAMGQEDRR4LXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 553CE47B5A0
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:02:19 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id w17-20020a056402269100b003f7ed57f96bsf8639281edd.16
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:02:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037739; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hi7k4byiao6+/8r1Sk1AHM5zKiAzCclGKqwJJBtw9ldWg9nw9IAkb7JlzWN6UfnVKy
         Q2Mp2nWTSESB7OsfzAj+4z8PkCjXgsCa4ctGMTi0EAHoEyHzJiBYp1ybonxMU8bErVmC
         miII+5ktg/LmI83RvtsWaIpEZHvTlJp7GsCTsREiPsZSPRBpwMzuLPKx9cAHmGkrgRnf
         Y9ogKybK2CblaQmoRG3FPlTmG98iuW3DiG7UNXbacPMQRYbrrwUbWGhm3/3nTl46f7bX
         F7yFEzpVsSLYF/+XV82pR4BoYSCe+HowHn0BQSPfXP3L+8GNuRV+lkOB1ALxXOX41JxY
         AHPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lj8pZ35J9IP+Gcus/xK2Y0HX9Qcklpd7z4zOdnEzdDY=;
        b=M7JLa++Fwmf0+TqlOxFmM9XG10xPwKpBBWSg08Z8cZxXK90aLq+3+BZddI05LmiLu4
         7FmmkQLzhhifFLKFwNmxt3Gt0D4dWNP7csWANodjVfQ3VEZRCc4oOmTEVfbFggY0AwGd
         6I2ZBrraebKDS5oS6CdQbYrIo/+N9bPm6thiJaxwx9VimGu1CLCdL2NIancEJUjcnxU2
         h5FXDwMuCX/VpGRqOgz8hlci1liGaxUmOhRSkUZWglcOHew63Ml9K5eO3B0ynvRunU3G
         O3CLy4qjgCHk0zGNxfOXCjYE9LBEJbrTto/69hl7WWt6Cke12gwMGNsyNEwXuWvVWpE0
         gtcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tto1+4+s;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lj8pZ35J9IP+Gcus/xK2Y0HX9Qcklpd7z4zOdnEzdDY=;
        b=UfwFtea/RFYPHDrc6EFpgLNnTOn4WMCa3HCxF7rqOZlPYpEqQXRFZ6mhYvmqxp4lfW
         cnNKmP+yk9nnTS0TYaKQEHJRROkHLh5/ypXAHMzKCRd32vuXiWuWl6fbMWka7C8kc6JQ
         mt+AoqAqnzvDOHDM2Dfs/urFr1vAE0eMEAm7wwScbvjOJMxIjdGZAh5Q1JDkrCEZclDd
         GRbpwkqqA6MeEACM7nreVue6C1T7vohLDR09rlPWc/WVYrKwob6zVAFewLR84cUf7uBi
         GfuGxm6XzJlSR0aOFpdw6eke4Zv01xTe646N15wf7xXeHLPmhxT7SurZiwP2k5KE7rCm
         25HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lj8pZ35J9IP+Gcus/xK2Y0HX9Qcklpd7z4zOdnEzdDY=;
        b=Y7REEP9+ngYlQNd9cyAd+yCudbYYQXTTApmNhcqJb6wSPAiDAxCz9UHM7rm7tOCEsU
         3eswH9HGYqqQieG3QCPOQIjNhh7vMfCcWuSovF4/IIMIgy1IT2U93UWcFACEoAQ00EhF
         voMICbUB44eDSKQ5y/Did9Mcdc0XxDOBuhUvwfvB7oN2VvH9BY1aZnLjD376ZehFNkqK
         WutVTdEhq4XQoSLlIEaTzvZcRURYF3EK0AocCh0we2k9PF+TwH630g7WIzW84DrN+uR5
         676k3aWx9NGo74dq7CCM/trBf8IdNd8bilrR14pS0J6i5VokUuwVbOXT7FQQNW5On0kM
         DyWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530MSEsGeDqswnkXOfaeud4XjQ6bNU4lXH2Vr354PGdp3YVi96eh
	jpORBHv+l8ZOUy6jImDLWHI=
X-Google-Smtp-Source: ABdhPJzTTm51UXQAlHQV+2Ccyx/xMdRcOLyFwg1SgMNPtDmz0Boi58AyTUDhqkCYEsdUcow9Trramg==
X-Received: by 2002:aa7:cc15:: with SMTP id q21mr155116edt.254.1640037739140;
        Mon, 20 Dec 2021 14:02:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:3e0c:: with SMTP id hp12ls1512459ejc.7.gmail; Mon,
 20 Dec 2021 14:02:18 -0800 (PST)
X-Received: by 2002:a17:907:9116:: with SMTP id p22mr158099ejq.744.1640037738387;
        Mon, 20 Dec 2021 14:02:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037738; cv=none;
        d=google.com; s=arc-20160816;
        b=uyksGFgE5OUc33WCpbhWjSuC8zbTHtE0e775vFJo5zjrTtliCCAeSgcpDZVUCQKYLa
         6F+Amklp5r71CRm439WJgY9+pOUsMoP9E89gJDihtY2s757bjKzhDnsyIpZHX9gNumbE
         qdDYMG4HJCxG8TAWvq8xVH+QPDvxWa4+wS99KpPnUx0GE5mYJTwbrAuhuJXApuEAIXLw
         QaBeBvfAunLNKIljr7oPLSfYeKcXMdnnhu/wERJAUugrdqb8PBSD99USJMxVcXI/YyJu
         43cLKwxtfwRzbB4g6VNUR3d0UtzmtTA0XC7wDE1erY5cVsRnM7rYWyRl1EpEu1rLKKvx
         zkZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ho5qbW7O219QsLiwx5Xou5YZAD5IzYuW6GA8zK8d5vQ=;
        b=Zs1lmt8f4yWHIFILtbhspFDrNFbgBPexvVOVITvaAVOuFdQGDphdPd/TmjM67HZCSH
         gHVtYRD1UC3YCkCJBA7cM1UI6+s9J7jt9IDOVGikz2JVr6/DeT4gJDnB0inXXV52C+Ar
         dNsoa0WPOv9d7n01mkVIz1OwVqpCDFSMH4M2SixShz0CXZN4YQw926+wSML+OMBSLTcN
         Nul5jKKdalApxiqJW6zp2Bl5B26AX+/s89iN9SljvpF0Qpnny4zmHcRxOOaan2cxS/rV
         4daf/wWCASh2RRjYyvNay7KIhlgm8WtUlFKzVd+bBigvi3BLCk8V8CZLYYQL7qOOMMM/
         NKlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tto1+4+s;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id bo19si591508edb.2.2021.12.20.14.02.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:02:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v4 25/39] kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
Date: Mon, 20 Dec 2021 23:01:57 +0100
Message-Id: <606f72fd9b51eb790d11cb2d0dc4ee4eeac864b2.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tto1+4+s;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

HW_TAGS KASAN relies on ARM Memory Tagging Extension (MTE). With MTE,
a memory region must be mapped as MT_NORMAL_TAGGED to allow setting
memory tags via MTE-specific instructions.

Add proper protection bits to vmalloc() allocations. These allocations
are always backed by page_alloc pages, so the tags will actually be
getting set on the corresponding physical memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

---

Changes v3->v4:
- Rename arch_vmalloc_pgprot_modify() to arch_vmap_pgprot_tagged()
  to be consistent with other arch vmalloc hooks.
- Move checks from arch_vmap_pgprot_tagged() to __vmalloc_node_range()
  as the same condition is used for other things in subsequent patches.

Changes v2->v3:
- Update patch description.
---
 arch/arm64/include/asm/vmalloc.h | 6 ++++++
 include/linux/vmalloc.h          | 7 +++++++
 mm/vmalloc.c                     | 9 +++++++++
 3 files changed, 22 insertions(+)

diff --git a/arch/arm64/include/asm/vmalloc.h b/arch/arm64/include/asm/vmalloc.h
index b9185503feae..38fafffe699f 100644
--- a/arch/arm64/include/asm/vmalloc.h
+++ b/arch/arm64/include/asm/vmalloc.h
@@ -25,4 +25,10 @@ static inline bool arch_vmap_pmd_supported(pgprot_t prot)
 
 #endif
 
+#define arch_vmap_pgprot_tagged arch_vmap_pgprot_tagged
+static inline pgprot_t arch_vmap_pgprot_tagged(pgprot_t prot)
+{
+	return pgprot_tagged(prot);
+}
+
 #endif /* _ASM_ARM64_VMALLOC_H */
diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index 34ac66a656d4..0dc02a688207 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -115,6 +115,13 @@ static inline int arch_vmap_pte_supported_shift(unsigned long size)
 }
 #endif
 
+#ifndef arch_vmap_pgprot_tagged
+static inline pgprot_t arch_vmap_pgprot_tagged(pgprot_t prot)
+{
+	return prot;
+}
+#endif
+
 /*
  *	Highlevel APIs for driver use
  */
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index c0985f74c0c1..388a17c01376 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3102,6 +3102,15 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 		goto fail;
 	}
 
+	/*
+	 * Modify protection bits to allow tagging.
+	 * This must be done before mapping by __vmalloc_area_node().
+	 */
+	if (kasan_hw_tags_enabled() &&
+	    pgprot_val(prot) == pgprot_val(PAGE_KERNEL))
+		prot = arch_vmap_pgprot_tagged(prot);
+
+	/* Allocate physical pages and map them into vmalloc space. */
 	addr = __vmalloc_area_node(area, gfp_mask, prot, shift, node);
 	if (!addr)
 		goto fail;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/606f72fd9b51eb790d11cb2d0dc4ee4eeac864b2.1640036051.git.andreyknvl%40google.com.
