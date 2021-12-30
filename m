Return-Path: <kasan-dev+bncBAABBYEKXCHAMGQE327ZYHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D2C7481FAC
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:15:45 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id bd7-20020a05651c168700b0022d71e1839bsf8460600ljb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:15:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891745; cv=pass;
        d=google.com; s=arc-20160816;
        b=hGqXepyEPZN2JiMLQ0r9As8q/b1HrE1HEuVCoOXK6PAPZlU7v4PETQ2JJkboOXbZ1d
         L6FWmP1zGvP3uA0fq45fEB2OjMCAYKkFUv4HjUOLD2XXaDluxYVrPzVAjHYaRwqJxgcZ
         rjepQRm2RuRuwYrPZDROthvKqVTmG4AEi1DmYS+RTdW2YzfCBju74miMPfAwSafX1TWX
         33Le/LJ+MFRu6vQa1GaQZxTrYIr03ux6/O6+iLHPPSrEXiQq81LF20ovf1DQ9Kh47I4N
         nJ0ic4++kEq60Fqv4bJRggvdXDIx0yscswRjMFRICrUgxJzeM+7j22qaN+Dj49qq48dY
         Yv2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yUqa5cbMn/sY9aPgHZvn3SWNhdI3/ynf21JJwPbgX3Y=;
        b=Vy0oRjF+6nzu0FfTeIwgMAfAOsVTAkQ+aSLS/Qg0UBdqZzvLDjrf0VkGRu6IT1T/54
         rmry/kqiZaeSk1ynL5v8ymOI+3LeyqZKJ2OuPyRE6btPWAgc3mYQBVYPUaHAr4avApFG
         A77W9YlhVXCDHAvHe0OwIHd4tTjxNDJ/81+zCDlmamI9TXKBfUYyopuTGOxzRs0efY9X
         B4p6xlgM0Ke/qtd14Qn8qCAsT1fVabEtK8MP6lGwRs2CKgnNdnY/tCv4bSGOrsi+Is5T
         ul830wLKiqGcNuOLmJTsLp+xqovejbKVvJA1nczU9TiNpV/PRV5604BHemH0yP09lHJS
         nw/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hT9Ok0xI;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yUqa5cbMn/sY9aPgHZvn3SWNhdI3/ynf21JJwPbgX3Y=;
        b=FQa+Peo94NU6Bg6K+1vjx6kGxxllsh2SvWPiS50SjGo9PDdSfXG2Pa6Wxj/PyfaZZ2
         A769LIx4dxc7jcXVSMIEfNDjP7sAI2hJB2SyjGikuhVJmQV2cciWgLOTaWyzUV8R9EPM
         5J+qBXbXQqEhlSrvYCYgKi46Y9zNGUV28Che7wSZ7Qbf1hNvI05B9WFx+ACIi5RN3Nxz
         h0NRMw2a+z3/sNu9/yIx0g5aC/7w66gsL8FVvG6c9vOqK+ip0VwvlRL1W1edNn5UmO2T
         LtS3CSm5h9/Pe7t4AV77NtSy2aL955876YuTzVhIrICPYpifiggttWCu7qnz6mIMdpES
         TYOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yUqa5cbMn/sY9aPgHZvn3SWNhdI3/ynf21JJwPbgX3Y=;
        b=Li9qA8xHx+SUHOI7weE8fmjlOBCY74LHosGLNZjjdndPbUl/tfiwWWRPuQxfKg1r+r
         S1zib8AK/Vn+VCxiJs4mW8lLlwP0+9175NGs06yyDDCztzdEqpPsg5cJoh/TylDdMRkt
         Dhbt2X9LicJS76DDoZAaxD/PxKwCPyFAOXrlNNEvKtsjFwcteLMzdjUI/ev6JMgayOvH
         dLF5fUoYKm9PBd+6VEzSBwcvXCVFKhYzeMZM3olgDF9SMBUhF3Rd6EdCYZsBeYrpQouJ
         43mYdQGKFY113MGvQ2zpxGdASTtjgJid/xzv0rgA1ZoJSu2me/y56vDPR5NeFZpL6/vo
         4XOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531GVfSQap38JCaiveKegQVwHP1bdQEUeo+LRz3cQGA9M/4WstVb
	mWbCJa60AnDcVZ3uO+FCrOs=
X-Google-Smtp-Source: ABdhPJzz2MZf7hUtZE9TAK93P7ZNKXUaHrLsAAToRyPtmAOXt7Ug6U08pmtVf9jTDN88zgJ9IVImwA==
X-Received: by 2002:a19:a402:: with SMTP id q2mr29309532lfc.125.1640891744980;
        Thu, 30 Dec 2021 11:15:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81c6:: with SMTP id s6ls1950633ljg.4.gmail; Thu, 30 Dec
 2021 11:15:44 -0800 (PST)
X-Received: by 2002:a2e:9e90:: with SMTP id f16mr27643174ljk.103.1640891744306;
        Thu, 30 Dec 2021 11:15:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891744; cv=none;
        d=google.com; s=arc-20160816;
        b=BsuLXe+0qbHWeNarKAUsVB6USjOI8cN5zGRetsYFnm/b1gn55FiSXqSpPO14wzQrNj
         dicQ6fm6Y1NthN2soqAU0APazBdufVnN6davoWAFYQrDF9yyT48DClpzK6zR6VE4KffC
         4C+h2BJeoigi69wZzEaoE96c2N06lQYeGRV6F++PImjhw+KnKYBBDgxD26U2j1B2cn6A
         9prmb3NOyz5AmNgrv54H5cVSji4PCjEWeX2ek3Ql97TGPBlMf/wmWlaMWxGgtDfAPEOu
         25YzZJiv8P1BTjDCp5Dzbmzl0PDiqlcnEytPeCTIkx9liDSxuRhMD55qn7NJiwk62S3w
         +smA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VrE3/psf08ADei6YaHqnB+ODMy2mIuIHMF6QXp9r2eo=;
        b=IrA2aPWIY6mPA67VYZf24yc8m1ToZks2yMztQrJiunh2GgSsyZil0dqoC055TPYpaK
         5TCLhZe0OIgXZ/lgOL/XUYXfo3xYzeUMVYZVOhvpbopnmKRPlEa+zONvJTyhTgNQc+wd
         fCXMKhSZGx6RhA9f0MKX5owpX0bXJSgNLKWffoYNgZkrVH0LHUnS0X/IQkVWSvUks1cQ
         ua2l7IjzcjROTYyCYUeKVYpmvx+6ktOx2e9FjDw0Johs+zktmjYRkLA6Gzrck8UIHN9m
         HY+HDKY/7Lceu8ngkvakkUPOyl+4dKnyiD1/6U2cPuMzwMtN+f3Q16xB2/LmE9Tfqij+
         7edw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hT9Ok0xI;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id m22si568002lfu.3.2021.12.30.11.15.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:15:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH mm v5 25/39] kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
Date: Thu, 30 Dec 2021 20:14:50 +0100
Message-Id: <980f198c90d6017e0ef2b4f7aecb414358199fac.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=hT9Ok0xI;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
index da419db620ba..598bb65263c7 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3107,6 +3107,15 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/980f198c90d6017e0ef2b4f7aecb414358199fac.1640891329.git.andreyknvl%40google.com.
