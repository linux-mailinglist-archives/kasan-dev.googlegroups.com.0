Return-Path: <kasan-dev+bncBAABBH6VXOHQMGQE4WQWN3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 66A554987C1
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:06:24 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id h11-20020ac250cb000000b00436e68ebef5sf2905816lfm.19
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:06:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047584; cv=pass;
        d=google.com; s=arc-20160816;
        b=mKRlbl/AORymwgiH/S612l1V5bh06LXCZNlTnWK3nXy/v6cakJcqBXru/azHm2J+cW
         fLS8yqaalgDHGxw1ZSv/RvB67Qtg/sEK5p+rOuDGXp/vQeXfKBw1GNKRKx+eWkHM1E9l
         tqeFLRqbViQ9fW0ZyZE9Qt4+DiVrkI1FG5tKiE7XjgCvxp13OTVYgUsd1DAuHjqYKOzf
         cd05mLIZfbj9rpLJtEFNNqAlRy6E5e5BQ/LZnYTwF0txXTZvNRNW8YKEbb3N9n6o43MT
         3FiMKEk8Dv7a3+m+ev+r1U5NH2k61IaOgDgGx0aTqGKLUSJrwm3v6yFG/qeb/KQkHX4z
         cnXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=c5IjiurdjLe5pyos3NbgtHrQMfacdkAIfGMX6Iu2cl4=;
        b=Ll7fU4GjENpxj5vJp+ArgQKtlWW7yEhBKjJwolFl+goryan5JCFD7Ipgn2F6OKaaJp
         zSFtxC56wS2i6ACUP+UMsFCWQKLSzRW3A+S1FhKXWpQ4kNNPY4rgGKfVv0HntlvOulPR
         CbkCbp1FFxs18l7Lzrye1UBYExu6JTyGMngHlE/7yNcpE+EAi+C89MdwYyvXsASM+Ykg
         6KdkmUv4DIWCZ0TAht0bFDnf1mBWifqAg0kNB2AXSbiBokiPf+0Ia03yvg/eruY+KvUc
         BQptlHRZ+aR1XuEME3edxksBlzsDNaZJKof6h8MJL0f1KFknmtSGievWwXmElR3eWnTc
         lPsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=urMo9kR2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c5IjiurdjLe5pyos3NbgtHrQMfacdkAIfGMX6Iu2cl4=;
        b=Y9YtjVCxVS6veUVj6yocxKy7fIqqOhXpvI19oIQF/zpoiX7ZF3pxFUV0vINOKLTURO
         Khd9/r5PdfFZvv9xU4VsbiHipVXwQ2ninWroIMrVYtcXPvWDeCcnmhnt0BAQwpfpbVkS
         tF8RadIhhJt5HPeMNXu2JWr8HG6x7tOqgENIFNRL35UzOiGyBcYELwuI1+BrfiQuPswY
         CkUS399+O5VJ6RaXd6t93yIlAofMUZuLvTmfu0zjekNPyjUYqEAzVevidmf872y66JC6
         KY8j58AA4aK1r/sZCX8Qbgc21J+1N9+lkmodKNKTXQADuxgN43BIQM6zk5+8wZC/awgQ
         oeyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c5IjiurdjLe5pyos3NbgtHrQMfacdkAIfGMX6Iu2cl4=;
        b=YinJprmhtmeRyVsmTe0WHbYmQdkcIt+1IWNE7hf8v1Gu8mjWACxr2fLXPLUndO9BPQ
         8nWHrr0JniidftZFtK4+5DH7rf6rjj4pvZ11q9o5kdCdPC/DQunAh6qVMnpPpcqb3SKz
         LBEMB0B2eBOtu69rqrxg4mFZJtMRURTjIA4JvYfPUFD4gjF/W+EBh+dnQ3eufrnUKLuE
         Zt4Put+CTN42fzoXMGIcu3xp0XrE5xOco8vb9WFJX9ei46eTkylj6mEdkR/itGnxOotZ
         2d0P2HSSznkJ/A0riBU1016HNvxUPT8rcPreNEyPEOoDftb4zqcaGWeyEWceE1mRonv3
         iISg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532HmNfpBc7FL1AVjK4dy10RYFhKJOzTPVQgBo91GUf6+WpNM+vZ
	NIHTjXA9mdHlXXfrkkF8R+w=
X-Google-Smtp-Source: ABdhPJy3L5zUP1NCCM7CDrCJvHtEZaivVBhDlQQk9F4Cv67dhILashbarqL94g8AvTXyAuAMcx6BfA==
X-Received: by 2002:a2e:311:: with SMTP id 17mr6985422ljd.519.1643047583918;
        Mon, 24 Jan 2022 10:06:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:39c3:: with SMTP id k3ls572878lfu.0.gmail; Mon, 24
 Jan 2022 10:06:23 -0800 (PST)
X-Received: by 2002:a05:6512:696:: with SMTP id t22mr14251950lfe.538.1643047583239;
        Mon, 24 Jan 2022 10:06:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047583; cv=none;
        d=google.com; s=arc-20160816;
        b=ZtuIjNU9uWOsBpMv1an6M9aNmsLjpim8XoXF/N8ZduAitBs9myMBw5EBuLNG+6D0Ob
         PwG9pOznYoqheNjhHDuoxAzuXTkUQIzDqhetnwG8k9xMHreUWPFGjXj6yaMsiQUSP232
         wUgLmDfEJxZ6UZyoER9E2Bv6OYs1h8rZIxdPWFVoiDLNnFJshzwUEiRq2qHehdHtq4VK
         233homQI8zDrJOZw5Jj8+wxrZ+itvE8U8UKNAZk6V4f8AxTX6n9DzdKtDi7CWyPWJAkS
         9zNPJ4zv6M0HzlDn5hi+CgMfwOGYhODRG/L4dxYEKZtty2TFr1g8Ma7Mb6bTHp0Y8tli
         hGmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EP4tI+Rouw15xYzxaTB6yeKX8++pBPS4+JzWpz9l86E=;
        b=EJAZrK0MI7EhNJdsARND+n2U/paZWsZtYk5Wi6KqL2zyEPXd1YBjDykZGR+wPI7Vgr
         YS+Rn73WK9L0i7XPolj5njZRIHwcFdNNgEKnP99umCWAFTm/pnCPn7utd982+ipHVagH
         W82NrdBTMdNF9x5/inPvW5o5lHPTuZwh7cvti+cvQHx0+4vmdJjDjwrL56AMuWmwGaNn
         jbMNL9a7lvLSJ8dHa8OMsGeNc6nRqNlpAUPC12Vfb61WbzQo/euNBCxrcPvzJv7RSLNP
         1E4kDpoMJnFo+tVD86VGuTWykP155p5IsILncjr2uEaq0iykRg5T/vQBkVvSRVtRQBMa
         q8Gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=urMo9kR2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id i10si576850lfr.5.2022.01.24.10.06.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:06:23 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH v6 25/39] kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
Date: Mon, 24 Jan 2022 19:04:59 +0100
Message-Id: <983fc33542db2f6b1e77b34ca23448d4640bbb9e.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=urMo9kR2;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index 87f8cfec50a0..7b879c77bec5 100644
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
index 15e1a4fdfe0b..92e635b7490c 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3108,6 +3108,15 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/983fc33542db2f6b1e77b34ca23448d4640bbb9e.1643047180.git.andreyknvl%40google.com.
