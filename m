Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBJOXW6GQMGQEHEPUJFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 483F346945C
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 11:53:26 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id j25-20020a05600c1c1900b00332372c252dsf4319508wms.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 02:53:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638788006; cv=pass;
        d=google.com; s=arc-20160816;
        b=wzgWKljk60UrwPeohWqB6/x1+5OA4ubY6PgAuuUUASZtL/3MTBIl1YCX3jtFYsIrfh
         r992X0nmA+dng8mz9NmJzdbg8uLhc6OlYmyAOF1IsXfGjBnk0Rr1B0gGruo3+NKUu7qZ
         PC0V4TFyrSp0VdrhuG2HnTPVwgf02Rsn54KkIyd4C1UMNEcqOPnZ/XE++59i8k6pjDMb
         Dc6XjfDuHUxMfJfAg0dfnZqDf1FmyvVXm7ZyYF9Iowl9+nrKiy3CkKc83gf1hiDzYe33
         yGlTZWz6V3/FQnY1lHMt8Xn0MH/z2WR9smazpVHWuM05gZPsr7N11fpNdjkFCoEFA9Yy
         S4+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2+h7qyJE4ilNspvCXpinofCY17yOmetyptKp1uQnq1E=;
        b=w3t2bFGghEPYdjMWNE1gWQMSQK6JeY9QmMhC+t+zKLRUzMa5sgaoqiEXydnsHjPtDM
         F43Qevl3tJtS64rFFi/nYSOQub8CrqwOcJ4o+4J6u1pMj3gmMEH6HnBKbnnDYsilq6i/
         9rsgLqLNnxGJ69N3mF2C9enQx4Y/Y4hkyeoNPCqsqllNTTUQPP2xc3F+fWIgz77YYanf
         FrrCuVghxO5tHCkCQUOH8aOuEIE6RKNxLaDzczcV4YCuF8jIC2yMtGE0tGBFhxDSda8r
         nURIQMpPm7WMdOPhIiuNqD5FOoPd/L6JN/yIQB6clN/IBRBGTrHgJMNVdB4oY764dA8i
         MXAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=asObokCf;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2+h7qyJE4ilNspvCXpinofCY17yOmetyptKp1uQnq1E=;
        b=SLpMWpz2HBiPqWVkvBxRtTmXwsbIcFts0Isf8LUAwMzB17tcxvbiKH+9ahpjzPIVFH
         espIcy1AWmx+CKSQADW9ewlFxjVFMx1O4lcD5fivF+pe22ZuN/2eGjB8BtzOfe49eFk3
         ZHZN7tDdFiYA1wmhVngbJkP3dxj6uoOzuiuuB9N0suHJfaI5ODdB4L2Efk+b67AGLTk2
         A/T5qXimqnT34YoUT9pwMaV+/YiXT8pyAWEo+XjiOjDkfmzNFsDWdoSgtB8SoR10THYZ
         vPefUWli5dEtJorLFrLCItR0jOYJlhH6iOrrDwPkmTkviFdNuYAJdzAdd0/meNvlO9/x
         la1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2+h7qyJE4ilNspvCXpinofCY17yOmetyptKp1uQnq1E=;
        b=rzXrkZpAy5AnqQtpDVq8aOgPPjd9ItNYdlUKf0ZmesiXppUz56Nll644WmrpysVyeK
         nlXOq19SmUigKOp8772ywA1hlXTlmZKkXLQQyPPTLgkADRHvKhUjyeju6Ei8seYljgT3
         r9ramyFFSW79FoGHofRaS2Mpq1ZiAab4qqDhRpJgwhx1dNexBrCQGx3Aq5JIrr/JQiI9
         TJTtN5tU92OavskXp04ehnqcGgcB5I/wJRszv4zOK5gLKhC/TIpNycRvauO49Tib0Wrq
         6H1RG7kbWxJUTPDAhZygNmcBn16qCaV6JNV6L3JMtuw1spnhI26O9+NYd16KfCGDW1tC
         JL+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531yHf87dm8bhTrhQLoMIi60k31Slibhxq//R19fyA3g2SIZKPoB
	UPsNUroEGQXea+vilrzzfVM=
X-Google-Smtp-Source: ABdhPJxaHAq8yMUfy83Uj2eiO1RSA9tZQyHdcIlGX9aIyCUaeS/WlhNVxUDjFBhKzK4lKlZNFZG4aw==
X-Received: by 2002:a05:600c:210a:: with SMTP id u10mr37242059wml.33.1638788006066;
        Mon, 06 Dec 2021 02:53:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1c7:: with SMTP id 190ls9954520wmb.3.canary-gmail; Mon,
 06 Dec 2021 02:53:25 -0800 (PST)
X-Received: by 2002:a1c:1dd6:: with SMTP id d205mr23728165wmd.77.1638788005226;
        Mon, 06 Dec 2021 02:53:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638788005; cv=none;
        d=google.com; s=arc-20160816;
        b=NeDQTaq+7vjiFd40ZR1hLowtbyVaxU9iYjdX9jVzNzysoLV8maiw3en3zG/wEXuNLG
         UPteKL0+tA9kx/tJVFCVR1b/kwUTKNSErRM8III7HYAtcLMdRPCCyJmwEHmNRH5/98mU
         PG/puiEwTelnjSHSvOmvW3JsEBPA/gq0MUD14KHRuam91XI7s07v95XaztNfm1inMTTv
         6silEpZ7e7AySqMN6BZczjEyrRgqx7MmmBQKf+jYH2EH3i8MtoFMQ8T9sB4i6iQ8ogYu
         PSZ07eMP4Glylzyrtz+ObN3WPmWqijHdtpwXKkZiX9ZOrbf9uIn9RbffwWMAf47HsOox
         Y0bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gG/WhBjtCMK9Juy/cpLoUS+Fz+e97sYPeCnLmIYCPu8=;
        b=DakWe6avb1WRWY8fQyIF3gKjt0uIK8j+Gx7EoHSreN/z6JO7p7jx+LOSUA2gF1QQu9
         kjFWITmtH23+MWqmixS5LtpDrGf5xhUSlRWslq1PPHN6mTgGSOsYl5L5uBhmid5axS7t
         +UOdjgYq+wETgplvhfoOrnXrOi6xqLNu4aSqz059ewQDlnaCfpN2PbwdzCzUSnuLl7hW
         OWG8N4Nem5GfTuWjQSD2bPHXHWFTrOjAFY1gbXaJof8wanrQ8ZrC6iboBUJjuI8no3/l
         80MI8n1c6RxKc26EB2YHNmylnVUuYzLan/blScwmXt00ZXYVv2rRMHEzujT4DJT9qWCZ
         aIFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=asObokCf;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id z64si1275116wmc.0.2021.12.06.02.53.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:53:25 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com [209.85.221.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 42CCC3F1B8
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 10:53:24 +0000 (UTC)
Received: by mail-wr1-f70.google.com with SMTP id q17-20020adff791000000b00183e734ba48so1895041wrp.8
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 02:53:24 -0800 (PST)
X-Received: by 2002:a7b:c102:: with SMTP id w2mr37750661wmi.151.1638788003993;
        Mon, 06 Dec 2021 02:53:23 -0800 (PST)
X-Received: by 2002:a7b:c102:: with SMTP id w2mr37750632wmi.151.1638788003798;
        Mon, 06 Dec 2021 02:53:23 -0800 (PST)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id p5sm11021231wrd.13.2021.12.06.02.53.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:53:23 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@rivosinc.com>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Guo Ren <guoren@linux.alibaba.com>,
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
	Mayuresh Chitale <mchitale@ventanamicro.com>,
	panqinglin2020@iscas.ac.cn,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v3 06/13] asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
Date: Mon,  6 Dec 2021 11:46:50 +0100
Message-Id: <20211206104657.433304-7-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=asObokCf;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

In the following commits, riscv will almost use the generic versions of
pud_alloc_one and pud_free but an additional check is required since those
functions are only relevant when using at least a 4-level page table, which
will be determined at runtime on riscv.

So move the content of those functions into other functions that riscv
can use without duplicating code.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 include/asm-generic/pgalloc.h | 24 ++++++++++++++++++------
 1 file changed, 18 insertions(+), 6 deletions(-)

diff --git a/include/asm-generic/pgalloc.h b/include/asm-generic/pgalloc.h
index 02932efad3ab..977bea16cf1b 100644
--- a/include/asm-generic/pgalloc.h
+++ b/include/asm-generic/pgalloc.h
@@ -147,6 +147,15 @@ static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
 
 #if CONFIG_PGTABLE_LEVELS > 3
 
+static inline pud_t *__pud_alloc_one(struct mm_struct *mm, unsigned long addr)
+{
+	gfp_t gfp = GFP_PGTABLE_USER;
+
+	if (mm == &init_mm)
+		gfp = GFP_PGTABLE_KERNEL;
+	return (pud_t *)get_zeroed_page(gfp);
+}
+
 #ifndef __HAVE_ARCH_PUD_ALLOC_ONE
 /**
  * pud_alloc_one - allocate a page for PUD-level page table
@@ -159,20 +168,23 @@ static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
  */
 static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
 {
-	gfp_t gfp = GFP_PGTABLE_USER;
-
-	if (mm == &init_mm)
-		gfp = GFP_PGTABLE_KERNEL;
-	return (pud_t *)get_zeroed_page(gfp);
+	return __pud_alloc_one(mm, addr);
 }
 #endif
 
-static inline void pud_free(struct mm_struct *mm, pud_t *pud)
+static inline void __pud_free(struct mm_struct *mm, pud_t *pud)
 {
 	BUG_ON((unsigned long)pud & (PAGE_SIZE-1));
 	free_page((unsigned long)pud);
 }
 
+#ifndef __HAVE_ARCH_PUD_FREE
+static inline void pud_free(struct mm_struct *mm, pud_t *pud)
+{
+	__pud_free(mm, pud);
+}
+#endif
+
 #endif /* CONFIG_PGTABLE_LEVELS > 3 */
 
 #ifndef __HAVE_ARCH_PGD_FREE
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206104657.433304-7-alexandre.ghiti%40canonical.com.
