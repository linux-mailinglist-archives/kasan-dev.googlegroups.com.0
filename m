Return-Path: <kasan-dev+bncBAABB4PHRHEAMGQEAFACOMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D666BC1D228
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 21:07:23 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-592fd238f0esf101808e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 13:07:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761768434; cv=pass;
        d=google.com; s=arc-20240605;
        b=MHEFdwERR4/cIKV3DpDSHHWbxpqSCG1lskuUHR008GUSY5tQzMV1TavrKjKC/5TZ9I
         sdAoJ3RgQbox1/w7ZfOT6WwlCzgXF3hbTdoYkXeuBe7vStriyM48B5N/4tSUJhWsJoML
         PGvi1l8rZIVV41ZvGOKHLOKcXasRWEwyIKSY9Qxojc3Rn1pDmMbcu+C9uUoLVLY3w8nq
         bMhzAQAhpqYuelhZr6Wt8E3IlkLyy+KSeip5mNHZIASUkubt5Ux5XKIytoidBk5QdR7d
         JkaIe6LE1Gi8mroSNFN+ldRp6MdEqrqwwl7nteed7uvd5N/YG/oSLmK+SEeDcXeDoLjL
         J2ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=k+kzEJtw/KRQMCl/nz9lW+0OCWdzXf8j0YsnZw9G0zQ=;
        fh=oUl/CmlZbZnb0QD/VPazRUb/33hz3NfBMBfiqD5vMBc=;
        b=gB8WaJDs6hhLJSWdMBTS7VkPaYHH6PKgrhgI4x/MlkcxNkHch7wIT1j+g0tgM830u6
         KsOyvNol7ueuPK62b4sUQXDlRUIfHkVVEPqqu/FCAjDFknIfH6O2JP6lPPwRlMPIcpxu
         k9a5NczLxwaKoNSiUlQoOzGrBO5DOTQ/0p/700T2FvBxYCKAAYpMbmLlileiRFW8aswl
         kbMTwNPTDzbvFdc0DjYky7JR5vGRmK2cplOhoSQOHGUgqRXhMo+79ik4bGvd7p9GlQHU
         bJoldv9p9Q53mHj/A6LEWx95J3i0OTHXLT1hOWIPzt6y9Xtqn3Mqo0u3F6DAsVIEnUEy
         RxPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Q8fbvGeL;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761768434; x=1762373234; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=k+kzEJtw/KRQMCl/nz9lW+0OCWdzXf8j0YsnZw9G0zQ=;
        b=hFAN/ForDi/Tyh6DisX5DoTbeDyVq8Y0hCvAppES5nhdnU75tjQ33nD8Ew7RK7/6Ge
         wHjF/bYzhW6XNlFRZgOjq/SSLhJ4Db2C0DMceoVEGuqhinfOLm3y4wD0ecAu4K1Y833Q
         2+CGYE6B4/VuqbthczbDYNxxXTZdomYaG9SgdirV6EPy5CPZG73aYV6+UGiQmOCAoMVq
         mY3BzLHjv+X2duyqi5pJJm0RVmLucujAP5PVegT5+oIjiWIEboaFywqLlIpA5jjxeKMz
         IQuunE4I33oKn7fGqGmDsGTwsYzzI+m6b/GWJ3SDADEkfN0jO2DkLMQJ8NChVfaymkWq
         Bvqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761768434; x=1762373234;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k+kzEJtw/KRQMCl/nz9lW+0OCWdzXf8j0YsnZw9G0zQ=;
        b=ZItnQj0RVTye0x1W9ANDu7RpdCtcqY0UMEkbAyOJACrwClRHCGg5CBDuU1JvbDFMnd
         CafOhwKdol8u0IyGShLDA9GFbGCQKshz4YW620LVEjXr6IqQ26XTXhlFi3RxCSXgAKnl
         xI5C7LZUaV/KVRkQqbtkzO3nc3VuMZyMLXI9A5xYiP2SdAG+XTccVxjbXbcIf7e4tVeL
         wMzHfddWJMvkpt47tDlx1yCHhw46aozStjX6Px4Afcu2CEt8lcFbIBYPSs1JjcNO+O+p
         B22I8KPGl7IYONaK25lO4djJx14qOSEdlGQX1Gw2PzEWds6ijS3lijJA7BPajA3OH9Mh
         crdA==
X-Forwarded-Encrypted: i=2; AJvYcCUUIdM5E3d+iXKeIlA4JKcbIt1q1A5YUHqIpw1h6Yfe11CmbnS1L2tAQxjnJf86yLVqD29ZFA==@lfdr.de
X-Gm-Message-State: AOJu0YyJACdpeXOK1LM6eBDChQimyaTOfqnLMc81D9Fg6xmGAF25FG0H
	U4VMXOuOxbh3XtdawAd86PYQ6YcsbqiyfWbeNJ9saQGfjNUU8N/nd+3g
X-Google-Smtp-Source: AGHT+IFhrThDD3o23DC9Pv0Ynp2OdYt3a6kvlno29nIZDO1gUOp3mV4Klyk4rz8ZKYcgApjIlDu3Bg==
X-Received: by 2002:a05:6512:4028:b0:592:fea0:c11b with SMTP id 2adb3069b0e04-59416e7de06mr196819e87.19.1761768433952;
        Wed, 29 Oct 2025 13:07:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YTWYYV2LX40dog8NgpSEWCuCIbrlvY26Ui8w/Wo4F6eA=="
Received: by 2002:a05:6512:3986:b0:586:87c3:6151 with SMTP id
 2adb3069b0e04-594175af2a1ls37813e87.0.-pod-prod-08-eu; Wed, 29 Oct 2025
 13:07:11 -0700 (PDT)
X-Received: by 2002:a05:6512:3089:b0:590:5995:6dda with SMTP id 2adb3069b0e04-59416e67b10mr205364e87.7.1761768431580;
        Wed, 29 Oct 2025 13:07:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761768431; cv=none;
        d=google.com; s=arc-20240605;
        b=GhAmStazv4Yav96IY5dnKgbEPpDgHRlPM1VN0RC2445z0d1m5yoHdEdG/ekjuNH4VE
         m43sim0IoyvtS3Q6P+BpLGLigOxf3UOilx1DDpou1EhQQNeNp4xB0vC2lvMP269P0b/q
         +COy38vi1fDarO7lQeBD4bFAuD8uj3Nw6rw59Kjf3KuTGOvusaVgZvD8mJyMb57WaAWb
         8T8lNubF4wzywWYx5am1sl7c46cKvM/7outvZBW6PLldGorPi9zeRd4Q1KC/nJMA97BJ
         Ti4e8Fk0jK04uuvDERktC5jmCaDca+No81YYL/bo3gENKEcL2vZH+XjeTvZ5TcC+gRZo
         3uyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=ORgS5h+xBvFClF5iXcyTXC092gY8CGZFTCYy/D6hFpU=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=ASI4NFhnBcfVZ5NU4R4tL2xZR1ba+8SdptvPcm75eGdp7qSgyBcU28f/z97Sh/IV/d
         tfzZ5f9R7S+gps8gT65Ngxw+533l8aCZvMldu7jlzHIKZ0dSGO6jBfOD//TUTClvgn6M
         Kc2gRMs2k1tKshtho4S7KaSsNhnpDmFFIjaQUmu3jVzRaWRXRgpRMphlNT6/3q25fDAu
         qbM042FwVhVfoSXTnGqZEmYxWovYhg52JE0RVETbXeaAFjfsrqg9AWJ+3hi+vs9DpUWA
         xsoEyokWnv8wH85yuIC5uOTAclyYy6XoWJF7Ulf6LtHg5J2ZzEYozf1/XPWWMKbo4C4B
         awrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Q8fbvGeL;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4316.protonmail.ch (mail-4316.protonmail.ch. [185.70.43.16])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-593028932c2si247834e87.3.2025.10.29.13.07.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 13:07:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) client-ip=185.70.43.16;
Date: Wed, 29 Oct 2025 20:07:02 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 10/18] x86/mm: Physical address comparisons in fill_p*d/pte
Message-ID: <da6cee1f1e596da12ef6e57202c26ec802f7528a.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 931b8bb7920f3633ea9d19d797d43379e99d4838
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=Q8fbvGeL;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

Calculating page offset returns a pointer without a tag. When comparing
the calculated offset to a tagged page pointer an error is raised
because they are not equal.

Change pointer comparisons to physical address comparisons as to avoid
issues with tagged pointers that pointer arithmetic would create. Open
code pte_offset_kernel(), pmd_offset(), pud_offset() and p4d_offset().
Because one parameter is always zero and the rest of the function
insides are enclosed inside __va(), removing that layer lowers the
complexity of final assembly.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v2:
- Open code *_offset() to avoid it's internal __va().

 arch/x86/mm/init_64.c | 11 +++++++----
 1 file changed, 7 insertions(+), 4 deletions(-)

diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
index 0e4270e20fad..2d79fc0cf391 100644
--- a/arch/x86/mm/init_64.c
+++ b/arch/x86/mm/init_64.c
@@ -269,7 +269,10 @@ static p4d_t *fill_p4d(pgd_t *pgd, unsigned long vaddr)
 	if (pgd_none(*pgd)) {
 		p4d_t *p4d = (p4d_t *)spp_getpage();
 		pgd_populate(&init_mm, pgd, p4d);
-		if (p4d != p4d_offset(pgd, 0))
+
+		if (__pa(p4d) != (pgtable_l5_enabled() ?
+				  __pa(pgd) :
+				  (unsigned long)pgd_val(*pgd) & PTE_PFN_MASK))
 			printk(KERN_ERR "PAGETABLE BUG #00! %p <-> %p\n",
 			       p4d, p4d_offset(pgd, 0));
 	}
@@ -281,7 +284,7 @@ static pud_t *fill_pud(p4d_t *p4d, unsigned long vaddr)
 	if (p4d_none(*p4d)) {
 		pud_t *pud = (pud_t *)spp_getpage();
 		p4d_populate(&init_mm, p4d, pud);
-		if (pud != pud_offset(p4d, 0))
+		if (__pa(pud) != (p4d_val(*p4d) & p4d_pfn_mask(*p4d)))
 			printk(KERN_ERR "PAGETABLE BUG #01! %p <-> %p\n",
 			       pud, pud_offset(p4d, 0));
 	}
@@ -293,7 +296,7 @@ static pmd_t *fill_pmd(pud_t *pud, unsigned long vaddr)
 	if (pud_none(*pud)) {
 		pmd_t *pmd = (pmd_t *) spp_getpage();
 		pud_populate(&init_mm, pud, pmd);
-		if (pmd != pmd_offset(pud, 0))
+		if (__pa(pmd) != (pud_val(*pud) & pud_pfn_mask(*pud)))
 			printk(KERN_ERR "PAGETABLE BUG #02! %p <-> %p\n",
 			       pmd, pmd_offset(pud, 0));
 	}
@@ -305,7 +308,7 @@ static pte_t *fill_pte(pmd_t *pmd, unsigned long vaddr)
 	if (pmd_none(*pmd)) {
 		pte_t *pte = (pte_t *) spp_getpage();
 		pmd_populate_kernel(&init_mm, pmd, pte);
-		if (pte != pte_offset_kernel(pmd, 0))
+		if (__pa(pte) != (pmd_val(*pmd) & pmd_pfn_mask(*pmd)))
 			printk(KERN_ERR "PAGETABLE BUG #03!\n");
 	}
 	return pte_offset_kernel(pmd, vaddr);
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/da6cee1f1e596da12ef6e57202c26ec802f7528a.1761763681.git.m.wieczorretman%40pm.me.
