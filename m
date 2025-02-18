Return-Path: <kasan-dev+bncBCMMDDFSWYCBBEMF2G6QMGQEEFR4SLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A9DFA394F8
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:19:31 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2fc2f22f959sf7615186a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:19:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866770; cv=pass;
        d=google.com; s=arc-20240605;
        b=M6cupH3IdQ3zw5/8hm9fEAiDcEB45uHsukKlrvdP4JCuvgwmhcXGu17/rnb0+ZMzTK
         yYXmTSq0uIZaXt3csEVVGRRBAvgJOBJjwLAALjZtnXmc67wlEFQLsO7Hg7nFHjRA7sM9
         iYGZ3HZNavn20hmIG/+rqU52lzfTqAPOjxof5NgwO6XbUUZj82OlrQUKHme/Zi66U2Nv
         qeVkxCxHP3ckFM3um2QS5snIbKNvhOuKxOwRI66xf6LGLvwgG7AK735pB7xulyvQEzra
         Aa/4i0kuH/uC1w8UtEzZts9qHBZ6UtLaNfiWdnSmK9CS54HbE0fGIDpwY8AVWe/PQpoW
         XONA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=G4XJxdYZrhe+MdFLrF2umiOvOrSnpP0R6Ef6B3T9wr0=;
        fh=xuDzZldtExQJOcHRnPFeXTjvf8aptpmkd7klER8Mb0A=;
        b=LU1lNCGxiJJpqBHdkqoni7DJU2GMy67X7Ndm1j0fZ4HKmOTj35D0lvpv1MEHv5FxSf
         XFRshoGCUKtAIXk+73foABx7EfmyUq4M8i+o6Aq/OXvu6Humag7aw5rigeWyw9JKZs6E
         rcE3aLpoaRRTrpeJqS83MKQa1wMttL7chpePmtF2Tz/vPfyI8IhqBj1VooLbz+TwiydE
         CWdh6y9SdPfHF7CpbJBtGg7Vf5koNsRqZLq8dFxVFf3ZaKYXsRdqmoNdr0OCovI1Hp4T
         mQlL9gZ72Mskwem+xX6XXgbVP62d606NSSJeMXCNpTeAyZK4QiSOHGpVY92pPcz+vSv2
         ZIxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=D+6NaU6P;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866770; x=1740471570; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G4XJxdYZrhe+MdFLrF2umiOvOrSnpP0R6Ef6B3T9wr0=;
        b=J8A85MjlcthwabkEcTOSAkkC66V5q6lxpLBhkPdBTlLf5nMItOMe2pHB+Ma68mXTe/
         7FPKJ6kWcTh+fhD+KRcV0PWWFCyDZ90QzT18aqOv+ZCY1HbcIT2V8vNCOy84BVm+jEqH
         h5JJDN2PogkQTq+HTWY0DIm9tAyBywBiZYDCcm4E6ud/H6xXPzRL5OonTx+ULqTJCrH4
         PjGCoKDKb65zmCq/Tcvgw3jYewDbEMc+Mnk6hifpwurBkdvXnj7/ikpc3anlnhamUZ/s
         QEe/dVeDHBtzgOIiLv/8rXoLuLnl9EYUS9Z7N+fu0HvXYIjONSeOkhDTHbdz7CTg3v/l
         323w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866770; x=1740471570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=G4XJxdYZrhe+MdFLrF2umiOvOrSnpP0R6Ef6B3T9wr0=;
        b=OzX7owVIgHHk5pIe/aI8nwStN63ZblvKcykfnrSbT98mwOwl3b3nfG5ZTRaw1zVGTY
         y7TiMbTQo3Q1qJKxUwHLxohA9aoBYv84v610/jI7I8xBYEBbmi+jNOtoQajOGo/7bqOh
         enD/cAlbgoOTzgGMX4itGtw9MfnSVi35imIHoYT6BQJSc8KRsDxkmsRaZt4itGNdGmy8
         JXS87CeouT+hhATpekbXlN8oX3TthAWc0zeE+3PzIgE4/Nm++bxTCmPfOPBtL/8Koowg
         33yiDj00SNCqwTHDnUTCmtlHSe1wl3ZoMmpHLWV/uBnqBeMqTwFmQ3gTX+3C4Od7k8Wj
         5ecw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZbAkq5SPf8Ye8br0su8Evjt/f8KvtGG/+xIduGt8yr0WRtTtjpKjlYJw1HM/jYUHrnOqIIg==@lfdr.de
X-Gm-Message-State: AOJu0YykIVnqMY9Tncbxz3o6COyTW2mKxSYOFZLQifLTcrtdMCKRbXTh
	QhTo/PYRfJASzWAjKEhxXOIypDp3WccGUjjbA/PwOu3/fyPQKdRc
X-Google-Smtp-Source: AGHT+IHXaMlioard4qG+8nKZLOtpgFJz4d5uDbgwwtnexWUk9x0sj5qDglwTzllGiHa5AS50XoOjMA==
X-Received: by 2002:a05:6a00:2292:b0:725:4a1b:38ec with SMTP id d2e1a72fcca58-7323c45aa40mr40537136b3a.3.1739866769749;
        Tue, 18 Feb 2025 00:19:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFrWgUhW/8UlTQSZLQp3Ra2cUrZcY7Tgaha2y0BaV0Now==
Received: by 2002:aa7:8456:0:b0:725:d903:a683 with SMTP id d2e1a72fcca58-7323befa968ls978907b3a.1.-pod-prod-00-us;
 Tue, 18 Feb 2025 00:19:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVA95UBboa6pr2Q3fKiNzapMiLoZok74S7DgGNmUs9OSj7f2pizMXhnCpZkAWFvBcekTTDR3hmccdI=@googlegroups.com
X-Received: by 2002:aa7:9912:0:b0:732:5875:eb95 with SMTP id d2e1a72fcca58-7325875ee4fmr20434687b3a.4.1739866768486;
        Tue, 18 Feb 2025 00:19:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866768; cv=none;
        d=google.com; s=arc-20240605;
        b=BokbycL3lu+N0Nbds7tJ4/V38XHbVaoEsPKI4YtmC54TvgCqwuQjCasuEi8lrEkpIT
         c7hkJcNyO89iljV559BB9KcoWI9wOE5rK+BxiTJr19PanKXO7JOnG2tH9NekKghFT17P
         pUrAScdJ+8/FU+gUogd41xLaxyjFe6N2tY1VoTEbWdPpw+0ct0VvuQCTZkq/m1RkD3ue
         32NTbB4jZKN2LxyUGjD0KuTtoIVWRwjXBT5FiOaT20ShOY/RV2M2lrm4NhoJbzdmDbNu
         wQuqO9Jb6dmf7F2PWgA7lCKL3EB3AmiI78aD8E2nTe7UPld8MIslk9Vgk3qhiCLaJuPh
         qdaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Wa0dFcuZNks8+m78LqIF6+BNsI3gx1vfldLXivV4N3o=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=IL4h1pIPFMC0up12p1EKGQWPn+7GrSZxD1I+tOTtjLX/i0JeURIssANon3+IdDYQjU
         PWa3MsH83/NoNeIay6Vw+BRkr3SiFcrB/XMnESS4lXMkrDx20YNh1hTi0wabcGYeVXth
         Ib0wHYC155GmUGxSdCrGErB4pRvrihMqPzPRfRChEqlroWXFlc1OLeAQjFTPYaduDxjA
         G9IfrOdJl4GUoWk7Xfywx66PryRKpDxkqeiZnEsf3aZLU2TJzfhe2htD8u6a9ImjhmxO
         qNVqXuIbrunZJ/jxoAaRpLZE6B9WacyKnBzS0H5/vZtKzZN+y+ybMGozIrJI9OKbYsaI
         /J2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=D+6NaU6P;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7324261b12dsi529727b3a.3.2025.02.18.00.19.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:19:28 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: 1GgYPqQwTbG2FpsvP5RGAg==
X-CSE-MsgGUID: ciIjVDa1SI+26/uUePT+Bw==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28150424"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28150424"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:19:28 -0800
X-CSE-ConnectionGUID: 46KsSX6nShmB+6L3gB4eDg==
X-CSE-MsgGUID: zDFh8fMPSzOB5kwIyeazag==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119247888"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:19:09 -0800
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: kees@kernel.org,
	julian.stecklina@cyberus-technology.de,
	kevinloughlin@google.com,
	peterz@infradead.org,
	tglx@linutronix.de,
	justinstitt@google.com,
	catalin.marinas@arm.com,
	wangkefeng.wang@huawei.com,
	bhe@redhat.com,
	ryabinin.a.a@gmail.com,
	kirill.shutemov@linux.intel.com,
	will@kernel.org,
	ardb@kernel.org,
	jason.andryuk@amd.com,
	dave.hansen@linux.intel.com,
	pasha.tatashin@soleen.com,
	ndesaulniers@google.com,
	guoweikang.kernel@gmail.com,
	dwmw@amazon.co.uk,
	mark.rutland@arm.com,
	broonie@kernel.org,
	apopple@nvidia.com,
	bp@alien8.de,
	rppt@kernel.org,
	kaleshsingh@google.com,
	richard.weiyang@gmail.com,
	luto@kernel.org,
	glider@google.com,
	pankaj.gupta@amd.com,
	andreyknvl@gmail.com,
	pawan.kumar.gupta@linux.intel.com,
	kuan-ying.lee@canonical.com,
	tony.luck@intel.com,
	tj@kernel.org,
	jgross@suse.com,
	dvyukov@google.com,
	baohua@kernel.org,
	samuel.holland@sifive.com,
	dennis@kernel.org,
	akpm@linux-foundation.org,
	thomas.weissschuh@linutronix.de,
	surenb@google.com,
	kbingham@kernel.org,
	ankita@nvidia.com,
	nathan@kernel.org,
	maciej.wieczor-retman@intel.com,
	ziy@nvidia.com,
	xin@zytor.com,
	rafael.j.wysocki@intel.com,
	andriy.shevchenko@linux.intel.com,
	cl@linux.com,
	jhubbard@nvidia.com,
	hpa@zytor.com,
	scott@os.amperecomputing.com,
	david@redhat.com,
	jan.kiszka@siemens.com,
	vincenzo.frascino@arm.com,
	corbet@lwn.net,
	maz@kernel.org,
	mingo@redhat.com,
	arnd@arndb.de,
	ytcoode@gmail.com,
	xur@google.com,
	morbo@google.com,
	thiago.bauermann@linaro.org
Cc: linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org
Subject: [PATCH v2 10/14] x86: KASAN raw shadow memory PTE init
Date: Tue, 18 Feb 2025 09:15:26 +0100
Message-ID: <738373d32089fbf84a8c5d6f32ade1bf28d14020.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=D+6NaU6P;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

In KASAN's generic mode the default value in shadow memory is zero.
During initialization of shadow memory pages they are allocated and
zeroed.

In KASAN's tag-based mode the default tag for the arm64 architecture is
0xFE which corresponds to any memory that should not be accessed. On x86
(where tags are 4-bit wide instead of 8-bit wide) that tag is 0xE so
during the initializations all the bytes in shadow memory pages should
be filled with 0xE or 0xEE if two tags should be packed in one shadow
byte.

Use memblock_alloc_try_nid_raw() instead of memblock_alloc_try_nid() to
avoid zeroing out the memory so it can be set with the KASAN invalid
tag.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v2:
- Remove dense mode references, use memset() instead of kasan_poison().

 arch/x86/mm/kasan_init_64.c | 19 ++++++++++++++++---
 1 file changed, 16 insertions(+), 3 deletions(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 9dddf19a5571..299a2144dac4 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -35,6 +35,18 @@ static __init void *early_alloc(size_t size, int nid, bool should_panic)
 	return ptr;
 }
 
+static __init void *early_raw_alloc(size_t size, int nid, bool should_panic)
+{
+	void *ptr = memblock_alloc_try_nid_raw(size, size,
+			__pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, nid);
+
+	if (!ptr && should_panic)
+		panic("%pS: Failed to allocate page, nid=%d from=%lx\n",
+		      (void *)_RET_IP_, nid, __pa(MAX_DMA_ADDRESS));
+
+	return ptr;
+}
+
 static void __init kasan_populate_pmd(pmd_t *pmd, unsigned long addr,
 				      unsigned long end, int nid)
 {
@@ -64,8 +76,9 @@ static void __init kasan_populate_pmd(pmd_t *pmd, unsigned long addr,
 		if (!pte_none(*pte))
 			continue;
 
-		p = early_alloc(PAGE_SIZE, nid, true);
-		entry = pfn_pte(PFN_DOWN(__pa(p)), PAGE_KERNEL);
+		p = early_raw_alloc(PAGE_SIZE, nid, true);
+		memset(p, PAGE_SIZE, KASAN_SHADOW_INIT);
+		entry = pfn_pte(PFN_DOWN(__pa_nodebug(p)), PAGE_KERNEL);
 		set_pte_at(&init_mm, addr, pte, entry);
 	} while (pte++, addr += PAGE_SIZE, addr != end);
 }
@@ -437,7 +450,7 @@ void __init kasan_init(void)
 	 * it may contain some garbage. Now we can clear and write protect it,
 	 * since after the TLB flush no one should write to it.
 	 */
-	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	for (i = 0; i < PTRS_PER_PTE; i++) {
 		pte_t pte;
 		pgprot_t prot;
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/738373d32089fbf84a8c5d6f32ade1bf28d14020.1739866028.git.maciej.wieczor-retman%40intel.com.
