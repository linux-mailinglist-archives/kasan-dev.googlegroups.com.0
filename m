Return-Path: <kasan-dev+bncBCMMDDFSWYCBBNNXX67QMGQE7OQUU3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 407DAA7BD71
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:16:40 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-af91ea9e885sf1842067a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:16:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772598; cv=pass;
        d=google.com; s=arc-20240605;
        b=GQLLHWG6095IbRdCA7bWG8WRxxi0mSlC75/Q0sSKdCyru2NnKBFqyGvzNAob2pfZnO
         X6C8ChdzKGrkDZndDdPrQy8Em5dazq9Sskh3dfjnVx0tgf9BzilL2xqxD5d1UhORgFqr
         mBwbFQTQvnE1V9CfIP4vJaeBVeHzXdAHPSb15C3mTT4O2HIUWVW4W3YIF98v8vexXY7G
         XpDV631Ju7OJLeS2KVJvHvt2kFGFdaXb3VI1qKbXWWvlJhBy2aXLa6DDB+azEZuRyUCM
         dDpQlF3swcNWISiYU8y9KEF2yiqNE1X9iTZubUQufadkqZhT0ODfHLldVicCbHo0J9bw
         sEng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DBMprvfgjcMeNZiO4LjehyEw+X/YeY/L3rVgpPcBeqM=;
        fh=AlWRUnJsV5GB3hGIPs9cmXVJvSZyuU9s+0tI1uvwn8E=;
        b=CKeg1GDcMhpqUfl8OzvwZ+ohXBqJZt5ZB9WO3qsA+s8AbPShQvdNBp+TSbkJQgFbt6
         yLI8nHEBivpDILWTzQD/nBvM8eXi5EYbr9zVSg/7BP4JaJKa73wINGpL7rtQbqvUg0+g
         fa1vZkvjlezv8BvBfEIux+vFpnNBQ4HZfTIPcFjXAESvxUYeHBFFFBuFz4G2i3vFBByN
         z6TpdCtP2Lcq2BZ0ZSIuJe+KWxjA54LnVhUYJPtr7iHCWiPdPz8XTrqkUaPzgk9y6xTj
         dzzxOqnFHVLka4xeKBRarE5wupVQjQe4rkE+OPJp/gqbIJSGWwO4MABiY3DdJg3LQBRG
         ZwqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="Vyj7/+yX";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772598; x=1744377398; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DBMprvfgjcMeNZiO4LjehyEw+X/YeY/L3rVgpPcBeqM=;
        b=AuSZNCjdc7NoxfTlO1EhRlOoMDmLHHMpb2u9YaAaO/TQnb2VTzjwYWmUK/pei3vVe1
         HIp6x3OY/ipcdSb7zM42yYx44FUh9oSQMXUihFS9PsZUO/jlPBETrw0NoUeIvti4qrT5
         0k+g1bGjAHYjxwJN4nE9c1f2Cwrv7CBUdoy6B5IrzLeJBckocjDvd4CaJaHPrvGvy9do
         25u5mlosK605o4pG/m4bBhrkasGn6QWP3cE+99h5cLMSHvti2UIyCe6R/+6AeO3iCpu+
         1Xlt2Q+/J3a8IbzZaq7dhPSF7c58wUAibbb7UmZmBbs+FpyIoUY7N++jNr8pkPRciQwq
         LRZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772598; x=1744377398;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DBMprvfgjcMeNZiO4LjehyEw+X/YeY/L3rVgpPcBeqM=;
        b=bgoHfanmzV1aYleoQxKmOER83/AQeZAsc+SE+aCptOKkYWV3eUy5JzLr7BeVYb/S7A
         PSU7F5+G0yctLW9LORBATwDtNvVcbw99iVmoYicJtVB32aojmDAyZN6i0v4NRDmUuGfa
         d7ortUMUZ1pZkArVqEE4sM7JOHFtKYsloGv/VKSpKvrotnLSYkrQRzmo+kXQqMYDz6MW
         pljEyOw6+fLpmt/yNF1xX8latLXyqUPEcOhSd+JL9rBaYetOuyfKJ05kb8G34C3fgsGl
         b2zhGZIjXfGJ7D5Cg2xFPJdBU0XghD6I2hUyqTIflb4/mFb9bYXL2FvztGBkuwe7F2ta
         wDqA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXi6RscYUM1XkTv4YeQnnApYI6gtZ7oihL107qcnDbyrLdK317gT7dAksk1TEb1QGVMBfcqzg==@lfdr.de
X-Gm-Message-State: AOJu0Ywgt4N5ElCpjgCBwihCaaYGodZoMapIGCGRXeTCVpMCCZ2kRuwz
	4lZKP/V/tnyFwACcXZmKqxhDMB1Dn9YGMZ+7xcEv2K9YhTgqtnIl
X-Google-Smtp-Source: AGHT+IFMdwoJkd2u/x2LtvjImPuQVtBfwPeDFtl8ERXMZoiOmlf5W6H6q/ktjHmUzPH8NIZn3l6wrA==
X-Received: by 2002:a17:90b:56cf:b0:2ee:45fd:34f2 with SMTP id 98e67ed59e1d1-306a61208demr3491178a91.6.1743772598114;
        Fri, 04 Apr 2025 06:16:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJTvD+pyQa0FBE6/2UBhrjC9O6LDJUgclK8s+f/RPeJFw==
Received: by 2002:a17:90b:1f90:b0:2ef:703f:6f3 with SMTP id
 98e67ed59e1d1-30579fa145els45527a91.1.-pod-prod-08-us; Fri, 04 Apr 2025
 06:16:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWj8Bx8s1RASOpYzV2TSsaeB75ecMK095M1T7a5RefdVr+ypjR0VZMw51lck4z4eKMSfCQqHy91yZs=@googlegroups.com
X-Received: by 2002:a17:90b:5448:b0:2f6:be57:49d2 with SMTP id 98e67ed59e1d1-306a6179aa1mr4563623a91.17.1743772594586;
        Fri, 04 Apr 2025 06:16:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772594; cv=none;
        d=google.com; s=arc-20240605;
        b=R+XlGvY84vuT/RT/w4JpfVI3eOm4jqiHmjsRB8I7SRKvVyJWcfQ+bIanA+IA7sgBub
         emk+mI0LOJGycq+d+IpGi73o427AL8TB73a1NiTTE5DPZ6ufKd1E7euTiV1CuDFp14qs
         pxi6JQq3/uM+oKdvnkJi+DKVJrVsX0paKbxxe0/WaHVkZROMTPxmV3KtThAIJ54ZJaeC
         G3jzEf/8nfh+6/c6zNzZgOMPGuzMZOE1EYD3EhxNZ3SzxhMdkTzagIwz07E57FMvYX67
         /y4XdSV0cG/hMuqjCttxyUdKWadkEoaTkvVNTAwRFfT+QV8xbLHx2SgIwnySO+z7MrUL
         umIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=u3tIUvdwJ1dXcDSmm2Wnk8OG4iSBjdCOlpfnuayIjeM=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=TZBTUUja8RYWF4mWGTBmwZAHDVZbXN6qhaYWP+CVWmarfpP/QPqcW2p2M5v5FqUbqJ
         YvgVB/IwfXjqcRS7VtTQAqemb+QilvvtlDPx5UbkpzkJu+dWvaP2J7q28k6QtdsjqYZO
         ImbsW8vD1pyZndQafpfQ9jltb8UKyyTLe9cV0UF67PeZ6Sf6g+R5RqF/Gbux5DWu6lxB
         dI098KBnXd50vKvA0EuNwmwSF3Jc7EvFQNDo4oqrr63MgLg+BO/uF4W5YCDZsWkXUGeW
         rRNbEvh6f+RXbtAoWfab3PTw33FUXmPWo2x/PcEfAekkOXWy2XPi4HIW/5pTkMVj8Sdj
         bk2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="Vyj7/+yX";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-739d9ea902fsi157988b3a.4.2025.04.04.06.16.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:16:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: iIqQ7lnERPK/Qe8hy39BZg==
X-CSE-MsgGUID: ZAKAaZhETKCcqF/TOhLPVg==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55401792"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55401792"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:16:33 -0700
X-CSE-ConnectionGUID: TzYslCmYQFCBxN0Q9bAEvg==
X-CSE-MsgGUID: AIqBIgH2RQGX8Ny4prod5A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128157216"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:16:17 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: hpa@zytor.com,
	hch@infradead.org,
	nick.desaulniers+lkml@gmail.com,
	kuan-ying.lee@canonical.com,
	masahiroy@kernel.org,
	samuel.holland@sifive.com,
	mingo@redhat.com,
	corbet@lwn.net,
	ryabinin.a.a@gmail.com,
	guoweikang.kernel@gmail.com,
	jpoimboe@kernel.org,
	ardb@kernel.org,
	vincenzo.frascino@arm.com,
	glider@google.com,
	kirill.shutemov@linux.intel.com,
	apopple@nvidia.com,
	samitolvanen@google.com,
	maciej.wieczor-retman@intel.com,
	kaleshsingh@google.com,
	jgross@suse.com,
	andreyknvl@gmail.com,
	scott@os.amperecomputing.com,
	tony.luck@intel.com,
	dvyukov@google.com,
	pasha.tatashin@soleen.com,
	ziy@nvidia.com,
	broonie@kernel.org,
	gatlin.newhouse@gmail.com,
	jackmanb@google.com,
	wangkefeng.wang@huawei.com,
	thiago.bauermann@linaro.org,
	tglx@linutronix.de,
	kees@kernel.org,
	akpm@linux-foundation.org,
	jason.andryuk@amd.com,
	snovitoll@gmail.com,
	xin@zytor.com,
	jan.kiszka@siemens.com,
	bp@alien8.de,
	rppt@kernel.org,
	peterz@infradead.org,
	pankaj.gupta@amd.com,
	thuth@redhat.com,
	andriy.shevchenko@linux.intel.com,
	joel.granados@kernel.org,
	kbingham@kernel.org,
	nicolas@fjasle.eu,
	mark.rutland@arm.com,
	surenb@google.com,
	catalin.marinas@arm.com,
	morbo@google.com,
	justinstitt@google.com,
	ubizjak@gmail.com,
	jhubbard@nvidia.com,
	urezki@gmail.com,
	dave.hansen@linux.intel.com,
	bhe@redhat.com,
	luto@kernel.org,
	baohua@kernel.org,
	nathan@kernel.org,
	will@kernel.org,
	brgerst@gmail.com
Cc: llvm@lists.linux.dev,
	linux-mm@kvack.org,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	x86@kernel.org
Subject: [PATCH v3 07/14] x86: KASAN raw shadow memory PTE init
Date: Fri,  4 Apr 2025 15:14:11 +0200
Message-ID: <a5d62e8ed4eddec7ddc7a2039469ae4dd8ba0386.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="Vyj7/+yX";       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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
be filled with 0xE.

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
index 0539efd0d216..e8a451cafc8c 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -34,6 +34,18 @@ static __init void *early_alloc(size_t size, int nid, bool should_panic)
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
@@ -63,8 +75,9 @@ static void __init kasan_populate_pmd(pmd_t *pmd, unsigned long addr,
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
@@ -436,7 +449,7 @@ void __init kasan_init(void)
 	 * it may contain some garbage. Now we can clear and write protect it,
 	 * since after the TLB flush no one should write to it.
 	 */
-	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	for (i = 0; i < PTRS_PER_PTE; i++) {
 		pte_t pte;
 		pgprot_t prot;
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a5d62e8ed4eddec7ddc7a2039469ae4dd8ba0386.1743772053.git.maciej.wieczor-retman%40intel.com.
