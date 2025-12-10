Return-Path: <kasan-dev+bncBAABBDO443EQMGQEB43WZ2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id B2E2FCB3A12
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 18:29:50 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id a640c23a62f3a-b79e98a23c5sf543766b.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 09:29:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765387790; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z/N5cHVi48qn7pKq3RxddHGVZaoTYXk5y7MrzIj2cuoQ13ihsYa5+8YG/KwC8fRKDI
         uwiYiW0rTetL53boVTkmeiPPIBLAg/Mkr2/4h94Dtz3FYd/yincP4t/ZH4cxHwnQ1sAa
         H8OpAJiGot/S4x6Yp6JexSF+B54yiWuFP8MebYWVUeIO6XsqIf76Om5Ut/9nUWGRFEzs
         VVWC3Z2/zaqAPDUw95Ml/JTfzw9zJd6ZMn6eS7phY7gc6TRxe63b0PRw5AMpPW/etjMo
         InBSjtunuMt2gdQUVf7EoSP2o/e5uW5HnCRFNFjvSCU6+lU7HQDbpxNzpvEjF0DfP958
         tlDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=xYmgFzrgxXWPQDsLUaG9s4LC1Ewg4f9qFd04LMFf6no=;
        fh=CjBsKM3GTHUp3uBRpWMXTJSHvHEr6vnJzIL9CED5nco=;
        b=bSGWDUnXUkm9jiMsHah6s6caljfdRCpCOdUBHI6i9KtrrFtao80o6hAfQKZW6n6TAQ
         tMoyPSWWSis+ezTlp0xCtEvj/4sNBnyQFKqOjiz8uBV3Tjplej1jYTiJyHcilZBWuWgS
         rzIoHryLD6FJw100XLlm6omGKD+W9BuffpDa3E/uY01gRvKV2ARKLZ3uiXBd0HqXHPIQ
         3huPkcA/jwMZwG2fYaALwqHeJnMGLDqrGKT0CT4WZOpkFtT/e8VuRn/CWHcF8Mus1Esu
         sFJzJSAdcV83F4SreI1tmSeVb1BgCqqTLx0zlLuLXbINin7I/J25Zk+fvXdxc+eiIFqp
         stNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=BzeuwUkH;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765387790; x=1765992590; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=xYmgFzrgxXWPQDsLUaG9s4LC1Ewg4f9qFd04LMFf6no=;
        b=XmsEWubmKfxJlj/ApPvXvxXgpB+SU7cQ/ylslRxZkDLiezgYA+QUWoNPybwf5c/WJB
         39NZc7UdCfikU/jZm1tsiR3VNjEUCG3WsUur4m/kBTuP+5O9Q/rJJUTquErD2pfqRK3p
         egbHbiDdD769HzEOd7yGRSXISs33fkalBvfdORwPcMvsBegFslNztX2JOpMXRe/qWy2V
         H75fcp7L9kWCIZCAqK/k5sOBRECIkRP8cS6+HE/uQxzsXyihw5XN+He61rJIl4LB8SSr
         Bsb34idgYcLoF4pH3HFG0fEzIVcqLX5qAaFBf3byDGiNuqCuqIRQiPkioYdUWvqy29iM
         WtAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765387790; x=1765992590;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xYmgFzrgxXWPQDsLUaG9s4LC1Ewg4f9qFd04LMFf6no=;
        b=TOwb8miD4BljS0f36U0+ErYEnvKFFE6NITYJMIlb+x2qWtAsHTUgaqdtCbypf+UR8s
         98Ym/e8mNSlan+2ZBqkI7jIUohqALFV5erl9MHvR6OcOwXm8i1AvOLEeoAXt0hDJk+FT
         19HD4zdeMephxJv5bUDNB0QzFGzVxiy8TbaxHX9forKdGSmoxej2D54Xw68G/pWgssuR
         gFcfOgQyoNzGMH+XyMP/5QXyMDYo9XPm0Aq8AYH93tCmnKdCYL9904bqsqIsxaoq5tIi
         tdM2MstazJ/mW1mAxCc2dIvwln8AZii5SgYxdr/9AetxHjp64d7WWTUxNwYEdQAcXFgh
         vUZw==
X-Forwarded-Encrypted: i=2; AJvYcCXVJfDkUhmicEidsY4GZ9mRljhyCIiNQTC9utXSI5obrCSB8Ev7cEUBSMZb0Y31Q+Uu//66tw==@lfdr.de
X-Gm-Message-State: AOJu0YxXpugE248xWqdNh4mMkYaF6ECDZiIELYGPooovs0ekgb0vrpws
	2IJkAlujoxzX2QpwcqrxTmZyc7vxIndl39p3oYfVivuGB+Mb1Zz39OzK
X-Google-Smtp-Source: AGHT+IEaMv7VH/2Y6eZLppGk2IDH27HdKQrt51isSA9zpx7geoi+BEiWxej2mF2jhktPUi6uEc37cg==
X-Received: by 2002:a17:906:794a:b0:b74:984c:a3de with SMTP id a640c23a62f3a-b7ce83f69f7mr390535966b.28.1765387789959;
        Wed, 10 Dec 2025 09:29:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb3hVJ1H1+3XN0ZYkzYAesdtd3HVHbUWGsGkp/HJHJBeA=="
Received: by 2002:a05:6402:5206:b0:643:8196:951 with SMTP id
 4fb4d7f45d1cf-647ad2f52a2ls5895758a12.0.-pod-prod-07-eu; Wed, 10 Dec 2025
 09:29:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWylrgKpabjSjf/bZ3HPrtivtioC7NzAKc8c8XjSlmDHI4vWdUO/QWU0UU5wkGQLf2Nl/5LtlAt9ZQ=@googlegroups.com
X-Received: by 2002:a05:6402:2109:b0:649:62e1:10ca with SMTP id 4fb4d7f45d1cf-6496d5b627dmr2920908a12.27.1765387787422;
        Wed, 10 Dec 2025 09:29:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765387787; cv=none;
        d=google.com; s=arc-20240605;
        b=hOmaCkkSFcO1FZ7cvI5TfecXlk94fGziMTRNW0mkyGWeqPXSJd9Td8r+9yzzkMgEUv
         yr6x8bomj+CBImk3U5iWhsWQM4NVfYZ8Hw4fJ/jNx8bs9mrbKERN8OLgGTsDBYMiTOxo
         MNE/L047+/CnnAasi49sOAApH8FhScJ/BSzr2KiwIwGbmMufikD5uVlw7gKYn6XsbKMW
         yS4eIXNM1PLY9nS/6k74b/vkHy8fdCn7leJYGmerb8ueL2J2jXyXcO4DuA3zwjaewQWc
         J2HA+2pBdC9OlnTullmfQu5EPmYN9YRX51np3CASSSUzaCj7R903mDP/zqHnLKMrhs3o
         Ar3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=3onoTwDkEsWsTTZEKyNLGTuXan36WSJnDCZpzSRbbSc=;
        fh=KLj9rC8/yM5WHvRVQqlm3CjMJ3Fog1rZzSvqm1XSRj8=;
        b=dOTTSWTDetuWnO2OarxT4Mrbo0b1QMEYR1UvUzoOg7QCLRwisuKpxj01vu7OE9cE3Z
         Z2FTq/n2XKO3g33Qvf/kj2L2PSLTmsZkaVqk720cQ5ELePdU4Xhlb2h318fMsXBn+4bS
         8uQSIuxz2iRh0aHmUc9fgBEFoXGMYIhWYrnAmyYMfd4q6uTt6Fhq0nP5b8JbzGuMKsYr
         o3GYXbnk6++x9wDo1Cfs69HmP+2iKL4IT9ROkw/PmlOsfh1tXBoFEcC696ZuluHG75qc
         BwGG1DQbQZEjdtMT2/23Q9NbQwdPPLfrHBP3HdR3KiH9GxfEHeXiLrCqqFosBL8jOyKp
         SPBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=BzeuwUkH;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4316.protonmail.ch (mail-4316.protonmail.ch. [185.70.43.16])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64982042339si2191a12.2.2025.12.10.09.29.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Dec 2025 09:29:47 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) client-ip=185.70.43.16;
Date: Wed, 10 Dec 2025 17:29:40 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: [PATCH v7 08/15] x86/kasan: KASAN raw shadow memory PTE init
Message-ID: <d8df791c9209ffff2ff23bdc724a9d31986e032c.1765386422.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1765386422.git.m.wieczorretman@pm.me>
References: <cover.1765386422.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: d96ecac2f6d36d49de04f91f75d4a5b61f3385a3
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=BzeuwUkH;       spf=pass
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

In KASAN's generic mode the default value in shadow memory is zero.
During initialization of shadow memory pages they are allocated and
zeroed.

In KASAN's tag-based mode the default tag for the arm64 architecture is
0xFE which corresponds to any memory that should not be accessed. On x86
(where tags are 4-bit wide instead of 8-bit wide) that tag is 0xE so
during the initializations all the bytes in shadow memory pages should
be filled with it.

Use memblock_alloc_try_nid_raw() instead of memblock_alloc_try_nid() to
avoid zeroing out the memory so it can be set with the KASAN invalid
tag.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Changelog v7:
- Fix flipped arguments in memset().
- Add Alexander's reviewed-by tag.

Changelog v2:
- Remove dense mode references, use memset() instead of kasan_poison().

 arch/x86/mm/kasan_init_64.c | 19 ++++++++++++++++---
 1 file changed, 16 insertions(+), 3 deletions(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 998b6010d6d3..7f5c11328ec1 100644
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
+		memset(p, KASAN_SHADOW_INIT, PAGE_SIZE);
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
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d8df791c9209ffff2ff23bdc724a9d31986e032c.1765386422.git.m.wieczorretman%40pm.me.
