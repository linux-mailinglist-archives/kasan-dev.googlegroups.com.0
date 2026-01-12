Return-Path: <kasan-dev+bncBAABBKW6STFQMGQEN2T5OJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id D7B23D145A8
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 18:28:11 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id a640c23a62f3a-b801784f406sf854977566b.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 09:28:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768238891; cv=pass;
        d=google.com; s=arc-20240605;
        b=EcSexWN4y42D5B8ZM/Vb9+EQqUAY6E2CTq0A2Pktevhn9uHiJquZr3fYUTJsy3xPFD
         tjlKp6WKBscuteXuwhRmvpTBhpEgZb4D/MDJXFM4JqWwCC8CVKjns3fZa6YlMB9TNfF5
         HUZxh2WV+ORsHy4noksuNyqDDl53r1n380ApmbQmsdbrOOQjkpbClT23WRhfKi2WFUXD
         h/Y1uEf4sWTuJcWKJJI29Qj5DxbYfbcJMdfO0qQo/2+CgZNDc4uS5Q10OBuEc6tMnGFQ
         27pG9CVeWqUsw+oNGSh2hDaN1yYfRyI1KA3haXvNfQl7XbLrqfoCFYMFuSpwtNj8S4GQ
         XaIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=ZHEzd9gzmDykn0R+nl38Df/NzYhyNc0t9u4KJdGTER0=;
        fh=X2aIt32KvJq1lU0WDL11iCCIAG6gPSw1KagaQMdV6Ok=;
        b=iL+JFwFrjJy4gATGe3Odmy9P94Qa1rgBt00ahM8PwK/bp0Mf57yMAm88R1ZNVSXrCy
         MIxgYKa7/wurHECZZsbLqNUEbopgE+6//YwmH8eXZKeJPUG1ELWD4PYWptpAMDven5nA
         1sgzXoA2lc2/f/uTXUhyaTDCrPRmvzTWJRKdxoEqawPRIWCYaqvgPhkdeQoJnJXtRk4d
         rDKOexNyRKYkTFhZEDF3yG5Ovl3Hm3V8RXeyFoqGJq+siNgw6D8BZGjqYjsLGliSrHSt
         K/8QwCyO/MBNvIaDw9xF2ybmad6ejgMjECbLa4LaE1n1TrI77ZDMjtsUR/THi4pVix2N
         2/kw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=d5+JR31P;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768238891; x=1768843691; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=ZHEzd9gzmDykn0R+nl38Df/NzYhyNc0t9u4KJdGTER0=;
        b=qwSIW06QRiFeja6ccRKrDS9P30PPMSGsO1bNSCa1Q/0IKtinFk7soUpTSfYGmW9WCD
         w0n1Ws1OnC3Z5jTRqoYCtFkEMuL65kmphQZ77y7vQQLJS8nTZdFCPc/Cr+1seaqTgPFG
         +81OywvyEbGhDZklyBzG+E5uYJl8z4B8yifL5YMHjsBXpKzjsdHcR7F+wAqwvL+bnyHj
         NU9n9CsXEBGbOlJlaqMkLh0ncp4Km6wACabq/GUShNdUtbJI1vGuGZVSk8WukAVvaZUY
         w/Qqt+tu7xDXx8JSGOxQe8fpJ20Ya3mo/Xz44pbQhPGrgOrYsigJDBsexTegYB0HSPEi
         9soA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768238891; x=1768843691;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZHEzd9gzmDykn0R+nl38Df/NzYhyNc0t9u4KJdGTER0=;
        b=IC1VQ3MCsxjeClDlUkKyS3EvL8qt/76QTtaCWdX1M13jYUYsAwrpbQMZlB53yavBx+
         90BZIj8TYUOTKy2+0jol+GNL+mCZfLOBvKrDCfDQoVW9zbAZCKqfumsqJwPiXqwx9vX1
         XT+JutNFL6KqR1UODfXwqQnv5K7oJqP6hHmpO+yakHqTstQkojMeA/rEYeuYb11wJDVJ
         TqXJMJr4K1e7TccwlK5dvVfr0L/l1uKjfPg0KlMTMOB9Sdq1tkrW4wxRNJzwf2Hl+fOE
         TmScuLzloi/bwDTC3upPoSfmaegv844dG3fmqxmrXLpW2CLVgCitKT0RXgJoh0jWT4mB
         ApZg==
X-Forwarded-Encrypted: i=2; AJvYcCVyjzZYF07Nwa3ZM/4w2olb3yq5ZHC++s+iSJGNj8VYOm5xmV3LDCW/uglZ1aJj6COjISJP6g==@lfdr.de
X-Gm-Message-State: AOJu0Yz/GV2Khb1pzOxcL+ZuvjNDXrv4R/1lwty/ShgYj2jsIsOfhBpR
	WYlyKTLcVjbEZHUGsf5XzflfYAaYYz4QIc4h4ZScte0H+/XZ9JHh7icj
X-Google-Smtp-Source: AGHT+IFBRLTT0Q4M5CBHuaIZxF/L1BW01tdVuwunyGZkIFZY94+1mawW+YHGPUnTRR2r4uyBlzBL6w==
X-Received: by 2002:a05:6402:35c8:b0:640:b373:205e with SMTP id 4fb4d7f45d1cf-65097dfadd8mr18206921a12.15.1768238890997;
        Mon, 12 Jan 2026 09:28:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GTnrwH9xi4AMEZWHmrScCmbnVbEIaCmE0YJY17yKC9TQ=="
Received: by 2002:aa7:cb46:0:b0:64b:7641:af54 with SMTP id 4fb4d7f45d1cf-650748c6938ls6448290a12.2.-pod-prod-02-eu;
 Mon, 12 Jan 2026 09:28:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVRUSgiyY072YoDEwsbXOVBISLoCHOLbjnBWPzi0IzNW3SL/fkEkUwrxEfQrB01GwjjBikRuC2pItg=@googlegroups.com
X-Received: by 2002:a17:907:3d8b:b0:b87:19b3:3d66 with SMTP id a640c23a62f3a-b8719b34151mr363946766b.60.1768238889126;
        Mon, 12 Jan 2026 09:28:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768238889; cv=none;
        d=google.com; s=arc-20240605;
        b=bJuYOx/IGzakLbhasFPVST6W+ltEB22a08F6Lhow0fo2P0vfEnQqefssn6AbjAFhtY
         txerAW9mAqgd1s8wwuwgMHnYo3O9A7aKsIZKLHtS6FfQ1GItCIHDWW23cnQelCotkyvM
         HqbPXwtq2+ga0f9GmpAB12nYNDp4HVSbMnXrpLJzwqHLOgHyaA2ZsT1CLH/wj1qHiViq
         JnzBtKLHWVD4QaiFOEKfBrC/NX6oUSxfOimL1oIwJrAF+Q/6oM0H0LR5QPOQ2EgBatZ2
         1sckiLWBETq99N5eNHdjC02ZDHl/0Z0UI/1/pTuFZxU2knfNLN3jiIYGqAhvhoE85pMr
         v9FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=3onoTwDkEsWsTTZEKyNLGTuXan36WSJnDCZpzSRbbSc=;
        fh=Ic9cO4DP1pM0NxajhJIHL/plwfo8Sl9C6v3axgIrteg=;
        b=ebCQbiFSuuWB4Q7EHFn4UkBQb3XcUKlk4kPSalniv/08prAZ8X6sHdoeK/d6cLfiGJ
         AhLwdtmBht9C2knKGgecVeB3qz/x9lHDIPtdMyzNy1e2wPEVLUOiEdLH4sBoHUKU0ZVm
         fjLI3bHLKDvXJxzezGGXTQXH49iMGuel9m8FXM9uoigqI/RvKO8+pptu4pgpZNhZ+Fnf
         6QgkreACLjwdwPqEP57w/xIrCtzDSjiPZgBDSDKnsJGXPd6VdqUeFOMSAVTZIt45QUN4
         jQ5UkALMmIgrwDqEtrMCr3ppXMexMvklytFjzS3Yv1S+CUhAQtAOzHvTh6sSu/NJmpGt
         /img==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=d5+JR31P;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106121.protonmail.ch (mail-106121.protonmail.ch. [79.135.106.121])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b8440d439a5si33749466b.3.2026.01.12.09.28.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 09:28:09 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) client-ip=79.135.106.121;
Date: Mon, 12 Jan 2026 17:28:05 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: [PATCH v8 08/14] x86/kasan: KASAN raw shadow memory PTE init
Message-ID: <9968297ee3c83a73e1fb05c6415b024d1d2d6a04.1768233085.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768233085.git.m.wieczorretman@pm.me>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 10ab74b16ddac3f72093d110909467bea85605dd
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=d5+JR31P;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9968297ee3c83a73e1fb05c6415b024d1d2d6a04.1768233085.git.m.wieczorretman%40pm.me.
