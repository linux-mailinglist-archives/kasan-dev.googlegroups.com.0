Return-Path: <kasan-dev+bncBAABB4VXR3GAMGQEF44IM2Q@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 4KmbAvabg2nppwMAu9opvQ
	(envelope-from <kasan-dev+bncBAABB4VXR3GAMGQEF44IM2Q@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 20:20:22 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dy1-x1337.google.com (mail-dy1-x1337.google.com [IPv6:2607:f8b0:4864:20::1337])
	by mail.lfdr.de (Postfix) with ESMTPS id 9308FEC078
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 20:20:21 +0100 (CET)
Received: by mail-dy1-x1337.google.com with SMTP id 5a478bee46e88-2b799f7a603sf351404eec.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 11:20:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770232819; cv=pass;
        d=google.com; s=arc-20240605;
        b=SMy8cXalMhHbY30+3EaBjIA7Vhdtl7TJhtjtdbvHna7QqZxpB/WLgRUG/054eNvwo3
         f/of0aayp/QxD9dQvhtl1WNRi575VXABYwrqqc6G6oH6XkbFuWtaTuGY3F4iCpOfbH8x
         kcRnb0IZsyBo4Uqb5La4OcP+PXiq7HZlo831bGP0kUvhvmQ3l6mtLkR8PyZGXnFzkUlc
         GLClDJk5pH0V90tDZWIVi4aZxEyxeWHhLdLdPt4fBkdkugrLPAlAyu1fKcd+M962FW5y
         cR4merJAmrBnUktdJLbmMhkQ7Ldv2wwhutPGtlVCruuWoLRF3yyMvTrrWhi1ulRDjz/U
         eeRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=SPBkNEFa+Y6LGvYukzbuyBSFXoh8cHYtojM9cLx//2g=;
        fh=XNJQdOwRDGjIxjMMBeSkAgGCuEWkCzJ6ojJWzBHaHHc=;
        b=NLL//TDtS9x1906tS2OIIwqBBZvKhOhgFTP3FDtTY3zH2UrMsLVE4EcRTYg8IBthCm
         pW0JoGA7qU1O9Q91FMcuV05xr9i0QXfHoD4LNXkA7y5NoKTOa67mNUqO1rUFDMTxFNzJ
         AY0efD7PgdlBt+Hp2g05WlbOgH/x6h7cXleimC+sIOMRazETcDyhTqYWkc7B0A+DS8/p
         cBWfCZo/PuJyujnFdugBpB8cwvGCo+lKj1uVHGZrgXcKeTMWubCvySI6yqb1+u4UezUe
         vPYwEBeX5jIxGgFffZ9k42LUQz2+3HEfuTDt387U7bxwopNm2Z52q5X+0ihPEpeKRGix
         4M4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=rNvLAa2c;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770232819; x=1770837619; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=SPBkNEFa+Y6LGvYukzbuyBSFXoh8cHYtojM9cLx//2g=;
        b=EDy0HHVBwHa001OZ+30IQ9tc5mp1GbG/v2oL2qMW1xc1u0WHrNl4wjP7oDvXYNC9s7
         UrFF93Txr5bf2iH1Bfn1cysP8SuKefVCdxixEvY3Pd+R1yzEygEhS3EZqQTzrSSbbpj3
         4gX4ScQlle/oGCCA7ekSqWmcXMExY88vRQ0GGzs7LW0Zt/BUcyOSNTn1IBeVAl8zQxX6
         3l3FyoU0+dJDwh+GWbOVeWwWIQQ6pNDuNayQPyEtzpFk9HGOubE4eY0OuTrTLLZhoogz
         B7xLhC8wEcJE39B0nenG0MX0Ybd3fQpQ1D9V63HMer9PA65rllzBQH+J2YRcL8XYilej
         +jnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770232819; x=1770837619;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SPBkNEFa+Y6LGvYukzbuyBSFXoh8cHYtojM9cLx//2g=;
        b=Usalf/atZRXSZgcHg9iijMbWPjvsVtLmrDBdn7SbwAIMY0x6z4Eun/FQgOk5l0Pomk
         OZCwbeBk5F4mlPV0pDyT+e/1qh25xGdvmEOUsE0M22tdO+q/7UNivn+vNp9OTC7lx4qn
         2ztCI0vOh6wdie2l7JYWUv52SlbhkPjU1bZi2kHmRF5LwbRKWYrKMN3Dupp43j28ornI
         +xKmFhI+LYPxyxtq4yXBHyrD58IzE3wE6HmgnVdx//7oTQwGaNnSYidijvVWHym78R1D
         2dzuCoj3xqAqWnXAKAUh7jSk9GnhFfUsDPTuJL5qJWIMF6IGMxoWBxMZorCr9JuXQLHQ
         62aQ==
X-Forwarded-Encrypted: i=2; AJvYcCUNt4m3mEADqvnI3tqZNy8+qNOP5ZM09HD9Qg+5xdLT6SjkGtGPvUFMMA3x2to65CeZiAjZag==@lfdr.de
X-Gm-Message-State: AOJu0Ywc560w3gtlC+PSZ0qNxIt/WddnpFaFEJQtOFYiow3nfoV5pW4w
	54hZ2qR7mAJeeVCo30cNpVdbI3CjIFDiAP3okHrW4Z6bdv3nkYZi0EUQ
X-Received: by 2002:a05:7022:220e:b0:122:345:a948 with SMTP id a92af1059eb24-126f47dd567mr2136911c88.46.1770232819066;
        Wed, 04 Feb 2026 11:20:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F8Q4MIjS1rjUjcX8xY4c8bPPBV5z+GkLbQ7mX2VO7Wuw=="
Received: by 2002:a05:7022:43a1:b0:11b:519:db61 with SMTP id
 a92af1059eb24-126fc109224ls117395c88.1.-pod-prod-01-us; Wed, 04 Feb 2026
 11:20:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW2m6pz/NiBjzsuUjONsFFeNgDJDPpcR7lg0Xlqe7isVmPTvIFnK2UQo5ton27D4SRMu5r+3axf+eU=@googlegroups.com
X-Received: by 2002:a05:7300:ed0d:b0:2b0:4943:8999 with SMTP id 5a478bee46e88-2b8329a94edmr1745124eec.33.1770232817752;
        Wed, 04 Feb 2026 11:20:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770232817; cv=none;
        d=google.com; s=arc-20240605;
        b=AsjMGrv4dkJQk+Y2Vz4z19/6qYngwx0wXbESAfpFGwcCW6YdsBB7/RBCptMlAaSFKc
         qj6/rN6x4KABpSksxwlClEADv/LbcQaGO8aS76bwHXOUvG0tRe480q02aID5u3hYN/FK
         awdnHthYvGjQ1WzFhZHXGOqPOBwXM5Tzp+oIwmDzeY+HNEm+4KmV76AT255gAJZbJ1zR
         h8ffbpZj4NbqsJRyHB2xFGRVopRYoTkkaLbO7bXzJKemcDyklxU6xGDkipbioKY62CG9
         abPIenG1GdfcN3Z7LDjpVJ/AhklA7ar3i+f5LxKWFJEYyAej51aurHp+gs5gM+XKyxPT
         2IXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=svfiyvtEE/lqQ8xsx5lT5DL7oiLrvzGxpb3VchVEZvw=;
        fh=Ic9cO4DP1pM0NxajhJIHL/plwfo8Sl9C6v3axgIrteg=;
        b=aw1sKBWBa6MXjofJenx81XVOvYokmW75ZZ0OJUTY0ILuX5FE5LYOL6iyIe3tHx+IMB
         CtB+iiH1bwiPBvAhNVxeNow2jiXzMCGFZdFAyAIa11iBDqec/FpNXPvGkv83eWQYnpiH
         B5XyGZr1v23PWkDIwY5hDAPAKpj7NtDG9N0ipUCPfiIKKyv/q0W0xnRQ48OzmjPVQCHz
         LJ1mrDvGAXfL1OS3dP4ikHurLghvO53Air6cdl5QmALUWE8Cyd4M1qjVs8GWHeajx5Md
         zfTpuA6obAv20aAj38qw9XmmdXX52T0Cz4pkAxSj68VuB7Bh27CeDXpcj3I+gWJCdrvb
         +neA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=rNvLAa2c;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244116.protonmail.ch (mail-244116.protonmail.ch. [109.224.244.116])
        by gmr-mx.google.com with ESMTPS id 5a478bee46e88-2b832e0eb35si119540eec.2.2026.02.04.11.20.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Feb 2026 11:20:17 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) client-ip=109.224.244.116;
Date: Wed, 04 Feb 2026 19:20:11 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: [PATCH v10 08/13] x86/kasan: Initialize KASAN raw shadow memory
Message-ID: <2b8c56c9cd5eaa0947c9d892aabdf90d8dcc1a32.1770232424.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1770232424.git.m.wieczorretman@pm.me>
References: <cover.1770232424.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 07e7f08f7e4df775c95de8f939252895a37507bb
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=rNvLAa2c;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBAABB4VXR3GAMGQEF44IM2Q];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	FREEMAIL_TO(0.00)[gmail.com,google.com,arm.com,linux.intel.com,kernel.org,infradead.org,redhat.com,alien8.de,zytor.com];
	RCPT_COUNT_TWELVE(0.00)[17];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,googlegroups.com:email,googlegroups.com:dkim,pm.me:mid,pm.me:replyto,mail-dy1-x1337.google.com:helo,mail-dy1-x1337.google.com:rdns]
X-Rspamd-Queue-Id: 9308FEC078
X-Rspamd-Action: no action

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
Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
---
Changelog v9:
- Rename patch title so it fits the tip standards.
- Add Andrey Ryabinin's Reviewed-by tag.

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
2.53.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2b8c56c9cd5eaa0947c9d892aabdf90d8dcc1a32.1770232424.git.m.wieczorretman%40pm.me.
