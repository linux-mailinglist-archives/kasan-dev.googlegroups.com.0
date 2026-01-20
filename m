Return-Path: <kasan-dev+bncBAABBONIX3FQMGQE6WXUO5I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id cJdnDj2jb2l7DgAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBONIX3FQMGQE6WXUO5I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:46:05 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id C3F324697E
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:46:04 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-2a77c84638asf1040995ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:46:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768923963; cv=pass;
        d=google.com; s=arc-20240605;
        b=aEs0N2yXVdLQS1ft/ANZNrAql0pAy3XU2fWzc54rgmK3JA7201qZBUTooYVLIYRKwV
         OIPrAcwXbg7d2BTe9XUhJCtwDsMARcFiT2RediICOLd9BZ66DxJdNFQIWKRBk3kcF2Fo
         nOuFf37gh5XqY0IC9iHEfqq0qbLD3CgxAsIL3Iax2dXJRpMymtcxxnUCIQCJoWUb0vKa
         xsccZLD5BUMDv3l1bvGk5ElvW3/Lbvpngo2wZv8Xt2puiFGV61XdTn6lEngSsKX7OUQC
         vUAvXeQKhaKTIENXp8v5yumU2dAzSD0lfiTl+amDjdg1VGSZnxEC5ku3HRsxLqTxfN13
         sTjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=lDdzcVcxM+ufh5XR8eYvthPM3fl7uGUleWyBrLxT1TY=;
        fh=8EzAArx41PD2Klbs4fF/0sohZFeO6/gWWdajB1Um/XA=;
        b=DAeXKQM6492FwDkIR3UywEpKZnhF/FXD4Y2FIoDY1x+ZYDBLVsKtnJhxmqeI069hGq
         MkpIWZgoLp6g41d03FIHMXjBCNLX9Ek+b1ZsCjDyZDQu5F3yQ3aEnfFMau7Byyezh4c+
         Q+aZfIugoccoMgQDggOCVOSEkFWQt2i1K6/aAzhZ8Z0HsedAph+JMg6XcjrT9xm0yuvp
         VWMXdT6jV6BpXP6BWKRjfUn33NmaZN11Yrokix7HdTStoIIWqLx/HZBz8FGOt9LaoxZ3
         /EUPjYyRZaUpL/w8H6i+G3XSc0LU84MKQXnvHqn8/aX4g1lVhlYA31NYcz3VTHDHNLb0
         k51A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="r8/QUqXH";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768923963; x=1769528763; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=lDdzcVcxM+ufh5XR8eYvthPM3fl7uGUleWyBrLxT1TY=;
        b=iCwgUvAaCPZNLJJb2JieLE/UkgFSOTkFtdtTz2IBEK3Mxp4EoICXo7NK5ceIKrrAaY
         3EMYMOYRt+vEk+CuLYd+rn7Q0QXMdXRaFofnWhR1NNF/W+UT3AmfWBsz1pm4Q3Thc5mK
         4bcAVGNVa/Vbvo1JfQ+AW4J+zr6FNh+YcYdU1cgdD/+rrcajyps5ASEY0u9NIH+vhZlK
         pMwdt213wjwSmWjeDPw6Yvg70c6ihhmtYKPv/XsBxxkaw8TLiXotK6hnm6lITbsGopIw
         8ien+E2gxAycbFFqcgPyaJ92zX+VwAgYJZTUoKZBZ2fAhqE0moBwDA7Gi5lAP2BL6Q92
         OzFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768923963; x=1769528763;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lDdzcVcxM+ufh5XR8eYvthPM3fl7uGUleWyBrLxT1TY=;
        b=aYs0W66W9K6hneNFhGFheAwyQKYUD4KD5uDJFcqJmCa77LtiwkgddJf6SdjWUYJ/oP
         yom/txnSRPdbAHLiSX/OvtE3W6WbJUxpXfSQi0a4kjNtQYq9rUc3Q8LDIWfUuPiGLDx/
         x6GfiBcb67GDf5afuDeVy7Mf/rbXEE/O3UoRm9vKia4HYmMfopf+MNwz/a1SeAWVX6uj
         eO+E0PXyFDkii56GD4/+ug4zaK2yx1CSjCxKgjGoBFsH8G9DGkZUAD3S8X4Ihd3hCMJk
         uEwYgCysG2hwfBjSgtLkmKDuZlXnhXtW+N9P0qWi8k/hhGrRg5mdY8lHoYvCRmIKu+iM
         kG5A==
X-Forwarded-Encrypted: i=2; AJvYcCW3qTrh4CzSiauYYzh6rezfrr+zXXj7LhTnM+J06TNdFP8QUbUDABOwPJpmXeCCM6NL/Y3EQQ==@lfdr.de
X-Gm-Message-State: AOJu0YwUsfUKdAAJuniUCUJTHsFPXPGxGjvC48lXN/GnTIe/TFseLmop
	cAm3yM5Gf++zn3nm30qr56v8440rn2HHGSYyIIiB++F7QxwcCpaO5aWF
X-Received: by 2002:a17:902:db04:b0:29d:779c:c0cb with SMTP id d9443c01a7336-2a71750a3c1mr94661965ad.2.1768920121494;
        Tue, 20 Jan 2026 06:42:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Eyw6pLjADMu3UXdctDGu4u6uTtWqPWbKHwmuoYu6gc2A=="
Received: by 2002:a17:902:ebc4:b0:2a3:e6f6:d86f with SMTP id
 d9443c01a7336-2a70333f564ls52338625ad.2.-pod-prod-08-us; Tue, 20 Jan 2026
 06:42:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVE+sD3dMeR8kHOuFGAu3SWKAr23IzAHPY7efJAe3IkyyRy5L/WkkvKbbY5iyuKgVsQSd/+dnZ/Xu0=@googlegroups.com
X-Received: by 2002:a17:902:da88:b0:2a3:ec72:f462 with SMTP id d9443c01a7336-2a7698f6e47mr22162165ad.25.1768920120203;
        Tue, 20 Jan 2026 06:42:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768920120; cv=none;
        d=google.com; s=arc-20240605;
        b=ZO3Ws7TStOS0o1piR2nRIss+fVSGgx9rNj77iEVx7DAXtpoHj5UlTVRTqTA15MOe0w
         6qpRLytaxH+FqJltpI8Ho7gvyKXORppbxjauDisBkgsfT4z2TdPdoOnHggiYoBk1OyK4
         UDH+2Dk1QtuPoeVN4LsSJWmhMa4fIYGnRmOLcQo27tXeL8eZV7wrYBR5oxXaw2h13vS0
         Y5oC2ee6ah9Ph8shMHKdkK0TTIayQ0Ga82mXcxYpcW4RY3B5nHVQqtsd1VPCNr27qI+J
         G0hwH3jdIHr0qvhhQ/SvVvxVw0U3qhMjUCB9A5csAwguiH81R8FJRsf2cSwgW/j87CYT
         ilbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=A25tv44ykjvi1Kbnb5x6U/k0DKYzcpc1BCKXyH8bncU=;
        fh=Ic9cO4DP1pM0NxajhJIHL/plwfo8Sl9C6v3axgIrteg=;
        b=gw/Xmy4lmt87ugyB5M4ZwUdQ8nn3I7hjJ8ff+t2I2BzaflsO++BuSfzA9KczBOV+zl
         MtEcN9tDJB/AXlvXErSE8hT3GXJmphjlOUqO14sc5K44x4dUC1nmxbIniul8J9EDiiS5
         rRueFO5OKgZxLhpcswYUJ6X8DsA8ERderKwt7TS1f3rJ+UmeM0/361/tt4vhF2GCILwn
         45aZ00OF2IdJhq2yJKFPCNKZNJ1MZJOEbZR5GA1YRjh5fgVfIHa8maa3sGeplQ/aM6TV
         yQJU+7/4Xvy/C6ewrAmu/mA59zmOjlrL8uKIvmgf0bNSq/N9iY8/YF4ZdAHNRNi+ZbEe
         O6KA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="r8/QUqXH";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244122.protonmail.ch (mail-244122.protonmail.ch. [109.224.244.122])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a7193cd42fsi3371345ad.10.2026.01.20.06.41.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 06:42:00 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as permitted sender) client-ip=109.224.244.122;
Date: Tue, 20 Jan 2026 14:41:55 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: [PATCH v9 08/13] x86/kasan: Initialize KASAN raw shadow memory
Message-ID: <7dd4bcbbcb055dc9cbc1f5abb0825b6943d0fd7f.1768845098.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768845098.git.m.wieczorretman@pm.me>
References: <cover.1768845098.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 1638d56cbb1a8d2a03dfa4123fb056d50bb4db2e
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="r8/QUqXH";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com,google.com,arm.com,linux.intel.com,kernel.org,infradead.org,redhat.com,alien8.de,zytor.com];
	RCPT_COUNT_TWELVE(0.00)[17];
	TAGGED_FROM(0.00)[bncBAABBONIX3FQMGQE6WXUO5I];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[pm.me:mid,pm.me:replyto,intel.com:email,googlegroups.com:email,googlegroups.com:dkim,mail-pl1-x637.google.com:rdns,mail-pl1-x637.google.com:helo]
X-Rspamd-Queue-Id: C3F324697E
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

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
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7dd4bcbbcb055dc9cbc1f5abb0825b6943d0fd7f.1768845098.git.m.wieczorretman%40pm.me.
