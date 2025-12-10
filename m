Return-Path: <kasan-dev+bncBAABBMO443EQMGQEAAJEP2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 604CDCB3A1B
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 18:30:27 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-6416581521esf99806a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 09:30:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765387827; cv=pass;
        d=google.com; s=arc-20240605;
        b=goFwpEc3V+qX1MACvuf+lxfqLzG9DU+5WyiWJi+U0NYw0Jup7EAo2gHWCjxYSVEjJp
         R+XI9n+fXKsYGYqanlYKK2p0TjPzUXbphu48T7KoBlI/77xafUWbzjCXB9/o5ryyDg0r
         Mb/Reqf6sEzSDblArIw+ZZDOwgrAvQZwJ9trHzjw/24vNtJEmEI1y/3o1PHBCF7xYRUc
         uhE7l+tNJA91sTdCqvbxNBLjFNjWQRu2cULKiDChDs7BWm9AeSAC8fAvpswm4WZOawD0
         kkH5Re3h6Bt4YkDPG27arOiFnSyVeJn+ran9BtEpWxstuSCTOT9vOK0Ix7Rl9QXFHTvq
         iSpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=srLdLxfR7P7wfR1513LWZrTslSSf4es1klTRV/G/CYA=;
        fh=tk5bLafHKWsn25X7cFxXE77iHjSJv4tecSlpdo6zPIw=;
        b=ftXcgdPQA5BxO/46XsCPXY6dCe1lH/l0vs6f4x7p9njbcdyks7fpCM119EXC94apt6
         d0ab7DWlCt1ak5zBthJ71x9YLoM77ve0NTTgnF+30xxBmyUERFbLh4o1TKugMyZmWSky
         npw2Clasp5HCkWHMA4VzdNNTd8pCvj0d6d5/92nXE93YZ+ys4/RuQ/FfPDmRAMO7KuDU
         BINRQFmgWhX53mLIqkKLGfDLjWrbRkjOcb9w6X1adIjfo1LUNRyaIFkzxCzZ9/+gvHmV
         Oi429hq5/2+9PdFpU8ZIPLVJoGdTjLLHd9KpASakAkjhD27y21vVncYeNAbkOTBrDCQU
         eM4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="WwAq/3hF";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765387827; x=1765992627; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=srLdLxfR7P7wfR1513LWZrTslSSf4es1klTRV/G/CYA=;
        b=lawD4j3m1E/IyoB4DtPZP8KA60jx8OnsNSyr6iXL8mbgQydYqBUCltwAXUIvjCxjXY
         X59kPkfTdCE2xyf4IhHjsITQ7nyOCHalKZ7bbBOipxFbk9FWAQPaD4G/TFiT2hqxhb+e
         QQsT5vh34gvvrzZ7cdTwBevlb7zTiKkS++iyX/ovknGTkLhNdQgXopTqSH2ypLqzwt0c
         eFQ7Vt71e6MPgkg/RCzs65kgIFd2PVNDjgeUu4qhCwewLaD7DS58HXlV3GcRRUzDjDmz
         BHeEqAO4xyq4kqv+OdTfY5+qKtnVTLJaizyU96n5ClG4JDYuQ3zEWPfr5+Vygeu0EoDz
         RZqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765387827; x=1765992627;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=srLdLxfR7P7wfR1513LWZrTslSSf4es1klTRV/G/CYA=;
        b=Nvwv7c2Og3gOYo31C+KwWUexCXgK9f0bHeiZPM88hz41MpnnURmw+Vd9Nu+xAcYAWL
         SPoswM50KqohAXOJdHCySGJMVi3176afbifhTTNeCmL6jjbLzxT7+0LDqc//1PrttMt9
         kNA4zrmVOg1ODl7wt2C6GrYlLu2PWpMqb2AXB1JW9aPFzP+m0JN3OhUOfneJS4zIsmWh
         gTkO9rdGlkvoHzwxiG36e8OLlzY0gqtejpTCBWftKm+HmQy12sIUWH4+La+u6mhAF/ni
         j8eKFYXiXQMdT0JvQi68TdkH4Zv50WcYcv3/QDfsCQ+65hMSHvOFfwISi0s9YZcT7kND
         Cz1g==
X-Forwarded-Encrypted: i=2; AJvYcCUTQMqgVUnGRtb2z3judnd8FCtvO1hyUO9Af7rjN+/2iOQWJxaO3DlM6KstjTMKPoJmLQCxUA==@lfdr.de
X-Gm-Message-State: AOJu0YySWDWhaEUldBCnfQ3c7pKxhXOFeAel1GyZ8zTo8mgxvkGKkWSW
	3CWlJ6XrIeVDEjYFvr5jyYthrDUAnDgEA4QpdmyTzizVib/BQy9AZLvg
X-Google-Smtp-Source: AGHT+IH5UTe0C2M6Y1ysUSNbRxSDTkNvnb+UyeM0OCyaZyn6GZHObJ9HaIOgwq4ZC16D+Ojsn9HdDg==
X-Received: by 2002:a05:6402:51cb:b0:645:dc76:c169 with SMTP id 4fb4d7f45d1cf-6496cbc4320mr2771643a12.21.1765387826454;
        Wed, 10 Dec 2025 09:30:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbMLvbZLTehH/IQWXWvg2jtjtz0GD8yrvmMbtHy59Jxhw=="
Received: by 2002:a05:6402:5346:10b0:643:8196:931 with SMTP id
 4fb4d7f45d1cf-647ad2edcacls5166739a12.0.-pod-prod-09-eu; Wed, 10 Dec 2025
 09:30:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUibZ29KVUBbAOF8Lwc37mqznbBGmafU1XWiVqR6E72CPucp4iTGVjuQLN6J9renEe0krrz7kH2Xb4=@googlegroups.com
X-Received: by 2002:a05:6402:234e:b0:640:f1ea:8d1b with SMTP id 4fb4d7f45d1cf-6496cbc43eamr3203042a12.16.1765387824494;
        Wed, 10 Dec 2025 09:30:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765387824; cv=none;
        d=google.com; s=arc-20240605;
        b=O2sQhX437ooOxbswQt1mjbMzXaPJiAJu77ke94LB/ITDKz3FRXexgGxvpMdBuLvz8S
         3sTsZRNoa0JbycgYYxFLPG9a296Y7khJYPgf5usrMmPU/ZIyncMRkon+7fO8BK6PU23z
         dzbX7IJAGKT6a35DvO2+VgnHNAO7JgPcraIkyizltaEjtB675MiYkA0BYYV6lhiKZPed
         fOcG2j2XOhdteOkfx02AyV5ETB9QIxobRW4hfqpTCBQSINVEKsit9sjtblA/n8yeniEa
         LIS70eLEx5bN1G3wpY/EqeQdq6pzq2ZLLrnXi68BgjIq13hkYc2g1PFV8sE3qSbODOb3
         h8RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=yptnXmuAYz2NtPaUpK9TGJ5xoKzD/S2RQj7G4MSwUA8=;
        fh=lnRawnbYaphrv/cdWVMfU5jZn46h4hXJw/4SyEBAVY8=;
        b=UGYLLirmR1n2t78YO+OK9YUQvYd+zRWTJ08LI78V+T3/LUw+wlt7s0scwZkf75xFnr
         ICXiOH2eg7b92+rnFVeO3bQ0CbQ7z6nQbPnuFbtF5P6I5LRixYDA4vzjkzNjD43kDXsb
         ENRd6e8BuWh/6BoVedSk+eihkKaqu11eJAUvsSl079MImikXlot1HkH4vEQYYprCs3bN
         aszwwLBNG3aLiId/Z9+So7nylfSPteO12Fcspd010Y8ir+FPP2cz3DXjWeCm76s4AeOx
         Z54vcI7lPfX8uL3iVLPgDGP5hx9wBDWuERGFoRoZuvN7IUJHsr8gI6ODuyQSkTb9cosZ
         62qw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="WwAq/3hF";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10628.protonmail.ch (mail-10628.protonmail.ch. [79.135.106.28])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-649820f7a5asi2822a12.7.2025.12.10.09.30.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Dec 2025 09:30:24 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) client-ip=79.135.106.28;
Date: Wed, 10 Dec 2025 17:30:14 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v7 14/15] x86/kasan: Logical bit shift for kasan_mem_to_shadow
Message-ID: <4dd0d4481bbd89d04bcc85a37a1b9d4ec08522c4.1765386422.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1765386422.git.m.wieczorretman@pm.me>
References: <cover.1765386422.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 67aeb239351e306f83687190add56130a7705643
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="WwAq/3hF";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as
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

The tag-based KASAN adopts an arithemitc bit shift to convert a memory
address to a shadow memory address. While it makes a lot of sense on
arm64, it doesn't work well for all cases on x86 - either the
non-canonical hook becomes quite complex for different paging levels, or
the inline mode would need a lot more adjustments. Thus the best working
scheme is the logical bit shift and non-canonical shadow offset that x86
uses for generic KASAN, of course adjusted for the increased granularity
from 8 to 16 bytes.

Add an arch specific implementation of kasan_mem_to_shadow() that uses
the logical bit shift.

The non-canonical hook tries to calculate whether an address came from
kasan_mem_to_shadow(). First it checks whether this address fits into
the legal set of values possible to output from the mem to shadow
function.

Tie both generic and tag-based x86 KASAN modes to the address range
check associated with generic KASAN.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v7:
- Redo the patch message and add a comment to __kasan_mem_to_shadow() to
  provide better explanation on why x86 doesn't work well with the
  arithemitc bit shift approach (Marco).

Changelog v4:
- Add this patch to the series.

 arch/x86/include/asm/kasan.h | 15 +++++++++++++++
 mm/kasan/report.c            |  5 +++--
 2 files changed, 18 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 6e083d45770d..395e133d551d 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -49,6 +49,21 @@
 #include <linux/bits.h>
 
 #ifdef CONFIG_KASAN_SW_TAGS
+/*
+ * Using the non-arch specific implementation of __kasan_mem_to_shadow() with a
+ * arithmetic bit shift can cause high code complexity in KASAN's non-canonical
+ * hook for x86 or might not work for some paging level and KASAN mode
+ * combinations. The inline mode compiler support could also suffer from higher
+ * complexity for no specific benefit. Therefore the generic mode's logical
+ * shift implementation is used.
+ */
+static inline void *__kasan_mem_to_shadow(const void *addr)
+{
+	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
+		+ KASAN_SHADOW_OFFSET;
+}
+
+#define kasan_mem_to_shadow(addr)	__kasan_mem_to_shadow(addr)
 #define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
 #define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
 #define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index b5beb1b10bd2..db6a9a3d01b2 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -642,13 +642,14 @@ void kasan_non_canonical_hook(unsigned long addr)
 	const char *bug_type;
 
 	/*
-	 * For Generic KASAN, kasan_mem_to_shadow() uses the logical right shift
+	 * For Generic KASAN and Software Tag-Based mode on the x86
+	 * architecture, kasan_mem_to_shadow() uses the logical right shift
 	 * and never overflows with the chosen KASAN_SHADOW_OFFSET values (on
 	 * both x86 and arm64). Thus, the possible shadow addresses (even for
 	 * bogus pointers) belong to a single contiguous region that is the
 	 * result of kasan_mem_to_shadow() applied to the whole address space.
 	 */
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) || IS_ENABLED(CONFIG_X86_64)) {
 		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0ULL)) ||
 		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
 			return;
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4dd0d4481bbd89d04bcc85a37a1b9d4ec08522c4.1765386422.git.m.wieczorretman%40pm.me.
