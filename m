Return-Path: <kasan-dev+bncBAABBRO6STFQMGQELFJJZLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F680D145B1
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 18:28:39 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-88a2f8e7d8dsf192356286d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 09:28:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768238918; cv=pass;
        d=google.com; s=arc-20240605;
        b=GCqazv192vxfXALFxIJfeoQQbmZu5Kyc7rZwtnZUQCjQ5LBplfoEeN3qAYgNBvAJM0
         5jn2Eb8vdWLcF1XBPYVsD6EJ8rIOyLFfWJn6Uc9z+SW1jNBtFAT0kLgq8JUbShgZpC5T
         Bd32FXrCEm0uir665UGJsnoO6HjhLTVGOvzfsuTBw8NzPLgAPvi61WUtkTb+/1R4is8O
         ALIzclA9zhnKW5h6/cEml8NKtP5URU3J8vy5t1JzmSNLQz7F7blhgSkz1nWzi1NJdfPP
         N7e+caIHf22hENq7OvvFmd7QpZvGrCYIMuMzPudgE6GbXQrfKI94ZSkdS6OCszgVhjEa
         9K4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=ykOGCcHW3/qzPSUJYxa4ZpuiM8lGNvTZQTXuFjVNn+8=;
        fh=AIF5pIQG42mAHgkvB60J5FyIE0bs6OVcpYSP2P6ILSA=;
        b=iUtWShjgVVD1H8y+KEImJa9tc4j4ZblhUpqpiEOQklIAghKT6yyCQA8uZLql649i48
         N7CYEhSzvkFl5NUH+M5h3fLi5iBPGO3rh1Jn2rnF4z1gBpadWDLpE+H1ZFB18HTg6yBr
         kFghFZjjj8jXEc/kVAImJebTuYK30HLKBkYHQduFrfgqeUV0PHRgzUKQPtKCi5hwPXFL
         5Zv49UTWjJo+HIw9JMiZz4cCu3aaqTIX1FP/GDEQJCNbF8INBi7VuvHZd2WXoP/FKCsP
         hHIlCuXYXBTq97qbX8UxoRa+kHm3SCv6SnkhoHvrQjnMEheXYDafrTg2eiX1QpTMfvuP
         B7YQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=G4blWAFk;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768238918; x=1768843718; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=ykOGCcHW3/qzPSUJYxa4ZpuiM8lGNvTZQTXuFjVNn+8=;
        b=jLtubMt1rJIkCunH5xRhx0WmO6aTr6h0zOwpr69UwvnaPqOhTUC8jfoAJba/T+pIg+
         eAv5E/yhTkBe4fXveV5oPVUJHsyLKJ0CxjTlCGoIbTsI7avrFwEs+6rlXffiGSj1L5Zm
         B28nrJqMisr00lgVq02zCExQB7FDJszcWy5EI+mK80VoGwTaZSX8y/7ewo6S+Z9Oe9CE
         2jZIN3OTsK/waZDDRDh5Ludnknm/INyo3N6q1oiSirnnAQojJFiZjpPFDswztWbNZAuB
         0olSvjwDKnADBNA804uyW5F09B72SevjXBGCCOAFVtAqhJzredUTTzo1Ws/LgdDYvTLO
         vb3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768238918; x=1768843718;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ykOGCcHW3/qzPSUJYxa4ZpuiM8lGNvTZQTXuFjVNn+8=;
        b=T1fINikNZsQKhUvPWVw7SJ3biWqCRB6H7uC0aCYddmwOlJK1aURTaXUGb3gegi8Seh
         LGudx4eUH2Kh71QXW5GkOF0p5DhsZKVr1cLgXoNldUB04XfS1ydxC+Ul9PMuMRm9XUG2
         dtN0NgkdhY4YIqIi7QKsxpw3qIxjmaO8Pc9o65C5n1uLH6uyUV7EaxB4PgxBcEX/4by7
         rw84GOZ6SAL8sP/+lCPW4hY5ZNIAU0x1j6LFVXI887CJ3VmhmzPWb5UoTXeoQOuYK2Nb
         zczRENRV4mzi3v5WXVgix0JHlXMRgTcga6VQ+V9OUBrcl14Hll1zUs4/5J6yXNj7uPVf
         1QGg==
X-Forwarded-Encrypted: i=2; AJvYcCW27rRiTOsovDEYP7UvkQMslTmNaz85JKLjf49ntcWDA8WbElQsjkaFNCqeR0Lt0oyoA5Emyg==@lfdr.de
X-Gm-Message-State: AOJu0YwZB+CR9ujXzfeyN0bpAZBCDDYGeTpRJy+DrHqNNADmepuuORCT
	/wI4WL+PlOHHsVVHHk4c47vKtsS1KFoNQGvNFMVyzV0bRhbR+uMQYKB6
X-Google-Smtp-Source: AGHT+IEvHkhKyMxiPYki/JZLeUOjEwp7tp4AKF8I35DJ4cwVUtaR7ZW16/t0ACSMjQrXVcwZzQubRg==
X-Received: by 2002:a05:6214:2427:b0:880:6a57:1a48 with SMTP id 6a1803df08f44-89084187182mr237944546d6.12.1768238917692;
        Mon, 12 Jan 2026 09:28:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GyA7nlZ2hxhAT879msMEOsGi34SjkSCke1yw7xA+9lWA=="
Received: by 2002:a05:6214:d0a:b0:88a:577b:fa53 with SMTP id
 6a1803df08f44-890756cc896ls145386796d6.2.-pod-prod-02-us; Mon, 12 Jan 2026
 09:28:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVm7/NiI65U1aEAld0GEoOAW9dRR9TVtd8qBg9WiInzePhC/RYAc8BvClYlJvXmX0BmSvpMJEGflS4=@googlegroups.com
X-Received: by 2002:a05:6102:800e:b0:5ee:d0ff:7254 with SMTP id ada2fe7eead31-5eed0ff7574mr6062739137.34.1768238916688;
        Mon, 12 Jan 2026 09:28:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768238916; cv=none;
        d=google.com; s=arc-20240605;
        b=bbYtMIeSIJIUowE+UDDf0JJ5mFYlCLcgkA98L0SgWRS9dPr40ojG7KngxbzfLdaWc0
         IQqon8KD+nqCP6y5K6jY5I8HMuJ3EtuFfr4Gfdpg0XgQb93iWOnJ+AHq1trxfDG6XN9M
         D1Qcr4tqvPBYQ6o2iB7AeP2wsAtS5281StKZzeF96E6vHFz9h5p9rQ8Lhrtq7/QKwR6C
         z00ngj9EnP1buwpMrl+fA30rwy3Tl4TiXL9tnSF7zuSgH9AQ0GuZU58wRFUMcQyQHxUU
         irHRRlCWjIsymV0dDxUqdcr70XfwcFlJBHFfNGpCewPvQW5ft8jwuMD2Elub98txLYwv
         7MbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=/xH0MFGMknW13Vj90S8r/ENniLRp7vgZ605IVSOXpxk=;
        fh=jdv7KQkHDi6F8sQiaOexIKwuoJIlqxv9waUs6lMJXcc=;
        b=En2WDEkk9dLfAGxwHG6ohwE6QmVfDU6Q3kemkcuAkhvhYdyjT3QMZrTpbcU/57nL4e
         cxLkC5oIPe69il7SonVegHmrXMyt+zUdc0gD7MiokNPMvnwvZH1VNoX8/pZ8JsNPLRW/
         tXZdaRPSDvNbv8vG8MGRTg2jx5bvHO1PBoO/zK1gZwO9QesB5+4dy3uGD5aPKdOk9lB+
         2KpzSYBIME7WrHkp9q1zWos2BJrDJvlp1M0UvkGgejBeW6O+VvgIGsysxVKhVFOUATGg
         33xL5OYYm1pxwBKGufsYgb2We+VbCriEdm+ygtiO+gp8D8OSC68YoqCb79gWXMDcd8oB
         rjRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=G4blWAFk;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24416.protonmail.ch (mail-24416.protonmail.ch. [109.224.244.16])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-9441327f1a9si678909241.0.2026.01.12.09.28.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 09:28:36 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) client-ip=109.224.244.16;
Date: Mon, 12 Jan 2026 17:28:29 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v8 13/14] x86/kasan: Logical bit shift for kasan_mem_to_shadow
Message-ID: <b1dcc32aa58fd94196885842e0e7f7501182a7c4.1768233085.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768233085.git.m.wieczorretman@pm.me>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: ebf057f553a2e357d38ef3e18edf71ca7fe2c8c0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=G4blWAFk;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as
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
index eab12527ed7f..9b7951a79753 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -31,6 +31,21 @@
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b1dcc32aa58fd94196885842e0e7f7501182a7c4.1768233085.git.m.wieczorretman%40pm.me.
