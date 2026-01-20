Return-Path: <kasan-dev+bncBAABBVFIX3FQMGQE4CMBGSA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id YF/8BzSlb2lIDwAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBVFIX3FQMGQE4CMBGSA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:54:28 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id B3A1746D00
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:54:27 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-655b10ed8d1sf4328489a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:54:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768924467; cv=pass;
        d=google.com; s=arc-20240605;
        b=YfoQEk1dMrxRGMa3SNicYIFpTZ3SHaIdA7+3DfwqS791295bZ6veAo1Idyy4YxadGY
         77woNadBiDrh/wD5/D6RZ1rOWQcRNwzd/iC7OKuWiGtEiwQWbeLMglJ1TlaXes0aRwj/
         +LVt/WqXi4jHczkbo/+xYQz5AZXdpQCcfdwXh0sotKS/ulWAE9dopnf8BwACOOut6Rkj
         v/pmVbXmONTvDmOuI3eA/N79thdY48HYbXNfzr1kzqRRsGnFl9bFv5HBSam2Bid71bio
         5lwrFNNOHxaaSpLbJhW+FThGqciJDTnRP6ae8EB0X/fllk8x1I0zX2BC8tH08BfbuXcK
         WAaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=AenGwoOau0ABTeFZ4NZyNH08LOHksOjPkiPDYKTcu7Q=;
        fh=qZqJBvvLfI3NZeTau8KFSEEYMsbjQzMIbCSvbxxyY9g=;
        b=hX/dJ3b05B9zzJv6XC1woJL3JVdo9R9ZC6QOjRbho7KK96j1YD9JRO3fwrX4gXvZmm
         IPa1GKFiqwN6o5GCROtloPPloHmIXawRJMBCbTlcWme7ieFMk8nwTtpExqczbC3l+QPi
         kM8khEQxlVSikOvo4Mf+YN37Yo3HjJLgfmkjuO1R8ciO2mjVYYKKUzKEA+SjkQMA1ONw
         ZZcn6l+3pgbmvSgyHXwtFuO1//itPMZmb3S9kAVbDd1xRj+1S4RzcACXFAcQvdskJNZQ
         a7GpdaAn4OhkGbgWBTGqjrH9AnJ8G1RROy8sceaGvu6XMZP0KH7WOpllr+6WysbH+N3E
         Me+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=MPjzsOCN;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768924467; x=1769529267; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=AenGwoOau0ABTeFZ4NZyNH08LOHksOjPkiPDYKTcu7Q=;
        b=AzIVmXFbLIIO8KWuFbdrbI2UaCmQXMCTkads3S3t3/yIa3hP4/sjPzOHHcLY7JeHxT
         w+q95fnbXcUEDCAYz+OFwMVEivuaQlqQwYLbHLt5gMrvMEmbtEbJfBxVywZv1JVpJAMG
         zNXeiu/SSkiVSNIKc8c0ZYSYwNcU41xRmP6rgIpxqNBAQAPLACsy5wyV6u+0ZIr+Zzy9
         mvaJDquLDujBuCHMkSMjcZzeUswHaZ+b1mfCghaSacdNLwua08zx3XMNwmHoXwKL9v7J
         5C+UlyERG1GJM1/Ke93fFyql34Ds1cHGJkMaf+HaJvW19t9TaDV76DtYV0OCdgCwyE62
         xj8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768924467; x=1769529267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AenGwoOau0ABTeFZ4NZyNH08LOHksOjPkiPDYKTcu7Q=;
        b=VBUEUREoIJQPykujWKg8yI5FKUsr8K+OqJp+oRDMdkwiu56qwcbTnmanRFv7wYX52G
         jx10eKRLTteuq+Rq1IFhNzvoYUETz2FAhYMv3hIX4kSaWlhsEcq9yupNho3/8IJxX6CI
         QvR8jg4dM424Hmn1SJO7Hgg2aEsvTAqN1DiiFsvMWL7ZiX6bkhQvh4J0lr52j4cSp0Jc
         cypN64lm1dMDBcpH1MRHKrBK87959FO8pqh3h7nvBh501J5zzeYYjEARJxrViy0R5Mhs
         LJr1ofs7tGbLwwam0xL6UqC9eU03UzgmeSC6MBatulA5aQD9PwwnIPmpZVI4iqVC1qD9
         6Yxw==
X-Forwarded-Encrypted: i=2; AJvYcCVzhxnhHyexAFuJP0YdT/kYildfjUeazWKpRj0jnVEE6kD7Xq3kmXtyHqUT35vAnmhl5klbnQ==@lfdr.de
X-Gm-Message-State: AOJu0YzXv3IR/56ZMsOyoaxhHm4KLbi98EHA6Lt7q4efXV/WVZHPRxzu
	pc+qQ9PdmCnm+BXbfBxZD/ugmYZtvbjTqmzbSleNOo+0sSEsL+qSHTrM
X-Received: by 2002:a05:6512:401a:b0:59c:bfeb:fa22 with SMTP id 2adb3069b0e04-59cbfebfb25mr2830669e87.10.1768920149356;
        Tue, 20 Jan 2026 06:42:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G/XpO31dd7y1ooDHx+6eDHryGmyFEKDYd2sqPe37LEuw=="
Received: by 2002:a2e:3309:0:b0:382:fc93:d438 with SMTP id 38308e7fff4ca-3836ee0c362ls4329671fa.1.-pod-prod-00-eu;
 Tue, 20 Jan 2026 06:42:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWBGkNG1d/0uik8LSNASq4dlnRRQ/HXTZigU9NlQ5gMUGlLo74ItCLr/URGuCy7YqUXqYCnJzt2ooE=@googlegroups.com
X-Received: by 2002:a05:651c:31c6:b0:382:4f57:e8d1 with SMTP id 38308e7fff4ca-38384e0783cmr49522181fa.18.1768920147019;
        Tue, 20 Jan 2026 06:42:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768920147; cv=none;
        d=google.com; s=arc-20240605;
        b=FhY8mvYpyfBQK8L2kojPb5ZRHcn7OobgYgRN58CTMZmD2LvpamqFhOFTPPv6NUSaT1
         YgeL8jqCpkdhvcjQ1tZDwZ5ajFkHGkoJZ0BsMhrwWqGcAT43Z6yIUkbzT1zvn7Z6CGU6
         luTLCxb+59A79vaX/zcH4nBpXJpSvaEnIPv/ObDb0TgLBtBgBM+EzYyO9ki4H8kHHdPE
         j4kVW7YJnzNvcgSNSjuHl+L0PoVnwttqAh+TLap1H08bXh8BrOy5+SNxcWkmtDo8zLC5
         uJ+6oZOWFTBb5ikr53ptc5/EPUrVTMruofAtGx75fXspIgHcS9LIZ0fGTbv/39CUpEpN
         gCoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=05JADZgjoheEyPdKhVm9fLyRjRHfc1LL020rdvHmL5M=;
        fh=1M1spAKXRL1ft3V52YDxcSPLLmwT2TtGJN4YN+QkeXw=;
        b=iWkhUTlMaMYpT/iWELt8RKfCx+S3Hi7z88H1veC3O+H5XSft44AveZnHhmw3GedKRi
         0is5lU8sb81dY6DxWx33+M3imprD2bfGFg6IcRmrLxkNiTncmUU7vlfAIiVIxFZi2mer
         E3St91U9NaZq79L2bi8XzV8zR8sIX4kUWaXfmVvJF2JgOy8dtwrhv+Y45ID/ZLkUdlIS
         DBXH6Pba4rrVaE5/PcELodJO93+E5OEsdKFrGvg5Uf5PW2AnXHmzFz4eshYZLfpyDo9O
         9roNHZwOvdRt4h1N89nvAI9Imnh5fHRBAdBeojPj5d9zdLCyTYQYU0B+9KazMnip3njy
         1jjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=MPjzsOCN;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4322.protonmail.ch (mail-4322.protonmail.ch. [185.70.43.22])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384d0ff47si2750651fa.1.2026.01.20.06.42.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 06:42:27 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) client-ip=185.70.43.22;
Date: Tue, 20 Jan 2026 14:42:18 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: [PATCH v9 12/13] x86/kasan: Use a logical bit shift for kasan_mem_to_shadow
Message-ID: <30f2be778f068da0c489979b70f8c91119414a41.1768845098.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768845098.git.m.wieczorretman@pm.me>
References: <cover.1768845098.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: aa6d3c3aa640d2e8287111686e4ebf0b609cfcbc
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=MPjzsOCN;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as
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
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com,google.com,arm.com,kernel.org,redhat.com,alien8.de,linux.intel.com,zytor.com];
	RCPT_COUNT_TWELVE(0.00)[15];
	TAGGED_FROM(0.00)[bncBAABBVFIX3FQMGQE4CMBGSA];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,pm.me:mid,pm.me:replyto,googlegroups.com:email,googlegroups.com:dkim,mail-ed1-x539.google.com:rdns,mail-ed1-x539.google.com:helo]
X-Rspamd-Queue-Id: B3A1746D00
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

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

Duplicate the generic mode check from kasan_non_canonical_hook() into
the arch specific function as the calculation follows the same logic due
to the same logical bit shift.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v9:
- Rename patch title so it fits the tip standards.
- Take out the x86 part from mm/kasan/report.c and put it in the arch
  specific function. Adjust the patch message.

Changelog v7:
- Redo the patch message and add a comment to __kasan_mem_to_shadow() to
  provide better explanation on why x86 doesn't work well with the
  arithemitc bit shift approach (Marco).

Changelog v4:
- Add this patch to the series.

 arch/x86/include/asm/kasan.h | 32 ++++++++++++++++++++++++++++++++
 1 file changed, 32 insertions(+)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index c868ae734f68..90c18e30848f 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -31,6 +31,38 @@
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
+#define kasan_mem_to_shadow(addr)	__kasan_mem_to_shadow(addr)
+
+static __always_inline bool __arch_kasan_non_canonical_hook(unsigned long addr)
+{
+	/*
+	 * For Generic KASAN and Software Tag-Based mode on the x86
+	 * architecture, kasan_mem_to_shadow() uses the logical right shift
+	 * and never overflows with the chosen KASAN_SHADOW_OFFSET values (on
+	 * both x86 and arm64). Thus, the possible shadow addresses (even for
+	 * bogus pointers) belong to a single contiguous region that is the
+	 * result of kasan_mem_to_shadow() applied to the whole address space.
+	 */
+	if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0ULL)) ||
+	    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
+		return true;
+	return false;
+}
+#define arch_kasan_non_canonical_hook(addr) __arch_kasan_non_canonical_hook(addr)
+
 #define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
 #define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
 #define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/30f2be778f068da0c489979b70f8c91119414a41.1768845098.git.m.wieczorretman%40pm.me.
