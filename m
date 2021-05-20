Return-Path: <kasan-dev+bncBCJZXCHARQJRBZMGS6CQMGQE46MDSEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B758389B20
	for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 04:03:19 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 139-20020a6304910000b029021636f6732asf9487638pge.17
        for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 19:03:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621476198; cv=pass;
        d=google.com; s=arc-20160816;
        b=ECngDcYdapUzjkaaAdquqrMMfxwMDFDJM1Bb71ziMrReWisicd66/XNcn2ERndMIOo
         /RWF1NxiTXHvn0fQbcS8ymYcA+J3CaVVdOWj3iUWVxqQ8MBWFUqIvE3LcNvKnh5O8Z1X
         BLbNp0rusSXF4VaU6P/4MgOcxnkCgz1501Lod46sca2l9PauL31yLEYNw2bgyWuVYO5g
         mYUnT31GepvgYwwFOjCqrxU39Grnl1AHISbHMgsysLSMcsUBbXlZOLnltUtNk4PXcM5F
         etFgmwh4MBd1NwM+uUOGRVfuz9S6I2V4DUt/UtGEyILXNv/9dY0UR7CMQeJtVZzzkH60
         WxuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=6jzVRvfdn3Cqmp8UemGcH50yTQmtfFo46RNS34T5pSA=;
        b=nNnz3yv9vhJ9C20/nF0DWuyqSfKq+6fXIvauJHKz3zwaHHW+lFmpGE2c8JeXRPj5iG
         6Sdm9ga32iJ+0bloHzhChchLUCeeEivSIYZjJdCq7U71W5uzUtt6MpxZCW1F3/C9ggru
         fJkwo6Cv0vLEbXKb7IL1uD5jJB4kguZaSFQ6vDQZWceNGRklxrYC7JiDVhzpNttY6N9e
         vc3dIJgFgrSTU3Q2XrjP7RX6my0nnRVBdFMktOh8/hUQqIMbVDPpy5L1dNNFgpaKZzuD
         JpLGYFQ0ed3oBXwPKdBWohex2BMj7Hz6asDoFFuJ48fD3t4tgZr4FlWrRg2wdTwUdvqv
         Rn6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ffv4hWV7;
       spf=pass (google.com: domain of 3zmolyackcy0vbxv4z9x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ZMOlYAcKCY0vBxv4z9x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--eugenis.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6jzVRvfdn3Cqmp8UemGcH50yTQmtfFo46RNS34T5pSA=;
        b=awcZuFdWzVcJaH4OH6xLbqDVZ9yW/+zW7SIqj4UGzVXma0pG10fpGrCvzD+EFf5GTP
         Uwmy3sDAMK33rusIpa9TtdxC1bHC838VFtubl27jO7BzWK5JeIyjOer0Kga8WYXufxV5
         jaymjYhmzontPmeEq2NRpb/RRBZoTbvT0sqUPzx+FjWcxJhzo6WEnPxuFMiC53NZX5yn
         rMFT+7Os6dgBVKm9y6kMzoiC9HVMehfA4pdzLx5lGM5EfnbCdlAWYJ4pruOoFlWBQgQi
         K8ig9u0KgzLb2W+LB2L5RSXzvyY08teq1XGL9n3CdeCL8C5cKyKDEutf/S2Sifc1VD3w
         hj+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6jzVRvfdn3Cqmp8UemGcH50yTQmtfFo46RNS34T5pSA=;
        b=hTHVmpH3AfhSpRPO6wHGCL90U8FPpTGmWd1zkvbX0Sx7LQzwlJxMjMxBlAFQKyPJGZ
         I9Jzfm0mYHpOp9EETls7DsCF8PnV7hez9GiyBOyv8splsq2wULzhl9xNybRteFbfoPr7
         b/yzPYajl2CKDnuj9D7hrJNuc0ViV0lEg0sFCZDts3mk6lEf4VvQaXkiOa8Iec5pLbez
         2aU4wOBjAs/Kor5y1HJmLx10c4HUP4D9pKWuzZc7pCwajkTB+PtO2PxsysLirkEBfCdf
         XE4unPU1aliSK48UdcdKPUMqlNTjLIKatpnRCAZW/WdHuWJW5BptQWz3v/oWRRDwKC4D
         dfYw==
X-Gm-Message-State: AOAM5318a/FLwf0dN+8pDZERPrfRsnj07z1+TsStFumh1k8swbPX8f9/
	xCbsspy0msk36gVNH493LCc=
X-Google-Smtp-Source: ABdhPJwjGwPc44MG7xyAvmPVUBMifYHO8leNIgF3h3MQ6nlkmfVFR/TE5tKf+ikhVUAltih+BM8dhQ==
X-Received: by 2002:a17:902:ea06:b029:f1:9082:3ddc with SMTP id s6-20020a170902ea06b02900f190823ddcmr3029648plg.43.1621476197934;
        Wed, 19 May 2021 19:03:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8d95:: with SMTP id v21ls731478plo.8.gmail; Wed, 19
 May 2021 19:03:17 -0700 (PDT)
X-Received: by 2002:a17:90b:180b:: with SMTP id lw11mr2137604pjb.141.1621476197243;
        Wed, 19 May 2021 19:03:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621476197; cv=none;
        d=google.com; s=arc-20160816;
        b=Yn1m9ZGG56dTlRMLmqQpwmc3GfDWgF77PTH0kWmnopmkXM4xdP2+6AIQlBl/ltkydm
         wMfxCQqERX0FzN9jRXo5GTypeQDpw0j+4btxvNJlDeBc1GxFrW74r42zI6/1OUKvW/Xb
         WlhvYGiaQ4Wquli8EalKYONXZJzp951h7c78LAtgdZT7fgjRFEA0jylfxtGt6peI/4Ql
         oFI7OgEsCArmFtJ2/zoi10BBPVoV03LknXdWqDf0UcOJcz+4NI+h8Lz2AbgIeI/h+pkO
         5XVIJFGDXOVBXm7TkJ8ptMHgpfM7Dbj6d49Uq3cZPRKAjwKUcn+U5o7m7Hm06SErZRSi
         1v3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=RWXPMPgEuCU/3b7hbbrURn9Chl/0n89KN/Wk7Q6xjkE=;
        b=t86e+q7e9Pn0SM+Ykzqx5wCipyzEcGj95S6nQYmsKwIkG6T7JFt/jJusZYPPFtDGdP
         i/RuCCjtO5J14ijEaKROMNzgvdvK2SEbVhWXpPq9LSx3kruTLwL20oPq8q7mC53CegHy
         F65XKATeCoeLKYeCxvGcKJsTG0oJf8WEmV6jw111Gaei7NmYb/hFeT2lubsLOexDDcNN
         tmozJPVUuJD4wFJXiW1Jx7dWB9VppoQ72vyorHQJPo0/NHPBmLpt5bv53QupgsNy+Cge
         xgvFY16h/HCe1ZFKtSjmlTyCPcHwMmxLd4Za4ut8ek4doM+0b95csFH5C5QCy0Lj1jwQ
         sEfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ffv4hWV7;
       spf=pass (google.com: domain of 3zmolyackcy0vbxv4z9x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ZMOlYAcKCY0vBxv4z9x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--eugenis.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id b17si153223pgs.1.2021.05.19.19.03.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 May 2021 19:03:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zmolyackcy0vbxv4z9x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id q6-20020a25bfc60000b02904f9715cd13cso20482789ybm.3
        for <kasan-dev@googlegroups.com>; Wed, 19 May 2021 19:03:17 -0700 (PDT)
X-Received: from eugenis.svl.corp.google.com ([2620:15c:2ce:200:b800:442e:78b7:3fac])
 (user=eugenis job=sendgmr) by 2002:a25:b701:: with SMTP id
 t1mr3595486ybj.348.1621476196428; Wed, 19 May 2021 19:03:16 -0700 (PDT)
Date: Wed, 19 May 2021 19:03:05 -0700
Message-Id: <20210520020305.2826694-1-eugenis@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.751.gd2f1c929bd-goog
Subject: [PATCH v4] kasan: speed up mte_set_mem_tag_range
From: "'Evgenii Stepanov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Steven Price <steven.price@arm.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: eugenis@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ffv4hWV7;       spf=pass
 (google.com: domain of 3zmolyackcy0vbxv4z9x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--eugenis.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ZMOlYAcKCY0vBxv4z9x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--eugenis.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Evgenii Stepanov <eugenis@google.com>
Reply-To: Evgenii Stepanov <eugenis@google.com>
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

Use DC GVA / DC GZVA to speed up KASan memory tagging in HW tags mode.

The first cacheline is always tagged using STG/STZG even if the address is
cacheline-aligned, as benchmarks show it is faster than a conditional
branch.

Signed-off-by: Evgenii Stepanov <eugenis@google.com>
Co-developed-by: Peter Collingbourne <pcc@google.com>
Signed-off-by: Peter Collingbourne <pcc@google.com>
---
Changelog since v1:
- Added Co-developed-by.

Changelog since v2:
- Added Signed-off-by.

Changelog since v3:
- Move the implementation back to C with a bit of inline asm.

 arch/arm64/include/asm/mte-kasan.h | 98 +++++++++++++++++++++---------
 1 file changed, 70 insertions(+), 28 deletions(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index ddd4d17cf9a0..34e23886f346 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -48,43 +48,85 @@ static inline u8 mte_get_random_tag(void)
 	return mte_get_ptr_tag(addr);
 }
 
+static inline u64 __stg_post(u64 p)
+{
+	asm volatile(__MTE_PREAMBLE "stg %0, [%0], #16"
+		     : "+r"(p)
+		     :
+		     : "memory");
+	return p;
+}
+
+static inline u64 __stzg_post(u64 p)
+{
+	asm volatile(__MTE_PREAMBLE "stzg %0, [%0], #16"
+		     : "+r"(p)
+		     :
+		     : "memory");
+	return p;
+}
+
+static inline void __dc_gva(u64 p)
+{
+	asm volatile(__MTE_PREAMBLE "dc gva, %0" : : "r"(p) : "memory");
+}
+
+static inline void __dc_gzva(u64 p)
+{
+	asm volatile(__MTE_PREAMBLE "dc gzva, %0" : : "r"(p) : "memory");
+}
+
 /*
  * Assign allocation tags for a region of memory based on the pointer tag.
  * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
- * size must be non-zero and MTE_GRANULE_SIZE aligned.
+ * size must be MTE_GRANULE_SIZE aligned.
  */
-static inline void mte_set_mem_tag_range(void *addr, size_t size,
-						u8 tag, bool init)
+static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag,
+					 bool init)
 {
-	u64 curr, end;
+	u64 curr, DCZID, mask, line_size, end1, end2, end3;
 
-	if (!size)
-		return;
+	/* Read DC G(Z)VA store size from the register. */
+	__asm__ __volatile__(__MTE_PREAMBLE "mrs %0, dczid_el0"
+			     : "=r"(DCZID)::);
+	line_size = 4ul << (DCZID & 0xf);
 
 	curr = (u64)__tag_set(addr, tag);
-	end = curr + size;
-
-	/*
-	 * 'asm volatile' is required to prevent the compiler to move
-	 * the statement outside of the loop.
+	mask = line_size - 1;
+	/* STG/STZG up to the end of the first cache line. */
+	end1 = curr | mask;
+	end3 = curr + size;
+	/* DC GVA / GZVA in [end1, end2) */
+	end2 = end3 & ~mask;
+
+	/* The following code uses STG on the first cache line even if the start
+	 * address is cache line aligned - it appears to be faster than an
+	 * alignment check + conditional branch. Also, if the size is at least 2
+	 * cache lines, the first two loops can use post-condition to save one
+	 * branch each.
 	 */
-	if (init) {
-		do {
-			asm volatile(__MTE_PREAMBLE "stzg %0, [%0]"
-				     :
-				     : "r" (curr)
-				     : "memory");
-			curr += MTE_GRANULE_SIZE;
-		} while (curr != end);
-	} else {
-		do {
-			asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
-				     :
-				     : "r" (curr)
-				     : "memory");
-			curr += MTE_GRANULE_SIZE;
-		} while (curr != end);
-	}
+#define SET_MEMTAG_RANGE(stg_post, dc_gva)		\
+	do {						\
+		if (size >= 2 * line_size) {		\
+			do {				\
+				curr = stg_post(curr);	\
+			} while (curr < end1);		\
+							\
+			do {				\
+				dc_gva(curr);		\
+				curr += line_size;	\
+			} while (curr < end2);		\
+		}					\
+							\
+		while (curr < end3)			\
+			curr = stg_post(curr);		\
+	} while (0)
+
+	if (init)
+		SET_MEMTAG_RANGE(__stzg_post, __dc_gzva);
+	else
+		SET_MEMTAG_RANGE(__stg_post, __dc_gva);
+#undef SET_MEMTAG_RANGE
 }
 
 void mte_enable_kernel_sync(void);
-- 
2.31.1.751.gd2f1c929bd-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210520020305.2826694-1-eugenis%40google.com.
