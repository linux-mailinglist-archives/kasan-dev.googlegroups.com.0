Return-Path: <kasan-dev+bncBCJZXCHARQJRBMMMTSCQMGQENDY2QUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4699D38BB28
	for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 03:00:35 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id t13-20020a170902dccdb02900f0bc643e1fsf9253474pll.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 18:00:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621558834; cv=pass;
        d=google.com; s=arc-20160816;
        b=qUfpNHRwPjS53xgHAxF5d0/ywFtXEyzMqLLoPuowozdRM1SErq7ai/jZIi3am7Bfib
         uGQcLY4/+uQmVdkcYaI6HCjSdqGnFIUOpV6c/orfUSzuyfqj+Byr0pg28rXszCWAV+qE
         +wOR894sqYh0nUHkoVOLLj2qn84rvjI4RYKxcBHkVlNz6zxe6jiIM7tLUSCLgPL7dVxL
         UWzJjnx2wOkgWdSE5ajx5sAkHhzceytwqSsazwbopySaZsmCKDas0DgOR/wQPwsQoInH
         17w6wvAF9Zxl3e+pEKrxk1jeUkuIPrhfsfYCaaeGRLdkwX+cHY7WeOx5FytDeO/UUGNl
         ZWrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=o55wi/slJFT7DNUG+WVwOP07FRtIHE4wC8PPTDjKvHA=;
        b=fDG/eXMV2SfjX4YsQmby5iiBOfO5byq2e+HYdVBqgQO1LmR+x+hL5UTyAe4AZKLWBX
         +5btEDXblQ6WiGHeKkIdcJG3E+EwKJ5tFYJdb+tZm+cid6d2arMQcps2GLVF3zYnnRqV
         C5WqMp/3nPoTILgW30Y27I1Wx/vsU5zA8WC4p6HYCpBgtWAD3w0FkSf1eezm68vBBXqd
         qp0fdWi9bN8NQ8ZarFNKgOVfwW9ojeTrYXg8nXlCb1/3TrGsThD1Xx16ZovOysHfqxx2
         XXY4CuvuzvtRJuWHjrE6+56X7cZ6Hyfnqj2aRWAHm3FgsTrpy+uKBxrHiT8ztQlSfIf1
         HjDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BwoAvtTf;
       spf=pass (google.com: domain of 3lwanyackceiiykirmwksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3LwanYAcKCeIIYKIRMWKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--eugenis.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=o55wi/slJFT7DNUG+WVwOP07FRtIHE4wC8PPTDjKvHA=;
        b=JkC9rOXdOEdEZxv9Eivq021zR0YokKFt3WvbZkKaZBCwlrWwuM/bexnIKKNyE/51Vu
         HxU2kxp5nncw9uwm6Je5LyP4LEF1PB2wuzZ6HP9lulYiCJm6pOBOX8qkZ1Qx5TakSa9R
         XimRqCex+ZJwgHFjgBxFd+MZvLKIi+0JCMcUMBgd7tU1ou91f+hERl24KRpQA1e75PQS
         o6aBUnFuklZob6zSbWNoXAyokrWuFr8Uebw0BM+aolOnJFB5EpYMJfYfLnfu7O0H62li
         poXO1SASMZknGp2DozQd5vmP/9sSsAxW2UaJz6kgV3kseR+Ez9qzW7gEQ1mwxe2DZrms
         xnLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o55wi/slJFT7DNUG+WVwOP07FRtIHE4wC8PPTDjKvHA=;
        b=jnm/sBa+EHdRbiFDcnA1OzA7fP/pq0pJcgFVCY/OEh5qPt1RjQ0bjPPgrwtG8vtkWm
         lFD04jf3+NjFCW/Q/PvYYKb7V0Vrb5VxT/cCdhzHLT7sMAliRchteRLkBTRaOwlLtJOL
         7ww16ZZU5vhqr8H/+ux1YkhBQmL9ke4nWEnDn8sLexnkI2E+QAUTXVKBvu4BE/0JQOYv
         V7ZXTHfbjcANRdVdj0fjO41V6Y8HO47Lel08qA/QMLfLK2ndQpBkUmXnrJCk9s6aZOAE
         nftovaNNBZCZdSuww5rnUaZNlYwcToTi87nhshsRAyluSi28L3wijQk91mgBYZj66eUE
         PXNA==
X-Gm-Message-State: AOAM533o9UU3bBqSa21LWPQnwfC9mv6/31VOrTe+acWfibYT1WJZ4uev
	FGZrZANXcTKXXpHrXbdBp1g=
X-Google-Smtp-Source: ABdhPJwXr8TYFPpfknyTyHyJ95suYCcRQX+tFsDCy4Wp85ekab7V9uhjXpjCBvS9wBFOlm7dKUHuPw==
X-Received: by 2002:a17:90b:e02:: with SMTP id ge2mr7829422pjb.196.1621558833873;
        Thu, 20 May 2021 18:00:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ce82:: with SMTP id f2ls2953500plg.1.gmail; Thu, 20
 May 2021 18:00:32 -0700 (PDT)
X-Received: by 2002:a17:90a:71c7:: with SMTP id m7mr8054188pjs.9.1621558832071;
        Thu, 20 May 2021 18:00:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621558832; cv=none;
        d=google.com; s=arc-20160816;
        b=TJZaWJ7+ZPJqMXt8d8q5ZahIsmYIM+6Zeo2/aerGXI6qaBih18Py+c7ryU/e9bv2ay
         +pg8f7fd5rkVk7tx4hKLQ3YJ/Cy7t6ozZNgv+1A+Ek0gKvREnEPpBn13YovjEHgjE44e
         nUMncjDfl3Z+s6tdrmRdjz5aVq35KpZPUIJuAQ5Z3R8MNdckmkKQd4KAYMLjXT7Io8pb
         V6mUteb+mPnWnbGwGMetsQu/fW3BvsKzViFoANJiUvw4qaXMKhPFhYqNZYrtmWCLPkP1
         Ql18MNzSgh3IyrY6v0PP0dK7UsYXgMjZNSVKeELQI3BP8fTGwFOIrcLmAdIB6xQrUVBa
         WXYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=MP2sMnnxnX2LmSdngJ3nolM2oLXjZHItYoP+hS8tzaE=;
        b=PqFk1tx6NOl5qb3jkbzVBWFccWA8/TV7h/mNn4xiUNF84ZBexhsxsquxq6cqa5cpJS
         ifc0vZzk07OGHA16HpNP3Vev8B5GnKvK/P26B2ITcuTz58gtcXvkVjQAzjksiZno8WhD
         dN+GuhrjQDkeCferFgLaLYGWcn0qLi74yZV2A4uj5rmg/bw44kQNT+LybLxucYShmcOq
         rewZ1hZ4j+lnu9hvEtNAfm4ryI8chMzmb/ckiI3S66av36MWHBdncjnJ9Wb5G3DKdP/Q
         jzkOXe4dfbp/u5oJUDBeUakm98ikQdBZRJh9eIzcbENIKdHGru1gVHWYB7WcxUWSjNOL
         kzuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BwoAvtTf;
       spf=pass (google.com: domain of 3lwanyackceiiykirmwksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3LwanYAcKCeIIYKIRMWKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--eugenis.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id hk5si426215pjb.1.2021.05.20.18.00.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 May 2021 18:00:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lwanyackceiiykirmwksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id u126-20020a3792840000b02902e769005fe1so14359973qkd.2
        for <kasan-dev@googlegroups.com>; Thu, 20 May 2021 18:00:32 -0700 (PDT)
X-Received: from eugenis.svl.corp.google.com ([2620:15c:2ce:200:d894:cb92:45a3:f171])
 (user=eugenis job=sendgmr) by 2002:a05:6214:391:: with SMTP id
 l17mr9195252qvy.22.1621558831163; Thu, 20 May 2021 18:00:31 -0700 (PDT)
Date: Thu, 20 May 2021 18:00:23 -0700
Message-Id: <20210521010023.3244784-1-eugenis@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.818.g46aad6cb9e-goog
Subject: [PATCH v5] kasan: speed up mte_set_mem_tag_range
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
 header.i=@google.com header.s=20161025 header.b=BwoAvtTf;       spf=pass
 (google.com: domain of 3lwanyackceiiykirmwksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--eugenis.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3LwanYAcKCeIIYKIRMWKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--eugenis.bounces.google.com;
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
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Changelog since v1:
- Added Co-developed-by.

Changelog since v2:
- Added Signed-off-by.

Changelog since v3:
- Move the implementation back to C with a bit of inline asm.

Changelog since v3:
- Fixed coding style issues.

 arch/arm64/include/asm/mte-kasan.h | 93 +++++++++++++++++++++---------
 1 file changed, 67 insertions(+), 26 deletions(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index ddd4d17cf9a0..d952352bd008 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -48,43 +48,84 @@ static inline u8 mte_get_random_tag(void)
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
+	u64 curr, mask, dczid_bs, end1, end2, end3;
 
-	if (!size)
-		return;
+	/* Read DC G(Z)VA block size from the system register. */
+	dczid_bs = 4ul << (read_cpuid(DCZID_EL0) & 0xf);
 
 	curr = (u64)__tag_set(addr, tag);
-	end = curr + size;
+	mask = dczid_bs - 1;
+	/* STG/STZG up to the end of the first block. */
+	end1 = curr | mask;
+	end3 = curr + size;
+	/* DC GVA / GZVA in [end1, end2) */
+	end2 = end3 & ~mask;
 
 	/*
-	 * 'asm volatile' is required to prevent the compiler to move
-	 * the statement outside of the loop.
+	 * The following code uses STG on the first DC GVA block even if the
+	 * start address is aligned - it appears to be faster than an alignment
+	 * check + conditional branch. Also, if the range size is at least 2 DC
+	 * GVA blocks, the first two loops can use post-condition to save one
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
+		if (size >= 2 * dczid_bs) {		\
+			do {				\
+				curr = stg_post(curr);	\
+			} while (curr < end1);		\
+							\
+			do {				\
+				dc_gva(curr);		\
+				curr += dczid_bs;	\
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
2.31.1.818.g46aad6cb9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210521010023.3244784-1-eugenis%40google.com.
