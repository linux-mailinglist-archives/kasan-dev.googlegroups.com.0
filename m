Return-Path: <kasan-dev+bncBDQ27FVWWUFRBVX5Z6DAMGQE3SGGRZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CF123B2591
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jun 2021 05:41:11 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id e24-20020a9d63d80000b029045ea018532dsf2585346otl.9
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 20:41:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624506070; cv=pass;
        d=google.com; s=arc-20160816;
        b=mtqoIrzflQlUtpih5s3QsRSgb63Ci2PmtikW9grJvXpiYSLX2Mz57gmIKSW3Hu7lT/
         2bZnu5VRmPU6eEEmSWGf3hAi9HeSVUfYdxPl84zYJCzVuCnD+MFfnkUtZRtRTWfSIwtx
         XSXDbTiB2rNVvOV3+PEWo3cHCiKGhC3FCMeZLLRPy5ln+IHImE/MK8HS2rx7LFmgPN3e
         susd6O2hZeOE3L52YexHrpH/hM658AxyR/RgV7sQfUFBgPp6YDN5eKANYZrVTY9WjUtS
         cZrLpm67jAKcQjn1+j/eAWX7Ro0I22V0IdzlmfIBdffonYNWUGnjepnAZAqApaHngqor
         EYug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ODwToSFD6/hTCSBdPb2RRdj0az19MWIMn55dapzhj/4=;
        b=gc875W8DLZwil8KwvAut+vaiqvwJygoj56+/eNC9yFTKnk6rjP69/K+y/SxYOPRyAR
         aDV7BsgJhxG9b4txteSqRs35ehkdaevB/rh58xugaZFZK3GK+hdy4r/meVTtqjTxyU+S
         mc70wIAILB4z3lfF/50KECklzqXtYsdUrx5uSKJicoyH9LVzfD6Jyrt9MxufJGGO6N2X
         EBetzpXPRgebGRyjBTVzW6g8/GgF54Bd7S7gmEBfBYssZBqCVM2Qo+Pqcsn8Ub6Uhrm5
         RpqxxEAlMk9QJBg4n96tcbsLibEX/0KVU7RuczBtCnv02BgJDVYW3qCPDOlNTdLpNM1X
         K+6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=J2OkXKOb;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ODwToSFD6/hTCSBdPb2RRdj0az19MWIMn55dapzhj/4=;
        b=Z2kzUL/2OpIp8hTNThTR7yZ6+1Ke1Gyw7v/azZELTyc4rjA/WEcFbRcklwHCVgpPh9
         uGnEGmDwgjCWpMcwSO1HCXBCy5KtjBOGXeiJKdz1QVB4qmRKEaItO7z0CrzAwkNgjsCB
         qhA3UzJZUHmyubOM2WvUHFbgitxCBaOSs5iJ2P+4QSkbwbxL2R3Y31fTvq/jq+1wH8v5
         h2jwguj2RtTI7eT7rSAH9z1A4T6/scR+sH0aBc48ATDp/tvYP6hoRoCaKmOKWVvqaoBs
         BYYu0VGis1cuoWU6aikMbTgBHjqZ06yY0ZM2+FLJTCZdVEXo+HQlw7br67x2E9MU7GIF
         jOSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ODwToSFD6/hTCSBdPb2RRdj0az19MWIMn55dapzhj/4=;
        b=R3NCatfPi3/3RFLEWBtThhcSTDs31TB5z2ZHnmMBPUic6zCUIgguOZr/nO64s4zopd
         GMmOPSt2WKjB+HjAR7Mnd/EdEd2eIVEcjcab59xZcSG1nU7n6RxmJe8sIkGhIOwH4Y4Y
         dM1Znv6LKeTNlgb7FTZ+oWquekUIWY5P+9AmsIWm5OdRHAuschSvd4PmzTCJFXkWsfdt
         1yAcVi7cokuVknAg7yFgHDzsxWxqUtnJFRcx4096afbciK7rxAcqi/20UyMbKkmxicSt
         QbZ+mRaHQcD+t9v6wo7ukpDdbBVNMs6sTG+Od+lGex2iCrUZgRL09XZgo5jUTHdg92iq
         48nQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533uI3dQdWVWinTjSFslDtzttP6l7GlZUQRQ1CRb96ETu4EepaY0
	s+nu4dowBkKKy49MrKSaFks=
X-Google-Smtp-Source: ABdhPJwPo5T5yXPe4hEL3Uo2UqxfwwhszFrlmL8SCncslPBLgCOKP7JW8U4S8p6SDWSdkdZn3KmfEg==
X-Received: by 2002:aca:f587:: with SMTP id t129mr2497690oih.4.1624506070365;
        Wed, 23 Jun 2021 20:41:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f24:: with SMTP id e4ls1539850oth.4.gmail; Wed, 23
 Jun 2021 20:41:10 -0700 (PDT)
X-Received: by 2002:a9d:2f62:: with SMTP id h89mr2731955otb.225.1624506069924;
        Wed, 23 Jun 2021 20:41:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624506069; cv=none;
        d=google.com; s=arc-20160816;
        b=gs8K9VpTJvzUfiSu7cB95sBrEf1p20MLB+/GI8IHswY0BoMEOARgoznkjIUExKHewM
         ciJ4+fJh5w/28s38JP48TS344bDrcNzqA06wg/Cm8tlhZRa3lljNVbrR1DINspcBY/mO
         X7m7Mvrtk3FuvGmLovtSwIdwMwD9Y1n0S5X73A47tdC4gWd1k4P7VzGmnAmynWgPwiWG
         wPzmF3yuqIVAmNmWV8cW+F1HdzzKHt7hX40+8n7sGXNFJZUFpI2FaWYquXttSHaLuQma
         qlEhh5kodWAfBOBhtUXAUf5GnQKxiY6TJ4t1KLLQck/7jkb/2UJ+DFCSFChaOgho/bld
         XLAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rvCzMPY1iDnXrmjh/pjQWKgOuSudghioSXufJUjyJjc=;
        b=NhfvUgNuBIVFD++L47mMHOcVwUiTLMnIXGpBUmbe5R47GgCiYaQJIq8C9HYMXVH2o9
         CZHCBiHG54q90kFk3V7IGnroL6Xzs8nWoGsGQ6ozGBRjhFekGDXvq+02gvCEqZTsnxkP
         2tA8xsDaIB1abS0Ds+USMTRcd6ax7bbcTBgE349bq0DlqliAhA9n3Cv3WnZErhiDuMRQ
         BBb64xASQeTLPV26anNncl7HxXyZqlWCi/74AghMXWbpJj5siEc5Z8SI4X2GOYZHoGgi
         VHwLIuQNSlhIJIW4TR32FCDXTBP9mfL9xriePcvgJbDDEJzU4jGgv1E7eVq0NtsBKlVY
         xjQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=J2OkXKOb;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id n10si45764oie.2.2021.06.23.20.41.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Jun 2021 20:41:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id e20so3616026pgg.0
        for <kasan-dev@googlegroups.com>; Wed, 23 Jun 2021 20:41:09 -0700 (PDT)
X-Received: by 2002:a62:844d:0:b029:308:230c:fe3a with SMTP id k74-20020a62844d0000b0290308230cfe3amr906161pfd.34.1624506069293;
        Wed, 23 Jun 2021 20:41:09 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id j19sm556042pgm.44.2021.06.23.20.41.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Jun 2021 20:41:08 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	elver@google.com,
	akpm@linux-foundation.org,
	andreyknvl@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v16 3/4] mm: define default MAX_PTRS_PER_* in include/pgtable.h
Date: Thu, 24 Jun 2021 13:40:49 +1000
Message-Id: <20210624034050.511391-4-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210624034050.511391-1-dja@axtens.net>
References: <20210624034050.511391-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=J2OkXKOb;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::532 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Commit c65e774fb3f6 ("x86/mm: Make PGDIR_SHIFT and PTRS_PER_P4D variable")
made PTRS_PER_P4D variable on x86 and introduced MAX_PTRS_PER_P4D as a
constant for cases which need a compile-time constant (e.g. fixed-size
arrays).

powerpc likewise has boot-time selectable MMU features which can cause
other mm "constants" to vary. For KASAN, we have some static
PTE/PMD/PUD/P4D arrays so we need compile-time maximums for all these
constants. Extend the MAX_PTRS_PER_ idiom, and place default definitions
in include/pgtable.h. These define MAX_PTRS_PER_x to be PTRS_PER_x unless
an architecture has defined MAX_PTRS_PER_x in its arch headers.

Clean up pgtable-nop4d.h and s390's MAX_PTRS_PER_P4D definitions while
we're at it: both can just pick up the default now.

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>

---

s390 was compile tested only.
---
 arch/s390/include/asm/pgtable.h     |  2 --
 include/asm-generic/pgtable-nop4d.h |  1 -
 include/linux/pgtable.h             | 22 ++++++++++++++++++++++
 3 files changed, 22 insertions(+), 3 deletions(-)

diff --git a/arch/s390/include/asm/pgtable.h b/arch/s390/include/asm/pgtable.h
index 79742f497cb5..dcac7b2df72c 100644
--- a/arch/s390/include/asm/pgtable.h
+++ b/arch/s390/include/asm/pgtable.h
@@ -343,8 +343,6 @@ static inline int is_module_addr(void *addr)
 #define PTRS_PER_P4D	_CRST_ENTRIES
 #define PTRS_PER_PGD	_CRST_ENTRIES
 
-#define MAX_PTRS_PER_P4D	PTRS_PER_P4D
-
 /*
  * Segment table and region3 table entry encoding
  * (R = read-only, I = invalid, y = young bit):
diff --git a/include/asm-generic/pgtable-nop4d.h b/include/asm-generic/pgtable-nop4d.h
index 2f1d0aad645c..03b7dae47dd4 100644
--- a/include/asm-generic/pgtable-nop4d.h
+++ b/include/asm-generic/pgtable-nop4d.h
@@ -9,7 +9,6 @@
 typedef struct { pgd_t pgd; } p4d_t;
 
 #define P4D_SHIFT		PGDIR_SHIFT
-#define MAX_PTRS_PER_P4D	1
 #define PTRS_PER_P4D		1
 #define P4D_SIZE		(1UL << P4D_SHIFT)
 #define P4D_MASK		(~(P4D_SIZE-1))
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index fb20c57de2ce..d147480cdefc 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -1634,4 +1634,26 @@ typedef unsigned int pgtbl_mod_mask;
 #define pte_leaf_size(x) PAGE_SIZE
 #endif
 
+/*
+ * Some architectures have MMUs that are configurable or selectable at boot
+ * time. These lead to variable PTRS_PER_x. For statically allocated arrays it
+ * helps to have a static maximum value.
+ */
+
+#ifndef MAX_PTRS_PER_PTE
+#define MAX_PTRS_PER_PTE PTRS_PER_PTE
+#endif
+
+#ifndef MAX_PTRS_PER_PMD
+#define MAX_PTRS_PER_PMD PTRS_PER_PMD
+#endif
+
+#ifndef MAX_PTRS_PER_PUD
+#define MAX_PTRS_PER_PUD PTRS_PER_PUD
+#endif
+
+#ifndef MAX_PTRS_PER_P4D
+#define MAX_PTRS_PER_P4D PTRS_PER_P4D
+#endif
+
 #endif /* _LINUX_PGTABLE_H */
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210624034050.511391-4-dja%40axtens.net.
