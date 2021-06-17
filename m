Return-Path: <kasan-dev+bncBDQ27FVWWUFRBTFMVSDAMGQE7VVJZUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 418113AAFBB
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 11:30:53 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 59-20020a9d0dc10000b02902a57e382ca1sf3523306ots.7
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 02:30:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623922252; cv=pass;
        d=google.com; s=arc-20160816;
        b=BMGjKs6bRLP7FE3CWn2mZ124n5xvlUDPWK6sld3SVbDQb6jMd3qY6qyPGm+dvsb3F2
         ZJERO/jXj/j3MTbfogHC3K6V6ykoBq03hDTY5mVnBA69mSYWUxz7PJ1f+XLsqUkcVGqC
         CZe//mFdBbU0u7zW80/2J9SUFYTWLrlCpVYmdZFvecbKXgzVcI0cK/Wy11/2anTDh50r
         tUMnyCyu2D7Ah48LKPbtLiNT92oFUNj73P7E9iT+D0Yb0vRvoADsA3bI3emZhRyqZcFt
         /HH7EOqPIS+oN5lGQlehvCtR7SeRnGyJpk9tCs/xrt6Mu8tSk81JJFzhuHeYF5NM0HB2
         739w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ltNU+v9vYfwMFMEPxHiAvFcz7u6+nHdAX0xA4Y8a0xI=;
        b=G76C0WY6MvsZRyO4ZrMe5lCksCcYPNdpTH6UNANCTo+9z+NgpE3E/CsS0NZjiikXnT
         KLnAgAG9BzGGDa5Hxl3CuxB3v8+A7WpmBp4nhLfhW+NBpkxylSpVLPz8CGLsCkaIMFc8
         csvbFhgGEAqssIENzPW4UK7SMek/2cTqcinnKfYhYfcUebWp7S6E5+neBFT9B00N0Q6z
         W3I4zXXKYL2zIREqYPY2cj5yTT/3u0k0HfEizavhWidWkmSrGYTEX7vp3BG3PV7ytclN
         PiRJ1SuMFQMhpQc6yPh4U8u2c830YePTh4BcrnLmlBJpXV0RZoiw8EMwp5mddlbI/MPt
         GrEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=MHJxWIov;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ltNU+v9vYfwMFMEPxHiAvFcz7u6+nHdAX0xA4Y8a0xI=;
        b=RNFqfdYyGAHd7qx1tpJgcXso4yzfEuW1gSxdxX0VXvkIhNkOs49L5Mksy1Znnu/hot
         xDtNMzSUATPReiwaSGKjYJIn140GpCWZm0DaghHSZGdnnkpgtjHi8ZDISVCEXWRshYgz
         Ht1ACNOCTWLSe2vqVOdEZeCsyhX5enHu+YIEke/KCeHUxQ9m1S4JLBkC0Ol5fMYoU4Fd
         AuTgoieravniAp8yAGM8Evy9G0ANU0N585hFFTMp2piAutXNKMuSjsFVIedgH57lan9d
         mJ9nZU8oV7zVKGgG7k4+hgg7aNT79Nx/7cNWCiockDHf/6cV1Wk4KGRi31VnESmGlcaB
         BPZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ltNU+v9vYfwMFMEPxHiAvFcz7u6+nHdAX0xA4Y8a0xI=;
        b=CY2AH95tdWYFiUQlMOYLvJGASVxpdNlaPb4IK19KmtBbGLVsjd2qo/aL87T9XfK7It
         6k8y+bUbHVhl0F7kjOivxyVJqU5BSO7j/C2wm5ygKoa4IvxLcT7bNGLVpqeiGkiyCJLy
         8Zc++xfRHl5J7iGx2FPNYs4nroEofD/RK7NyvMAObauz0TowrQXTv2XnuZtkf54tNRXr
         rN1Czsjj22lEMdgtxKauK1UmAgaw0BE9isSnsZg2jl+Juc3dur68DGJrqLzETJUwtBWd
         LF7+QQOjfMr8bkfk4wZCZfUFsJfXONgRa2UeS3etByMu/rnoymlcN14BqTb/su64LSk8
         xESg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530r78jK6mUYdCnB5DhM8JEfPGUETRgqqXY3l5/PX686BZOLOTt1
	/6Td8pQlDnklAx/voIogLwQ=
X-Google-Smtp-Source: ABdhPJyC7JxwbHN01lDl3VZmiB+kK7DPUDRmHqc4wVuhrw8aLMjQjEJ74oW4vzZc8DFmMNsgWAuUXg==
X-Received: by 2002:a9d:264a:: with SMTP id a68mr3798304otb.50.1623922252196;
        Thu, 17 Jun 2021 02:30:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d09a:: with SMTP id i26ls661384oor.1.gmail; Thu, 17 Jun
 2021 02:30:51 -0700 (PDT)
X-Received: by 2002:a4a:8111:: with SMTP id b17mr3611600oog.5.1623922251812;
        Thu, 17 Jun 2021 02:30:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623922251; cv=none;
        d=google.com; s=arc-20160816;
        b=JrxN+RYUlYAyYMzjKF8DKQttDoUdqISJ69sSddFI8uWVwhpfPqP0fGqNoko8OR23bF
         pmQsvFzv7rhCjFQLnStykRkxWY8EBcuxrlaA5IiXIXRjVTRl+VKZGrlWTmjwl579z8Ia
         0jorOZJPf9wj4TvMR4JIQ+5nu/htuZjTvOdPXVkjRns96rPo22YUvGFb+gC7xmHC5H9q
         6b87WE/uPLPTarYIhUflxSkGfTtQQzlevBj+G54GYtKXuF+G0iR3M2k7r4ZXP7DdTOmN
         wIYZquks9bRvtYiGnz8Ihg1w890UvlddtStIJQJe4oB9kVY5kgxbMPJ2YH8ekm8Zf6Ij
         yreg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Nxkv0O/k/UB4v+Xu5eY5paN7/JzM4aFGdvV8fAfzbmY=;
        b=O3z1IYiJE2Gybo4DfRkibVXUA8r+sLr4cl/y5xThODzoIumAF72FESaMs0UHTMih2o
         mmxUIqJcanrgnH/RPfWXc3q5TvIstAdj/O3aGj8L7wrWPOSZ9DGE4hbGEueGrpthQ/I9
         +s2uutgdk6CQJDS6sLxT7+pghQRL3sho1ueBB0eqxkbGhzfc/wBPNYBenpzIoM8xsVeY
         YjquUcXosjn5OVGvY5WKB/C75dXTDPYP5ajMraUkd3Qbw+abBY+ttJ5p9/kTIXIyGpYS
         fM8RsyoSocr/H5hnpz0ty7H7Kkzh3sdB1MOZriUtE/1m47DP53FV50/56Egf/xoKT3yT
         lyvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=MHJxWIov;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id h26si332497oos.1.2021.06.17.02.30.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 02:30:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id g4so3466483pjk.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 02:30:51 -0700 (PDT)
X-Received: by 2002:a17:902:dac2:b029:110:994a:abc3 with SMTP id q2-20020a170902dac2b0290110994aabc3mr3626941plx.78.1623922251151;
        Thu, 17 Jun 2021 02:30:51 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id v8sm4557656pff.34.2021.06.17.02.30.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jun 2021 02:30:50 -0700 (PDT)
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
Subject: [PATCH v15 3/4] mm: define default MAX_PTRS_PER_* in include/pgtable.h
Date: Thu, 17 Jun 2021 19:30:31 +1000
Message-Id: <20210617093032.103097-4-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210617093032.103097-1-dja@axtens.net>
References: <20210617093032.103097-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=MHJxWIov;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102a as
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
index 7c66ae5d7e32..cf05954ce013 100644
--- a/arch/s390/include/asm/pgtable.h
+++ b/arch/s390/include/asm/pgtable.h
@@ -342,8 +342,6 @@ static inline int is_module_addr(void *addr)
 #define PTRS_PER_P4D	_CRST_ENTRIES
 #define PTRS_PER_PGD	_CRST_ENTRIES
 
-#define MAX_PTRS_PER_P4D	PTRS_PER_P4D
-
 /*
  * Segment table and region3 table entry encoding
  * (R = read-only, I = invalid, y = young bit):
diff --git a/include/asm-generic/pgtable-nop4d.h b/include/asm-generic/pgtable-nop4d.h
index ce2cbb3c380f..2f6b1befb129 100644
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
index 9e6f71265f72..69700e3e615f 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -1625,4 +1625,26 @@ typedef unsigned int pgtbl_mod_mask;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210617093032.103097-4-dja%40axtens.net.
