Return-Path: <kasan-dev+bncBDQ27FVWWUFRBGMM5PXQKGQE6OERDZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id E24F0125893
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 01:36:42 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id a31sf2046731pje.4
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 16:36:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576715801; cv=pass;
        d=google.com; s=arc-20160816;
        b=rOfhuh3R3h07C0CYSB5Tp+iVBAsIjeAz6RndI88VgZpGajmYbw11lq4CMn/hjudxqt
         GvSuvbTLRD3rINfeOrgnKTvmb/uK7wgPcAOnF97BdX+R+bJ7ywc+eQJgjLudkV/VINIu
         ANrSmhT4T0mn8CAKMOx9hKGBWWziqrW3IZuguHNxbEXgZ6xuHBNcb2IY6FEvclcBX0ey
         FZ2GgU8SAwSnSZbMEObxkEdRR5oWOZqRxGKlC+bhLP/JKNZp7YO5IbuNW6ljScj8dxYT
         Sp7dLrs76wpsdxazzBb1rjju2ip3F/D8vrevQKnS2JZ7+ICMeuAYmLqhDvswCs1cbqgn
         d4bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lZLv20aIq5ivssagcZ/MyJ04ctLF/DHjNBzGh+Jz91A=;
        b=QAgLKmt/6M+mTktuN40zpkxhHm8+SbYOdS70YlyuudOoU0AH1IVHsOlJRrbmO9EBbS
         4zaOBG2KMbWsJdk/zUFvUPzL4F7s68ilQ/HEeCi6awxRid2xFirAVf+fRkEeNZrqh/1d
         kf0D9W8ihuPHuVS4JiuynQKv3GK3capfOiF1HdJl3KS0G/GM90z0v61iX5djlfKSp0IA
         e38/RNeOk8aJydrDAZCtxY7NvGohHEAio8SwsbtwTOGzaoRgPOq5cSeiXrKhqzdZXH71
         yrgf5uqQsz+j7C4HxvL3mxkhamDmHNUqm5U1/Li3iO9k4Ax34DIHQFdIM3ErPgz2j1J/
         b4/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=qQ6wvPa5;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lZLv20aIq5ivssagcZ/MyJ04ctLF/DHjNBzGh+Jz91A=;
        b=tCNib4YeZFjVg/trc99GS99/NWxNdN27gA7HeBB01rkDQmsQ+BaoLBhRAgJl2ohAAU
         02RlY7slUQHyW/qQhylaGvSVwA3dXHy08X6UcVnSYgBWhILFHAVh05EfwyO/p7ol6P6Y
         ygs9lYxsLAqxzU9/a5mVrq6vwhSgsmISJ4xsPmZorsBEwe3GsW0N3tQUwWBVHsaZCAus
         myQHjMZSv8ESSI35Zh+pKEOD//QXI3UibEqZwdY2v7FToTs/0m4pE0Jz2+614dySlqZK
         Xgqfk+BB4B8+6MxHj9/f+2P3hNbKVCOOQBH56Ui5lkqgaRZiFUYvw6aYLTJj8KGMtdIs
         UUSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lZLv20aIq5ivssagcZ/MyJ04ctLF/DHjNBzGh+Jz91A=;
        b=ijigXRQQ+Jeffp2O72Luhrztf/apnnnWJFecn75YKIjghoWhfkcGs9Gj0eHBmU2aAp
         1Ml2Zm48XP/mvIj6M4OTL4qYMEGRqvF1CiBT/sU+HOPhP4A3WY1oY2ZJ+WHujHdV+giZ
         +uoFJbRRZECFNmvi8IO/uft+c6GSa9OzTPSMOfV7e4Zc1VLtZ37SBpkbv0eNJxqcIfVr
         /PoGaRZoY1e7RRiY0JvOP2Bw83lWmbFSVzalFWXO46zFsDBpVMwi2YFtqvVw7QgdB2lB
         UoYc/brk7YI6ofidvq6vReLVDZaxVKiUomylHwAm01Ta3yt1Y+ZWcr8/bfT6NcPsJsRh
         GlnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUdJvw7jqAI5/xAiOKY7+DKj7hlO6h6MFArXKKNXzLoSaRQrAw+
	BVwe+uvyu4Z0Zp4nli+J1hs=
X-Google-Smtp-Source: APXvYqzXXL/lEluO3f1XmXAaQMdr9jBA8m/ZudxgiMywc19TykA0JpdL+rUH/MJzJZ1dELCBwq2tTA==
X-Received: by 2002:a65:68ca:: with SMTP id k10mr6226857pgt.222.1576715801448;
        Wed, 18 Dec 2019 16:36:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f8d:: with SMTP id 13ls959827pjz.0.gmail; Wed, 18
 Dec 2019 16:36:41 -0800 (PST)
X-Received: by 2002:a17:90a:4d02:: with SMTP id c2mr6230028pjg.94.1576715801045;
        Wed, 18 Dec 2019 16:36:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576715801; cv=none;
        d=google.com; s=arc-20160816;
        b=FTnm0i932KmvHiaw6x9ITYapV1L/N14vEYFzNOkJhwpTQ5Q9hDLW+nSQW25Nhjap55
         JCO7qLTOHZYPgt31thFAl3TASwRZIfWMY2/Crnn+76PiQG1wjrw5nSvvPG/mu0/sLjuR
         /HZ9Bz91FTRkBPzA7XwN1LQVBnn6ZOAqrLhwl794B2PrEcMRuY5Q9PLphk0+qLV8/zhq
         7MxYLWzofkyV7twbP3VDBETc3hAjtSGa6zeFjGdcGOLLMxI1lonvSC1AHicP2Xt3AEa3
         I1gEGaoS1J89EBK7ujzLipV8fSLbmgrF8RTu1B8VPz+o2b0Nj2Vj1NtiCYMCxXh7l+TP
         vx6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+Qbs6Z3rqfBFwWIlrYI64jfvYzlaBBfAFpq17iRyZdo=;
        b=sp2LWpCzZFx6fPWElZV5YOTvkptLKFqWRN4su+/TtRhsNt3qIQCKjql0666MhOwFTz
         +UH6/UTBmwx6R2wsf+rzh80VpVzdZ6n8pudNLhp1XlnalrxdwDloDZaUpDZGC7uokmVh
         /XOpk+Qc9Hu2pnx6ZRh3eDgSOZI6a9M9Ol/chsv+dW1ZbbEJyw404h3o0juZF4zqMYsM
         /IHI/0ypmliZzmnuyPzjdrdYN0sBUGqD6ME3juVptPNXrey8XH9hQCrCYXMIcoaOdh16
         prrSTa7hqW0YsLllRQ75sWHeDnwJ3sBkcm0dM28AoKxVVWgKvzUkxmwRZBCpcUt31NzO
         aTIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=qQ6wvPa5;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id d9si175417pls.5.2019.12.18.16.36.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Dec 2019 16:36:41 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id l127so2172745pfl.1
        for <kasan-dev@googlegroups.com>; Wed, 18 Dec 2019 16:36:41 -0800 (PST)
X-Received: by 2002:a63:5211:: with SMTP id g17mr6345964pgb.426.1576715800699;
        Wed, 18 Dec 2019 16:36:40 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-b05d-cbfe-b2ee-de17.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:b05d:cbfe:b2ee:de17])
        by smtp.gmail.com with ESMTPSA id u26sm4807512pfn.46.2019.12.18.16.36.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Dec 2019 16:36:40 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v4 1/4] kasan: define and use MAX_PTRS_PER_* for early shadow tables
Date: Thu, 19 Dec 2019 11:36:27 +1100
Message-Id: <20191219003630.31288-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191219003630.31288-1-dja@axtens.net>
References: <20191219003630.31288-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=qQ6wvPa5;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
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

powerpc has a variable number of PTRS_PER_*, set at runtime based
on the MMU that the kernel is booted under.

This means the PTRS_PER_* are no longer constants, and therefore
breaks the build.

Define default MAX_PTRS_PER_*s in the same style as MAX_PTRS_PER_P4D.
As KASAN is the only user at the moment, just define them in the kasan
header, and have them default to PTRS_PER_* unless overridden in arch
code.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Suggested-by: Balbir Singh <bsingharora@gmail.com>
Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
Reviewed-by: Balbir Singh <bsingharora@gmail.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/linux/kasan.h | 18 +++++++++++++++---
 mm/kasan/init.c       |  6 +++---
 2 files changed, 18 insertions(+), 6 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index e18fe54969e9..70865810d0e7 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -14,10 +14,22 @@ struct task_struct;
 #include <asm/kasan.h>
 #include <asm/pgtable.h>
 
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
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
-extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
-extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
-extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
+extern pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE];
+extern pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD];
+extern pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD];
 extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 
 int kasan_populate_early_shadow(const void *shadow_start,
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index ce45c491ebcd..8b54a96d3b3e 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -46,7 +46,7 @@ static inline bool kasan_p4d_table(pgd_t pgd)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 3
-pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
+pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD] __page_aligned_bss;
 static inline bool kasan_pud_table(p4d_t p4d)
 {
 	return p4d_page(p4d) == virt_to_page(lm_alias(kasan_early_shadow_pud));
@@ -58,7 +58,7 @@ static inline bool kasan_pud_table(p4d_t p4d)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 2
-pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
+pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD] __page_aligned_bss;
 static inline bool kasan_pmd_table(pud_t pud)
 {
 	return pud_page(pud) == virt_to_page(lm_alias(kasan_early_shadow_pmd));
@@ -69,7 +69,7 @@ static inline bool kasan_pmd_table(pud_t pud)
 	return false;
 }
 #endif
-pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
+pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE] __page_aligned_bss;
 
 static inline bool kasan_pte_table(pmd_t pmd)
 {
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191219003630.31288-2-dja%40axtens.net.
