Return-Path: <kasan-dev+bncBDQ27FVWWUFRBBX6XHVQKGQESY5PCJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E023A6BFB
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2019 16:56:08 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id b12sf5619123pgm.14
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 07:56:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567522566; cv=pass;
        d=google.com; s=arc-20160816;
        b=aluRDeofHn/UC/hidGteH8kXXU7fdronpS4CLvFjWYjTACO76RaQh/9QJkT/dstatI
         e8gV6vnO2Z89yk9Fr/CTbjy+QP8PROD1yGWpQvnE8GA/ZL8p0Ivq+BJXLsMywVtK9F8p
         SSVdgx7e+Ub9D9s+IcarUvNc5lRJIz6tBD5HimNmaQ80wFJCM2nPRssC9P+g9ytjpKLi
         09iY2bHy4UwtYIMqT3DEAMGPS26sIg2d0ytTcHiCCJOJB/jbtM5KkGRne+4lK982AoYj
         nCnoGx1/MQKwvgzNj1Pxpodgin0MbVezD5Ly1Rf9L6J6wW6F6Sxn49OiG1Fu25Y+d3mu
         E/gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZGsPjSluEerJ6985h0qZLdTacyVKFEljMM1ryA7yupM=;
        b=pjPQrvYKtSRKeEc/yzPf0j2ZNW5WM/zFCxWiv0OffW8O8bdb+YiVP90qxQFvSB1LQu
         x6gOvNiRKz/Kg1+Xks8IGLaz5+y2LflBptj/kkxr2jwz9ZGPwYiP7ghs+pxO+J9E0V37
         prjKQWE8jAMPbK4BjCbD4ixYJBGlCkOBc2S1/gceDF60cNVmkeRA7IzERg1VME99PxYN
         e9noWfIKdmj5qHSa/PepiJkOQt2Psj6HF9/tdw1qLn+QLYXlKXJR8hiEfJwmbY+1TIh1
         6Do7F7Cae+YVzfl4V7Bdwsp5AbN+zhF1Kx8xVEQrPMJZywLNfomhce9MDxMp26D92EC2
         wToA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=LXzNdZWa;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZGsPjSluEerJ6985h0qZLdTacyVKFEljMM1ryA7yupM=;
        b=iOQq8mweXFyuTTeAH4XrNing91AkrKb2QC/9KX1g3fKwLQKC33AXbnE9scwpRMUjKr
         MWvfOaeUUOD+C/GysUlXmQ0kd/RL5dPlIOhDH+doZO88gvb8I6gxEYzt4yPA5yxjz69e
         gcO+veYGhJekrAb2g1O3cII8HG9HzLmR0eV/0qeaUCt5Qwxz/Vqy8ClJqqpkPgBUTGwt
         +TdwvbURz9hl42dU9o/BgyC4RZ90cY7pDKIf2sDrK6Hl+JTWPS4I34O5qDwqRgwCD5xA
         ck9NqN+HDJWXRFO0CSfr98u71uim3qpjuDxk6mL52GCCqzhDzbolAkgNSprIs6PFADx9
         Ad9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZGsPjSluEerJ6985h0qZLdTacyVKFEljMM1ryA7yupM=;
        b=Me9Eqd6o/sngP1uOCFXh2OgIMFxtdD8JV491cSBWAcbjqkejUYMP7BnOayemS5mov6
         gpqjQ+j7oAWK2+XsfSMR/wV0sZrcgi1JuCbSHm2bLlAEWUo6r8/EkhI/W9d08xAUsuDi
         iC+R7iRUdqeRyuQpuUtNAiyABQ2xK5OB9FUkf0xayc3b/bV8O5HWtyRqte4Mrp3rprFA
         Vp4mJa4ST8iwyuOtNJMeIKbKdeidl7NePBd1jT4K1KLNewPPUD2xJFSlrhPPA2JvSc3I
         TqqDQ6bTMZK/bCZUPFTSiDjmsji4A60dC8IaV539H6kjG2T0+smvpqyfl2rMyeNMWpbI
         f6ag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVq9wg1jMFLSQ/Jx0RXz5awgGu4NY0N+C8d2vVhF5rbj12JKQbq
	J5vvu8G54wVGZTWNjMJ2jZI=
X-Google-Smtp-Source: APXvYqy7hR4DPGWsqHjydCD1KqC8INAGnl56enIHpSOEdn6GQ9/Ft4kdfhwCuFRvp9GEz8bqrGKiXQ==
X-Received: by 2002:a63:5941:: with SMTP id j1mr28503679pgm.319.1567522566574;
        Tue, 03 Sep 2019 07:56:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7b84:: with SMTP id w4ls5666553pll.10.gmail; Tue, 03
 Sep 2019 07:56:06 -0700 (PDT)
X-Received: by 2002:a17:902:748c:: with SMTP id h12mr7171613pll.58.1567522566322;
        Tue, 03 Sep 2019 07:56:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567522566; cv=none;
        d=google.com; s=arc-20160816;
        b=m+utw3kTKZC/3xSgy+7AsBd4BhVaUOO1u1HzUxGwkYuSHjGeZxv986DzsaRjtigiHf
         IASECOsOx8yfgY31LaKJylVtsiYnJERkWv+rPiooF5DGbismjEEibxcIF5nlhoUv/bQH
         iHfjNJD6s0FcETezv4oP/QfBydcSE+g5BVZGyy/MQAi7uIa+0cLdTI33ZZrMX7oVyWgx
         7HcDl0HG54vXvo2v+8kFjpXj2hR+Qgq7sC6KG25iq9IuUMH1VTm9IpoEs+NpQLa7tkek
         3sBnuZRGMn5aHWeHS5VLCM680/jXYFdJeGw5pf0Rt67IcTiEidBFnlpgmPCGputsZmBD
         BMAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vF6m0g42G8C15Kjxq7JM+Zo7viFkQMObl5+b/f7Khts=;
        b=urVhnqyz83TF746KrwgLC8Z7ZBsLOvqbDCriSPkrrPLKHkGLxiwVVBYv8B/j3yFHPP
         tc6siJHK+HbD6O8ygoo0HTBhJ0a2pxvoVFZSL+HNkPdAQSxeu8JvxKzx4oyEYYqh+Ll0
         SF00OX9Co1haiNMJUgUme4OT4rG7yd74LCx7CZ+hR55yKXuAYWFgKvUETboxW4+HKXtd
         HhtbVIAaWQvYjCKmQY/jDR2irdyjzZFRjpSXZVQTtFCFJ47QA6zF5taA/cDcTdYp4pH9
         WAhqKcVdF+ZB3Ca0bxe5SIIqJ/nTLSY4kmULSBB1hSavczqeOYcSkV8HfPdF8FdTczzb
         SDCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=LXzNdZWa;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id g12si376369plm.2.2019.09.03.07.56.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2019 07:56:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id q5so3079646pfg.13
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2019 07:56:06 -0700 (PDT)
X-Received: by 2002:a63:194f:: with SMTP id 15mr31482111pgz.382.1567522565767;
        Tue, 03 Sep 2019 07:56:05 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id c1sm19943843pfd.117.2019.09.03.07.56.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Sep 2019 07:56:05 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v7 5/5] kasan debug: track pages allocated for vmalloc shadow
Date: Wed,  4 Sep 2019 00:55:36 +1000
Message-Id: <20190903145536.3390-6-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190903145536.3390-1-dja@axtens.net>
References: <20190903145536.3390-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=LXzNdZWa;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
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

Provide the current number of vmalloc shadow pages in
/sys/kernel/debug/kasan_vmalloc/shadow_pages.

Signed-off-by: Daniel Axtens <dja@axtens.net>

---

Merging this is probably overkill, but I leave it to the discretion
of the broader community.

On v4 (no dynamic freeing), I saw the following approximate figures
on my test VM:

 - fresh boot: 720
 - after test_vmalloc: ~14000

With v5 (lazy dynamic freeing):

 - boot: ~490-500
 - running modprobe test_vmalloc pushes the figures up to sometimes
    as high as ~14000, but they drop down to ~560 after the test ends.
    I'm not sure where the extra sixty pages are from, but running the
    test repeately doesn't cause the number to keep growing, so I don't
    think we're leaking.
 - with vmap_stack, spawning tasks pushes the figure up to ~4200, then
    some clearing kicks in and drops it down to previous levels again.
---
 mm/kasan/common.c | 26 ++++++++++++++++++++++++++
 1 file changed, 26 insertions(+)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index e33cbab83309..e40854512417 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -35,6 +35,7 @@
 #include <linux/vmalloc.h>
 #include <linux/bug.h>
 #include <linux/uaccess.h>
+#include <linux/debugfs.h>
 
 #include <asm/tlbflush.h>
 
@@ -750,6 +751,8 @@ core_initcall(kasan_memhotplug_init);
 #endif
 
 #ifdef CONFIG_KASAN_VMALLOC
+static u64 vmalloc_shadow_pages;
+
 static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 				      void *unused)
 {
@@ -776,6 +779,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (likely(pte_none(*ptep))) {
 		set_pte_at(&init_mm, addr, ptep, pte);
 		page = 0;
+		vmalloc_shadow_pages++;
 	}
 	spin_unlock(&init_mm.page_table_lock);
 	if (page)
@@ -829,6 +833,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (likely(!pte_none(*ptep))) {
 		pte_clear(&init_mm, addr, ptep);
 		free_page(page);
+		vmalloc_shadow_pages--;
 	}
 	spin_unlock(&init_mm.page_table_lock);
 
@@ -947,4 +952,25 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 				       (unsigned long)shadow_end);
 	}
 }
+
+static __init int kasan_init_vmalloc_debugfs(void)
+{
+	struct dentry *root, *count;
+
+	root = debugfs_create_dir("kasan_vmalloc", NULL);
+	if (IS_ERR(root)) {
+		if (PTR_ERR(root) == -ENODEV)
+			return 0;
+		return PTR_ERR(root);
+	}
+
+	count = debugfs_create_u64("shadow_pages", 0444, root,
+				   &vmalloc_shadow_pages);
+
+	if (IS_ERR(count))
+		return PTR_ERR(root);
+
+	return 0;
+}
+late_initcall(kasan_init_vmalloc_debugfs);
 #endif
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190903145536.3390-6-dja%40axtens.net.
