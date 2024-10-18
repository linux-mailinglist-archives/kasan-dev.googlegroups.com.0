Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBQ5WZK4AMGQEVGVZJWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id C47AA9A44A4
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:30:44 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6cbe77eeeadsf32660796d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:30:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729272643; cv=pass;
        d=google.com; s=arc-20240605;
        b=ix7wPQCuTeOWlzlS2rfL3oDpb49O+fdYLiajBAHZFTzoE8+mF4FOhRaHAHP8a9RL7p
         AI2P5ggrh21Jg19IcePzJcLfgdGaDwNz8U64r/Nz+I47MTBbwEVWSNWszBdLKhhlT2OH
         NlUCX3j6pd3DVtW3OOOmD6SQP3QQbV4rWjTAGax2SJ0REintf0+qzrKAeovqN7oC6x7a
         nLbEF8wtoPts1C6mdeie+z84KD0SsJva7A8s82JrBi6Q36DzzYhLIfTGQDdGIYLKBR9d
         ZcpuU3QtHvj7cCdCfmUa9d765vNoFWk7uzrDkll1b3/5Y0NkY4LI1r58OD5AV7+hDA3J
         sQjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=NIeYPCECCqFCnZdTc5tFfGD6QgMgWiewcDbiJNmnQ1s=;
        fh=H0VNksm5sE636PYZBpk03kyBANzvtJXRNSA1ZVINVN8=;
        b=lfYLbCG0UMWmhMavEmvcV83H+5mcY6wnmG48NKbMUOOeUWRy2op+bO17FXTRPH+lfT
         ZrA8KkeSWqBu7lM9jo1/ih781qD1RnLF7Q01ewVYS8ZglaaccfSkcfnCSPQEiYIexnk/
         /Jaq8eM9KtbMRJpvRZlShrMkiTK5LCPF2g71TJc0PRyGFts2LkWdflPd1E2qKOHcMdQN
         AjHqeiIfLAdCGGjHsbPWGhH79MJGRNujA02n2n1ogMyqzKkLmzLHSoJk9Irc+OARAsbB
         TK2neRwdZXZxsuHSolP5QITVpK/fEZBteGOKzSGZ6EXH7JNzyYjQGE4DC1upUyeULRPy
         7UUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S3X2Pfkk;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729272643; x=1729877443; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NIeYPCECCqFCnZdTc5tFfGD6QgMgWiewcDbiJNmnQ1s=;
        b=Gy5rt10GhnRU/SgpO/P6PO/zm0cHQhSxaHvvn/USHJIGuKHOq1AdmtquJLEbZ2AAK+
         WPDMnlawLravZLXpg5IsKYXOZW/q3mcdTtrCQ+2qVrhTO+Up+8udOnmuBPbPbdtpufxa
         sk2csgOoOrB04PfmKc9BFR/OeNnjkt+Z/yZiSgoS68n6W2eA/UUqul2pmV939XHO0D3z
         YV5mxuDwxHJGRY8ZGsRJnGZfq28jub97xzKMOLAz2433FTpZcWZT5AyRxT+2z3/jJpYB
         0oHMTdpx0KOoO9GlmkCraa3orOert8O5/LUuCCb1NwdfcMYcDBolDinsrRcPb+mnejig
         CGDA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729272643; x=1729877443; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=NIeYPCECCqFCnZdTc5tFfGD6QgMgWiewcDbiJNmnQ1s=;
        b=hJxQR9ybX/WVBYm1lWZqD5bNGovZwyxAfuTb1EATdjDts+GSMMQ7ajD/x6bc3hL3jp
         cciF2cpXL1T7jhTXf+3SsHvkeVkCHDx65Jxwe0zrhpL6x4W+JwEFyMW34l+lW2VrWCAk
         5SM7XDzs4Tj9rVONFImpiUJ9mDrZItswiRjf5VTrXrmp1ZjWBSUHVOAd0i8w+oEoGWEc
         5etweyysC3z6WrNOa2eJbzlZDlUISXuVTOj4hNvydDwa/3tyzhal63qOcIhFUnbkvg7+
         cBC5fI44Td7IjHnnrBnQ+1eDC+lyNG/IHbXc7+9pzpeh2llrI5/4xXWl+/Unf9f45aDd
         iu7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729272643; x=1729877443;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NIeYPCECCqFCnZdTc5tFfGD6QgMgWiewcDbiJNmnQ1s=;
        b=SwscwQmUeUQs9zjAipMaRzfZvyJrq+lkS8fQKgsgqbXzxsy9u+CXmGlAX3vbdXTeD3
         Sffrg12ID2N6sxtTqG8VXlr0qXsaq9m9L6t1uHSm1QoJxokb9Cn8ayEJNbehSBwwUg9Z
         TGGnvm6U1qNTCfWWlHmOxmlxmqYEWH0QkyfsQesXlxFjZ3urbdpPdRKqVwV4oGGuwCxx
         Vm14LYk4aUZWujPTIIhVnQYNqzbp6+ke/JfvRh7ruwyLh5KDrJxOUaxFkYvpx8k7y577
         tcchVHODYPaxIz8tHVBMNtKPX3VUjNInwNwAoio1J9vMeYoA1Po+agHL+Ed4Y87iYMow
         boHw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUIrUY4+pi/zMRJ23Tm2aEwwicmDBSXgJeadoi4T6kKOtmyumYHIVINlrvqrB5HaFJqjA+FMw==@lfdr.de
X-Gm-Message-State: AOJu0YzyEOpFmiUW4shYVjk/sA+l1mWEy17yetPM4jtd2RSMHmWESRP3
	pW6qRpTKRLX6IwGp4ATRSBbp3V3JD6dUqj7t/ranLX1nMvu6iNTT
X-Google-Smtp-Source: AGHT+IE56QGFf2ZfyjwgComaNGg4rNrMeCZnkltvtCs0y6uVODEa00pEDdXHlxEtHQdrIBziPdYs2Q==
X-Received: by 2002:a05:6214:3381:b0:6cb:f039:85a0 with SMTP id 6a1803df08f44-6cde16203bfmr44873446d6.40.1729272643509;
        Fri, 18 Oct 2024 10:30:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5aeb:0:b0:6c5:127c:2ebc with SMTP id 6a1803df08f44-6cc371dbb8als52323836d6.2.-pod-prod-05-us;
 Fri, 18 Oct 2024 10:30:42 -0700 (PDT)
X-Received: by 2002:a05:6102:5120:b0:492:9e3a:9f48 with SMTP id ada2fe7eead31-4a5d6a8b20bmr2992458137.2.1729272642526;
        Fri, 18 Oct 2024 10:30:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729272642; cv=none;
        d=google.com; s=arc-20240605;
        b=CuMHOuLk2KQ4IOdrQZMcfVDPQ+a4zZlEnlFe9XZoNpX2OX4lv1xOEOZlKNO93r5rBt
         eiisk3XLpqW0Piqvl+pIuN2rVfBOoLiDyJ9xsrj31Kgmi8U62J6tDXA9Y0Fw12OcALum
         lbf1sot73x7QzZRkCDt4MejZ20mNlSIP3RNY5KGMNtYH6HgaoVubl8XsIqsMjldMv7Oe
         tVx/mmzE0JqNNATcYgMoqDLsYu5smyATrcKt+z8b0kpY+k2zKDMbw6cV5TAK/nCfHg20
         E0N/5QhQWy2592L9lZPsD4cRzbPkPhnbraT8Svcjpbnqbmty1Zjl/JGcpn8D4BeosSgR
         ioqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Jw41Uo4vlK/av70SyuzQ/EcBacKxJaXG8uVQm7tNSaA=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=DZ21t7ZkfhQppWbvG+P38+P+tW+22H+Lon+GzKJ8OzR617/Rg5H/Pg3EZtTeLI3aJ2
         FUQuaVVg/9RNzzNbu1kgT177QVqndAhsxhfj3PTcnIdFAjOiO3xOJ9K/l/eYzVlEZp6X
         GzuuJIv2gI1CM1SnN4ZaPbJ6Taw9mPWu8QTAX+eDv+8fzIMQxL08gdNv+hfrT0WnlZdB
         ZVL1yUrmHdxZCm740sH6l9nGtJkY/64tH8tWT2rOAAHOutkVsIWPAf/6ojjkv7daZqpn
         x6M8J/4OXTT7FKmtGxIIBnCrI17+hMguKweS9U0c2wY2vnKn2+MRC7PclxfK7MRzuRJP
         Urww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S3X2Pfkk;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4a5d633cf21si93873137.2.2024.10.18.10.30.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:30:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-71e93d551a3so1606858b3a.1
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:30:42 -0700 (PDT)
X-Received: by 2002:aa7:86da:0:b0:71e:b1dc:f255 with SMTP id d2e1a72fcca58-71eb1dcf5e7mr118528b3a.9.1729272641491;
        Fri, 18 Oct 2024 10:30:41 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea3311f51sm1725242b3a.36.2024.10.18.10.30.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:30:40 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [PATCH v3 04/12] book3s64/hash: Add hash_debug_pagealloc_add_slot() function
Date: Fri, 18 Oct 2024 22:59:45 +0530
Message-ID: <026f0aaa1dddd89154dc8d20ceccfca4f63ccf79.1729271995.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=S3X2Pfkk;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::436
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

This adds hash_debug_pagealloc_add_slot() function instead of open
coding that in htab_bolt_mapping(). This is required since we will be
separating kfence functionality to not depend upon debug_pagealloc.

No functionality change in this patch.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 13 ++++++++++---
 1 file changed, 10 insertions(+), 3 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index fb2f717e9e74..de3cabd66812 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -328,6 +328,14 @@ static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long lmi)
 				     mmu_kernel_ssize, 0);
 }
 
+static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot)
+{
+	if (!debug_pagealloc_enabled())
+		return;
+	if ((paddr >> PAGE_SHIFT) < linear_map_hash_count)
+		linear_map_hash_slots[paddr >> PAGE_SHIFT] = slot | 0x80;
+}
+
 int hash__kernel_map_pages(struct page *page, int numpages, int enable)
 {
 	unsigned long flags, vaddr, lmi;
@@ -353,6 +361,7 @@ int hash__kernel_map_pages(struct page *page, int numpages,
 {
 	return 0;
 }
+static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot) {}
 #endif /* CONFIG_DEBUG_PAGEALLOC */
 
 /*
@@ -513,9 +522,7 @@ int htab_bolt_mapping(unsigned long vstart, unsigned long vend,
 			break;
 
 		cond_resched();
-		if (debug_pagealloc_enabled() &&
-			(paddr >> PAGE_SHIFT) < linear_map_hash_count)
-			linear_map_hash_slots[paddr >> PAGE_SHIFT] = ret | 0x80;
+		hash_debug_pagealloc_add_slot(paddr, ret);
 	}
 	return ret < 0 ? ret : 0;
 }
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/026f0aaa1dddd89154dc8d20ceccfca4f63ccf79.1729271995.git.ritesh.list%40gmail.com.
