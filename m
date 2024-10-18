Return-Path: <kasan-dev+bncBDS6NZUJ6ILRB25WZK4AMGQEMPTJF4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F3BC9A44B5
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:31:25 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-83ac0354401sf52015639f.3
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:31:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729272683; cv=pass;
        d=google.com; s=arc-20240605;
        b=WN5HLvsY04Kn95B/yUp/EbsrtqOY/br24ref4zEJNybIRKAYmu7DKllzNy8L0pFC2l
         fncILO/uLrG07ULfIDGdbk1A4Hccu2xdjiwYsld0wh368adZVxJsUnO2hI9Wst0aj5cX
         mqLXX6kpnzpVjJoRrZTJETampv+Wk7TSnGJuExjhPk6qHL6lkk6OecfGJHJ7IDnvJfr0
         JqnTnpjBPyKmiWmVJE1CF7XSCRXsZrXbzfEozGE9lKm6xBY8fpjlQJUSAMxvOqdeOPXX
         yJCk65djRN4fyHNd3hDwohrwvZ3/7Fp9M0C0eJGQSGHoRIyQT8P/KRSnpsTBKiTSdWI/
         yM9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=FnlYHYypW3Wn7rgt6ZsSpLeJ57s2ZS0nae5YU3Z+wj8=;
        fh=CT+qWFSIVezM05A+HmM9nkrSqq28IebK2tOBZf1vekY=;
        b=IBrF6YBBSAhicS7d9R5AX6dggmqujyeesi6q90dgyNoa1/WiahAlyc5gNWmw8gMQVJ
         P2yRHD0AzogR5jc10xg9j8AyiXwqA+1Avu7H0Z5xB08LLjK+VpuBu1R/0qFMIg6PILI2
         ScelG3PJaOr4LHmVx0QZdAAdeYFoovRxGMWoALckfu5lqgxQs5MEvwWlp29ebi4O45ai
         OQQkbTyhoUS+cZfq90XpMZ//ggEZEJyqvAIWEsFOZP6NB75zKM1kqmJpGw/gtb77MrT/
         dcul31u7YJL96YI/x29r8DWUZauSjpsVMdiSLz7iPUca2dl1KIY/AAiqE6HjLhBnrqbA
         RJBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Z5QQ1Fkk;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729272683; x=1729877483; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FnlYHYypW3Wn7rgt6ZsSpLeJ57s2ZS0nae5YU3Z+wj8=;
        b=YYRimzZlCk9olcg354Xkx9M2akBCz4CNW/n2RB2tTYoFe22RgJCpii/+pxmZCxTx62
         y0RiSzotOLlzhzCL6Nsm/wn9G/HbECGrH3YXvJewbAgxCmlbYH51iY3yrLfhvo+Sypxd
         pJftfIt+LiK0blVc6OCfXUm0FdGfv5TmruP4R8ts8zJCXh219s3jjqVahBiN14EaQvCq
         k8hP5sfPIMW1yr/C2RjJXav65hjO8IKK3khRKqj1euhlsZFtqyXrEVHFQzQnjccHqJKy
         mQd/YzjrUIRNI78m6o7nst0FiLgFKimkQdy6JJiilltZhlsnBoj/aItSQIH2DqajuwyM
         6gaw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729272683; x=1729877483; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=FnlYHYypW3Wn7rgt6ZsSpLeJ57s2ZS0nae5YU3Z+wj8=;
        b=VL74h80RJe4EP5JIYAwFQxywE0wrsAtdSOcePEeaPF5EN8Ele8U3ug3KJkQdeKhyaL
         sGbRNK5iEcsxsNh+tT13j4aMyYtE1uQuVUm9H/Tv8Ichv39rRopYmdc1JctvdY7jZKQu
         qwWhzMY1ZNpzir/BKnyqV5nHthhN6eO31/hgWfstTuvlyBALi4DizRbAIhqjR05nfiT4
         A7ONSwL/nNcrkhE/ESaaYj5LOSzBJ/LQZZqdquZtOFc87TvSfEZAGZXX0n3ueHqGu1NA
         mOitWIw0GQGCEc+pZElEyJ+t7+R4S7/qotd9g7pwGwjnvUKDzNK3sqvAs+0QnlkPVOHi
         VAbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729272683; x=1729877483;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FnlYHYypW3Wn7rgt6ZsSpLeJ57s2ZS0nae5YU3Z+wj8=;
        b=ZOe9u9svi+t6gK4iRM2mddYPqxHUPxDQ4DYC/hd6/WIC/u8FWoP+tkk7s1cEpA6g5L
         k2eFK1S7k9IVd/g6HzeM3XIwHwWaOXlCAy9XeHTQfilBOLprGedWeUkXcKAKDmSdWPy2
         QEj7hhWoinjCQtNRvwzuHZjMOwljVzY8GBGoz6vS0VEnwi6+pb1n/+Ez8o/hXUlkURCj
         cwU2ZCF7atLRgbuFjpVG5ceShcW1WG5gDYTAxcQkUzRzlhha530MwXdM7uhQrlIc5lU2
         rMjm2qhBKGPEbQKD2bmVrShi1fiER42Vs/FLJntCCPlMCYB91xS+6hlKtEoYw4aBJKR7
         xWtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUqI8GhA6GOV4qqn1WGQ00S79Pjhprbnyn+/BOxcrRHAiPD/Xj8yHGi8cXCa2pQ8Z1CGnYGbg==@lfdr.de
X-Gm-Message-State: AOJu0YyTMP13embSrQwNQw9vfy2C2SABzr5YQfSQlJGUqE8Zlg7rhlOS
	cDSFGx4AwWym3NtsiaHSXBd8WmkU+GcgWVm2fAG3XGfD0dOPrjaM
X-Google-Smtp-Source: AGHT+IFvi53Je2RhEjgHOXthhuHG5XFd46zGv0Znpg5tf3yKX5r2Tk2SFZU6rBWyU6H3V4EfcxI5BA==
X-Received: by 2002:a05:6e02:1c8d:b0:3a0:98b2:8f3b with SMTP id e9e14a558f8ab-3a3f405445emr32701795ab.7.1729272683566;
        Fri, 18 Oct 2024 10:31:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c563:0:b0:3a0:beb4:f1e6 with SMTP id e9e14a558f8ab-3a3e4afb8bcls5412085ab.1.-pod-prod-05-us;
 Fri, 18 Oct 2024 10:31:22 -0700 (PDT)
X-Received: by 2002:a05:6e02:180e:b0:3a0:ae35:f2eb with SMTP id e9e14a558f8ab-3a3f409f253mr34604155ab.19.1729272682727;
        Fri, 18 Oct 2024 10:31:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729272682; cv=none;
        d=google.com; s=arc-20240605;
        b=C9str/Szq1fABdk5t2UmFJk69qDT2t0PpYp/qdFb3oss8665heXSFrJk7MSYIPWuhp
         Jz7/kDcP2edBl0bIeY08EXoP0rzqo6DVqi/zqCdJvD0dJeXerqREPo5B5te/iAQDrf1U
         PSxQC68PsaTdoclNn72F/EIpOomTpl6iF8oxPrHvXY9R8Qvp/PhjIdhQuUa9tpu4h5AT
         E+DqxrGlajhXNMgb1bzDwaQG1ahi++zwKIlKk/saIF/P+2m6EqBDCYqoQZp7ClLJfPrJ
         rD7nub5OmLN2wPj1TJ1gVxZVnOoAp44e7kYVikduEF4xmeY0S0I1ossXpw+eJpsLwzTR
         ViAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1QLaMyzhWv0h56bpJNLe2thoYBckgfAdM8HvqGdr41M=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=Pvio7ShCEBVpeQUuauCI1o0ZCILaGtFrHQdwIVxu0rl8f75gQEz18iRMzuGveRmlWg
         OcDp3EDupFug3G+RwK43xhH/ez2OFiVDMBPDP193u9NVM86fEwC+JkgS78hikZvd6BaC
         CMqttCLrb4I/Ai+kgwh9Y/ojO8hjUX51/lXUYnihwSmgaXmWNKAiatJ0IUZX1hZkqVV5
         CKUSq8Ul7ewWfk2Sijo6i3yAmeWuIVgd3DOUfv/OQYgi1tsIRZn/l5zf07mpNnFgA3Wl
         9XU32x3uREJhUJJNCqUr7Va2D97dilxRDho5Fcz2N9TLqS7Qik9Y0HaC8+7GZSPwoVVW
         6mHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Z5QQ1Fkk;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4dc10c1b0b7si87575173.4.2024.10.18.10.31.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:31:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-71e953f4e7cso1514413b3a.3
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:31:22 -0700 (PDT)
X-Received: by 2002:a05:6a00:cd4:b0:71e:cf8:d6f1 with SMTP id d2e1a72fcca58-71ea316bf4emr3925702b3a.14.1729272682003;
        Fri, 18 Oct 2024 10:31:22 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea3311f51sm1725242b3a.36.2024.10.18.10.31.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:31:21 -0700 (PDT)
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
Subject: [PATCH v3 12/12] book3s64/hash: Early detect debug_pagealloc size requirement
Date: Fri, 18 Oct 2024 22:59:53 +0530
Message-ID: <c33c6691b2a2cf619cc74ac100118ca4dbf21a48.1729271995.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Z5QQ1Fkk;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::429
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

Add hash_supports_debug_pagealloc() helper to detect whether
debug_pagealloc can be supported on hash or not. This checks for both,
whether debug_pagealloc config is enabled and the linear map should
fit within rma_size/4 region size.

This can then be used early during htab_init_page_sizes() to decide
linear map pagesize if hash supports either debug_pagealloc or
kfence.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 25 +++++++++++++------------
 1 file changed, 13 insertions(+), 12 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 2f5dd6310a8f..2674f763f5db 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -329,25 +329,26 @@ static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long idx,
 }
 #endif
 
+static inline bool hash_supports_debug_pagealloc(void)
+{
+	unsigned long max_hash_count = ppc64_rma_size / 4;
+	unsigned long linear_map_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
+
+	if (!debug_pagealloc_enabled() || linear_map_count > max_hash_count)
+		return false;
+	return true;
+}
+
 #ifdef CONFIG_DEBUG_PAGEALLOC
 static u8 *linear_map_hash_slots;
 static unsigned long linear_map_hash_count;
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
 static void hash_debug_pagealloc_alloc_slots(void)
 {
-	unsigned long max_hash_count = ppc64_rma_size / 4;
-
-	if (!debug_pagealloc_enabled())
-		return;
-	linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
-	if (unlikely(linear_map_hash_count > max_hash_count)) {
-		pr_info("linear map size (%llu) greater than 4 times RMA region (%llu). Disabling debug_pagealloc\n",
-			((u64)linear_map_hash_count << PAGE_SHIFT),
-			ppc64_rma_size);
-		linear_map_hash_count = 0;
+	if (!hash_supports_debug_pagealloc())
 		return;
-	}
 
+	linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
 	linear_map_hash_slots = memblock_alloc_try_nid(
 			linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
 			ppc64_rma_size,	NUMA_NO_NODE);
@@ -1076,7 +1077,7 @@ static void __init htab_init_page_sizes(void)
 	bool aligned = true;
 	init_hpte_page_sizes();
 
-	if (!debug_pagealloc_enabled() && !kfence_early_init_enabled()) {
+	if (!hash_supports_debug_pagealloc() && !kfence_early_init_enabled()) {
 		/*
 		 * Pick a size for the linear mapping. Currently, we only
 		 * support 16M, 1M and 4K which is the default
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c33c6691b2a2cf619cc74ac100118ca4dbf21a48.1729271995.git.ritesh.list%40gmail.com.
