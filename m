Return-Path: <kasan-dev+bncBC7OD3FKWUERBN7KUKXQMGQE6YSRV3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CF7D873EA8
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:26:01 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1dca68a8b96sf51925ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:26:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749560; cv=pass;
        d=google.com; s=arc-20160816;
        b=XfkvHEbzMPk8I2h1pLH1munL68xoPDzjWWhGb8vqv6/uv+DbIvXYmIyDeivGrhV6Rx
         7UJZ/YsKueVkKVB2ORHbguixibzlPTHmRZvWZGBH2J3IiOE5TTyAisDtFKMslgJpAAvx
         dVXCtFHc7YH1vnicKJpHmmnUO1P7QMqVM04uBcofm4c+Tq5bM6wgWQIYX1p0LRSewtG3
         fSN3dP4An2Ed+LD+jjSIv4C0PhWuIMWcJgbBESh60qggKt55uF+hUEm4PCADxPCMyMam
         tterwWybr9ciw+arNI1od09nGtUYPwTM8+y4GjIx9G66PNPHwEEy6FIWugohiQAafs6K
         HnNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=l9kb7tPtB2f7gePPsQG02lv/r2cFEUr75HPSeM6qAvQ=;
        fh=eu0Bq77EkmmU8eWWN2YlqWKSRyyeu25pTZyMfe3OcLM=;
        b=TXgc5Wo8Ykr6lkKkrkHH51JZKH5LT8Qzub3PQoVVl0DYTPMJn1vjjSSZGaAgKwuptf
         T66uz3LiK3921gr5jvQv2nn2pVBdEQcoIxG5bPMTGoleseWLETI+HQHB6FcM4tvZejDB
         v+2XrMVTekHfUs+toFQY9GV3yR/p6XGd+2Qf3p4HBSD7WyJRq/XseH6CJR9KWGuuXLR2
         2f7nCnaMpCL5b3Pyj8hosH2tUfK/0PyFg8iz/Nz1RJpWabbpNT4FQVTA2/NnWve0v84F
         sBA44y0Dos07eseEm/DOwAmSvIYg/1D4sOeGYJVeKYKek21dNRmogjR5yokQIgi27Eme
         SMfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="PhPVM/hD";
       spf=pass (google.com: domain of 3nbxozqykcxgoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3NbXoZQYKCXgoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749559; x=1710354359; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=l9kb7tPtB2f7gePPsQG02lv/r2cFEUr75HPSeM6qAvQ=;
        b=G+rL4rMbtA8DO6VghfWfFQD2+2Nk9/nqzi+Sbf5IlTojafqWFHW+lacoP5K+KGw4BO
         nnW1O5LHxeEuwW1XbQrW5/KKoQjGs7jFf8jETgIPfIfCDuyGgPHFlOtPn7XYYTn3NcCs
         Hv5+76pj5F/kOJvXQIXlzwoSWXxwIToSJ8gla2o/g4m8/cnl0uCjLQ/2n2Qx8CmjfNXh
         6kSOdlqTeFJl+ndIEn3c8OyrViyGOkMbVQ1wO6jIId8SrVnkwWy7bvIglp/YvxvtS7bH
         rvyxY2xAEI79st+8SHaog8WdoAro+7/EMulU75yqPxTjTVuNXju37uBps3T8bxMyLJnW
         RvMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749559; x=1710354359;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l9kb7tPtB2f7gePPsQG02lv/r2cFEUr75HPSeM6qAvQ=;
        b=lNvM5o4dQ63SX1yTsZMHraoOJFbECrHTu6+9xLuMdue/bsB8X5aey3kyGWVgHPKfca
         bFrshGJs0tKeohIgPVBePdaDlGOMJOAK3vTSD1zgoKwqpiySzHKDybK4AjxZm745MxGH
         pMhIWwCF074koH+YfEb0c66rio5Uf+Q5z5LL4qQcXOvDLJqnNTNeLmFChf5KEf3S4Rx6
         8kRTL/PIbIGHndzldej5V+vwnQAUySFkKcsarclGuG1A4SezQq9RRDqxAKBLNs6Su6mk
         J2LYpLoowpVpzYfiC04QaBrkwcWRosHAjiZfHdFYex7LBj98G6V/4YomR/I6GhC6UPkb
         dwjQ==
X-Forwarded-Encrypted: i=2; AJvYcCW5eC3HIixS6z2SavbS/AcMXMNUlWi8211jEkfuSxrZop++2mJ2eM1sdEsqNXWESyImxoBdbn+T4GzL/ZOUuEOs/8Ljvt2kag==
X-Gm-Message-State: AOJu0YxqdyAJayoCOTYDeDuPMkSBzhLjO4wyygI+eBUJNwESIvEdexcM
	4cN5EDwhM6hr3EOf8SB/SVGQhKe0KvQj6bdYtZst4d/xn70VeTk+
X-Google-Smtp-Source: AGHT+IHeu9TRgCkog8Ciwwlq5GIR+PM5XtwczgybkIXpBBRI1UeT0NnHVeMesfRLcVCbie0xgqMzvw==
X-Received: by 2002:a17:902:da84:b0:1db:e5e3:f7ac with SMTP id j4-20020a170902da8400b001dbe5e3f7acmr42334plx.7.1709749559702;
        Wed, 06 Mar 2024 10:25:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1886:b0:6e5:cff0:6ad2 with SMTP id
 x6-20020a056a00188600b006e5cff06ad2ls105185pfh.0.-pod-prod-04-us; Wed, 06 Mar
 2024 10:25:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV+R8utihjCJu0B65LQSOwAePI/zo/frwDIy0BhxcUurhrblbpu2vkzRmYHIYOIKb2N8+wdzpNVjd7hKr3VxZbknMPbUdiairuMDw==
X-Received: by 2002:a05:6a20:3941:b0:1a1:50d2:58d6 with SMTP id r1-20020a056a20394100b001a150d258d6mr5742603pzg.23.1709749558566;
        Wed, 06 Mar 2024 10:25:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749558; cv=none;
        d=google.com; s=arc-20160816;
        b=lTu61qcrIOrF/r6u5lcMKWxLpIDPPnNAZ1IIWrPDwaTAQ5LHRehysCbR3jduzLBerQ
         bxC3RE3CEEmdIlbDODP7ACmrMaWDQdZ7m+k4evUmSRkoAvDzr6Ucb62pRl4VVo5OdgXT
         zBZFxt23z0ufv+qX5NPe8kBNKU5dVgi9P15+mOpFP0iZE5qM9hhgggW65XH89IeedSDl
         13iUW1NnoTdNpFzGxVgKIKmnsVmkzpasnYStyVxl2ygfxmSJVE4fd0c8J9pNDzwvYSEG
         lID192M001Bsn6U17fQZLGj+Hk8oxqApleIBm9XqME8FIJKhKaAPwFMul6BCD7bpOiKJ
         arrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=/rQHM1U0nLVwxoqb6VDJGJRpri0atHFBD/ukIXSlku4=;
        fh=XjgGvZvLGK49P7qNOeanGDsxU5+j0l5pf60+ienR4wE=;
        b=jIld4ExN+gt9iuAoyjmKJ88O2AZyJG1Knnf6cXZdV0hmm1t25Dw0w7h8R7wDMMLQyK
         yRDHEWBWuqUAPQavjv8jH1cAG9iLWftC4FNMNpNwNyovjei+alGRVVkUSEgG2SErve8a
         760SHuyOEZDOQfXHGDVBAL+32vWyWDqABY9Vq+u8A8ts+oBwY9+NobBk8CSpmeRq9ohK
         CS+rRJeCOQ5He7SWR99H8EvuRkUJJbF9Q+IZ9me1irzTbUZFEiShSO2TKbHE89wKXpf+
         IMvmE9B8cQeUVwIXPv7lARgojuJ+rfNkyZ68HsVaGusNTtK+noYP0tA4VOX/ZS4/tVxr
         HudA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="PhPVM/hD";
       spf=pass (google.com: domain of 3nbxozqykcxgoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3NbXoZQYKCXgoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id s3-20020a170903200300b001dd46c6d2d9si38544pla.3.2024.03.06.10.25.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nbxozqykcxgoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-609a8fc232bso692307b3.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXkq84pUaD2N6WKD7ybXrsFeXhQLyIf+ihG+evCu49XiFuGHRWUQsjBHOI087Uwd5OHsEObAuCBtXi5wcp7xTxtL4tnI80r9slG2Q==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a81:9b97:0:b0:609:3c53:d489 with SMTP id
 s145-20020a819b97000000b006093c53d489mr3279719ywg.3.1709749557600; Wed, 06
 Mar 2024 10:25:57 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:32 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-35-surenb@google.com>
Subject: [PATCH v5 34/37] codetag: debug: mark codetags for reserved pages as empty
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="PhPVM/hD";       spf=pass
 (google.com: domain of 3nbxozqykcxgoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3NbXoZQYKCXgoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

To avoid debug warnings while freeing reserved pages which were not
allocated with usual allocators, mark their codetags as empty before
freeing.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Kees Cook <keescook@chromium.org>
---
 include/linux/alloc_tag.h   |  1 +
 include/linux/mm.h          |  9 +++++++++
 include/linux/pgalloc_tag.h |  2 ++
 mm/mm_init.c                | 12 +++++++++++-
 4 files changed, 23 insertions(+), 1 deletion(-)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index c30e6c944353..100ddf66eb8e 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -46,6 +46,7 @@ static inline void set_codetag_empty(union codetag_ref *ref)
 #else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
 static inline bool is_codetag_empty(union codetag_ref *ref) { return false; }
+static inline void set_codetag_empty(union codetag_ref *ref) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 699e850d143c..9d25d449e512 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -5,6 +5,7 @@
 #include <linux/errno.h>
 #include <linux/mmdebug.h>
 #include <linux/gfp.h>
+#include <linux/pgalloc_tag.h>
 #include <linux/bug.h>
 #include <linux/list.h>
 #include <linux/mmzone.h>
@@ -3118,6 +3119,14 @@ extern void reserve_bootmem_region(phys_addr_t start,
 /* Free the reserved page into the buddy system, so it gets managed. */
 static inline void free_reserved_page(struct page *page)
 {
+	if (mem_alloc_profiling_enabled()) {
+		union codetag_ref *ref = get_page_tag_ref(page);
+
+		if (ref) {
+			set_codetag_empty(ref);
+			put_page_tag_ref(ref);
+		}
+	}
 	ClearPageReserved(page);
 	init_page_count(page);
 	__free_page(page);
diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
index 59de43172cc2..01f256234e60 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -120,6 +120,8 @@ static inline void pgalloc_tag_sub_bytes(struct alloc_tag *tag, unsigned int ord
 
 #else /* CONFIG_MEM_ALLOC_PROFILING */
 
+static inline union codetag_ref *get_page_tag_ref(struct page *page) { return NULL; }
+static inline void put_page_tag_ref(union codetag_ref *ref) {}
 static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
 				   unsigned int order) {}
 static inline void pgalloc_tag_sub(struct page *page, unsigned int order) {}
diff --git a/mm/mm_init.c b/mm/mm_init.c
index 2fd9bf044a79..f45c2b32ba82 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -2567,7 +2567,6 @@ void __init set_dma_reserve(unsigned long new_dma_reserve)
 void __init memblock_free_pages(struct page *page, unsigned long pfn,
 							unsigned int order)
 {
-
 	if (IS_ENABLED(CONFIG_DEFERRED_STRUCT_PAGE_INIT)) {
 		int nid = early_pfn_to_nid(pfn);
 
@@ -2579,6 +2578,17 @@ void __init memblock_free_pages(struct page *page, unsigned long pfn,
 		/* KMSAN will take care of these pages. */
 		return;
 	}
+
+	/* pages were reserved and not allocated */
+	if (mem_alloc_profiling_enabled()) {
+		union codetag_ref *ref = get_page_tag_ref(page);
+
+		if (ref) {
+			set_codetag_empty(ref);
+			put_page_tag_ref(ref);
+		}
+	}
+
 	__free_pages_core(page, order);
 }
 
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-35-surenb%40google.com.
