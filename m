Return-Path: <kasan-dev+bncBC7OD3FKWUERBYOE6GXQMGQEWTHZYSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 31962885DB8
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:55 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-6e6bab4b84dsf994632b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039074; cv=pass;
        d=google.com; s=arc-20160816;
        b=KP0PZmnAXf077Nj8yUW644XWVYiR5V6xLljQdszXaBcHKhi1iZN7d/qc9uaj8QRpxX
         dR94EC7y2P473XntvIPNbq+KatMsom9gPjs6p1YQsu6Z46z7zx8rJ/ROB+8xDlBDUUtw
         x5FM6I55nkPHHcr9kSiATuAbrkthlfvhEqu71vVCypJIszyyiLsTbFtfONkkaS/0LouH
         hVou4vHmfPW2Tf+BiEo8ofISlJlEIFeF2c5CNGr1kw+tSmvIuOL+XL+mN14NrcwJZ1Pt
         OUk669tr0b/DDdKIYYicR8VzSn5HJNF8h6u7lJ9L76AVQAjq0bZ2jfnDStczrlch7VWd
         gwhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=2IK8bPGhOnnbplvW8aR9K1jOySPQUb3rdvL5LoPiNT4=;
        fh=lbK87sdRbioMnId/cME/1Sk2XzufGGLYR1zDgExSITY=;
        b=I9NdqC5a/tiym9GOQJC5eusr2WNquUionFJRuo+U52A2fL+hO0gBksSRMyhURjVfx6
         sJ4u4XqQOzK4SoP4nAT9OCHPiIb659BMHcrUdTOqgQ1LrzYHUl97KfZioceJDxJZMVq+
         AVSz1X/HAwXvT1vfxQKxFXxpSmyqVeWc86JpQIhs0aC1DPBF/goFL4te/8wpqi7BMQKx
         9oM4JEffC9h2CNxSZcfP7Lk91+UTZsy+0Z5+MkgRyVHM1DCqfV9OX4xTOfztGN5fuMy3
         OjBd3foavjr/VxcgpdWIX7JcqCePo8zoGMjHMMNTnfi9jPZxoFViD1gDkABz2XvrYR85
         GVew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D6+QVu45;
       spf=pass (google.com: domain of 3x2l8zqykcuw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3X2L8ZQYKCUw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039074; x=1711643874; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2IK8bPGhOnnbplvW8aR9K1jOySPQUb3rdvL5LoPiNT4=;
        b=HJqwkZ44IQZBSMXfbpvyS1DqLiks6fq+esOhUoyBI5iKq5r8Q+DEj39IlMin/a9SIK
         fsra+Atg8yqaw/VKYIIn2NlviuV6AhDfwF6zCP87ShquFy2owGTV/arOJY3x2NOoPIe6
         1y9LBPXQkjrBkAfJRKYPEZH05McOEf5GE3yWBDNx/EjsQjmMxj5sIAwtA91h7NyH/691
         /Oh0GU0lgee9Z0KRWe8IP2C+tFbT8oEsNxXcqtSGN11j8JmQCW60FH/89JU186n5djfg
         NNwkDs9zIsLfkm4y8fZXpAv9lj0O3MXL57B1QVsUnxjN4QTYUYZKc9q4zwSYcwXzpKQf
         B3Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039074; x=1711643874;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2IK8bPGhOnnbplvW8aR9K1jOySPQUb3rdvL5LoPiNT4=;
        b=bgpjzu3tHraLrbwwSDTqkZkxWIpCyuB+uAgFyfhB2QddhTdnMkLh+0D8ia8IVrpOcS
         qeNFdju27KDWMYbY5ufmJNhO+THfbvr5yTqU59bKtg2R7NraPBAUKdxHjw5BiUO7sSq5
         ufS1zPtnt8QShA9VQLBSfuOHA6hvEhvQ8PufKZRWI0BOPehnAWEGyPZsQsVd7vn50XYZ
         XzOcx+EKsJgPH07EsojNiukZK73a7A5spPUn7FviwteASBCsSxBMfwGaHxnIMOPpxkrI
         5sPALpMjTBaL09YmHaNMXMjTTwBphHot9u0Z2FhiYceattuZWm4zIe38hSsHC3YI4/5y
         SHBA==
X-Forwarded-Encrypted: i=2; AJvYcCWDr7q/jHp8iAaU02cCJ2TsyYftwwalyuYf8vWh2NVQ7bZDr9N3c1lWn1ZY7cCOU7m4md4ib9tNpdHn16MqqsvcJi3qUXlUGg==
X-Gm-Message-State: AOJu0Ywd8OWXKT7LdvgUvrZQq2E00KOolHCqyneam/opLw3bbyDDzULx
	PEnyldPhlY47hOpvaoCNENcdm8Iz2PF47QRLEhQx3YbmHI4EF5Le
X-Google-Smtp-Source: AGHT+IFlwNFBI/DY3MKceCmPpNDqrrSRUfGwapgXQAoJ8SdxDpAAZ1tsiZInoHlCUGQ+ryCV73H0VA==
X-Received: by 2002:a05:6a00:4f93:b0:6e9:74d7:7092 with SMTP id ld19-20020a056a004f9300b006e974d77092mr4608868pfb.24.1711039073649;
        Thu, 21 Mar 2024 09:37:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:93aa:b0:6e6:f6ed:5daf with SMTP id
 ka42-20020a056a0093aa00b006e6f6ed5dafls814466pfb.1.-pod-prod-07-us; Thu, 21
 Mar 2024 09:37:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXfMlTZdU0r1i7hRGl7aMqDaEZq0cbGxP9XFvQUiSvw3k7gBabv//8YiJQApkrRu7tLoRgOZMyhpbPyt45qFAR2PWj7rYqN169r3w==
X-Received: by 2002:a05:6a20:2447:b0:1a3:6f9a:54e5 with SMTP id t7-20020a056a20244700b001a36f9a54e5mr109830pzc.0.1711039072318;
        Thu, 21 Mar 2024 09:37:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039072; cv=none;
        d=google.com; s=arc-20160816;
        b=yTvftltxIQnzSkyDMtN8Qzj5fx4tA7hgQtgJ915xamKU4ZwJmw+nm3ox9KT0q3oZZI
         3sFa+lAyiEQveCWAnFVKFVmWGGt1T8boSHLtT9PKPI3zcd8/AsvYR8RO3G5gVG1HLRyO
         Pl6QfjWGFFkrqHvjZdytHtDljx7xgo9Jz8DhjwGEWjtXG6uiisATnPTeHCi+dHMY10na
         tZhkJnrq5PHgkA38IrT6wBDqu1iKakt8PGX8eG3T10HkyW+YUmqiiqI4cNe5XBq7+Yav
         JP267Cb0WtqzRCJV/KVIcM5mc/6P7nXq9zFJW/bZNTHGWsfAaouBxo6QuSJqOGctVTQ4
         qkZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=VNGm+8y6Ss+mlVcFwBeCqCAgvw3+NOVbq/tJOyMa3ww=;
        fh=U6jeJxTrM1avZPlZV6RwoNKnc43NHnVjgTZxZDfPkcA=;
        b=d8ai7Ya+9JXYRfUy9ONpV0yBTT/KEhC0AlS52PT6H2ezHufLrfFWjhEigw6+BF3FX6
         qQRkEjnni7sMBz7ec8N+Qpfi4xEZbLH5yc7mGkyFqfk68xmiMhWjiyfQGP+aFO+TkCLL
         2hSxxxPcWWUTaIOCR4P6zZ9Jq2sk81VAXwPng/Xk+Em/ZNmHTATz6B3LYdFExm0eSH5A
         /M3qQxVq8qaYT938/iLXK2ZTTYLOgkcKe/tG2GZR+BXG8Duk9qsMeWSoy1BoQFl0Tx3q
         vNR/JLTaMNpnTlOL27F0oAhEFc/egBxmNAHudd3KrRFqJZ5NGmeVolpW/TdNf0GrQLyB
         SZeg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D6+QVu45;
       spf=pass (google.com: domain of 3x2l8zqykcuw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3X2L8ZQYKCUw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id c10-20020a17090abf0a00b0029fe3bdb544si170127pjs.0.2024.03.21.09.37.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3x2l8zqykcuw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dcbee93a3e1so1860764276.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXtZW+iIB0NP2AgvhbfaVCextvVXD1QNSS+OFILAATHvOgPfX9hcH0V2UAgmlNJ9vUzYAU9JH1ksuRpMR4hc+4GINNTzrk4M3Ge7w==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:1004:b0:dc6:44d4:bee0 with SMTP id
 w4-20020a056902100400b00dc644d4bee0mr1149298ybt.7.1711039071427; Thu, 21 Mar
 2024 09:37:51 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:41 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-20-surenb@google.com>
Subject: [PATCH v6 19/37] mm: create new codetag references during page splitting
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
	glider@google.com, elver@google.com, dvyukov@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=D6+QVu45;       spf=pass
 (google.com: domain of 3x2l8zqykcuw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3X2L8ZQYKCUw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com;
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

When a high-order page is split into smaller ones, each newly split
page should get its codetag. After the split each split page will be
referencing the original codetag. The codetag's "bytes" counter
remains the same because the amount of allocated memory has not
changed, however the "calls" counter gets increased to keep the
counter correct when these individual pages get freed.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/alloc_tag.h   |  9 +++++++++
 include/linux/pgalloc_tag.h | 30 ++++++++++++++++++++++++++++++
 mm/huge_memory.c            |  2 ++
 mm/page_alloc.c             |  2 ++
 4 files changed, 43 insertions(+)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index 28c0005edae1..bc9b1b99a55b 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -106,6 +106,15 @@ static inline void __alloc_tag_ref_set(union codetag_ref *ref, struct alloc_tag
 	this_cpu_inc(tag->counters->calls);
 }
 
+static inline void alloc_tag_ref_set(union codetag_ref *ref, struct alloc_tag *tag)
+{
+	alloc_tag_add_check(ref, tag);
+	if (!ref || !tag)
+		return;
+
+	__alloc_tag_ref_set(ref, tag);
+}
+
 static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag, size_t bytes)
 {
 	alloc_tag_add_check(ref, tag);
diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
index 66bd021eb46e..093edf98c3d7 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -67,11 +67,41 @@ static inline void pgalloc_tag_sub(struct page *page, unsigned int nr)
 	}
 }
 
+static inline void pgalloc_tag_split(struct page *page, unsigned int nr)
+{
+	int i;
+	struct page_ext *page_ext;
+	union codetag_ref *ref;
+	struct alloc_tag *tag;
+
+	if (!mem_alloc_profiling_enabled())
+		return;
+
+	page_ext = page_ext_get(page);
+	if (unlikely(!page_ext))
+		return;
+
+	ref = codetag_ref_from_page_ext(page_ext);
+	if (!ref->ct)
+		goto out;
+
+	tag = ct_to_alloc_tag(ref->ct);
+	page_ext = page_ext_next(page_ext);
+	for (i = 1; i < nr; i++) {
+		/* Set new reference to point to the original tag */
+		alloc_tag_ref_set(codetag_ref_from_page_ext(page_ext), tag);
+		page_ext = page_ext_next(page_ext);
+	}
+out:
+	page_ext_put(page_ext);
+}
+
 #else /* CONFIG_MEM_ALLOC_PROFILING */
 
 static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
 				   unsigned int nr) {}
 static inline void pgalloc_tag_sub(struct page *page, unsigned int nr) {}
+static inline void pgalloc_tag_split(struct page *page, unsigned int nr) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING */
 
diff --git a/mm/huge_memory.c b/mm/huge_memory.c
index c77cedf45f3a..b29f9ef0fcb2 100644
--- a/mm/huge_memory.c
+++ b/mm/huge_memory.c
@@ -38,6 +38,7 @@
 #include <linux/sched/sysctl.h>
 #include <linux/memory-tiers.h>
 #include <linux/compat.h>
+#include <linux/pgalloc_tag.h>
 
 #include <asm/tlb.h>
 #include <asm/pgalloc.h>
@@ -2924,6 +2925,7 @@ static void __split_huge_page(struct page *page, struct list_head *list,
 	/* Caller disabled irqs, so they are still disabled here */
 
 	split_page_owner(head, order, new_order);
+	pgalloc_tag_split(head, 1 << order);
 
 	/* See comment in __split_huge_page_tail() */
 	if (folio_test_anon(folio)) {
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 9c86ef2a0296..fd1cc5b80a56 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2666,6 +2666,7 @@ void split_page(struct page *page, unsigned int order)
 	for (i = 1; i < (1 << order); i++)
 		set_page_refcounted(page + i);
 	split_page_owner(page, order, 0);
+	pgalloc_tag_split(page, 1 << order);
 	split_page_memcg(page, order, 0);
 }
 EXPORT_SYMBOL_GPL(split_page);
@@ -4863,6 +4864,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
 		struct page *last = page + nr;
 
 		split_page_owner(page, order, 0);
+		pgalloc_tag_split(page, 1 << order);
 		split_page_memcg(page, order, 0);
 		while (page < --last)
 			set_page_refcounted(last);
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-20-surenb%40google.com.
