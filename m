Return-Path: <kasan-dev+bncBC7OD3FKWUERB3MV36UQMGQERHDXGLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id ECDD47D5252
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:26 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-5b87150242csf2820062a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155245; cv=pass;
        d=google.com; s=arc-20160816;
        b=ehwPmtlA9Df6WTAl9tnESTMQHmmqnB458DrzIWeo3nz9WyqOybALOR4bNSna3ttGyX
         9zPs2kaIy7mEcpZjmWrmWekgTdI/TiqPCzCKlbBgVt7e2HeCkNk4Gn8zgSTKLu/QjwLc
         /jHxmkXRAyJJ27ElI4xQRVcRzgS1D4nDdK1QpnR0GxKrllfeyEsOH12v1EMDMMDourtm
         KE0tC8uawUJK0ElhDpvUKjyCxwRlaACjPrt7RJipI1WvFwPoVL7xINYNLR7MhHC28Nh6
         bSKdgM3ORysz4kfM6MxOuGDNxwY27z4Xf3TasYLiXYoeYhRXyAts2RJTmhH+ziyQSJIP
         1Ncg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=NEqbIcnd617Dp+knYbDCiVFkCp56n4HjI2/A/5qtoVg=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=a4jozcXyq2WN+SLyP8Q2JuqxNHIINHcC+EZEbdTSW0oPz/8DF5V7OO4m2c5wsXUzLy
         ZF7om4arMT6wxJ6uHtRCl6iOjqIpt/BDzeIfTyTT4OYD1SHzXUMc2UQvGfhno7EmDLwu
         maIuy/dstzbaanfhu7mciGiosUlOz5Uq7E6eKXT96wX8Y5+ZZCAtYMKfMuigxrisDE6X
         O94FxG527mMh3o4xl/VIpJ/wt+ArG759NENyI1qG1NItArWvrMdgR22hysx/qwdc4C/Y
         YRcv9sYfSTKY9ySQwEIk0hOknRoTvhVzmWIAqgnlkHF6igAfIKlLRpP2Lq1k7vkdSdTK
         f2ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZnkIIFz3;
       spf=pass (google.com: domain of 368o3zqykczaceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=368o3ZQYKCZACEBy7v08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155245; x=1698760045; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NEqbIcnd617Dp+knYbDCiVFkCp56n4HjI2/A/5qtoVg=;
        b=hnDsKjKEbe6rRI/OvflMuLKKKyxsDfkIF/1XY8fp6CrxO6HrQ+MvsZXxMUx8BcSB1x
         ba6XgEf7jwLMuBFALxu1bW752j1oXPPFOVuxgZk7kEi5thP1sBVeGOnBN0aiuBDh/NV2
         smWqpQMwtWTy6DDe01cLa4yUiU5dR5AqO6uAoTQDFyHOycmwePKGlWPo09ZDyGnSb9Wx
         kccYDmbqAE3FMZZjvVFH41EBf4g4Pzo+OSZMb3H3N/P4Re0DO+mMtPiIrVWolSM5WwBw
         pr2lM/GMexbwaA3lJ/Nso/2rmwwOP/dJuD9cMccKHhbCr41kZBQzLCEWerHEQ+0kVE5b
         fi4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155245; x=1698760045;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NEqbIcnd617Dp+knYbDCiVFkCp56n4HjI2/A/5qtoVg=;
        b=jeKoDgVDGdIlVWUIiWUVYW9GPaK/zTObGWYZvUKi/4VlvR/nULxu6SLlVwq/hgpa9T
         kDIif7Mh9tL6IGuXfPXo0GrRyOtioVIOZtzUB6+3jCidr4ZQj9OpR9bzpKKa81oJTlOC
         hjtAFv8iiKAMWwu+abVU/KP2DWKKue/xEdIiyTEDM/baocrLFMfPd6SKqbhmS/nMVw9m
         KuHxHHo2Us5j22X3g416vCU6YopNoyF9VChZjCxFETGzodmYfiM0DHuXh34hwQJogmHk
         a/nXvIA+t89BdFUUuUYhginzXUvG3VMZowxjBk+xWr7x62SLqqaJJnN2LLuUYRhNzlWr
         Lq9w==
X-Gm-Message-State: AOJu0Yw8UAQpCHC0MKqS6dRZURyOeupmkc1ozdZT427j2/bL/qZbVR8p
	EwCd+YfH5k45gA3AbvUGi6U=
X-Google-Smtp-Source: AGHT+IEry44JUGG7rDFSD0NPxBo4/05mGueL7WhF7hRePOjCEXgzECUJI+e9c9jmNEjzEnbVd5PIeA==
X-Received: by 2002:a05:6a21:9998:b0:153:39d9:56fe with SMTP id ve24-20020a056a21999800b0015339d956femr2096510pzb.47.1698155245147;
        Tue, 24 Oct 2023 06:47:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1995:b0:688:6f02:a66e with SMTP id
 d21-20020a056a00199500b006886f02a66els2370726pfl.2.-pod-prod-02-us; Tue, 24
 Oct 2023 06:47:24 -0700 (PDT)
X-Received: by 2002:a05:6a21:78a5:b0:179:feba:732 with SMTP id bf37-20020a056a2178a500b00179feba0732mr2733874pzc.33.1698155244145;
        Tue, 24 Oct 2023 06:47:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155244; cv=none;
        d=google.com; s=arc-20160816;
        b=Iz97K2ZOr19T25dOaD1N4MeQKJrgxEr2YLhGuUp+3/+T9uCVUEr+AkRL1x6oTq6fSo
         nsR76a6O8YEjprQ6+LZU27wwCGeSxFEsYi6GYwPJ5KA7pCW7bxdkM5nuLsBhwxCGW1j8
         pheM8wW0MJFm4AOE5Vu30l8SBHCTWwR1KatO2g3cg4dpz3nVt1u6GZUH8irVkE9FQCye
         LFsmn73ERzG+msZGtJ+9G+uPrGlYwEIip0JaKI5uNhEOX+n/sxxHGx9jKEtzUvDp5oGN
         CNJdnWFf/pWG/asKYT/0JjASv2VnAsFK5CC/L+7RjdcU4aj21kmQiASvmQvA7NFuB6zv
         nHQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=aDBkAbyEeXJgt2cs2rmRo9d2BeozU6HvXUKgeAkvqwY=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=lPe5ALLO1z2FFQT7SDphvlhPk7+YjDZIcTwt+/fu7efADVjPU/TZ9B7kXl9x+LkrPq
         cvq1NscBHOf5ne1Ax7zXmJ4/J2FvJFWJsMzXvDmeS9Zl5e9iL6AHvAXJX/SfbUkkJPuf
         RHWg/YmtCvhY8L9kdF3oZhfSU+oZOpuxAM5ShsCtk+NWnTK580FxwaN+UCeeMH5a7ETk
         7rhM6EXegBzdZuu2AouoqUEg/VcWSFZ4WhjmL9Aj5AvVZQL2YrEVs5AS/cXq0Q9euBrf
         VL8iplIJjAWaCLNgSe8lH6wOhH4HBKnGgGNrmJTAEx8EVu557L8f1d4JMniNm2kgUchJ
         JIKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZnkIIFz3;
       spf=pass (google.com: domain of 368o3zqykczaceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=368o3ZQYKCZACEBy7v08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id ch6-20020a056a00288600b0068e35848ad4si607462pfb.5.2023.10.24.06.47.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 368o3zqykczaceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-d9cafa90160so5239344276.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:24 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a05:6902:105:b0:da0:3da9:ce08 with SMTP id
 o5-20020a056902010500b00da03da9ce08mr35574ybh.10.1698155243657; Tue, 24 Oct
 2023 06:47:23 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:16 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-20-surenb@google.com>
Subject: [PATCH v2 19/39] mm: enable page allocation tagging
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ZnkIIFz3;       spf=pass
 (google.com: domain of 368o3zqykczaceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=368o3ZQYKCZACEBy7v08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--surenb.bounces.google.com;
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

Redefine page allocators to record allocation tags upon their invocation.
Instrument post_alloc_hook and free_pages_prepare to modify current
allocation tag.

Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/alloc_tag.h |  10 ++++
 include/linux/gfp.h       | 111 +++++++++++++++++++++++---------------
 include/linux/pagemap.h   |   9 ++--
 mm/compaction.c           |   7 ++-
 mm/filemap.c              |   6 +--
 mm/mempolicy.c            |  42 +++++++--------
 mm/page_alloc.c           |  60 ++++++++++-----------
 7 files changed, 144 insertions(+), 101 deletions(-)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index cf55a149fa84..6fa8a94d8bc1 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -130,4 +130,14 @@ static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
 
 #endif
 
+#define alloc_hooks(_do_alloc)						\
+({									\
+	typeof(_do_alloc) _res;						\
+	DEFINE_ALLOC_TAG(_alloc_tag, _old);				\
+									\
+	_res = _do_alloc;						\
+	alloc_tag_restore(&_alloc_tag, _old);				\
+	_res;								\
+})
+
 #endif /* _LINUX_ALLOC_TAG_H */
diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 665f06675c83..20686fd1f417 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -6,6 +6,8 @@
 
 #include <linux/mmzone.h>
 #include <linux/topology.h>
+#include <linux/alloc_tag.h>
+#include <linux/sched.h>
 
 struct vm_area_struct;
 
@@ -174,42 +176,43 @@ static inline void arch_free_page(struct page *page, int order) { }
 static inline void arch_alloc_page(struct page *page, int order) { }
 #endif
 
-struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
+struct page *__alloc_pages_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
 		nodemask_t *nodemask);
-struct folio *__folio_alloc(gfp_t gfp, unsigned int order, int preferred_nid,
+#define __alloc_pages(...)			alloc_hooks(__alloc_pages_noprof(__VA_ARGS__))
+
+struct folio *__folio_alloc_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
 		nodemask_t *nodemask);
+#define __folio_alloc(...)			alloc_hooks(__folio_alloc_noprof(__VA_ARGS__))
 
-unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
+unsigned long alloc_pages_bulk_noprof(gfp_t gfp, int preferred_nid,
 				nodemask_t *nodemask, int nr_pages,
 				struct list_head *page_list,
 				struct page **page_array);
+#define __alloc_pages_bulk(...)			alloc_hooks(alloc_pages_bulk_noprof(__VA_ARGS__))
 
-unsigned long alloc_pages_bulk_array_mempolicy(gfp_t gfp,
+unsigned long alloc_pages_bulk_array_mempolicy_noprof(gfp_t gfp,
 				unsigned long nr_pages,
 				struct page **page_array);
+#define  alloc_pages_bulk_array_mempolicy(...)	alloc_hooks(alloc_pages_bulk_array_mempolicy_noprof(__VA_ARGS__))
 
 /* Bulk allocate order-0 pages */
-static inline unsigned long
-alloc_pages_bulk_list(gfp_t gfp, unsigned long nr_pages, struct list_head *list)
-{
-	return __alloc_pages_bulk(gfp, numa_mem_id(), NULL, nr_pages, list, NULL);
-}
+#define alloc_pages_bulk_list(_gfp, _nr_pages, _list)			\
+	__alloc_pages_bulk(_gfp, numa_mem_id(), NULL, _nr_pages, _list, NULL)
 
-static inline unsigned long
-alloc_pages_bulk_array(gfp_t gfp, unsigned long nr_pages, struct page **page_array)
-{
-	return __alloc_pages_bulk(gfp, numa_mem_id(), NULL, nr_pages, NULL, page_array);
-}
+#define alloc_pages_bulk_array(_gfp, _nr_pages, _page_array)		\
+	__alloc_pages_bulk(_gfp, numa_mem_id(), NULL, _nr_pages, NULL, _page_array)
 
 static inline unsigned long
-alloc_pages_bulk_array_node(gfp_t gfp, int nid, unsigned long nr_pages, struct page **page_array)
+alloc_pages_bulk_array_node_noprof(gfp_t gfp, int nid, unsigned long nr_pages, struct page **page_array)
 {
 	if (nid == NUMA_NO_NODE)
 		nid = numa_mem_id();
 
-	return __alloc_pages_bulk(gfp, nid, NULL, nr_pages, NULL, page_array);
+	return alloc_pages_bulk_noprof(gfp, nid, NULL, nr_pages, NULL, page_array);
 }
 
+#define alloc_pages_bulk_array_node(...)	alloc_hooks(alloc_pages_bulk_array_node_noprof(__VA_ARGS__))
+
 static inline void warn_if_node_offline(int this_node, gfp_t gfp_mask)
 {
 	gfp_t warn_gfp = gfp_mask & (__GFP_THISNODE|__GFP_NOWARN);
@@ -229,21 +232,23 @@ static inline void warn_if_node_offline(int this_node, gfp_t gfp_mask)
  * online. For more general interface, see alloc_pages_node().
  */
 static inline struct page *
-__alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
+__alloc_pages_node_noprof(int nid, gfp_t gfp_mask, unsigned int order)
 {
 	VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);
 	warn_if_node_offline(nid, gfp_mask);
 
-	return __alloc_pages(gfp_mask, order, nid, NULL);
+	return __alloc_pages_noprof(gfp_mask, order, nid, NULL);
 }
 
+#define  __alloc_pages_node(...)		alloc_hooks(__alloc_pages_node_noprof(__VA_ARGS__))
+
 static inline
 struct folio *__folio_alloc_node(gfp_t gfp, unsigned int order, int nid)
 {
 	VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);
 	warn_if_node_offline(nid, gfp);
 
-	return __folio_alloc(gfp, order, nid, NULL);
+	return __folio_alloc_noprof(gfp, order, nid, NULL);
 }
 
 /*
@@ -251,53 +256,69 @@ struct folio *__folio_alloc_node(gfp_t gfp, unsigned int order, int nid)
  * prefer the current CPU's closest node. Otherwise node must be valid and
  * online.
  */
-static inline struct page *alloc_pages_node(int nid, gfp_t gfp_mask,
-						unsigned int order)
+static inline struct page *alloc_pages_node_noprof(int nid, gfp_t gfp_mask,
+						   unsigned int order)
 {
 	if (nid == NUMA_NO_NODE)
 		nid = numa_mem_id();
 
-	return __alloc_pages_node(nid, gfp_mask, order);
+	return __alloc_pages_node_noprof(nid, gfp_mask, order);
 }
 
+#define  alloc_pages_node(...)			alloc_hooks(alloc_pages_node_noprof(__VA_ARGS__))
+
 #ifdef CONFIG_NUMA
-struct page *alloc_pages(gfp_t gfp, unsigned int order);
-struct folio *folio_alloc(gfp_t gfp, unsigned order);
-struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
+struct page *alloc_pages_noprof(gfp_t gfp, unsigned int order);
+struct folio *folio_alloc_noprof(gfp_t gfp, unsigned int order);
+struct folio *vma_alloc_folio_noprof(gfp_t gfp, int order, struct vm_area_struct *vma,
 		unsigned long addr, bool hugepage);
 #else
-static inline struct page *alloc_pages(gfp_t gfp_mask, unsigned int order)
+static inline struct page *alloc_pages_noprof(gfp_t gfp_mask, unsigned int order)
 {
-	return alloc_pages_node(numa_node_id(), gfp_mask, order);
+	return alloc_pages_node_noprof(numa_node_id(), gfp_mask, order);
 }
-static inline struct folio *folio_alloc(gfp_t gfp, unsigned int order)
+static inline struct folio *folio_alloc_noprof(gfp_t gfp, unsigned int order)
 {
 	return __folio_alloc_node(gfp, order, numa_node_id());
 }
-#define vma_alloc_folio(gfp, order, vma, addr, hugepage)		\
-	folio_alloc(gfp, order)
+#define vma_alloc_folio_noprof(gfp, order, vma, addr, hugepage)		\
+	folio_alloc_noprof(gfp, order)
 #endif
+
+#define alloc_pages(...)			alloc_hooks(alloc_pages_noprof(__VA_ARGS__))
+#define folio_alloc(...)			alloc_hooks(folio_alloc_noprof(__VA_ARGS__))
+#define vma_alloc_folio(...)			alloc_hooks(vma_alloc_folio_noprof(__VA_ARGS__))
+
 #define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)
-static inline struct page *alloc_page_vma(gfp_t gfp,
+
+static inline struct page *alloc_page_vma_noprof(gfp_t gfp,
 		struct vm_area_struct *vma, unsigned long addr)
 {
-	struct folio *folio = vma_alloc_folio(gfp, 0, vma, addr, false);
+	struct folio *folio = vma_alloc_folio_noprof(gfp, 0, vma, addr, false);
 
 	return &folio->page;
 }
+#define alloc_page_vma(...)			alloc_hooks(alloc_page_vma_noprof(__VA_ARGS__))
+
+extern unsigned long get_free_pages_noprof(gfp_t gfp_mask, unsigned int order);
+#define __get_free_pages(...)			alloc_hooks(get_free_pages_noprof(__VA_ARGS__))
 
-extern unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order);
-extern unsigned long get_zeroed_page(gfp_t gfp_mask);
+extern unsigned long get_zeroed_page_noprof(gfp_t gfp_mask);
+#define get_zeroed_page(...)			alloc_hooks(get_zeroed_page_noprof(__VA_ARGS__))
+
+void *alloc_pages_exact_noprof(size_t size, gfp_t gfp_mask) __alloc_size(1);
+#define alloc_pages_exact(...)			alloc_hooks(alloc_pages_exact_noprof(__VA_ARGS__))
 
-void *alloc_pages_exact(size_t size, gfp_t gfp_mask) __alloc_size(1);
 void free_pages_exact(void *virt, size_t size);
-__meminit void *alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask) __alloc_size(2);
 
-#define __get_free_page(gfp_mask) \
-		__get_free_pages((gfp_mask), 0)
+__meminit void *alloc_pages_exact_nid_noprof(int nid, size_t size, gfp_t gfp_mask) __alloc_size(2);
+#define alloc_pages_exact_nid(...)		alloc_hooks(alloc_pages_exact_nid_noprof(__VA_ARGS__))
+
+#define __get_free_page(gfp_mask)					\
+	__get_free_pages((gfp_mask), 0)
 
-#define __get_dma_pages(gfp_mask, order) \
-		__get_free_pages((gfp_mask) | GFP_DMA, (order))
+#define __get_dma_pages(gfp_mask, order)				\
+	__get_free_pages((gfp_mask) | GFP_DMA, (order))
 
 extern void __free_pages(struct page *page, unsigned int order);
 extern void free_pages(unsigned long addr, unsigned int order);
@@ -347,10 +368,14 @@ extern gfp_t vma_thp_gfp_mask(struct vm_area_struct *vma);
 
 #ifdef CONFIG_CONTIG_ALLOC
 /* The below functions must be run on a range from a single zone. */
-extern int alloc_contig_range(unsigned long start, unsigned long end,
+extern int alloc_contig_range_noprof(unsigned long start, unsigned long end,
 			      unsigned migratetype, gfp_t gfp_mask);
-extern struct page *alloc_contig_pages(unsigned long nr_pages, gfp_t gfp_mask,
-				       int nid, nodemask_t *nodemask);
+#define alloc_contig_range(...)			alloc_hooks(alloc_contig_range_noprof(__VA_ARGS__))
+
+extern struct page *alloc_contig_pages_noprof(unsigned long nr_pages, gfp_t gfp_mask,
+					      int nid, nodemask_t *nodemask);
+#define alloc_contig_pages(...)			alloc_hooks(alloc_contig_pages_noprof(__VA_ARGS__))
+
 #endif
 void free_contig_range(unsigned long pfn, unsigned long nr_pages);
 
diff --git a/include/linux/pagemap.h b/include/linux/pagemap.h
index 351c3b7f93a1..cb387321f929 100644
--- a/include/linux/pagemap.h
+++ b/include/linux/pagemap.h
@@ -508,14 +508,17 @@ static inline void *detach_page_private(struct page *page)
 #endif
 
 #ifdef CONFIG_NUMA
-struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order);
+struct folio *filemap_alloc_folio_noprof(gfp_t gfp, unsigned int order);
 #else
-static inline struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order)
+static inline struct folio *filemap_alloc_folio_noprof(gfp_t gfp, unsigned int order)
 {
-	return folio_alloc(gfp, order);
+	return folio_alloc_noprof(gfp, order);
 }
 #endif
 
+#define filemap_alloc_folio(...)				\
+	alloc_hooks(filemap_alloc_folio_noprof(__VA_ARGS__))
+
 static inline struct page *__page_cache_alloc(gfp_t gfp)
 {
 	return &filemap_alloc_folio(gfp, 0)->page;
diff --git a/mm/compaction.c b/mm/compaction.c
index 38c8d216c6a3..74a7ec71660d 100644
--- a/mm/compaction.c
+++ b/mm/compaction.c
@@ -1760,7 +1760,7 @@ static void isolate_freepages(struct compact_control *cc)
  * This is a migrate-callback that "allocates" freepages by taking pages
  * from the isolated freelists in the block we are migrating to.
  */
-static struct folio *compaction_alloc(struct folio *src, unsigned long data)
+static struct folio *compaction_alloc_noprof(struct folio *src, unsigned long data)
 {
 	struct compact_control *cc = (struct compact_control *)data;
 	struct folio *dst;
@@ -1779,6 +1779,11 @@ static struct folio *compaction_alloc(struct folio *src, unsigned long data)
 	return dst;
 }
 
+static struct folio *compaction_alloc(struct folio *src, unsigned long data)
+{
+	return alloc_hooks(compaction_alloc_noprof(src, data));
+}
+
 /*
  * This is a migrate-callback that "frees" freepages back to the isolated
  * freelist.  All pages on the freelist are from the same zone, so there is no
diff --git a/mm/filemap.c b/mm/filemap.c
index f0a15ce1bd1b..fc0e4b630b51 100644
--- a/mm/filemap.c
+++ b/mm/filemap.c
@@ -958,7 +958,7 @@ int filemap_add_folio(struct address_space *mapping, struct folio *folio,
 EXPORT_SYMBOL_GPL(filemap_add_folio);
 
 #ifdef CONFIG_NUMA
-struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order)
+struct folio *filemap_alloc_folio_noprof(gfp_t gfp, unsigned int order)
 {
 	int n;
 	struct folio *folio;
@@ -973,9 +973,9 @@ struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order)
 
 		return folio;
 	}
-	return folio_alloc(gfp, order);
+	return folio_alloc_noprof(gfp, order);
 }
-EXPORT_SYMBOL(filemap_alloc_folio);
+EXPORT_SYMBOL(filemap_alloc_folio_noprof);
 #endif
 
 /*
diff --git a/mm/mempolicy.c b/mm/mempolicy.c
index f1b00d6ac7ee..0c3d65fbf9e8 100644
--- a/mm/mempolicy.c
+++ b/mm/mempolicy.c
@@ -2127,7 +2127,7 @@ static struct page *alloc_page_interleave(gfp_t gfp, unsigned order,
 {
 	struct page *page;
 
-	page = __alloc_pages(gfp, order, nid, NULL);
+	page = __alloc_pages_noprof(gfp, order, nid, NULL);
 	/* skip NUMA_INTERLEAVE_HIT counter update if numa stats is disabled */
 	if (!static_branch_likely(&vm_numa_stat_key))
 		return page;
@@ -2153,15 +2153,15 @@ static struct page *alloc_pages_preferred_many(gfp_t gfp, unsigned int order,
 	 */
 	preferred_gfp = gfp | __GFP_NOWARN;
 	preferred_gfp &= ~(__GFP_DIRECT_RECLAIM | __GFP_NOFAIL);
-	page = __alloc_pages(preferred_gfp, order, nid, &pol->nodes);
+	page = __alloc_pages_noprof(preferred_gfp, order, nid, &pol->nodes);
 	if (!page)
-		page = __alloc_pages(gfp, order, nid, NULL);
+		page = __alloc_pages_noprof(gfp, order, nid, NULL);
 
 	return page;
 }
 
 /**
- * vma_alloc_folio - Allocate a folio for a VMA.
+ * vma_alloc_folio_noprof - Allocate a folio for a VMA.
  * @gfp: GFP flags.
  * @order: Order of the folio.
  * @vma: Pointer to VMA or NULL if not available.
@@ -2175,7 +2175,7 @@ static struct page *alloc_pages_preferred_many(gfp_t gfp, unsigned int order,
  *
  * Return: The folio on success or NULL if allocation fails.
  */
-struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
+struct folio *vma_alloc_folio_noprof(gfp_t gfp, int order, struct vm_area_struct *vma,
 		unsigned long addr, bool hugepage)
 {
 	struct mempolicy *pol;
@@ -2246,7 +2246,7 @@ struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
 			 * memory with both reclaim and compact as well.
 			 */
 			if (!folio && (gfp & __GFP_DIRECT_RECLAIM))
-				folio = __folio_alloc(gfp, order, hpage_node,
+				folio = __folio_alloc_noprof(gfp, order, hpage_node,
 						      nmask);
 
 			goto out;
@@ -2255,15 +2255,15 @@ struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
 
 	nmask = policy_nodemask(gfp, pol);
 	preferred_nid = policy_node(gfp, pol, node);
-	folio = __folio_alloc(gfp, order, preferred_nid, nmask);
+	folio = __folio_alloc_noprof(gfp, order, preferred_nid, nmask);
 	mpol_cond_put(pol);
 out:
 	return folio;
 }
-EXPORT_SYMBOL(vma_alloc_folio);
+EXPORT_SYMBOL(vma_alloc_folio_noprof);
 
 /**
- * alloc_pages - Allocate pages.
+ * alloc_pages_noprof - Allocate pages.
  * @gfp: GFP flags.
  * @order: Power of two of number of pages to allocate.
  *
@@ -2276,7 +2276,7 @@ EXPORT_SYMBOL(vma_alloc_folio);
  * flags are used.
  * Return: The page on success or NULL if allocation fails.
  */
-struct page *alloc_pages(gfp_t gfp, unsigned order)
+struct page *alloc_pages_noprof(gfp_t gfp, unsigned int order)
 {
 	struct mempolicy *pol = &default_policy;
 	struct page *page;
@@ -2294,24 +2294,24 @@ struct page *alloc_pages(gfp_t gfp, unsigned order)
 		page = alloc_pages_preferred_many(gfp, order,
 				  policy_node(gfp, pol, numa_node_id()), pol);
 	else
-		page = __alloc_pages(gfp, order,
+		page = __alloc_pages_noprof(gfp, order,
 				policy_node(gfp, pol, numa_node_id()),
 				policy_nodemask(gfp, pol));
 
 	return page;
 }
-EXPORT_SYMBOL(alloc_pages);
+EXPORT_SYMBOL(alloc_pages_noprof);
 
-struct folio *folio_alloc(gfp_t gfp, unsigned order)
+struct folio *folio_alloc_noprof(gfp_t gfp, unsigned int order)
 {
-	struct page *page = alloc_pages(gfp | __GFP_COMP, order);
+	struct page *page = alloc_pages_noprof(gfp | __GFP_COMP, order);
 	struct folio *folio = (struct folio *)page;
 
 	if (folio && order > 1)
 		folio_prep_large_rmappable(folio);
 	return folio;
 }
-EXPORT_SYMBOL(folio_alloc);
+EXPORT_SYMBOL(folio_alloc_noprof);
 
 static unsigned long alloc_pages_bulk_array_interleave(gfp_t gfp,
 		struct mempolicy *pol, unsigned long nr_pages,
@@ -2330,13 +2330,13 @@ static unsigned long alloc_pages_bulk_array_interleave(gfp_t gfp,
 
 	for (i = 0; i < nodes; i++) {
 		if (delta) {
-			nr_allocated = __alloc_pages_bulk(gfp,
+			nr_allocated = alloc_pages_bulk_noprof(gfp,
 					interleave_nodes(pol), NULL,
 					nr_pages_per_node + 1, NULL,
 					page_array);
 			delta--;
 		} else {
-			nr_allocated = __alloc_pages_bulk(gfp,
+			nr_allocated = alloc_pages_bulk_noprof(gfp,
 					interleave_nodes(pol), NULL,
 					nr_pages_per_node, NULL, page_array);
 		}
@@ -2358,11 +2358,11 @@ static unsigned long alloc_pages_bulk_array_preferred_many(gfp_t gfp, int nid,
 	preferred_gfp = gfp | __GFP_NOWARN;
 	preferred_gfp &= ~(__GFP_DIRECT_RECLAIM | __GFP_NOFAIL);
 
-	nr_allocated  = __alloc_pages_bulk(preferred_gfp, nid, &pol->nodes,
+	nr_allocated  = alloc_pages_bulk_noprof(preferred_gfp, nid, &pol->nodes,
 					   nr_pages, NULL, page_array);
 
 	if (nr_allocated < nr_pages)
-		nr_allocated += __alloc_pages_bulk(gfp, numa_node_id(), NULL,
+		nr_allocated += alloc_pages_bulk_noprof(gfp, numa_node_id(), NULL,
 				nr_pages - nr_allocated, NULL,
 				page_array + nr_allocated);
 	return nr_allocated;
@@ -2374,7 +2374,7 @@ static unsigned long alloc_pages_bulk_array_preferred_many(gfp_t gfp, int nid,
  * It can accelerate memory allocation especially interleaving
  * allocate memory.
  */
-unsigned long alloc_pages_bulk_array_mempolicy(gfp_t gfp,
+unsigned long alloc_pages_bulk_array_mempolicy_noprof(gfp_t gfp,
 		unsigned long nr_pages, struct page **page_array)
 {
 	struct mempolicy *pol = &default_policy;
@@ -2390,7 +2390,7 @@ unsigned long alloc_pages_bulk_array_mempolicy(gfp_t gfp,
 		return alloc_pages_bulk_array_preferred_many(gfp,
 				numa_node_id(), pol, nr_pages, page_array);
 
-	return __alloc_pages_bulk(gfp, policy_node(gfp, pol, numa_node_id()),
+	return alloc_pages_bulk_noprof(gfp, policy_node(gfp, pol, numa_node_id()),
 				  policy_nodemask(gfp, pol), nr_pages, NULL,
 				  page_array);
 }
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index d490d0f73e72..63dc2f8c7901 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -4239,7 +4239,7 @@ static inline bool prepare_alloc_pages(gfp_t gfp_mask, unsigned int order,
  *
  * Returns the number of pages on the list or array.
  */
-unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
+unsigned long alloc_pages_bulk_noprof(gfp_t gfp, int preferred_nid,
 			nodemask_t *nodemask, int nr_pages,
 			struct list_head *page_list,
 			struct page **page_array)
@@ -4375,7 +4375,7 @@ unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
 	pcp_trylock_finish(UP_flags);
 
 failed:
-	page = __alloc_pages(gfp, 0, preferred_nid, nodemask);
+	page = __alloc_pages_noprof(gfp, 0, preferred_nid, nodemask);
 	if (page) {
 		if (page_list)
 			list_add(&page->lru, page_list);
@@ -4386,13 +4386,13 @@ unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
 
 	goto out;
 }
-EXPORT_SYMBOL_GPL(__alloc_pages_bulk);
+EXPORT_SYMBOL_GPL(alloc_pages_bulk_noprof);
 
 /*
  * This is the 'heart' of the zoned buddy allocator.
  */
-struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
-							nodemask_t *nodemask)
+struct page *__alloc_pages_noprof(gfp_t gfp, unsigned int order,
+				      int preferred_nid, nodemask_t *nodemask)
 {
 	struct page *page;
 	unsigned int alloc_flags = ALLOC_WMARK_LOW;
@@ -4454,12 +4454,12 @@ struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
 
 	return page;
 }
-EXPORT_SYMBOL(__alloc_pages);
+EXPORT_SYMBOL(__alloc_pages_noprof);
 
-struct folio *__folio_alloc(gfp_t gfp, unsigned int order, int preferred_nid,
+struct folio *__folio_alloc_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
 		nodemask_t *nodemask)
 {
-	struct page *page = __alloc_pages(gfp | __GFP_COMP, order,
+	struct page *page = __alloc_pages_noprof(gfp | __GFP_COMP, order,
 			preferred_nid, nodemask);
 	struct folio *folio = (struct folio *)page;
 
@@ -4467,29 +4467,29 @@ struct folio *__folio_alloc(gfp_t gfp, unsigned int order, int preferred_nid,
 		folio_prep_large_rmappable(folio);
 	return folio;
 }
-EXPORT_SYMBOL(__folio_alloc);
+EXPORT_SYMBOL(__folio_alloc_noprof);
 
 /*
  * Common helper functions. Never use with __GFP_HIGHMEM because the returned
  * address cannot represent highmem pages. Use alloc_pages and then kmap if
  * you need to access high mem.
  */
-unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order)
+unsigned long get_free_pages_noprof(gfp_t gfp_mask, unsigned int order)
 {
 	struct page *page;
 
-	page = alloc_pages(gfp_mask & ~__GFP_HIGHMEM, order);
+	page = alloc_pages_noprof(gfp_mask & ~__GFP_HIGHMEM, order);
 	if (!page)
 		return 0;
 	return (unsigned long) page_address(page);
 }
-EXPORT_SYMBOL(__get_free_pages);
+EXPORT_SYMBOL(get_free_pages_noprof);
 
-unsigned long get_zeroed_page(gfp_t gfp_mask)
+unsigned long get_zeroed_page_noprof(gfp_t gfp_mask)
 {
-	return __get_free_page(gfp_mask | __GFP_ZERO);
+	return get_free_pages_noprof(gfp_mask | __GFP_ZERO, 0);
 }
-EXPORT_SYMBOL(get_zeroed_page);
+EXPORT_SYMBOL(get_zeroed_page_noprof);
 
 /**
  * __free_pages - Free pages allocated with alloc_pages().
@@ -4681,7 +4681,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
 }
 
 /**
- * alloc_pages_exact - allocate an exact number physically-contiguous pages.
+ * alloc_pages_exact_noprof - allocate an exact number physically-contiguous pages.
  * @size: the number of bytes to allocate
  * @gfp_mask: GFP flags for the allocation, must not contain __GFP_COMP
  *
@@ -4695,7 +4695,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
  *
  * Return: pointer to the allocated area or %NULL in case of error.
  */
-void *alloc_pages_exact(size_t size, gfp_t gfp_mask)
+void *alloc_pages_exact_noprof(size_t size, gfp_t gfp_mask)
 {
 	unsigned int order = get_order(size);
 	unsigned long addr;
@@ -4703,13 +4703,13 @@ void *alloc_pages_exact(size_t size, gfp_t gfp_mask)
 	if (WARN_ON_ONCE(gfp_mask & (__GFP_COMP | __GFP_HIGHMEM)))
 		gfp_mask &= ~(__GFP_COMP | __GFP_HIGHMEM);
 
-	addr = __get_free_pages(gfp_mask, order);
+	addr = get_free_pages_noprof(gfp_mask, order);
 	return make_alloc_exact(addr, order, size);
 }
-EXPORT_SYMBOL(alloc_pages_exact);
+EXPORT_SYMBOL(alloc_pages_exact_noprof);
 
 /**
- * alloc_pages_exact_nid - allocate an exact number of physically-contiguous
+ * alloc_pages_exact_nid_noprof - allocate an exact number of physically-contiguous
  *			   pages on a node.
  * @nid: the preferred node ID where memory should be allocated
  * @size: the number of bytes to allocate
@@ -4720,7 +4720,7 @@ EXPORT_SYMBOL(alloc_pages_exact);
  *
  * Return: pointer to the allocated area or %NULL in case of error.
  */
-void * __meminit alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask)
+void * __meminit alloc_pages_exact_nid_noprof(int nid, size_t size, gfp_t gfp_mask)
 {
 	unsigned int order = get_order(size);
 	struct page *p;
@@ -4728,7 +4728,7 @@ void * __meminit alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask)
 	if (WARN_ON_ONCE(gfp_mask & (__GFP_COMP | __GFP_HIGHMEM)))
 		gfp_mask &= ~(__GFP_COMP | __GFP_HIGHMEM);
 
-	p = alloc_pages_node(nid, gfp_mask, order);
+	p = alloc_pages_node_noprof(nid, gfp_mask, order);
 	if (!p)
 		return NULL;
 	return make_alloc_exact((unsigned long)page_address(p), order, size);
@@ -6090,7 +6090,7 @@ int __alloc_contig_migrate_range(struct compact_control *cc,
 }
 
 /**
- * alloc_contig_range() -- tries to allocate given range of pages
+ * alloc_contig_range_noprof() -- tries to allocate given range of pages
  * @start:	start PFN to allocate
  * @end:	one-past-the-last PFN to allocate
  * @migratetype:	migratetype of the underlying pageblocks (either
@@ -6110,7 +6110,7 @@ int __alloc_contig_migrate_range(struct compact_control *cc,
  * pages which PFN is in [start, end) are allocated for the caller and
  * need to be freed with free_contig_range().
  */
-int alloc_contig_range(unsigned long start, unsigned long end,
+int alloc_contig_range_noprof(unsigned long start, unsigned long end,
 		       unsigned migratetype, gfp_t gfp_mask)
 {
 	unsigned long outer_start, outer_end;
@@ -6234,15 +6234,15 @@ int alloc_contig_range(unsigned long start, unsigned long end,
 	undo_isolate_page_range(start, end, migratetype);
 	return ret;
 }
-EXPORT_SYMBOL(alloc_contig_range);
+EXPORT_SYMBOL(alloc_contig_range_noprof);
 
 static int __alloc_contig_pages(unsigned long start_pfn,
 				unsigned long nr_pages, gfp_t gfp_mask)
 {
 	unsigned long end_pfn = start_pfn + nr_pages;
 
-	return alloc_contig_range(start_pfn, end_pfn, MIGRATE_MOVABLE,
-				  gfp_mask);
+	return alloc_contig_range_noprof(start_pfn, end_pfn, MIGRATE_MOVABLE,
+				   gfp_mask);
 }
 
 static bool pfn_range_valid_contig(struct zone *z, unsigned long start_pfn,
@@ -6277,7 +6277,7 @@ static bool zone_spans_last_pfn(const struct zone *zone,
 }
 
 /**
- * alloc_contig_pages() -- tries to find and allocate contiguous range of pages
+ * alloc_contig_pages_noprof() -- tries to find and allocate contiguous range of pages
  * @nr_pages:	Number of contiguous pages to allocate
  * @gfp_mask:	GFP mask to limit search and used during compaction
  * @nid:	Target node
@@ -6297,8 +6297,8 @@ static bool zone_spans_last_pfn(const struct zone *zone,
  *
  * Return: pointer to contiguous pages on success, or NULL if not successful.
  */
-struct page *alloc_contig_pages(unsigned long nr_pages, gfp_t gfp_mask,
-				int nid, nodemask_t *nodemask)
+struct page *alloc_contig_pages_noprof(unsigned long nr_pages, gfp_t gfp_mask,
+				 int nid, nodemask_t *nodemask)
 {
 	unsigned long ret, pfn, flags;
 	struct zonelist *zonelist;
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-20-surenb%40google.com.
