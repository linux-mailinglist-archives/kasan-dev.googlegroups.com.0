Return-Path: <kasan-dev+bncBC7OD3FKWUERBGW6X6RAMGQECQNE5BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 211626F33DD
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:56 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-766588051b3sf159083639f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960155; cv=pass;
        d=google.com; s=arc-20160816;
        b=ovnuYl7vm50q/jvS/CcyjKXowDHLXfinRPLqKBQjt+6YRIdUPSeEbcYh2Hbajehijn
         o9ijkKHllBbIZ1X4rzdT0wS+DCS4IBePAGv8y0IWZQ238+GBzyr0XmJRKfh6MwChZbQk
         9bhMiloKCHWocEvQflnBxmFiot7StmDODP4CZL8rd8k7PgGkz9whh3NIRn+G6g7T9ugo
         pZ+zafxcNT0V477ix8N6zT9a2e+WAk2kVLsBTk1rHg1wSnttd0JxR7WaoC75sqP1FWpo
         haRio/TB47b23FU5+ewZhUQWs8AehflaDjvdxhhAOudRjjm6HJFpp15JDEHheIZt6Ozf
         ZUvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=GigyZTT3cPvIuWGtlNnBVaxro5Lwd6fW8N/5NsvEh6o=;
        b=IT4IXnm0QMiDBzTlOp2ZBZKQG8+imY1xlkaAJO67LLnYZYKlvYY2uq921C63UB5mFt
         vQoCJ9WoEO+RWVPaMmrZbmo+cadp6Hi4CVXcBU/NKi22r9MHvYWCdoYfm/lctywcrxcn
         UURkAsevQQnoRWMtgNDCx9nnQBPL3E/gDvtgzbJQziZvZIoMUTqnBG2jW3PYJKsNavxL
         NtPsl3FmpL1hiyicb9V8Eozo4MQT+VgZ9qZmyc++HalAvx0RkVyBSZaeQgbBcVIWnm/9
         b5DYAx0xxc2JTn3WtwV2M9QyXJM1mQOXwP5j65lJHM988WmIhUuaHy8NlGtNwR7umne3
         gY6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=t3klBo0f;
       spf=pass (google.com: domain of 3ge9pzaykcwaqspcl9emmejc.amki8q8l-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Ge9PZAYKCWAQSPCL9EMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960155; x=1685552155;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GigyZTT3cPvIuWGtlNnBVaxro5Lwd6fW8N/5NsvEh6o=;
        b=Uvaqf8V2JsB4oopDnVh1wkkg1U7i6ojnZKRJYLjcgTo/qrTriVI+PMEjpt173QdyIE
         5pgwptZB5FSqqxdthuUYvhztNLHybSo1bT4nmsD3lh2fIyfxTwa/m/HJ5R8mSbZp5vIM
         6RUpE7dlI1XbW5qWSCj5G6WqSZZGxWiUGVCwjqfkb8hU8I9XwoXE3nAJxIYzYFHoXHMv
         ifyn7oxOiAt6E1rh2kcNi7YoKd9RJicz6T1yXRGZitvcHv6gGEDP4PqEbR1UQXPgN20X
         pewjl+aoZo3+C2rtRVEibfg3DjBlcSjxvJtCrcWEysorA3NoTRAFD1LRJdQF23OWcunB
         HqJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960155; x=1685552155;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GigyZTT3cPvIuWGtlNnBVaxro5Lwd6fW8N/5NsvEh6o=;
        b=BvyrjGINc/Zn74b/VpVYEPXl3jJRV/LJV5iezmYHUbAmAWW22Y85NuDANfFfWHcCvv
         iRwFxr5Q45km1briW84dBgV7fBKzD4ROmsdq6/SL1tr3vAF6rx2Ik9JS4xlT7HPy0iKE
         GmYSX2u2EOAlEkCM9m2UnDICdQEsEdKxEGcT7Kg0NecRpM7zO/3fxKizt20Gj54Z3VB/
         Rb+h5pCR5uLJoUb6Ndl/E/Mhn98KBK8ZLn7Ezltcvhc7i8p2dgkxHPocLDpj1WZRylEK
         mD8f5M7r0rrrhOhi+9QIRjOFX7DDhdU/HuRnhGbdtivUFCTHf98YrS4M3tuZIBEW/CwY
         ra1Q==
X-Gm-Message-State: AC+VfDzzDWZsSPbGjrkDfgSS6tPGrUfUxiDYKiZBDOuUHGeSYDOe+o2J
	PA+wY8o/pFumnRx7nti5RZs=
X-Google-Smtp-Source: ACHHUZ73l9hGDOxE0WIcj4XhOo+FZwJr159v6osLdJdPEfMbW4BNVZwoVnkzG6XY5ZWCtKJkNX4kyg==
X-Received: by 2002:a5d:9a8e:0:b0:761:22af:1e36 with SMTP id c14-20020a5d9a8e000000b0076122af1e36mr6486159iom.1.1682960154996;
        Mon, 01 May 2023 09:55:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:16cd:b0:32b:1332:3d22 with SMTP id
 13-20020a056e0216cd00b0032b13323d22ls3408003ilx.6.-pod-prod-gmail; Mon, 01
 May 2023 09:55:54 -0700 (PDT)
X-Received: by 2002:a92:c104:0:b0:32c:3272:ffde with SMTP id p4-20020a92c104000000b0032c3272ffdemr8791368ile.14.1682960154341;
        Mon, 01 May 2023 09:55:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960154; cv=none;
        d=google.com; s=arc-20160816;
        b=vVb/6lSWFPL+zah1hU5IyqMBl6SEA8MzPqQ4wXZISWVNIf0nFVnHJepC6FlPA7Iidd
         mmxrpXVu32t/08P7t6kDmt5OQ9QuBEcJjQBxCEzNB3GmbXqFBU9W6zwrJ3kuhrYS5hJN
         y0HqXMr7H3OFIfw69klHZoxRa+920BhHgWWjAYn8O5QzVeHqUcWpf7YSQpyR7ikcBFHX
         VEF3S2yKcfYrgQ+dDCSEFF++st3u1z4P6PnG5IWA9KhT69SU7OMoS4DITWBfdHsOGSwG
         rkMKGBURavyWX2qKHRchQzU26L+0lHHrmXexG4sNK4AdXSiGBHyo4ts5RD/pvS3bqcTv
         0l1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Mri2z+LvwzIobpEl78ZbT4L3ds7H/B8V3mrszruJwqU=;
        b=WUslGahj1pXxLY5VCFHKubDtwcRL4PX4aOsCYGOQEX6hvzZb/ka5QRXRuVQcet9Xl+
         rv7f9LlNCyYg8uUy4Fn079jITr8vdsRMxdJNfXO+wCfS6uRqoZfZWmFFwJ5HJAfnPUrL
         4D4lyehvWh77yvYRgVG9K+MLY6PdCQkJl0vpUn8xCKE7xpyiUgX3JbsOuQ4Y5+BG9sIs
         yNUD1BHFcrsIxfWNzYq5CxCTTngoX8lhpjAR6dfrOFACgei/+I/s80BLBQyfoR4ZvURk
         yRILqAhNv9R4dHgXKwsijaFMPtUILcclpKCjjFMtqKggijvqVOVQhDs6m2I+BLUW80QK
         GGgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=t3klBo0f;
       spf=pass (google.com: domain of 3ge9pzaykcwaqspcl9emmejc.amki8q8l-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Ge9PZAYKCWAQSPCL9EMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id w13-20020a056638138d00b0040fc30ac205si2470438jad.0.2023.05.01.09.55.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ge9pzaykcwaqspcl9emmejc.amki8q8l-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-559f179cd38so41349717b3.0
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:54 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a81:9f09:0:b0:559:e830:60f1 with SMTP id
 s9-20020a819f09000000b00559e83060f1mr4600345ywn.8.1682960153830; Mon, 01 May
 2023 09:55:53 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:30 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-21-surenb@google.com>
Subject: [PATCH 20/40] mm: enable page allocation tagging
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
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=t3klBo0f;       spf=pass
 (google.com: domain of 3ge9pzaykcwaqspcl9emmejc.amki8q8l-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Ge9PZAYKCWAQSPCL9EMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--surenb.bounces.google.com;
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

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/alloc_tag.h   |  11 ++++
 include/linux/gfp.h         | 123 +++++++++++++++++++++++++-----------
 include/linux/page_ext.h    |   1 -
 include/linux/pagemap.h     |   9 ++-
 include/linux/pgalloc_tag.h |  38 +++++++++--
 mm/compaction.c             |   9 ++-
 mm/filemap.c                |   6 +-
 mm/mempolicy.c              |  30 ++++-----
 mm/mm_init.c                |   1 +
 mm/page_alloc.c             |  73 ++++++++++++---------
 10 files changed, 208 insertions(+), 93 deletions(-)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index d913f8d9a7d8..07922d81b641 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -102,4 +102,15 @@ static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
 
 #endif
 
+#define alloc_hooks(_do_alloc, _res_type, _err)			\
+({									\
+	_res_type _res;							\
+	DEFINE_ALLOC_TAG(_alloc_tag, _old);				\
+									\
+	_res = _do_alloc;						\
+	alloc_tag_restore(&_alloc_tag, _old);				\
+	_res;								\
+})
+
+
 #endif /* _LINUX_ALLOC_TAG_H */
diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index ed8cb537c6a7..0cb4a515109a 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -6,6 +6,8 @@
 
 #include <linux/mmzone.h>
 #include <linux/topology.h>
+#include <linux/alloc_tag.h>
+#include <linux/sched.h>
 
 struct vm_area_struct;
 
@@ -174,42 +176,57 @@ static inline void arch_free_page(struct page *page, int order) { }
 static inline void arch_alloc_page(struct page *page, int order) { }
 #endif
 
-struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
+struct page *_alloc_pages2(gfp_t gfp, unsigned int order, int preferred_nid,
 		nodemask_t *nodemask);
-struct folio *__folio_alloc(gfp_t gfp, unsigned int order, int preferred_nid,
+#define __alloc_pages(_gfp, _order, _preferred_nid, _nodemask) \
+		alloc_hooks(_alloc_pages2(_gfp, _order, _preferred_nid, \
+					    _nodemask), struct page *, NULL)
+
+struct folio *_folio_alloc2(gfp_t gfp, unsigned int order, int preferred_nid,
 		nodemask_t *nodemask);
+#define __folio_alloc(_gfp, _order, _preferred_nid, _nodemask) \
+		alloc_hooks(_folio_alloc2(_gfp, _order, _preferred_nid, \
+					    _nodemask), struct folio *, NULL)
 
-unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
+unsigned long _alloc_pages_bulk(gfp_t gfp, int preferred_nid,
 				nodemask_t *nodemask, int nr_pages,
 				struct list_head *page_list,
 				struct page **page_array);
-
-unsigned long alloc_pages_bulk_array_mempolicy(gfp_t gfp,
+#define __alloc_pages_bulk(_gfp, _preferred_nid, _nodemask, _nr_pages, \
+			   _page_list, _page_array) \
+		alloc_hooks(_alloc_pages_bulk(_gfp, _preferred_nid, \
+						_nodemask, _nr_pages, \
+						_page_list, _page_array), \
+						unsigned long, 0)
+
+unsigned long _alloc_pages_bulk_array_mempolicy(gfp_t gfp,
 				unsigned long nr_pages,
 				struct page **page_array);
+#define  alloc_pages_bulk_array_mempolicy(_gfp, _nr_pages, _page_array) \
+		alloc_hooks(_alloc_pages_bulk_array_mempolicy(_gfp, \
+					_nr_pages, _page_array), \
+					unsigned long, 0)
 
 /* Bulk allocate order-0 pages */
-static inline unsigned long
-alloc_pages_bulk_list(gfp_t gfp, unsigned long nr_pages, struct list_head *list)
-{
-	return __alloc_pages_bulk(gfp, numa_mem_id(), NULL, nr_pages, list, NULL);
-}
+#define alloc_pages_bulk_list(_gfp, _nr_pages, _list)				\
+	__alloc_pages_bulk(_gfp, numa_mem_id(), NULL, _nr_pages, _list, NULL)
 
-static inline unsigned long
-alloc_pages_bulk_array(gfp_t gfp, unsigned long nr_pages, struct page **page_array)
-{
-	return __alloc_pages_bulk(gfp, numa_mem_id(), NULL, nr_pages, NULL, page_array);
-}
+#define alloc_pages_bulk_array(_gfp, _nr_pages, _page_array)			\
+	__alloc_pages_bulk(_gfp, numa_mem_id(), NULL, _nr_pages, NULL, _page_array)
 
 static inline unsigned long
-alloc_pages_bulk_array_node(gfp_t gfp, int nid, unsigned long nr_pages, struct page **page_array)
+_alloc_pages_bulk_array_node(gfp_t gfp, int nid, unsigned long nr_pages, struct page **page_array)
 {
 	if (nid == NUMA_NO_NODE)
 		nid = numa_mem_id();
 
-	return __alloc_pages_bulk(gfp, nid, NULL, nr_pages, NULL, page_array);
+	return _alloc_pages_bulk(gfp, nid, NULL, nr_pages, NULL, page_array);
 }
 
+#define alloc_pages_bulk_array_node(_gfp, _nid, _nr_pages, _page_array) \
+	alloc_hooks(_alloc_pages_bulk_array_node(_gfp, _nid, _nr_pages, _page_array), \
+		    unsigned long, 0)
+
 static inline void warn_if_node_offline(int this_node, gfp_t gfp_mask)
 {
 	gfp_t warn_gfp = gfp_mask & (__GFP_THISNODE|__GFP_NOWARN);
@@ -229,21 +246,25 @@ static inline void warn_if_node_offline(int this_node, gfp_t gfp_mask)
  * online. For more general interface, see alloc_pages_node().
  */
 static inline struct page *
-__alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
+_alloc_pages_node2(int nid, gfp_t gfp_mask, unsigned int order)
 {
 	VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);
 	warn_if_node_offline(nid, gfp_mask);
 
-	return __alloc_pages(gfp_mask, order, nid, NULL);
+	return _alloc_pages2(gfp_mask, order, nid, NULL);
 }
 
+#define  __alloc_pages_node(_nid, _gfp_mask, _order) \
+		alloc_hooks(_alloc_pages_node2(_nid, _gfp_mask, _order), \
+					struct page *, NULL)
+
 static inline
 struct folio *__folio_alloc_node(gfp_t gfp, unsigned int order, int nid)
 {
 	VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);
 	warn_if_node_offline(nid, gfp);
 
-	return __folio_alloc(gfp, order, nid, NULL);
+	return _folio_alloc2(gfp, order, nid, NULL);
 }
 
 /*
@@ -251,32 +272,45 @@ struct folio *__folio_alloc_node(gfp_t gfp, unsigned int order, int nid)
  * prefer the current CPU's closest node. Otherwise node must be valid and
  * online.
  */
-static inline struct page *alloc_pages_node(int nid, gfp_t gfp_mask,
+static inline struct page *_alloc_pages_node(int nid, gfp_t gfp_mask,
 						unsigned int order)
 {
 	if (nid == NUMA_NO_NODE)
 		nid = numa_mem_id();
 
-	return __alloc_pages_node(nid, gfp_mask, order);
+	return _alloc_pages_node2(nid, gfp_mask, order);
 }
 
+#define  alloc_pages_node(_nid, _gfp_mask, _order) \
+		alloc_hooks(_alloc_pages_node(_nid, _gfp_mask, _order), \
+					struct page *, NULL)
+
 #ifdef CONFIG_NUMA
-struct page *alloc_pages(gfp_t gfp, unsigned int order);
-struct folio *folio_alloc(gfp_t gfp, unsigned order);
-struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
+struct page *_alloc_pages(gfp_t gfp, unsigned int order);
+struct folio *_folio_alloc(gfp_t gfp, unsigned int order);
+struct folio *_vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
 		unsigned long addr, bool hugepage);
 #else
-static inline struct page *alloc_pages(gfp_t gfp_mask, unsigned int order)
+static inline struct page *_alloc_pages(gfp_t gfp_mask, unsigned int order)
 {
-	return alloc_pages_node(numa_node_id(), gfp_mask, order);
+	return _alloc_pages_node(numa_node_id(), gfp_mask, order);
 }
-static inline struct folio *folio_alloc(gfp_t gfp, unsigned int order)
+static inline struct folio *_folio_alloc(gfp_t gfp, unsigned int order)
 {
 	return __folio_alloc_node(gfp, order, numa_node_id());
 }
-#define vma_alloc_folio(gfp, order, vma, addr, hugepage)		\
-	folio_alloc(gfp, order)
+#define _vma_alloc_folio(gfp, order, vma, addr, hugepage)		\
+	_folio_alloc(gfp, order)
 #endif
+
+#define alloc_pages(_gfp, _order) \
+		alloc_hooks(_alloc_pages(_gfp, _order), struct page *, NULL)
+#define folio_alloc(_gfp, _order) \
+		alloc_hooks(_folio_alloc(_gfp, _order), struct folio *, NULL)
+#define vma_alloc_folio(_gfp, _order, _vma, _addr, _hugepage)		\
+		alloc_hooks(_vma_alloc_folio(_gfp, _order, _vma, _addr, \
+				_hugepage), struct folio *, NULL)
+
 #define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)
 static inline struct page *alloc_page_vma(gfp_t gfp,
 		struct vm_area_struct *vma, unsigned long addr)
@@ -286,12 +320,21 @@ static inline struct page *alloc_page_vma(gfp_t gfp,
 	return &folio->page;
 }
 
-extern unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order);
-extern unsigned long get_zeroed_page(gfp_t gfp_mask);
+extern unsigned long _get_free_pages(gfp_t gfp_mask, unsigned int order);
+#define __get_free_pages(_gfp_mask, _order) \
+		alloc_hooks(_get_free_pages(_gfp_mask, _order), unsigned long, 0)
+extern unsigned long _get_zeroed_page(gfp_t gfp_mask);
+#define get_zeroed_page(_gfp_mask) \
+		alloc_hooks(_get_zeroed_page(_gfp_mask), unsigned long, 0)
 
-void *alloc_pages_exact(size_t size, gfp_t gfp_mask) __alloc_size(1);
+void *_alloc_pages_exact(size_t size, gfp_t gfp_mask) __alloc_size(1);
+#define alloc_pages_exact(_size, _gfp_mask) \
+		alloc_hooks(_alloc_pages_exact(_size, _gfp_mask), void *, NULL)
 void free_pages_exact(void *virt, size_t size);
-__meminit void *alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask) __alloc_size(2);
+
+__meminit void *_alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask) __alloc_size(2);
+#define alloc_pages_exact_nid(_nid, _size, _gfp_mask) \
+		alloc_hooks(_alloc_pages_exact_nid(_nid, _size, _gfp_mask), void *, NULL)
 
 #define __get_free_page(gfp_mask) \
 		__get_free_pages((gfp_mask), 0)
@@ -354,10 +397,16 @@ static inline bool pm_suspended_storage(void)
 
 #ifdef CONFIG_CONTIG_ALLOC
 /* The below functions must be run on a range from a single zone. */
-extern int alloc_contig_range(unsigned long start, unsigned long end,
+extern int _alloc_contig_range(unsigned long start, unsigned long end,
 			      unsigned migratetype, gfp_t gfp_mask);
-extern struct page *alloc_contig_pages(unsigned long nr_pages, gfp_t gfp_mask,
-				       int nid, nodemask_t *nodemask);
+#define alloc_contig_range(_start, _end, _migratetype, _gfp_mask) \
+		alloc_hooks(_alloc_contig_range(_start, _end, _migratetype, \
+						 _gfp_mask), int, -ENOMEM)
+extern struct page *_alloc_contig_pages(unsigned long nr_pages, gfp_t gfp_mask,
+					int nid, nodemask_t *nodemask);
+#define alloc_contig_pages(_nr_pages, _gfp_mask, _nid, _nodemask) \
+		alloc_hooks(_alloc_contig_pages(_nr_pages, _gfp_mask, _nid, \
+						  _nodemask), struct page *, NULL)
 #endif
 void free_contig_range(unsigned long pfn, unsigned long nr_pages);
 
diff --git a/include/linux/page_ext.h b/include/linux/page_ext.h
index 67314f648aeb..cff15ee5440e 100644
--- a/include/linux/page_ext.h
+++ b/include/linux/page_ext.h
@@ -4,7 +4,6 @@
 
 #include <linux/types.h>
 #include <linux/stacktrace.h>
-#include <linux/stackdepot.h>
 
 struct pglist_data;
 
diff --git a/include/linux/pagemap.h b/include/linux/pagemap.h
index a56308a9d1a4..b2efafa001f8 100644
--- a/include/linux/pagemap.h
+++ b/include/linux/pagemap.h
@@ -467,14 +467,17 @@ static inline void *detach_page_private(struct page *page)
 }
 
 #ifdef CONFIG_NUMA
-struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order);
+struct folio *_filemap_alloc_folio(gfp_t gfp, unsigned int order);
 #else
-static inline struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order)
+static inline struct folio *_filemap_alloc_folio(gfp_t gfp, unsigned int order)
 {
-	return folio_alloc(gfp, order);
+	return _folio_alloc(gfp, order);
 }
 #endif
 
+#define filemap_alloc_folio(_gfp, _order) \
+	alloc_hooks(_filemap_alloc_folio(_gfp, _order), struct folio *, NULL)
+
 static inline struct page *__page_cache_alloc(gfp_t gfp)
 {
 	return &filemap_alloc_folio(gfp, 0)->page;
diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
index f8c7b6ef9c75..567327c1c46f 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -6,28 +6,58 @@
 #define _LINUX_PGALLOC_TAG_H
 
 #include <linux/alloc_tag.h>
+
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+
 #include <linux/page_ext.h>
 
 extern struct page_ext_operations page_alloc_tagging_ops;
-struct page_ext *lookup_page_ext(const struct page *page);
+extern struct page_ext *page_ext_get(struct page *page);
+extern void page_ext_put(struct page_ext *page_ext);
+
+static inline union codetag_ref *codetag_ref_from_page_ext(struct page_ext *page_ext)
+{
+	return (void *)page_ext + page_alloc_tagging_ops.offset;
+}
+
+static inline struct page_ext *page_ext_from_codetag_ref(union codetag_ref *ref)
+{
+	return (void *)ref - page_alloc_tagging_ops.offset;
+}
 
 static inline union codetag_ref *get_page_tag_ref(struct page *page)
 {
 	if (page && mem_alloc_profiling_enabled()) {
-		struct page_ext *page_ext = lookup_page_ext(page);
+		struct page_ext *page_ext = page_ext_get(page);
 
 		if (page_ext)
-			return (void *)page_ext + page_alloc_tagging_ops.offset;
+			return codetag_ref_from_page_ext(page_ext);
 	}
 	return NULL;
 }
 
+static inline void put_page_tag_ref(union codetag_ref *ref)
+{
+	if (ref)
+		page_ext_put(page_ext_from_codetag_ref(ref));
+}
+
 static inline void pgalloc_tag_dec(struct page *page, unsigned int order)
 {
 	union codetag_ref *ref = get_page_tag_ref(page);
 
-	if (ref)
+	if (ref) {
 		alloc_tag_sub(ref, PAGE_SIZE << order);
+		put_page_tag_ref(ref);
+	}
 }
 
+#else /* CONFIG_MEM_ALLOC_PROFILING */
+
+static inline union codetag_ref *get_page_tag_ref(struct page *page) { return NULL; }
+static inline void put_page_tag_ref(union codetag_ref *ref) {}
+#define pgalloc_tag_dec(__page, __size)		do {} while (0)
+
+#endif /* CONFIG_MEM_ALLOC_PROFILING */
+
 #endif /* _LINUX_PGALLOC_TAG_H */
diff --git a/mm/compaction.c b/mm/compaction.c
index c8bcdea15f5f..32707fb62495 100644
--- a/mm/compaction.c
+++ b/mm/compaction.c
@@ -1684,7 +1684,7 @@ static void isolate_freepages(struct compact_control *cc)
  * This is a migrate-callback that "allocates" freepages by taking pages
  * from the isolated freelists in the block we are migrating to.
  */
-static struct page *compaction_alloc(struct page *migratepage,
+static struct page *_compaction_alloc(struct page *migratepage,
 					unsigned long data)
 {
 	struct compact_control *cc = (struct compact_control *)data;
@@ -1704,6 +1704,13 @@ static struct page *compaction_alloc(struct page *migratepage,
 	return freepage;
 }
 
+static struct page *compaction_alloc(struct page *migratepage,
+				     unsigned long data)
+{
+	return alloc_hooks(_compaction_alloc(migratepage, data),
+			   struct page *, NULL);
+}
+
 /*
  * This is a migrate-callback that "frees" freepages back to the isolated
  * freelist.  All pages on the freelist are from the same zone, so there is no
diff --git a/mm/filemap.c b/mm/filemap.c
index a34abfe8c654..f0f8b782d172 100644
--- a/mm/filemap.c
+++ b/mm/filemap.c
@@ -958,7 +958,7 @@ int filemap_add_folio(struct address_space *mapping, struct folio *folio,
 EXPORT_SYMBOL_GPL(filemap_add_folio);
 
 #ifdef CONFIG_NUMA
-struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order)
+struct folio *_filemap_alloc_folio(gfp_t gfp, unsigned int order)
 {
 	int n;
 	struct folio *folio;
@@ -973,9 +973,9 @@ struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order)
 
 		return folio;
 	}
-	return folio_alloc(gfp, order);
+	return _folio_alloc(gfp, order);
 }
-EXPORT_SYMBOL(filemap_alloc_folio);
+EXPORT_SYMBOL(_filemap_alloc_folio);
 #endif
 
 /*
diff --git a/mm/mempolicy.c b/mm/mempolicy.c
index 2068b594dc88..80cd33811641 100644
--- a/mm/mempolicy.c
+++ b/mm/mempolicy.c
@@ -2141,7 +2141,7 @@ static struct page *alloc_pages_preferred_many(gfp_t gfp, unsigned int order,
 }
 
 /**
- * vma_alloc_folio - Allocate a folio for a VMA.
+ * _vma_alloc_folio - Allocate a folio for a VMA.
  * @gfp: GFP flags.
  * @order: Order of the folio.
  * @vma: Pointer to VMA or NULL if not available.
@@ -2155,7 +2155,7 @@ static struct page *alloc_pages_preferred_many(gfp_t gfp, unsigned int order,
  *
  * Return: The folio on success or NULL if allocation fails.
  */
-struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
+struct folio *_vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
 		unsigned long addr, bool hugepage)
 {
 	struct mempolicy *pol;
@@ -2240,10 +2240,10 @@ struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
 out:
 	return folio;
 }
-EXPORT_SYMBOL(vma_alloc_folio);
+EXPORT_SYMBOL(_vma_alloc_folio);
 
 /**
- * alloc_pages - Allocate pages.
+ * _alloc_pages - Allocate pages.
  * @gfp: GFP flags.
  * @order: Power of two of number of pages to allocate.
  *
@@ -2256,7 +2256,7 @@ EXPORT_SYMBOL(vma_alloc_folio);
  * flags are used.
  * Return: The page on success or NULL if allocation fails.
  */
-struct page *alloc_pages(gfp_t gfp, unsigned order)
+struct page *_alloc_pages(gfp_t gfp, unsigned int order)
 {
 	struct mempolicy *pol = &default_policy;
 	struct page *page;
@@ -2274,15 +2274,15 @@ struct page *alloc_pages(gfp_t gfp, unsigned order)
 		page = alloc_pages_preferred_many(gfp, order,
 				  policy_node(gfp, pol, numa_node_id()), pol);
 	else
-		page = __alloc_pages(gfp, order,
+		page = _alloc_pages2(gfp, order,
 				policy_node(gfp, pol, numa_node_id()),
 				policy_nodemask(gfp, pol));
 
 	return page;
 }
-EXPORT_SYMBOL(alloc_pages);
+EXPORT_SYMBOL(_alloc_pages);
 
-struct folio *folio_alloc(gfp_t gfp, unsigned order)
+struct folio *_folio_alloc(gfp_t gfp, unsigned int order)
 {
 	struct page *page = alloc_pages(gfp | __GFP_COMP, order);
 
@@ -2290,7 +2290,7 @@ struct folio *folio_alloc(gfp_t gfp, unsigned order)
 		prep_transhuge_page(page);
 	return (struct folio *)page;
 }
-EXPORT_SYMBOL(folio_alloc);
+EXPORT_SYMBOL(_folio_alloc);
 
 static unsigned long alloc_pages_bulk_array_interleave(gfp_t gfp,
 		struct mempolicy *pol, unsigned long nr_pages,
@@ -2309,13 +2309,13 @@ static unsigned long alloc_pages_bulk_array_interleave(gfp_t gfp,
 
 	for (i = 0; i < nodes; i++) {
 		if (delta) {
-			nr_allocated = __alloc_pages_bulk(gfp,
+			nr_allocated = _alloc_pages_bulk(gfp,
 					interleave_nodes(pol), NULL,
 					nr_pages_per_node + 1, NULL,
 					page_array);
 			delta--;
 		} else {
-			nr_allocated = __alloc_pages_bulk(gfp,
+			nr_allocated = _alloc_pages_bulk(gfp,
 					interleave_nodes(pol), NULL,
 					nr_pages_per_node, NULL, page_array);
 		}
@@ -2337,11 +2337,11 @@ static unsigned long alloc_pages_bulk_array_preferred_many(gfp_t gfp, int nid,
 	preferred_gfp = gfp | __GFP_NOWARN;
 	preferred_gfp &= ~(__GFP_DIRECT_RECLAIM | __GFP_NOFAIL);
 
-	nr_allocated  = __alloc_pages_bulk(preferred_gfp, nid, &pol->nodes,
+	nr_allocated  = _alloc_pages_bulk(preferred_gfp, nid, &pol->nodes,
 					   nr_pages, NULL, page_array);
 
 	if (nr_allocated < nr_pages)
-		nr_allocated += __alloc_pages_bulk(gfp, numa_node_id(), NULL,
+		nr_allocated += _alloc_pages_bulk(gfp, numa_node_id(), NULL,
 				nr_pages - nr_allocated, NULL,
 				page_array + nr_allocated);
 	return nr_allocated;
@@ -2353,7 +2353,7 @@ static unsigned long alloc_pages_bulk_array_preferred_many(gfp_t gfp, int nid,
  * It can accelerate memory allocation especially interleaving
  * allocate memory.
  */
-unsigned long alloc_pages_bulk_array_mempolicy(gfp_t gfp,
+unsigned long _alloc_pages_bulk_array_mempolicy(gfp_t gfp,
 		unsigned long nr_pages, struct page **page_array)
 {
 	struct mempolicy *pol = &default_policy;
@@ -2369,7 +2369,7 @@ unsigned long alloc_pages_bulk_array_mempolicy(gfp_t gfp,
 		return alloc_pages_bulk_array_preferred_many(gfp,
 				numa_node_id(), pol, nr_pages, page_array);
 
-	return __alloc_pages_bulk(gfp, policy_node(gfp, pol, numa_node_id()),
+	return _alloc_pages_bulk(gfp, policy_node(gfp, pol, numa_node_id()),
 				  policy_nodemask(gfp, pol), nr_pages, NULL,
 				  page_array);
 }
diff --git a/mm/mm_init.c b/mm/mm_init.c
index 7f7f9c677854..42135fad4d8a 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -24,6 +24,7 @@
 #include <linux/page_ext.h>
 #include <linux/pti.h>
 #include <linux/pgtable.h>
+#include <linux/stackdepot.h>
 #include <linux/swap.h>
 #include <linux/cma.h>
 #include "internal.h"
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 9de2a18519a1..edd35500f7f6 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -74,6 +74,7 @@
 #include <linux/psi.h>
 #include <linux/khugepaged.h>
 #include <linux/delayacct.h>
+#include <linux/pgalloc_tag.h>
 #include <asm/sections.h>
 #include <asm/tlbflush.h>
 #include <asm/div64.h>
@@ -657,6 +658,7 @@ static inline bool pcp_allowed_order(unsigned int order)
 
 static inline void free_the_page(struct page *page, unsigned int order)
 {
+
 	if (pcp_allowed_order(order))		/* Via pcp? */
 		free_unref_page(page, order);
 	else
@@ -1259,6 +1261,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			__memcg_kmem_uncharge_page(page, order);
 		reset_page_owner(page, order);
 		page_table_check_free(page, order);
+		pgalloc_tag_dec(page, order);
 		return false;
 	}
 
@@ -1301,6 +1304,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
 	reset_page_owner(page, order);
 	page_table_check_free(page, order);
+	pgalloc_tag_dec(page, order);
 
 	if (!PageHighMem(page)) {
 		debug_check_no_locks_freed(page_address(page),
@@ -1669,6 +1673,9 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
 			!should_skip_init(gfp_flags);
 	bool zero_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	union codetag_ref *ref;
+#endif
 	int i;
 
 	set_page_private(page, 0);
@@ -1721,6 +1728,14 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 
 	set_page_owner(page, order, gfp_flags);
 	page_table_check_alloc(page, order);
+
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	ref = get_page_tag_ref(page);
+	if (ref) {
+		alloc_tag_add(ref, current->alloc_tag, PAGE_SIZE << order);
+		put_page_tag_ref(ref);
+	}
+#endif
 }
 
 static void prep_new_page(struct page *page, unsigned int order, gfp_t gfp_flags,
@@ -4568,7 +4583,7 @@ static inline bool prepare_alloc_pages(gfp_t gfp_mask, unsigned int order,
  *
  * Returns the number of pages on the list or array.
  */
-unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
+unsigned long _alloc_pages_bulk(gfp_t gfp, int preferred_nid,
 			nodemask_t *nodemask, int nr_pages,
 			struct list_head *page_list,
 			struct page **page_array)
@@ -4704,7 +4719,7 @@ unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
 	pcp_trylock_finish(UP_flags);
 
 failed:
-	page = __alloc_pages(gfp, 0, preferred_nid, nodemask);
+	page = _alloc_pages2(gfp, 0, preferred_nid, nodemask);
 	if (page) {
 		if (page_list)
 			list_add(&page->lru, page_list);
@@ -4715,12 +4730,12 @@ unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
 
 	goto out;
 }
-EXPORT_SYMBOL_GPL(__alloc_pages_bulk);
+EXPORT_SYMBOL_GPL(_alloc_pages_bulk);
 
 /*
  * This is the 'heart' of the zoned buddy allocator.
  */
-struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
+struct page *_alloc_pages2(gfp_t gfp, unsigned int order, int preferred_nid,
 							nodemask_t *nodemask)
 {
 	struct page *page;
@@ -4783,41 +4798,41 @@ struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
 
 	return page;
 }
-EXPORT_SYMBOL(__alloc_pages);
+EXPORT_SYMBOL(_alloc_pages2);
 
-struct folio *__folio_alloc(gfp_t gfp, unsigned int order, int preferred_nid,
+struct folio *_folio_alloc2(gfp_t gfp, unsigned int order, int preferred_nid,
 		nodemask_t *nodemask)
 {
-	struct page *page = __alloc_pages(gfp | __GFP_COMP, order,
+	struct page *page = _alloc_pages2(gfp | __GFP_COMP, order,
 			preferred_nid, nodemask);
 
 	if (page && order > 1)
 		prep_transhuge_page(page);
 	return (struct folio *)page;
 }
-EXPORT_SYMBOL(__folio_alloc);
+EXPORT_SYMBOL(_folio_alloc2);
 
 /*
  * Common helper functions. Never use with __GFP_HIGHMEM because the returned
  * address cannot represent highmem pages. Use alloc_pages and then kmap if
  * you need to access high mem.
  */
-unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order)
+unsigned long _get_free_pages(gfp_t gfp_mask, unsigned int order)
 {
 	struct page *page;
 
-	page = alloc_pages(gfp_mask & ~__GFP_HIGHMEM, order);
+	page = _alloc_pages(gfp_mask & ~__GFP_HIGHMEM, order);
 	if (!page)
 		return 0;
 	return (unsigned long) page_address(page);
 }
-EXPORT_SYMBOL(__get_free_pages);
+EXPORT_SYMBOL(_get_free_pages);
 
-unsigned long get_zeroed_page(gfp_t gfp_mask)
+unsigned long _get_zeroed_page(gfp_t gfp_mask)
 {
-	return __get_free_page(gfp_mask | __GFP_ZERO);
+	return _get_free_pages(gfp_mask | __GFP_ZERO, 0);
 }
-EXPORT_SYMBOL(get_zeroed_page);
+EXPORT_SYMBOL(_get_zeroed_page);
 
 /**
  * __free_pages - Free pages allocated with alloc_pages().
@@ -5009,7 +5024,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
 }
 
 /**
- * alloc_pages_exact - allocate an exact number physically-contiguous pages.
+ * _alloc_pages_exact - allocate an exact number physically-contiguous pages.
  * @size: the number of bytes to allocate
  * @gfp_mask: GFP flags for the allocation, must not contain __GFP_COMP
  *
@@ -5023,7 +5038,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
  *
  * Return: pointer to the allocated area or %NULL in case of error.
  */
-void *alloc_pages_exact(size_t size, gfp_t gfp_mask)
+void *_alloc_pages_exact(size_t size, gfp_t gfp_mask)
 {
 	unsigned int order = get_order(size);
 	unsigned long addr;
@@ -5031,13 +5046,13 @@ void *alloc_pages_exact(size_t size, gfp_t gfp_mask)
 	if (WARN_ON_ONCE(gfp_mask & (__GFP_COMP | __GFP_HIGHMEM)))
 		gfp_mask &= ~(__GFP_COMP | __GFP_HIGHMEM);
 
-	addr = __get_free_pages(gfp_mask, order);
+	addr = _get_free_pages(gfp_mask, order);
 	return make_alloc_exact(addr, order, size);
 }
-EXPORT_SYMBOL(alloc_pages_exact);
+EXPORT_SYMBOL(_alloc_pages_exact);
 
 /**
- * alloc_pages_exact_nid - allocate an exact number of physically-contiguous
+ * _alloc_pages_exact_nid - allocate an exact number of physically-contiguous
  *			   pages on a node.
  * @nid: the preferred node ID where memory should be allocated
  * @size: the number of bytes to allocate
@@ -5048,7 +5063,7 @@ EXPORT_SYMBOL(alloc_pages_exact);
  *
  * Return: pointer to the allocated area or %NULL in case of error.
  */
-void * __meminit alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask)
+void * __meminit _alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask)
 {
 	unsigned int order = get_order(size);
 	struct page *p;
@@ -5056,7 +5071,7 @@ void * __meminit alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask)
 	if (WARN_ON_ONCE(gfp_mask & (__GFP_COMP | __GFP_HIGHMEM)))
 		gfp_mask &= ~(__GFP_COMP | __GFP_HIGHMEM);
 
-	p = alloc_pages_node(nid, gfp_mask, order);
+	p = _alloc_pages_node(nid, gfp_mask, order);
 	if (!p)
 		return NULL;
 	return make_alloc_exact((unsigned long)page_address(p), order, size);
@@ -6729,7 +6744,7 @@ int __alloc_contig_migrate_range(struct compact_control *cc,
 }
 
 /**
- * alloc_contig_range() -- tries to allocate given range of pages
+ * _alloc_contig_range() -- tries to allocate given range of pages
  * @start:	start PFN to allocate
  * @end:	one-past-the-last PFN to allocate
  * @migratetype:	migratetype of the underlying pageblocks (either
@@ -6749,7 +6764,7 @@ int __alloc_contig_migrate_range(struct compact_control *cc,
  * pages which PFN is in [start, end) are allocated for the caller and
  * need to be freed with free_contig_range().
  */
-int alloc_contig_range(unsigned long start, unsigned long end,
+int _alloc_contig_range(unsigned long start, unsigned long end,
 		       unsigned migratetype, gfp_t gfp_mask)
 {
 	unsigned long outer_start, outer_end;
@@ -6873,15 +6888,15 @@ int alloc_contig_range(unsigned long start, unsigned long end,
 	undo_isolate_page_range(start, end, migratetype);
 	return ret;
 }
-EXPORT_SYMBOL(alloc_contig_range);
+EXPORT_SYMBOL(_alloc_contig_range);
 
 static int __alloc_contig_pages(unsigned long start_pfn,
 				unsigned long nr_pages, gfp_t gfp_mask)
 {
 	unsigned long end_pfn = start_pfn + nr_pages;
 
-	return alloc_contig_range(start_pfn, end_pfn, MIGRATE_MOVABLE,
-				  gfp_mask);
+	return _alloc_contig_range(start_pfn, end_pfn, MIGRATE_MOVABLE,
+				   gfp_mask);
 }
 
 static bool pfn_range_valid_contig(struct zone *z, unsigned long start_pfn,
@@ -6916,7 +6931,7 @@ static bool zone_spans_last_pfn(const struct zone *zone,
 }
 
 /**
- * alloc_contig_pages() -- tries to find and allocate contiguous range of pages
+ * _alloc_contig_pages() -- tries to find and allocate contiguous range of pages
  * @nr_pages:	Number of contiguous pages to allocate
  * @gfp_mask:	GFP mask to limit search and used during compaction
  * @nid:	Target node
@@ -6936,8 +6951,8 @@ static bool zone_spans_last_pfn(const struct zone *zone,
  *
  * Return: pointer to contiguous pages on success, or NULL if not successful.
  */
-struct page *alloc_contig_pages(unsigned long nr_pages, gfp_t gfp_mask,
-				int nid, nodemask_t *nodemask)
+struct page *_alloc_contig_pages(unsigned long nr_pages, gfp_t gfp_mask,
+				 int nid, nodemask_t *nodemask)
 {
 	unsigned long ret, pfn, flags;
 	struct zonelist *zonelist;
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-21-surenb%40google.com.
