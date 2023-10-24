Return-Path: <kasan-dev+bncBC7OD3FKWUERB34V36UQMGQEIQR2U7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 83DF57D5254
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:28 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-357ce7283d3sf1050765ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155247; cv=pass;
        d=google.com; s=arc-20160816;
        b=slr2CUOZ19BPYF9fS5ibOQVgJIfOtofRPrvzeubUNxqmug7/jUQ+nCE/w8c8ZcWguj
         wf5iGYKeZUQiEEPYuNjhEdvXOcscpiGtRwcM9F/Ox6K4yDLEuLCYuqXoP+ESII6ZhCVM
         pggL0EE1vBDSFjww0o3nKazZFSmdnDpO7CHW5/QzzQ1bXbYBRyJkXWZWs+u5TJgJBNpV
         UV3+PFxCQjV0XE5iPxIglnDtESDINvYeKVGZa7OzrvltlE7bA753hwa6bVl4GWZs6iXB
         zIs9TCQnZpyCGh7Od23KE/7jJ+C0hoquB4jQXe7u/f+L3LRmbxX+iFZvP+EaFIjCyHtF
         ZjiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=sLuKZXqdFSibUuRu7V7w+k+cwHmWi/efMCZx5OaiYqY=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=H5cqbbQVjCh1CSDFOU699cs1WOUBO9aKOOD3UHJaxiBaJPtUQ0BmGfi7Vl7p4awRtG
         XfHBDOC+7cRsKx1zwnMvs7AyT3E4Dl8LCBvGix1NciEEpHZqDl5LkvbC38xVJlDcSly6
         TEGNVO02kEDy14Yj2LiQwysdUAYCf6nr/cDPe/M/XJ1wPLPXA8lgfxQjth5gHf7Epktl
         L2gCm5FXA6OtqNaycJWrDT/vqT1DZs6HTohOx9gEsfYojv8QF5uJMcmps9XgGKRGODLL
         TU5xkRRaVHQIOH1qAg7v97M6fyP9dX98MvcnZmiZA54N1Bj6A1qA+O7ERP1NLn/VAV/V
         +ndQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zg2dRr1S;
       spf=pass (google.com: domain of 37co3zqykcziegd09x2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=37co3ZQYKCZIEGD09x2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155247; x=1698760047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=sLuKZXqdFSibUuRu7V7w+k+cwHmWi/efMCZx5OaiYqY=;
        b=s04imqUJcXatTWUClL+MY0lqKUBBMRnfZa8sy0lzSUaYYflN5zfgFXTK6k4Q+AYPce
         G05BuOtZVwzaVAejDt8+3OskTZyF8uHaTzhIhPlmxgaIbcBoP/DU1kQuMoCa20N2fH1x
         8WniVYaRx3N2pwDjfbhK+NqMmQqpnOlEymUoQx0vNXxKI9CpMQQWiOczxe9PVr+0KiNx
         Fp1W4Jm7Z+90ICCJyvNBT42mS3hD3u/XinwpBVFh9yXu2n6v8lwENLkMnmJjgEwzBbIX
         AHdHR6Z1qQ6Xp+H/3PuUI5fs5tWYiGNLJfPmoZ//mGoFSnF33yWt1N0baCjip3pSDPZt
         lpZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155247; x=1698760047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sLuKZXqdFSibUuRu7V7w+k+cwHmWi/efMCZx5OaiYqY=;
        b=a0q/wC6L3g7i2yKtwwM3Gmb06VM/n/8I0uw/3XQiiX8Lm9r21b08exetWZ8iL/akDh
         eF2vhutuGzSebJ6fy+9dyGANkQbRuyDl+yYump5UXdaMCQcZFPlBviaJ11Pv6u66Prvo
         Qb2WwOJA49iif9mYzGyy/tF+bGuNilHeJzVKoqMuihCz9ykBRIobmlPlq5i1XUyXe7ry
         W2W3B9oOMz9K1QsJAvEB7ABSUjYUyPCAlGbqnCkVmg0vFTXgsgTVRZgTrEERFTyu0z9s
         byAhK6yjtU7q+otFat2gBL7xLDV9JcqL8j86a+ARM0aobky3UnWUJ3j7rRnrAJCWFUNA
         xb2w==
X-Gm-Message-State: AOJu0YzzUHK8VJ+t/VnmtY4e7I33VDbDfL8MzQ4DARqm3dLj3SKPQcfn
	1QZV0cFRooetQZY8VBN3xBc=
X-Google-Smtp-Source: AGHT+IEfqUbn9DvTGx+vhUSTfXLMGH/08Ozh5Pi/4JdEAmSSLW/uk8q7bigXoI3zoegSYEY7zSBWZQ==
X-Received: by 2002:a92:cda6:0:b0:34d:f90f:d42a with SMTP id g6-20020a92cda6000000b0034df90fd42amr204634ild.1.1698155247331;
        Tue, 24 Oct 2023 06:47:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1201:b0:348:84f9:eb8 with SMTP id
 a1-20020a056e02120100b0034884f90eb8ls74768ilq.1.-pod-prod-02-us; Tue, 24 Oct
 2023 06:47:26 -0700 (PDT)
X-Received: by 2002:a05:6602:14c5:b0:786:7100:72de with SMTP id b5-20020a05660214c500b00786710072demr16134833iow.16.1698155246672;
        Tue, 24 Oct 2023 06:47:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155246; cv=none;
        d=google.com; s=arc-20160816;
        b=F56c+YV8kaR3QfvZ0CXhA5uX86VYbPvwQ9MJs0xHGsBaQWYa8gCtvw+gXe7G4PMtxK
         1HWXDw+HRPZz5efXpx1JJ7sYUwM9ZbPE2ka1YKD9+WCk1+4GUhGYrov0OYws2eSWl9Kb
         UvQzF0D9fp91aeohqiOLpNgqXbNrIbM2KR/trenyYYKjA2Or6QihjAu/ZdAKh3FPD8om
         cheK0PPk+1abEOBhceRmPhGQGEsz6YFS28FsO+3CW07pFSlXnXq5bhKqdw4zm5YXd8Hy
         jaVc2PF5hjRj2PpZ9XeFxudGuxFDyordfcFp6xrR6OdbqKSN/Hvi//EdoOQAa8+GytnT
         aRDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=zhzOhwHQcxJuZ74GpFe9sYgSfMOEl4CWCuHOL/zyxyA=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=U6IY8fGGKt9wnuvLpH0P1sPrWSa8U/pIg/A+1kRVuWgddC3mlbc+wlxr0sJ67yaFUN
         0O8anLEvqCG6PvofBzhThTEqMkT2oKBkh1Mb97sEIPJtkJ93zMf4MchKHW2VVnOa0fYY
         ylZ2sMAmxP4Ftf6ShEAJ8zUHJNzH3HNZSx3Z3Wim4A1QLU4Ghtq+t1pO5dE21BZZpXdL
         Eg8Znmc5GEqUdqVqZPFGxlnQgA6a6DXWFcy6YnZE9ZDxAZHwycbaDkTl/UFpic1/wOwS
         q7iqSh7tygzaO5VBJHUbA8uL3cgrigqvM/M6RI4eXSHSSr+nhP2orc88KF62M+Fk1RcT
         GWaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zg2dRr1S;
       spf=pass (google.com: domain of 37co3zqykcziegd09x2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=37co3ZQYKCZIEGD09x2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id f10-20020a05660215ca00b0079f9c4f99absi735758iow.2.2023.10.24.06.47.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37co3zqykcziegd09x2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-5a7bbe0a453so55613417b3.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:26 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:42c9:0:b0:d9a:bce6:acf3 with SMTP id
 p192-20020a2542c9000000b00d9abce6acf3mr225566yba.0.1698155245951; Tue, 24 Oct
 2023 06:47:25 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:17 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-21-surenb@google.com>
Subject: [PATCH v2 20/39] mm: create new codetag references during page splitting
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
 header.i=@google.com header.s=20230601 header.b=zg2dRr1S;       spf=pass
 (google.com: domain of 37co3zqykcziegd09x2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=37co3ZQYKCZIEGD09x2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--surenb.bounces.google.com;
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
page should get its codetag. The original codetag is reused for these
pages but it's recorded as 0-byte allocation because original codetag
already accounts for the original high-order allocated page.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/pgalloc_tag.h | 30 ++++++++++++++++++++++++++++++
 mm/huge_memory.c            |  2 ++
 mm/page_alloc.c             |  2 ++
 3 files changed, 34 insertions(+)

diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
index a060c26eb449..0174aff5e871 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -62,11 +62,41 @@ static inline void pgalloc_tag_sub(struct page *page, unsigned int order)
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
+		/* New reference with 0 bytes accounted */
+		alloc_tag_add(codetag_ref_from_page_ext(page_ext), tag, 0);
+		page_ext = page_ext_next(page_ext);
+	}
+out:
+	page_ext_put(page_ext);
+}
+
 #else /* CONFIG_MEM_ALLOC_PROFILING */
 
 static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
 				   unsigned int order) {}
 static inline void pgalloc_tag_sub(struct page *page, unsigned int order) {}
+static inline void pgalloc_tag_split(struct page *page, unsigned int nr) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING */
 
diff --git a/mm/huge_memory.c b/mm/huge_memory.c
index 064fbd90822b..392b6907d875 100644
--- a/mm/huge_memory.c
+++ b/mm/huge_memory.c
@@ -37,6 +37,7 @@
 #include <linux/page_owner.h>
 #include <linux/sched/sysctl.h>
 #include <linux/memory-tiers.h>
+#include <linux/pgalloc_tag.h>
 
 #include <asm/tlb.h>
 #include <asm/pgalloc.h>
@@ -2545,6 +2546,7 @@ static void __split_huge_page(struct page *page, struct list_head *list,
 	/* Caller disabled irqs, so they are still disabled here */
 
 	split_page_owner(head, nr);
+	pgalloc_tag_split(head, nr);
 
 	/* See comment in __split_huge_page_tail() */
 	if (PageAnon(head)) {
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 63dc2f8c7901..c4f0cd127e14 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2540,6 +2540,7 @@ void split_page(struct page *page, unsigned int order)
 	for (i = 1; i < (1 << order); i++)
 		set_page_refcounted(page + i);
 	split_page_owner(page, 1 << order);
+	pgalloc_tag_split(page, 1 << order);
 	split_page_memcg(page, 1 << order);
 }
 EXPORT_SYMBOL_GPL(split_page);
@@ -4669,6 +4670,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
 		struct page *last = page + nr;
 
 		split_page_owner(page, 1 << order);
+		pgalloc_tag_split(page, 1 << order);
 		split_page_memcg(page, 1 << order);
 		while (page < --last)
 			set_page_refcounted(last);
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-21-surenb%40google.com.
