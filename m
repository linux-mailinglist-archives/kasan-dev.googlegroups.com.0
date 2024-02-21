Return-Path: <kasan-dev+bncBC7OD3FKWUERB5FD3GXAMGQEV6NNAEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id C944185E789
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:41 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-5cec8bc5c66sf5282657a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544500; cv=pass;
        d=google.com; s=arc-20160816;
        b=aRU77kX7Xa39D677Ax2b/Z93MgKyzan+Nw/OY+ohwGL3sn73YI1zGqLAERZfNxJeaw
         hwdF5V5aUZehNH4rHkjh+gZrx5YHo2h8tyt5l6Tm+D4xcTbtDivkI4z7KYs5EZdKPPWR
         RfUoTJHAdIccVXU8d6TzEvkT466CHK8FNFIZuYLfyk3O2Nh5USeIekNRlxbP6J6a3PD+
         CE/38F/dohHGdNOfY7kFHXh+HYtS+6UAHKb4Vwfc83Imy5OfPzSKRXzIhUnAITP0ujl8
         eMzAAE8FlWueJXph4wAw5hfrSts5UXXVOIRGmzWXj+fLkFtmPaNjERndonnd5wgGzigw
         nQ/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=bBMXxmQrvSWNpGAMF3TjC9WVQI4Pbmy7j0UWVN6Yj7Q=;
        fh=65fqMI+ITVLytFynAQTxJXgkW5bDcZUueK3pnkbMKT4=;
        b=tpZbg0rzXigmvohNH/M94YroToghxwbdi6TurV2YM0KMPsNnw4DRKGUwY2h/xzYvwM
         4vQthAZ1DZwMqwbY2Tp6L7bLyETAVa43Vtby5c2BRV0qOjmKfV7hN41L1HGDSZcMTMUX
         xPrPU5BCYBxVogmpGB2FvorCA/Zoj6ZvSaLDXmjuFismQ4gosWIFIAJ1rzPmtbIFMp0d
         qQQnAd2pBt6Q2Y1gOws/ts6yksflpppi72ppNh3mnZ/Df3c3Bow5nHsPEIUf8n/qIaoQ
         C1s13N+MfAKG+JS0tRn6MwocqRrDvi6LLRRXpsOXURQAwPyPK0QPrzucebOCLYAFyCK4
         coDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zhSM+H6+;
       spf=pass (google.com: domain of 38lhwzqykcsutvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=38lHWZQYKCSUTVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544500; x=1709149300; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bBMXxmQrvSWNpGAMF3TjC9WVQI4Pbmy7j0UWVN6Yj7Q=;
        b=kFoBwvqYmoCvBgr8h3ks182qCJBagOil0JTrgfzHxZbh4sn/K0nPbl5Lyc58ElDjZ2
         lxba3qcZ+7pG4kH3al2+OuK/cL2ua/2EAem8upWs/2VrSJnSwKsuGbwHEmOrDbR2ZOc3
         BoqZ8LzJJDoumFNVgtd3C7O+hzQwNssdv43yMAhJrDHKJa/8C2HMNLKnCdT+YudIOU5Q
         /jdRf7yx/A2j3nGcOL8dcEYb9anXnMleUJz7nerLzGvK3NQCK6eYDiTrwmgVfS9q1HVW
         DvzD1A6+6Pwwx+XwVz3qTBuw9W9Cdqt1S+HWoHQ77jD/rn0yrWbJtGZ8YGf0rLNKV5FM
         0SBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544500; x=1709149300;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bBMXxmQrvSWNpGAMF3TjC9WVQI4Pbmy7j0UWVN6Yj7Q=;
        b=nI0pfg2MQiuDEgxH5iEXdV2SjLTW+M6HAAf7NJDiEiMoDlVegTcHnPqaAfV1H9rJLz
         zY/beP4hw4YJNpmbM3+yY9ktEog2UKLDw0HM1k6UEnsN2RIR/63/yAjJ+a7Jmxm7WrKx
         fmQ4cuwXN46J238XNcAp2Jwh9kw0dr23/W/EljqbM/AA0kn5GglVeoIjmXKmu76k3E5i
         lndKLJgbQIPbt8/7pruAk+Y5KERm4X3Ga33S9cxv0OsEZwQg/nH96UCbo7JmwW92TKcK
         F3eK6yQ3NsSan1NYiO8qEZ+orYzcv4vZsmIktqUxeRpQQFNNcYl7saq3u0KA5WvtvtVG
         Zudg==
X-Forwarded-Encrypted: i=2; AJvYcCWdWXShSQYd1g1zylGkS11Ct9UHAaUwpMSHqUmyq2UogHgg6Hj6eZ60WPieh/6E0j11vlTte/JqETV3s0t68G9RIDo3kKwZIQ==
X-Gm-Message-State: AOJu0YxOMLXiWQA9gb+mOcVyfXllRou1ZQ/0ShNoA7WW2go3fOLrONkQ
	U+I9q9PI527JSzNpmCS4QYg9VJDa2loDTB4TovzatF7158cewE6c
X-Google-Smtp-Source: AGHT+IHwzgMF3bIqd1SeR3qRG32eAtnQNSj1zTnmg8/QpuhjqyaRMKTChxhx1qYU4uii6Bz0EVUCQw==
X-Received: by 2002:a05:6a21:1394:b0:1a0:cd54:6d9e with SMTP id oa20-20020a056a21139400b001a0cd546d9emr1191692pzb.24.1708544500223;
        Wed, 21 Feb 2024 11:41:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3309:b0:6e0:f00b:3ffe with SMTP id
 cq9-20020a056a00330900b006e0f00b3ffels2431623pfb.0.-pod-prod-01-us; Wed, 21
 Feb 2024 11:41:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWkig5IoGgJYg/SGwJtfv0qFBvjyIV3jhv5TVXhOq2GvV8ZUiku5Wjfg0jYdDxB2cDXtY+8D7l51yHKhdrjXxiDNhZBjYuQDTL6aQ==
X-Received: by 2002:a05:6a00:9386:b0:6e4:6793:5c6a with SMTP id ka6-20020a056a00938600b006e467935c6amr9736068pfb.7.1708544499220;
        Wed, 21 Feb 2024 11:41:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544499; cv=none;
        d=google.com; s=arc-20160816;
        b=yn5fLd/PLSWwWL7+NPjdNAAmKdMq7I0nMxNEwacqmcaVTjrwgp6TTJRbKFnOBCbAf9
         1Z8fpIeuafUh4qaKoFTZ8DOYWblzasOB0P5VoUqTu5IIijgVzhsH2wZlZorRtfBWxZvi
         09qg16e7HlWL6MAXApAEjAcOxvWHNG6PlM/I0YVJimACbnTdMd/Ozc2/NSrAMshUPWuT
         520ACf6tT21H3RYbyvbQcUGqn2U27pnb9XEN2mlD07LeATdgaq72ABWDDtNr4Zbci09b
         R+aXaQB4T1glJNCGjGGdd289LTpN+dlPbxTAkN8X2gAEg5TIIVLKLPxn0iQOfoj304wJ
         fZVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=1hWNqJFIgMmzuIRMCt7lzLBdngxXaEaZ9g59MUlptRo=;
        fh=IkDYvkv6hisc9QWHiOKKBv2xQdme6PZJRahWmVIJCrs=;
        b=xmFoGucpcwStxzh9G/13dn99yDHymOvCCUNlodq+eYRnzROkcBrpdNZljM2pQP3nmI
         8ldTr/ynohncVqYTgPM0P4KoRNASRWgPI6epJF0YYIiP1B+9FI+cF2nUKaxozKhPD8CN
         8vcv8OfLJrEvpEjl+vDMuo6yY6pch4tfcV0MwKf8u2NhiCSGklY5si6cF+gTGnFJNiio
         Z85Nj2YLfJi71IjIiOUBzKo0wr5+ik02lrQ8f/zU9HuIp17PU0VDSTTapDccnYzme5Lr
         sB93jPcgr/fph5vI3UQvtdOppwdgLJoI4m2ika8u+5Fdi1ZcnvZ/r/b+p8kgbaXpMXIt
         mmbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zhSM+H6+;
       spf=pass (google.com: domain of 38lhwzqykcsutvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=38lHWZQYKCSUTVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id s38-20020a056a0017a600b006e48338a3c0si257651pfg.6.2024.02.21.11.41.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 38lhwzqykcsutvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dce775fa8adso2077434276.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:39 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXCyNHv3Bcxy6kqDHD5TY4B/fwvr9rlPwEf5GQzkp47yvjov905Kwz5mz+nH6GczFlHMLa5isFge2jmUSAIUNk1aM09mhxUbdRMqg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:6902:18d6:b0:dc6:dfc6:4207 with SMTP id
 ck22-20020a05690218d600b00dc6dfc64207mr68537ybb.10.1708544498016; Wed, 21 Feb
 2024 11:41:38 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:32 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-20-surenb@google.com>
Subject: [PATCH v4 19/36] mm: create new codetag references during page splitting
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
 header.i=@google.com header.s=20230601 header.b=zhSM+H6+;       spf=pass
 (google.com: domain of 38lhwzqykcsutvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=38lHWZQYKCSUTVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
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
index b49ab955300f..9e6ad8e0e4aa 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -67,11 +67,41 @@ static inline void pgalloc_tag_sub(struct page *page, unsigned int order)
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
 				   unsigned int order) {}
 static inline void pgalloc_tag_sub(struct page *page, unsigned int order) {}
+static inline void pgalloc_tag_split(struct page *page, unsigned int nr) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING */
 
diff --git a/mm/huge_memory.c b/mm/huge_memory.c
index 94c958f7ebb5..86daae671319 100644
--- a/mm/huge_memory.c
+++ b/mm/huge_memory.c
@@ -38,6 +38,7 @@
 #include <linux/sched/sysctl.h>
 #include <linux/memory-tiers.h>
 #include <linux/compat.h>
+#include <linux/pgalloc_tag.h>
 
 #include <asm/tlb.h>
 #include <asm/pgalloc.h>
@@ -2899,6 +2900,7 @@ static void __split_huge_page(struct page *page, struct list_head *list,
 	/* Caller disabled irqs, so they are still disabled here */
 
 	split_page_owner(head, nr);
+	pgalloc_tag_split(head, nr);
 
 	/* See comment in __split_huge_page_tail() */
 	if (PageAnon(head)) {
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 58c0e8b948a4..4bc5b4720fee 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2621,6 +2621,7 @@ void split_page(struct page *page, unsigned int order)
 	for (i = 1; i < (1 << order); i++)
 		set_page_refcounted(page + i);
 	split_page_owner(page, 1 << order);
+	pgalloc_tag_split(page, 1 << order);
 	split_page_memcg(page, 1 << order);
 }
 EXPORT_SYMBOL_GPL(split_page);
@@ -4806,6 +4807,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
 		struct page *last = page + nr;
 
 		split_page_owner(page, 1 << order);
+		pgalloc_tag_split(page, 1 << order);
 		split_page_memcg(page, 1 << order);
 		while (page < --last)
 			set_page_refcounted(last);
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-20-surenb%40google.com.
