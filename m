Return-Path: <kasan-dev+bncBC7OD3FKWUERBKMMXKMAMGQEC6K6Q3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D0E15A6FAB
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:34 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id c7-20020a056e020bc700b002e59be6ce85sf9184491ilu.12
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896233; cv=pass;
        d=google.com; s=arc-20160816;
        b=d/xkfoZQkAfElKgWpJgKTjGplYCS+zcSKU7BcMwuWj27fjqBBW1HkskhO7UCDPpa2r
         VJVbuEQlFINJ6xoa29mH8Cw7Bl3TcBM7wjjOC75I7jkceRk5F3uHxsk4CJfQ0YOAMb8f
         3PW9xbRZqy/yglaYlNO+rJf6UO8D3RHwBB/9ywr+z0idLrQuEgHd6wxfnSkCVj7gUD2U
         /qYRmwVY9xMkh0oOheYSm5my0BhMHkWaBad1f5VufT6Um04r91b8WF/G9GIlaByYurbh
         M66O87zrRmIX74IbFAsgWgzU5sScjigFb3NJVAv/JyD5hGY9CHUQU/5gmUw98a+jfQm4
         T1aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=nrUCElBjSrjyeYOgUfVlnpavUvezSuOEoxdieRd/dYs=;
        b=azN/ySTF71YEdMHjpmJxiX6uZ3GHW8/xa/zi3CdSFqCa1JwFgKNTDRgM+rX7N4H2hn
         idk7YjXfTXCk+HkaQisSz7zLMMpwhU3m/QZQeOnBJEhX/zUWfMZDY4PB2VOVU0yauxXM
         4eADFzJ7ayoI6A2Rsyj7G6rRcdxoZxt/MjPzsXXQ2o1aLjj4rYXKYtX9lghCOHY9V99k
         iNhgrzFpvd/jCWXYdutrsovRya6pP9PWfzocTsqIGM0o0WdAghKw7pD1kFMDjmges7dF
         gJvKL6MA1m4aDxjTh8jkSJRY1/ULoIMpT0QABFCgRYy7SgS5mmPxC0N4QF6kVY5rFWx4
         Ce6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nwraOOA8;
       spf=pass (google.com: domain of 3kiyoywykcy09b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KIYOYwYKCY09B8v4sx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=nrUCElBjSrjyeYOgUfVlnpavUvezSuOEoxdieRd/dYs=;
        b=UtamyvX0y+FIySRJ/9pqD0l6pdqnCZyPRcw0pqUCjJDkoj+QEheW0dTQnoo3rBMnmk
         V0ZQBnUZaG9kCMAIWggWsH0LK+QnWe3E5m2sjAp+Yy/6n/RbipZTrYgvTSDwcPeCS+Vf
         LrWZVSaiag3wexWptF7Wd741ceacapmi10CDgSw9+5gHdCpd03dxfDzgBuqUZDhZ5Kbp
         9J3/V42CEuRSas85qme1b5SvV5IjvDp3/0sG0M1E7Ib/1n87WFg6dG0kKbR51jamI5pA
         TYfk0sqWVu5ubYthDSbg0y73Fdd0gsyCzPhNqrv0/Z+JDo1Ym7i9dBdiFOsIfG/0RjyO
         K+jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=nrUCElBjSrjyeYOgUfVlnpavUvezSuOEoxdieRd/dYs=;
        b=GcZrhDwYlQqiGRER8BWvfi3gD8XXRxlPI3z3FN26aWl9+BJMjI6svQ8lQeHjuKMtBf
         /syFm44ziouaUjUacJ215Yz55PwGyGZNTH41mnw2We11su1hXv3lSsTD0rTsZYHXDeVb
         nTH4FVKYXStQpjeKUksOZEya07rhuOzE/SCcR5wp7Ss/AjtVsn6AP3UdgF9MDRd+RkvA
         e1naoMvxJgGzULlzeEqxDmhIH4R21+zcZRco9kCR3eAbEvcO1wuilnbnfug7pv4O71ue
         CRWvOcdNy1USrXmOFj5qQRPVbdG8s4pvsfudmbcFyMj4I4UnyVH8lQwPbAEAbjDAAQfN
         O9Uw==
X-Gm-Message-State: ACgBeo2k7gkZxD072D/8DIviUgsVv0wPcB34rCKpThK2oju6o6rY/rYs
	gXESRmSteo5471xqUYb4QBY=
X-Google-Smtp-Source: AA6agR5TnQq6V+LKhzr24LGXEAZPzaGC/5p45kbtVETrvwkkNfSOVXmtPpUm77w24WLyJ/6KbzBMkg==
X-Received: by 2002:a05:6638:438f:b0:349:db38:9b0e with SMTP id bo15-20020a056638438f00b00349db389b0emr13190720jab.150.1661896233517;
        Tue, 30 Aug 2022 14:50:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:216d:b0:34c:dcb:a180 with SMTP id
 p13-20020a056638216d00b0034c0dcba180ls96530jak.4.-pod-prod-gmail; Tue, 30 Aug
 2022 14:50:33 -0700 (PDT)
X-Received: by 2002:a02:cc78:0:b0:342:7639:6d20 with SMTP id j24-20020a02cc78000000b0034276396d20mr13353066jaq.53.1661896233120;
        Tue, 30 Aug 2022 14:50:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896233; cv=none;
        d=google.com; s=arc-20160816;
        b=zZyJsS1T7zjNBZm1w+/LS4RAAfw/VnfHMpKSQSR+jzKiQH3OevpzrIMw9dmwswys9A
         SsjuFfTtox+szZGY8HC9vclW82BYB4o+coSYprch86qId2x3gIt26igK0SFXMKrXxyVO
         30bzhqo7VMbqutuUhADqjVmA37Axzep9IsMsctQDTCnKt6JPMgK5qAJdyHHNuqRA71EE
         eUo43a4IJS+ArD/maf4M07141mHDCF+02ipkRPJm2BKFHAnw3k3xEhxpuW/colOTPybt
         ihBl+BsNx5ocJCW4Oj2Myzh81jESajGOOU4XmaQymvU8ZdVETIRBQa5eK2zdbvhYDEbl
         1WSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=q8clZUHCVXNR9yzPtPwGAp/8c18i/nqvvNYb9V5EY+0=;
        b=oja4DV9vjQOa7GDTm3LMhz/VBEiWYk7WqhwFJTtvkAbMio5oT6wVlUffEDTZhAIFib
         0twf1HtWOss9BrOkyBkdkSfie/vnKu2IZZU0MEyUiCYreAPmxt3/i/SBy/SnaI0Oqgwp
         4fgNetuChcYTg0C8GX74RYIqvbH2HNxjfxr92t1cN65fz+iDZt1SZDK4hgvShdQ80ajh
         GjWWKJAIhRQJIQ+bEckof6il3pLEGsuKu0iHx+1a557N0C0Cm46Om9Jp5RDNPjHcURdo
         OEK2+zt0tgu7A7CRq4VDiQwKJbav61GijIqNpQKN66MEHOwKr672Bw76juMqSb1ZLidO
         NTnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nwraOOA8;
       spf=pass (google.com: domain of 3kiyoywykcy09b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KIYOYwYKCY09B8v4sx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id m8-20020a5e8d08000000b00684c9b5bc7asi687874ioj.1.2022.08.30.14.50.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kiyoywykcy09b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id p8-20020a258188000000b0069ca52d9f68so713353ybk.2
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:33 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a5b:2ce:0:b0:67a:6054:9eb0 with SMTP id
 h14-20020a5b02ce000000b0067a60549eb0mr13092972ybp.15.1661896232608; Tue, 30
 Aug 2022 14:50:32 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:15 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-27-surenb@google.com>
Subject: [RFC PATCH 26/30] bcache: Convert to lib/time_stats
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org, Coly Li <colyli@suse.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=nwraOOA8;       spf=pass
 (google.com: domain of 3kiyoywykcy09b8v4sx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KIYOYwYKCY09B8v4sx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--surenb.bounces.google.com;
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

From: Kent Overstreet <kent.overstreet@linux.dev>

This patch converts bcache to the new generic time_stats code
lib/time_stats.c. The new code is from bcachefs, and has some changes
from the version in bcache:

 - we now use ktime_get_ns(), not local_clock(). When the code was
   originally written multi processor systems that lacked synchronized
   TSCs were still common, and so local_clock() was much cheaper than
   sched_clock() (though not necessarily fully accurate, due to TSC
   drift). ktime_get_ns() should be cheap enough on all common hardware
   now, and more standard/correct.

 - time_stats are now exported in a single file in sysfs, which means we
   can improve the statistics we keep track of without changing all
   users. This also means we don't have to manually specify which units
   (ms, us, ns) a given time_stats should be printed in; that's handled
   dynamically.

 - There's a lazily-allocated percpu buffer, which now needs to be freed
   with time_stats_exit().

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Coly Li <colyli@suse.de>
---
 drivers/md/bcache/Kconfig  |  1 +
 drivers/md/bcache/bcache.h |  1 +
 drivers/md/bcache/bset.c   |  8 +++---
 drivers/md/bcache/bset.h   |  1 +
 drivers/md/bcache/btree.c  | 12 ++++----
 drivers/md/bcache/super.c  |  3 ++
 drivers/md/bcache/sysfs.c  | 43 ++++++++++++++++++++--------
 drivers/md/bcache/util.c   | 30 --------------------
 drivers/md/bcache/util.h   | 57 --------------------------------------
 9 files changed, 47 insertions(+), 109 deletions(-)

diff --git a/drivers/md/bcache/Kconfig b/drivers/md/bcache/Kconfig
index 529c9d04e9a4..8d165052e508 100644
--- a/drivers/md/bcache/Kconfig
+++ b/drivers/md/bcache/Kconfig
@@ -4,6 +4,7 @@ config BCACHE
 	tristate "Block device as cache"
 	select BLOCK_HOLDER_DEPRECATED if SYSFS
 	select CRC64
+	select TIME_STATS
 	help
 	Allows a block device to be used as cache for other devices; uses
 	a btree for indexing and the layout is optimized for SSDs.
diff --git a/drivers/md/bcache/bcache.h b/drivers/md/bcache/bcache.h
index 2acda9cea0f9..5100010a3897 100644
--- a/drivers/md/bcache/bcache.h
+++ b/drivers/md/bcache/bcache.h
@@ -185,6 +185,7 @@
 #include <linux/rbtree.h>
 #include <linux/rwsem.h>
 #include <linux/refcount.h>
+#include <linux/time_stats.h>
 #include <linux/types.h>
 #include <linux/workqueue.h>
 #include <linux/kthread.h>
diff --git a/drivers/md/bcache/bset.c b/drivers/md/bcache/bset.c
index 94d38e8a59b3..727e9b7aead4 100644
--- a/drivers/md/bcache/bset.c
+++ b/drivers/md/bcache/bset.c
@@ -1251,7 +1251,7 @@ static void __btree_sort(struct btree_keys *b, struct btree_iter *iter,
 		order = state->page_order;
 	}
 
-	start_time = local_clock();
+	start_time = ktime_get_ns();
 
 	btree_mergesort(b, out, iter, fixup, false);
 	b->nsets = start;
@@ -1286,7 +1286,7 @@ static void __btree_sort(struct btree_keys *b, struct btree_iter *iter,
 	bch_bset_build_written_tree(b);
 
 	if (!start)
-		bch_time_stats_update(&state->time, start_time);
+		time_stats_update(&state->time, start_time);
 }
 
 void bch_btree_sort_partial(struct btree_keys *b, unsigned int start,
@@ -1322,14 +1322,14 @@ void bch_btree_sort_and_fix_extents(struct btree_keys *b,
 void bch_btree_sort_into(struct btree_keys *b, struct btree_keys *new,
 			 struct bset_sort_state *state)
 {
-	uint64_t start_time = local_clock();
+	uint64_t start_time = ktime_get_ns();
 	struct btree_iter iter;
 
 	bch_btree_iter_init(b, &iter, NULL);
 
 	btree_mergesort(b, new->set->data, &iter, false, true);
 
-	bch_time_stats_update(&state->time, start_time);
+	time_stats_update(&state->time, start_time);
 
 	new->set->size = 0; // XXX: why?
 }
diff --git a/drivers/md/bcache/bset.h b/drivers/md/bcache/bset.h
index d795c84246b0..13e524ad7783 100644
--- a/drivers/md/bcache/bset.h
+++ b/drivers/md/bcache/bset.h
@@ -3,6 +3,7 @@
 #define _BCACHE_BSET_H
 
 #include <linux/kernel.h>
+#include <linux/time_stats.h>
 #include <linux/types.h>
 
 #include "bcache_ondisk.h"
diff --git a/drivers/md/bcache/btree.c b/drivers/md/bcache/btree.c
index 147c493a989a..abf543bc7551 100644
--- a/drivers/md/bcache/btree.c
+++ b/drivers/md/bcache/btree.c
@@ -242,7 +242,7 @@ static void btree_node_read_endio(struct bio *bio)
 
 static void bch_btree_node_read(struct btree *b)
 {
-	uint64_t start_time = local_clock();
+	uint64_t start_time = ktime_get_ns();
 	struct closure cl;
 	struct bio *bio;
 
@@ -270,7 +270,7 @@ static void bch_btree_node_read(struct btree *b)
 		goto err;
 
 	bch_btree_node_read_done(b);
-	bch_time_stats_update(&b->c->btree_read_time, start_time);
+	time_stats_update(&b->c->btree_read_time, start_time);
 
 	return;
 err:
@@ -1789,7 +1789,7 @@ static void bch_btree_gc(struct cache_set *c)
 	struct gc_stat stats;
 	struct closure writes;
 	struct btree_op op;
-	uint64_t start_time = local_clock();
+	uint64_t start_time = ktime_get_ns();
 
 	trace_bcache_gc_start(c);
 
@@ -1815,7 +1815,7 @@ static void bch_btree_gc(struct cache_set *c)
 	bch_btree_gc_finish(c);
 	wake_up_allocators(c);
 
-	bch_time_stats_update(&c->btree_gc_time, start_time);
+	time_stats_update(&c->btree_gc_time, start_time);
 
 	stats.key_bytes *= sizeof(uint64_t);
 	stats.data	<<= 9;
@@ -2191,7 +2191,7 @@ static int btree_split(struct btree *b, struct btree_op *op,
 {
 	bool split;
 	struct btree *n1, *n2 = NULL, *n3 = NULL;
-	uint64_t start_time = local_clock();
+	uint64_t start_time = ktime_get_ns();
 	struct closure cl;
 	struct keylist parent_keys;
 
@@ -2297,7 +2297,7 @@ static int btree_split(struct btree *b, struct btree_op *op,
 	btree_node_free(b);
 	rw_unlock(true, n1);
 
-	bch_time_stats_update(&b->c->btree_split_time, start_time);
+	time_stats_update(&b->c->btree_split_time, start_time);
 
 	return 0;
 err_free2:
diff --git a/drivers/md/bcache/super.c b/drivers/md/bcache/super.c
index ba3909bb6bea..26c8fa93b55d 100644
--- a/drivers/md/bcache/super.c
+++ b/drivers/md/bcache/super.c
@@ -1691,6 +1691,9 @@ static void cache_set_free(struct closure *cl)
 		kobject_put(&ca->kobj);
 	}
 
+	time_stats_exit(&c->btree_gc_time);
+	time_stats_exit(&c->btree_split_time);
+	time_stats_exit(&c->sort.time);
 
 	if (c->moving_gc_wq)
 		destroy_workqueue(c->moving_gc_wq);
diff --git a/drivers/md/bcache/sysfs.c b/drivers/md/bcache/sysfs.c
index c6f677059214..01eec5877cd7 100644
--- a/drivers/md/bcache/sysfs.c
+++ b/drivers/md/bcache/sysfs.c
@@ -16,6 +16,7 @@
 #include <linux/blkdev.h>
 #include <linux/sort.h>
 #include <linux/sched/clock.h>
+#include <linux/seq_buf.h>
 
 extern bool bcache_is_reboot;
 
@@ -79,10 +80,10 @@ read_attribute(active_journal_entries);
 read_attribute(backing_dev_name);
 read_attribute(backing_dev_uuid);
 
-sysfs_time_stats_attribute(btree_gc,	sec, ms);
-sysfs_time_stats_attribute(btree_split, sec, us);
-sysfs_time_stats_attribute(btree_sort,	ms,  us);
-sysfs_time_stats_attribute(btree_read,	ms,  us);
+read_attribute(btree_gc_time);
+read_attribute(btree_split_time);
+read_attribute(btree_sort_time);
+read_attribute(btree_read_time);
 
 read_attribute(btree_nodes);
 read_attribute(btree_used_percent);
@@ -731,6 +732,9 @@ static unsigned int bch_average_key_size(struct cache_set *c)
 SHOW(__bch_cache_set)
 {
 	struct cache_set *c = container_of(kobj, struct cache_set, kobj);
+	struct seq_buf s;
+
+	seq_buf_init(&s, buf, PAGE_SIZE);
 
 	sysfs_print(synchronous,		CACHE_SYNC(&c->cache->sb));
 	sysfs_print(journal_delay_ms,		c->journal_delay_ms);
@@ -743,10 +747,25 @@ SHOW(__bch_cache_set)
 	sysfs_print(btree_cache_max_chain,	bch_cache_max_chain(c));
 	sysfs_print(cache_available_percent,	100 - c->gc_stats.in_use);
 
-	sysfs_print_time_stats(&c->btree_gc_time,	btree_gc, sec, ms);
-	sysfs_print_time_stats(&c->btree_split_time,	btree_split, sec, us);
-	sysfs_print_time_stats(&c->sort.time,		btree_sort, ms, us);
-	sysfs_print_time_stats(&c->btree_read_time,	btree_read, ms, us);
+	if (attr == &sysfs_btree_gc_time) {
+		time_stats_to_text(&s, &c->btree_gc_time);
+		return s.len;
+	}
+
+	if (attr == &sysfs_btree_split_time) {
+		time_stats_to_text(&s, &c->btree_split_time);
+		return s.len;
+	}
+
+	if (attr == &sysfs_btree_sort_time) {
+		time_stats_to_text(&s, &c->sort.time);
+		return s.len;
+	}
+
+	if (attr == &sysfs_btree_read_time) {
+		time_stats_to_text(&s, &c->btree_read_time);
+		return s.len;
+	}
 
 	sysfs_print(btree_used_percent,	bch_btree_used(c));
 	sysfs_print(btree_nodes,	c->gc_stats.nodes);
@@ -988,10 +1007,10 @@ KTYPE(bch_cache_set);
 static struct attribute *bch_cache_set_internal_attrs[] = {
 	&sysfs_active_journal_entries,
 
-	sysfs_time_stats_attribute_list(btree_gc, sec, ms)
-	sysfs_time_stats_attribute_list(btree_split, sec, us)
-	sysfs_time_stats_attribute_list(btree_sort, ms, us)
-	sysfs_time_stats_attribute_list(btree_read, ms, us)
+	&sysfs_btree_gc_time,
+	&sysfs_btree_split_time,
+	&sysfs_btree_sort_time,
+	&sysfs_btree_read_time,
 
 	&sysfs_btree_nodes,
 	&sysfs_btree_used_percent,
diff --git a/drivers/md/bcache/util.c b/drivers/md/bcache/util.c
index ae380bc3992e..95282bf0f9a7 100644
--- a/drivers/md/bcache/util.c
+++ b/drivers/md/bcache/util.c
@@ -160,36 +160,6 @@ int bch_parse_uuid(const char *s, char *uuid)
 	return i;
 }
 
-void bch_time_stats_update(struct time_stats *stats, uint64_t start_time)
-{
-	uint64_t now, duration, last;
-
-	spin_lock(&stats->lock);
-
-	now		= local_clock();
-	duration	= time_after64(now, start_time)
-		? now - start_time : 0;
-	last		= time_after64(now, stats->last)
-		? now - stats->last : 0;
-
-	stats->max_duration = max(stats->max_duration, duration);
-
-	if (stats->last) {
-		ewma_add(stats->average_duration, duration, 8, 8);
-
-		if (stats->average_frequency)
-			ewma_add(stats->average_frequency, last, 8, 8);
-		else
-			stats->average_frequency  = last << 8;
-	} else {
-		stats->average_duration  = duration << 8;
-	}
-
-	stats->last = now ?: 1;
-
-	spin_unlock(&stats->lock);
-}
-
 /**
  * bch_next_delay() - update ratelimiting statistics and calculate next delay
  * @d: the struct bch_ratelimit to update
diff --git a/drivers/md/bcache/util.h b/drivers/md/bcache/util.h
index 6f3cb7c92130..1e1bdbae9593 100644
--- a/drivers/md/bcache/util.h
+++ b/drivers/md/bcache/util.h
@@ -345,68 +345,11 @@ ssize_t bch_hprint(char *buf, int64_t v);
 bool bch_is_zero(const char *p, size_t n);
 int bch_parse_uuid(const char *s, char *uuid);
 
-struct time_stats {
-	spinlock_t	lock;
-	/*
-	 * all fields are in nanoseconds, averages are ewmas stored left shifted
-	 * by 8
-	 */
-	uint64_t	max_duration;
-	uint64_t	average_duration;
-	uint64_t	average_frequency;
-	uint64_t	last;
-};
-
-void bch_time_stats_update(struct time_stats *stats, uint64_t time);
-
 static inline unsigned int local_clock_us(void)
 {
 	return local_clock() >> 10;
 }
 
-#define NSEC_PER_ns			1L
-#define NSEC_PER_us			NSEC_PER_USEC
-#define NSEC_PER_ms			NSEC_PER_MSEC
-#define NSEC_PER_sec			NSEC_PER_SEC
-
-#define __print_time_stat(stats, name, stat, units)			\
-	sysfs_print(name ## _ ## stat ## _ ## units,			\
-		    div_u64((stats)->stat >> 8, NSEC_PER_ ## units))
-
-#define sysfs_print_time_stats(stats, name,				\
-			       frequency_units,				\
-			       duration_units)				\
-do {									\
-	__print_time_stat(stats, name,					\
-			  average_frequency,	frequency_units);	\
-	__print_time_stat(stats, name,					\
-			  average_duration,	duration_units);	\
-	sysfs_print(name ## _ ##max_duration ## _ ## duration_units,	\
-			div_u64((stats)->max_duration,			\
-				NSEC_PER_ ## duration_units));		\
-									\
-	sysfs_print(name ## _last_ ## frequency_units, (stats)->last	\
-		    ? div_s64(local_clock() - (stats)->last,		\
-			      NSEC_PER_ ## frequency_units)		\
-		    : -1LL);						\
-} while (0)
-
-#define sysfs_time_stats_attribute(name,				\
-				   frequency_units,			\
-				   duration_units)			\
-read_attribute(name ## _average_frequency_ ## frequency_units);		\
-read_attribute(name ## _average_duration_ ## duration_units);		\
-read_attribute(name ## _max_duration_ ## duration_units);		\
-read_attribute(name ## _last_ ## frequency_units)
-
-#define sysfs_time_stats_attribute_list(name,				\
-					frequency_units,		\
-					duration_units)			\
-&sysfs_ ## name ## _average_frequency_ ## frequency_units,		\
-&sysfs_ ## name ## _average_duration_ ## duration_units,		\
-&sysfs_ ## name ## _max_duration_ ## duration_units,			\
-&sysfs_ ## name ## _last_ ## frequency_units,
-
 #define ewma_add(ewma, val, weight, factor)				\
 ({									\
 	(ewma) *= (weight) - 1;						\
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-27-surenb%40google.com.
