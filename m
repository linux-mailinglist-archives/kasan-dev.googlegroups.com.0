Return-Path: <kasan-dev+bncBC7OD3FKWUERBF4MXKMAMGQEGEH7C6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D0865A6F9B
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:16 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id i13-20020a056e02152d00b002e97839ff00sf9222675ilu.15
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896215; cv=pass;
        d=google.com; s=arc-20160816;
        b=ga5J68RcrQDSAWlQWKPm3gzzRAAA+5S514oPD7vo6Vcb+cErvNfoEPiTRehyBJz0A2
         hG7mnj1RbprRmuvyc98osr5QBhyaL78GpdD+yn4CDj/6wqePuGie/VjZetZRWsbMJOtT
         /8ykd7rIy5OKBDDU6MRDbZx56M78/sAU7T2yvS8P8/QnBAG26ltRO+KHeiccgOioI5fK
         Y/mTj1025rLg/Ey5aVKztdaZyfFR2mZl7CgSJ0dhGHdINVwEAVECOtfLhVxU+UofpSYE
         eoUv5p+MP6AehEOiMviP3OxLhyICBxOcuUSU29dza0i4j6tYKzVMHYahhdf/OfSorICd
         xGfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=NOV7q57NMUVNf1KFUT9RL6DRLtTJQc+fxtCjebHVp1A=;
        b=s88Mt/4adWSAtnvTAQE9g2UgcWxzZ1BPzEcMW342m6u3WaujGjKTClfvcSZIGapJE8
         veWSZOEn6ODhBSk+tOPgK0583hyCtCEHUIyieJ0rxY1BNkCNLl8QvP07Dy9uN8rg/oyb
         mzvdOlUvrl902BdR0D2vKGU8I7kxy1+nhtrAt/2z0H/SpQzPL05hjUkrvUo4sWSYrUry
         x4yV4jeZOdd1iU0UKlDwLd0TOwgmTEr9Fb1GAEzqGT+iFtllo7xtYy1emkNzKpFm8xde
         99bm1U7jEeoX6GeBuIMAZzTyJ1IiTwOYfVuHgTK24uo7YwsG7OzB1HlkWqUQ7rE4KiI0
         T9tA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OXRgptnZ;
       spf=pass (google.com: domain of 3foyoywykcxsrtqdmafnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3FoYOYwYKCXsrtqdmafnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=NOV7q57NMUVNf1KFUT9RL6DRLtTJQc+fxtCjebHVp1A=;
        b=i1o+EYTfPw21Fz+ugB6fHxmyfm6ygyLCikLB1/85UGfGF8lMV+DZvjDhdgdIUlD5Ls
         pYrRL0e+k+Wmbty2Nb11xPWvKrmutbW2y/3gQR2wHtbYOwpgTa86+PUj/h2JSyZjrAK/
         p9Pez9SAH8Abfe9g+5EABo1b+umpFTiC42hK+xnLucCWwpHaXE2kMiUFtoMD5jQ70Pm8
         Qe5DThU9TDDI67n0e3JCQiNEjRqO6oGPtHjDxvLsJvWcddL2Itm9Oy5kd7M5HqRCi/yy
         OYjGhUR7eYhtUgQWFqBZghQ/SqLbx8CkjEOMRffielyNw5BDAklMu55VP3XNZPvs2umc
         UYTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=NOV7q57NMUVNf1KFUT9RL6DRLtTJQc+fxtCjebHVp1A=;
        b=ty4czAkbTrAkVtw29lxjEtBNvejLinG482I1UbFKtEtQ3fQ7dv0M9UrgYD6bkePoRh
         bGkjq1pS/kLJCaSj1clTNc12HvFE3LCpQWlu3nfMZnGuskIHRyQyxOvDK7qvQIuWHuUb
         5O+8xjGflUWeo44OQiQxK2L1AGzP59zzNymq166UldIjqFHK33hRGW1nVnn4FT6Xhoyf
         e50g+XTcNRUGcn3Jrk1UUp3d9P6l9uG+u15BdlVnHBL+lAVyXiu4mdNh+ISg2Z6yk1tj
         xUx+KCf3tqCFEzSJ7V7kY63Cpfk1+OwjvtAxykqNj9gB3xovixDqj9hmtsYQFT5xfk+5
         r2bA==
X-Gm-Message-State: ACgBeo1BIygAsmxQXZFxnlC44AxV13F/KVbMpdnKnc8Flj/wQjmeEddg
	ro5ovukBoqnXT/gcZ81Fmdk=
X-Google-Smtp-Source: AA6agR57KQcYGVx+rdZNJn1bbnMF7DPH/hgJXmgoWykXuTbdWci0w5UUhaIKLjokUdIVIzyVz2wYPg==
X-Received: by 2002:a05:6e02:1805:b0:2ea:1106:e0eb with SMTP id a5-20020a056e02180500b002ea1106e0ebmr13168861ilv.75.1661896215252;
        Tue, 30 Aug 2022 14:50:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:848d:0:b0:34a:4271:878f with SMTP id f13-20020a02848d000000b0034a4271878fls1748178jai.11.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:50:14 -0700 (PDT)
X-Received: by 2002:a05:6638:2394:b0:34a:2fb2:143b with SMTP id q20-20020a056638239400b0034a2fb2143bmr9779522jat.24.1661896214797;
        Tue, 30 Aug 2022 14:50:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896214; cv=none;
        d=google.com; s=arc-20160816;
        b=jSaulPn8DqRkuLEAUN2SQlrBkfw2Ei4awj0c5Vd4uKsJxkvQ1QHNngQMuE5tIsxn05
         SddV5H/DCn/2Rnf2BpALMU/tQaOZJ2vQRZBTGZLSMXFujrmcbHALpLa82E8wO0V/UdJ8
         nS59am7OoUMEc0LtngvOLMvS2g+r0dvnh7DxnDoy1AgExSFOFzgl4VW+Zb3+nPwRqAL8
         NkXSGpUKlK4bDctPMDjxTMz5svL1L9GOffeRCIvx/vKoAem8m7IqKWC/0CG8OxsTvfcL
         bmr57JHaQpvsQ2I8WRAK/iAAU79/CuJQpfk58a6qXq12maVjBo9TBDCHF1wqrxdeTe6g
         lp7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=vjjGk6pymrjMSyrfbdxQ3/p6O8Kus1ISFMk96O5o39I=;
        b=KVs8vMS/aTNOwV6bUMOuX9cN3PnXYdnwYkpO458QqJjUHBefbG870vRo3Tf/Wb6j4s
         Owm4pVrP+vqUdrKCqlhRVuoPAEEsoTsuk+MhfndESIcuVkTod0lPozLXXzk/eEtPoxxs
         Wz6rcbLEYZXkDCgnEMbiJst/d6hOrnXIeC7J3r41SRBZI6sNrsQ/mavUgWMNH8DymeOb
         Ix+Acd6U4ofk99jnNtqR+n9omNnazXUW8uOqigVFwcq97/qRCKOv3RJ7F6Nx7Q4uHr9A
         UGlEfzTTMyENrQ8WawIK1atXnW97IRzWKbDhmyC0J6+j0HuFzx7yNtervo+fsHlQALyb
         iQMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OXRgptnZ;
       spf=pass (google.com: domain of 3foyoywykcxsrtqdmafnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3FoYOYwYKCXsrtqdmafnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id g9-20020a05660226c900b00688fefa6d1dsi654134ioo.2.2022.08.30.14.50.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3foyoywykcxsrtqdmafnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id f12-20020a25b6cc000000b0069a9e36de26so717059ybm.16
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:14 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a81:f47:0:b0:31f:434b:5ee with SMTP id
 68-20020a810f47000000b0031f434b05eemr15734874ywp.383.1661896214287; Tue, 30
 Aug 2022 14:50:14 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:08 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-20-surenb@google.com>
Subject: [RFC PATCH 19/30] move stack capture functionality into a separate
 function for reuse
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
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=OXRgptnZ;       spf=pass
 (google.com: domain of 3foyoywykcxsrtqdmafnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3FoYOYwYKCXsrtqdmafnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com;
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

Make save_stack() function part of stackdepot API to be used outside of
page_owner. Also rename task_struct's in_page_owner to in_capture_stack
flag to better convey the wider use of this flag.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/sched.h      |  6 ++--
 include/linux/stackdepot.h |  3 ++
 lib/stackdepot.c           | 68 ++++++++++++++++++++++++++++++++++++++
 mm/page_owner.c            | 52 ++---------------------------
 4 files changed, 77 insertions(+), 52 deletions(-)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index e7b2f8a5c711..d06cad6c14bd 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -930,9 +930,9 @@ struct task_struct {
 	/* Stalled due to lack of memory */
 	unsigned			in_memstall:1;
 #endif
-#ifdef CONFIG_PAGE_OWNER
-	/* Used by page_owner=on to detect recursion in page tracking. */
-	unsigned			in_page_owner:1;
+#ifdef CONFIG_STACKDEPOT
+	/* Used by stack_depot_capture_stack to detect recursion. */
+	unsigned			in_capture_stack:1;
 #endif
 #ifdef CONFIG_EVENTFD
 	/* Recursion prevention for eventfd_signal() */
diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index bc2797955de9..8dc9fdb2c4dd 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -64,4 +64,7 @@ int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 
 void stack_depot_print(depot_stack_handle_t stack);
 
+bool stack_depot_capture_init(void);
+depot_stack_handle_t stack_depot_capture_stack(gfp_t flags);
+
 #endif
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index e73fda23388d..c8615bd6dc25 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -514,3 +514,71 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 	return __stack_depot_save(entries, nr_entries, alloc_flags, true);
 }
 EXPORT_SYMBOL_GPL(stack_depot_save);
+
+static depot_stack_handle_t recursion_handle;
+static depot_stack_handle_t failure_handle;
+
+static __always_inline depot_stack_handle_t create_custom_stack(void)
+{
+	unsigned long entries[4];
+	unsigned int nr_entries;
+
+	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
+	return stack_depot_save(entries, nr_entries, GFP_KERNEL);
+}
+
+static noinline void register_recursion_stack(void)
+{
+	recursion_handle = create_custom_stack();
+}
+
+static noinline void register_failure_stack(void)
+{
+	failure_handle = create_custom_stack();
+}
+
+bool stack_depot_capture_init(void)
+{
+	static DEFINE_MUTEX(stack_depot_capture_init_mutex);
+	static bool utility_stacks_ready;
+
+	mutex_lock(&stack_depot_capture_init_mutex);
+	if (!utility_stacks_ready) {
+		register_recursion_stack();
+		register_failure_stack();
+		utility_stacks_ready = true;
+	}
+	mutex_unlock(&stack_depot_capture_init_mutex);
+
+	return utility_stacks_ready;
+}
+
+/* TODO: teach stack_depot_capture_stack to use off stack temporal storage */
+#define CAPTURE_STACK_DEPTH (16)
+
+depot_stack_handle_t stack_depot_capture_stack(gfp_t flags)
+{
+	unsigned long entries[CAPTURE_STACK_DEPTH];
+	depot_stack_handle_t handle;
+	unsigned int nr_entries;
+
+	/*
+	 * Avoid recursion.
+	 *
+	 * Sometimes page metadata allocation tracking requires more
+	 * memory to be allocated:
+	 * - when new stack trace is saved to stack depot
+	 * - when backtrace itself is calculated (ia64)
+	 */
+	if (current->in_capture_stack)
+		return recursion_handle;
+	current->in_capture_stack = 1;
+
+	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 2);
+	handle = stack_depot_save(entries, nr_entries, flags);
+	if (!handle)
+		handle = failure_handle;
+
+	current->in_capture_stack = 0;
+	return handle;
+}
diff --git a/mm/page_owner.c b/mm/page_owner.c
index fd4af1ad34b8..c3173e34a779 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -15,12 +15,6 @@
 
 #include "internal.h"
 
-/*
- * TODO: teach PAGE_OWNER_STACK_DEPTH (__dump_page_owner and save_stack)
- * to use off stack temporal storage
- */
-#define PAGE_OWNER_STACK_DEPTH (16)
-
 struct page_owner {
 	unsigned short order;
 	short last_migrate_reason;
@@ -37,8 +31,6 @@ struct page_owner {
 static bool page_owner_enabled __initdata;
 DEFINE_STATIC_KEY_FALSE(page_owner_inited);
 
-static depot_stack_handle_t dummy_handle;
-static depot_stack_handle_t failure_handle;
 static depot_stack_handle_t early_handle;
 
 static void init_early_allocated_pages(void);
@@ -68,16 +60,6 @@ static __always_inline depot_stack_handle_t create_dummy_stack(void)
 	return stack_depot_save(entries, nr_entries, GFP_KERNEL);
 }
 
-static noinline void register_dummy_stack(void)
-{
-	dummy_handle = create_dummy_stack();
-}
-
-static noinline void register_failure_stack(void)
-{
-	failure_handle = create_dummy_stack();
-}
-
 static noinline void register_early_stack(void)
 {
 	early_handle = create_dummy_stack();
@@ -88,8 +70,7 @@ static __init void init_page_owner(void)
 	if (!page_owner_enabled)
 		return;
 
-	register_dummy_stack();
-	register_failure_stack();
+	stack_depot_capture_init();
 	register_early_stack();
 	static_branch_enable(&page_owner_inited);
 	init_early_allocated_pages();
@@ -106,33 +87,6 @@ static inline struct page_owner *get_page_owner(struct page_ext *page_ext)
 	return (void *)page_ext + page_owner_ops.offset;
 }
 
-static noinline depot_stack_handle_t save_stack(gfp_t flags)
-{
-	unsigned long entries[PAGE_OWNER_STACK_DEPTH];
-	depot_stack_handle_t handle;
-	unsigned int nr_entries;
-
-	/*
-	 * Avoid recursion.
-	 *
-	 * Sometimes page metadata allocation tracking requires more
-	 * memory to be allocated:
-	 * - when new stack trace is saved to stack depot
-	 * - when backtrace itself is calculated (ia64)
-	 */
-	if (current->in_page_owner)
-		return dummy_handle;
-	current->in_page_owner = 1;
-
-	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 2);
-	handle = stack_depot_save(entries, nr_entries, flags);
-	if (!handle)
-		handle = failure_handle;
-
-	current->in_page_owner = 0;
-	return handle;
-}
-
 void __reset_page_owner(struct page *page, unsigned short order)
 {
 	int i;
@@ -145,7 +99,7 @@ void __reset_page_owner(struct page *page, unsigned short order)
 	if (unlikely(!page_ext))
 		return;
 
-	handle = save_stack(GFP_NOWAIT | __GFP_NOWARN);
+	handle = stack_depot_capture_stack(GFP_NOWAIT | __GFP_NOWARN);
 	for (i = 0; i < (1 << order); i++) {
 		__clear_bit(PAGE_EXT_OWNER_ALLOCATED, &page_ext->flags);
 		page_owner = get_page_owner(page_ext);
@@ -189,7 +143,7 @@ noinline void __set_page_owner(struct page *page, unsigned short order,
 	if (unlikely(!page_ext))
 		return;
 
-	handle = save_stack(gfp_mask);
+	handle = stack_depot_capture_stack(gfp_mask);
 	__set_page_owner_handle(page_ext, handle, order, gfp_mask);
 }
 
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-20-surenb%40google.com.
