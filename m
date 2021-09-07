Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMHH3WEQMGQEFEXOSBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AC54402A83
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Sep 2021 16:14:10 +0200 (CEST)
Received: by mail-ua1-x939.google.com with SMTP id f5-20020ab024050000b02902ab59347e03sf2820689uan.15
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Sep 2021 07:14:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631024049; cv=pass;
        d=google.com; s=arc-20160816;
        b=IC4/HbCdCrX1cTA4VjjDVrTCgidJw5t5Sbi2UHwJq7oKqfADGpXbxgBXSaT+1QNinJ
         qy/+60Vwq3YZIgPUO6d8nmTFi1cEppMzZANsKaLcOLpv7Kx9ap5PBA97KpCCd0IAtUx7
         sbOc7nv97RdZLa9VvEZcBqzugchNZg34PJ5OgbhC8pKsCKyYV5ZVFzogubH2XLzfcdFW
         By44M7dS3RmintAYwqixsAAK3cPssNRp7GytkGt0vzbU9B+11Q9l4IEUNKcWgKA3c1TC
         dh7Hy/OUq7j+5PehrtlIT7CD+Ip0rve2mi1DD4lgmw2KfgVhFWFMsXTMDVEFMNwg8CLR
         VLKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=wXb7KkzN+khEyxnx5As2ozPYAadNyjkOvpoazgukpbc=;
        b=M+DO8kjIRYcaJZXfFAH7vYrciUCCGSotKrU3dgSmGhqJ13peA+maCudGdfgXuDeia6
         LmpQcjfIBSYTARM6BDHgkVKaY7kX2jxoTeBy32uk1XHHA7cHrB2r2JQzD36eIeFDQLtW
         FjeOtNNC2adUbc5i6PUVfuqKAs8matAl7VV5V4auaCVNm/oLopIv3zwCtB/UBK26cUAI
         DBFUwIX4IDmKZvWh47isqOFJypDrX93FB3cr33eFSVoEPd/iMdxBDIFKsdEGm8lHR7j1
         1iUM+0AXgDq1GR2C1J4Z0QncfoC6hmB85RjO6eQr16f8EwwhSYRBgME9CbD+dHjEev7l
         YrFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ICdgop9B;
       spf=pass (google.com: domain of 3shm3yqukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3sHM3YQUKCYUnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wXb7KkzN+khEyxnx5As2ozPYAadNyjkOvpoazgukpbc=;
        b=ENbmNi4a36DB3uIeOwK9GYl1AKWlYLo7iPpsLjMdIoIsEB5O2vPqnvxmfKDmwQ7gTQ
         gaVYGj/7+6BjkWPT2/FsWaPye7NAWWdVsXwgvf0ex54aeK4x382x1vE6pM1JixbWFCZg
         fLbIyB0dH67fLSi0fryS2KzXaU6vciavvl7bI/SnfsX7XQxvnSLPHuQN6S7ZQs6Fj8WR
         QTmPP/R92EuXc3wCYejnv5cALpo3h1RWC7qLM8kJvjsJzk4S7aIBMpFBoX5jDO4YeDAN
         WT/J9BugScAvPzBOG50nUtxtbudqrQ8lBxs24mfyuOM58OQOWwVn3uSC6ntPu/gS5HND
         EDCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wXb7KkzN+khEyxnx5As2ozPYAadNyjkOvpoazgukpbc=;
        b=BU9hUoy3L+PbWVKKnZtl8WDlySpOVBBwynL+Z7sEdHqxqpIH4VlpTI766dg/ZItTCr
         lXfFbVlL6ClNDPQTM6Y/LMdyED9iB96mxghiQgLVOzb5YbSty6lfS94BvWukW7Z/8O2v
         gidzhgS5KzLjoEaD+/fCk+eUqfuglUe9Z9H3nulDMS74NGSzAx0TRtq4lMvyqOPECnGq
         63+l983bqS3qHpEnVimESvFsZi0JFNtHiSv/VyfXIOBaSjd+slVe8tAvqCNPDAbOjbzZ
         YsEVxVfa2pA5fXEUfGkqZ/tfvqWRuNRwNuhTzxo7miD5lo2xJ31HkmtOAFs7hVUrDvnG
         PunQ==
X-Gm-Message-State: AOAM530jK9Pf3iULUBIzkE2WCKVbgqDd7Q1CPOs43VrRqIQ+CrUP9f8a
	gkxc7RnTq85/3f6G0iL7j4Y=
X-Google-Smtp-Source: ABdhPJxc0lkSx4CkqnGhJyCfpoRNQzZ4LEQVIXIYzY2kGw9kYiRfj7I0lChfZfhc8zxT9mrFRK4Z0A==
X-Received: by 2002:a1f:d902:: with SMTP id q2mr8387080vkg.20.1631024049150;
        Tue, 07 Sep 2021 07:14:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a8c6:: with SMTP id r189ls570632vke.11.gmail; Tue, 07
 Sep 2021 07:14:08 -0700 (PDT)
X-Received: by 2002:a1f:308d:: with SMTP id w135mr8124857vkw.15.1631024048502;
        Tue, 07 Sep 2021 07:14:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631024048; cv=none;
        d=google.com; s=arc-20160816;
        b=a3Y9K/5nQShKVqWjErof/3nTrrpzl9swj03+mQ76qL2qTHfPe2jc6zGr4f3puFR2OD
         lJrBwdk86dvsWvmCjHR44XwN93s6HW1oo6WlwX9PfpNcoax4pLimdb+1Q0VO9wQOE9jp
         CYWbGFwRVAaIThHLlJ168F1/itPolurobWUikvXHXxzbod5k+eoOARSL4KwUZDAKHCL6
         gXsbJ4j7tLh+kSM9oJo7LtPQBCIIHRQpGXkLA5JtHZThEQ+h1MdytCAsjsae1QQNOQy8
         Rpl4jyyc63tcj2cuK/464/paEEenRbrjziT2hDn9Max+XB3SCIj5UgKIN/DrwXpKbsNi
         gOPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ClauTO0DAc/W2CE5FaWJtasGRNKjOeQhVVw0fZ55opA=;
        b=SvlNOBjyf5VoPMweOzlyasYDI9XTgNdf0EcZJeqMjFpxVb8woHm1HQ6gpKcUmVot6Y
         XkA0RiJX2iCwVhBv/QgtxH800yd0JOjt2aMilbktXpYO+Nxx3a/7vpVvJSYzQfAEk1C3
         /zh3SuhfOzzC3Rdo0x0EKg0SM90VPt+G/HhmxxjDo9G7IQor/e8Wr9aiPD+KcP22cJOq
         q6kab9NnI1a2K6m/lp5QfkQG8M6pz1OhADDfLoVXAqqxxunDqVtjQZTXtZqrBgN6EQPR
         Y2ssMaP1nz8bi6R5ZHkNc4Eej64KFYy1WpgM/f5foBsXyXTIyTW7BM/tN2sqVWSk+FYv
         BbUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ICdgop9B;
       spf=pass (google.com: domain of 3shm3yqukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3sHM3YQUKCYUnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id az31si404648uab.0.2021.09.07.07.14.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Sep 2021 07:14:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3shm3yqukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id k12-20020a05620a0b8c00b003d5c8646ec2so14469326qkh.20
        for <kasan-dev@googlegroups.com>; Tue, 07 Sep 2021 07:14:08 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6800:c1ea:4271:5898])
 (user=elver job=sendgmr) by 2002:a05:6214:14f2:: with SMTP id
 k18mr17256135qvw.19.1631024048156; Tue, 07 Sep 2021 07:14:08 -0700 (PDT)
Date: Tue,  7 Sep 2021 16:13:04 +0200
In-Reply-To: <20210907141307.1437816-1-elver@google.com>
Message-Id: <20210907141307.1437816-4-elver@google.com>
Mime-Version: 1.0
References: <20210907141307.1437816-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.153.gba50c8fa24-goog
Subject: [PATCH 3/6] lib/stackdepot: introduce __stack_depot_save()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ICdgop9B;       spf=pass
 (google.com: domain of 3shm3yqukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3sHM3YQUKCYUnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add __stack_depot_save(), which provides more fine-grained control over
stackdepot's memory allocation behaviour, in case stackdepot runs out of
"stack slabs".

Normally stackdepot uses alloc_pages() in case it runs out of space;
passing can_alloc==false to __stack_depot_save() prohibits this, at the
cost of more likely failure to record a stack trace.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/stackdepot.h |  4 ++++
 lib/stackdepot.c           | 42 ++++++++++++++++++++++++++++++++------
 2 files changed, 40 insertions(+), 6 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 97b36dc53301..b2f7e7c6ba54 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -15,6 +15,10 @@
 
 typedef u32 depot_stack_handle_t;
 
+depot_stack_handle_t __stack_depot_save(unsigned long *entries,
+					unsigned int nr_entries,
+					gfp_t gfp_flags, bool can_alloc);
+
 depot_stack_handle_t stack_depot_save(unsigned long *entries,
 				      unsigned int nr_entries, gfp_t gfp_flags);
 
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index c80a9f734253..cab6cf117290 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -248,17 +248,28 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 EXPORT_SYMBOL_GPL(stack_depot_fetch);
 
 /**
- * stack_depot_save - Save a stack trace from an array
+ * __stack_depot_save - Save a stack trace from an array
  *
  * @entries:		Pointer to storage array
  * @nr_entries:		Size of the storage array
  * @alloc_flags:	Allocation gfp flags
+ * @can_alloc:		Allocate stack slabs (increased chance of failure if false)
+ *
+ * Saves a stack trace from @entries array of size @nr_entries. If @can_alloc is
+ * %true, is allowed to replenish the stack slab pool in case no space is left
+ * (allocates using GFP flags of @alloc_flags). If @can_alloc is %false, avoids
+ * any allocations and will fail if no space is left to store the stack trace.
+ *
+ * Context: Any context, but setting @can_alloc to %false is required if
+ *          alloc_pages() cannot be used from the current context. Currently
+ *          this is the case from contexts where neither %GFP_ATOMIC nor
+ *          %GFP_NOWAIT can be used (NMI, raw_spin_lock).
  *
- * Return: The handle of the stack struct stored in depot
+ * Return: The handle of the stack struct stored in depot, 0 on failure.
  */
-depot_stack_handle_t stack_depot_save(unsigned long *entries,
-				      unsigned int nr_entries,
-				      gfp_t alloc_flags)
+depot_stack_handle_t __stack_depot_save(unsigned long *entries,
+					unsigned int nr_entries,
+					gfp_t alloc_flags, bool can_alloc)
 {
 	struct stack_record *found = NULL, **bucket;
 	depot_stack_handle_t retval = 0;
@@ -291,7 +302,7 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 	 * The smp_load_acquire() here pairs with smp_store_release() to
 	 * |next_slab_inited| in depot_alloc_stack() and init_stack_slab().
 	 */
-	if (unlikely(!smp_load_acquire(&next_slab_inited))) {
+	if (unlikely(can_alloc && !smp_load_acquire(&next_slab_inited))) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -339,6 +350,25 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 fast_exit:
 	return retval;
 }
+EXPORT_SYMBOL_GPL(__stack_depot_save);
+
+/**
+ * stack_depot_save - Save a stack trace from an array
+ *
+ * @entries:		Pointer to storage array
+ * @nr_entries:		Size of the storage array
+ * @alloc_flags:	Allocation gfp flags
+ *
+ * Context: Contexts where allocations via alloc_pages() are allowed.
+ *
+ * Return: The handle of the stack struct stored in depot, 0 on failure.
+ */
+depot_stack_handle_t stack_depot_save(unsigned long *entries,
+				      unsigned int nr_entries,
+				      gfp_t alloc_flags)
+{
+	return __stack_depot_save(entries, nr_entries, alloc_flags, true);
+}
 EXPORT_SYMBOL_GPL(stack_depot_save);
 
 static inline int in_irqentry_text(unsigned long ptr)
-- 
2.33.0.153.gba50c8fa24-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210907141307.1437816-4-elver%40google.com.
