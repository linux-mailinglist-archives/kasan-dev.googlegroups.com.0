Return-Path: <kasan-dev+bncBC7OD3FKWUERBG4MXKMAMGQEAF5N26I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 12D505A6FA2
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:21 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id f202-20020a1f38d3000000b003802dd3dc36sf2100321vka.23
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896220; cv=pass;
        d=google.com; s=arc-20160816;
        b=l0MzfG41JtjZuZiKfFMzSXQkXHXpnQ9ixHhcuRdYok9WOBOs8ayOkN8zLpeerD6ukc
         4ztupACEuK/gLN0Xc4K/Y89E+Sx10wXEy0XGMVeiir8nLWPuurifdtcoDWKJdH7JBrGO
         YlfZkVT0C5/e+BHXWOj3CddeW2zHAypekD69SOSbHx6amRO5gP3IYGgZFNmrI0y/3ozC
         +3lznoeo5IBA1knM3AJrxBH7jdgjQyp0e59zvXL/i/RZJKN9tNJWx1VUu/howKQbdqlf
         zv067MNWM0aMtyGTkqh++tKpGit95DAShsOPwy7ozm+XFtrf+ulYH6p2zGs5v5a3HK9n
         RbSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=kich+y+D5wKnddk6kjwuf/caqFO+HFNdM66O/emBl5c=;
        b=1Exicwa5GXe9sZi48RqvvBnzNEixfbXl8Eefkk4U+N3oLOu7Tmjo2ZjwigOuQ1R1Kl
         IfIblsbcB+CC2Dsmvqo0cKCfwRIJ1bGYNHz5sLemM/LJSf45iH3Kq5Vcdk1QVCWwGUX2
         r2cAIp4RmXjl6WofwziZmnoV4JXsA8da3NZfZZ4GSIphgOPAOQ05+DlpnvzUtiZ/3Vs1
         55uyG5heP331RKrorzt91/9dDZxY8XdWpkrjWUbpXGzA0pF1sgkQ5wNnJ+vVa7ugpXyD
         ortBMhZbRoABB8C7wj5rGzutkrjymfVvnBmNGEBBr9ommFOImPTorx3vzWFS2jMrZJzF
         KQMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=W9ws8GQM;
       spf=pass (google.com: domain of 3g4yoywykcyawyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3G4YOYwYKCYAwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=kich+y+D5wKnddk6kjwuf/caqFO+HFNdM66O/emBl5c=;
        b=ORDsPnV9Io+k9UQfBIYqHiAivscsYnpRvwzuSHnaR7hgt3OzzHUP4u9yRqEQ/aUySr
         AKM9f2DsaYmvjopw0QUh3rVbiZywrCThZgHBjVbJsHY0ozAcWnGqKcvTVEOn4nR7FsaK
         Zu6o4Fx2LUH+50tSFgomdUNFI+tLKQkEvhksXFAasYtfQwys3NU4oUOOAaNsWHaN6Gdn
         cwceOPxqCc6XGD46WWlYXgN8RvYUKIjIfDXnSKP0odNMng11X85+LmTvg2mKOV0WTjHg
         ++5qDfVk1+LP5r0g14rnes5XmaB+Tcds2FcKhCXapYDNg2rYyyrPBQll8LSwMsmrkOme
         6jrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=kich+y+D5wKnddk6kjwuf/caqFO+HFNdM66O/emBl5c=;
        b=m3gBalW/RU2k/2HBBtd4Duuc0AckUrE42nZVTl+xfRPzLhonm3fccVC6btPx2ryTIl
         lBskccUpAQSSODbWuTcNYnw7c9mHFLc4leGdmsT6LkHKlep+9SG4nqGwkSpUHfTZh31Z
         zqko9NO8UG5PjuuBxAXj5/eDfYHT0Y9LKsPynVZzQWmxuxGhe1c/wYDPqGLUx2+q5/sJ
         4DJ7crFDIUnB5c03boLYdD/52N7Of0KZa4y6EIo7erk1Rk2KJkJAy4iRjiOkx12/5FLa
         gS8QOvZi0EfbWGg7GWkNigODBSWOtWb6J9uiS6s2VNdi7E84Qge/xEm89UgiPJfOK8MO
         asSg==
X-Gm-Message-State: ACgBeo1nFXDXNWIj6fjw0Tg+M1cLLoVXkT/Dc5/w9FWyKBXrQZ3oevVl
	6EIGIFmfZRS39O6DCHi+ORQ=
X-Google-Smtp-Source: AA6agR73bQFBnbplVPRGFJ4g6aEJwwB+R0qAEENUQRFzeAWFQUXEpDWAWAfngrm5D3wB7AI/4usvKA==
X-Received: by 2002:a1f:9f87:0:b0:394:54f:19f6 with SMTP id i129-20020a1f9f87000000b00394054f19f6mr5022986vke.6.1661896220038;
        Tue, 30 Aug 2022 14:50:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:3b5a:0:b0:387:5050:a2c with SMTP id o26-20020ab03b5a000000b0038750500a2cls611940uaw.1.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:50:19 -0700 (PDT)
X-Received: by 2002:a9f:37f1:0:b0:381:e385:2fdc with SMTP id q104-20020a9f37f1000000b00381e3852fdcmr5737741uaq.116.1661896219516;
        Tue, 30 Aug 2022 14:50:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896219; cv=none;
        d=google.com; s=arc-20160816;
        b=t7U9Epg9uuKMfK5axzq344xrNv2YpPV7cH8VlC6RMA39yqwBo+wgq8IX0OrDv+702g
         rmhdPI6Y9u9suOuuRIhIu+ONOJ4JY6GpCzuV+Y3+uaQg/AIXExHNw1Se0mZvXr4ZvwEq
         IxqJyJHNoKIgljEE9xpI+pwNsF9lHYSMxQH8mTQGZz/Cevqexk8I8K1XYqT0Xd3WD16Q
         /YcPGKdTKshm/1FsYICH1I3Q6LypKWKtZlXEtXv/3fH6oLLHL+v6W1O1zWKtvlMckz9T
         EuORaS2/I9pmy4lNEI8soz3ThmXM8V+FKr9+jKRDvAd8URXwFpwy+Zz3ym4I+V3JMuRl
         GKQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=g/YTY0u3yadOEciruM5AsrsoCBr2LdU6F8XKpTCCoXE=;
        b=Gl5c+mx+saWMuC7K9HqekiKAjsIzT+gI5Vlr/SpxATPS1XAVGio7H/4rO9IC18GWv8
         yJvw0v6mGCIhJQI3FSiVfZC5tCc7H9Y8g28ma12eL54IQE93HtHt+Y6BaXrSxuDlHtdt
         DjSWcYuoa0YYHLTFq03yuUONzI2aWHp9IThVtL2DpZrfv86mbXN1760WSrK4xXX90WFt
         AseRCHkGsNQUxNha1DnaImMsIg4B8oZ8wBkOBjMCYf+q8JItdmJRplU+EsVoxNL/DMLC
         +gX32um64qQEMQDMtBbtIx0sEu+yBIUJUwAiMhEmwuBWPhVKiKZpS6hge+I4qJUR9dsa
         hCtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=W9ws8GQM;
       spf=pass (google.com: domain of 3g4yoywykcyawyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3G4YOYwYKCYAwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id s4-20020a1f2c04000000b0038cd23ea90dsi461428vks.4.2022.08.30.14.50.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3g4yoywykcyawyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-340862314d9so173450717b3.3
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:19 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a05:6902:100b:b0:695:bd4e:95d6 with SMTP id
 w11-20020a056902100b00b00695bd4e95d6mr13705955ybt.595.1661896219160; Tue, 30
 Aug 2022 14:50:19 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:10 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-22-surenb@google.com>
Subject: [RFC PATCH 21/30] lib: implement context capture support for page and
 slab allocators
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
 header.i=@google.com header.s=20210112 header.b=W9ws8GQM;       spf=pass
 (google.com: domain of 3g4yoywykcyawyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3G4YOYwYKCYAwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com;
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

Implement mechanisms for capturing allocation call context which consists
of:
- allocation size
- pid, tgid and name of the allocating task
- allocation timestamp
- allocation call stack
The patch creates alloc_tags.ctx file which can be written to
enable/disable context capture for a specific code tag. Captured context
can be obtained by reading alloc_tags.ctx file.
Usage example:

echo "file include/asm-generic/pgalloc.h line 63 enable" > \
    /sys/kernel/debug/alloc_tags.ctx
cat alloc_tags.ctx
 91.0MiB      212 include/asm-generic/pgalloc.h:63 module:pgtable func:__pte_alloc_one
    size: 4096
    pid: 1551
    tgid: 1551
    comm: cat
    ts: 670109646361
    call stack:
         pte_alloc_one+0xfe/0x130
         __pte_alloc+0x22/0x90
         move_page_tables.part.0+0x994/0xa60
         shift_arg_pages+0xa4/0x180
         setup_arg_pages+0x286/0x2d0
         load_elf_binary+0x4e1/0x18d0
         bprm_execve+0x26b/0x660
         do_execveat_common.isra.0+0x19d/0x220
         __x64_sys_execve+0x2e/0x40
         do_syscall_64+0x38/0x90
         entry_SYSCALL_64_after_hwframe+0x63/0xcd

    size: 4096
    pid: 1551
    tgid: 1551
    comm: cat
    ts: 670109711801
    call stack:
         pte_alloc_one+0xfe/0x130
         __do_fault+0x52/0xc0
         __handle_mm_fault+0x7d9/0xdd0
         handle_mm_fault+0xc0/0x2b0
         do_user_addr_fault+0x1c3/0x660
         exc_page_fault+0x62/0x150
         asm_exc_page_fault+0x22/0x30
...

echo "file include/asm-generic/pgalloc.h line 63 disable" > \
    /sys/kernel/debug/alloc_tags.ctx

Note that disabling context capture will not clear already captured
context but no new context will be captured.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/alloc_tag.h |  28 ++++-
 include/linux/codetag.h   |   3 +-
 lib/Kconfig.debug         |   1 +
 lib/alloc_tag.c           | 239 +++++++++++++++++++++++++++++++++++++-
 lib/codetag.c             |  20 ++--
 5 files changed, 273 insertions(+), 18 deletions(-)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index b3f589afb1c9..66638cbf349a 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -16,27 +16,41 @@
  * an array of these. Embedded codetag utilizes codetag framework.
  */
 struct alloc_tag {
-	struct codetag			ct;
+	struct codetag_with_ctx		ctc;
 	unsigned long			last_wrap;
 	struct raw_lazy_percpu_counter	call_count;
 	struct raw_lazy_percpu_counter	bytes_allocated;
 } __aligned(8);
 
+static inline struct alloc_tag *ctc_to_alloc_tag(struct codetag_with_ctx *ctc)
+{
+	return container_of(ctc, struct alloc_tag, ctc);
+}
+
 static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
 {
-	return container_of(ct, struct alloc_tag, ct);
+	return container_of(ct_to_ctc(ct), struct alloc_tag, ctc);
 }
 
+struct codetag_ctx *alloc_tag_create_ctx(struct alloc_tag *tag, size_t size);
+void alloc_tag_free_ctx(struct codetag_ctx *ctx, struct alloc_tag **ptag);
+bool alloc_tag_enable_ctx(struct alloc_tag *tag, bool enable);
+
 #define DEFINE_ALLOC_TAG(_alloc_tag)					\
 	static struct alloc_tag _alloc_tag __used __aligned(8)		\
-	__section("alloc_tags") = { .ct = CODE_TAG_INIT }
+	__section("alloc_tags") = { .ctc.ct = CODE_TAG_INIT }
 
 #define alloc_tag_counter_read(counter)					\
 	__lazy_percpu_counter_read(counter)
 
 static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes)
 {
-	struct alloc_tag *tag = ct_to_alloc_tag(ref->ct);
+	struct alloc_tag *tag;
+
+	if (is_codetag_ctx_ref(ref))
+		alloc_tag_free_ctx(ref->ctx, &tag);
+	else
+		tag = ct_to_alloc_tag(ref->ct);
 
 	__lazy_percpu_counter_add(&tag->call_count, &tag->last_wrap, -1);
 	__lazy_percpu_counter_add(&tag->bytes_allocated, &tag->last_wrap, -bytes);
@@ -51,7 +65,11 @@ do {									\
 
 static inline void __alloc_tag_add(struct alloc_tag *tag, union codetag_ref *ref, size_t bytes)
 {
-	ref->ct = &tag->ct;
+	if (codetag_ctx_enabled(&tag->ctc))
+		ref->ctx = alloc_tag_create_ctx(tag, bytes);
+	else
+		ref->ct = &tag->ctc.ct;
+
 	__lazy_percpu_counter_add(&tag->call_count, &tag->last_wrap, 1);
 	__lazy_percpu_counter_add(&tag->bytes_allocated, &tag->last_wrap, bytes);
 }
diff --git a/include/linux/codetag.h b/include/linux/codetag.h
index 57736ec77b45..a10c5fcbdd20 100644
--- a/include/linux/codetag.h
+++ b/include/linux/codetag.h
@@ -104,7 +104,8 @@ struct codetag_with_ctx *ct_to_ctc(struct codetag *ct)
 }
 
 void codetag_lock_module_list(struct codetag_type *cttype, bool lock);
-struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype);
+void codetag_init_iter(struct codetag_iterator *iter,
+		       struct codetag_type *cttype);
 struct codetag *codetag_next_ct(struct codetag_iterator *iter);
 struct codetag_ctx *codetag_next_ctx(struct codetag_iterator *iter);
 
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 08c97a978906..2790848464f1 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -977,6 +977,7 @@ config ALLOC_TAGGING
 	bool
 	select CODE_TAGGING
 	select LAZY_PERCPU_COUNTER
+	select STACKDEPOT
 
 config PAGE_ALLOC_TAGGING
 	bool "Enable page allocation tagging"
diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
index 082fbde184ef..50d7bdc2a3c8 100644
--- a/lib/alloc_tag.c
+++ b/lib/alloc_tag.c
@@ -1,12 +1,75 @@
 // SPDX-License-Identifier: GPL-2.0-only
 #include <linux/alloc_tag.h>
+#include <linux/codetag_ctx.h>
 #include <linux/debugfs.h>
 #include <linux/fs.h>
 #include <linux/gfp.h>
 #include <linux/module.h>
+#include <linux/sched.h>
+#include <linux/sched/clock.h>
 #include <linux/seq_buf.h>
+#include <linux/stackdepot.h>
 #include <linux/uaccess.h>
 
+#define STACK_BUF_SIZE 1024
+
+struct alloc_call_ctx {
+	struct codetag_ctx ctx;
+	size_t size;
+	pid_t pid;
+	pid_t tgid;
+	char comm[TASK_COMM_LEN];
+	u64 ts_nsec;
+	depot_stack_handle_t stack_handle;
+} __aligned(8);
+
+static void alloc_tag_ops_free_ctx(struct kref *refcount)
+{
+	kfree(container_of(kref_to_ctx(refcount), struct alloc_call_ctx, ctx));
+}
+
+struct codetag_ctx *alloc_tag_create_ctx(struct alloc_tag *tag, size_t size)
+{
+	struct alloc_call_ctx *ac_ctx;
+
+	/* TODO: use a dedicated kmem_cache */
+	ac_ctx = kmalloc(sizeof(struct alloc_call_ctx), GFP_KERNEL);
+	if (WARN_ON(!ac_ctx))
+		return NULL;
+
+	ac_ctx->size = size;
+	ac_ctx->pid = current->pid;
+	ac_ctx->tgid = current->tgid;
+	strscpy(ac_ctx->comm, current->comm, sizeof(ac_ctx->comm));
+	ac_ctx->ts_nsec = local_clock();
+	ac_ctx->stack_handle =
+			stack_depot_capture_stack(GFP_NOWAIT | __GFP_NOWARN);
+	add_ctx(&ac_ctx->ctx, &tag->ctc);
+
+	return &ac_ctx->ctx;
+}
+EXPORT_SYMBOL_GPL(alloc_tag_create_ctx);
+
+void alloc_tag_free_ctx(struct codetag_ctx *ctx, struct alloc_tag **ptag)
+{
+	*ptag = ctc_to_alloc_tag(ctx->ctc);
+	rem_ctx(ctx, alloc_tag_ops_free_ctx);
+}
+EXPORT_SYMBOL_GPL(alloc_tag_free_ctx);
+
+bool alloc_tag_enable_ctx(struct alloc_tag *tag, bool enable)
+{
+	static bool stack_depot_ready;
+
+	if (enable && !stack_depot_ready) {
+		stack_depot_init();
+		stack_depot_capture_init();
+		stack_depot_ready = true;
+	}
+
+	return codetag_enable_ctx(&tag->ctc, enable);
+}
+
 #ifdef CONFIG_DEBUG_FS
 
 struct alloc_tag_file_iterator {
@@ -50,7 +113,7 @@ static int alloc_tag_file_open(struct inode *inode, struct file *file)
 		return -ENOMEM;
 
 	codetag_lock_module_list(cttype, true);
-	iter->ct_iter = codetag_get_ct_iter(cttype);
+	codetag_init_iter(&iter->ct_iter, cttype);
 	codetag_lock_module_list(cttype, false);
 	seq_buf_init(&iter->buf, iter->rawbuf, sizeof(iter->rawbuf));
 	file->private_data = iter;
@@ -111,14 +174,182 @@ static const struct file_operations alloc_tag_file_ops = {
 	.read	= alloc_tag_file_read,
 };
 
+static void alloc_tag_ctx_to_text(struct seq_buf *out, struct codetag_ctx *ctx)
+{
+	struct alloc_call_ctx *ac_ctx;
+	char *buf;
+
+	ac_ctx = container_of(ctx, struct alloc_call_ctx, ctx);
+	seq_buf_printf(out, "    size: %zu\n", ac_ctx->size);
+	seq_buf_printf(out, "    pid: %d\n", ac_ctx->pid);
+	seq_buf_printf(out, "    tgid: %d\n", ac_ctx->tgid);
+	seq_buf_printf(out, "    comm: %s\n", ac_ctx->comm);
+	seq_buf_printf(out, "    ts: %llu\n", ac_ctx->ts_nsec);
+
+	buf = kmalloc(STACK_BUF_SIZE, GFP_KERNEL);
+	if (buf) {
+		int bytes_read = stack_depot_snprint(ac_ctx->stack_handle, buf,
+						     STACK_BUF_SIZE - 1, 8);
+		buf[bytes_read] = '\0';
+		seq_buf_printf(out, "    call stack:\n%s\n", buf);
+	}
+	kfree(buf);
+}
+
+static ssize_t alloc_tag_ctx_file_read(struct file *file, char __user *ubuf,
+				       size_t size, loff_t *ppos)
+{
+	struct alloc_tag_file_iterator *iter = file->private_data;
+	struct codetag_iterator *ct_iter = &iter->ct_iter;
+	struct user_buf	buf = { .buf = ubuf, .size = size };
+	struct codetag_ctx *ctx;
+	struct codetag *prev_ct;
+	int err = 0;
+
+	codetag_lock_module_list(ct_iter->cttype, true);
+	while (1) {
+		err = flush_ubuf(&buf, &iter->buf);
+		if (err || !buf.size)
+			break;
+
+		prev_ct = ct_iter->ct;
+		ctx = codetag_next_ctx(ct_iter);
+		if (!ctx)
+			break;
+
+		if (prev_ct != &ctx->ctc->ct)
+			alloc_tag_to_text(&iter->buf, &ctx->ctc->ct);
+		alloc_tag_ctx_to_text(&iter->buf, ctx);
+	}
+	codetag_lock_module_list(ct_iter->cttype, false);
+
+	return err ? : buf.ret;
+}
+
+#define CTX_CAPTURE_TOKENS()	\
+	x(disable,	0)	\
+	x(enable,	0)
+
+static const char * const ctx_capture_token_strs[] = {
+#define x(name, nr_args)	#name,
+	CTX_CAPTURE_TOKENS()
+#undef x
+	NULL
+};
+
+enum ctx_capture_token {
+#define x(name, nr_args)	TOK_##name,
+	CTX_CAPTURE_TOKENS()
+#undef x
+};
+
+static int enable_ctx_capture(struct codetag_type *cttype,
+			      struct codetag_query *query, bool enable)
+{
+	struct codetag_iterator ct_iter;
+	struct codetag_with_ctx *ctc;
+	struct codetag *ct;
+	unsigned int nfound = 0;
+
+	codetag_lock_module_list(cttype, true);
+
+	codetag_init_iter(&ct_iter, cttype);
+	while ((ct = codetag_next_ct(&ct_iter))) {
+		if (!codetag_matches_query(query, ct, ct_iter.cmod, NULL))
+			continue;
+
+		ctc = ct_to_ctc(ct);
+		if (codetag_ctx_enabled(ctc) == enable)
+			continue;
+
+		if (!alloc_tag_enable_ctx(ctc_to_alloc_tag(ctc), enable)) {
+			pr_warn("Failed to toggle context capture\n");
+			continue;
+		}
+
+		nfound++;
+	}
+
+	codetag_lock_module_list(cttype, false);
+
+	return nfound ? 0 : -ENOENT;
+}
+
+static int parse_command(struct codetag_type *cttype, char *buf)
+{
+	struct codetag_query query = { NULL };
+	char *cmd;
+	int ret;
+	int tok;
+
+	buf = codetag_query_parse(&query, buf);
+	if (IS_ERR(buf))
+		return PTR_ERR(buf);
+
+	cmd = strsep_no_empty(&buf, " \t\r\n");
+	if (!cmd)
+		return -EINVAL;	/* no command */
+
+	tok = match_string(ctx_capture_token_strs,
+			   ARRAY_SIZE(ctx_capture_token_strs), cmd);
+	if (tok < 0)
+		return -EINVAL;	/* unknown command */
+
+	ret = enable_ctx_capture(cttype, &query, tok == TOK_enable);
+	if (ret < 0)
+		return ret;
+
+	return 0;
+}
+
+static ssize_t alloc_tag_ctx_file_write(struct file *file, const char __user *ubuf,
+					size_t len, loff_t *offp)
+{
+	struct alloc_tag_file_iterator *iter = file->private_data;
+	char tmpbuf[256];
+
+	if (len == 0)
+		return 0;
+	/* we don't check *offp -- multiple writes() are allowed */
+	if (len > sizeof(tmpbuf) - 1)
+		return -E2BIG;
+
+	if (copy_from_user(tmpbuf, ubuf, len))
+		return -EFAULT;
+
+	tmpbuf[len] = '\0';
+	parse_command(iter->ct_iter.cttype, tmpbuf);
+
+	*offp += len;
+	return len;
+}
+
+static const struct file_operations alloc_tag_ctx_file_ops = {
+	.owner	= THIS_MODULE,
+	.open	= alloc_tag_file_open,
+	.release = alloc_tag_file_release,
+	.read	= alloc_tag_ctx_file_read,
+	.write	= alloc_tag_ctx_file_write,
+};
+
 static int dbgfs_init(struct codetag_type *cttype)
 {
 	struct dentry *file;
+	struct dentry *ctx_file;
 
 	file = debugfs_create_file("alloc_tags", 0444, NULL, cttype,
 				   &alloc_tag_file_ops);
+	if (IS_ERR(file))
+		return PTR_ERR(file);
+
+	ctx_file = debugfs_create_file("alloc_tags.ctx", 0666, NULL, cttype,
+				       &alloc_tag_ctx_file_ops);
+	if (IS_ERR(ctx_file)) {
+		debugfs_remove(file);
+		return PTR_ERR(ctx_file);
+	}
 
-	return IS_ERR(file) ? PTR_ERR(file) : 0;
+	return 0;
 }
 
 #else /* CONFIG_DEBUG_FS */
@@ -129,9 +360,10 @@ static int dbgfs_init(struct codetag_type *) { return 0; }
 
 static void alloc_tag_module_unload(struct codetag_type *cttype, struct codetag_module *cmod)
 {
-	struct codetag_iterator iter = codetag_get_ct_iter(cttype);
+	struct codetag_iterator iter;
 	struct codetag *ct;
 
+	codetag_init_iter(&iter, cttype);
 	for (ct = codetag_next_ct(&iter); ct; ct = codetag_next_ct(&iter)) {
 		struct alloc_tag *tag = ct_to_alloc_tag(ct);
 
@@ -147,6 +379,7 @@ static int __init alloc_tag_init(void)
 		.section	= "alloc_tags",
 		.tag_size	= sizeof(struct alloc_tag),
 		.module_unload	= alloc_tag_module_unload,
+		.free_ctx	= alloc_tag_ops_free_ctx,
 	};
 
 	cttype = codetag_register_type(&desc);
diff --git a/lib/codetag.c b/lib/codetag.c
index 2762fda5c016..a936d2988c96 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -26,16 +26,14 @@ void codetag_lock_module_list(struct codetag_type *cttype, bool lock)
 		up_read(&cttype->mod_lock);
 }
 
-struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype)
+void codetag_init_iter(struct codetag_iterator *iter,
+		       struct codetag_type *cttype)
 {
-	struct codetag_iterator iter = {
-		.cttype = cttype,
-		.cmod = NULL,
-		.mod_id = 0,
-		.ct = NULL,
-	};
-
-	return iter;
+	iter->cttype = cttype;
+	iter->cmod = NULL;
+	iter->mod_id = 0;
+	iter->ct = NULL;
+	iter->ctx = NULL;
 }
 
 static inline struct codetag *get_first_module_ct(struct codetag_module *cmod)
@@ -127,6 +125,10 @@ struct codetag_ctx *codetag_next_ctx(struct codetag_iterator *iter)
 
 	lockdep_assert_held(&iter->cttype->mod_lock);
 
+	/* Move to the first codetag if search just started */
+	if (!iter->ct)
+		codetag_next_ct(iter);
+
 	if (!ctx)
 		return next_ctx_from_ct(iter);
 
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-22-surenb%40google.com.
