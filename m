Return-Path: <kasan-dev+bncBC7OD3FKWUERBM66X6RAMGQECSNUHLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A92E6F33F4
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:20 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-74deda8705dsf142508985a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960179; cv=pass;
        d=google.com; s=arc-20160816;
        b=jkP5VEihNQzytxuLxIYKhVCE0GOq2oorywkbIVxV0nLR4sQ9Wfn0Di4Tz80ImFDNIM
         l/4251hfsV/YyyguEh9wup9/wPDliMMSSDVe3DEMRgCIAp2+wfONyxE4hBTm0GhAn5ju
         9HtIpIEFYSEjxry4p3dZmZN/9QUFpC7iOqLJPlTJf7K9Up5ziISPYkZg0zmrSqmdDROc
         YLAZnLO4IlKGU4/m8smYDSiD7XMirumeeVKczy2C4v+W7UNN7QEYBP9uFLpN/uEFBCGs
         VuBPMKYdnpdpY5u1wiw/2A4jznJBqQlH7dfUlLJnrkCbewAvjLWGzDh+1zpGnfeNWIwR
         YC+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=A4+9IOHinsObcG9NkaMbfgn1+8VzBTlsSzOnF5lA/Nc=;
        b=AkULrc0dM/8YikBC8d0NTeMhkvn9d3sYQs9YuxUcl6yS0owCwSGiIpJ5KZ2BYKxgi0
         mN30M2eKmKApUvkanpUrYU+5jltDBSNY/OcH9qGVy4qXWuuASQuNP5VSrbm5RBh6W1Z7
         snbp6nk/37G/lbSpeI9NMZo74QGcgB6ulYNxHhPalb445nfzNbLviMCG0+70+6aMx7Q3
         dgvfU+rjMj/+CXAx7yFyWtN/IcAVfxTNwPcGItXILmrYyy2unLWgJ0SnFgCFt/2h4+sq
         Q1Wk3EACd/JjePEgJc1hbgGtW3vp9CI+haUF8RBCY12tGqk5pZI++ZtsJ0MzsLMrIw6h
         NzUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=6MUphdHN;
       spf=pass (google.com: domain of 3mu9pzaykcxkprobkydlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Mu9PZAYKCXkprobkYdlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960179; x=1685552179;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=A4+9IOHinsObcG9NkaMbfgn1+8VzBTlsSzOnF5lA/Nc=;
        b=efYPNxjO72Y41EUnefKQKHnSxEuaCIuYKG75PoOHjEpgcXk0F1dimYO7SGILJBwtTu
         YlT8NDqeOceSqT9JzkIrHp19wrsjJxKkAc2QIT7aAaBUgmDctbRw5LEol7C/OJI+kVXY
         YrScg9gnzAQjPo99MkCCU/QaA+df/DVkM1W8CCfgK9pdbK2TlDrVErqQKZaSkcMvCxka
         TEiWUOqgXRV/IMdx2qPRl7SvWf5gO9Iawh4Gmr8fWVLtNp0I3OHvcglA5z0SAtXr1lk5
         wL7wUYVx212sgMdGJ9xRECeI8R29/C2RvNGLrL99+UKKtegpnY7kgkfVVEJR0aQt3fhh
         SSpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960179; x=1685552179;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A4+9IOHinsObcG9NkaMbfgn1+8VzBTlsSzOnF5lA/Nc=;
        b=CLShc65HKAtcav+EdkXGfvKbz6oihWD/nxq3JgpY/J2Y5IlOSDSee0H6+Wi9EaAhTX
         dsOqB74P3NOAFaznRjSLSpC4U595HKya7vL8Cq/Dkvue0SjUAPbK3wiQqZS92R0HGQ4Y
         FMsvGpeUXpdGOiPQSZ9kZSns4lg6gjA5D3X0n7Cm9+5hn2JsDTsTum17x5U3mPJl8NhP
         bkiB/nrUGc036Hznn+6RMz9HaBzJmgLloYhKiXROiB8timtf84k/LeaD8e10gDUslqf1
         DQdnyECeRqPEyQHeOjcgQxcUX3F50h2Qga8e/SGCIJcc5jLz1Gr9tWXUMLnyoTYX5kNz
         l10A==
X-Gm-Message-State: AC+VfDwOssG873q+cxOq7lexFV6JdpzJdPY6S5vWgVYNkY/dgstLd6q6
	XTVdQMUZqp7vk8HMcQNKUhs=
X-Google-Smtp-Source: ACHHUZ5mPxRQava6uh4nfIpjCn2uEkUevrqgyTYN15G4LeXdAJfR6aezZlt4qk0QAyT5GaLfwrQiOg==
X-Received: by 2002:a05:622a:15c1:b0:3ef:499a:dd95 with SMTP id d1-20020a05622a15c100b003ef499add95mr4532611qty.7.1682960179604;
        Mon, 01 May 2023 09:56:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:be86:0:b0:5f1:684f:420a with SMTP id n6-20020a0cbe86000000b005f1684f420als7417913qvi.5.-pod-prod-gmail;
 Mon, 01 May 2023 09:56:19 -0700 (PDT)
X-Received: by 2002:ad4:5ce7:0:b0:5e9:2d8c:9a06 with SMTP id iv7-20020ad45ce7000000b005e92d8c9a06mr824828qvb.39.1682960178939;
        Mon, 01 May 2023 09:56:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960178; cv=none;
        d=google.com; s=arc-20160816;
        b=0LdmCnI62Q12vIrBhS8+0bQ18kapZEOAot7averTaEosM6WeSs9kdqHEYtJ4xR2J/d
         eK4yM5d+SvqaltvAEoRyhVGNSN73qTLj1XDxCQl4dX20639GbaCyUjyI9UR6age1KVMe
         GMG9kwFMKke3her7aJE/AlvBKJrghSTafTF1waUH6JV7agvYxj+7qMXkzTDaGamL21/3
         USigvi/fUlwh0RjQNO//qfWflOcKew3U28nf5yCwdfjjqkqDdeMdQm8YiID5FiSHCnew
         ED57tPpbkaGmXhIWrp8TEzY1p9T9N7SdJNjpfPBVqXWCJYf2M2cO857DbVGc3tGLQdos
         VasQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=FLzZ9YV8+8xWjeDeRDWFnLJt6gby5ahlup+t8unODj4=;
        b=bpNrOCqHie0DDL707GxLWiFZT8jOnYIkmVNPS5u7kXUVm80CjfljBb1IknBVx/D5rK
         5ocqCd96T9wHhv2wyhalvKfSxKPO8YjIBosjNXdIjM/ieojWM09kr0uaKvsmTaEr8pLP
         r002Canqs43vXsC2HoIXInVtn79cA9ZpO59vlQ2j8m9lJrRNBCXgFWJYL/GZYCER2Jke
         IviAZMLJpMjJAiWIMSkgtURNB64Vepe0RKnxfEv667B7aC6/5BeYDtvvfazVi4bwsYSa
         tNnsCQ2SVeiXOrRpZtxWWwnaItZpR8ieBraOsWDXnW0V0tRAuDwcoex75g9r0cPFcfM/
         ehVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=6MUphdHN;
       spf=pass (google.com: domain of 3mu9pzaykcxkprobkydlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Mu9PZAYKCXkprobkYdlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id qd16-20020a05620a659000b0074e023f65fbsi1562854qkn.7.2023.05.01.09.56.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mu9pzaykcxkprobkydlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-b9a7ddd9aceso5483323276.3
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:18 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:d18e:0:b0:b9e:5008:1770 with SMTP id
 i136-20020a25d18e000000b00b9e50081770mr393470ybg.8.1682960178602; Mon, 01 May
 2023 09:56:18 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:41 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-32-surenb@google.com>
Subject: [PATCH 31/40] mm: percpu: enable per-cpu allocation tagging
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
 header.i=@google.com header.s=20221208 header.b=6MUphdHN;       spf=pass
 (google.com: domain of 3mu9pzaykcxkprobkydlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Mu9PZAYKCXkprobkYdlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--surenb.bounces.google.com;
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

Redefine __alloc_percpu, __alloc_percpu_gfp and __alloc_reserved_percpu
to record allocations and deallocations done by these functions.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/percpu.h | 19 ++++++++----
 mm/percpu.c            | 66 +++++-------------------------------------
 2 files changed, 22 insertions(+), 63 deletions(-)

diff --git a/include/linux/percpu.h b/include/linux/percpu.h
index 1338ea2aa720..51ec257379af 100644
--- a/include/linux/percpu.h
+++ b/include/linux/percpu.h
@@ -2,12 +2,14 @@
 #ifndef __LINUX_PERCPU_H
 #define __LINUX_PERCPU_H
 
+#include <linux/alloc_tag.h>
 #include <linux/mmdebug.h>
 #include <linux/preempt.h>
 #include <linux/smp.h>
 #include <linux/cpumask.h>
 #include <linux/pfn.h>
 #include <linux/init.h>
+#include <linux/sched.h>
 
 #include <asm/percpu.h>
 
@@ -116,7 +118,6 @@ extern int __init pcpu_page_first_chunk(size_t reserved_size,
 				pcpu_fc_cpu_to_node_fn_t cpu_to_nd_fn);
 #endif
 
-extern void __percpu *__alloc_reserved_percpu(size_t size, size_t align) __alloc_size(1);
 extern bool __is_kernel_percpu_address(unsigned long addr, unsigned long *can_addr);
 extern bool is_kernel_percpu_address(unsigned long addr);
 
@@ -124,10 +125,15 @@ extern bool is_kernel_percpu_address(unsigned long addr);
 extern void __init setup_per_cpu_areas(void);
 #endif
 
-extern void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp) __alloc_size(1);
-extern void __percpu *__alloc_percpu(size_t size, size_t align) __alloc_size(1);
-extern void free_percpu(void __percpu *__pdata);
-extern phys_addr_t per_cpu_ptr_to_phys(void *addr);
+extern void __percpu *__pcpu_alloc(size_t size, size_t align, bool reserved,
+				   gfp_t gfp) __alloc_size(1);
+
+#define __alloc_percpu_gfp(_size, _align, _gfp)	alloc_hooks(		\
+		__pcpu_alloc(_size, _align, false, _gfp), void __percpu *, NULL)
+#define __alloc_percpu(_size, _align)		alloc_hooks(		\
+		__pcpu_alloc(_size, _align, false, GFP_KERNEL), void __percpu *, NULL)
+#define __alloc_reserved_percpu(_size, _align)	alloc_hooks(		\
+		__pcpu_alloc(_size, _align, true, GFP_KERNEL), void __percpu *, NULL)
 
 #define alloc_percpu_gfp(type, gfp)					\
 	(typeof(type) __percpu *)__alloc_percpu_gfp(sizeof(type),	\
@@ -136,6 +142,9 @@ extern phys_addr_t per_cpu_ptr_to_phys(void *addr);
 	(typeof(type) __percpu *)__alloc_percpu(sizeof(type),		\
 						__alignof__(type))
 
+extern void free_percpu(void __percpu *__pdata);
+extern phys_addr_t per_cpu_ptr_to_phys(void *addr);
+
 extern unsigned long pcpu_nr_pages(void);
 
 #endif /* __LINUX_PERCPU_H */
diff --git a/mm/percpu.c b/mm/percpu.c
index 4e2592f2e58f..4b5cf260d8e0 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -1728,7 +1728,7 @@ static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t s
 #endif
 
 /**
- * pcpu_alloc - the percpu allocator
+ * __pcpu_alloc - the percpu allocator
  * @size: size of area to allocate in bytes
  * @align: alignment of area (max PAGE_SIZE)
  * @reserved: allocate from the reserved chunk if available
@@ -1742,8 +1742,8 @@ static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t s
  * RETURNS:
  * Percpu pointer to the allocated area on success, NULL on failure.
  */
-static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
-				 gfp_t gfp)
+void __percpu *__pcpu_alloc(size_t size, size_t align, bool reserved,
+			    gfp_t gfp)
 {
 	gfp_t pcpu_gfp;
 	bool is_atomic;
@@ -1909,6 +1909,8 @@ static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
 
 	pcpu_memcg_post_alloc_hook(objcg, chunk, off, size);
 
+	pcpu_alloc_tag_alloc_hook(chunk, off, size);
+
 	return ptr;
 
 fail_unlock:
@@ -1935,61 +1937,7 @@ static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
 
 	return NULL;
 }
-
-/**
- * __alloc_percpu_gfp - allocate dynamic percpu area
- * @size: size of area to allocate in bytes
- * @align: alignment of area (max PAGE_SIZE)
- * @gfp: allocation flags
- *
- * Allocate zero-filled percpu area of @size bytes aligned at @align.  If
- * @gfp doesn't contain %GFP_KERNEL, the allocation doesn't block and can
- * be called from any context but is a lot more likely to fail. If @gfp
- * has __GFP_NOWARN then no warning will be triggered on invalid or failed
- * allocation requests.
- *
- * RETURNS:
- * Percpu pointer to the allocated area on success, NULL on failure.
- */
-void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp)
-{
-	return pcpu_alloc(size, align, false, gfp);
-}
-EXPORT_SYMBOL_GPL(__alloc_percpu_gfp);
-
-/**
- * __alloc_percpu - allocate dynamic percpu area
- * @size: size of area to allocate in bytes
- * @align: alignment of area (max PAGE_SIZE)
- *
- * Equivalent to __alloc_percpu_gfp(size, align, %GFP_KERNEL).
- */
-void __percpu *__alloc_percpu(size_t size, size_t align)
-{
-	return pcpu_alloc(size, align, false, GFP_KERNEL);
-}
-EXPORT_SYMBOL_GPL(__alloc_percpu);
-
-/**
- * __alloc_reserved_percpu - allocate reserved percpu area
- * @size: size of area to allocate in bytes
- * @align: alignment of area (max PAGE_SIZE)
- *
- * Allocate zero-filled percpu area of @size bytes aligned at @align
- * from reserved percpu area if arch has set it up; otherwise,
- * allocation is served from the same dynamic area.  Might sleep.
- * Might trigger writeouts.
- *
- * CONTEXT:
- * Does GFP_KERNEL allocation.
- *
- * RETURNS:
- * Percpu pointer to the allocated area on success, NULL on failure.
- */
-void __percpu *__alloc_reserved_percpu(size_t size, size_t align)
-{
-	return pcpu_alloc(size, align, true, GFP_KERNEL);
-}
+EXPORT_SYMBOL_GPL(__pcpu_alloc);
 
 /**
  * pcpu_balance_free - manage the amount of free chunks
@@ -2299,6 +2247,8 @@ void free_percpu(void __percpu *ptr)
 
 	size = pcpu_free_area(chunk, off);
 
+	pcpu_alloc_tag_free_hook(chunk, off, size);
+
 	pcpu_memcg_free_hook(chunk, off, size);
 
 	/*
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-32-surenb%40google.com.
