Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4NWWGFAMGQE66YBIIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C219415C35
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 12:48:18 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id e22-20020a05620a209600b003d5ff97bff7sf19156304qka.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 03:48:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632394097; cv=pass;
        d=google.com; s=arc-20160816;
        b=HOGg9DXD3tBWctsy/Set7g7AaDvt6gGy7t3R8+RwZmcC7IbdjpgySSabJ+lLLG55uM
         c8rKmCpnvBZ7BEv04FTkg7jPxeVyLKyQAO8U6fx9YKWMZzhSkbdMX8VtSrj769N65dP2
         tiLdWW+tH0aNuG5/UHAKbw3nd2lEYgw4D8FNHrJPi/uVzHFhx7A+9uIb8WBiFqFBBNJy
         KNVdD9hzu8SgZ8ddAgzJoCNDVRM9NQavqDoaPw50oTbJo5bhYmtmW68Dewqh3fNunrlj
         J5DyjEKBcojU3gj7HNbvccZ3B+tprKm5K5Ae8DhaoUqornQN1oW5gFQEY4HSzxROX7jS
         Roqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=wnRuy4wIL07k7Fs2pwWf/ia4VxWixuJ5XdOhBj3p1f0=;
        b=M6tpsT7DTjzy3+Ky1W8lVTC7AY6H1Yp+++myA79KjqXdf305mkL+KTb9r8Vda0wc8c
         EE1E1mJWrSLDQIjxYnu6EKSFlqy8vFgOvsdlSAkPmkpSfN8Wu5UNfbcC3yjqsoNp++wk
         0iqDPbxJvpxMLE+tHxLJJDhC945X5tWFoFvmhEfMzfimOF0REuG+el3UsxzjedI5Scv2
         A2j1hlA32wmEiU1VME0T4ba/T69i307jdgabLhmzhjsdAn9wSDxpJfoerelecjJmV8LB
         E+uHz+UU/XSkMnfYZNr1hltMvB4j5JexcSLbBt+XGFwCczDGo2vGeRn4HuAAG1dBf2u8
         5n9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RkZpopRF;
       spf=pass (google.com: domain of 3cftmyqukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3cFtMYQUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wnRuy4wIL07k7Fs2pwWf/ia4VxWixuJ5XdOhBj3p1f0=;
        b=UAVgT8j9MSORWsRD3cV3XADqh8rkoG9iUEFG2y1RPId82FqUh1U8slHcfdLAfiC+YN
         Oc8hCO8GEepqn9WhyyHZ7hlIAIm1tajkyTdQ1vidGFdG5Q2Qai0CeRsoRU3ZKLo42sIV
         NL0Vc3L8WdWVIoLld2hk3O7FlFqQtjem4i9MzgZ0UcNwlV1rQjS85kjKz9KVWsNHy+HI
         5tp4baxgPZPoesXjUCZpgSzFtMW654n9f9E6tVaF4CEBkBkUCSStMIH83YT/AiQMYp4G
         oIVEymCx9iR6ygi3EFfkVhiBTvQMkw509i0gfAcaUGGj2kaazNZM3KBI9xxpcFMw4pyF
         URzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wnRuy4wIL07k7Fs2pwWf/ia4VxWixuJ5XdOhBj3p1f0=;
        b=EuyCK2Yb91RbJknYmVUlqPGIxbGEz4QD5X7mtoOWY8O+2ln9IJKysNQC1Gs8nnutVg
         eY1Dxo3sk7ePLbeFbItM9xeGRJObvwgek9Po1njX8D6ruZnmepQjYDgQL+aIniXRn7l0
         gfDgg1GH8+dJC08C4tC4VBHtMkeNYx5r9dWBxQNsteCYaMvGPw09HcQOzihQApLhzDDL
         ZIUxYcTPQ45p8bbSnm1O6SY5FivBx3NOyYlaBu4fKJ+nb9m3vix6pVeNtPzv+elwAHR1
         Kpk8UhE7IPsKybXD6I2Bx9Nh+rJNWdvFmbmSWeBHuVRVJjy8QtXuSX4vqtePdXRouStL
         Mx1w==
X-Gm-Message-State: AOAM533cZYJxpa7TCLd2IyBoJ7HqfkVgJeRS+qMQeeT5jdhUzm7Dpv6Z
	H2+VET6mrr3RWOtMcnuOo38=
X-Google-Smtp-Source: ABdhPJwq8XiE3rRJH443a6BbO9duc53xqpSMYfqDahE62GxKjWthDxUVOP2xrUzenVA2DeFxvQbjFg==
X-Received: by 2002:a37:9b16:: with SMTP id d22mr4120259qke.22.1632394097258;
        Thu, 23 Sep 2021 03:48:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:100f:: with SMTP id z15ls4010130qkj.2.gmail; Thu,
 23 Sep 2021 03:48:16 -0700 (PDT)
X-Received: by 2002:a37:2d05:: with SMTP id t5mr801562qkh.360.1632394096815;
        Thu, 23 Sep 2021 03:48:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632394096; cv=none;
        d=google.com; s=arc-20160816;
        b=hcPGIFVtRDV/jjZIth/3pUkaaKCa98jcAXQ2hJFUEiDW9jc1vXRcvYGokllhEjsafZ
         5OpIcvWsh2qA3hslt9vTqJhBkukRRbsiyxcvLf5wdyH0dqw0NYSKzV6MzwYcvExfsepb
         fzYxUryysfrfN5zWgylI5o7KqvOvED4WI9q0qQkvO01uANQAAYBWPZYcUo5Ce35YhQVV
         h4JQQt6J2OCzIk9G4RKm2QI8yBbukfFnCvBuJqHDouarNG4K4tJP259XV5bX1VNdMoqJ
         8Z0un6mXhLLRGQuggsiT8lHuaC5poV17vOX9gS2TKwQVaAZKR/nMSVYJvE3EjWLIjCTU
         EZ5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=QoufVORGRixTO8MhoQUDRlzmXbjgEZCp2vEpgCNZeS8=;
        b=d3VsDJReyihMl+W6m+sIe5L+STD7XmU/SMKJZecomgRIlMgJd8+z0P1PmCSV0I8Ngv
         teWni7W+88kwMtyLcRbRY+WGE+s21j9QGr9Q3DSLvOXXb5OZySnaceM3mjcMXWGwzCAD
         66ZNAY1/ExFrSwGP8VM+SFcDdz9dZ1v0LS10Scilx92qlNTTP5irjLLZrKVoqnTGuEg3
         K7Gu/L11jy4FmAF9AyIpVGrIarpNTIJ/WOnWjcaqpJqcl2Bh6qgMUDN3clJQD8eZYjkZ
         efbuCOZhDJRIus84xKwKc/ymX/PEmPzABDAsdenJdwAVzjyHBNyjgIJWSDaHLDoM1Iy5
         1Ovg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RkZpopRF;
       spf=pass (google.com: domain of 3cftmyqukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3cFtMYQUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id 11si772888qtu.5.2021.09.23.03.48.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 03:48:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cftmyqukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id h4-20020a05620a244400b004334ede5036so18344710qkn.13
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 03:48:16 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:bd72:fd35:a085:c2e3])
 (user=elver job=sendgmr) by 2002:a05:6214:406:: with SMTP id
 z6mr3769082qvx.34.1632394096539; Thu, 23 Sep 2021 03:48:16 -0700 (PDT)
Date: Thu, 23 Sep 2021 12:48:01 +0200
In-Reply-To: <20210923104803.2620285-1-elver@google.com>
Message-Id: <20210923104803.2620285-3-elver@google.com>
Mime-Version: 1.0
References: <20210923104803.2620285-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH v3 3/5] kfence: move saving stack trace of allocations into __kfence_alloc()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RkZpopRF;       spf=pass
 (google.com: domain of 3cftmyqukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3cFtMYQUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
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

Move the saving of the stack trace of allocations into __kfence_alloc(),
so that the stack entries array can be used outside of
kfence_guarded_alloc() and we avoid potentially unwinding the stack
multiple times.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
v2:
* New patch.
---
 mm/kfence/core.c | 35 ++++++++++++++++++++++++-----------
 1 file changed, 24 insertions(+), 11 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 249d75b7e5ee..db01814f8ff0 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -187,19 +187,26 @@ static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *m
  * Update the object's metadata state, including updating the alloc/free stacks
  * depending on the state transition.
  */
-static noinline void metadata_update_state(struct kfence_metadata *meta,
-					   enum kfence_object_state next)
+static noinline void
+metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state next,
+		      unsigned long *stack_entries, size_t num_stack_entries)
 {
 	struct kfence_track *track =
 		next == KFENCE_OBJECT_FREED ? &meta->free_track : &meta->alloc_track;
 
 	lockdep_assert_held(&meta->lock);
 
-	/*
-	 * Skip over 1 (this) functions; noinline ensures we do not accidentally
-	 * skip over the caller by never inlining.
-	 */
-	track->num_stack_entries = stack_trace_save(track->stack_entries, KFENCE_STACK_DEPTH, 1);
+	if (stack_entries) {
+		memcpy(track->stack_entries, stack_entries,
+		       num_stack_entries * sizeof(stack_entries[0]));
+	} else {
+		/*
+		 * Skip over 1 (this) functions; noinline ensures we do not
+		 * accidentally skip over the caller by never inlining.
+		 */
+		num_stack_entries = stack_trace_save(track->stack_entries, KFENCE_STACK_DEPTH, 1);
+	}
+	track->num_stack_entries = num_stack_entries;
 	track->pid = task_pid_nr(current);
 	track->cpu = raw_smp_processor_id();
 	track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
@@ -261,7 +268,8 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
 	}
 }
 
-static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
+static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp,
+				  unsigned long *stack_entries, size_t num_stack_entries)
 {
 	struct kfence_metadata *meta = NULL;
 	unsigned long flags;
@@ -320,7 +328,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	addr = (void *)meta->addr;
 
 	/* Update remaining metadata. */
-	metadata_update_state(meta, KFENCE_OBJECT_ALLOCATED);
+	metadata_update_state(meta, KFENCE_OBJECT_ALLOCATED, stack_entries, num_stack_entries);
 	/* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
 	WRITE_ONCE(meta->cache, cache);
 	meta->size = size;
@@ -400,7 +408,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 		memzero_explicit(addr, meta->size);
 
 	/* Mark the object as freed. */
-	metadata_update_state(meta, KFENCE_OBJECT_FREED);
+	metadata_update_state(meta, KFENCE_OBJECT_FREED, NULL, 0);
 
 	raw_spin_unlock_irqrestore(&meta->lock, flags);
 
@@ -742,6 +750,9 @@ void kfence_shutdown_cache(struct kmem_cache *s)
 
 void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 {
+	unsigned long stack_entries[KFENCE_STACK_DEPTH];
+	size_t num_stack_entries;
+
 	/*
 	 * Perform size check before switching kfence_allocation_gate, so that
 	 * we don't disable KFENCE without making an allocation.
@@ -786,7 +797,9 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 	if (!READ_ONCE(kfence_enabled))
 		return NULL;
 
-	return kfence_guarded_alloc(s, size, flags);
+	num_stack_entries = stack_trace_save(stack_entries, KFENCE_STACK_DEPTH, 0);
+
+	return kfence_guarded_alloc(s, size, flags, stack_entries, num_stack_entries);
 }
 
 size_t kfence_ksize(const void *addr)
-- 
2.33.0.464.g1972c5931b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923104803.2620285-3-elver%40google.com.
