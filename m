Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE67U2FAMGQELSFPYWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 943FD41314C
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 12:10:28 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id c6-20020a05651200c600b003fc6d39efa4sf4764519lfp.12
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 03:10:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632219028; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZUIFZf1+jDuANkKLXpsfyqJ0wbOIm9svysOP8QucUplbu4IRFAQ4qJBbUrM6K1VLZH
         1HoOT3ia4mM2IfMujeHRuSFXInCQ8DwBKHgjMAmBqDnmEp1HgOBTSra8Rs4dTLtj94UZ
         s2Fj/AZVrEgCQrb3+640sLfPEPPvJd5LD2fydyk7wB693CMSfGQtW/XBebHG6fmCrLzW
         yY8cORBcoARCJmdz/3Q2PBm1dmA0IOXRMhiUzG7ABsZ1unj3i0rz4sn4cIMZWbe8unV1
         wEsV7uiNA75aUpk3ObEfDFuR9sz8HKC+/i9rEPkz5KFQVUi2dKMEWV71CXLcEYDdaV4T
         SKlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Gi/fkVTsOu3cyeyrFgPNtlUnKnCeizTrSGe2u4QzpVw=;
        b=iSaA/1WdU2oxO58LxzQewpX9XkSPFK/95FPWEu4QS+6flzY8LRY2ofA2/jnqWJQGct
         5tyUT6BIHT5+07SPmfOxYL4BQJABUH0OT7HhYP0G6sY7Q2cslhD8Jh2ycj/oqOJoM/0h
         dCYugvMryA70i/Eit8sFSLSF3z9uXdOkpixa3ceDAF6fJPORsBMGURvxGuJ4V/ktu+Fi
         UdiRXl+IFXrdaq3VmxafiGCzV37x8a8KvIKQ5UJe/NbZROSmQ3Cf//UNTTXELxZdB64q
         ltT6nSoeiUv05iAkCc6ztFtHi7nd8Mu63LyC3HMUDC5CNPG1KMl7z07zwt/av0cbdaOj
         bUDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FhrffzQu;
       spf=pass (google.com: domain of 3kq9jyqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3kq9JYQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gi/fkVTsOu3cyeyrFgPNtlUnKnCeizTrSGe2u4QzpVw=;
        b=J8wN3M5BZiCXeRX6Ht0wPkyntAPV2zhMEZZgUqCRLWxFF9jAHMjG43+Irs+p0B7K/h
         sN5Niit/zIZNIwaWMc9cB92W1dDT/tlz12UPimgwU9MdpSa4lrJkFEJ/Nc6samwEYivn
         /888siuFzj8EMgREgtxW/+kRoecDGSpJ4CJRUlCgpGnvFoieyso5LvQWAPFUOymlD/T1
         23XmUxnbMXmZcxSObYyYlh847UBc/P3Z6QBLcAKLw4cBAGda7Bxet39kD9+50V6D42Dl
         rTn3lr9vUyMjG54w1PrhfWYCGX3/KFP8vJoY4uN+j5hfkl0RcQyLQ7PMbwbtTVgcdDnh
         4yMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gi/fkVTsOu3cyeyrFgPNtlUnKnCeizTrSGe2u4QzpVw=;
        b=nLlImlKmuFg8GuY8Lq1iuhqy+kXHlWU6iNtrIg9pve+PVZY8Zn7vlCALvCtpiGd9Vw
         S1pt3i5sOymOwxbKLpqAbZCmZ9L4SW17gtYMpOyGWAPMvvrQrjOflhhEROPhBh/yBQC4
         aqhB9enmuxtfswI2VxM46tWZX3N1/1oCAAl8fjn1GIRoooiQL6z7325sghcH76Y+q6hd
         VXscZrGSYYIvoqkJo8vQJzJMQur9AvvBbko3WqlujWCsXDVieRupRXsvTCcrgo5FLwiT
         jcHf6an70zSgSyPC+wjiv0rmPL8VFR6lJu7BUxqHmDSJQe1qgmgH2vOqu9gqUx16gDLO
         f8TQ==
X-Gm-Message-State: AOAM530JmAtPT2ymLdw3x7CouACIhxQArfbwU5AjTAoRr96e2xNIAnN4
	Mh+XkixXB96jimpF1XwIVVE=
X-Google-Smtp-Source: ABdhPJy+hkF2lopvFFyBkGuD3GZPQ1xyGPxPBSHoseUjbDkUfgs8t7PjAS/Ns7n7hcA/oVI9a771VA==
X-Received: by 2002:a05:6512:3257:: with SMTP id c23mr22301562lfr.90.1632219028075;
        Tue, 21 Sep 2021 03:10:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:5843:: with SMTP id x3ls3515239ljd.10.gmail; Tue, 21 Sep
 2021 03:10:27 -0700 (PDT)
X-Received: by 2002:a2e:3309:: with SMTP id d9mr14945563ljc.249.1632219026964;
        Tue, 21 Sep 2021 03:10:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632219026; cv=none;
        d=google.com; s=arc-20160816;
        b=qdvwnrD/NsZhPvqiXCsuZb8uC9wym9xgyLzCvbC2bwuX5No54AKbo4EqEhR1BLaL7Z
         FfRSoasznMkTSfndNSSNYIinF5/o4HYq4b9R5UnwvmMgDpOHVKLfq8QVODdG3Nhjy0kb
         aP/4rvwYKGo0kOqpjw2KzYI2sg6lsTKUWIt2kw6PyaCi0iUoQrcVCVUGPrRuNmskV6h1
         K3BgwK289MCaMR2Z611D5F+lNcKjtBFkYGJfKJXQM9GUjQI7pBQsrHCutcR7N0g1jkDZ
         nSO3CD7B0YzEw+8icyQQUEGkZl8Gb8ltUGic9KVl98RwazluoDdWdiSnoQGWIR5qgx5K
         qwOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=4f6yUJ+4Yot7zlWdOonsXRBu3J0/vvau8TCpbcwqOZE=;
        b=bpzUI05R6fMZ26R6z/IOx4XuYrq0wVO7LdAEO9nguD+OrnL7xdpcDQn8gj89f3fI2F
         metAVV4wqOftH6CmtkMr7kCFrBRJ49tX2MpeTCkL9TPkL72Kp6dd8jk42uLsp4XjZUeu
         Fr9b7ib0AdhR/cAaHInhgly9+ibyKGJapOjS0iGqG4LU30bzYnRESkDGT2TWEKrNQ3dt
         qbPEHf7/x92pWIXL+ISHYd/YrtWL1K5TqpoW0nxeShEIzp0A7tcS8pIy0L+0K0rprHj5
         ip8CG1wS6FHQJafCMu1r2ZTKDa0M4+EaSqfToLHVEuFg9sGGt6jDfZxm6AaKzCak2qgX
         v59A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FhrffzQu;
       spf=pass (google.com: domain of 3kq9jyqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3kq9JYQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id e14si1437271lfs.11.2021.09.21.03.10.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Sep 2021 03:10:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kq9jyqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id v15-20020adff68f000000b0015df51efa18so8370459wrp.16
        for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 03:10:26 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:dd03:c280:4625:60db])
 (user=elver job=sendgmr) by 2002:a05:600c:4f55:: with SMTP id
 m21mr3560923wmq.149.1632219026385; Tue, 21 Sep 2021 03:10:26 -0700 (PDT)
Date: Tue, 21 Sep 2021 12:10:12 +0200
In-Reply-To: <20210921101014.1938382-1-elver@google.com>
Message-Id: <20210921101014.1938382-3-elver@google.com>
Mime-Version: 1.0
References: <20210921101014.1938382-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH v2 3/5] kfence: move saving stack trace of allocations into __kfence_alloc()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FhrffzQu;       spf=pass
 (google.com: domain of 3kq9jyqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3kq9JYQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210921101014.1938382-3-elver%40google.com.
