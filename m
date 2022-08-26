Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZGDUOMAMGQEQZP2CCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id E025B5A2A5B
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:20 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id sb14-20020a1709076d8e00b0073d48a10e10sf725050ejc.16
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526500; cv=pass;
        d=google.com; s=arc-20160816;
        b=jlERufHOzdA04XdCrxv1S2pZQeZu7M1HmL0QquIg7KhQZ1DSC/EU5PjUMOaO1ZCBBc
         5cM2J+ujUbieqxE1WtVwFrZe2coepfUmWiwuEUfIEjUlqDQH1khiiPR32WkpxN+lI5dH
         RVvyTkgUHCakcSsEFTzIGArsMirCePGLJXeNzKEkgwOImxq2MO+FzWpeh7N8wMJ7dHas
         U3AciJVAagV9wRXwuH4OKeUT44tc59vZkv4wee//S89ltHCX3KRgfT1+FbuZM9KjnTDr
         BYvHY5lENFEhvUiVXfITGFSXZbAr2Sq4EhjgqJSMfxz5lrhvvsZZjNM8RNegWL4SOIa9
         z+MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=jmSqT2+W7lq6UchGqjG49lFqiBuCBdho41zxEvkcZMM=;
        b=o8qSZM4wQdUc0vYBBNdZtyCerUWB/+6zAUdZSRJGCCgun7VUm8i/FXXQDDxVLssa4H
         /Y7Bbxofv6f2G85xjZUk7mejf+wZMvBdQmFTiRsisUVklI51Shmbf6Ta4z/+sepxorSH
         5TGRIGN3uwJl0wB5tmAJSxVRYDkZisemgp2DBAfMVV01d0mxLg4bhO4gMV1f8lQvOrNW
         n0BzWfZdh1Y5kf8IGxgfJHrErn6s8Qae3juKOsMNxwM9Sp2IpKRpwtcdx7C73rMh5OM2
         FI8M3LMXwdDGcY2QiC3ee401vJ60B2mFLYphd7MnjzqIhnB0lVEpk3b2nPIs8bEEt3Y3
         RN+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RA3+jZoN;
       spf=pass (google.com: domain of 34ueiywykcecpurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=34uEIYwYKCecPURMNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=jmSqT2+W7lq6UchGqjG49lFqiBuCBdho41zxEvkcZMM=;
        b=Ys6Vfw8VPynHXlgFEF7n6O2qeRLIEEQRf0k9aRuBQm3y3kLef61H76TaWUu1NWY+W8
         uGSvkNuPvYWed3G0pLDYSZaUh0dwMnWYWnA3W+KW8MQlV5tSWVn4X0wC4Q9qLM/nRVQS
         q5cW1+waEcs6vg4kOGxNaz8Ff6/I+Zk5h2cA2PqBXZv+Q38pxZY586RlUWvHyHxhpVkJ
         0mhzI50+LxUPqlWdXjQd2M9V6s8+b5IFn7B4CO4VYw4KFcoJBuuXUOf8QCUq7JnPMM28
         RygQZ4ox4Xi04nUDxF/i2iHO7Yngmcoh2EwtSAEuAI+ZjKpG6MmGGhPenqXXKzPE0Jo3
         59Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=jmSqT2+W7lq6UchGqjG49lFqiBuCBdho41zxEvkcZMM=;
        b=ybTJHFa5eILcPxSoq5uNo7zMwn3DnawPNetPICcR4DFUyTHlueyMsfYE4xwilyAmQw
         IU+/oW6+MN5tj5f1LW0ZLs7FpTK3stt2VxKGQBfRLqsVHgi8FbMJNhsvjbkD+cTvHRa1
         RpyTXGPyjDjBC+nx/TAkY21+MrWmjs1w7MOTcrO4gIET+FWKmhZf3smLFveCXrNsoLGe
         uMXKtzWj6lbRwpDwBGpo0YSWM8fucqEsarIsMDsz4hy2n2bODbhHVD8+pREv86q/kf+3
         IQVuWqVa8+p5DeF+h8NjKTeVZQDr3CCT25lhd9b/zEv3Iz/jUhTDipIIVA2tGeYmp+mR
         1lPg==
X-Gm-Message-State: ACgBeo1Yg2e4PpQWlenygyH7KQ+hS6vxr5m8Hj8qrbe88hU72nZoVO2u
	DbMBu9Qmn/hKh2KyF914aao=
X-Google-Smtp-Source: AA6agR68+Z0Eqe5+j1/d5g95Iw5pZaxQoMN7IeqK8qLpImj7pWdtYtFwM5gKkNgS786yAfMLNJSX3g==
X-Received: by 2002:a17:907:762d:b0:73d:ad57:e037 with SMTP id jy13-20020a170907762d00b0073dad57e037mr5797164ejc.405.1661526500375;
        Fri, 26 Aug 2022 08:08:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:2e8b:b0:726:abf9:5f2e with SMTP id
 o11-20020a1709062e8b00b00726abf95f2els2140918eji.9.-pod-prod-gmail; Fri, 26
 Aug 2022 08:08:19 -0700 (PDT)
X-Received: by 2002:a17:907:c05:b0:73d:6e0a:8d22 with SMTP id ga5-20020a1709070c0500b0073d6e0a8d22mr5688311ejc.646.1661526499314;
        Fri, 26 Aug 2022 08:08:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526499; cv=none;
        d=google.com; s=arc-20160816;
        b=NwMD58h4B4aBwR7+yMXFdPKCSHU+f7HKSrM8eTst6+ceTQmCz0ylJcTwGMAkaLdA2f
         u23B3QJwNkFUPMz+tCkf9Bz1MWaKdLJiqXBH4G8RQoXH2tGDqZh7ak7gOc2mrsCfXrYV
         KA7chM+MQN7SBh6Od7cLbxNm/1B7ntGTqI4OzjlV/QDRP9aXxt1gdfyXolehgziyeher
         Bafqlj2nyvSJNWPip784gyznsm6aDmPV3sL9MDS+PFkXaFXKvaLBywYpPM2ARII/jjW2
         q9mjVVyifviTuCP3QRqG+/pi2XE1VzWIFLca4y+dVYxERal1Yw3VL/0KlLRt2S9o1Fy8
         M8nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=omcyQ1o+RVSxzRVZJZY/qms7uBp4WMcvPZ8eVf62Bcs=;
        b=Oz00NhFqBBg0nifthpqnNrKusgkaFPKYfx4hH4OtlvlsQf9GijlI/uwVlR0ZGF5eRU
         kFH0g0pR/dfpE4Gef1hB1L1DineHAigliFLdKZsYu+fBsP4BtFGgiqUcSb06gwI4Q85/
         swqdHrsBnCPzsQecEUEWSubflj2xVFf40j5X8P/2HAy8lrOhJeS9ob8ZqdyWg5cvpjs8
         jM5Q+lwBC9j7i08eLDUgYlAYjYKK76EDjR8fvepbcJGQorT9V/hPltIL/kdrNkOMbIp0
         Tds11hHi2QXy5YtS/af5QtGFF1IAPh39f18khilIAfHyn6D+dp1RfyhfxJMyoirDkXZp
         uFxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RA3+jZoN;
       spf=pass (google.com: domain of 34ueiywykcecpurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=34uEIYwYKCecPURMNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id jx2-20020a170907760200b0073d9d812170si68507ejc.1.2022.08.26.08.08.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34ueiywykcecpurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id q32-20020a05640224a000b004462f105fa9so1237945eda.4
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:19 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:270a:b0:446:c9e9:6e00 with SMTP id
 y10-20020a056402270a00b00446c9e96e00mr6913543edd.315.1661526498732; Fri, 26
 Aug 2022 08:08:18 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:25 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-3-glider@google.com>
Subject: [PATCH v5 02/44] stackdepot: reserve 5 extra bits in depot_stack_handle_t
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RA3+jZoN;       spf=pass
 (google.com: domain of 34ueiywykcecpurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=34uEIYwYKCecPURMNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Some users (currently only KMSAN) may want to use spare bits in
depot_stack_handle_t. Let them do so by adding @extra_bits to
__stack_depot_save() to store arbitrary flags, and providing
stack_depot_get_extra_bits() to retrieve those flags.

Also adapt KASAN to the new prototype by passing extra_bits=0, as KASAN
does not intend to store additional information in the stack handle.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>

---
v4:
 -- per Marco Elver's request, fold "kasan: common: adapt to the new
    prototype of __stack_depot_save()" into this patch to prevent
    bisection breakages.

Link: https://linux-review.googlesource.com/id/I0587f6c777667864768daf07821d594bce6d8ff9
---
 include/linux/stackdepot.h |  8 ++++++++
 lib/stackdepot.c           | 29 ++++++++++++++++++++++++-----
 mm/kasan/common.c          |  2 +-
 3 files changed, 33 insertions(+), 6 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index bc2797955de90..9ca7798d7a318 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -14,9 +14,15 @@
 #include <linux/gfp.h>
 
 typedef u32 depot_stack_handle_t;
+/*
+ * Number of bits in the handle that stack depot doesn't use. Users may store
+ * information in them.
+ */
+#define STACK_DEPOT_EXTRA_BITS 5
 
 depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					unsigned int nr_entries,
+					unsigned int extra_bits,
 					gfp_t gfp_flags, bool can_alloc);
 
 /*
@@ -59,6 +65,8 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries);
 
+unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle);
+
 int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 		       int spaces);
 
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index e73fda23388d8..79e894cf84064 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -43,7 +43,8 @@
 #define STACK_ALLOC_OFFSET_BITS (STACK_ALLOC_ORDER + PAGE_SHIFT - \
 					STACK_ALLOC_ALIGN)
 #define STACK_ALLOC_INDEX_BITS (DEPOT_STACK_BITS - \
-		STACK_ALLOC_NULL_PROTECTION_BITS - STACK_ALLOC_OFFSET_BITS)
+		STACK_ALLOC_NULL_PROTECTION_BITS - \
+		STACK_ALLOC_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS)
 #define STACK_ALLOC_SLABS_CAP 8192
 #define STACK_ALLOC_MAX_SLABS \
 	(((1LL << (STACK_ALLOC_INDEX_BITS)) < STACK_ALLOC_SLABS_CAP) ? \
@@ -56,6 +57,7 @@ union handle_parts {
 		u32 slabindex : STACK_ALLOC_INDEX_BITS;
 		u32 offset : STACK_ALLOC_OFFSET_BITS;
 		u32 valid : STACK_ALLOC_NULL_PROTECTION_BITS;
+		u32 extra : STACK_DEPOT_EXTRA_BITS;
 	};
 };
 
@@ -77,6 +79,14 @@ static int next_slab_inited;
 static size_t depot_offset;
 static DEFINE_RAW_SPINLOCK(depot_lock);
 
+unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle)
+{
+	union handle_parts parts = { .handle = handle };
+
+	return parts.extra;
+}
+EXPORT_SYMBOL(stack_depot_get_extra_bits);
+
 static bool init_stack_slab(void **prealloc)
 {
 	if (!*prealloc)
@@ -140,6 +150,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->handle.slabindex = depot_index;
 	stack->handle.offset = depot_offset >> STACK_ALLOC_ALIGN;
 	stack->handle.valid = 1;
+	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 	depot_offset += required_size;
 
@@ -382,6 +393,7 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
  *
  * @entries:		Pointer to storage array
  * @nr_entries:		Size of the storage array
+ * @extra_bits:		Flags to store in unused bits of depot_stack_handle_t
  * @alloc_flags:	Allocation gfp flags
  * @can_alloc:		Allocate stack slabs (increased chance of failure if false)
  *
@@ -393,6 +405,10 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
  * If the stack trace in @entries is from an interrupt, only the portion up to
  * interrupt entry is saved.
  *
+ * Additional opaque flags can be passed in @extra_bits, stored in the unused
+ * bits of the stack handle, and retrieved using stack_depot_get_extra_bits()
+ * without calling stack_depot_fetch().
+ *
  * Context: Any context, but setting @can_alloc to %false is required if
  *          alloc_pages() cannot be used from the current context. Currently
  *          this is the case from contexts where neither %GFP_ATOMIC nor
@@ -402,10 +418,11 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
  */
 depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					unsigned int nr_entries,
+					unsigned int extra_bits,
 					gfp_t alloc_flags, bool can_alloc)
 {
 	struct stack_record *found = NULL, **bucket;
-	depot_stack_handle_t retval = 0;
+	union handle_parts retval = { .handle = 0 };
 	struct page *page = NULL;
 	void *prealloc = NULL;
 	unsigned long flags;
@@ -489,9 +506,11 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		free_pages((unsigned long)prealloc, STACK_ALLOC_ORDER);
 	}
 	if (found)
-		retval = found->handle.handle;
+		retval.handle = found->handle.handle;
 fast_exit:
-	return retval;
+	retval.extra = extra_bits;
+
+	return retval.handle;
 }
 EXPORT_SYMBOL_GPL(__stack_depot_save);
 
@@ -511,6 +530,6 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 				      unsigned int nr_entries,
 				      gfp_t alloc_flags)
 {
-	return __stack_depot_save(entries, nr_entries, alloc_flags, true);
+	return __stack_depot_save(entries, nr_entries, 0, alloc_flags, true);
 }
 EXPORT_SYMBOL_GPL(stack_depot_save);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 69f583855c8be..94caa2d46a327 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -36,7 +36,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
 	unsigned int nr_entries;
 
 	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
-	return __stack_depot_save(entries, nr_entries, flags, can_alloc);
+	return __stack_depot_save(entries, nr_entries, 0, flags, can_alloc);
 }
 
 void kasan_set_track(struct kasan_track *track, gfp_t flags)
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-3-glider%40google.com.
