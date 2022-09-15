Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDX6RSMQMGQEGC7N2XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D6505B9DFA
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:04:47 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id y17-20020a056512045100b0049e83e1053fsf900507lfk.9
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:04:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254286; cv=pass;
        d=google.com; s=arc-20160816;
        b=PRAlGzXVWfkdjpt8lNRoTcdwp9RvCVTiyISLIzke0gwDPxJwvGQYZ8lz9XDQkmZwBK
         BerRSAaDoqX8chOQtF3fl/IjZX1qDMM4EJ3um2PXvP+2rdLbU/t9V9ZQ0RykzkGjxuSl
         9t2Ee7uEWPIJ8ed+rSCxfSHIivF1li/JJRKq58kgDreWKp83Bo6Rn+igIW1+LL9ZZP9k
         B1MpjQznqws0+FjP+qIct647FuepTFlQRnHoXYoSbzDQHz/P6tjd+K1tSli7uK9juPKL
         YziLVXZu6gKioAW5ftDO9WiiZ8+aJ8b4BuKF/WsLmABjY/QsvFp6SGLI1pkNEHi53mo+
         44mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=q3boPlfUPF+GKAheIi4fTYvqgQFxQgdwpZIKExSZKc4=;
        b=Icko26DVIyT2a3mAPtEMsk2zZto9VPJTsJxfae6giKQolhCyopBwJHW7rQ24mr4Vt+
         yp0V9DVEmOJKAhbSYF/nRTiN7USa2ytYZ8kxP97R23wOTQBdsa1TCt/U9NjEWNaWoMai
         BHJCDsYu/cXz9XGvrqbc7Eo0Tze/A7pkqpoW4x5R4hor05FqbjaXAXDD2AUi/QcVzx4h
         ojYklmEtEVCHKMxWSX0X7hJbtgODkSnXIgjWloaYAKfGj90APLbF4KLFhV+OAeynl+So
         Xku/1fo1WlvRLzdpw14HbotQJn/Xx5Qx48+kG15eJjSZpjfapROjzDVmRbiK8mxyNB10
         oJPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gS6j99y0;
       spf=pass (google.com: domain of 3cj8jywykctuxczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Cj8jYwYKCTUXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=q3boPlfUPF+GKAheIi4fTYvqgQFxQgdwpZIKExSZKc4=;
        b=ihjG9vsYSWBGxr4ww9M4cTMKMh2umRmqV6cFIAQqNMqPNkyzr4IN3KO4bIVoS3ODsx
         cKu/LBr3r/bsApX1pf9ZXsXzUdpsNvEZ2L2kTK+K2CeRbNmG4M1t/KFn8wPPyQ9Z2I0/
         ApHMpkZkphRDXtUP9NyyY9b9reGeeBf3MjBPjehQ1z1q3RAXWOBHHjDECOrf4Bf32a3m
         0m00MViqISO9COAoF6nlkYPxCSu3zQHgNFPcobxXFvFnUZs7cvGv5oBiD6cDWqThR9u3
         Fqz/zGbjDwk2MppDq7UxNDSPRURj2+Fidt1s+nPHQwbdh5NXFd6tuBIFLHn75K/15zep
         b04w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=q3boPlfUPF+GKAheIi4fTYvqgQFxQgdwpZIKExSZKc4=;
        b=uo141AwvJaxSklS0QmgPzwdnOy2GhWhfVJlecQZQIYZH8H2dAQVSp80htxyzWOA+JS
         CAKb6UhXw4siEzqkML0VvtzTENdbGo8xJfTfz82zfN9k7LI/O2qKzQsQ3/r5Hs5OcFC2
         jrAr2S34yhwsHIrHqfyRLu43UNwQ3Dkv7eQfbwAoxUCJx30niPcSW46HLNxtcRWo2nfb
         KMPuruVIkYOBGZ6zb5GaPA/rl++292CtVR3kLknHW8MpPFbNwVf3MWV82mH2Cahu4yLc
         qdhtaNl9ypwbqv7Wlsa+TYeY37Z1tVhZ8sBo+XqdASedfW5uhfISjRivrS6rZOO7dpj2
         02PQ==
X-Gm-Message-State: ACrzQf2QwvhQ900PzaBAbOcE9oyOgWFRslRyaNlWshExL6Up51//vkc6
	2phFcsSmlFf9JkTvtTIQZc0=
X-Google-Smtp-Source: AMsMyM50YOU2ZuNciN9y/jG/gnSK1xv491uhU1Ks5ri819IrZlsgCIsOgOMdiGMIyB1Nuu+a2zW3qA==
X-Received: by 2002:a2e:b16a:0:b0:26b:df20:c9db with SMTP id a10-20020a2eb16a000000b0026bdf20c9dbmr70358ljm.8.1663254286344;
        Thu, 15 Sep 2022 08:04:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e24:0:b0:49a:b814:856d with SMTP id o4-20020ac25e24000000b0049ab814856dls1226462lfg.1.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:04:43 -0700 (PDT)
X-Received: by 2002:a05:6512:b08:b0:492:87ad:5f5c with SMTP id w8-20020a0565120b0800b0049287ad5f5cmr118882lfu.293.1663254283507;
        Thu, 15 Sep 2022 08:04:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254283; cv=none;
        d=google.com; s=arc-20160816;
        b=UYQDWfOsslrsl3+fVVbqDUOTh8k7NOQdAuIo6NJepEqPrZx9Mbf+dLGYirJfHyNEGS
         rhZHwYvH0J9o6/+WE5ucqvU5QbjrqL1h6h4VbZEJ9j54I8Ki7RYRQkplv9FqcMHtGPtt
         UjqPotP2RAer4L/esalx0/H8yZTVyTkGqjRgTynIH8KpstGdIdFAGfzxw6i9j1QvY3QO
         U5R57Tt8ZUdLJ7qlgRIEkhZD6St8rsmpitL95/dMYZScwQA976WP9XQbSX66Uvlidpke
         tntH9tXx5352Nq2WKsxmC4EB4+CV4IzfXFtZiZ2ZVZcG8ED4MfNJpFoIV1xDSAfGQD8G
         JePQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=myl6nRKQ/2lBkAfAPAxtf2MFDBMrGN4kiGAEDqUjhHA=;
        b=SZFFrqPhD0saSfLRKoFLUObf0Umx51UHPo9tN4IzPmhT/DKcuCsZJm+TDctsTS0S5I
         m4esngCBcraUb77txn+MaWvH+G4KLziBiG0J3lPtb5aKk0Lw0/CfkJW2hSwClUm8TT3h
         NuY2Lqpa80AheTtOF4opcKthHRoiaJKZAOYKRC6wE8ns2lqVW6eaKYJK0DZE7ycfS7cK
         9YbOffOHWCHVzUT9R+6+Nsjfm4BpyXeIv+/cF6gERFPevPzIEw9ZD7H6pbv2kt6FwWsh
         RFOdoUrNCkkzDgf1lIUHE33hjR5Pgomz5WceURx60kTcV5Ug5XkOu59yqkNOQxjdDYLg
         Jo3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gS6j99y0;
       spf=pass (google.com: domain of 3cj8jywykctuxczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Cj8jYwYKCTUXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id s7-20020a056512214700b0049ba11e2f38si283745lfr.11.2022.09.15.08.04.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:04:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cj8jywykctuxczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id t13-20020a056402524d00b00452c6289448so3773275edd.17
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:04:43 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6402:43cc:b0:451:129e:1b1e with SMTP id
 p12-20020a05640243cc00b00451129e1b1emr273421edc.258.1663254282917; Thu, 15
 Sep 2022 08:04:42 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:36 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-3-glider@google.com>
Subject: [PATCH v7 02/43] stackdepot: reserve 5 extra bits in depot_stack_handle_t
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gS6j99y0;       spf=pass
 (google.com: domain of 3cj8jywykctuxczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Cj8jYwYKCTUXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-3-glider%40google.com.
