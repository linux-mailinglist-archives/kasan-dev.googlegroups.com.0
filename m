Return-Path: <kasan-dev+bncBCCMH5WKTMGRBW4G7SKQMGQESQ5A3LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 27E26563507
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:24 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id b40-20020a2ebc28000000b0025c047ea79dsf457707ljf.23
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685403; cv=pass;
        d=google.com; s=arc-20160816;
        b=g5ecFzlHrqGxGFh4+ykp5o9mo9xlRp8TVbPXzhr5WVpiX3osJ7sKb/X4oUoGZfNv5w
         3zYEyNFrMKQ1Gv5gaSjyLcxis0aZUBc5efXim2AENJQUJXWYNGc6+sU8s5TH2VLdd7rZ
         4hfgn9j91GIZLVvu6xPGsIJl3z2IDXPXEJdDEqxT9M56T8e8oUGgP6V98Ap2RoxkIOco
         FzcZ5WKydAH3xu/GMP/QJ7O+h/Fb8LtyU7dzX6OUhYMc3M2SU1W6IQHDtvwuX+u0qv/d
         ZqnDSFd2F3YxjiDsJB3/ELSpw/f1jnnNo5jJhO9MMFALtIhshRS+qCO53da1CCWXPo1I
         Mc4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=OjD9xNMOcGzdPNt23Zb2kNTd7lQzlxAz6qBqbN0xhQU=;
        b=m1conWvdaKA2kMYtLObsZF4VCSE57UL3B31c1PajounFxJgs417DQg0o0CcSzCZEqT
         ZxZ/AWGOJIiCjIA5P+/aHCKG/oUICPXvKPlS5TOCdp6QDx17HKmSW2G3sJ5qILuLU5Aq
         ozhzcJ1KwqbCTLVCI7MXryYdeK41pqZ0k6043T+4GoIlzQJ7LmKxaNpTjfiUJazPlYcv
         LsI2dMYIqoM874TT2KUkmUrXIPWORS44cqOfps5sVaX50UbL4WHciF897Rc9PvC2h/49
         YvjgrlKkyb0wT+0RaLsqinoodfy6bUATOzsxmDNh8U2zzah70h7fBwQ2qzvSjh7RLaIg
         f7Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EefzW4eC;
       spf=pass (google.com: domain of 3wqo_ygykcxgchezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3WQO_YgYKCXgcheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OjD9xNMOcGzdPNt23Zb2kNTd7lQzlxAz6qBqbN0xhQU=;
        b=U58SnE8K9RuENno6Nsp4+Wl4EJs9UTVmEgidmM5TSvMhSCbipu99FOB2s6gi9MCtUg
         zkGy9n9GVL0cSPmP+1iiCeAVfTQZ6mStwdSm2oBP/MH9YTuPwxkOyPxT0+wIsfneEZy8
         MwSkjBxTSvf5C+V7Cr1En7rrhDfMY9PXcbDd9eeqKqmD1EDohB4cWNyprbRs3VqgKGzp
         /aPhWqu3ur0XMmCkODvEd9fEiOBdiY0aVQaaejTRmg3U0Z6QO7TuGoPmBzNPu/AZ4FRO
         Ra58FoZc3hC2/Y8oeO8IKJxUjfpk9pbGbNfH+P45GhTEADNmXUvUOtwcPbEZowq8KZ7p
         hLlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OjD9xNMOcGzdPNt23Zb2kNTd7lQzlxAz6qBqbN0xhQU=;
        b=yRxo3FPGIZsNhZnmCS6QMqw0oLCTHJdlVzBaM99KYMJG1JA/xQjmOwYrGAI9vMiDvN
         gz05+1rDF7g2SPE5WA6aUae3BnUfbyAjLlI99HvRJ1CuvPshO3//czQHnGGqKqlfJI/P
         5vn6ePd72ZOxsTPZyGgcp87tHK6AMi2ifSt/xVLmc6ZxwaDhMzF52YMJpEQm7SgueBvx
         9l8gRW1QAY87YSegJhhyzwkZNlXPlv3ftg4zrztmIyBOdsDS1InqU/Nd4dqiGziaNvwc
         zNYdJfLTtw+NYbvaARz2bQ/HFaQY7adkuYFuxqUUF0vtk8uET8Gc3FTjvG4GDDuPz8HE
         YZTA==
X-Gm-Message-State: AJIora/Qv7Anq1G5lQERCx2WukHsVL8U0SueW+vMVnHL8emNfBdzUw6I
	0oSRFMHSAmoPpVRCZzm9EY4=
X-Google-Smtp-Source: AGRyM1uCbi0kecm/IudvdTTCN0ufLdBfshFUTJwugaTdiA4GcfQ+9zj48v+WcSBacUUhvYwXKK/uiQ==
X-Received: by 2002:a2e:964d:0:b0:25a:8dd5:cf04 with SMTP id z13-20020a2e964d000000b0025a8dd5cf04mr8661029ljh.278.1656685403670;
        Fri, 01 Jul 2022 07:23:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls85636lfn.2.gmail;
 Fri, 01 Jul 2022 07:23:22 -0700 (PDT)
X-Received: by 2002:a05:6512:1053:b0:47f:915d:b14f with SMTP id c19-20020a056512105300b0047f915db14fmr9213952lfb.661.1656685402084;
        Fri, 01 Jul 2022 07:23:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685402; cv=none;
        d=google.com; s=arc-20160816;
        b=yk4zkpIN9MMwMZqczSVFI2WGOhE5E0CX2bxCL6PfRnBffdFzAVmV8BXM2x5CZPiiFX
         eCNUpvIQx0WyV/3G9c90BLOMviYIyIiaYjA97O5NYlm70qBQuR08D/BF5Ic6WlUSJNvW
         qB3+r8ApIIE/+I1qZ6ZeeXN31r5LFGcQRK1lAITar0h8wtkpZtLwmmHzc0B8wsnGHYtP
         NvX4n5c273LN3Y3bRrZVnSVUmwoKGhpIhBn8l1AlM7Iqcz5/uq6T6pVE71Qc3Ovd49EG
         MPe1OjRuOTcUJzGfA6tvFBvB6gzY6T2FeYghvheOJcbSiH0HQcpJ2YEUSa75ub3WhQCV
         OHsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=CwX7/lGI7AR80Huh7duB2nRTvZ0igKEJIu5G+Gv7rzk=;
        b=IRvk54is0R5nM+NktSXIJiXmnsWcgxyJa6n6DeHlJpsus4Xt028rbPsfUcBgK22/jI
         SzD6F4W12y5XpRzvkDu4cRaub0OrtphzHiXK8bCXyyN99Im9E641wz3fgrfgsRGnOc8i
         ZBrRw+tQUYwg0ip4hxrVgbJY6PLhhVCS1hr3OSydOEm/gtjx92FZOajcOJPRMp3++1GW
         bvNl49nrQSK5nUhbl88dZ25YQyG1KO9QA1nEBzDs4Ba7yFh4AxR6SGh3q7ewc/0YQ7gZ
         eOqbp9Jshuk775LWMuA7z4b0MbxLI878N7b9mE/pIO2fOL72Go/RmDyGojLh5ZxdwC8w
         Cfpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EefzW4eC;
       spf=pass (google.com: domain of 3wqo_ygykcxgchezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3WQO_YgYKCXgcheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id t28-20020a05651c205c00b00258ed232ee9si845176ljo.8.2022.07.01.07.23.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wqo_ygykcxgchezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id x21-20020a05640226d500b00435bd7f9367so1884152edd.8
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:22 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a17:907:7da1:b0:726:9562:b09f with SMTP id
 oz33-20020a1709077da100b007269562b09fmr15604327ejc.11.1656685401482; Fri, 01
 Jul 2022 07:23:21 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:27 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-3-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 02/45] stackdepot: reserve 5 extra bits in depot_stack_handle_t
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
 header.i=@google.com header.s=20210112 header.b=EefzW4eC;       spf=pass
 (google.com: domain of 3wqo_ygykcxgchezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3WQO_YgYKCXgcheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
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
index 5ca0d086ef4a3..3d1dbdd5a87f6 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -42,7 +42,8 @@
 #define STACK_ALLOC_OFFSET_BITS (STACK_ALLOC_ORDER + PAGE_SHIFT - \
 					STACK_ALLOC_ALIGN)
 #define STACK_ALLOC_INDEX_BITS (DEPOT_STACK_BITS - \
-		STACK_ALLOC_NULL_PROTECTION_BITS - STACK_ALLOC_OFFSET_BITS)
+		STACK_ALLOC_NULL_PROTECTION_BITS - \
+		STACK_ALLOC_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS)
 #define STACK_ALLOC_SLABS_CAP 8192
 #define STACK_ALLOC_MAX_SLABS \
 	(((1LL << (STACK_ALLOC_INDEX_BITS)) < STACK_ALLOC_SLABS_CAP) ? \
@@ -55,6 +56,7 @@ union handle_parts {
 		u32 slabindex : STACK_ALLOC_INDEX_BITS;
 		u32 offset : STACK_ALLOC_OFFSET_BITS;
 		u32 valid : STACK_ALLOC_NULL_PROTECTION_BITS;
+		u32 extra : STACK_DEPOT_EXTRA_BITS;
 	};
 };
 
@@ -76,6 +78,14 @@ static int next_slab_inited;
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
@@ -139,6 +149,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->handle.slabindex = depot_index;
 	stack->handle.offset = depot_offset >> STACK_ALLOC_ALIGN;
 	stack->handle.valid = 1;
+	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 	depot_offset += required_size;
 
@@ -343,6 +354,7 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
  *
  * @entries:		Pointer to storage array
  * @nr_entries:		Size of the storage array
+ * @extra_bits:		Flags to store in unused bits of depot_stack_handle_t
  * @alloc_flags:	Allocation gfp flags
  * @can_alloc:		Allocate stack slabs (increased chance of failure if false)
  *
@@ -354,6 +366,10 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
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
@@ -363,10 +379,11 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
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
@@ -450,9 +467,11 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
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
 
@@ -472,6 +491,6 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 				      unsigned int nr_entries,
 				      gfp_t alloc_flags)
 {
-	return __stack_depot_save(entries, nr_entries, alloc_flags, true);
+	return __stack_depot_save(entries, nr_entries, 0, alloc_flags, true);
 }
 EXPORT_SYMBOL_GPL(stack_depot_save);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index c40c0e7b3b5f1..ba4fceeec173c 100644
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-3-glider%40google.com.
