Return-Path: <kasan-dev+bncBCCMH5WKTMGRBH6V26MAMGQEMCHTFWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 78DA75AD24E
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:04 +0200 (CEST)
Received: by mail-ej1-x639.google.com with SMTP id xc12-20020a170907074c00b007416699ea14sf2250564ejb.19
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380704; cv=pass;
        d=google.com; s=arc-20160816;
        b=sR2W+jBNwTxRzL//yhtQO0YUewk+I6Uq2SE0dhjrwocnxG9cfEKXragwUDF4Gx17ub
         1KDDGVqwGJHCIDxukQJ9H3scU9Lez/eB5Aw0fWh9mWE9i9ZFqU9J+rAEqKRqPJWmE3TT
         uFA7rBsJIruI1niR8ZL16ZqARSmGvjmJs+Mz1M0H2AAFS2A7KBjLl0awheCPkQe9aGH3
         LwS/LvQS0RMiDAl78IeLo8kZb0bh9KsZdVuBttaZD9T7NTlGYNV2Bq+kxk5FRCHo1dhs
         X/k8Tzg4OOG9kEtOe6YkapB8SkuOeSDac1uJdYrn6rvPofTliocXn5QQR5EZk9KoJfo6
         dsTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=o6eVBYqPfVnoIXkyNQKjRm0xZAMjyktxPlL3r8Y/b/A=;
        b=GLjGVqumFI0XHG8re7w3aTPtQ9Tdde10xzKP7cP4xlkGWAXsK+j8SCDZNuXnrQJWxg
         lkEjwA6w4Y5hhegC/OLTBilaWtX2lXr+oxUPluCgGYpK2DE5s4UOjrpOT8vqEkfampWz
         tHvDk5/e9T+bUyZKTfuIMxZ7D8kjVEP2kYY/37NgHF8s0cmkIpTDulJwXRRYME6wUEQR
         ziYsBbUhrPCczS6Gp5t8dcwPwhpx2GdbDkQSZ6xrM3cXtc7ixIyOhKede2jYk9cwdqfl
         AKa9jhPygJwGU8eMMhuZT1ISI/gN5I0IOpJxRwwIEbGKmTpFKkqR4lW5reJ+/g3exaJ5
         qsVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IBpKp0yu;
       spf=pass (google.com: domain of 3nuovywykcekrwtopcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3nuoVYwYKCekRWTOPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=o6eVBYqPfVnoIXkyNQKjRm0xZAMjyktxPlL3r8Y/b/A=;
        b=ff4R1pw6wwhCPUUo9jAhhWGxmbZoNZ0QvadoECtHHtguI14dHrUdNqwn+pCvJoF09y
         fHtJQOtuwcwoIiUZh3bXVfkCXcsoETiiz5kNz2D4sa1K4jyA85h8Rw8VAFX32pH749qY
         /Y3pMoFDLhOc3UPFgklDWfuugnyoEkxlFFYJG9qEt3WDwyVjJq04Aa20T1VZdwuA4JWX
         4oeqshW0mihVcGQ+6ZD6Ag/w7hKKYLw+N42AxGZe49u2zA1yypz8zQC4qeGmXYhbWP1Z
         qJBBB04VhLM9cBJ0X+B1yyvmqSs7kubz10wUUvmj2DsPKGfZj8V9nRRcrYu2t6d2QIt9
         Gssg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=o6eVBYqPfVnoIXkyNQKjRm0xZAMjyktxPlL3r8Y/b/A=;
        b=6kGW5ZEK/jLh06Cq39TbaAsb/2bMY8TXEZLFii3ri6zxJCENcnQArj7TvPZoS0P/i8
         A/T+aP2hYCH54yNuuM86+/38HGHrSmA9pJ+191wU5PwHY8QLwO0h2NxDpqyTMVdSnXvW
         m7x+HBeZSZlpCCL2RkvOfyJ0q+BPyxjh5L3VNMFb+SwBHv3AP/TLTtQSdjja1ogTKrfC
         Seg3N+1UMqG7r3doxVgCyBiqkRKuKUzB4RKb198M7sDCejizFpGVekZzYe/C+2IZWeM3
         Vug0POwIngFeRUJ0rJu8wxJRXZva4+mzpFD8qY5aSoYFESx7hr3BozGgzyCUXf54B/4V
         IWRA==
X-Gm-Message-State: ACgBeo0pQ1Pt7DuDHpWimq9lWZH/m9UjOG0Vz1OnjsHYpBlJjeTrdZPm
	1SED+lUVgqXzPNBq59DtzaI=
X-Google-Smtp-Source: AA6agR7YhdCETGYjmxJeqESV0SmgJp7oV6Zp3fh/mklR3ZNXot0QPJqWcKbpiMssnB1OUYyH2CqN7A==
X-Received: by 2002:a17:907:3f90:b0:741:96fe:6641 with SMTP id hr16-20020a1709073f9000b0074196fe6641mr24917392ejc.378.1662380704019;
        Mon, 05 Sep 2022 05:25:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26c8:b0:448:77f2:6859 with SMTP id
 x8-20020a05640226c800b0044877f26859ls6883636edd.3.-pod-prod-gmail; Mon, 05
 Sep 2022 05:25:03 -0700 (PDT)
X-Received: by 2002:a05:6402:c45:b0:442:c549:8e6b with SMTP id cs5-20020a0564020c4500b00442c5498e6bmr43645661edb.123.1662380702960;
        Mon, 05 Sep 2022 05:25:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380702; cv=none;
        d=google.com; s=arc-20160816;
        b=b9v6LhjQBypqjEoS63X1EmQ1wOJFNqMGhMsaSFxJWyn8tKAm1+2Mxb1yWad4nU7hfF
         fiumdUsz6dGbKrX7OKgnpJiKHLXaiEX05E4flr0cGOEIi9OWkxImKxPRngPzR+0FGC0W
         wpuQSl4i8xFou7HnA4V9XsGtWxBjPyPuVsKsjtMNmu8yfnYjLrOhLBtLNnGUKcLf3CRQ
         eLW/ImIeQQg8/Z1qCY57nSA12t0boPmwVFymTYOEl8JHZsTRIZATqD3mivpCYRkgxkvl
         lgjcbGAZHjMMjSUQozE2Wvj6rGwz9+6d67e3AxkCPiRUuDU79JQkEyDg+ani6t4gZBgf
         mWCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=myl6nRKQ/2lBkAfAPAxtf2MFDBMrGN4kiGAEDqUjhHA=;
        b=ackguf5FKoFHGWsy41P+/fLbT6YgrRSAH3ly6qURx8ycTbZfpabNwPfSEIAGQYbHEc
         bJqLx3FutKsjeqylbchgH+pVTgsZCgQnlRusC7TC2xogJjPgj+hwbYahwY9liuwgfwHt
         q/wBiic6BRD3EhOjY2xMZ8IRf7FSD7N7XpkFaUQmLV2gVe0BzDMuqmYAVUXVb+70haNd
         WbfiQtGuC7trZllKf56RJT7VuHukWohZvQCsxmyQGYr6WqMR0Pz0Dl+24VvUFQshjsnc
         uDynB/q/3sWXNE+tTCKivYAds4lf4v11Um9hNTzx253pHg0gP9MKsr9wUykkxmkMvAuE
         ovqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IBpKp0yu;
       spf=pass (google.com: domain of 3nuovywykcekrwtopcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3nuoVYwYKCekRWTOPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id hx8-20020a170906846800b0073d9d812170si404823ejc.1.2022.09.05.05.25.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nuovywykcekrwtopcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id i6-20020a05640242c600b00447c00a776aso5850474edc.20
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:02 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:906:7310:b0:741:85de:ead0 with SMTP id
 di16-20020a170906731000b0074185deead0mr26364424ejc.441.1662380702571; Mon, 05
 Sep 2022 05:25:02 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:10 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-3-glider@google.com>
Subject: [PATCH v6 02/44] stackdepot: reserve 5 extra bits in depot_stack_handle_t
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
 header.i=@google.com header.s=20210112 header.b=IBpKp0yu;       spf=pass
 (google.com: domain of 3nuovywykcekrwtopcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3nuoVYwYKCekRWTOPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-3-glider%40google.com.
