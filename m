Return-Path: <kasan-dev+bncBCCMH5WKTMGRB26CUCJQMGQE2DCWEOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FE1A5103DA
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:44:27 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id l7-20020adfa387000000b0020acc61dbaesf3160994wrb.7
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:44:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991467; cv=pass;
        d=google.com; s=arc-20160816;
        b=WrS6oYYlKqhb4GhN+V6fbgl+fKN9LLbiBKQJx8jDvOJP2lYeEXugCJX0URq88INDrQ
         gEZYu8xSOezzRMsyJJXnFDJAKRbV1H9htZOoMOhuY1/1XuGuF1uQbj+NcBgCRkoBygnP
         ZLMztGe+kvEpSwtLO2JU8kQd4FE3R7YfmIoMDI1Qd83aYDuRHFcEsRVthpoUxNZxVYJw
         Qf2/tbACxP/K5uSkjvyvAIqas41Woc/fva0OJ+bmJduiNrMb/iRx75b5E42ln7mrVbGo
         TTISkvssF4eTlEDSQQnOBgAEZusf1GlXm2VtO3GkP7LXy4fY+Ghg/j5FP44tOSZiqRO5
         7mGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=UQr0DwZSXklT0OmZ0qTCGCNCobCAwt1dmWAf+qaJ7Os=;
        b=zsxrr1kMMkgM8UvU3qLPLAiNSedTbMOdz31mG6jvemZ8kgokCA6ttvvIHE1CYCj8TX
         nJPhClwWHTc4fGKaywJMn5Wu9L5UtsfkYUEQDYrGOyWidxsdMRKtcj+XCrPKAbXUN5Ve
         sY/0FvXMHf8mGJS+7hOdbydrx/kSk8p2zjJ8AafJ7yjXgajPxnhiOS6PZSZOQ0RAAPr1
         JtSUdvMHeLuLCftoQOq4aQE3f3TFv2uIjLtTSuqyJZ/F8GAO3a+hzknskWPRO6fzOHp7
         M6u+/VsUaLS5VKU8Y5aunmpDz5W4rcr+tdeXj3bQ1gEz673cIQBKkzTLoEF5cK4djNTA
         7UFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Gl3v87A3;
       spf=pass (google.com: domain of 3asfoygykcwykpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3aSFoYgYKCWYKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UQr0DwZSXklT0OmZ0qTCGCNCobCAwt1dmWAf+qaJ7Os=;
        b=riuZ0ToeZ3hOGAf8OEe17vjL8ohrxEWGXiWBI8iF0afzjzc4tLq8S+IC0O5rb7phZF
         x5bGjF1TVQBRfGG+F1t1bBpSrmLSySm5YWPyxj4dAxFr2TFcsqZGgwDc8yOuCilM+N81
         hrep8ypkzqhsmW1kKihvdVTW6qVcvkh79/FzW5hHW34Fq6gB2GrNRTQs8ACI9SpifGS9
         XHH6mrx0uHXRzWDrXxqH8+I+OdCNLyRNRDennFf+Ob5waoPVtSMSOu8CCBAfRcz8BBDg
         DHyWCQo27E78fxBf8WD3yKvNJzhM299Ml/LkKK345NTAn4mU0zLKnjihs9eE2XC/78x8
         pzKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UQr0DwZSXklT0OmZ0qTCGCNCobCAwt1dmWAf+qaJ7Os=;
        b=XYFx7/dX8dsLcej6NOdiOi8Yfe/WwubEiBlyeOmQVhcRqO1GTaOdLzrg8U/YonCOjw
         H1XXj3b0Byf98HqThuKQjazqNapeK8x5wtFS3iUlA15Esv1l8e+xzz95zZu/bXB0g/G8
         NdCTCTYvCXvvzoYKD0/fDq/t9Uw8REIW8iHSDLm8M+QiyvPOi6J/KON0kVr4BrD82h+D
         tq3aBlJLPGMoI9ZLaCuQC5v1aeHyUIzqJknd74LHnuye1RvkLxhqoCNWuWXOavpESPXv
         0vqH48bIoOYWPg+cbnmcJylyTIsH5KTQbyUGAJNcHApUcaO4mUJHQK/V0k5yGyhHIRP5
         kvTw==
X-Gm-Message-State: AOAM532iFYw0lqrnaHFUu7vHxfGccURdqhuvJnOCezW3DJqsTNnBhx1o
	Iq0cmw/+YpbXE4oLXA4IQNM=
X-Google-Smtp-Source: ABdhPJwFrrdjSuYFMy629mGLGy2y+VBpYvtxqlCxpgat5zuC1ChxBnsqbDjSJUGlIq8SV8Ev1i6JwQ==
X-Received: by 2002:a5d:4008:0:b0:20a:ea86:e101 with SMTP id n8-20020a5d4008000000b0020aea86e101mr1245169wrp.141.1650991467189;
        Tue, 26 Apr 2022 09:44:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:59a4:0:b0:20a:d221:a277 with SMTP id p4-20020a5d59a4000000b0020ad221a277ls1005814wrr.2.gmail;
 Tue, 26 Apr 2022 09:44:26 -0700 (PDT)
X-Received: by 2002:adf:e491:0:b0:20a:cf97:58df with SMTP id i17-20020adfe491000000b0020acf9758dfmr14939486wrm.213.1650991466224;
        Tue, 26 Apr 2022 09:44:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991466; cv=none;
        d=google.com; s=arc-20160816;
        b=FXaW2NvL+VfcY1f5u/9tHKY8CuR4fgmDh4DHSkdedTb5X3LC5Dg0WN+LMWFBloyfbh
         NO/uSjPFmimRpOeXThCjBaVkK7Gxb6Mf6/YG3YDUA073HFJ06lqNI6+TzN3FN4TVBNB1
         OBQtLtzx0nS2SVUdgAMHAYhtel2kwLsee8jhO1KyXIQhmP4Z+zpaO8PJONFXibU3n0YX
         vW7bX1nhVc/ehOAl4ce+LABzEbQ8AD1gZDPIzpqePqtJwnSMocMlqmfE2ynx/nXP01mn
         RbuKvoFLDkSTCORitftRaXNWd4/gQM3tw8vXc7dsaaml27jYu5h9zOlczqA7NSfeSGyP
         K0hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=x9iYgpTxv0DnaRejeNz0igsc6c2qOQO28HLcQTucooU=;
        b=FK+1PwjFjD8R4TnJP6g4udHN4OI+HYEVhev1y9UTICFIJmcLo04Ffw/Pz4N4xeXsav
         nKu89vHEXZTnxXbECwKV2j0UuIDv437d3hQG2/qd+U498oD5SlHvPTAzIJbn2GTACs6+
         gFr100hTzZCSXJljtv4BDtxmDSJ0Yccpj95Lat5zaZ7mIludF6vu+fuAze6ugGFdpuhX
         VypYx90Br0M67c+ESwu3QXPJuC/IwT0RNy5BfFzjWZMIys7kUG5+aFkJ3cxXfhvHbInl
         iuSYRkDEE8nQPIyMQGxNgQRtJwZxxpQgwcMppjYRniswQZ8TFzIQiSNpftX9hfeC4nwo
         WiwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Gl3v87A3;
       spf=pass (google.com: domain of 3asfoygykcwykpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3aSFoYgYKCWYKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x249.google.com (mail-lj1-x249.google.com. [2a00:1450:4864:20::249])
        by gmr-mx.google.com with ESMTPS id y1-20020a056000168100b0020aecc91bfdsi7977wrd.0.2022.04.26.09.44.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:44:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3asfoygykcwykpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) client-ip=2a00:1450:4864:20::249;
Received: by mail-lj1-x249.google.com with SMTP id l8-20020a2ea808000000b0024da289e41dso4842705ljq.7
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:44:26 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:ac2:424e:0:b0:46b:9249:8ce3 with SMTP id
 m14-20020ac2424e000000b0046b92498ce3mr17070835lfl.282.1650991465442; Tue, 26
 Apr 2022 09:44:25 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:31 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-3-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 02/46] stackdepot: reserve 5 extra bits in depot_stack_handle_t
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Gl3v87A3;       spf=pass
 (google.com: domain of 3asfoygykcwykpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3aSFoYgYKCWYKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
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

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I0587f6c777667864768daf07821d594bce6d8ff9
---
 include/linux/stackdepot.h |  8 ++++++++
 lib/stackdepot.c           | 29 ++++++++++++++++++++++++-----
 2 files changed, 32 insertions(+), 5 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 17f992fe6355b..fd641d266bead 100644
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
@@ -41,6 +47,8 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries);
 
+unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle);
+
 int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 		       int spaces);
 
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index bf5ba9af05009..6dc11a3b7b88e 100644
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
 
@@ -73,6 +75,14 @@ static int next_slab_inited;
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
@@ -136,6 +146,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->handle.slabindex = depot_index;
 	stack->handle.offset = depot_offset >> STACK_ALLOC_ALIGN;
 	stack->handle.valid = 1;
+	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 	depot_offset += required_size;
 
@@ -320,6 +331,7 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
  *
  * @entries:		Pointer to storage array
  * @nr_entries:		Size of the storage array
+ * @extra_bits:		Flags to store in unused bits of depot_stack_handle_t
  * @alloc_flags:	Allocation gfp flags
  * @can_alloc:		Allocate stack slabs (increased chance of failure if false)
  *
@@ -331,6 +343,10 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
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
@@ -340,10 +356,11 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
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
@@ -427,9 +444,11 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
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
 
@@ -449,6 +468,6 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 				      unsigned int nr_entries,
 				      gfp_t alloc_flags)
 {
-	return __stack_depot_save(entries, nr_entries, alloc_flags, true);
+	return __stack_depot_save(entries, nr_entries, 0, alloc_flags, true);
 }
 EXPORT_SYMBOL_GPL(stack_depot_save);
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-3-glider%40google.com.
