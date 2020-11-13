Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNMNXT6QKGQEPKATZFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D00E2B2840
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:38 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id w12sf7464850iom.5
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306037; cv=pass;
        d=google.com; s=arc-20160816;
        b=JAY1sP/RcZsrBPVJrBC6akIfgAjwKOCaZ9zU/7dtlA9hgHtEZpzseuxGf798traMbR
         egJnFRxi7nJn8rwd3tbYQ4dpKfk3r1fSZJGVhA/ECt0il5L4agwrxYigpoF9oDHhgx/U
         vKyPKtThN7zQon9zkXzs+8uZ/hGKEWeGng0c0xTKU76/2P+imklbDsz5SbzzBOHlPey/
         Q5K0ETM+gGpcQwnZhWu8mOgs6l/olZD7vGkLMk4AflEmrsRHg3WQSP+/2dHXo0eHQszq
         smvdL+i8sOr2eg2HK+JeLe508APU3u80xHAefZq+vFLm7Pm6YsQQHVYiYa5/P/IYM8ZR
         Dxkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=nE83bHa9pwC+H/9ONdpJodr/qhBY360KRMLbaHd5JAk=;
        b=DbZURSK+FMyf3OxpfugjTqZ01kR3NLSHqwqB1GdoSei22vupD94LWvtOuVhReRmCsu
         7R3F381wkm7JqSiZ9AdulK0qrGVB3RpS4AHqzBNfwO51bTAvLzFD7aawsJeYEU1J20W6
         83aYN8VV8rsc5mXDgMZR2IGkSNUUJSxObWXmLVVKnvQEGXMfk+G3qFPz4oQ4SN0wXwWX
         ypR8sKwEetnNtTlpHy6cp9KA9gQYpyf8GQ1wQK37019FeQfWO80C/NSbtKQJ8mi0eV6p
         /6My7yuYuTAXKBYniqX6SeGzg9Gv/POytvIQkJ6sYrWejC+d7MfMy/gyhd3AJP9tCwc1
         JI4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F7pTXHrB;
       spf=pass (google.com: domain of 3taavxwokcyefsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3tAavXwoKCYEfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nE83bHa9pwC+H/9ONdpJodr/qhBY360KRMLbaHd5JAk=;
        b=l5KX5rb7BRwO7TTVZ8X6PEMUlYWAZazwXrQvROOEzaDrUwENxxJhALItXzxmg7VUUn
         0gpSSNjGyJHnmEWuu+oXLBRdY6foEzvkwHOwcVM7lS9H7AzlX4/Pv9jpCitOidFg8Gdt
         tv8hsDWVfeMtPiqU2llGmWugxEX6sxO21jRB2In9zxrh1m1HPVC4ZELZ9wqT4Gq8RBEp
         wCRB63Q4zzvSjTwo7LeBgLY4Djp/ZCscsgsoVZdHFDGvbSBzwkyBumZoSolKAFS9PN3k
         Xv5QkDFCg4yBsopiwFr8Vq1YrV5Uqpc1WPb8MR0jlwpeki9DsNEIqeIQr6SqqIXhpzKj
         gZxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nE83bHa9pwC+H/9ONdpJodr/qhBY360KRMLbaHd5JAk=;
        b=uhPC4TMK+GmLUkUiItyiIX+NUbKIDGrGwGAA3GdSDRwIJX+7eSasL09Zy2Y3rM1Di3
         9a0NxJuGKJxHhUacyJHhLF401hnW2YSuHbOc9Ppkx8xjBH7tRBGrWoZrZmZFJZUJcm/2
         0G2ANPJg2DwDDlTLNNCp2doD5ImXg8kJYpnbjbgQao/ebFj/kb6IfVDAcecfhknxkQm9
         YUHMHarXcu4v//Y8gzCZZcCuL9VUukC6LzL4uV4otrnO8OlfLc7CIJHS923j+ebgS+hc
         Ot7PunClP9FLqKiENAHlmnwnAFsmUjmQJVmV0FNjvLCho9j6/6Egg0MTBAmytTetCyzT
         Ma0g==
X-Gm-Message-State: AOAM532wVbgBIVZ1HMUQu+2HGRoxu+fz8J/wdmUT4OHB2Yi3vKOStVxX
	anv0m6lkeMW2287U8u2mwCY=
X-Google-Smtp-Source: ABdhPJwsP+oM6Uo1+vEenG0yu2bN+jbyuKzt4V5j93+XbMIQUjsgpLV42hTw9hCVF9wg+dFkxjBIsQ==
X-Received: by 2002:a02:aa0d:: with SMTP id r13mr3809099jam.26.1605306037659;
        Fri, 13 Nov 2020 14:20:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5e9a:: with SMTP id f26ls1852619ilg.9.gmail; Fri, 13 Nov
 2020 14:20:37 -0800 (PST)
X-Received: by 2002:a05:6e02:11a4:: with SMTP id 4mr1577920ilj.141.1605306037298;
        Fri, 13 Nov 2020 14:20:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306037; cv=none;
        d=google.com; s=arc-20160816;
        b=H9gBgu52N+rnLYEn1UEHNN7IMoQKSXH5qxZZzfd/coY+XNl2TWy1LhZ+EDCrvVAtPw
         gfoe8AduxLNTCC4RFaSwBqlp37BPReQjJFtaXfdalCcimxQVkTCynqhnwBvxEKjmLuYF
         +2H85EyWCTzPWEAQQJOKOLtXhHum8hpA3lwhIJq2TV8cf5EcHW0gqY3IVaDMsE/rR9tr
         dxTQ6899L+F4H5wALP8jv0/zLFl5ZMR23GwEvpnSQltuUSPyj3K1GWQeLuE8hOKAuJFs
         oN3s2xpQFNH6HX7xFtZJAOlIE5QD5k4I1qVixkzkQvUh0cIKI5F8kY3mMey71ekPnT5D
         bmGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=DB+H7HqoS0BsRTXGNuAwKRf0LlfChpk6LpCcjRkDvbU=;
        b=HSwJ9m0gd1PkDUBi0W2R8vI+g6A+JxgqgxdqoReHgWKt0PrUCg9OmZauGW3wz8VOgA
         B/ZzwhJr9wY4UfvkTh97ukyOpIZFHsX69WiBWEGVxP/aIDSJCz8BGNz13Hlw4tdZmDYa
         tOL5IBbjiF2B0FRPgjUcRJXcVVWsZS2BZ0IL2iVemNGv6Pxc7IMiqp5YAjxyCnPmnyjw
         oiH+vpckQj8g/4TMgypqyyQOjEmwWiNN3WB8kApW/NwG3b5Hfle5b1+ZTelM2+ds3Bwe
         BDpHDRXdo7x57oALk9w3Gm5LC1+P4OSCjoztx/4gyt98KUTAbZK6oYrWycqAAwHcDZhg
         MIRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F7pTXHrB;
       spf=pass (google.com: domain of 3taavxwokcyefsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3tAavXwoKCYEfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id z10si291805ilp.1.2020.11.13.14.20.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3taavxwokcyefsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id cu18so6253503qvb.17
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:37 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:12ed:: with SMTP id
 w13mr4550130qvv.23.1605306036643; Fri, 13 Nov 2020 14:20:36 -0800 (PST)
Date: Fri, 13 Nov 2020 23:19:59 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <4d64025c647190a8b7101d0b1da3deb922535a0d.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 09/19] kasan: open-code kasan_unpoison_slab
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=F7pTXHrB;       spf=pass
 (google.com: domain of 3taavxwokcyefsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3tAavXwoKCYEfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

There's the external annotation kasan_unpoison_slab() that is currently
defined as static inline and uses kasan_unpoison_range(). Open-code this
function in mempool.c. Otherwise with an upcoming change this function
will result in an unnecessary function call.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ia7c8b659f79209935cbaab3913bf7f082cc43a0e
---
 include/linux/kasan.h | 6 ------
 mm/mempool.c          | 2 +-
 2 files changed, 1 insertion(+), 7 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 1594177f86bb..872bf145ddde 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -106,11 +106,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-size_t __ksize(const void *);
-static inline void kasan_unpoison_slab(const void *ptr)
-{
-	kasan_unpoison_range(ptr, __ksize(ptr));
-}
 size_t kasan_metadata_size(struct kmem_cache *cache);
 
 bool kasan_save_enable_multi_shot(void);
@@ -166,7 +161,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
-static inline void kasan_unpoison_slab(const void *ptr) { }
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #endif /* CONFIG_KASAN */
diff --git a/mm/mempool.c b/mm/mempool.c
index f473cdddaff0..583a9865b181 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -112,7 +112,7 @@ static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
 static void kasan_unpoison_element(mempool_t *pool, void *element)
 {
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
-		kasan_unpoison_slab(element);
+		kasan_unpoison_range(element, __ksize(element));
 	else if (pool->alloc == mempool_alloc_pages)
 		kasan_alloc_pages(element, (unsigned long)pool->pool_data);
 }
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4d64025c647190a8b7101d0b1da3deb922535a0d.1605305978.git.andreyknvl%40google.com.
