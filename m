Return-Path: <kasan-dev+bncBAABBH6BTKGQMGQECUZCWZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 018E44640FF
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:07:28 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id q17-20020aa7da91000000b003e7c0641b9csf18225370eds.12
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:07:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310047; cv=pass;
        d=google.com; s=arc-20160816;
        b=KHRJfHshkstayA4R4WBomGIn9k7KlYplRMZOiIPaew2VVGmg8/dIzd+AMshnUEJ79Q
         sS12KibKOwBK6ZMg/jpuwEdt+oZqhQqQEufLuiuZYJygXHKtIFWwso+lES079BlnCLxt
         Z70AYPusuxOOf/UsqnCJ1Y7YQirQBd45IlyNlXRZgvNLw0vcQqbGpzzgmAEsUaATNUoU
         3AcQ29RYvToHXDkbHYBJT/Q9Hm80usx6ZoW7UWp7j8H1HAsHEsov0wXL9SJBZ2STMw6k
         DinvILXsCBNkV3VL8eOYDBo0j8BXEPyM0c474h6PGQzOSOMILY4c0tl9jQV23UJWvwUX
         Lfnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+ymBPFL35P97XtLTCrLWKwuw6bhf5mPlW1e+0U0izHQ=;
        b=GdGVTfy3OWbqLGjj7GtDeoyTr1q/4CckhL25rxJRPeQWbETh6zhV3FjJutrek4fG0a
         U1HitKjO9FvHN0yQLdh6ACzoFMOwVD936HyGXnudJxuqY3S4E1pEp+pAEQ50MCxMmA0F
         xsRQzTrZIHc5uADWuDIf/yHbG16402u7szf04/G7gUqYG68L6m+7sWkCD7EfgMlOO27t
         rP8DXgHHd9QKjRjCqfRqpZeqOAxXCA4wauuIVxyzBUTISAlAD+0AQXpWCt/2aZ01Hl8q
         xZMB2DSUGXbFYvuB+kRKneEf7NmlGJd3hmYqXAw0ezX8oRKIB34qDUbxqC2W6znUNnXr
         yK0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ATD5lSou;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ymBPFL35P97XtLTCrLWKwuw6bhf5mPlW1e+0U0izHQ=;
        b=mIpwQX7H+7ww/tSW/cJoDXeBx1K/tLafqDG1JgoViLoABMN2bGs862oc42L7be0U2h
         bs+/hRlJKs2PuB+yMaslh9IHBmm6/f13xYMxNe9ZciQMRESOrRzHbtMAuPmfg9VrUH/L
         1ywIrnO7juLaX4fgUkMLcr44F+iAIPbg4mSq62gaTLQtBGVt3m+Wc52PyNRdchyTR7Z3
         P8t+BIQZy7Wk1qjuFTqpFbYDhV9hjhx2KcTlhybADeSJB2JzbvGyCmOiRJjS54Kl7peq
         aj5zktbZdkFAsEAV9OJstby1GTe8gnIA8HGtmHDi2s5YSHjsumi6qUg02O6x4S8MOk3g
         IOuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ymBPFL35P97XtLTCrLWKwuw6bhf5mPlW1e+0U0izHQ=;
        b=nqKPnpehqBBiPAnoBOMt+oGHIGgdhCTxdozHIommrj2a7KcHbcxjEdrLP8q8/eSfVf
         GU0MDZDxrQI4fBFAsH0qx1u3hW52sgBXLMk4ffhmvvdyJDO8tIUgx9gTPkWr1svmSlAq
         p3o/gnEMVaJ04LES0ACBQTwXJZ/0K/V0vpDNVCRHe9Mxzagk/tV8LnbsZaNnGJQfCFjS
         nPpdD3DfKsB6HbZe6Ft2l9hspZ2CI+z7oVfSqcmkp+k8dv5ycB03xb6I5yAeQrDwQxb0
         7WKPF9BafRA7u+PWtev59OWDDMLz3bsBzjppPwLvnoGo5Sd1IS2BM4qkN8mpVeyZ9Tr7
         dj5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/hj0EGHywoaZleTUxsQth/FhnVl5x3St21TrF/X46LL2oV1dW
	m/7WvR0bL/x7MSGFs/7+Lho=
X-Google-Smtp-Source: ABdhPJxAa2+hjUVg0/kmJwrqY1l6MG0xmLzRbeqxd1H4raYwf50SCpfEUlKzm7ZJmhOoq2002IkucA==
X-Received: by 2002:a17:907:7ea6:: with SMTP id qb38mr2128979ejc.248.1638310047776;
        Tue, 30 Nov 2021 14:07:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c944:: with SMTP id h4ls252155edt.1.gmail; Tue, 30 Nov
 2021 14:07:27 -0800 (PST)
X-Received: by 2002:a05:6402:2152:: with SMTP id bq18mr2481892edb.105.1638310047204;
        Tue, 30 Nov 2021 14:07:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310047; cv=none;
        d=google.com; s=arc-20160816;
        b=OB0EEfzwfW8D+trl91FfEYDNZjJZTAd9Zue7JHIQyyNi5AjXXuxwqQ/6mv+dsJDt2n
         q3QbuCbDIjKwM/5cyGcxpfWddJfm2Bxv/je8K8NSr+G5gtE51qNnf3ecje1UmGZURS4t
         MeiF1cDFbFS00EaicEfkM0/W0KzrIDKuOhPkcJhCbdgdbavy3xQ9EnfCc/wtqLVgZajJ
         RL3df/O9ZS8KtblaWHP5zRaujDjNIH6Af2lU4K74guTwDHM4pnk42LcisrghCrmAXCM5
         CFPBje/uOQe0G0+rUXEP4QDWlzOHYnoAiiM7TcKE9kshZSMrr7hQvNAXZwb7fQqYI1tD
         8KnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AoP2BIKCAOk5uPiTZbwMHsLeQD0XCkLrxAffbVYmGOg=;
        b=goQ2lVC4gOwwj7PeNjvxXg0SWJ9HnFiDYYLS3uwoWI2ad6gMVFGVyD9A5wTWYRJm1V
         RlM0wXSN9zyHi1qom2+aatQl4oHF4lufuwG3abU9WR2N2DJ3h0JpsngjPqDH692EMLcp
         vyFoXRkTypdKY6w/qhq5GMZmyPhtdYR6MxkA92bQTmd534BRhl3UgyP6dVLBWIeKKY0n
         hakrEyYS0LfM9jkO4zrbNvIuNAkTxSigSalA+EiCLyyPvPhUsTgFV4GDpalcr/qGtuOZ
         +Bm3CcVp1Xni56QWzXmD19UsXmMhxoQcSsYyuSsrA+ZE/laZSGSA4RwnmhJFOnxIL6zU
         5QnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ATD5lSou;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id eb8si1637913edb.0.2021.11.30.14.07.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:07:27 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 22/31] kasan, vmalloc: add vmalloc support to SW_TAGS
Date: Tue, 30 Nov 2021 23:07:07 +0100
Message-Id: <0c479434ed079f9e28fe9552adb709645c9d785c.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ATD5lSou;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

This patch adds vmalloc tagging support to SW_TAGS KASAN.

The changes include:

- __kasan_unpoison_vmalloc() now assigns a random pointer tag, poisons
  the virtual mapping accordingly, and embeds the tag into the returned
  pointer.

- __get_vm_area_node() (used by vmalloc() and vmap()) and
  pcpu_get_vm_areas() save the tagged pointer into vm_struct->addr
  (note: not into vmap_area->addr). This requires putting
  kasan_unpoison_vmalloc() after setup_vmalloc_vm[_locked]();
  otherwise the latter will overwrite the tagged pointer.
  The tagged pointer then is naturally propagateed to vmalloc()
  and vmap().

- vm_map_ram() returns the tagged pointer directly.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 17 +++++++++++------
 mm/kasan/shadow.c     |  6 ++++--
 mm/vmalloc.c          | 14 ++++++++------
 3 files changed, 23 insertions(+), 14 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index ad4798e77f60..6a2619759e93 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -423,12 +423,14 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void __kasan_unpoison_vmalloc(const void *start, unsigned long size);
-static __always_inline void kasan_unpoison_vmalloc(const void *start,
-						   unsigned long size)
+void * __must_check __kasan_unpoison_vmalloc(const void *start,
+					     unsigned long size);
+static __always_inline void * __must_check kasan_unpoison_vmalloc(
+					const void *start, unsigned long size)
 {
 	if (kasan_enabled())
-		__kasan_unpoison_vmalloc(start, size);
+		return __kasan_unpoison_vmalloc(start, size);
+	return (void *)start;
 }
 
 void __kasan_poison_vmalloc(const void *start, unsigned long size);
@@ -453,8 +455,11 @@ static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long free_region_start,
 					 unsigned long free_region_end) { }
 
-static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{ }
+static inline void *kasan_unpoison_vmalloc(const void *start,
+					   unsigned long size, bool unique)
+{
+	return (void *)start;
+}
 static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index fa0c8a750d09..4ca280a96fbc 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -475,12 +475,14 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-void __kasan_unpoison_vmalloc(const void *start, unsigned long size)
+void *__kasan_unpoison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
-		return;
+		return (void *)start;
 
+	start = set_tag(start, kasan_random_tag());
 	kasan_unpoison(start, size, false);
+	return (void *)start;
 }
 
 /*
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index a059b3100c0a..7be18b292679 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2208,7 +2208,7 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 		mem = (void *)addr;
 	}
 
-	kasan_unpoison_vmalloc(mem, size);
+	mem = kasan_unpoison_vmalloc(mem, size);
 
 	if (vmap_pages_range(addr, addr + size, PAGE_KERNEL,
 				pages, PAGE_SHIFT) < 0) {
@@ -2441,10 +2441,10 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 		return NULL;
 	}
 
-	kasan_unpoison_vmalloc((void *)va->va_start, requested_size);
-
 	setup_vmalloc_vm(area, va, flags, caller);
 
+	area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
+
 	return area;
 }
 
@@ -3752,9 +3752,6 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	for (area = 0; area < nr_vms; area++) {
 		if (kasan_populate_vmalloc(vas[area]->va_start, sizes[area]))
 			goto err_free_shadow;
-
-		kasan_unpoison_vmalloc((void *)vas[area]->va_start,
-				       sizes[area]);
 	}
 
 	/* insert all vm's */
@@ -3767,6 +3764,11 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	}
 	spin_unlock(&vmap_area_lock);
 
+	/* mark allocated areas as accessible */
+	for (area = 0; area < nr_vms; area++)
+		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
+							 vms[area]->size);
+
 	kfree(vas);
 	return vms;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0c479434ed079f9e28fe9552adb709645c9d785c.1638308023.git.andreyknvl%40google.com.
