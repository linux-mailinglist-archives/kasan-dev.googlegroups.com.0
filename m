Return-Path: <kasan-dev+bncBAABB7FSRCWAMGQEQYPYD4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 381B381938A
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:30:22 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2cc5edaddd7sf644921fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:30:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025021; cv=pass;
        d=google.com; s=arc-20160816;
        b=hNf+T8j0q8zgKISocQ8B6S8USRUpB2Of4XNp83ynQFKRfAKQZwLHOzI41x3bbOfrvQ
         Y5+BqiY3k2kAd0VlclODqyv9kyC/63OeUY5JqFfIKl3smoQF4rbyTLiQgWplLuWORogR
         lpTwquAOjj1XjtK9urInh7tAr3khhFa4dqgpmql3vGVxVXX+3OVuYJMrZ9qc4UOiE62m
         PbLLR7UbIQ8BquGN49R6Ll/v89hE9QDbGw8HqAGPW3hLlPby1D6pLJddmGkxvO/SYK8l
         9JoUwY5/Lc2pKCMWkxyR0K61bBSAncxvUB01az4VJvY1cEL9KbH8DV+TwQG+mZUO/l2f
         BSsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6PwKYohmSLhFPdtsqsCtF0TVnLauCiCkvSGBtK/kxlA=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=m50Vn0pIQaXDE4jq6MITYmZueKhH8CrY5qYNHf3OL0VQlrZzuxkb5tCkBbYkI2IUOa
         DJPmlfvO3/hzRQk0KaHdwjfY8ZRenRlt1VTFxkgHS28tXnOUMrHo4Dat7+j83HnwgaS+
         VnSw6wd6SBliIU4beM4UF1ip1imUyV18sgG26GGWEwV34FxCRtoUxqfSTh9uGR5QIAFf
         C0rrEwdAk+djecFJfCs8H1n34c9Mhk/YbIufpXhwlyds7vZ0eEur/Lf/DqFoPWet0EHW
         xvvYcea+43C4Tfe8V/MK2NKTCkE76ULb/t28SfbP6gFdnnwYjXWWGYi/OMTzIy0DWVEy
         llyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qKyzmQgF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025021; x=1703629821; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6PwKYohmSLhFPdtsqsCtF0TVnLauCiCkvSGBtK/kxlA=;
        b=AsbSNQJZuIoAb5uG04DmkMLw/O01Sg8nD9GHbXNWEVwvD1V6q7kuKGDyM19uM1C7L3
         kbmJPcGBhxqxdkgqfXd8bscnLJnsclY4luywMwGokZqaLQJ7TtCVdfFl2K1GcuHA4Wj4
         T6gogpGBiS5XEnhKxuvuvRUGuflzoVZJZmX6JqY4WvGFBbIR0aiPstCkxCwnz3Y1wcNH
         38VWDP7/uYU4CscVsUnAMXQZnlzetc+dPi7qgMuOlZyhT7zXr73EazQrizfIBzVts6wF
         MwTbgoZeGepX/xJgTj4pXiT8m+DzwfiQbcGktAVJM3kBXjyx8/r5lYMjhK7jN6TsnOEZ
         3Ccw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025021; x=1703629821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6PwKYohmSLhFPdtsqsCtF0TVnLauCiCkvSGBtK/kxlA=;
        b=N2usHF+3oCotJ1wITmCQHwfmiwxcVOy2T7jQuRdpyJeZy4tbIQY/5iHgrlVq4YrqU3
         Wr7hFywLKeMQapOHHXzFBvhgM2udSgMAY6IjdXhwvasbfBpIg63MLNEWQMQk0KfPUT1+
         cQvag62fsX/osFoR5Me/NvXgnZGKZP6kv7ugepci1MlRYkL+D66O/sDqPZQb/6Vm9fIp
         nmkyg9Quc1ii6d2/CQKizBmfdB8cc03z0bs95OMUj1YCkutfbUopKKfy4WHE7voreMQd
         9XFIIOWliSsd2eBfxKVAUsFytywMpkrhHX1R1KoOM7EHYv9JPLNQmKK38r2vrb1HmvhM
         0QAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzHpIreDzd/dzAKVTdh3VpZCB40G/+gLt3y1pFTgxIDKVpZ8k42
	c82LyqJVju3LLvV0XV8z8+o=
X-Google-Smtp-Source: AGHT+IGJL2hABdsZT48R0nYBQ80KqtkUMa2X1iOiLVdr0/sGAyyl5GL2YpnSIE3+DC5NOW41aQAS8A==
X-Received: by 2002:a2e:8681:0:b0:2cc:7976:f5f1 with SMTP id l1-20020a2e8681000000b002cc7976f5f1mr1145909lji.4.1703025020442;
        Tue, 19 Dec 2023 14:30:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc13:0:b0:2cc:6f45:8ae6 with SMTP id b19-20020a2ebc13000000b002cc6f458ae6ls460959ljf.2.-pod-prod-00-eu;
 Tue, 19 Dec 2023 14:30:19 -0800 (PST)
X-Received: by 2002:ac2:54a2:0:b0:50e:278c:b6cd with SMTP id w2-20020ac254a2000000b0050e278cb6cdmr1097400lfk.2.1703025018589;
        Tue, 19 Dec 2023 14:30:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025018; cv=none;
        d=google.com; s=arc-20160816;
        b=0ivGjvwMzTX7CPyi9Rn6tg3UoGAOwzV6KIHIo8Eyxyv9RhV/ipyVkdRa1BaD8D9O/k
         mpNvLF3xMsmbmAsEIdLHqgLoZ58rn8COxJpKOWGc0444Uuv0SvlLi9vImS6ksO5U/fqy
         HET9ll9cj6DVFmeF0Hw0fcClWe3+2jkC7MpfEEt6xOTTXckrS5+S5OPt6lJlbo0rktT/
         6srWDJl1grlDDvTET6CS1VYSRGw61s430D7mdX7RIQjHfCWA3lOU2NI3C31pAtffdREx
         HcxFaHaj3n2F0xIES8XUnmIEUJ5c7fQgmFpc03AZLCNauaz7uhp5s86mNUtcE26pw3PL
         gJAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uNoAVP0QdjYefiRU2LrZ1wqxo2WmCMSn1BBV5oc4/p4=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=odwqC572ZW6rPokTcGGpdAFADQDLGiyZfSMgZ9yQGGLdh4kplIuarRSWMtuka2P0C5
         b2+D1mgtrIVPnx5wq1toNsI+vymbSSLLXQGLHRA+jO7U6NMZkcNFNNox62jWEBHYWEsG
         DMPSZ7UJwuznfX0m2B1vOyOWRiM7Js6k78Q9c+k6d5sV79wmBwYv/eDRk1d7+87HFRlm
         +ZMzgmUuya/YSpGCcwJpdlLNe3vww5OJHHs/y3E9oDhZli3g+busp/tO3tEFL+Ejxwba
         GNT61s1NLYKiKx12RxiwQ89ukFt6giQVn3vcZfAtf7OkCdnjALugdceb/gGhTc/YBxx1
         GItA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qKyzmQgF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-177.mta0.migadu.com (out-177.mta0.migadu.com. [2001:41d0:1004:224b::b1])
        by gmr-mx.google.com with ESMTPS id j19-20020a056512109300b0050e1cab8d0csi412703lfg.13.2023.12.19.14.30.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:30:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b1 as permitted sender) client-ip=2001:41d0:1004:224b::b1;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 06/21] kasan: introduce kasan_mempool_poison_pages
Date: Tue, 19 Dec 2023 23:28:50 +0100
Message-Id: <88dc7340cce28249abf789f6e0c792c317df9ba5.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qKyzmQgF;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Introduce and document a kasan_mempool_poison_pages hook to be used
by the mempool code instead of kasan_poison_pages.

Compated to kasan_poison_pages, the new hook:

1. For the tag-based modes, skips checking and poisoning allocations that
   were not tagged due to sampling.

2. Checks for double-free and invalid-free bugs.

In the future, kasan_poison_pages can also be updated to handle #2, but
this is out-of-scope of this series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 27 +++++++++++++++++++++++++++
 mm/kasan/common.c     | 23 +++++++++++++++++++++++
 2 files changed, 50 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index c5fe303bc1c2..de2a695ad34d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -212,6 +212,29 @@ static __always_inline void * __must_check kasan_krealloc(const void *object,
 	return (void *)object;
 }
 
+bool __kasan_mempool_poison_pages(struct page *page, unsigned int order,
+				  unsigned long ip);
+/**
+ * kasan_mempool_poison_pages - Check and poison a mempool page allocation.
+ * @page: Pointer to the page allocation.
+ * @order: Order of the allocation.
+ *
+ * This function is intended for kernel subsystems that cache page allocations
+ * to reuse them instead of freeing them back to page_alloc (e.g. mempool).
+ *
+ * This function is similar to kasan_mempool_poison_object() but operates on
+ * page allocations.
+ *
+ * Return: true if the allocation can be safely reused; false otherwise.
+ */
+static __always_inline bool kasan_mempool_poison_pages(struct page *page,
+						       unsigned int order)
+{
+	if (kasan_enabled())
+		return __kasan_mempool_poison_pages(page, order, _RET_IP_);
+	return true;
+}
+
 bool __kasan_mempool_poison_object(void *ptr, unsigned long ip);
 /**
  * kasan_mempool_poison_object - Check and poison a mempool slab allocation.
@@ -326,6 +349,10 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 {
 	return (void *)object;
 }
+static inline bool kasan_mempool_poison_pages(struct page *page, unsigned int order)
+{
+	return true;
+}
 static inline bool kasan_mempool_poison_object(void *ptr)
 {
 	return true;
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 4b85d35bb8ab..b416f4c265a4 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -426,6 +426,29 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 		return ____kasan_kmalloc(slab->slab_cache, object, size, flags);
 }
 
+bool __kasan_mempool_poison_pages(struct page *page, unsigned int order,
+				  unsigned long ip)
+{
+	unsigned long *ptr;
+
+	if (unlikely(PageHighMem(page)))
+		return true;
+
+	/* Bail out if allocation was excluded due to sampling. */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
+	    page_kasan_tag(page) == KASAN_TAG_KERNEL)
+		return true;
+
+	ptr = page_address(page);
+
+	if (check_page_allocation(ptr, ip))
+		return false;
+
+	kasan_poison(ptr, PAGE_SIZE << order, KASAN_PAGE_FREE, false);
+
+	return true;
+}
+
 bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 {
 	struct folio *folio;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/88dc7340cce28249abf789f6e0c792c317df9ba5.1703024586.git.andreyknvl%40google.com.
