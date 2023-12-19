Return-Path: <kasan-dev+bncBAABB65SRCWAMGQE4N2RYEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id BE20B819388
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:30:20 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-333501e22casf3354104f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:30:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025020; cv=pass;
        d=google.com; s=arc-20160816;
        b=yaVBCTULb9zOkXbzxf5Rh+r9Xnkizu8au4xw3bu2/91yhwWynIFkPJAYYiMvW51zeF
         07I/1Ki69Hki1bQgznkNPisWNa7R8KEPJ9gTu4NrukfhfmtI+2LuTPdg7032DxxaZVpk
         s+24lowajYX8lMZ5WSaP6yaTE2DEhk5JqqNFiBib3GbjrrZBCR8dDiQHMavH6Y+IRaNo
         a19B89FQawwMIfEANmqhoNf/GFsxIlLASLGNpRbkl66Kp69W9jknTxlyTDgP+hEX+hpB
         E8eLnAPOraMSQj0O7kgwoL2LwvcOWA9WOxL/VUmLymg8sbgRPuhBsPfe+s0x0aNH7jFC
         nt2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=t+0HaP1qoMZ4GXY0bNn+2IwuHyvDcP+0v3KMkjgPyJA=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=nG2iMl1ODCe6vfUbiK/B1XdjHC1vOkl4eVHpOp5dSbOqNJuzGik6GiY+riXHz0Atzv
         MCkZwMg93BxcJsn8HYl9pBRfAxPvSPsKKJv5SZRWCtPtsVa6gMX8V6se5t6FOWpItcns
         TNqXKe8lYLOUgkDlQihkaA6ZuCwVYpe6PmmF4WRDBrIYq8rr5ArzbdlapqU+/WMahz8K
         cy6nk1Re7+uhZr+B+bwmr359olkAex/bDvK1hsSlPJT8EnDbfPR4hUPHZUILL+wQ0txB
         Rbp0XSGJWEED62RzruGea4rUdUbVg37c1BLQjAMXRtrMgwitq427dD0xs2RSftA+8iaO
         2iSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mmCEXgMa;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025020; x=1703629820; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=t+0HaP1qoMZ4GXY0bNn+2IwuHyvDcP+0v3KMkjgPyJA=;
        b=rO2J+lqokcJDLmZUmYlE7HBnXif5lRNZMZdNelc/cuJCW8sQIp1n3wanv794VjlUAv
         x+g6LweP3RfciKXzMlkCcTD+SxzXzYVrq7EoS8+ljfIsesaiMWwXzKqt42TQDzIP7paS
         OAqFWy8gnGzv+UNtBuxQqmkTqt7jNwWLHnOZZO+POK4qQStcntlhbqUE5WwhuuvBpf9m
         QwQ/gS85yCkkfwNk0/XOzIJscL+6A94GQJrSWCaRXzyojzUl7roUArkwv1mXfTTlbRe0
         CGXSdn2ytWUjaB/6WsZCHasrohypXQDN31GALyBFH77vYZ3a5Z61seSJwLayu3tFycB6
         0xOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025020; x=1703629820;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=t+0HaP1qoMZ4GXY0bNn+2IwuHyvDcP+0v3KMkjgPyJA=;
        b=gxVwsugMjgMpY+z9nMymyB0DLTvCKxol66JZ3pIfcydALGvWFoZYMffYm7k93BxHgH
         4SPxPgjAKUuewPuYgH6W7cU/5Gn/47GNoGIxEgxQu4huY7ekWzJwMi/eL1QyDLyHZyhm
         rrJaUpEeTN4D113IGQQFA24E2je7YlvtV9qe8Eret7SBNB1znRW7GvgLTZvi0CZekNi6
         nyO890XFpfQyOlQ7x71S6auaOL8q8UWOm7CPcjk74x0nA83KAyAGAJPHHpEJeeNHYuYY
         3GrhU0yeYqVZ/PBUuWYA2vhGMRQo6n0KZyB6FiRa6s3DeaZ4uyNs3iq2dVsmu0/QT7vk
         y2AQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyM4o2td7B5ppeped9qtSsVYMDYTe1LWern07N/QiuBMh1j6Ad7
	WAH6Fzb20WBZX/p0xxVUZCA=
X-Google-Smtp-Source: AGHT+IEeC2ZkVeVWpheC3WMMeFvUo/+jr6cGVsv0EZM5Z5gZ0KQIg2a9+N6uknbrx5ApaDaUz9+6WQ==
X-Received: by 2002:a05:6000:4ec:b0:336:9ec:683 with SMTP id cr12-20020a05600004ec00b0033609ec0683mr8379494wrb.24.1703025020108;
        Tue, 19 Dec 2023 14:30:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:43cd:0:b0:333:325d:50b6 with SMTP id v13-20020a5d43cd000000b00333325d50b6ls447761wrr.1.-pod-prod-03-eu;
 Tue, 19 Dec 2023 14:30:19 -0800 (PST)
X-Received: by 2002:a05:600c:3d09:b0:40d:3327:2bfa with SMTP id bh9-20020a05600c3d0900b0040d33272bfamr160558wmb.161.1703025018702;
        Tue, 19 Dec 2023 14:30:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025018; cv=none;
        d=google.com; s=arc-20160816;
        b=uYEHD42rhdaTeKVR49NJvyHT7FI42qb4dXhm3egAmvDYtQBl2xpLdeUYmmqKa/UgKK
         zkKtTJmet137CJVNKkvSGrM/xIYSjImjUU5Msjao8hMj+mVaWBcXPM/DMFxKo3Xdyokr
         4+JhSHs80B9iN+40fWxrJ2gjHlqZGhq41k2cYKJjqzq+aQHpJH2RQAwANh7G5eMAPomg
         kwX9p5cvept6xphmcE1rXvBt2evgfe8dH2msvyYZBitAsk/Kq4PDM2y46PCUeyg5IopJ
         YX9/qn39qJCJ93OeAcplGibVBjJkFqKR+6wDRlDbaquceX8XUn4cHyTK27ClYPZPDlSz
         lP0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WvnDVDl+9gd8JY/2icI2mu85dJxeSXpMDACLsdprvYg=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=I0RTrxfIj2iPe+YTYWSvESehDfFWkUR5vIzlscssy8Fr/L/sL2rutOXOK9Wq8iw9Ua
         JA3zpQiWOFt6E/Un7scaS9sa7PRyel6WudGXedG+2hKlfLO38IGVYSFH2uYQa1WqU08I
         HHc69sn8l/Mq+c31Rq4bulJjsEL1icTmdLble49Qz21ITiLm4egr98jVjWS3BazahdAw
         Ly/5rpXUkkhSQYc2PLqGgDdyZzueZLWyx1ggGVBPElaBMAWslz5nozFuUbddwlUca29G
         DX1Z1Z8uxtMjuXO48pNS3V4IvsLgfANuiVdGGYFacs9P6o5J0K32iJ6pJeWU53BOQSwr
         +t7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mmCEXgMa;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta0.migadu.com (out-171.mta0.migadu.com. [2001:41d0:1004:224b::ab])
        by gmr-mx.google.com with ESMTPS id e16-20020a05600c4e5000b0040d35336338si198wmq.1.2023.12.19.14.30.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:30:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) client-ip=2001:41d0:1004:224b::ab;
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
Subject: [PATCH mm 07/21] kasan: introduce kasan_mempool_unpoison_pages
Date: Tue, 19 Dec 2023 23:28:51 +0100
Message-Id: <239bd9af6176f2cc59f5c25893eb36143184daff.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mmCEXgMa;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Introduce and document a new kasan_mempool_unpoison_pages hook to be used
by the mempool code instead of kasan_unpoison_pages.

This hook is not functionally different from kasan_unpoison_pages, but
using it improves the mempool code readability.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 25 +++++++++++++++++++++++++
 mm/kasan/common.c     |  6 ++++++
 2 files changed, 31 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index de2a695ad34d..f8ebde384bd7 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -225,6 +225,9 @@ bool __kasan_mempool_poison_pages(struct page *page, unsigned int order,
  * This function is similar to kasan_mempool_poison_object() but operates on
  * page allocations.
  *
+ * Before the poisoned allocation can be reused, it must be unpoisoned via
+ * kasan_mempool_unpoison_pages().
+ *
  * Return: true if the allocation can be safely reused; false otherwise.
  */
 static __always_inline bool kasan_mempool_poison_pages(struct page *page,
@@ -235,6 +238,27 @@ static __always_inline bool kasan_mempool_poison_pages(struct page *page,
 	return true;
 }
 
+void __kasan_mempool_unpoison_pages(struct page *page, unsigned int order,
+				    unsigned long ip);
+/**
+ * kasan_mempool_unpoison_pages - Unpoison a mempool page allocation.
+ * @page: Pointer to the page allocation.
+ * @order: Order of the allocation.
+ *
+ * This function is intended for kernel subsystems that cache page allocations
+ * to reuse them instead of freeing them back to page_alloc (e.g. mempool).
+ *
+ * This function unpoisons a page allocation that was previously poisoned by
+ * kasan_mempool_poison_pages() without zeroing the allocation's memory. For
+ * the tag-based modes, this function assigns a new tag to the allocation.
+ */
+static __always_inline void kasan_mempool_unpoison_pages(struct page *page,
+							 unsigned int order)
+{
+	if (kasan_enabled())
+		__kasan_mempool_unpoison_pages(page, order, _RET_IP_);
+}
+
 bool __kasan_mempool_poison_object(void *ptr, unsigned long ip);
 /**
  * kasan_mempool_poison_object - Check and poison a mempool slab allocation.
@@ -353,6 +377,7 @@ static inline bool kasan_mempool_poison_pages(struct page *page, unsigned int or
 {
 	return true;
 }
+static inline void kasan_mempool_unpoison_pages(struct page *page, unsigned int order) {}
 static inline bool kasan_mempool_poison_object(void *ptr)
 {
 	return true;
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index b416f4c265a4..7ebc001d0fcd 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -449,6 +449,12 @@ bool __kasan_mempool_poison_pages(struct page *page, unsigned int order,
 	return true;
 }
 
+void __kasan_mempool_unpoison_pages(struct page *page, unsigned int order,
+				    unsigned long ip)
+{
+	__kasan_unpoison_pages(page, order, false);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/239bd9af6176f2cc59f5c25893eb36143184daff.1703024586.git.andreyknvl%40google.com.
