Return-Path: <kasan-dev+bncBAABB7MQUWVAMGQEN2EPDIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 218807E2DC9
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:11:43 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4091c9bdb8esf35562535e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:11:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301502; cv=pass;
        d=google.com; s=arc-20160816;
        b=ux/ua7Jk9kXrhXTZJZSYTzoUaY+fUkc5tfaD842cLQZI9XLxzD6SNu6qZAIXy3WLJo
         Ui/6DUjhre0zQT6+U+T38mXuLGGYMv44COqBkTNWA61xubPmmPkC0SRLh34jLJmJkrr3
         fLjnaYgal8DxAdF1ZsqzrxfFTwSuOSjAnhujExXALe+ttsIX/XG1tJAWPK0dkPtQS3hh
         ytyEHI4GUZ5YxM57LJ7lEhQ1MiD60/gWZtZC5MToDtDwbOKYYQAafjSB4p47BDn+n0XR
         Qio6kGpZOd8JbxSxSVikdSdNe65LBHfIcbSJbw5p39nlYnNfB0R+wPq8sTAr2UPtjI8C
         p6Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=edlWSD03p8vISS3AxHmIiZ9NYYenAg0SxUOI8oVNuoM=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=maSSR+0d+CyrA823IpQNq5Kw6pa737IFUdU8dPlMKKHGD493BFrPVDYXPTEnEGgf8y
         aAlVomVpZvljo2dawvHUGta/YF1yyxTCXCnC35YQ5M8tmG+zRHaGRd3HP+DtCfHBQGE+
         S3rLqYjqIaCviUb5QLXlgKhF4qOwI1D5eN5lne/a5wm4JEsCDiRu8U4pIiO13Pe3Nd7v
         Wr+Yj0DuOi6Si0qdPM2ePwTsuYJh/Qivzdwxa3jkXQUCbyQObu94TFXnGCvIibQiviSG
         TEy749VadXIpZRk6c7wIPp1cJ8WqUe/hvIIRuGvfsT6Onmz9Qs8u+wyhEHkuDu5xszyp
         yTIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="nqNu/iJt";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301502; x=1699906302; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=edlWSD03p8vISS3AxHmIiZ9NYYenAg0SxUOI8oVNuoM=;
        b=smN1NQ1sT6ReMtnXrKHIgtr2nLfzXvLEakN+DsK1Gk5PG+srSUjgwOiUrVThKSBa8h
         dJ9QQQia0A+T3euDO3DwiwaxG55okmGGsy3h4LbTnLadVl0X01VwqshbZpDIBv29SIV4
         /xDzwz8mO0TtA6D96bkWP4VKc2peExzveZ2XIwKOKeRjiPCrC849DjAAETXr9YqWozM9
         HR3TwQxR1XfZYEn7bZV4G5ohPIXsJxxmiFEd4s0jd8laYbjQ8LzHxb7dFjJpgJxLWmEx
         p2Hn075fay0VvoLQZJ3HvUgeOpYLh52gUPMqK5kcLe/jBMS04GXxoOI8tLsUmbcLvJ2f
         DImw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301502; x=1699906302;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=edlWSD03p8vISS3AxHmIiZ9NYYenAg0SxUOI8oVNuoM=;
        b=Ml6G2WSHR9cTUG9JZ7BO28auLj6hGJ/NUM5nItenJefH0ViSei4D8z9OF7SIzkWJfI
         Gfkou0MJ/ihh+p/VO81bSGenhwLwfJgPTcDi+YQUaGqGlDc38y98rDskU7HnY6uYETGw
         c4JvFT+0aeqpHva1T/+KYZr56FsaVSPVRlhq2zOaINZNIdltWG4LLSBqUgiy/2pYyy2T
         auVtFB3bQxPFQRG80NG3CA1AlXDP3BiOCSUQmOIzFlf0tEsY/jpUafZHDdk19E2Yf7SU
         9Ke8NLhixbU/xZbHG+MMiAFXte9/lQcg8xCLaKDCh+JmW2vDYnN7dwvYoH8gQl/bE6yj
         KLkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzUCJHQTDLuM65HYlxoF0Phw0VEUihIHPEJnUPEsjnf1QNOvvZW
	/fSWbdPNqiUkymgMh/Y7/uM=
X-Google-Smtp-Source: AGHT+IEGfcj9rDxVLE1NH9YpVH2ykY27lHuLHU09dIAZXq8Nh0KoPH3zvgPvFiMNvhwxeYIDoN+pCw==
X-Received: by 2002:a05:600c:c0c:b0:401:b425:2414 with SMTP id fm12-20020a05600c0c0c00b00401b4252414mr654744wmb.18.1699301501474;
        Mon, 06 Nov 2023 12:11:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b9d:b0:409:5426:9d6a with SMTP id
 n29-20020a05600c3b9d00b0040954269d6als1497232wms.1.-pod-prod-00-eu; Mon, 06
 Nov 2023 12:11:40 -0800 (PST)
X-Received: by 2002:a05:600c:45c6:b0:405:3924:3cad with SMTP id s6-20020a05600c45c600b0040539243cadmr711940wmo.15.1699301499618;
        Mon, 06 Nov 2023 12:11:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301499; cv=none;
        d=google.com; s=arc-20160816;
        b=XY/uQuv4BhS4iej3W1n672dYGvadQV5vs6794hQNy/LXUQCH2gSkLJGtYPmnoL+Kim
         IK8IXCYw6fJtXP/JVD8xid2+YSzKQ4D0Qgc+Nfg8Ppvd2mYWhQj4dCrex/aqjjMTqnmR
         /XTEfgZ+HkgA5BGPNRbg6Lp52Q+WlGL0nUep8egDMOyh9/xCU8/0ER1vPyDaeIXg7fRY
         zR/sy1/pENTs0elwCw8mFbJPDezQZq8SCFnbwihpOlrKvTk9fBcZZmQCqLTJ7nSjZiOz
         9qn+ynP8fZ8j7yJCUYDSINNubYodwb3IKqb7hz2DvQ/lbpCrGPtydGNF9DXizMJv+Q9J
         iQTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z8UoFAswFgd+L4wk44THWP2F8PtTdf8hA2eur1Xmylc=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=PBk+As7oMXUHFkghJXq0s3s6hd6FfPyLyLaJ4mtdIEairKYDaFDqwH1KiHg1CjO8we
         zQLS4v1DVin+xs6qwU0Rb5c6+qqFc2zasH+YKW49XOJ0Hly1N/23TduHrf61ZgZkE7Yq
         5MCQpxRey+G3NPBTzvXldqPrYCfePkTzVPxZIyUQZOXVTmiEcxthuk4LvkSxQatvRAAS
         ii0r/r/SC4692/yxLQsM+WqPm997Vw9CiZ4LpjBNisIIhgZBj06kSO8sXHfH1gY9MgTm
         uFAICemnulISoQHP3H5rSat4oR+BPe3Qd9RYgCdLqjjz/UsIZxL6z/XB/Dt+VQ4i3r1m
         HwIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="nqNu/iJt";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-172.mta1.migadu.com (out-172.mta1.migadu.com. [2001:41d0:203:375::ac])
        by gmr-mx.google.com with ESMTPS id bd27-20020a05600c1f1b00b004047722bcc7si581366wmb.1.2023.11.06.12.11.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:11:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) client-ip=2001:41d0:203:375::ac;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH RFC 07/20] kasan: introduce kasan_mempool_unpoison_pages
Date: Mon,  6 Nov 2023 21:10:16 +0100
Message-Id: <573ab13b08f2e13d8add349c3a3900bcb7d79680.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="nqNu/iJt";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index 9ccc78b20cf2..6283f0206ef6 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -439,6 +439,12 @@ bool __kasan_mempool_poison_pages(struct page *page, unsigned int order,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/573ab13b08f2e13d8add349c3a3900bcb7d79680.1699297309.git.andreyknvl%40google.com.
