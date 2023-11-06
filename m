Return-Path: <kasan-dev+bncBAABBB4RUWVAMGQELD2SHFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A0C5E7E2DD0
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:11:52 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5094998f7e8sf5503619e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:11:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301512; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qi9z6lfa6Dfko7N2/0qjXgpeI+QgMTRfmE2mQRFdF4CaACqg+TDiV/lSesdMUWC7Rz
         Itym4SuvS60BOQB/8HTrR1HjkpV8uZ9Xsvc5BWqYylLvnaDaBATDk8QCDeHis/wgzHlX
         a2z6Wl5xB8OF2FJ4WLOds/GgUfR3Wxpwc3It2r5NNED9N8C8QjpK8VDIm+EgGN6FxNP/
         14vZx20c9K/N6swy4J2bGNKknrOC+rmSsL3k9YwXvpkwWyjl+o+qCVGRaxca0ihRxbCF
         LHltTe1zgl3O44TlhPDtu5f64d+ee83V8wZTaXo2kkl4pBg0kLHAh4nzfes6K+EuELae
         9zEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=h/DGIKM/11S8hC2r/q/NnJI9CBXw86uu93eQFhA/Exk=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=B01BNpm+k4+N6/8ruCAUfaU3WiwDQzL6rfYjP63N+uFnBcBSQHGD6F7UU+l1LbeWwf
         nU6RfIR+pWp9e1pUEvqr3KfmFiNobF3q4TpD50i7lp5biSukkkJqrvNiY+nMs/E4ZDiD
         UlnE6Phmj/lhAoky3EAaHS/dAp6PkyyjdLId/D12Npm1Ey/lXQRv32NqN9C9bHxpndqL
         fDscaZNKmxd0oGXwyZnv4vZJ8qwUUy7e/nF8hecXd3jutKnD4s6UReoyIZTgtUOw748A
         h8/dxU50P9nUZjLmRXv9eJpe11fbOdVcxw5VHNHz9y7Wfso+Y4jfh+2FGv6XhKW3rxRA
         EB2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=whzKutAZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.189 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301512; x=1699906312; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=h/DGIKM/11S8hC2r/q/NnJI9CBXw86uu93eQFhA/Exk=;
        b=jKA57S2HQN8YtUdmrBUkoyaqnT5McF5NfimX/lkDiEnfB/F9+/Q+iH/6+0SUaqXSGj
         0mnKWKmINP7WYKl96L78lpIfr0L0HNHU+SwVV2t6r1/mm5T06uKi+jSO4ImlSXNOC761
         uf+SfpIZbAKjirQ3UPgRLhNVjlLcqVqk0dfpe9maoBmeyZUYj/0t0TLRiZ5EAZI6MVso
         qBGGJoaCgjw30LBnXimVI506aYgZ+wEzwsXW0KABmFA9zLIYxGIp5F+oWFR9R1kHoyMy
         sBnKtCEg7tEu4KYTMdIP5hg86Xk9pvppPb94yoH75oVpkiEX/NtyzvhA0CA31D+3sZhH
         qlyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301512; x=1699906312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h/DGIKM/11S8hC2r/q/NnJI9CBXw86uu93eQFhA/Exk=;
        b=P05haDw/p5lHIlWE+viL+tyM+F7R90OEQyVx/6TTUc73G4QtwTHjb5vLPqRQ8DqqO1
         7CHidoycW+6weMoUZKqZB1Z4XxeBWAzkOtpNpLakno3ytkOK5h/ER9kVBTMRXHEnSECR
         ji5xIGHZDs9VIyhZEeQtGWUI1hLJPgTs6rmcIFsk541iABUb30Y62l9S4pl2fdJR63nJ
         kvsSUb4Znm/SgXR44DZ6jJ1BL+7Powr5qyAwLSvkba+HkkO57I/je/rKIGizdMI97KpF
         69RqmAYZXZGp4y3jrlzxU+sXJxtIL7RFZOThVfyotO1StXTokgJVPmaV3gG2JZnlwl76
         rsjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzhz3EO+aitFJzlvlEjdvBLNnoWdkCL4Ir9LJqe0MTwhd//7ALv
	CioOBrUzXGSuNylGjo7DxQ8=
X-Google-Smtp-Source: AGHT+IFpxQ0qOGErheCygAkRcOp8A+M5gGAGcAMlIbF1YGvs6vTjHsXyOUTtuAseS/8ndB+f4rOc6g==
X-Received: by 2002:a05:6512:401b:b0:509:e5e:232a with SMTP id br27-20020a056512401b00b005090e5e232amr24252320lfb.42.1699301511244;
        Mon, 06 Nov 2023 12:11:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:562e:0:b0:503:a8b:c1b with SMTP id b14-20020ac2562e000000b005030a8b0c1bls2483329lff.2.-pod-prod-02-eu;
 Mon, 06 Nov 2023 12:11:39 -0800 (PST)
X-Received: by 2002:a05:6512:ad5:b0:509:11fa:a208 with SMTP id n21-20020a0565120ad500b0050911faa208mr24870674lfu.43.1699301499513;
        Mon, 06 Nov 2023 12:11:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301499; cv=none;
        d=google.com; s=arc-20160816;
        b=bFtaXpJ6E9OH2sk8FFx3N//YPlFytwqxSWtNTaVU4ZIRleNk4c/k9Bf1C5XsQKcDnW
         0QhW/gkfi6dYLeiZWdcAWMcQg+jQo5Z3pM/2T98b+Yp2Sa1P9qXkaCydVpnkvZM5EVgF
         wBz208EQSfiG0lyfvIGCfGN6Bdw0SOMeKJFUdLq70NXwtu3Qwl6BNLoJSlhXzgI+B1+x
         DSgQGnTLPAg9ISL0/WE8mfyguZVxXQv/NDSBKEj5j8oyHGtGpMpxJ9wfCkgVZSdM0W+D
         K5+ti5hw+qyCgYqjn9oVgVYcTs8oCe9/aES48KUsw3uLuO8c4bOLGVPwHSGbO3HwJs8Z
         gwZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wOW8bM5LUt0/83cpSlqfBj0DKQkCrWZjISfEAI+z8F8=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=tK4eH/+fvPJz6HOWNceqjuF3LflDdnr2AhwnkLgEwlsS40Yk9FytVOv1RQIRXmWtd6
         CvgLAnpARrPKVuq16SYtRWuFt4nCcWjaMi3LNMDD+s/1dMuCyr3NbAnghrOq99rsjlRR
         wy3Op1mnF2eIQpzcvyMZKh2WQhbUd+5jrXaB6ElFfeXWCOX3V5RE5xvblwJuUkgFiOB5
         hbgHGRV/cTkeC2Ftpw3AaWpPme2JCk/Wp4WRODZhU9+5mRmtixP416T6QlLpLZzP3c6J
         upiqp6wkIGrnaDiyfASw01woNdBwmdqQFynOW6G7WfuywS86PB/DFvte2qVLKsTow0WA
         Rq5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=whzKutAZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.189 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-189.mta1.migadu.com (out-189.mta1.migadu.com. [95.215.58.189])
        by gmr-mx.google.com with ESMTPS id b14-20020a0565120b8e00b0050946d339d1si552541lfv.6.2023.11.06.12.11.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:11:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.189 as permitted sender) client-ip=95.215.58.189;
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
Subject: [PATCH RFC 06/20] kasan: introduce kasan_mempool_poison_pages
Date: Mon,  6 Nov 2023 21:10:15 +0100
Message-Id: <3a377ec3223f9c98f3ac471845e084abe7fd6fe0.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=whzKutAZ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.189 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
index 033c860afe51..9ccc78b20cf2 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -416,6 +416,29 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3a377ec3223f9c98f3ac471845e084abe7fd6fe0.1699297309.git.andreyknvl%40google.com.
