Return-Path: <kasan-dev+bncBDAOJ6534YNBBLVVT7DQMGQEYNZCY2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 38432BC9DE9
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 17:54:24 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-63798d4b7casf1448589a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 08:54:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760025263; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y39h+VgCEqEBphK7UoQN+2Mu5mFQGZAq0L9MlJLgIQchPJ+OhHZcrOs+t/miqNfhZG
         Ml5Ok9jyLhQscUrP+D5RzT2LOUYoYrL2COveR6vWO5g1HsAqu5nFj+p/Z9JPVzHu+I6A
         PvRne6t4pYli6q0WJ3O9uGmnX9Bgbbhyol25qML/lXc4rWPPgj0rk136GIyM5TP4+H0c
         mJ1bFL5LIkLIEo67Mlqph7vwsVscdwCA0HNtN8Y1lPbSY5bCrrtEYDy0y/CeCLuAuC2r
         7QDxEbWq1vDukgp1li0eTvuWpwKzSAQfHcx8ufKTd+0/H/zrx6IMkYaHAWSCpTLNwu6n
         fWsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=oSyQcOwxf6SIFrhPG1pDhemuTy3+XBPxdT3USf0rq0Y=;
        fh=ESx9AYoAZOl6FYZoSr7Tma50zLuBcrpOjNMaOCTVUhA=;
        b=L5apkNrtbQ6ROJ1a2PsgZHvv8o3KgmgB7/bUVIxveyP0/UdVHfV26hvgz25sIXLaOC
         laexD2Wv2OW0TN2cYS8h5PLvO8aUB5yRssOC2wzY4CXLZ6PrraT64zPbAYw2iZoq1PyG
         0fWmiym7ua9qwQvk2CLfb0WVGk2RA9UDuBOKWwiqjF9wCAwFpzNVV+2MBgzwRu/rRudE
         Q+eGepgx7ZSXqxLFpLnlvJ70L9Ki0IdhTq718HbocQu9OonXZsqdphpbRUaeo0DH9pSw
         QJMMPwOfseBG0qLjRIlPQ/6zLrSl+QHr0ISjbHH1PwDsn/pzPD5lBpsUma/rTHD3O0Js
         dm9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nscSAR6f;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760025263; x=1760630063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oSyQcOwxf6SIFrhPG1pDhemuTy3+XBPxdT3USf0rq0Y=;
        b=MUAjp6zK+Jacdvg/Xl8NjuGB6C6Gu+Qm62vCqin5AHAjUIt7n0XhWoi2EYwBAdxp2d
         3gygx7JoAFFK2kNKXY3adI6YgdsTcrAS0+jiD5ExsRSoAPdMcXOoBjGts/T72K53RY0w
         ur4EqhygLT8/752cYicjKvQ1/YawDhqI2HzUsrcDMbTp5lOb+BLcUujM6xjS2zeL53v4
         CHgZSXvJe4EQZlEuGO2uSdhOp8cJV/rlyJiimxRO1BytZ7QNVvmgrrf1QMjiDuj6syZr
         h6zYAJx2ryKwolV45Ua+BmdPFGkMHwNlft5wirSXarfkO/vTRxzG7y9DFHfoTf+H9xse
         7GCQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760025263; x=1760630063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=oSyQcOwxf6SIFrhPG1pDhemuTy3+XBPxdT3USf0rq0Y=;
        b=VdFmw8Jag9qw9iEyrO6MvhQl0DHFqWhhUpsk7X+ZJayHaP/X4PRyhCuKh0I95uVdio
         xNPt3c2cDa01lSQlda9UVKoWpJrFWBg47/XbjF8V9CkKm9w9FOqEOHbXbZPBtgG6ETkv
         J9cayEVxG8voD8bJ3X+QgizxhpY3KbcLPcjGNoMJwoiWgEeD3jyBWdwrRj+fdT/0DHrt
         xjJsFzW+GTHO/69IfugxuF3cq7hLNjuTprVSJKOZtCR+i1hn5C+9h7bqrtTvmBYeLDm6
         seBG9geNRRPt4mJ9EvSC+MlCVO4k9qkjuY8CJQYfCcIVD/bhvPJ1vXtEiFLhCambEMnO
         8obg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760025263; x=1760630063;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oSyQcOwxf6SIFrhPG1pDhemuTy3+XBPxdT3USf0rq0Y=;
        b=IA6z+DAQSIlujpVNNBxPK0DuubEo7DaniBkKdqfficF6kfgxX4mLm/yo456A2n70tm
         b5f1RJNbsJioM7eQWElNGXQxadzEuX5wSYbug2P397ZCCHBeHpUsnl3N/Q1h/L/TXsNV
         eII5UPosVRxNn2JsLlLnx5kUjK8uO44NkvYfU8mnGBN+H2aUghm6zfuQADybxZWAtkxk
         LCaDmYLbRDZU1/P77YWTTve9IS6PiwrPrdConxeTEbJZk6QHbgsV2A0jUWJpG8INgx6C
         tCTeVyIrYuD2aXVdyPcuuGANekWp51VD0CuJRmXb/0FAfM91ZQ2adAsEbdCX0ZlYWVin
         +QOg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWOis9kdy/ibiY/guHeC+Hz2EUI2AfRfPFGIRvd8l6UpCBGpXz9RpiNECMSQWseQUCrgWHcKQ==@lfdr.de
X-Gm-Message-State: AOJu0YxcbLusg+x8YViNh5PSKptYGonTCj0yKlHGox/nfO0SDJItT8zI
	QN5XlW7KBUxAG119RutQSrDdRm88TOMqNBglND/GdWtb6nWIIrAJ1QjB
X-Google-Smtp-Source: AGHT+IGSkvWuZ5dxytS8oWwCTLoDDzJFvdiGPpnTZrXEHG3kbiuw3/UBz/EotBarMYQ3Efqe+l8rsw==
X-Received: by 2002:a05:6402:5244:b0:634:544b:a755 with SMTP id 4fb4d7f45d1cf-639d5c3294cmr7979677a12.19.1760025263381;
        Thu, 09 Oct 2025 08:54:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5Yo32X4ZqA38gfceAnH3YZ5n8+3W5O8ECI98pLnoYIwg=="
Received: by 2002:aa7:c1cf:0:b0:62f:4bd0:6c60 with SMTP id 4fb4d7f45d1cf-639f5a022e4ls1524677a12.1.-pod-prod-01-eu;
 Thu, 09 Oct 2025 08:54:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZgN5Ples7p3K+PEMBEcmvWg0P14/oZMHWYkQsGmDBLjqys9+ItiIBRc9b3QCE70HdwXb+pRDR0TA=@googlegroups.com
X-Received: by 2002:aa7:c9d4:0:b0:637:e94a:fb56 with SMTP id 4fb4d7f45d1cf-639d5c71065mr5797293a12.35.1760025260682;
        Thu, 09 Oct 2025 08:54:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760025260; cv=none;
        d=google.com; s=arc-20240605;
        b=B97et4I0C/mv1UU7fTm/7B8YNNo9LGhSceufIMiJt43qhNgKQ/Nt5My9vm9LPrFjpH
         5c8tupFQHxnU0ToOwFA1JGBShWGjENJg8LC/f13vrHla8xMQrtCrKp81ibCnEdwQaq8t
         /KRmzMA7N5zV1fcxnJQIV5QYgDUy+ZYqiOkz3l5513V7xhZqtMVqXCAIxyPvVWdsfPVh
         u9lU0Ay+CI5cHw7TVzJK21MYuJHSBcoRa8Cp7t6ZmNF0ZVsGpth5ou/ChB2Jo7TxL1ht
         AFBEJP/Fw/K1De3XgYXVT4PDgTD2oRHTbLVBDCXtP+feVRhfO2hvQcXqRNUxFEOu3hz/
         q2sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=h3jD6Srgk8c77Z/UJ+8ukqBQAN6er5a/zSDavY8QJGM=;
        fh=akHXbSTc8NBH6rJwDwDol2VQw6Zmj3V1rBLHoBINCOs=;
        b=IGkpyiOzauTotaAp6BI/HbRNr+SJcJHU8EiDzk7QkRlfjzDEEe613Bhc7p423l1mTQ
         UAI/WJitnd4fhARhR6HMLwGNl0Lq45gAJk9PL/at+3FZ3KIkyF0yO+UXhIN0GptL7coQ
         XYv1ftLLrB9Pw8GWVMyiMdh/1iZWss2V39aSMxYpDsARaO0pjQXpa6E7rTXBaCar/7v+
         fpQdcPu6+86PG0p3m2YYQNiEXRQJcLSj+mOyMBkjS03RIUjo5weAF8rnDSUmBWGWUHZL
         cuEvLhk1HhbjluitY03RbXCXxV1MXCRYnJQH5FSpJCuTxKgYe32wS6k9bgk8gg88mwgC
         MIGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nscSAR6f;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-63a52b04152si12731a12.1.2025.10.09.08.54.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 08:54:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id 38308e7fff4ca-3637d6e9923so9335051fa.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 08:54:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXnqKJdaJKt6CNN4BikPOZqzyj1Qm7Fb9qKRc8o7cpp2xC4iEVtyOFuu4i/GkuVDEzre+OcDg+9+HU=@googlegroups.com
X-Gm-Gg: ASbGnctqSKq1ACH1Zbi34RlY1AtoP/9j4FlHxJNcQc+9XYTK7As46gitIQEv9nBRUv+
	TCeNDOQiqw+f9uj8vaw/r7o8XcClyXq3QzC0inPe3hcpmZlsB3sCo9+WerigkqidwhNHnRdbPoQ
	CfIr1i1WZ0alkd3J/tBHOYyJsB3zzkodzTy6naKMY9X12gPoj4uwTDRO8hnfiYFCFLg0MCy00PV
	xqZ8p1rixMz1xf5iaTGXvHNb8hA5pVaQIj/CxWHz+dVM8ki9s5YKX43CHlN50w58Fgj5LOTE1mR
	roi02Z9RUR7WUmwM8xUlZzEfSvakchQHgUqgejj5h2GDJ4pCK+csWmRF9f40uXOZMkrAqeEJiiy
	m+2qoy1Amy9UYpgmp7aU7bNo6r1XOgInIiSMxbDIGA9fJEfnJAZycoU2QZEAAhCZV+IwPcmyk5w
	==
X-Received: by 2002:a05:651c:2210:b0:373:a537:6a19 with SMTP id 38308e7fff4ca-37609cf869emr22052341fa.2.1760025259655;
        Thu, 09 Oct 2025 08:54:19 -0700 (PDT)
Received: from fedora (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.googlemail.com with ESMTPSA id 38308e7fff4ca-375f3bcd2a8sm29499831fa.55.2025.10.09.08.54.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 08:54:19 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	bhe@redhat.com
Cc: christophe.leroy@csgroup.eu,
	ritesh.list@gmail.com,
	snovitoll@gmail.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: [PATCH 2/2] kasan: cleanup of kasan_enabled() checks
Date: Thu,  9 Oct 2025 20:54:03 +0500
Message-ID: <20251009155403.1379150-3-snovitoll@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20251009155403.1379150-1-snovitoll@gmail.com>
References: <20251009155403.1379150-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nscSAR6f;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Deduplication of kasan_enabled() checks which are already used by callers.

* Altered functions:

check_page_allocation
	Delete the check because callers have it already in __wrappers in
	include/linux/kasan.h:
		__kasan_kfree_large
		__kasan_mempool_poison_pages
		__kasan_mempool_poison_object

kasan_populate_vmalloc, kasan_release_vmalloc
	Add __wrappers in include/linux/kasan.h.
	They are called externally in mm/vmalloc.c.

__kasan_unpoison_vmalloc, __kasan_poison_vmalloc
	Delete checks because there're already kasan_enabled() checks
	in respective __wrappers in include/linux/kasan.h.

release_free_meta -- Delete the check because the higher caller path
	has it already. See the stack trace:

	__kasan_slab_free -- has the check already
	__kasan_mempool_poison_object -- has the check already
		poison_slab_object
			kasan_save_free_info
				release_free_meta
					kasan_enabled() -- Delete here

Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 include/linux/kasan.h | 20 ++++++++++++++++++--
 mm/kasan/common.c     |  3 ---
 mm/kasan/generic.c    |  3 ---
 mm/kasan/shadow.c     | 20 ++++----------------
 4 files changed, 22 insertions(+), 24 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d12e1a5f5a9..f335c1d7b61 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -571,11 +571,27 @@ static inline void kasan_init_hw_tags(void) { }
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
-int kasan_populate_vmalloc(unsigned long addr, unsigned long size, gfp_t gfp_mask);
-void kasan_release_vmalloc(unsigned long start, unsigned long end,
+int __kasan_populate_vmalloc(unsigned long addr, unsigned long size, gfp_t gfp_mask);
+static inline int kasan_populate_vmalloc(unsigned long addr,
+					 unsigned long size, gfp_t gfp_mask)
+{
+	if (kasan_enabled())
+		return __kasan_populate_vmalloc(addr, size, gfp_mask);
+	return 0;
+}
+void __kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end,
 			   unsigned long flags);
+static inline void kasan_release_vmalloc(unsigned long start, unsigned long end,
+			   unsigned long free_region_start,
+			   unsigned long free_region_end,
+			   unsigned long flags)
+{
+	if (kasan_enabled())
+		return __kasan_release_vmalloc(start, end, free_region_start,
+					 free_region_end, flags);
+}
 
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index d4c14359fea..22e5d67ff06 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -305,9 +305,6 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
 
 static inline bool check_page_allocation(void *ptr, unsigned long ip)
 {
-	if (!kasan_enabled())
-		return false;
-
 	if (ptr != page_address(virt_to_head_page(ptr))) {
 		kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_FREE);
 		return true;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 516b49accc4..2b8e73f5f6a 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -506,9 +506,6 @@ static void release_alloc_meta(struct kasan_alloc_meta *meta)
 
 static void release_free_meta(const void *object, struct kasan_free_meta *meta)
 {
-	if (!kasan_enabled())
-		return;
-
 	/* Check if free meta is valid. */
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREE_META)
 		return;
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 5d2a876035d..cf842b620a2 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -354,7 +354,7 @@ static int ___alloc_pages_bulk(struct page **pages, int nr_pages, gfp_t gfp_mask
 	return 0;
 }
 
-static int __kasan_populate_vmalloc(unsigned long start, unsigned long end, gfp_t gfp_mask)
+static int __kasan_populate_vmalloc_do(unsigned long start, unsigned long end, gfp_t gfp_mask)
 {
 	unsigned long nr_pages, nr_total = PFN_UP(end - start);
 	struct vmalloc_populate_data data;
@@ -403,14 +403,11 @@ static int __kasan_populate_vmalloc(unsigned long start, unsigned long end, gfp_
 	return ret;
 }
 
-int kasan_populate_vmalloc(unsigned long addr, unsigned long size, gfp_t gfp_mask)
+int __kasan_populate_vmalloc(unsigned long addr, unsigned long size, gfp_t gfp_mask)
 {
 	unsigned long shadow_start, shadow_end;
 	int ret;
 
-	if (!kasan_enabled())
-		return 0;
-
 	if (!is_vmalloc_or_module_addr((void *)addr))
 		return 0;
 
@@ -432,7 +429,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size, gfp_t gfp_mas
 	shadow_start = PAGE_ALIGN_DOWN(shadow_start);
 	shadow_end = PAGE_ALIGN(shadow_end);
 
-	ret = __kasan_populate_vmalloc(shadow_start, shadow_end, gfp_mask);
+	ret = __kasan_populate_vmalloc_do(shadow_start, shadow_end, gfp_mask);
 	if (ret)
 		return ret;
 
@@ -574,7 +571,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
  * pages entirely covered by the free region, we will not run in to any
  * trouble - any simultaneous allocations will be for disjoint regions.
  */
-void kasan_release_vmalloc(unsigned long start, unsigned long end,
+void __kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end,
 			   unsigned long flags)
@@ -583,9 +580,6 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
 
-	if (!kasan_enabled())
-		return;
-
 	region_start = ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
 	region_end = ALIGN_DOWN(end, KASAN_MEMORY_PER_SHADOW_PAGE);
 
@@ -634,9 +628,6 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	 * with setting memory tags, so the KASAN_VMALLOC_INIT flag is ignored.
 	 */
 
-	if (!kasan_enabled())
-		return (void *)start;
-
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
@@ -659,9 +650,6 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
  */
 void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
-	if (!kasan_enabled())
-		return;
-
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009155403.1379150-3-snovitoll%40gmail.com.
