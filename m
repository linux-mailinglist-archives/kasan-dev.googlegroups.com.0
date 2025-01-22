Return-Path: <kasan-dev+bncBCSL7B6LWYHBBX5PYS6AMGQEFMDVIJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A68DA19618
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2025 17:08:02 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-43625ceae52sf38612175e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2025 08:08:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737562080; cv=pass;
        d=google.com; s=arc-20240605;
        b=iPv3Lci4XZZpY+OpwlZ8rsN3+Ms7oj3rfzs4iOI2kqg9p5578jhG+5dQEjOoiLDOcL
         b2sukSiI5LHLesMg3i+uiFTO5GEnRkHfHf3Rmti9hl31P1Apbo2CpzO4U1BfGWMcxXoM
         Xh5SNDQCkXc9dDP9WQheK5qHoz6AHZcNSc9UxWdktbPSb76LX/rFv7BhooNcJxD5c6Ia
         3v2K3CPKOlABhPoKOSaufZffhCqZgmphHJ9oJOxtDAKG0bOHgnmmyQoviP+zbfdXR2sr
         BvvIQPvpg0RgBqOf73nKA5KkHQ/uGLf7K2q8k3El8ZaqwG4D2363KpAJ3cd4MwAVEbVp
         M5PA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=dyPlhfivXxNKMDGFHRQ1GP6dK2Wddv/cJm+iHKIURTM=;
        fh=3V6ji21mXoLhuG3WSOB4qFhePbTWi9gMabV5ACEtWis=;
        b=VJ7nfro9bzBAYo6Ip/htIFtAnIshwVfvvV345IY8vUyvddJMAuOQcKQM6F5f76mWD2
         M+uzEgRnTa0ImjNImtpprgf1MURAPL5vqErNwfnoRCzmm9RHcaik6mPIKQ1PQLip4Kmy
         RZs4rmkh3E6QsKOJa3WF7V6nMRyUtrzWXTn6nv9gsNNmhW6QUUTLhs3/3JQOvF+LjMw6
         wYs+Tlq/YJIbopCzxk/FZ0ck4SC81I628shGJbwdZxRQsX/Ss9+PKKmqmTnj9Mw+Agke
         CVpWw2wMqJohbb2c27FqjGCOpoD3eTBUtEWQiTz5Hojhazgw24KSl7AW0J2QYpd0C2Kp
         D8Ig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P4oALf8u;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737562080; x=1738166880; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dyPlhfivXxNKMDGFHRQ1GP6dK2Wddv/cJm+iHKIURTM=;
        b=gOP+gHKa8hY7Bx1GtQ1xnfTtZ33cwkEx7oPHpSDZ3diCzbh21l3KnaYDUmWkCxFrbU
         IXPcbRzzYTKpmJ1dAMEwiNYEY2qwighXZqm6bOm7UzwBPUWh7ICnAtd0Z76AQiJf1NyH
         FTPD0ZYbp6tGoaNWH8Lawi6b0LFhYYlVWoE6rcuS2YryCww/Xn2AcHA4BHL0GVpwPWM/
         kwf93I7rxmhSzq8cBWicYM/SYzzUDM6PM1POvYlVucJylk4g8wT4fBuM831ivCAu4hAA
         5XYnyPn0DTKFjfrVfjgfQiJT+rUk/+ATF6zxA4ELCHklakdvp9MkWrVaYDwXI5ZoYvSN
         r8sw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1737562080; x=1738166880; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=dyPlhfivXxNKMDGFHRQ1GP6dK2Wddv/cJm+iHKIURTM=;
        b=jyotBqreGKpyGBk1uSifUdlKV+WkF4e/cTFUAyvnvjrr2jXXXKqs9SR4xL6ccaG4zR
         ZinMD8mZ+uLlXdZmMh20A+Oh0s9ztc3Q/59hJSVIwcaJvxIAzyygMvxpFKDVHzxg6yIF
         JLRFmK0MIedlHU6eZ/xFNquCSH251looxBKR+7PAnp+bAjwao3fWe4Xo0lNx6QFE47Us
         KEviD+nM/XE1KnGsfwA5y5wc213IQae6d6/rdqjJhmVtl3G9hpmUyfpJ+SYMYTRObCyA
         xZKNr9nGHfgktWj6fvpF8o5OLyJQd19GAOQzRQLwH/f4zLgM0CMXXHX9U4PAlXDPlyVv
         c0GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737562080; x=1738166880;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dyPlhfivXxNKMDGFHRQ1GP6dK2Wddv/cJm+iHKIURTM=;
        b=YdQzyutcGxONumw1gy36e4ihcd+szZ3H/KwYquuyYGedyz7yoB3+iObVhx6QZ59YhF
         UAYWdro5fpx0cvYoareMUqa0LfAprp+KDvhdSJjs8Ke8JgvNPNIeNojMVsVTLvWuYjE2
         AYDDH3N26ri++OAjz4lOybjVGQyxrqwpNzLVveng3IYhJsWfLCWIBTywPfwlna4OwFMK
         /cLbxcJq1iJeS4O19dhMXNr7dUPUFYvMXNFUl1iXR+SUH2ZZopUiLu5ASrHK/P1fayFX
         C08V8sL3nYWMgxpU2OhahxWK9oQz69Wb6YQ1JZArCyr8fMwTkqUwVDHvjfKMvTpBDRey
         m0hQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXX5Fj4zQ9Ml/kXKww7w/ZCH5/9JkzYwVAkiXaY4NGook+DoiIcNwa1acRYHJ847h3OooXTRA==@lfdr.de
X-Gm-Message-State: AOJu0YyyW0/IartRn5FjNpZ/1DFdD+iFmlq4zVrll5huiT1UZjy4o5ft
	rrm7mUpIdAu0siiAgopfmMHz2PcETRJxdU9022yCNkVDyalt7D3i
X-Google-Smtp-Source: AGHT+IHK6WxIdSKHQrK9axaXjr4SYzFazsWJqNcjfEym81kgGnhTRpMfoY0DH5MrrNX//KRIBEKiIg==
X-Received: by 2002:a7b:c44d:0:b0:434:9fac:b158 with SMTP id 5b1f17b1804b1-438a2b59615mr129361695e9.1.1737562079444;
        Wed, 22 Jan 2025 08:07:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:c2:b0:436:5d0c:e9a4 with SMTP id
 5b1f17b1804b1-4388ab1950bls2390665e9.0.-pod-prod-08-eu; Wed, 22 Jan 2025
 08:07:57 -0800 (PST)
X-Received: by 2002:a05:600c:450c:b0:434:a91e:c709 with SMTP id 5b1f17b1804b1-4389145145fmr188686375e9.28.1737562076991;
        Wed, 22 Jan 2025 08:07:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737562076; cv=none;
        d=google.com; s=arc-20240605;
        b=c5BwFgSjIAUC29Dx0iYvVqTLwxR1KjrTJapEtccLqER60F6/gbjMh206LkNmyFj2CB
         yTOXdz0IJcUsLM32VaMp+tvobNMoKHlHebXwFDb2HBXd1PwkXmi9vF2ec59q5JirqZd4
         4gf9T3CXXKIzNcb7CmGqyToWfcAPseRVCxnsJS7iesCiURJj+XDZ5/kvYY6gZddPeEYJ
         YrpDElgTvhVkaom0E2U7VaTGKPxrGE2IgymiujzaOQz20spdl0vGBgp4I3IuCar/njaO
         BDWtOjlvwb/0BDpD4EXmGvRAX/iPHzjPqykvqGHMjCQbGblgk5TwnM1rxABPHwOQptmz
         Ry2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+BA0Dq1q60oIyJKUAlr4eKLYkxcKes1Z2J5zA+l+Dug=;
        fh=ZOEubWtvtpyt65cma0oq//l1eUii/kYji7FPDYyfmSo=;
        b=K3oPYxEqlJIyuzQmv0FhTrw/gOmFtRuRNnuuilvvdLz3Xa2+v8GEPXow8nSjWQgWfX
         JKs8qMHqngc6smykSwfz5Q2nRaann+tgIu2nRUIux5/QuuJMWn0aT208CyM9o21O74ye
         PzKFxe5pwI2NCp91qy7jx9/DKxrf/zVsmnbzEafqpjFR2CXaJiUg+0ejiSA4zcgNOyRd
         og13vl94z8gSvXHvtVl7JfA0IwgQEHJ4n7CdD+QK9sNaxTxKo6Ul5D1ObuyBsFPUjQrm
         GXOp06hKnG1skbUGkgEZkMBEY/iEI9tn/vddya3YoV2CtQl8JUIffP15Uokui4eXIzYU
         9kzA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P4oALf8u;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-438b319f687si291615e9.1.2025.01.22.08.07.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Jan 2025 08:07:56 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id 2adb3069b0e04-54019dfd6f1so977578e87.0
        for <kasan-dev@googlegroups.com>; Wed, 22 Jan 2025 08:07:56 -0800 (PST)
X-Gm-Gg: ASbGncstMFpgSbUu/EpmIfons1WKe5W4Ngws7E+/qjI0UZEaned7AIKIoTa7Tskryxq
	LZK3mBv4j+xfrkwK3ESXqa4pyb8na6JIjW5d4jRxLRj+vwuTlfyASyB6FvTaYMbkicsIR/o5zg7
	z67W4e8JbAkng5TN8WdUqcNFiaxowEO7r+551rpGjhJb8MqDwibfi898JCFjdz9CaYoQTBACDTP
	BgOT4Y28t+2CjHxSeaGZoxQW6U0GJsxGSmT9qRBFnYRMtENoVS20f9dEvg1yfeo+kpo/8KuPO9i
	hbWVow==
X-Received: by 2002:a05:6512:32c9:b0:542:9807:97b3 with SMTP id 2adb3069b0e04-543bb342b23mr680624e87.4.1737562075993;
        Wed, 22 Jan 2025 08:07:55 -0800 (PST)
Received: from dellarbn.yandex.net ([80.93.240.67])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5439af60c4esm2327409e87.128.2025.01.22.08.07.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 22 Jan 2025 08:07:55 -0800 (PST)
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	io-uring@vger.kernel.org,
	linux-mm@kvack.org,
	netdev@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	juntong.deng@outlook.com,
	lizetao1@huawei.com,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	stable@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Jens Axboe <axboe@kernel.dk>,
	Pavel Begunkov <asml.silence@gmail.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Simon Horman <horms@kernel.org>
Subject: [PATCH] kasan, mempool: don't store free stacktrace in io_alloc_cache objects.
Date: Wed, 22 Jan 2025 17:06:45 +0100
Message-ID: <20250122160645.28926-1-ryabinin.a.a@gmail.com>
X-Mailer: git-send-email 2.45.3
In-Reply-To: <CAPAsAGwzBeGXbVtWtZKhbUDbD4b4PtgAS9MJYU2kkiNHgyKpfQ@mail.gmail.com>
References: <CAPAsAGwzBeGXbVtWtZKhbUDbD4b4PtgAS9MJYU2kkiNHgyKpfQ@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=P4oALf8u;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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

Running the testcase liburing/accept-reust.t with CONFIG_KASAN=y and
CONFIG_KASAN_EXTRA_INFO=y leads to the following crash:

    Unable to handle kernel paging request at virtual address 00000c6455008008
    ...
    pc : __kasan_mempool_unpoison_object+0x38/0x170
    lr : io_netmsg_cache_free+0x8c/0x180
    ...
    Call trace:
     __kasan_mempool_unpoison_object+0x38/0x170 (P)
     io_netmsg_cache_free+0x8c/0x180
     io_ring_exit_work+0xd4c/0x13a0
     process_one_work+0x52c/0x1000
     worker_thread+0x830/0xdc0
     kthread+0x2bc/0x348
     ret_from_fork+0x10/0x20

Since the commit b556a462eb8d ("kasan: save free stack traces for slab mempools")
kasan_mempool_poison_object() stores some info inside an object.
It was expected that the object must be reinitialized after
kasan_mempool_unpoison_object() call, and this is what happens in the
most of use cases.

However io_uring code expects that io_alloc_cache_put/get doesn't modify
the object, so kasan_mempool_poison_object() end up corrupting it leading
to crash later.

Add @notrack argument to kasan_mempool_poison_object() call to tell
KASAN to avoid storing info in objects for io_uring use case.

Reported-by: lizetao <lizetao1@huawei.com>
Closes: https://lkml.kernel.org/r/ec2a6ca08c614c10853fbb1270296ac4@huawei.com
Fixes: b556a462eb8d ("kasan: save free stack traces for slab mempools")
Cc: stable@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Jens Axboe <axboe@kernel.dk>
Cc: Pavel Begunkov <asml.silence@gmail.com>
Cc: "David S. Miller" <davem@davemloft.net>
Cc: Eric Dumazet <edumazet@google.com>
Cc: Jakub Kicinski <kuba@kernel.org>
Cc: Paolo Abeni <pabeni@redhat.com>
Cc: Simon Horman <horms@kernel.org>
Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
---
 include/linux/kasan.h  | 13 +++++++------
 io_uring/alloc_cache.h |  2 +-
 io_uring/net.c         |  2 +-
 io_uring/rw.c          |  2 +-
 mm/kasan/common.c      | 11 ++++++-----
 mm/mempool.c           |  2 +-
 net/core/skbuff.c      |  2 +-
 7 files changed, 18 insertions(+), 16 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 890011071f2b..4d0bf4af399d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -328,18 +328,19 @@ static __always_inline void kasan_mempool_unpoison_pages(struct page *page,
 		__kasan_mempool_unpoison_pages(page, order, _RET_IP_);
 }
 
-bool __kasan_mempool_poison_object(void *ptr, unsigned long ip);
+bool __kasan_mempool_poison_object(void *ptr, bool notrack, unsigned long ip);
 /**
  * kasan_mempool_poison_object - Check and poison a mempool slab allocation.
  * @ptr: Pointer to the slab allocation.
+ * @notrack: Don't record stack trace of this call in the object.
  *
  * This function is intended for kernel subsystems that cache slab allocations
  * to reuse them instead of freeing them back to the slab allocator (e.g.
  * mempool).
  *
  * This function poisons a slab allocation and saves a free stack trace for it
- * without initializing the allocation's memory and without putting it into the
- * quarantine (for the Generic mode).
+ * (if @notrack == false) without initializing the allocation's memory and
+ * without putting it into the quarantine (for the Generic mode).
  *
  * This function also performs checks to detect double-free and invalid-free
  * bugs and reports them. The caller can use the return value of this function
@@ -354,10 +355,10 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip);
  *
  * Return: true if the allocation can be safely reused; false otherwise.
  */
-static __always_inline bool kasan_mempool_poison_object(void *ptr)
+static __always_inline bool kasan_mempool_poison_object(void *ptr, bool notrack)
 {
 	if (kasan_enabled())
-		return __kasan_mempool_poison_object(ptr, _RET_IP_);
+		return __kasan_mempool_poison_object(ptr, notrack, _RET_IP_);
 	return true;
 }
 
@@ -456,7 +457,7 @@ static inline bool kasan_mempool_poison_pages(struct page *page, unsigned int or
 	return true;
 }
 static inline void kasan_mempool_unpoison_pages(struct page *page, unsigned int order) {}
-static inline bool kasan_mempool_poison_object(void *ptr)
+static inline bool kasan_mempool_poison_object(void *ptr, bool notrack)
 {
 	return true;
 }
diff --git a/io_uring/alloc_cache.h b/io_uring/alloc_cache.h
index a3a8cfec32ce..dd508dddea33 100644
--- a/io_uring/alloc_cache.h
+++ b/io_uring/alloc_cache.h
@@ -10,7 +10,7 @@ static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
 				      void *entry)
 {
 	if (cache->nr_cached < cache->max_cached) {
-		if (!kasan_mempool_poison_object(entry))
+		if (!kasan_mempool_poison_object(entry, true))
 			return false;
 		cache->entries[cache->nr_cached++] = entry;
 		return true;
diff --git a/io_uring/net.c b/io_uring/net.c
index 85f55fbc25c9..a954e37c7fd3 100644
--- a/io_uring/net.c
+++ b/io_uring/net.c
@@ -149,7 +149,7 @@ static void io_netmsg_recycle(struct io_kiocb *req, unsigned int issue_flags)
 	iov = hdr->free_iov;
 	if (io_alloc_cache_put(&req->ctx->netmsg_cache, hdr)) {
 		if (iov)
-			kasan_mempool_poison_object(iov);
+			kasan_mempool_poison_object(iov, true);
 		req->async_data = NULL;
 		req->flags &= ~REQ_F_ASYNC_DATA;
 	}
diff --git a/io_uring/rw.c b/io_uring/rw.c
index a9a2733be842..cba475003ba7 100644
--- a/io_uring/rw.c
+++ b/io_uring/rw.c
@@ -167,7 +167,7 @@ static void io_rw_recycle(struct io_kiocb *req, unsigned int issue_flags)
 	iov = rw->free_iovec;
 	if (io_alloc_cache_put(&req->ctx->rw_cache, rw)) {
 		if (iov)
-			kasan_mempool_poison_object(iov);
+			kasan_mempool_poison_object(iov, true);
 		req->async_data = NULL;
 		req->flags &= ~REQ_F_ASYNC_DATA;
 	}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index ed4873e18c75..e7b54aa9494e 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -230,7 +230,8 @@ static bool check_slab_allocation(struct kmem_cache *cache, void *object,
 }
 
 static inline void poison_slab_object(struct kmem_cache *cache, void *object,
-				      bool init, bool still_accessible)
+				      bool init, bool still_accessible,
+				      bool notrack)
 {
 	void *tagged_object = object;
 
@@ -243,7 +244,7 @@ static inline void poison_slab_object(struct kmem_cache *cache, void *object,
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
 			KASAN_SLAB_FREE, init);
 
-	if (kasan_stack_collection_enabled())
+	if (kasan_stack_collection_enabled() && !notrack)
 		kasan_save_free_info(cache, tagged_object);
 }
 
@@ -261,7 +262,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
 	if (!kasan_arch_is_ready() || is_kfence_address(object))
 		return false;
 
-	poison_slab_object(cache, object, init, still_accessible);
+	poison_slab_object(cache, object, init, still_accessible, true);
 
 	/*
 	 * If the object is put into quarantine, do not let slab put the object
@@ -495,7 +496,7 @@ void __kasan_mempool_unpoison_pages(struct page *page, unsigned int order,
 	__kasan_unpoison_pages(page, order, false);
 }
 
-bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
+bool __kasan_mempool_poison_object(void *ptr, bool notrack, unsigned long ip)
 {
 	struct folio *folio = virt_to_folio(ptr);
 	struct slab *slab;
@@ -519,7 +520,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 	if (check_slab_allocation(slab->slab_cache, ptr, ip))
 		return false;
 
-	poison_slab_object(slab->slab_cache, ptr, false, false);
+	poison_slab_object(slab->slab_cache, ptr, false, false, notrack);
 	return true;
 }
 
diff --git a/mm/mempool.c b/mm/mempool.c
index 3223337135d0..283df5d2b995 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -115,7 +115,7 @@ static inline void poison_element(mempool_t *pool, void *element)
 static __always_inline bool kasan_poison_element(mempool_t *pool, void *element)
 {
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
-		return kasan_mempool_poison_object(element);
+		return kasan_mempool_poison_object(element, false);
 	else if (pool->alloc == mempool_alloc_pages)
 		return kasan_mempool_poison_pages(element,
 						(unsigned long)pool->pool_data);
diff --git a/net/core/skbuff.c b/net/core/skbuff.c
index a441613a1e6c..c9f58a698bb7 100644
--- a/net/core/skbuff.c
+++ b/net/core/skbuff.c
@@ -1457,7 +1457,7 @@ static void napi_skb_cache_put(struct sk_buff *skb)
 	struct napi_alloc_cache *nc = this_cpu_ptr(&napi_alloc_cache);
 	u32 i;
 
-	if (!kasan_mempool_poison_object(skb))
+	if (!kasan_mempool_poison_object(skb, false))
 		return;
 
 	local_lock_nested_bh(&napi_alloc_cache.bh_lock);
-- 
2.45.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250122160645.28926-1-ryabinin.a.a%40gmail.com.
