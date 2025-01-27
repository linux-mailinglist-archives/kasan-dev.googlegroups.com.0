Return-Path: <kasan-dev+bncBCSL7B6LWYHBBK6B326AMGQEDI7YD7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 87FCDA1D8F8
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jan 2025 16:05:17 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-53e44a2a6cdsf2171045e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jan 2025 07:05:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737990317; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qdt8JVyrgOnCIAINN136MKKelS70OnL0mJXV3KTbe8jk7I9PvBt5AgEVnSXTsPfAbk
         G+eJymiIYYPTwRslfLB52PxkMWSEpBwlgya8HJLUFqw3IxvCAm3YPWVvWLEKbZZxNV/t
         iN2qyap0P0lA3P4kzZl1yiUEW6sPZGo9rMFairudmSzF9b3Ovij5epr/khRSxx16Ry8o
         cJwdtPj6ofPtel/9C3vehmPBl88IcjdKyovpkM6fUFOgg98ngEbRf1NebeWeG1Kbfw8I
         HbpUe0gpeQvxiHYSs7IQXLMP6YuL3IBrUaWfx9Gv3V+w1dDOQN7AJW5RDoyy2J7kQ9s3
         roLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=A9xndSZnRZMGogHVDzwMOkQTDvydR8p9eyxDHBi/2ZQ=;
        fh=huFmBs5xTi3T4CQj5+LrHL3n1nZux66AkHEBleeG+tU=;
        b=jn5TD2dMWAf13EoDTvMIqGaryM5QNwxD+WC/opn7dv3hzB853tN60dmlp2Iana9sA6
         nLpgOu/s9elT/UQpZiImocAJ2gX7akKZEkH6HmeNBClZKIz6MHVCcc37XhlS0NmpK4X/
         Gw2ygGV0XE63BQkd1F6OI3WkbBwET9oPBw/Jj5iZWcgQPprcGCsTlO5kaLb8ida36/lb
         Uo15229BHBd56soYbkgTC6RnkH4DSupB8TnyM3MhvwYscRhLy0DjQ5aaMDJWqXtKa7ec
         9BBpRvaROdHeqpLUYiA46eTZucH3gxRJqw3PYqC8x8OuQy6foR0tdHvPo6M4sqSr+RKe
         wcig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iC8cQpiY;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737990317; x=1738595117; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A9xndSZnRZMGogHVDzwMOkQTDvydR8p9eyxDHBi/2ZQ=;
        b=loRnEoSoLni48ATOB7uDLS9aM/uxh7RcZ9W8ojXqi5fXhL2ZvvgqSP+3ATqNh4jzOe
         liN8Pv4heICKXTw2wd4i4cFzMcq+LOFKo3FhjNSvfSHAz/xOH5xvOjZF1dOttnftQmY5
         UOwm42stf2XXUcDYOh3BS2M4eZHXqkbSvR6vjj/UO0cKQm1vUhA1uy+L5cGjabyUVONZ
         4ADxpGLRv9d8X2MK7kdnYHNBNuUrpXgMKgxpoEFgNgkpT/DKLMWbpSPB+tjY5J4hA2Qa
         x7Rk3LQKb3zgQ//OT2gMLp0E8cG6o5LRcG1wJmLkKq+cwj9G1wBx2HdnveUNvmfXezxd
         y+mA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1737990317; x=1738595117; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=A9xndSZnRZMGogHVDzwMOkQTDvydR8p9eyxDHBi/2ZQ=;
        b=d8aFxvTl74Q8ze0XSP1HXhaU63HLO7lLA7n/5iGT5VOpJXFBn28/H0DzrsraKVLDIa
         eNZpylaJ+ZT+02iWqGW1z44pZH++VTyfw1fu3TOlwi7C9mXqeZimDNBUSUJW0oexd+gY
         NTESgndVX7o0Ft3WqdxvFqzkuO2kq3TgOac1N+owPIBkVmB+3eEDfGoHF1uJg64QaXWF
         GMZlIHDIOnMwqhzRAKUvSYpJ9nMs3K5KK/IBbHSXe2h69VheXVJdSQiDEf9GzckITJAl
         XssIZ9WdW1YBvAq3nHJgZxSn0eW8aUoS16nd6YWeuPIjx+f5unv/CxtLpSWYYgEYRNQA
         3yIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737990317; x=1738595117;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=A9xndSZnRZMGogHVDzwMOkQTDvydR8p9eyxDHBi/2ZQ=;
        b=iAf8DxVXDd6fXjQNAbeF0M/7b7AUwtaE0bX8qUd7GOzgCuHCEFMlSIWxbFhN6HpUnp
         uPtGZOZnk1c+0NqRQPL18ADVZoa/5h+2uE1eILhuqmF7SwaEWcuaI1MYiKkxM25ghYfS
         P3p9DTsrT6Tul8SV/FG8tPn7OUiz1nZJlZqinuL8U+C9+OH9KLzUcLIOyzI2EnQ8d4Ad
         taIjAhUVGh9F6zb0XhcKizLfUVjVRdKDuNgt6x3StE/04RlyDH/zlbcHXoJvZOz8z6+J
         QORy9H1Iz1ywgY2ImfbUAiP1QEBvPGSUqxlp73YI4oVVCyjnaFR8+Qmf+WPjPoqFX1ty
         ojJA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXcyo4SIjPDm2/NPPCWcwtTksi/o3SYvmHLM9+Bxt+8GQrpUrYOU3M7bmoN03oDsOmPJ6tP9g==@lfdr.de
X-Gm-Message-State: AOJu0YyXoq+2YSJGrNiswHff4AdHTCOJN9KK/hxA0cXvs2g6Ruh0OLSo
	o1/f5AYnWXXrhV/nmiwLLTaimOHsc+8wxugKWYDQTQEwMfHsn0uO
X-Google-Smtp-Source: AGHT+IH6S4IYOE8PwzTphvlv71v6SX/QGewJfKdqDXyW0epk94gt959oIE3FJzjDtRnibaKSe2n2NA==
X-Received: by 2002:ac2:4543:0:b0:53e:1b34:fed2 with SMTP id 2adb3069b0e04-5439c216be3mr10809978e87.8.1737990315719;
        Mon, 27 Jan 2025 07:05:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e012:0:b0:540:22e0:1f74 with SMTP id 2adb3069b0e04-543c23e303cls139321e87.0.-pod-prod-08-eu;
 Mon, 27 Jan 2025 07:05:12 -0800 (PST)
X-Received: by 2002:ac2:5d6e:0:b0:53e:3a9d:e4a with SMTP id 2adb3069b0e04-5439c216c0cmr10726669e87.10.1737990312566;
        Mon, 27 Jan 2025 07:05:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737990312; cv=none;
        d=google.com; s=arc-20240605;
        b=HHusbSYZwgVI3Og0/HQeJCENrkeANH5XQm4FLLNBXR0yH5r21lXqLZpqIthauVCR1F
         OEldmfUF8iy7GE1IUSa1ED7lBJVNX0gMj1RoNXTf8/r1tekQzCCicg08JH0wEGfQnVkW
         MI2gZP2FjdiT5MhlqeZuQPXvzVY5Mitj9JEwLuq0KAnNftTRwZ+qcGrPbTn0JC7bxTDd
         qGxCXzZOwVVMsS/rAqPdNAUTjeUzoio6GAletjrKORfpgRvskVFqZ6ycTLBh03jZSV3F
         tZUIMfoo5O+X+SbnjZ3dHBqMO6kyaRb//Qqj8sI7lB9uYPFDasAXsliAYourKKVPalEx
         khaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=a99Cj+rOUzLKKfU2RGwugGZfMRB43qPpEZQgebXePjs=;
        fh=ZOEubWtvtpyt65cma0oq//l1eUii/kYji7FPDYyfmSo=;
        b=hH9UeOZvC8O0+MC7bKhG5Mo9+RgTdRB5PbClAB3j9012XXl883HRhT3sVLsLBfql2v
         gTQ6RRaU1hbEu2A7P/wVYBCB3+YUPD05D+tjP1YO/xlFaKfjjv+nk8kPQW9lE7HswAc6
         pKUJuH+Z8pIZlc0sDP/JwRFiz+QLojBcIR6gBCyIQ+oWrHzS8aQHmF77/65pdNVXdWRi
         jv4CtHA2+sZxTwp6QaLL2JHiPt5vDXABCkyeZozd/otnHpjoQs5QbHKZiu8okToIsOzS
         bV9MYx6kXoOtKbhT2tIH4wMZjKhQoZJyPmPLKM+sARgk6pSzfTSHJ6/LpR4lSvzi9nNc
         Op0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iC8cQpiY;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-543c822a988si236582e87.4.2025.01.27.07.05.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Jan 2025 07:05:12 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-5402ec870b4so687968e87.2
        for <kasan-dev@googlegroups.com>; Mon, 27 Jan 2025 07:05:12 -0800 (PST)
X-Gm-Gg: ASbGncvysPibeqJleaL43Aj3OqCtUH6bIxk8lUYT8J+WT1FO8zzrxHeWpMnHRdToBnl
	2ztqeDqXhsqBstjAio4co9jGXCaimbei1fXwPo/NlrktPnuVEFAaqC974c4UvCACGkgd3YZhsv/
	BIKEGtDt1P8HzgvFyILI4jHQDJh1JOIqyeJxgopH5W5U4HifXW8xNqw2fjpQMxSPjLItBA2hgc7
	Y0qA60O6L0sxJKE0w2pMrC9F6JJTPpL/csQ0JIzN48fPZgHHI2HDlknwhBsQf1hcy1PH/F6BwYe
	hc+7Cboc6QSbSEpFCBPU5CECdnU=
X-Received: by 2002:ac2:4c4f:0:b0:542:297e:86c with SMTP id 2adb3069b0e04-543bb2ecf6emr3097051e87.0.1737990311100;
        Mon, 27 Jan 2025 07:05:11 -0800 (PST)
Received: from dellarbn.yandex.net ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-543c83684c6sm1321436e87.107.2025.01.27.07.05.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 Jan 2025 07:05:10 -0800 (PST)
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
Subject: [PATCH v2] kasan, mempool: don't store free stacktrace in io_alloc_cache objects.
Date: Mon, 27 Jan 2025 16:03:57 +0100
Message-ID: <20250127150357.13565-1-ryabinin.a.a@gmail.com>
X-Mailer: git-send-email 2.45.3
In-Reply-To: <20250122160645.28926-1-ryabinin.a.a@gmail.com>
References: <20250122160645.28926-1-ryabinin.a.a@gmail.com>
MIME-Version: 1.0
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=iC8cQpiY;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133
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
 - Changes since v1:
    s/true/false @notrack in __kasan_slab_free() per @andreyknvl

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
index ed4873e18c75..f08752dcd50b 100644
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
+	poison_slab_object(cache, object, init, still_accessible, false);
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250127150357.13565-1-ryabinin.a.a%40gmail.com.
