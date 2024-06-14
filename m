Return-Path: <kasan-dev+bncBAABBUVBWGZQMGQEZ7GW63Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 50E91908D24
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 16:16:52 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-52c893408b5sf1558828e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 07:16:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718374611; cv=pass;
        d=google.com; s=arc-20160816;
        b=LeU2vyfWD6WWEI8AVa5wrHs+77zX4vJj93YEYf6BlXP9oIXpQosLQEF9/c6RXrrnDI
         bScmZEGVLtejVYUPUBY/HG8vXxoqGE0r+RK/RsVQzzqH+q3m+GmkaOEs2RYwJPH6ECoT
         JpiAuWjTEVyIL/H/HM+Di5d3f+KQIPj2rmF4UXPhrsUib0OJmFglwmqzuDoHJvPuofS0
         cUoeKtDMWFa6nmyZcTLkdNr88jBJDlQJjiQPKgrGtwMBh0GGFaW7MkQ3f3Y0dZH2Yl5R
         uYGezKU8bFzLm0qegQhZm+zHDR0FTIKXTqz+/Rsk8LoS2CJdtnSzjDRjljRCp4fe4zWO
         pb2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=21KJQZwUlNVq80w26v3RnspdTzsLWk1/WNliRI1SRds=;
        fh=X118uXruBr1m7rzBCEI2eeKLzxdC75jo4OXJF6kkmSc=;
        b=HH0FitG7d6mvZaQqopWPKtz8GV6noKaOw//RUvoLfUyu19hDivAbXkknf+gDeMUwOC
         SP9w0emU/Z1BTjAMwkyeYlbRyQQkVhS7xvLquXL6gogo3kD4LepaE5DP3Iw6ldgbre9d
         4eIETiyko1Q6DsQ9vjShHkU8qEl8jDCBo0tUIQt5sNjx+bvHtqS7uGFvIwDzSPKiw99z
         7viJfzxfug/YazVzLUuT5KQm7m6Z13Vb18jq4HsskBdu5dsKq8mhkBpm7je2+5shOTRF
         bRHmX8/+0cJlmatEnN888EHFdgn+0gxmb7pyNb+y/2Jzz+X1jPtnNr2r4s5cr9TiX9gc
         ifdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="u3XAwKX/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.179 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718374611; x=1718979411; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=21KJQZwUlNVq80w26v3RnspdTzsLWk1/WNliRI1SRds=;
        b=Ex6tOtc4G351GFkG0pJBUFwulwoBGEl+mUqIUoF9rehhcgH/tDR4wbQiV1+6yf3Dbq
         X1csFRAl9/PoXoLbnV5OrQv6Lxmv3sz9M7BxDWgbqZvjQESv6hrFI2C7rv6ZszZeVfDZ
         OTwWdu5SYFrHl0yA8ul04BdfQiCm+k5cLcUMXSjpdhN4OlMLKP+/DEOIBRfdUo4Lui9c
         U3cXehrDTAYpqi8UENVAQSlgEnCIbWP9YRJMCu3DTbKg9r69qDl+PjwWvs7fpGy8T++M
         D4bjv8J8dPsqJ2kr5bR+Aei3O8Fdig+JGbRlecFBUKrQS6qEARuF5HCtfLx+qPJVOmwP
         h1BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718374611; x=1718979411;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=21KJQZwUlNVq80w26v3RnspdTzsLWk1/WNliRI1SRds=;
        b=qO6aJGKZSgzPnMqjMBSiAR0MLtB5VHaHJYR++TTAvSmyKz8ztA8/SN96rGjklJZVjr
         dzCbDnZTV8tJ41p+WEOs70UzJW2WCG0Pd5wcI3Z/xJJcUFIa6p6VNhD5CkVZArnAmNJx
         zD0ZjFA0hGvRQLQsmF6X5lweHZmSFJ/R82ujIVnwbMqknUNDb9/waxpfVCC7ruaItAnI
         88FvOUwV4eLBqwddu/pZSStQ+DA6cHi5GK6Ejk1tBTgp5cVb7FV+tVXaKf65RePAtyAB
         61MCetJB2yVGzH7xmg2vNKyIz5W0NQNyfy3F9ElHP4TOpspusm3Ye4HJgJ/5SHdNJAgl
         oBQA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTxhmV5wSc7o6/z3DiWEaFzeMUqxIRWdRdp6BEXWUBwMzggz+JnFD9Vpl1GR/o7w1JFxEkaLGe9IxRRvqT+vt4QGQdyKZFzw==
X-Gm-Message-State: AOJu0YywfG0yPbDLwD/urId/EFEsiGwxKMPE2EJCc+F9Yg+Ue8tJ0Fa5
	Z7+sf1UXEsUQl4ct1XOsDIRoSEzQWhw5Bx3Cffkhfx5FyvETQzNc
X-Google-Smtp-Source: AGHT+IFAmRxGnq5iJH5Ee7kLHfPKfMdICFEqXfQB7EP0mMpUR+VtyLFHEx1NPIoPpLfY7ctfhMB4sQ==
X-Received: by 2002:a05:6512:558:b0:52c:8318:dc14 with SMTP id 2adb3069b0e04-52ca6e66feemr1903356e87.25.1718374610761;
        Fri, 14 Jun 2024 07:16:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1383:b0:52c:2b7a:b993 with SMTP id
 2adb3069b0e04-52ca06ea134ls1020133e87.2.-pod-prod-01-eu; Fri, 14 Jun 2024
 07:16:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpiWdw6bqYfFbkuomeQXpe/CmXgjjTRUarz5NO45ZKqQgOQ803qfy4/XOEfr/QkQ6BVWVdnTJ+Z5k0JOmWY2wY/MMJfKCe2NHvbQ==
X-Received: by 2002:ac2:58f6:0:b0:52c:a002:1afc with SMTP id 2adb3069b0e04-52ca6e6dcd8mr1635122e87.34.1718374608761;
        Fri, 14 Jun 2024 07:16:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718374608; cv=none;
        d=google.com; s=arc-20160816;
        b=DiJpGzkEpAelPdbqpNjbL7pBZzNf0vxU0MCVLMCKqHgDcI24b3b3AZjpWYgyQHY5lx
         OPuUWWH62KBGPzLcpvxmThWev7+d/78RtE58wFM8SVrN4cjEpe9e6V06GwwgV1AzpTKF
         UtPKAX8R+lVgVnGw8n645gOXHpw2lmAC88Bq4KKWFoL7u348iA4VogjV5xNsLdNRE2tq
         a2ViZZKiwAlEvVbuOOExWh18dAhHTGxS7l/ex/4bdJP2xyX+2SAI9tVAdRj89NMCLOh1
         cvMdkC0tC+jZQPWO4Lu6K5nqrhoAa6SDPGIa8d6a/uCUjUcCiIBsg683KLVVVjSpJm55
         icNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=w8jKgK+1dz6W9hZOwl0Mk0auD1tYCqkT+HhvW1YvPYs=;
        fh=A8xiZTLpWpTC0DZIL+168rHKBhj8At1M2zQ2iArB4QE=;
        b=rXn01EJuduIzazSQMSUn/RKvpEA+dq+26ipFXr/Dj2XjRoqvu5qbAaH7OdATemNNAX
         mzqUwF4nByzzjMjKrcSMv0WLTYWWAsScXW42ww4McatfzF3pwqOX+JJxyiJ9rBMOjbCC
         JOd9nzTuocN7NXZMoACcByxCKfMj9aNwX6/ztVYi5fSbQ+ADkdNuNBA6+N+FcgyfXMmC
         Gla0Ls4q74TXDJnu253iIo2b8W48RiZqzAvnGzTosHIINIynG0iUbjdUJrgb/5NyMy9l
         iL1tdS6FgpRDyMPUQkGpDvIPcukUAdY+7pOspQStb1ooO6vAe64EQ5pIz6Z2Q3HpUIpk
         Sotg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="u3XAwKX/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.179 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta0.migadu.com (out-179.mta0.migadu.com. [91.218.175.179])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52ca282f0f1si74141e87.5.2024.06.14.07.16.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Jun 2024 07:16:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.179 as permitted sender) client-ip=91.218.175.179;
X-Envelope-To: akpm@linux-foundation.org
X-Envelope-To: andreyknvl@gmail.com
X-Envelope-To: elver@google.com
X-Envelope-To: glider@google.com
X-Envelope-To: dvyukov@google.com
X-Envelope-To: ryabinin.a.a@gmail.com
X-Envelope-To: kasan-dev@googlegroups.com
X-Envelope-To: linux-mm@kvack.org
X-Envelope-To: spender@grsecurity.net
X-Envelope-To: linux-kernel@vger.kernel.org
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Brad Spengler <spender@grsecurity.net>,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kasan: fix bad call to unpoison_slab_object
Date: Fri, 14 Jun 2024 16:16:40 +0200
Message-Id: <20240614141640.59324-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="u3XAwKX/";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.179
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

From: Andrey Konovalov <andreyknvl@gmail.com>

Commit 29d7355a9d05 ("kasan: save alloc stack traces for mempool") messed
up one of the calls to unpoison_slab_object: the last two arguments are
supposed to be GFP flags and whether to init the object memory.

Fix the call.

Without this fix, unpoison_slab_object provides the object's size as
GFP flags to unpoison_slab_object, which can cause LOCKDEP reports
(and probably other issues).

Fixes: 29d7355a9d05 ("kasan: save alloc stack traces for mempool")
Reported-by: Brad Spengler <spender@grsecurity.net>
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 mm/kasan/common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index e7c9a4dc89f8..85e7c6b4575c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -532,7 +532,7 @@ void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
 		return;
 
 	/* Unpoison the object and save alloc info for non-kmalloc() allocations. */
-	unpoison_slab_object(slab->slab_cache, ptr, size, flags);
+	unpoison_slab_object(slab->slab_cache, ptr, flags, false);
 
 	/* Poison the redzone and save alloc info for kmalloc() allocations. */
 	if (is_kmalloc_cache(slab->slab_cache))
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240614141640.59324-1-andrey.konovalov%40linux.dev.
