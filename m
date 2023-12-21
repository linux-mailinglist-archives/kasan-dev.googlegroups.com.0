Return-Path: <kasan-dev+bncBAABB35USKWAMGQEDIU5OFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D86481BF53
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:05:04 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-50e40d1a6fbsf1141227e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:05:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189104; cv=pass;
        d=google.com; s=arc-20160816;
        b=twSMbrwAAZd8C/7BnCp2gamgQ+N1AZtXWakqiANqtcSYu8vk0esW35zNsniKiypbxE
         0itwcIo18dstRp431Rnjozc6QKRnPU5P5wL8FJjTQXzDeYQre+HfbteKQloyqy9LEhtM
         8s6dYDD4BQi56xah5YI8TxcUtggQ1fUVBVHyzeX0B8NvKFZvLsgb7alz6X6KfAPWmuwO
         AqzctR+oxG5bLr1SNS3DPgfi9pQYx/UjBN4OiNhV2A8YTjFYf1DW4yxFS5Eg3bOerVct
         CCiOVBu/RyPm9vZ6tP1O3hJxfFOkBq5w+27N84CKDmynSGV/+R3LgXnX6+5B3CZuPoH4
         J7rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=w8gsG2sSCcEGLXTIapRQlocN7LZa/Kj7vn/5xI8c+kE=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=UyNRK1ClGpAfw3G5iqHKOKOxv1jwEkdZzR2Hh3+iHs/LpZvoaxYqqIvaOgEtZBo/46
         UOHNHwBrB/FdyovmqY2e7jeDGYYVxeNZougTAXg/uB+h8sVumCGtXvBvG43MyXZkladn
         UjgYdhb5/F8MYl98YZmgZBdJCBOTgiHhGL7RLJ9wA7rH4VAklR6QGUYrT89/ktcw/g53
         7fwvZm8fqCDaKwF4ssbYbxbyy9QQB4U7EtNg1ReRbggDl9ZY8T8Cl2GVkvbPRWZoBYQN
         YaqS1vYJRSfxgc/jSYA8K7rzyFwiQf2d8wQhGoOuJ0FPsA48JZgQy7KDeS+m04Ju9h45
         vBVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=T3Q2NIda;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189104; x=1703793904; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w8gsG2sSCcEGLXTIapRQlocN7LZa/Kj7vn/5xI8c+kE=;
        b=F01V2UkJoul9C1cFNwgHkBAlmwJV13yk0jFIlfRX/0YWeHOXuOBg4iWDesg8D7xEFH
         /fYKvwvyyt4TwpLYG0i2qoEH4JLw/R20u4cfg4GocOPxApC3y7WsT9lPQylZwA6svRfy
         InkL3gTFzWbSiAIpDrJ6ZzWUwAOb+UDv8Omq7g5qkyySX49w44hsWAhbETGVp05G2z/O
         B71Uz2gYCifggTvqD6rTkwrsUgfWRwtoyTYTkHB+ybljc0JMUlN4/dAcG8iwKWm/WV76
         cmkHXSJYYL9rRUFuvPKw/t9RT6DfZTlNQzPihmtI1fo552WIDkZksKGdUR3YKeook7io
         bUTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189104; x=1703793904;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=w8gsG2sSCcEGLXTIapRQlocN7LZa/Kj7vn/5xI8c+kE=;
        b=Td8L90elKfPmYjm4QzK+5mnqRytfmJS2CIsXPVL7JQ5eXDfPnscaPlPyQDv0J7MjNO
         2i0VZMyVcOpJFkqE6yUa2Uh2D/eYKxL/uLv4MV04uGnxS99yCWqGVJGq2YgxC+ykZJUC
         FS9dpJGSaEOVw7/Hpa66Nmb2py4SQiBm6LDaSpy7wxiZhdaRzSm51tP2nxCtgYchrLbx
         f9eYpGEjI5Xu+LSbAvpsmkM9wCAtiodZTwqOL6nVpGSDTjxOdKr1ut77qb7RwlLpv2PJ
         I8k2tkwSkSUKO+pjrmcSd9p4Sy4ka6Qltafz5JF1yjZaP5JnhtqtU5fBhKMqVhsg2b4n
         j74w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YymC4ktLDcB/2JiBGKre8QxKTS4dFMhK4f5Ee2zGjNbWRprD4WK
	bJUhRvTv68hB2nFAHJio0co=
X-Google-Smtp-Source: AGHT+IGJ/kOpgFBI3ul03Iswnhf9AtsHwgvvVgqE6M+gBWoGLCCaArSRRSnWzqWN6YmVmrmpw+iKEw==
X-Received: by 2002:ac2:5e8c:0:b0:50e:2cbd:cc50 with SMTP id b12-20020ac25e8c000000b0050e2cbdcc50mr94209lfq.23.1703189103253;
        Thu, 21 Dec 2023 12:05:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4014:b0:50e:2a73:bc3c with SMTP id
 br20-20020a056512401400b0050e2a73bc3cls689121lfb.0.-pod-prod-09-eu; Thu, 21
 Dec 2023 12:05:01 -0800 (PST)
X-Received: by 2002:ac2:4e6b:0:b0:50e:4baa:a937 with SMTP id y11-20020ac24e6b000000b0050e4baaa937mr95736lfs.27.1703189101524;
        Thu, 21 Dec 2023 12:05:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189101; cv=none;
        d=google.com; s=arc-20160816;
        b=OhiD0IeZ7ZC7sNce88v0w3xnsvMYkhxexYkIn6CRRawY5gI1rXgfWzHtA0Pbs5iTvG
         RsMqxRfIiiAT+A3x/w01N/VKeTB5k7oJOiXPWU5DNb9i/4Pe5D1Kx8lmm3HMnIAgx0bh
         oZ4dAcGyKn9TnX5cwlmah7CD+k269hjBP/eiolYF+Nkv6fK7yzzqcHeorXpYG6AIsT6A
         Z1zBmtRZ93Aw7kclB6FFb15VbqdiktBqHIXH2TlLm1O7UGpcFKJXpMkmNSsWQg1YoK2j
         lGTy6z+g+y4URgqXKSaAunxMs07RGJ5XjAE2zB3Bc8ApgvHG8y83XhA3a9hydxPrtCc5
         UoVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=02IeghrfT0ytg5MuYoXhCbr9XM7hY33pPyxRWGvQP4Y=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=svL12BkVcgR28C+rDR2SiWkGjq7gHPgEBlgJ8IR6pliLCO/DL1ohL1mrDPVlw/aVgE
         HkuO9yj5apRxmJ2xC2xxeFbw6O9sGZT0+jZRxCeYueQpN6xVn4o6IF2kDrv6HQ+a7ca/
         e1SyZ2W2hlfDe3Z3oniQuVAhvAAAHLkzW1RsywZb8EEDgtRhpsOu17bi17Gahtq4+kze
         mpzCVQha/jqU88gSLxdEWKrhnIXt6BDsgRZebC4uUGD5q3jiFlXOOJ5lw6ERKw5eyzqM
         ocAeorwfL9CpAxLVduTuxPCUE3V68a1Bqw/OkFq/jX8yf7kOICcCsDz8N1di2UwhNQE5
         98JA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=T3Q2NIda;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta1.migadu.com (out-185.mta1.migadu.com. [95.215.58.185])
        by gmr-mx.google.com with ESMTPS id cy13-20020a0564021c8d00b00552180ac40fsi106388edb.0.2023.12.21.12.05.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 12:05:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) client-ip=95.215.58.185;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 04/11] kasan: clean up kasan_requires_meta
Date: Thu, 21 Dec 2023 21:04:46 +0100
Message-Id: <8086623407095ac1c82377a2107dcc5845f99cfa.1703188911.git.andreyknvl@google.com>
In-Reply-To: <cover.1703188911.git.andreyknvl@google.com>
References: <cover.1703188911.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=T3Q2NIda;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as
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

Currently, for Generic KASAN mode, kasan_requires_meta is defined to
return kasan_stack_collection_enabled.

Even though the Generic mode does not support disabling stack trace
collection, kasan_requires_meta was implemented in this way to make it
easier to implement the disabling for the Generic mode in the future.

However, for the Generic mode, the per-object metadata also stores the
quarantine link. So even if disabling stack collection is implemented,
the per-object metadata will still be required.

Fix kasan_requires_meta to return true for the Generic mode and update
the related comments.

This change does not fix any observable bugs but rather just brings the
code to a cleaner state.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 18 +++++++++---------
 1 file changed, 9 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 0e209b823b2c..38af25b9c89c 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -101,21 +101,21 @@ static inline bool kasan_sample_page_alloc(unsigned int order)
 
 #ifdef CONFIG_KASAN_GENERIC
 
-/* Generic KASAN uses per-object metadata to store stack traces. */
+/*
+ * Generic KASAN uses per-object metadata to store alloc and free stack traces
+ * and the quarantine link.
+ */
 static inline bool kasan_requires_meta(void)
 {
-	/*
-	 * Technically, Generic KASAN always collects stack traces right now.
-	 * However, let's use kasan_stack_collection_enabled() in case the
-	 * kasan.stacktrace command-line argument is changed to affect
-	 * Generic KASAN.
-	 */
-	return kasan_stack_collection_enabled();
+	return true;
 }
 
 #else /* CONFIG_KASAN_GENERIC */
 
-/* Tag-based KASAN modes do not use per-object metadata. */
+/*
+ * Tag-based KASAN modes do not use per-object metadata: they use the stack
+ * ring to store alloc and free stack traces and do not use qurantine.
+ */
 static inline bool kasan_requires_meta(void)
 {
 	return false;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8086623407095ac1c82377a2107dcc5845f99cfa.1703188911.git.andreyknvl%40google.com.
