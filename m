Return-Path: <kasan-dev+bncBAABBSOOXCTQMGQEAEK75WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FC3378CA6F
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:13:46 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-401be705672sf25765805e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:13:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329226; cv=pass;
        d=google.com; s=arc-20160816;
        b=d9GcbEWcPR1EI5JW2Jrhf4GZbDIJbL2YhtoBtqS7c7MjAU2fWaOCtHoqropmc/GyY+
         JMQUsD0+KvakurKswXLBfAGrozc755HJWXN67FdoXFpjoZU5UhKgxmk9sLUzVP9lugaX
         IJSmY3a0WLwUU7Dt4FsrTxXWmRHb7rQa3jqq12nn6bZVO994U6KBwY9sKP4kIGKkiYvi
         n7QXNbFkZHZh8LE1VHJJjfkn0uOTepW1G7tmkkf89nXVb8HTbA+RX8nrzk6ttJ3XYmtt
         Yep8BNnKGj5YncCxNAJhTbOfhSJm8BRvsT6Zn78QlkaBE54qDY6qPDsdm/UgXeKnGhzF
         mpUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xJTc6CMljD5mS6hjuV1mI2rnOHpr4HbG8T013mLVYeQ=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=ybzi7h0Mter4FC+yJccsHXfMxIh9mCu3XjYl85wsNwAYsZ778Eyt0wqXlHEoqnciwo
         8kTNsl/GYAvOfkTT2lMt9Mq93lIpy3k7jPRZG9YHTwoNdeXHvNojLX5NKUMuHACHgY0l
         NgE/wLArmFU2CeerHUgAzmSZpIxWJX+x7vVR3ab4JVt9YMou/oHUQAFxlWQis7HHvvcY
         2fM3EMgZADyQ+OJlPWsWULP61Gl1fFeFV009QqzHO3ikZzBasSrblmFb2279k+RcGix2
         /b5KprN0dPBB3/myARKdQMX/kXO8Ng92cBuP4z1DcQG/LiBIywIDAVx3LBl84OjYSm9g
         1azg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=PT1yVeNi;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::fa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329226; x=1693934026;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xJTc6CMljD5mS6hjuV1mI2rnOHpr4HbG8T013mLVYeQ=;
        b=npg1Hb3HGTkbksxWhxTGZCf5GBdnytwzAQFA5l1lLy57BWpgwH5T8EZArz0XCYYDd1
         87mtIIj/jx9D642mdHEXeXZgBNr/U7hsBuGu2Xc3kamRRJbecXEaDxxIg8Ouh2n2uvDE
         oHyKIYAd+cfDHqsSguXScNu8wRYFSor6/kksXUhxhbdvr9cgE1Wbfaa54dTk+shdwJcm
         GhRGRQ+dHTh4ZnlpEn3y/cwt8nm2cxg7jXQX2ukZJDPnOdi4jlmpDRFIbhC/bgfHFTRO
         MN1YoyxGtmgf+3R/FHSWxjt1q9BajYyUs8usb1SWljM6wcNQxLGQKteVwXQe4v280pyL
         2C2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329226; x=1693934026;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xJTc6CMljD5mS6hjuV1mI2rnOHpr4HbG8T013mLVYeQ=;
        b=O6SuHPK9YCkDJEh9qtBiOk8TqgUn3FQmiyZ3CMv1LnvNJMkvvExEkjbdJD+s6gzFTT
         NrZTdj1rBzA/5Pl6kQ3N309HkSuWWUqxwgCVAv5E2dTIuZMjq5s7qHT14LyeGQrYfwZ7
         5cIluwNyAKCErj3Uybqkm0FirMks9UZsdrgL1vAOK2QG34jtVLkVFDzA3VjSl7y66AmY
         suAKJPK7iG7J1STimbjdR7uQ2CJapvx4S6xoOIg+bKU2Tj3LQYpNj8Fqv9t9KZrv29ry
         xBrYPaSvAvPI3+YIUC3+tdiAXTjPEDcHxYHEgSUNEaslpWfqOn3fSqzdd1twnMDr89Lw
         UdrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzUrEcb5bmP5W0XiYUCfBNsxYzFKMzeeGaDpnWcvXYD4E3J7fFU
	THPz4MEQRuUqIyWrzVN5WnQ=
X-Google-Smtp-Source: AGHT+IF8TLL/qAVZuLKoLAo5WsJDGyrIHC3LXwyn9kmowxnVUxOG76+6X5uosu72R0u1ckiTBJXcxQ==
X-Received: by 2002:a7b:cb41:0:b0:3fe:2079:196c with SMTP id v1-20020a7bcb41000000b003fe2079196cmr22059488wmj.16.1693329225690;
        Tue, 29 Aug 2023 10:13:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c19:b0:3fe:f6c4:6bc7 with SMTP id
 j25-20020a05600c1c1900b003fef6c46bc7ls233680wms.0.-pod-prod-01-eu; Tue, 29
 Aug 2023 10:13:44 -0700 (PDT)
X-Received: by 2002:a05:600c:22c8:b0:401:b504:b6a0 with SMTP id 8-20020a05600c22c800b00401b504b6a0mr9386545wmg.3.1693329224410;
        Tue, 29 Aug 2023 10:13:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329224; cv=none;
        d=google.com; s=arc-20160816;
        b=JI/zgZuIrHyuK2Y48FeGpuyXEkZ7hfdo1YgkMRWPQ+FEhVnidb7tkNGP6szJByVYYl
         GgKdY17oAVXaolqF1eD+yuzxTMLbbnVpCtbVzNI+h+fLUWYGi5l5rKyoxwrh1KIlnE6h
         Vj8Pw3jYe5RvWGaif47JvgBhGgCEuAOqELiPs+krpvfsbhwuRo3aDpr158FCGY7F3x5m
         d4Sioaaf/0tFJv8wEicerWWrjtdkv/iNzmj6pXsCYYppelE2iHGhU5UzoMMsH/+rwfj/
         ZxMjWnZBKskFTui1SKBOXydDQ9ZpbnlgI8xUB0uXzF15u6X8Em+wEk6zSul6M4ssnlEK
         G/TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6r+jJInS3pVfd7hB9KGynpwXDuP9tHCSgnjNZ7TlokM=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=q7nUNuBjQbrEEMftyhd06s7cPrmrVJ7/1IJVbDNtiHH/whXKbUdWqkkGV/YQLK/hjw
         wwsGpZa2bgMt6MD3YhDljKmHEyr/LTKfGJvX6BSuO2KLmPU9qsHUnr/spxQRotzmCnXa
         3Yhuj6Ly0wOONX2/vbljCObFkk7jpx6K5Ysv/YUsZPIV1xVoQeR517UkGhIm0LGrwN1Q
         T6POz19UDTflo2S0UgkzeVM39eii9OnVyemJrB1l2A0C09b1CEN9m+OSvMin4z+dVApL
         cX3RdOhT9AUKzHCht/L4h8o619Z/ylS74psTSbYq+2KtqYdMCYSL/6i7BMCBQ4qIkCUe
         NJpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=PT1yVeNi;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::fa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-250.mta1.migadu.com (out-250.mta1.migadu.com. [2001:41d0:203:375::fa])
        by gmr-mx.google.com with ESMTPS id j38-20020a05600c1c2600b003fe241a5aabsi952824wms.2.2023.08.29.10.13.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:13:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::fa as permitted sender) client-ip=2001:41d0:203:375::fa;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 13/15] stackdepot: add backwards links to hash table buckets
Date: Tue, 29 Aug 2023 19:11:23 +0200
Message-Id: <e9ed24afd386d12e01c1169c17531f9ce54c0044.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=PT1yVeNi;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::fa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Maintain links in the stack records to previous entries within the
hash table buckets.

This is preparatory patch for implementing the eviction of stack records
from the stack depot.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index a84c0debbb9e..641db97d8c7c 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -58,6 +58,7 @@ union handle_parts {
 
 struct stack_record {
 	struct stack_record *next;	/* Link in hash table or freelist */
+	struct stack_record *prev;	/* Link in hash table */
 	u32 hash;			/* Hash in hash table */
 	u32 size;			/* Number of stored frames */
 	union handle_parts handle;
@@ -493,6 +494,9 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
 		if (new) {
 			new->next = *bucket;
+			new->prev = NULL;
+			if (*bucket)
+				(*bucket)->prev = new;
 			*bucket = new;
 			found = new;
 		}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e9ed24afd386d12e01c1169c17531f9ce54c0044.1693328501.git.andreyknvl%40google.com.
