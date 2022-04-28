Return-Path: <kasan-dev+bncBAABBJ76VKJQMGQERP2Y2TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 457905139A2
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 18:22:00 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id t15-20020adfdc0f000000b001ef93643476sf2101133wri.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 09:22:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651162920; cv=pass;
        d=google.com; s=arc-20160816;
        b=D06vCOyJ7/7+y3jkHWdvyei3yrMSN6bkZQmg4NaD6AC24orfxHFvQhP/rUMQkaQKhY
         wAZy2/JNdgGFkzvcHMxDQDWQObm+ymPIGJOFyU+nkrhsMztHbl5Zi8y/a35UycmsyRev
         qriLm8hyciEIM9OsIQ9nCZbMkUZ1VkTxbo0XrkVfJU9W0f48XFayrpm9PTxgf6ZIvwpN
         XlbKTpD/86TqYY7drQxXRjB52+k06s/Ia5+xP5xNR3ESV65PD2Ad5j4hvIvCD6K6h90Q
         1TXZDLeBl70NN0o8cHTA/e3pMONDaLTw1jaeqNrxRT8mRlMEAEho58WXQr4QWVQIXvDo
         dvuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Ml8IcMmvrUKT7/FqGXEXZwEY6K978AgEG0dqIk5l+9k=;
        b=vvLvrTQJ3w4wTyGXQjvha2F2ydhytQ9HfGjZMdI3WMiX0PAoo9bEIpWdfKsGI8N34Q
         uJ5nRqTWMxWqrQT8cZWbTPvS+w2po3zNDk2jEKoqM7hPHBRlMxYfHB618DizIIj4cv1Z
         +EutRFys8FeHqLMj1HTj+cuN/7u5JsIJC4fgU0sShyM1yuKo1KqZlzu9vEGFvlADKtqb
         +dbnMkJdEvnXmvltPp7KmjPUshsb87iOwbhRZIiQzoSJ2CtUi3Uo+bJ6GVxwwwg916m7
         j7jiRlUT2/mT5UZDZztuT4YrXcpF/TxHmx9P1UjjFhqnDMFx8B3Ow+d9BhDNZuAHhE7q
         c6ZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ljf+8djC;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ml8IcMmvrUKT7/FqGXEXZwEY6K978AgEG0dqIk5l+9k=;
        b=k8+LI+klohaUtE8Ruut3meGAxMScrhGtaoYNjLahj/sfdkRSWBJab9FX+kF6MNwIkt
         4MrnZ2GlhCqzw0RUJN0eoe+uoVInmCgWeYoDeU6djwYvfrURSOzRDkISEFSMOkoPjsAZ
         AWx0pQY5GpXVU7nPStjy/6+QHC/7xrAarbM1oMmtTXo1s1yScHu3wnac5yNg2FMYTDNm
         TT6tUvEbAVovkQIb9eLUkn/D/n5CtwBW+Z1j+C3ofWiykDkbfjYCgtQjwLRAfjYrVEED
         e8zn3mn3KQsriHUDW9CRpTLV74upv7joTA+lIfIeZRdbS7qXZ3bD+4Wxa2eoDnUL0rjV
         8lDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ml8IcMmvrUKT7/FqGXEXZwEY6K978AgEG0dqIk5l+9k=;
        b=yrWP/qa5+4d63zH7+R83pX/gtC0NPnVeD0K5jtJKDDkpzFlX4LprLtIpKp9nq5tCdU
         rul9bsLWgh7sgSm6/1ofsc1JnDhCTLS1+Ip8zYU9r5lJLsJrcVQOsJgle8fKN0JLKOI6
         mB4IQQlGuIuzOshl6FWQ8VoRnVJ7N2a2dqCmIrBB8BEkvmfj5hg6S/jhMydtequ/0dUw
         M7ebzwLvp90j1cU+yxLaMm3E+dkv2en8XI2EouKcDLRvb+rhSFst6RR5mI26BmkpvrbU
         bPuUJlfCAp12NNhLL8ISzna1xGdfIEZf370dANU1ZkZMwIm3cgUIBjpeSZ2sJTcwCpqI
         bnSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533EkSVzC/MqA2P2Rf2G6zRq29OR8Kp/a/UY0B+/5Umg/ZJQS1cK
	p/ubRhzml5ROBDCLjWComG4=
X-Google-Smtp-Source: ABdhPJwA5XcGPPLCeZjBL11/aLOHLj/IrCp9qOpDjiHdD8kY6hmFI3hjVJUYqLDTenDu2lBD5LMMvQ==
X-Received: by 2002:a05:600c:1e89:b0:390:ba57:81c6 with SMTP id be9-20020a05600c1e8900b00390ba5781c6mr32490491wmb.29.1651162919798;
        Thu, 28 Apr 2022 09:21:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6d84:0:b0:20a:eafa:40fb with SMTP id l4-20020a5d6d84000000b0020aeafa40fbls691310wrs.3.gmail;
 Thu, 28 Apr 2022 09:21:59 -0700 (PDT)
X-Received: by 2002:a5d:5690:0:b0:20a:d24b:ad12 with SMTP id f16-20020a5d5690000000b0020ad24bad12mr21718985wrv.280.1651162919058;
        Thu, 28 Apr 2022 09:21:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651162919; cv=none;
        d=google.com; s=arc-20160816;
        b=mdPg5VT7zrJIaIlzYAEcbq03LVtwrnMWyeuhmAaCNlTBlBv9rIH5hWipsIBJ/UMcSw
         0KMl7MoBlPnmq5vUd/k2EXYIvt8ImjG7v4IbVnvMmwuryhcB3RbF9bEuCQwTs212z1Oy
         jqBlalykyiyZBXcUFRJMiJUpzw36SHmoWIl/dgCFXhCCuImdOxVJeNcqRSVBDii6nZJN
         Yrf4vclXeMpCpsG5wh5wNV2VtfnrXc7zkZChkvqB/MRCwmawDVsdiEzKsyV/Az71VrpY
         KZR5f1D1pgN4Fk9CkstwWa1uyv+lsNJxqzjjj5aRFcP5+CpEiOMT9mfrxe2k1gUt4GnL
         KPBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ScfRiX1QGknyiNAjIBYqs4VvQ59BCXbjYO7mgxh1RLQ=;
        b=CLbk+rYN3mUpBlhIgmipYSrQ1d89SR2e1q7p3C5HVYJGzpPeYB9HAIM1WxWdf8cQAD
         f6aZpsdT2IRToMhyom9q67Qvk9PtjwsBMsGf36ijONdyP5nKcyBdMjC1g6dqvxOwZ3LW
         YFQn2qU/WGNOEpbfnGLx41/YPJJng3200aW6DL96wFu2h9WVRP200Khf27sO+V3HRkgK
         UEoi+w72KkjXYg7mw6Ecyb7GcwiHXff6fhpo4ogecR8MtuzXk4eo9i9wmT5/Wx1sIY1L
         foRnnzMKKX2Rgv8bDKEcZNOR7+uOM00B7/s4VtgJ4OPNFkgkPVrnRqp9iO4t0AfuM/dp
         KKZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ljf+8djC;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id a11-20020a05600c348b00b0038e70fa4e56si481627wmq.3.2022.04.28.09.21.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 28 Apr 2022 09:21:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 2/3] kasan: use tabs to align shadow values
Date: Thu, 28 Apr 2022 18:21:51 +0200
Message-Id: <91a979ef1eb9aa68d820234663ad797b4818e098.1651162840.git.andreyknvl@google.com>
In-Reply-To: <3167cbec7a82704c1ed2c6bfe85b77534a836fdc.1651162840.git.andreyknvl@google.com>
References: <3167cbec7a82704c1ed2c6bfe85b77534a836fdc.1651162840.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Ljf+8djC;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
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

From: Andrey Konovalov <andreyknvl@google.com>

Consistently use tabs instead of spaces to shadow value definitions.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 32 ++++++++++++++++----------------
 1 file changed, 16 insertions(+), 16 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 13681516dc08..06fdea41ca4a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -74,29 +74,29 @@ static inline bool kasan_sync_fault_possible(void)
 #define KASAN_MEMORY_PER_SHADOW_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
 #ifdef CONFIG_KASAN_GENERIC
-#define KASAN_FREE_PAGE         0xFF  /* freed page */
-#define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocation */
-#define KASAN_KMALLOC_REDZONE   0xFC  /* redzone for slab object */
-#define KASAN_KMALLOC_FREE      0xFB  /* freed slab object */
-#define KASAN_VMALLOC_INVALID   0xF8  /* inaccessible space in vmap area */
+#define KASAN_FREE_PAGE		0xFF  /* freed page */
+#define KASAN_PAGE_REDZONE	0xFE  /* redzone for kmalloc_large allocation */
+#define KASAN_KMALLOC_REDZONE	0xFC  /* redzone for slab object */
+#define KASAN_KMALLOC_FREE	0xFB  /* freed slab object */
+#define KASAN_VMALLOC_INVALID	0xF8  /* inaccessible space in vmap area */
 #else
-#define KASAN_FREE_PAGE         KASAN_TAG_INVALID
-#define KASAN_PAGE_REDZONE      KASAN_TAG_INVALID
-#define KASAN_KMALLOC_REDZONE   KASAN_TAG_INVALID
-#define KASAN_KMALLOC_FREE      KASAN_TAG_INVALID
-#define KASAN_VMALLOC_INVALID   KASAN_TAG_INVALID /* only used for SW_TAGS */
+#define KASAN_FREE_PAGE		KASAN_TAG_INVALID
+#define KASAN_PAGE_REDZONE	KASAN_TAG_INVALID
+#define KASAN_KMALLOC_REDZONE	KASAN_TAG_INVALID
+#define KASAN_KMALLOC_FREE	KASAN_TAG_INVALID
+#define KASAN_VMALLOC_INVALID	KASAN_TAG_INVALID /* only used for SW_TAGS */
 #endif
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_KMALLOC_FREETRACK 0xFA  /* freed slab object with free track */
-#define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */
+#define KASAN_KMALLOC_FREETRACK	0xFA  /* freed slab object with free track */
+#define KASAN_GLOBAL_REDZONE	0xF9  /* redzone for global variable */
 
 /* Stack redzone shadow values. Compiler's ABI, do not change. */
-#define KASAN_STACK_LEFT        0xF1
-#define KASAN_STACK_MID         0xF2
-#define KASAN_STACK_RIGHT       0xF3
-#define KASAN_STACK_PARTIAL     0xF4
+#define KASAN_STACK_LEFT	0xF1
+#define KASAN_STACK_MID		0xF2
+#define KASAN_STACK_RIGHT	0xF3
+#define KASAN_STACK_PARTIAL	0xF4
 
 /* alloca redzone shadow values. */
 #define KASAN_ALLOCA_LEFT	0xCA
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/91a979ef1eb9aa68d820234663ad797b4818e098.1651162840.git.andreyknvl%40google.com.
