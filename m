Return-Path: <kasan-dev+bncBAABBTW4Q6UAMGQEWXFZ2HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id D8DDD79F01A
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:15:59 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2bcc2fd542bsf354551fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:15:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625359; cv=pass;
        d=google.com; s=arc-20160816;
        b=CFfEGJpAVy6+qo5wDsEUKjpkjnB9o2p2vKTErmFNxK/Mopgf6EMaT+/c8DTDIWoSVP
         VnBa2RoQTZ/uh5yOM2C8tkkpfYOGR0J6Foj7Z9im8LDwqT0Q+CRnj5QzITYiuiTbu7Sh
         60MkzX4rLUSD+8fyUP5kfU48yjjSPwEw11VCQYUJ6oJ4BHDtXTnJ1/bzwof+T99RlqWM
         spMVaLHfKz5aO7lYV18g51wyOfpuaSt9Tay40EDGJ/8zt36+7CFmhADZ/UQABEE2X09r
         7DOlAtUhxLVH5wl1jA1eSOzisf7J4bKyrPek6L79PPjcwXWJJXrbyZMF/nTC80sNlnw2
         ZLxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wyNjTUPYlRcnsvL5ujyLy7ASJsTuA75FrTFG+aVI8Vw=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=tiRx+sFGRBmAq9Z+Swrpj1VANjeQv5Zjbs1A1p6dU2S/beFQlqIFc1PcrbEHDvDgtE
         QlSAnj8rCtfW2QnxKRdSWHARPRQIYGsYhXugcG3s4ue+5eWcur69pAml1iiAj/qFo7Md
         BTTBBy/HqXXsJk/WW7lFK4BwuXZxUxQBBbFbAN1hcb89OV/51a6OvbI7PK2G2cfhBX+q
         DG3iMZYVr7pIgdLnOFEpiMYAWaqdZSlZ3vlPElAQwR4CVKceLYC7rOwe5KZlSgPd02PP
         Y1MXfm0VUbFoLMXFjV7AfskIeH54ViE8/Dp/iGyE3lG5an5SEAOSyvW4mGosIdgsC829
         TD1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wHA2oEp9;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.228 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625359; x=1695230159; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wyNjTUPYlRcnsvL5ujyLy7ASJsTuA75FrTFG+aVI8Vw=;
        b=GQ9t7wwpmtD1m2sq/ZzdRWItt9kt2Wo8OQtfV4c1z6jrVxajs4dd3x8dV30QT3jASt
         bzypmNTzLg5eG0GDzvEK+jt38RrrBOn2svMhhBWIgOMCgfCQi9g3ZYJnChKeEcKuPGCm
         0/aKqu7mX6BPBjGc9r4OKpLjfHzQIxGN+jh/L6DYvcVry5NMdK6uX9s4oH41ynzEZjRF
         lwzQ41yVeOD52ro+W84FtpCn6Px23+DBWWphalCPMkC6z3IYuloMSKwUUvSoSO2PrsdK
         u7M42WHF0Wc3dhYGRZsgZZPH6qnAPOP3AmuT1ZvkJLLdqAyDgoF5KL7yTypTxAqO4yF8
         GMzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625359; x=1695230159;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wyNjTUPYlRcnsvL5ujyLy7ASJsTuA75FrTFG+aVI8Vw=;
        b=DHwlwQ9byOe2TbEEAer3Lb2kUkrC1zzXRBbraL8LwOvxtkzmOPio/NbBE9UI+rdtQb
         1yrlH0lunbQjvh/LKalnCUzLHRitBmO0LLgEyVQnAM9HMwdJOZon+qwdnXhtC0KnLeeG
         ompKe5wprVOxUC+jN3T6xdXdjLFudWPcFshk+uA6ug/PS8U4vFmCOlCBUOUNcxxhohJz
         4a0C7ow/tZiQuooZiv57PXab9eEav4peW4fLmnOQZ8iNO61Rp5qzGYvW3CcCfsngrHAL
         rw8P8jNmepheUJlfhXIZk3jm+yRlYGr0Nv6ua/ZSkY06wCx5dDwMCVPEqpGf9SvSUCzb
         lTPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyUzhK1XdiMYdloNhfZ5LS4Z/D5F2TkaiDSoerKymG1zd6k9yTH
	l5N7X5A1/yiOwk9+1xGQG2Y=
X-Google-Smtp-Source: AGHT+IFkHmvytHe7hM/sISxUWDbNyucNrqwj03RTa36S+ldmLMZZeKVJ30teKoJ24k7v2QWQPnNckg==
X-Received: by 2002:a2e:3016:0:b0:2bd:102c:4161 with SMTP id w22-20020a2e3016000000b002bd102c4161mr3014389ljw.43.1694625358430;
        Wed, 13 Sep 2023 10:15:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b0c:b0:2b9:5ebc:4afe with SMTP id
 b12-20020a05651c0b0c00b002b95ebc4afels329930ljr.0.-pod-prod-09-eu; Wed, 13
 Sep 2023 10:15:57 -0700 (PDT)
X-Received: by 2002:a2e:6e10:0:b0:2bc:b815:d64d with SMTP id j16-20020a2e6e10000000b002bcb815d64dmr2941015ljc.30.1694625357068;
        Wed, 13 Sep 2023 10:15:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625357; cv=none;
        d=google.com; s=arc-20160816;
        b=aTybrqumpOxftfoQ71lL/TyBiZ8RZ0gfrqL3okLKNqEsPoZJqbe2qEN8wK22AWkhw/
         XWKO2xPNGbURX8Fd6ON91u74tepTd5LFtrAn7VTNwhu5Pw9Dyp/AUQhWECBMw91UOGFk
         5/e3nQny0Uz+O+Zzdk5AMEJKfqvZ2Mer/evpPdXEggO+T7QfJ2onmFoUFDqnmC/iSCZZ
         TUlAGtFpNGpEbwUDjbsbIeZhSlb8nGvqDK9TZWgSmTYzbtFYgJi4oBdH2f3Tbn4p+u4U
         ix2XeW8GDDcoLzgABVFlv0HPZXmhrrWxKeZPArit86GK9mTE8S1hSQjjtfI6pBDSSuLq
         Bk0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iF8d5PIu0hiypd5p1X1vzHkKz0HhegtzJ4nwY5HqH4s=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=QKP5fXIRjxriuVqkm26PynK13iM25xKSzdLVsPAni8NTWApkNGb7cZnuGZ0NmNLCL8
         0Iw6BTvE9e9iVSy7eMVNE7aiEvl8E+kENzRjYgD79SQMZFZ6hGnJO7b/P1lA5n2Xrlv5
         hIKiByZs3IJXV80OwLOitmjZNCWtlxHNKSmRMXDajZAlBH5qFoNg0W3m7n6svr2pAAJh
         QalUVKb6DM0Q5EAK7jO8XXV7YuQhKXWIXrxqh11F+LasuZhx83AI65wRyrHm9n2pnlzR
         wPvb2OtNXvBQA1SgFw2FWKNv5OG5OjlWffGjKuheoTAhbt5cwKVIgDF9XeJdxBV1wzN9
         wKlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wHA2oEp9;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.228 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-228.mta1.migadu.com (out-228.mta1.migadu.com. [95.215.58.228])
        by gmr-mx.google.com with ESMTPS id x15-20020a2ea7cf000000b002b9d5a29ef7si960704ljp.4.2023.09.13.10.15.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:15:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.228 as permitted sender) client-ip=95.215.58.228;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 09/19] lib/stackdepot: store next pool pointer in new_pool
Date: Wed, 13 Sep 2023 19:14:34 +0200
Message-Id: <3a7056408e391ff0c66b5f50c460a7b9f796228f.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=wHA2oEp9;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.228 as
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

Instead of using the last pointer in stack_pools for storing the pointer
to a new pool (which does not yet store any stack records), use a new
new_pool variable.

This a purely code readability change: it seems more logical to store
the pointer to a pool with a special meaning in a dedicated variable.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index e428f470faf6..81d8733cdbed 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -85,6 +85,8 @@ static unsigned int stack_hash_mask;
 
 /* Array of memory regions that store stack traces. */
 static void *stack_pools[DEPOT_MAX_POOLS];
+/* Newly allocated pool that is not yet added to stack_pools. */
+static void *new_pool;
 /* Currently used pool in stack_pools. */
 static int pool_index;
 /* Offset to the unused space in the currently used pool. */
@@ -233,7 +235,7 @@ static void depot_keep_new_pool(void **prealloc)
 	 * as long as we do not exceed the maximum number of pools.
 	 */
 	if (pool_index + 1 < DEPOT_MAX_POOLS) {
-		stack_pools[pool_index + 1] = *prealloc;
+		new_pool = *prealloc;
 		*prealloc = NULL;
 	}
 
@@ -263,6 +265,8 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 		 * stack_depot_fetch.
 		 */
 		WRITE_ONCE(pool_index, pool_index + 1);
+		stack_pools[pool_index] = new_pool;
+		new_pool = NULL;
 		pool_offset = 0;
 
 		/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3a7056408e391ff0c66b5f50c460a7b9f796228f.1694625260.git.andreyknvl%40google.com.
