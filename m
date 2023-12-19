Return-Path: <kasan-dev+bncBAABBAFURCWAMGQEDKRO2MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id CB7008193A1
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:32:32 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-40d27ea0165sf8439735e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:32:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025152; cv=pass;
        d=google.com; s=arc-20160816;
        b=zJ/qAejueBR2dSDJzM7Sbc4Vf4vKXv/yJa44bOPs0/oB17N7cojO0dkka7zkBfkyxH
         fe/ckWBMSQznb04EOMC5wrpaaZuAtXni8/qS3h+DwTXhR4ClXgHUxqs0ofacduQDy9/C
         mTbskotHeiQwcm6Z2z3uxT9YwrHnAzyZ7IaGIxPK67hDEAlZAh2b+fJfEswJQWjFCLuh
         ifsMR8+D5tb9jjUZUyGo47WQz8YNcSAPBhSU/a+ULTRRds57jOqu0rnN3jqjbnB+9ah9
         ifWwocCARR2G1rznF3A4/S410lnHKItk1oIPQvmbTFwCZNO0llNBVjlbRj/Rv5FQ6zVA
         6fXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6DnHhTlIMp2ubwbYvjOLSqQ7XgAwHxj+q0TFrk/I9qY=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=vEavb2TvRRg1Lywx9IxhEwKr0dIeJCTALWpCqmSQwufKFqdogbuieXAu9yirrffSJr
         hBNYVWdTM6xHGHHF1gpoC4ftyySG/Q0ZhUc8pkZymW4dp/oU2LtJvAUTDCnIa1HUSGSI
         iXIbB4eGYrdIi9UkFh96sGXdMKcJEV5G97jSrSUg+iLz6i7NZHz+C7AnVQNQeSOQap8I
         7cj+Xez82ez6jk0ravmbrakOepwvGqlKQD4JgGM77CHLSbQdN4y0gYdkOVVEztC1OLZL
         wDiEIx9OfrA/czzUooF9o9EA+mnXIB8L2jkRq++Z0s06IJXLQVT03o0xCxc2SZeMCyyc
         uZQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="PVS7/Vp9";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025152; x=1703629952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6DnHhTlIMp2ubwbYvjOLSqQ7XgAwHxj+q0TFrk/I9qY=;
        b=TgO9kPpuQfp8o+12Lyx/D6oIlqwpF+WVenkniwNgQOlx1isdJ5sOwUvs7UQadBCSmv
         yVvzA67xz3D0ybocA/2K4QDqWjAjcAl88cdstK3tNNK87gDUqOGKWCDXug1SDKlc7aGj
         EKiDfsoC43H1+p6E+TiaRjxA18l9HNF+zTLJ3pjFY46vFYoiXJM+m6gumOmPSLttdhaJ
         DjbO25LurtB6/86/uhChHp/AQbRmwGpO1Fz1WDgkl4QqbZ1fZP8IszvolBsDuQ0ODtjs
         zLqv1tQe1YSdibPIR1zpFNYDCmWWM2FueNYft189+B8rIvA0hK5UCojqL+flAXeqO8Ds
         waig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025152; x=1703629952;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6DnHhTlIMp2ubwbYvjOLSqQ7XgAwHxj+q0TFrk/I9qY=;
        b=eUDuTha0GGJd1Z6ia4twHVmpC7L5hGXhx7ss4vMzcAqZNh+fGYrslNaLe4QXPUdaS9
         dVooUT9Atb9T23Idxof7Kpgwa9M7wjq0e49VB5sKCjvxSSydgqVN+r6QuWSOCq6bx8jf
         vEwfpRarG9erpo/Qx6q7Wcx1365YbUyIZFvb27VPKVr/tWpLimrjV48CGPSfb6rQSI07
         QkysgRJ2hzzxsT5j+Tq/VAYnIILRGXFFWxR9jjxIZZf5LGeI0WZ1l44Dts51h72BDCzn
         H2utG94G6dO+GdAXtGkvamMrNiPCKPT7SeUODXp6uxQkmNAf9tUcuAnYLYcIEdvcURoI
         yepQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzRgi4a79HbwoycoLkjsheGullCb9J+waTKyHRCOgeYxG22yRJr
	Dmmz3UWjM3ZGXqSsgmQBVdY=
X-Google-Smtp-Source: AGHT+IGdzyO4YWbQTPoFiwMsDrhPqNpzzuhU9M3L+2ul1Gya74majif2ArsHKnQDxK96FDtpFHgNBA==
X-Received: by 2002:a05:600c:a49:b0:40d:231c:7f2d with SMTP id c9-20020a05600c0a4900b0040d231c7f2dmr946155wmq.17.1703025152359;
        Tue, 19 Dec 2023 14:32:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b02:b0:40c:3e7b:c687 with SMTP id
 m2-20020a05600c3b0200b0040c3e7bc687ls1290741wms.2.-pod-prod-06-eu; Tue, 19
 Dec 2023 14:32:31 -0800 (PST)
X-Received: by 2002:a05:600c:4709:b0:40b:3dae:1ff6 with SMTP id v9-20020a05600c470900b0040b3dae1ff6mr10216880wmo.14.1703025150888;
        Tue, 19 Dec 2023 14:32:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025150; cv=none;
        d=google.com; s=arc-20160816;
        b=v9R+I5c+njwWyvZ3m1GjZeAkQfCufXomP+s1Vm9qbeoqV4tS3bhaDRup8Io/xWR9pm
         vg7i8PQFRV0H/bBIRJiStzeNJ/QfxPxxEDPOCugenS3/WE4RS3ycX7E/UgqQntquy/po
         9/vmNmrfeTHLEG1FwojWi8uYtcoyFJ+WnIRdlpuYPpX5q4u3jjRiS1uJ/gNaAynPUVj8
         /9LZzvWEWR2Pk0JdfQxB23+fLwJ/tuv/iZPbHoMFfmlRVC2SuUR6LLBZ4xzexZ3enyGo
         KS8uAe4j3mFo2l8mFcUUNNWXDM2rbyzWdSq/HaHESLP7iH0cu5hj5udKI6icDm44kSnn
         5+MQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EPGVjwO+qP/d7FcuwPK2D6CcDKWjvT42oG4AsVrb0Go=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=YiAStcj2k8Y2crknejWAG0PGg+68TkuVflLEoTt4laXoFgscQxUljJExbKrpTH8OxZ
         hqJu1NxtLK7iRaNvfU1M8cLCgCid0AtFaKNYjFZ6kMRzBhnPVAB2RLJbDJE7ccGHx5yv
         RQK1kcnBymfYxUdW5/DVdhsGzVfxMGQsZ5R6Dk3tAc4jPOsD9AftlMS1R8lHxMSCvouC
         xj0UAjnmN/N6piDf4hMwWneYLySr66xU96QAJNVwpiDSZx1I5ecVDi7eknF2Y6LIz5JG
         HTgjXQycBFvsuPB5uPaSTZycTbHJXfdM2XHr66vCnENXx9hwXV6GxJUBnr4UikuHwTBw
         4uMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="PVS7/Vp9";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-187.mta1.migadu.com (out-187.mta1.migadu.com. [2001:41d0:203:375::bb])
        by gmr-mx.google.com with ESMTPS id e16-20020a05600c4e5000b0040d24b04686si483wmq.1.2023.12.19.14.32.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:32:30 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bb as permitted sender) client-ip=2001:41d0:203:375::bb;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 21/21] io_uring: use mempool KASAN hook
Date: Tue, 19 Dec 2023 23:29:05 +0100
Message-Id: <eca18d6cbf676ed784f1a1f209c386808a8087c5.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="PVS7/Vp9";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Use the proper kasan_mempool_unpoison_object hook for unpoisoning cached
objects.

A future change might also update io_uring to check the return value of
kasan_mempool_poison_object to prevent double-free and invalid-free bugs.
This proves to be non-trivial with the current way io_uring caches
objects, so this is left out-of-scope of this series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 io_uring/alloc_cache.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/io_uring/alloc_cache.h b/io_uring/alloc_cache.h
index 8de0414e8efe..bf2fb26a6539 100644
--- a/io_uring/alloc_cache.h
+++ b/io_uring/alloc_cache.h
@@ -33,7 +33,7 @@ static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *c
 		struct io_cache_entry *entry;
 
 		entry = container_of(cache->list.next, struct io_cache_entry, node);
-		kasan_unpoison_range(entry, cache->elem_size);
+		kasan_mempool_unpoison_object(entry, cache->elem_size);
 		cache->list.next = cache->list.next->next;
 		cache->nr_cached--;
 		return entry;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/eca18d6cbf676ed784f1a1f209c386808a8087c5.1703024586.git.andreyknvl%40google.com.
