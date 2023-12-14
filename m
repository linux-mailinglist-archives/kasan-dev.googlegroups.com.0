Return-Path: <kasan-dev+bncBAABBQ5B5GVQMGQEORYWK2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D8C8812417
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 01:48:05 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-50bfc3c3c5esf62467e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 16:48:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702514884; cv=pass;
        d=google.com; s=arc-20160816;
        b=iWN9yeqKt7eLCC7e73Olui0qMKOFVhZwmQxYy8jXLjqSuDNhjHEs5dlC5d1NiuGQQS
         FYqgYlr1wvV32QpThk3KFGqKrVzHvrwGVjMR7GvzcaijUGICrsu1cYW6Lc8o9AnyjFvA
         ineHB/WOwKzXwU8umlwnqHNZ9WczetS+Zo4w86LTyGN58qVxQmQLTZoC/O+PMiLkMdk3
         5ZyTcuwz/gn59qPJcDOEu3FfOBo0sxeJ267WY0h2ti89yPageHT/ejFP1md0qbzwYpsy
         COe+kZdeosYl4USxExr4ezsHVBAEk2FqY4Rb2QHiAY37UzF3uSsiVaCVtf4MCWIIhLFp
         2b3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FDRNzIkilRDwmMHnVA0vRFjqLc0RVSEPer3hChWSSA0=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=iIaPhwpdz/B4A88BKVIkzZsmagU9DfxFgs21M1xj9b4Y6vSF+/E9WpXcvdDazX9aU8
         id7eG8Fie3Dok6mzFc+kmqE+VPByx6ypjF8swo0ILvf1beDZd66eMJeuBhmMG9pH47Fd
         3f5z3ZxcZBmWtaeY3kwxhQ3c1rO/mOBzXE5pp3c0um+NoSN0GXyYVzdIO/W74KqNJGOk
         O5uHqxqza/UvB99LT6zfsMGbbM8mdFYr7FEuzTPADVh2VocExLxJ2ujuRynqZ2bXAF72
         uB/6Lpwy8YlS2Qvfxfr4BpXYnkKgQzBZmf7tbArKZPvkayClB3v3/f9pNSRPI/vJhR9i
         TCXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=chtz44aT;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ab as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702514884; x=1703119684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FDRNzIkilRDwmMHnVA0vRFjqLc0RVSEPer3hChWSSA0=;
        b=xKl31lEwaZJtrOHgZbqm4mB1cZGGVeVsK+e4GzIOHxzUBAiu+iLL2yzBd5tZSmvpKh
         UJrWkeyFB5fGx9ejv4R0dV1UFQ3UAmawxcn8OoiGfnLkvV8jIbo52z/TKwKYioQQP9mD
         2F7s/MHZKOIWYginkZ3cvO4hpR1gTBBHPydRN0RBFn53svkkXPsjVp/8pQ7ZlY96rRzs
         eZrX8ysJ+ShpfFeQXLniwfR6o7kqaDs2H5B6MS+8sfsq15EJI/UmT4o7jmjZ81oPPwkB
         /h+A5D6n9WDYvCayFSb0JWpxJOum8K/+EbpA/1HYNcdOAfqBWkKrZjAUHjtKt7j8HNU6
         1LBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702514884; x=1703119684;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FDRNzIkilRDwmMHnVA0vRFjqLc0RVSEPer3hChWSSA0=;
        b=p5rXifqG8Vi58oxbtGFPlY0sOdNVQecK8I8gPHYthfoWUNmoPGIprOFIXnrfYvLu4k
         R9ebtf5jDZqJod2XsgDq6mstZa+d83Ijwykm7xpIIM4bVX9wAQDQvauWKd1huYN2Pjv3
         WLgwOiUkJ0U+cq5UJkNxN0kccFC0kJVib9lmXT8XDMKJTy3FyGB6pBNms/0yy0v8Doj9
         RwkBveTLJiIUozkfmeVHa7VI+21+VoqJkA7vWc24mgpb3yvx9ZlNK8p1U9IBcrEeZNne
         DQV18+Jj6FNwFSmPO0P1XxuoDehz1JKgq1YSy/zF4Ghlq8BSpc50M0axqWJKBMW3kjeo
         PhQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy2D1/MikqEhwyn3WACLeEnwP9PksgFbi3WFMslu13FbtEqCq6+
	4ee1waLUeZpFr79S+92LjrE=
X-Google-Smtp-Source: AGHT+IGYlvck3ZM7upMHXfu+LNbIU7FvakGWzkhKkcGo6526NNaorSAH7zzNe9lcc9EYZfgnwgq+iA==
X-Received: by 2002:a05:6512:1248:b0:50b:fbb8:4911 with SMTP id fb8-20020a056512124800b0050bfbb84911mr5290047lfb.13.1702514884240;
        Wed, 13 Dec 2023 16:48:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:31cc:b0:50c:f12:6db6 with SMTP id
 j12-20020a05651231cc00b0050c0f126db6ls825281lfe.2.-pod-prod-00-eu; Wed, 13
 Dec 2023 16:48:03 -0800 (PST)
X-Received: by 2002:a2e:9e06:0:b0:2c9:f4f6:388b with SMTP id e6-20020a2e9e06000000b002c9f4f6388bmr4700730ljk.18.1702514882591;
        Wed, 13 Dec 2023 16:48:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702514882; cv=none;
        d=google.com; s=arc-20160816;
        b=z2z3arR5mfqU4ARsTmobvXke6WOKVXbLjK6b/Ket4ngfpebpyPza9XWdA40nbVbkce
         vnzgtsXK26HC9cqOkGiFAGqPj51C+OFQya/iChSNuKVGsmiPiKErpdOIH8faWOcpBeiV
         Ms7g4DOPR+oJ2S698V8pzDvOUYxiSG0iKhLCHCgATqFN26os9QFqVN1Sb35K2Az/yMPb
         U+BNU9O71ow710LCcrPSOS7QmXUHPPQVXKF6KplAHK9RGbRWoHcGyRPRKljXBLPq8tTt
         5R47f9U6BYXsCqLayu7mnvIMYUHFhELV3xGhxlPXhQicIQZyWpGGQMqvFyJvgWCyBX5Q
         Zugw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nCFM+nFcyoFd/gCQWZCb7EKvVZ+qSBSDeoPEA8Jfh0A=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=tYzuJ31+23kKQzt8FVniGqNppllARfvzOBhmsyiS8LJnnWTYYPin/EOJCQ6ZpBAK/t
         pCj659uspde2U5pa9cWrfpqlvoLo4CoNopGrMQpT4r85r/FXngeIqn4jzlGvLV4kZRPo
         lZa9nlhvDn0PeGp5nb7xFZsc63of8EP6NHQR5fJ/e8CX12nIC1ypsazDRCh4nRFKa/kt
         WuDLQ0PDb32HazBL1vkg5xiRT4MA1lAWzMkJWUuJJySq/gsmJ20aMpuHNi4+3bFTbZxB
         au9amgiDv8yAqDmjL6BGBXbkPvLrg4JExjX/yBuQ9VYzVRYc5IP5JzF9kAP2aUKDDgik
         sbzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=chtz44aT;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ab as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta1.migadu.com (out-171.mta1.migadu.com. [2001:41d0:203:375::ab])
        by gmr-mx.google.com with ESMTPS id i2-20020a2ea362000000b002c9ffe84c49si548001ljn.8.2023.12.13.16.48.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Dec 2023 16:48:02 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ab as permitted sender) client-ip=2001:41d0:203:375::ab;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH -v2 mm 4/4] lib/stackdepot: fix comment in include/linux/stackdepot.h
Date: Thu, 14 Dec 2023 01:47:54 +0100
Message-Id: <4123304d92b1ca3831113be5be7771fd225cddf9.1702514411.git.andreyknvl@google.com>
In-Reply-To: <cover.1702514411.git.andreyknvl@google.com>
References: <cover.1702514411.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=chtz44aT;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::ab as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

As stack traces can now be evicted from the stack depot, remove the
comment saying that they are never removed.

Fixes: 108be8def46e ("lib/stackdepot: allow users to evict stack traces")
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/stackdepot.h | 2 --
 1 file changed, 2 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index a6796f178913..adcbb8f23600 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -11,8 +11,6 @@
  * SLUB_DEBUG needs 256 bytes per object for that). Since allocation and free
  * stack traces often repeat, using stack depot allows to save about 100x space.
  *
- * Stack traces are never removed from the stack depot.
- *
  * Author: Alexander Potapenko <glider@google.com>
  * Copyright (C) 2016 Google, Inc.
  *
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4123304d92b1ca3831113be5be7771fd225cddf9.1702514411.git.andreyknvl%40google.com.
