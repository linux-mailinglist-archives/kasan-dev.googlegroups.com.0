Return-Path: <kasan-dev+bncBAABBVOL32VQMGQEFMDY4MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A74EA80DFE5
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 01:14:14 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-50bf07e91b7sf3728340e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 16:14:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702340054; cv=pass;
        d=google.com; s=arc-20160816;
        b=CDq6qrOTXKqkhmdqC/xtZxLG6OcYX8uZcAbXbh+YB5caZEf8UMq+GRzVbzur/ewIGM
         4aV/94/dexIHTNkyOAaemVgVen2/lEyJtbBnW6YJJHgYALMzH1g3lSYUCMCOFpWHqeDW
         M4y2GRwfOfjkTD93XAf575cXW2lmHW1CcxrvbTQllrfyhlQlCoXMjq9rNz/P/xjQZGSX
         +xm5TdlydEPaQpolVjcU6C04M8TWTBSSH3sRS8ZLth+MS8GGaH5R5JJc3lo2MvPZf2is
         WfS3tXICmZ1PEDR5PEoc80nkfqpX+joHrEDMx794340aUy8uJnGD+mitfG0QDwU0sT+/
         aw7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DMDf7xl3IN8S0wI1l6/gF+nR7BwxmTtZ8lMEPhWMY60=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=ofQXGZAxYlXeLEZVVNfD47D50RSIyjrZ1MQg7GShP7+HrfMve/GUTAYpVyH6ShTFIr
         S9E537Uq9jickJxgGd6HAhc03dSy/UL5zXuesNsHr9JM5q+mZIa7Jz8YyIMxN9EM36mi
         89p4liUeo5pI8ZoBqE/X9+Vec4XmSlUVCeCcaTXt5vWDNDDkNIWJ7wPKqLV40PgDuEOm
         D4iwk596z2YhDHOrscPHNkhtc2xwVwSZix8n4EYUjv0thBQ0ivDGy6qNk3zPk6pqGm+8
         eif5LEnMiYNvdq3zHtk8CTIgJVLkgDVgjZbzo0btIpmgsg4y8QRC/Amhn/pGKs+x/nsd
         BjFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pkglrqnI;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702340054; x=1702944854; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DMDf7xl3IN8S0wI1l6/gF+nR7BwxmTtZ8lMEPhWMY60=;
        b=ME7NGP4bVSvkL7wL33RfD3io5ETVcfWDJPTxYKainz8k7AfQolyjpvE/jIRORkaeKM
         WWzH1aOIMJnSOhpDmfhHkufCV3i6uNtqiaJWxhiz2njVJDLZFpioxAGYdTVow18fClQS
         LYE8i0UhjzsE8a7Bnk+t/Xxy6g8cW6Ea9P6LpxcTyCYEbZPHcJzWy/XnIxZ1QAH+WRtB
         mrJdG0y7DUYoSLnBLLp9nOudY7tM+y0/swbeqheCfjYA8GW7bAdull9/d95YzeYcFOFj
         Yi2YfxPl03Jd08lxXIzgNUCinnWuUfs2wCzkrD1ApnP19qluyHrRWx1HRQxC5eu5Zkqz
         Y2ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702340054; x=1702944854;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DMDf7xl3IN8S0wI1l6/gF+nR7BwxmTtZ8lMEPhWMY60=;
        b=OtsXdgWQHT7FQZXq+snmjFgzujCFx81ko6Px/yUwHGjfE9MRIHNbmQlppwS1iLdbsn
         qn7C5jjwXg6zPubf2YefwBjtPowsZCUixhUUgzWedSs8x7V54VxF3RxU9vG/2LSBDeKX
         AtUgLeinkWR8IQ9TOuZPoZZgAeOsLli7+zvWyoLQvfHHeZthus2OYbPQcZ8usqO+PJoR
         3rYkCMFsrLVl3TxGk22Qu96CW5a0xjTlRf+3yLteYYZnsE5dA5+3/bcOKAgmQujLonWc
         bOeQQlRfWYPLLYfZuQbt0Jc3+0b6uahMRllM6oCzA3es2qFF9kkHemmzpDD8hjZBh+a/
         ElBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxiyWamwfY23LygfkyJNdE+qIQfEl9TeEXF+c6NmJAcFhjnHJ8z
	hygUDhEva28/d4pMFeKf0lw=
X-Google-Smtp-Source: AGHT+IEgdJi+qLEgedSXClXHbcMVT2ZIpIFZY2vjAawA7R2dWR79X9kYbx/9xLBZQsSa7u+LCCIh9Q==
X-Received: by 2002:a05:6512:b20:b0:50d:f81e:6872 with SMTP id w32-20020a0565120b2000b0050df81e6872mr1690947lfu.10.1702340053881;
        Mon, 11 Dec 2023 16:14:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b0f:b0:50a:aa99:28a8 with SMTP id
 w15-20020a0565120b0f00b0050aaa9928a8ls2254911lfu.0.-pod-prod-01-eu; Mon, 11
 Dec 2023 16:14:12 -0800 (PST)
X-Received: by 2002:ac2:4dbc:0:b0:50b:fe37:d26e with SMTP id h28-20020ac24dbc000000b0050bfe37d26emr2066078lfe.67.1702340052197;
        Mon, 11 Dec 2023 16:14:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702340052; cv=none;
        d=google.com; s=arc-20160816;
        b=PlUGUIFJQu0qNSjMVPBTDBHd7uBjJlN2sST46WKh5i0/TChQ0qSWc7KJi0PSdQ4VKW
         gdGApYYi1NLmPNwQ8Z3VgVnQhIQuqVDNezqcWtD6ovenF+EC+ynopeWzceRPtKeMTHbn
         +hFtHIDCzydm+ldMjYq2jNygH1ophf8HUbSYAgWpFENrBy7qKD29QFNlMdCKs8vJyT/t
         nqEY49ZSrkiUjLI0XOmLGmVKv1mtmiWxUMlsvAM5WPzxwIpki0Xf2xQIgb0iqwHyRkLx
         xCubEl04+wOEtLUA5t5oKgs43CEuwsXH2tTGkwS5GjO4e71jfk3Wp38Bm4qh30GSxkJ+
         LJbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4v2xeqlY3bmUQ3FXCYD1mACtOfLEO5nvek1y1ZiQa0s=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=zix2//NtCBWAyoDHQhgVIrhYIZVVRKjbyBbu+KAkoELL2IY8vmQPg6vE5zOmLtujJR
         zQt22OFKl5z8Au+75Cdj3ZtayAErgofJg6eq7L07kGFf91PHldcmS429Rurb6zJ5Ks5b
         w9M2PXXql1p0KVirzg1XnUKI+D8U9ul55pl9PTACux9ShLMpF4KGR3iz0+r1NQI3R8rA
         qW9BFmfDuWUEWY64DZ47Q8wUw6OeeaKKxjvuWUSDYdCI4oIxgGqTBRt47XgGZX/cwtd6
         krxxcmKzu7iY3e5W1KaLezoLC4o++ikeHMRemvXpJl6XQGkYRzYKEGNJ285d5VGoNBr+
         xXUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pkglrqnI;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta1.migadu.com (out-173.mta1.migadu.com. [95.215.58.173])
        by gmr-mx.google.com with ESMTPS id u15-20020ac258cf000000b004fbcd4b8b84si357937lfo.0.2023.12.11.16.14.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Dec 2023 16:14:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as permitted sender) client-ip=95.215.58.173;
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
Subject: [PATCH mm 4/4] lib/stackdepot: fix comment in include/linux/stackdepot.h
Date: Tue, 12 Dec 2023 01:14:03 +0100
Message-Id: <c8bf7352aca695ea9752792412af9ee66dc2ca17.1702339432.git.andreyknvl@google.com>
In-Reply-To: <cover.1702339432.git.andreyknvl@google.com>
References: <cover.1702339432.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pkglrqnI;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as
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

As stack traces can now be evicted from the stack depot, remove the
comment saying that they are never removed.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Can be squashed into "lib/stackdepot: allow users to evict stack traces"
or left standalone.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c8bf7352aca695ea9752792412af9ee66dc2ca17.1702339432.git.andreyknvl%40google.com.
