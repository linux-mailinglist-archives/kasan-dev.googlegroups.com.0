Return-Path: <kasan-dev+bncBAABBMXP26LAMGQE77V4PXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id A8967578F17
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:15:47 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id b38-20020a2ebc26000000b0025d9fce1f19sf1981826ljf.22
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:15:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189747; cv=pass;
        d=google.com; s=arc-20160816;
        b=vGNo7jrxT2uDcot/4eIU8XwOSr9HUnO9JnofG4tlOrl1gLiIbx5gauYATjA0mVy2KB
         b0AL+k8E/d8LjcCOiQgCFe2/QXKk7KfK9NwaANgUT2LHz1kHFk34Fg2tl3Mqi12VUK/Q
         mAPNs0JlEYQh2EwGHdyn8wmYzg5rby9SYBgr+1cMfqZ3/o+A0cU/nD1U0fuDupRGcFdZ
         uNPw7VK4aus5OPHagZrpJOpCs4e+jDBoi9y6p0zkgnCxmSB6fTGFcbJ3VK4rvq6ei5dK
         xN8hqx7LOEOVUtfdr4TstXlfloAJMPN/mGioRf742Wj/pxtF6WFB8pCKGYCMMsPSw3Qj
         CCJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uR2SVK4lUZ6QtfUcnNYjG/l67Httj5o820IyEVYYgwU=;
        b=drE7rlKpv5zUf41KqIdb6mPjjOiwlzLXHH+JTse3VlzERF7oNNp+Mt9bqhx8Pl/EfD
         nGPGQUbRi1PqL5HuJZYZLm9nKkipSZU72KZuDwWTn3He56rQwuFI6gYPWSY2QBPK4k5V
         Wuv09XHOky/405yDEbsBWlr7rtbeAX3mfwaKYO0KBmoUkRZ0OSUXUOi4OZ3a95GPcspM
         pUgpg3kGkaWry+H61IrTDkhqT2YG/eCqqZNVsNBScRDy4FPiz32nnHI86JlKFOk0Ip9D
         IANNKtlyf+OteB25M22LxmrV4QoMGtSUOM99o0BtKyYG3v3LNo5FOSe/64XlB7SQOP9Y
         v/Vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NNYTqznY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uR2SVK4lUZ6QtfUcnNYjG/l67Httj5o820IyEVYYgwU=;
        b=T4+VeivbOeT6zm0YPDDf31M7zMwFKrWP+5c/pxxpvMHEkY77W7rFK8OhqqtfO9cuZ7
         0DFe4fwmV3q/rUrQ7kBn4aic35th8XkPmQ5qLr4bnjUEF5fU00lJoeUtZAQLkNzRqc3e
         hdZ+wyAMHw5sbxMP916yf96zm2ta2L2uqvom5hbvy2dqR6DKFgxf/y1l59VMBEvm1bNE
         wUf9lvyx3Ra5h6A9K9Hn42Qwht3X2gXjduQ2TicILy06+BsSyR9Pp6U2K1oZFGY4zEqf
         lywc8KjXngcT4Bx1MEJ6XWsZk7c39fdUTFYFKjumlgxiEo/7K5a2HHI9//HJeiiWFK2S
         ZawA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uR2SVK4lUZ6QtfUcnNYjG/l67Httj5o820IyEVYYgwU=;
        b=lKeZXak1psWK8qb9Vx9i+XrQCKqwEm8llqkiXV2qEjOvJJ66QvWLO9yykVwwOgHi5r
         J3rYqI11N9zKiqR8YzYRnf1ixL11nx6XpHnXQhOYDdudujG/QdgbV+T+4RuJU4rFVWeU
         XtxOky4dUMqVMVrfF16oKeEwG1BCIr+99/QMdMdaYg65i1yT/1dGJISG7IIeYevSnuEE
         VXKPRl86v2PgK8/NsaHFDtalI6fgPZzbh+qXTvWQ4fqyPzFvrruLAxOjvWcIp+X7Ybb+
         zeo4kYHdUhmBaP+8iXVl+dQPBRtmlf4YbBZV8G9KtOgtnInbBfoYKFbdyZQ1DLZr0sRK
         NcqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/Ec44dYj63hegOwKQQvBMFecsQuEpz8GTzFgE2w0A3EBu3PZbe
	9ohGvatn0FMgqSXqzXvAn2Q=
X-Google-Smtp-Source: AGRyM1s7aCH1Oklse7lZN1a9eF+b2JdlHRdWi91lDycsRwEQMdlpDzt8qwHY8OsvWeXrX06Lyt0drg==
X-Received: by 2002:a2e:93c8:0:b0:24d:b348:b070 with SMTP id p8-20020a2e93c8000000b0024db348b070mr14139191ljh.434.1658189747069;
        Mon, 18 Jul 2022 17:15:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3ac:b0:488:e12b:17e9 with SMTP id
 v12-20020a05651203ac00b00488e12b17e9ls1665076lfp.2.gmail; Mon, 18 Jul 2022
 17:15:46 -0700 (PDT)
X-Received: by 2002:a05:6512:238a:b0:489:e6f6:c13f with SMTP id c10-20020a056512238a00b00489e6f6c13fmr17337088lfv.673.1658189746302;
        Mon, 18 Jul 2022 17:15:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189746; cv=none;
        d=google.com; s=arc-20160816;
        b=dCMhrTAQsyCYgS3HN7XZGjLfP2xJHW3+B5hGCjp5E+/b05YbKBGALA4jXEAZfiY3LT
         umK1fjnkKoOP2IVJIk1JRDXFwNQ0it/FHk+2RFrVdBwwsmSlEm2L3EvGgTe6MQXNLyUY
         IuxqyUojeyw8gGBrEoDxmNcbxBjB2px4S5Ymbw9NYsLOcWT+SYL4D3kGkuezftCzN5t3
         tyaeE1nbVU/OdTt774EUgwycBMZxOcbMcsY9ko58vqnfbnmIEipi4Je3l52IjwQKHw80
         J92Hr5Z3L+8bYU6VXhX+U9tp4j1yljAYBVL7GJnU4Gz4KDsq1SNLzGYHMjIdcbGEhFKN
         yUZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QKjK8ZCYDbi7wJ5mRNldR0JmUEuXPl5aWvMQPqK0SzM=;
        b=C5nhlW/5/960vNmus7evLnWF/ykirYkfZmz//+wIct9rUBVoWdm46QHJGvR7BK0sEf
         km4BgjoJsEOiXWB/fMQo9fgvaex6lne+SjrwsjlGUmMUobf0pwvWxjr3LgfCtZGALy7S
         uBc390cJzj6uQuP1E77+RgX0PREpvMH4b0a7hzlHd2UXriOdL92U4DtzGNk674TvF7eC
         xHuHeTHadGzg2CAEwX4WeaO3SiH8Zc9LrH/XS4hgfb2azKOec7KIPBaursL93TRBtlmV
         4ELM9uYP2nzGHgmPs4DPqUG40Br0+AWA+a+L46i0GGqIQL0s7ZXEKWd9L+K5yo6hNXbC
         NMLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NNYTqznY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id o7-20020ac24e87000000b0047fae47ce32si398201lfr.9.2022.07.18.17.15.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:15:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 33/33] kasan: better identify bug types for tag-based modes
Date: Tue, 19 Jul 2022 02:10:13 +0200
Message-Id: <355b5734d7f70a70c87ded21b3c4267e1c401b10.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=NNYTqznY;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Identify the bug type for the tag-based modes based on the stack trace
entries found in the stack ring.

If a free entry is found first (meaning that it was added last), mark the
bug as use-after-free. If an alloc entry is found first, mark the bug as
slab-out-of-bounds. Otherwise, assign the common bug type.

This change returns the functionalify of the previously dropped
CONFIG_KASAN_TAGS_IDENTIFY.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report_tags.c | 25 +++++++++++++++++++++----
 1 file changed, 21 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 7e267e69ce19..cedcdc5890bc 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -10,7 +10,7 @@
 
 extern struct kasan_stack_ring stack_ring;
 
-static const char *get_bug_type(struct kasan_report_info *info)
+static const char *get_common_bug_type(struct kasan_report_info *info)
 {
 	/*
 	 * If access_size is a negative number, then it has reason to be
@@ -37,9 +37,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 	bool is_free;
 	bool alloc_found = false, free_found = false;
 
-	info->bug_type = get_bug_type(info);
-
-	if (!info->cache || !info->object)
+	if (!info->cache || !info->object) {
+		info->bug_type = get_common_bug_type(info);
 		return;
 	}
 
@@ -89,6 +88,13 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 			info->free_track.pid = pid;
 			info->free_track.stack = stack;
 			free_found = true;
+
+			/*
+			 * If a free entry is found first, the bug is likely
+			 * a use-after-free.
+			 */
+			if (!info->bug_type)
+				info->bug_type = "use-after-free";
 		} else {
 			/* Second alloc of the same object. Give up. */
 			if (alloc_found)
@@ -97,8 +103,19 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 			info->alloc_track.pid = pid;
 			info->alloc_track.stack = stack;
 			alloc_found = true;
+
+			/*
+			 * If an alloc entry is found first, the bug is likely
+			 * an out-of-bounds.
+			 */
+			if (!info->bug_type)
+				info->bug_type = "slab-out-of-bounds";
 		}
 	}
 
 	write_unlock_irqrestore(&stack_ring.lock, flags);
+
+	/* Assign the common bug type if no entries were found. */
+	if (!info->bug_type)
+		info->bug_type = get_common_bug_type(info);
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/355b5734d7f70a70c87ded21b3c4267e1c401b10.1658189199.git.andreyknvl%40google.com.
