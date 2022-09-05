Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3OV26MAMGQEKLBCKBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 108625AD26B
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:22 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id r11-20020a05640251cb00b004484ec7e3a4sf5725126edd.8
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380781; cv=pass;
        d=google.com; s=arc-20160816;
        b=d/kh3ZZBeQVd/j1KwOM0YIdBYZMxrx/ilbGbDRL5dym/z9zeUfbeON6mpikfLucGmm
         4BNuTrPOzPMceYj7qoMRtfU+vkc5j5yPRsgbLnFF0v9IjcnLzOu42zqRP5wuL4unKfTU
         3Ahy1ezvsmQ0LlnwjXdm7crUwrwiS+0PIdz9yACh/IwhA3oQfDVcO6VZt8KQ90ELBvrW
         EbWIC25LXhMOzsybqg5ALlqTW6F+mGbEvB+oEqm/7e/N66yCNF5z5sS0InkRRrJOaUZL
         czSu6/nZTi4I8+nR/+kv4Jtri5AlQVjkrvWT9W+RG7a+uxeFF+RzFj4aVzzgeDKyidZ6
         /whg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=dupevPsgQ6K9OrErTBAL8OzAxOef5zW1MPe7K1r4/NQ=;
        b=NYxWkQWOxi8mnljk0amR4TyziqOuXyb5QJRbVHZvvcjGLtGU/CSrzrHch0gw/TNAGw
         0/nnrY478I9DS3NE9PH0/hN7n6l7D0Wa+aWYXq+sKxwgXjOtT6t9jhIZPo9DUinrqL1Y
         MBxob6j0+gm40gSFJ/0fkx47xHbxxH0NR/XK9u93uKKlqp6Lwo0YS3gBp43EMGXClDJa
         bvmihO9/cYUyAksNTq3xVnLkJ7UiRw/Eg8d4azb/OYFwEWXC8pdIn7fx90/R76JctBPQ
         QSItEsFKVCzU2wFrA0fWlWNq/26w0HFYftHKroyuo7k0RPVYROve8INdIQlfz1z3j3G4
         dEWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SRHbIOUb;
       spf=pass (google.com: domain of 37oovywykctkbgdyzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=37OoVYwYKCTkbgdYZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=dupevPsgQ6K9OrErTBAL8OzAxOef5zW1MPe7K1r4/NQ=;
        b=b0xQiU97E4NkbIae3RwxYEyhOGUEVQLlmQOUjXkGzwCcRLnO2eSY7JC63xHQg2zKGw
         1bhQrtW0gCJuybgmqQ6utjrF5zZdyVBtHjGuYVVIukdUCc4C3s6uuPIeiFNWvyAs6qVd
         BLKid+fBEQhFtOs+Skuajyc7Hg84Q4TsPfdCUFF84bCdF/oSrTho7rUu39RGPZkO7/83
         xOOjhwTvRFeZIxIz0x/my7kkiUgYvi+HbGWq30ptQcGjB/I9g0foygsNdTDcTURo6RhU
         NkxllSny7K/8xTLLfVhmSoGmwuAWI6vI0mkmiPEsPw7vVr6/M1pe/rGNC1gf4l8dBcZr
         pSng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=dupevPsgQ6K9OrErTBAL8OzAxOef5zW1MPe7K1r4/NQ=;
        b=VXaXtE7JlEYshrVwvKWC3lyEG4EZiUnrvqjaql8Y0mTkQfgxllMyTbRwmJP/QQxFfs
         uEOTmKlKiZB8IbXqCXHC2wsKKDMtSWMMYP8oYA1XZzSDoBHayohwIn5jlewXsjejME5V
         Q/Y4gPNzdf1Q/uBGl/CPV2oi7lZAVH/raBCbn6tc87tHxFbCYJdxXZmiSXhD7aZtbFlA
         Y4+Oz/OeQh9LPKRLbWxeWGgRH2VBDwcGjtNg/hyX3ID3pmVABBgSaDlBb/hveRUXr5hP
         ISt8AQGq+dG5JiubmpNGWLL4Ro+we2CkDfD/MYBIm5O8rkkz4io9jZMgWrvAxqCs2f8Y
         FBrw==
X-Gm-Message-State: ACgBeo2Znqd8HHUbTo/ycuNTF8YJK4c58Ad0wYwcGDEyFJzwv5++TtPh
	joMYxz2f7SfMnrjsz8mX7j0=
X-Google-Smtp-Source: AA6agR6vC4e7wut6hr+JHtQxPx9G6+/VGw7f7KAj4i1FAE/DXE7dDbNigYD26sof9M6kobCaXnMHyw==
X-Received: by 2002:a17:907:75d2:b0:741:6a6f:eaaa with SMTP id jl18-20020a17090775d200b007416a6feaaamr26975405ejc.163.1662380781667;
        Mon, 05 Sep 2022 05:26:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:98f3:b0:73d:6af2:48f4 with SMTP id
 ke19-20020a17090798f300b0073d6af248f4ls3419576ejc.3.-pod-prod-gmail; Mon, 05
 Sep 2022 05:26:20 -0700 (PDT)
X-Received: by 2002:a17:907:2c74:b0:741:64cc:a4e2 with SMTP id ib20-20020a1709072c7400b0074164cca4e2mr27174322ejc.751.1662380780474;
        Mon, 05 Sep 2022 05:26:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380780; cv=none;
        d=google.com; s=arc-20160816;
        b=gsdXY+7iBFI/P//43pnVkBlLXQ09YQBPXsNaBXQdtm6EjZQPmLYjBgaffX8GCgEHxu
         PofBNuiTbaVCdUbNrXPUuM/Mb5Vs2+vW3xdafMiYmtkOJyhGhJgC4hhbti/9VOx7HkZX
         2EQEKyVnue+qpIHMb0mllqXPUJypzmKAfff/uRbCZWdVZ8jXYcsJawuBR9a2qqVWVq8m
         wYNJ5HLzqGfcZhBxWlh+dVSpiYB+afBXq/9S9TqwzWajI6cm+kiV/TVF0Lbu3OGaShOv
         ZCjPq/oeYhVz2hcTcU3P8y3qVpEjekw1Z/QXMQo0fzIq76vjeo35lIAVogPHLKQfuhVj
         khZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=TqyxH/L5MkAtosS0jWqWllGGzUIesiLdVg3wG3p7XtY=;
        b=XZUypWdoDBDvl0c9k4npvqBHSybzloDzS+AdRSuFZ3RNms+dFAe3mQPE4I3pEjvj/6
         vtfO4WmviC3Yu2hhGQqT+Rn5JOV553uOzyi+BCEKvmJTFmF+JcP2XPeW7/sM6/IL0nqj
         1lWIz4S95L3J5Yhm/zfXkVXfAsMtl1wTM8F15FjEjjnkBmxYiXTWrTN9YpjSk5BCxVfJ
         wXM+mM3aVGar5fAkzV4ccDf61e6WIHrSyjLDGSet7Uy3Rvl2ENCuPvCS+5sdI+J1yEAf
         W4beoYWde23bVe/e2HFYSUdO1G+rpleIAXVbpLV48MZJgyHsDcjQhVm6AzD3wTPNbI5I
         90bQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SRHbIOUb;
       spf=pass (google.com: domain of 37oovywykctkbgdyzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=37OoVYwYKCTkbgdYZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id og36-20020a1709071de400b007415240d93dsi373774ejc.2.2022.09.05.05.26.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37oovywykctkbgdyzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id d11-20020adfc08b000000b002207555c1f6so1224479wrf.7
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:20 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a5d:584b:0:b0:220:7624:5aae with SMTP id
 i11-20020a5d584b000000b0022076245aaemr24101908wrf.119.1662380780114; Mon, 05
 Sep 2022 05:26:20 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:38 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-31-glider@google.com>
Subject: [PATCH v6 30/44] kcov: kmsan: unpoison area->list in kcov_remote_area_put()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=SRHbIOUb;       spf=pass
 (google.com: domain of 37oovywykctkbgdyzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=37OoVYwYKCTkbgdYZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

KMSAN does not instrument kernel/kcov.c for performance reasons (with
CONFIG_KCOV=y virtually every place in the kernel invokes kcov
instrumentation). Therefore the tool may miss writes from kcov.c that
initialize memory.

When CONFIG_DEBUG_LIST is enabled, list pointers from kernel/kcov.c are
passed to instrumented helpers in lib/list_debug.c, resulting in false
positives.

To work around these reports, we unpoison the contents of area->list after
initializing it.

Signed-off-by: Alexander Potapenko <glider@google.com>
---

v4:
 -- change sizeof(type) to sizeof(*ptr)
 -- swap kcov: and kmsan: in the subject

Link: https://linux-review.googlesource.com/id/Ie17f2ee47a7af58f5cdf716d585ebf0769348a5a
---
 kernel/kcov.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index e19c84b02452e..e5cd09fd8a050 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -11,6 +11,7 @@
 #include <linux/fs.h>
 #include <linux/hashtable.h>
 #include <linux/init.h>
+#include <linux/kmsan-checks.h>
 #include <linux/mm.h>
 #include <linux/preempt.h>
 #include <linux/printk.h>
@@ -152,6 +153,12 @@ static void kcov_remote_area_put(struct kcov_remote_area *area,
 	INIT_LIST_HEAD(&area->list);
 	area->size = size;
 	list_add(&area->list, &kcov_remote_areas);
+	/*
+	 * KMSAN doesn't instrument this file, so it may not know area->list
+	 * is initialized. Unpoison it explicitly to avoid reports in
+	 * kcov_remote_area_get().
+	 */
+	kmsan_unpoison_memory(&area->list, sizeof(area->list));
 }
 
 static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-31-glider%40google.com.
