Return-Path: <kasan-dev+bncBCCMH5WKTMGRBKEH7SKQMGQEZNBVFGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id D4FC9563532
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:40 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id z17-20020a05640235d100b0043762b1e1e3sf1878297edc.21
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685480; cv=pass;
        d=google.com; s=arc-20160816;
        b=PFhM8/9Lz5mi7oYHgf0daajuoQ6m9JGlqQEfCFSY4i1qZtKh975abzEiplVEUQ6mou
         RKmpvai686AKESoAddPUtfhIGLE1p/Vyx8UVHmY+NpcXp07NO8kDqdSeGQcxreoChoQl
         iIUAwyew171nWZaZIxaRPlQicZ5KA+8hOO3WzrU2P9mF3BwCU6EbjHZJhizpBPY0Yu0w
         kYFramqbb/XOEP6MeqlHo2AjBnD2chQ/re3m++tWYj+1KI5SsFppDst0oZDPJADx8qjT
         Ros7InqCgs2wHdA906sfW8z1VuCrLLEoG55XiEfgKXdnTqjCfJHrKmfaZxL9ROd1zKDw
         3YdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=UBBdKtPmK18OcDnqVOMpS47ft4Ix6RxlG2K0ZSrD1Q8=;
        b=qn6ZcQ+YGWWPb2ysvVLXAL308EFy8tdHJDOKUab1VR+paKCNwUDVGUlFXtDb41h3tw
         ONw1V0H09XBoK7/q0WjjlnQ2mzyI3rJcew1qLopW62BaOG+tlCRNlXretFHuvddkeCjR
         KoRZVnUiNxk5RVgkDsa2WMtATIaJ9zpFUPYTZgq4X3WQCyUsal4x2J2n7UgVoebmLmjJ
         ELySk/1RSaq8uZd5jPjZZh2/Zl22GHt+P4rrpXhCE4Co2JkoMy+wBXDL2RW+6PI+Fuel
         dSfBsS6JtgOrCFKS7k84t/cfhuA6VCxWa90X3yENxlvf0imqtro7y6zcUsPCHa2X5Ad4
         bYzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ReMSGptb;
       spf=pass (google.com: domain of 3pwo_ygykccysxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3pwO_YgYKCcYsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UBBdKtPmK18OcDnqVOMpS47ft4Ix6RxlG2K0ZSrD1Q8=;
        b=Z0DgkLqYSiqKVcRy1b9EpsHWwU7cCzVtDwLHNpls/s9x7+TnxJeyp8C4/9rLaMSpHj
         g5f2j6KuGiGvRr/Wa75q9Bprx05DWfPzHEtaXo9yBF4iic58Ykemqa0H1aCNKw+u2W/l
         rLMMwdt1gtdtQoVCew70ZzHquZ0FDBsjSagqFDIUwZVitXdi1/sXqcDTTtCpKX+SdEXj
         5ziCAYTdLEal+cxXlNkydSQvwD9CTAMpif2i6N7Az03dljDjOp4sfD2sYiLR71Z4g/ah
         6Cf/vHp++xyKuptyi3KGU66rPoqaa02fggz5eQkFTj9wNCQpvYiO0n9v3RFpC71Ob6DS
         +SaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UBBdKtPmK18OcDnqVOMpS47ft4Ix6RxlG2K0ZSrD1Q8=;
        b=AjKWBrx3kClDiO7ZDE7PKiZtA7vstId0ERx3Bf1IkM/MMjTq8iYU48TQMj6j+PxgEM
         e31IQHk6wYE/JGaptrA5ooblHdHbatlvJb2I1YSVlbTF6xNOPbQGK8ESPXBZ2yS9MRj1
         d3mtUfwr4ulU5rKWETPyZsaVNfBEJMxusA6fcROJ2rusbJnCzJ55Wj7MTahEBUxXAoCL
         CqU1UMX22yNa0nieTAc4OEsBz55RoQjQ+3FxKkx2oggfIPBwUF8vGtMFfS3ehKnyPQUD
         j86hNIgZs1vEqU1mwHUKCtjYH0Lv4twiWXN65sW8TqB3EOGwFG0d0FqQ/rDKcfa3yjJZ
         9Bhw==
X-Gm-Message-State: AJIora+8iUvlS+j3Nv/WEnFI+Fa1Zd683OjALPrAmr1I5GpftJiS4jAn
	5cqEyriYCPc5xDrWkSfg/1k=
X-Google-Smtp-Source: AGRyM1tegl+LsWsWNWSxVhsjCLDfuQlVtwLwjdWhKcmwBY1eLl/9hxAj+GD1d8yPF17vynF1YWm1YA==
X-Received: by 2002:aa7:d38e:0:b0:435:6785:66d1 with SMTP id x14-20020aa7d38e000000b00435678566d1mr19159752edq.393.1656685480482;
        Fri, 01 Jul 2022 07:24:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:2ce1:b0:726:313a:5d6b with SMTP id
 hz1-20020a1709072ce100b00726313a5d6bls4450400ejc.4.gmail; Fri, 01 Jul 2022
 07:24:39 -0700 (PDT)
X-Received: by 2002:a17:907:7206:b0:726:abaf:16f5 with SMTP id dr6-20020a170907720600b00726abaf16f5mr14740618ejc.70.1656685479494;
        Fri, 01 Jul 2022 07:24:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685479; cv=none;
        d=google.com; s=arc-20160816;
        b=wxGjyongpwaPN+HxV+IaWocW7zReUwE9q8n+rwjzAGsyCSiDjsJxWxnpNXkJ/jWTXF
         Pg521zCSPlO+YgPcpthJwy4+eGAkS81LiMwJAtdxrqaf9N+jVqnxQ6cx0QbZIXGrUdQm
         J+uh9Oua7eqzw1z3JS4+SVLhqTMgjc9IDDCUOqVxtRuacNuOJWIo2nH4AxnMevrRag8l
         w9+i11sR159jvqroGle4D9zI+nbRxmior6SnBSjsA/ZUaptDGwM/tEdlr9vXz/gUX8E2
         xhoONrPLNTUHSihjGqXdUZnffxirdchE5DLqETJOhOln4ImOnu7sxcNnZlFoSCmbVWcl
         RDdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=5N9rqr7HITf8FFSE4yH2hCrYnonc5u0Mk2BxyWMh4Wc=;
        b=GokFa0JbvUa212krXY9Vjw1rYEQglZXZsWo55ftdv0ouGW7SlsKna549Os97suZI6E
         MUAdICw4rCgsu1u3/6U/hrL2XZaJmARgMpCHXFZtRrGz2FNm5yJFmlqSEltbT5F/I/DU
         3PCpb42B7OvNl6GAmwQRd+KCUrjxuf3miHQj2++5Nt+JXZqkr6xpUTpcRLiDNj5Ve2W3
         OCiq5FrOFrRUSvC0Oz3JHmH1LqHkdwYmvuvOVqRnvZmz/T9SY9fqW/LpEAZpbO3pFP5q
         +MBvZa3iJQw45ID1kbZwfwzci6E9GJtZ2t7gOBSoYcmwOMgk7SWZ7Xe8D3HKUvvaSr+6
         2s/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ReMSGptb;
       spf=pass (google.com: domain of 3pwo_ygykccysxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3pwO_YgYKCcYsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id q31-20020a056402249f00b0043780485814si737189eda.2.2022.07.01.07.24.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pwo_ygykccysxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id hs18-20020a1709073e9200b0072a3e7eb0beso843873ejc.10
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:39 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a17:906:8501:b0:711:bf65:2a47 with SMTP id
 i1-20020a170906850100b00711bf652a47mr14797955ejx.150.1656685479201; Fri, 01
 Jul 2022 07:24:39 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:55 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-31-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 30/45] kcov: kmsan: unpoison area->list in kcov_remote_area_put()
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
 header.i=@google.com header.s=20210112 header.b=ReMSGptb;       spf=pass
 (google.com: domain of 3pwo_ygykccysxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3pwO_YgYKCcYsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-31-glider%40google.com.
