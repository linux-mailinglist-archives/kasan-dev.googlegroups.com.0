Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVX6RSMQMGQEX4YQRFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 757345B9E25
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:59 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id c188-20020a1c35c5000000b003b2dee5fb58sf9726108wma.5
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254359; cv=pass;
        d=google.com; s=arc-20160816;
        b=EOwWtFHyS9cpFw4di7CF1TZJpB2NEzRK8UnqdVye6HU7il6cvD4+6CW/c1J5eyDMJc
         mjDlnmj+JvV9F2sYrXstZ5mLNqz1wuGsaYa/T75Rjby5LuWQyuHI3X/xfi7Nh86NuJGK
         ieORuWjM9N2SsTussPxxL/GRBeqgGS026TB8RCKvEEcf2kFvfyahZXJGUresf4Qb8zVL
         EYptMzxPQlEBWgjgkcc7LSTdExpjc7EfOUr+9F/tJ2MnsiBszGsjvikfjaCLX3RpYtS8
         7rn4J/wgBUMGZXhqeXefpbIxpQyXLQ7wpTKCAnfNu78bARlB7LvmOl8ATW7GFzwyr7o2
         vAKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=AYWBCvV2lfvrxZkX5kx2xw0KIT/Tgeo2eNGcTCKbQQo=;
        b=IVcPtkNOfvMetpFXjV7IFr0Kh4V4VnIcxcZsTB5YrcPWe83c9UZ2oO7uwQ+bJtQtxg
         JqvBGpoNvrpp24OhIuBxK7EHsBTthZjBwdhhRIYQ1+B+hoAXzs+r8gINSWuDWLdLpvtX
         mZUN+jpSG7953/HihUDyCfrgzmNN5IemCCvtnoh1PT77jExb3OfpJhNYnc1faqRnMXY3
         EsB9gzE+/nz3uf/uFN3F6TUPjvi/s2u6vclij8yN5q07DjR7c8A1Q4UjgofOdL2Q3k0h
         c6/UVtTD31YHvD7Qsch3Mj7+17C2LcRmbox84+vpdPY4xqXOWbMw8F3lVwGc/jtm9a/T
         tQEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LKBPWrq4;
       spf=pass (google.com: domain of 3vt8jywykcyakpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=3VT8jYwYKCYAkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=AYWBCvV2lfvrxZkX5kx2xw0KIT/Tgeo2eNGcTCKbQQo=;
        b=NdC/iqf98sl+xAZ9S2gi+wW2zUZpcaXwbf5I7nbOH8waZa1/+gD4JzyiBdkSX2lYzk
         voA71cshZG4tndOisB5TKNiVkNLff/SNEqX5ML2hNsgovHxC56NdRftMGSF2l68Mnjkh
         qFaUKt6D7X21fcYBUQmqp0p007mmCHE4Whq74WWK7lDTxzVq7eysow0swvZzgSz5ISTJ
         9jPIak8Sn3FyVEmuXTs9REGiKQpCpNAgX2QLhigDJR9ntUPlm23+K8UJ1sgaoPUbRBGE
         sbOZKJ4GIhfWajDXUKHSkh6rGs+wUrGBzq0q+ClqkPmh2dCznQybyE8YHp1SbGnXFquy
         k3oA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=AYWBCvV2lfvrxZkX5kx2xw0KIT/Tgeo2eNGcTCKbQQo=;
        b=eTwDUV65vIDs4JiQoBV2TB2FkC94sUoDzr6EZKgZvq1wGLNmTwLKKaAvITXqW6tKo4
         9jE3BAJLTaNR1Y1rtGx8Lb6WVAuD00iUdvuvhM+uJeKLdEksNT6NDfPsSsm6AY4E0B8s
         I64HQ8WMv9Sf0DMwFe35Y+iJXHXxPTg3Rem2ww4mHjtl2WRb683VWUrIoDqngJyTmC98
         vjh9QQrcXPQdjBWHdwPFVgFeKkebWIEzwg4qbMTG75TRIthC4GVyAP/7JXA3G+WQ2WTb
         6hnJQuSnASLh7XFe1jrFPoDS+7Me+ME8QQxD0Y8GQsOYtgkt6ZNZ4FQr6fCXMNLIFXPJ
         YJZQ==
X-Gm-Message-State: ACgBeo0gaRWBcrTxlN1+pJALAJusd6dS6cfET2poNA3dRhSKBdQCwO76
	5w1XhME7uHjhJq6m4XsXi9I=
X-Google-Smtp-Source: AA6agR7FYY0WJWmh2wH0L2vWD5Iad9ESFNNld8TEfXUHhG5pt4edob3xA0b3/bRvosiBFBn7KhzqqQ==
X-Received: by 2002:a05:600c:524b:b0:3b4:8c0c:f3b6 with SMTP id fc11-20020a05600c524b00b003b48c0cf3b6mr7346241wmb.50.1663254359156;
        Thu, 15 Sep 2022 08:05:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:256:b0:228:a25b:134a with SMTP id
 m22-20020a056000025600b00228a25b134als3204316wrz.0.-pod-prod-gmail; Thu, 15
 Sep 2022 08:05:57 -0700 (PDT)
X-Received: by 2002:adf:ed81:0:b0:226:a509:14b6 with SMTP id c1-20020adfed81000000b00226a50914b6mr83706wro.150.1663254357746;
        Thu, 15 Sep 2022 08:05:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254357; cv=none;
        d=google.com; s=arc-20160816;
        b=L0yOURq6QG53y2syOPg8ZGrSFCwMNWAoYmHb3WsovrkV+z/GxLy3PSkIzl6bUpoyp0
         ZVpufZzMTCNe9gIjfopLVYY8xAnlrkpj0jxhpaPPv3ZZOZxsS2iWiWF/6BPZKuJAPy/u
         cQktCujB7+alSGnU5Rr8Yu6Xl5Wx/ftha8UNIZVB9OlZFU/uoKrjvIpdv3fFyYanhF24
         Bc5ujNB6/59tAjmokeg5bZtl0HlD8uW2w8ghdR7YuWnXFnGDtl5u9jc1bM50T6RkeWv4
         ZNgmr6BAbN/hU9IfRm63fsAq06dH/v9iDUgfX1Fw4RlA8mM4El5iOg3FLFwZ3kqhE2U4
         1iEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=TqyxH/L5MkAtosS0jWqWllGGzUIesiLdVg3wG3p7XtY=;
        b=ErRI8kBSF4eptUKMc9vfJASXTaV+l6nGL1+ZuMG067uMvmXyqNMCgsiF29sjS/901S
         tAKGwsnOSEbcGAPiUvKlyFEOXAheJmL98PZMkZJqVGLntUDRHMYm+CYHumn/Go00C3YD
         8kU17pdHbzSXCSBfbuhD0z/nTLT+B0ft0u/ILb2j6TlgamxEOoQrd0uHaUXabTzhmKfU
         lK8VZiwannn+VKjDEXjwgvYBrEVe85k6T3imt/IhLXnYY7CjoH+kcuEtfbs+bqJthy2h
         Q2WX3lFf0MYuUWYfR+o+deamzq6d8EDQoDJM7JdkdvQvId3FuXpczj9jz/Rbd6mZt+j2
         frhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LKBPWrq4;
       spf=pass (google.com: domain of 3vt8jywykcyakpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=3VT8jYwYKCYAkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x14a.google.com (mail-lf1-x14a.google.com. [2a00:1450:4864:20::14a])
        by gmr-mx.google.com with ESMTPS id c2-20020a05600c0a4200b003a49e4e7e14si77735wmq.0.2022.09.15.08.05.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vt8jywykcyakpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) client-ip=2a00:1450:4864:20::14a;
Received: by mail-lf1-x14a.google.com with SMTP id x24-20020a0565123f9800b0049902986c6fso5159005lfa.3
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:57 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6512:3d2:b0:494:6546:dc1f with SMTP id
 w18-20020a05651203d200b004946546dc1fmr129949lfp.6.1663254357164; Thu, 15 Sep
 2022 08:05:57 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:03 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-30-glider@google.com>
Subject: [PATCH v7 29/43] kcov: kmsan: unpoison area->list in kcov_remote_area_put()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LKBPWrq4;       spf=pass
 (google.com: domain of 3vt8jywykcyakpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=3VT8jYwYKCYAkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-30-glider%40google.com.
