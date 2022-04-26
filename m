Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPODUCJQMGQEPJAP74A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 79621510404
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:50 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id w25-20020a05651234d900b0044023ac3f64sf7887130lfr.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991550; cv=pass;
        d=google.com; s=arc-20160816;
        b=cjyv0m5OfuY2+0WgXbvaF1HpkwFR/oMBE9iGLmcE3Dlry/zRKr8mWGFi6ESGy/dm5X
         rnQusutHBZ0RmtjewRbdLCoMBxQdBaykGeNmtBpY4YhcBYBo7DOLVcV9dWeT+LPx/JXY
         1ysx+q4Qpo0ZBMUTgnfIb1OUpJB+mnbuyyD4uP3MGIFnMvRXNOAODQpcaN9N7liAvXEH
         vRRkJ+izkEC0pcGQAzgu+/y0Dgy3tKUjd53p5bIgT67Od4mIGnwLDl6AbQyIczmN0lIj
         dA1CZHbjfO1P6BBWb4XCBTL9Z7POAoaRYwEfkIym7R//tDDw48rHmcXpq1mVB/9xMAqE
         Enmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=6IC1DXLO+8F8Tgi6/+rxk45GVkJPJJLws6t+60peZPA=;
        b=uCVZ/E7yW+mHY7j/MYjTF9tGPkCx7g4xrWRJAxUBakAGi3bGsc3dW7FUND2SA848zE
         ZlPOaNkByzEHw/T74EIb5Pm12JmTRKXjLpAx3CQMG5SZDK6esMlEUmT9ivTvUflGty1L
         c2YY64AJb2T/y/Y/bPHUcJBG2//x1kw2NdZH9qf+n4Ece3VibZ/hB433yCBip+DkNABS
         rkUGf0AatIKHW4Oy4RO20Tyuku6KZQG6OXnpwl5iMnxDPRgB9IMTyYqTmK4izkAfnjzL
         k071cWF4sdlCtJLhk5gIKdr5mKLpEyhqKk0hXfUbshNXS1lB+tWl9lkKTxIHUvxdnpEp
         5qiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ras6zX6z;
       spf=pass (google.com: domain of 3vcfoygykcbkfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3vCFoYgYKCbkfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6IC1DXLO+8F8Tgi6/+rxk45GVkJPJJLws6t+60peZPA=;
        b=runHNvJyMKXzHqSPnR7uub/+2zt9PN6KDVeS0Z3H/9iWgAJO/1Db3D14GZqzBlwAh1
         0HFs49oNwAuuh+C3axqB5QchaYsitFaw0SOxSnhAKSzuPAkIDButoo2353JdL5R2ehrv
         a3+KsNnR+3mP39ZJ8opOoKWJWmKTfrOIS9XFP0RTDYoOyEcy1NjjdXEk/LousdhaL9fi
         gFpiOSTq5zx2wTjYaK2t5JAIPuigf7SKTFtSuVAMnn3vB1hLRownLouER/NNGQgmFUqF
         g6+UsZ3kYhQyfChSD1OHyiNWN2hT5mt1oBYe7wzntIF4B4lyMueiAVzgh8N1HuJOBxYb
         5cTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6IC1DXLO+8F8Tgi6/+rxk45GVkJPJJLws6t+60peZPA=;
        b=VksHzKbbejA7OEtR5Sz8gEZeBBlpgaftDDhEY0pKWJ/lsbpXEwD2G/aajtWmFyPrU2
         RrRzFzPecEBF1cn/FhbuzTWSkFCPOA8PIMAJYQzmmRNv7nA15lkVKXOynd++sJl4DGw2
         kPXunFCCcztPL8UvrJsvPSVoKDZWaHMLvSKNu/YqMCLY5KlOmOO6nUL8hfbPXMYnyh+l
         ZvyKpNvbj6naemSD2lhgz0IAwCd+Se28bo8sA5829tqVzXhAI3tAtFIj8dmkdqAmLjLa
         T9ltAJIbaXKUDO6bCqe9LtzWY3fvh65ZLuXkzzVKoJMdxIWKl5o4OtnTRKWVJ9RznX2o
         QUoA==
X-Gm-Message-State: AOAM53337I7IVboiqf7NBvZd2JO2eat9X1Y3lb/ldD49I43IM59hBKPB
	FzRhPFTRcAaOu7hDpJdCY+4=
X-Google-Smtp-Source: ABdhPJyzEQkRmmevluquiH5ymjC5bQKQ+5KnUtEkKKS0Tuh8dQw5/CptvdRf48TJ2hgO6J0hGrY5DQ==
X-Received: by 2002:a2e:81d1:0:b0:24f:728:a16c with SMTP id s17-20020a2e81d1000000b0024f0728a16cmr10524347ljg.333.1650991550082;
        Tue, 26 Apr 2022 09:45:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e2a:b0:471:af61:f198 with SMTP id
 i42-20020a0565123e2a00b00471af61f198ls2094564lfv.0.gmail; Tue, 26 Apr 2022
 09:45:49 -0700 (PDT)
X-Received: by 2002:a05:6512:2601:b0:464:f8ca:979a with SMTP id bt1-20020a056512260100b00464f8ca979amr17779059lfb.84.1650991549117;
        Tue, 26 Apr 2022 09:45:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991549; cv=none;
        d=google.com; s=arc-20160816;
        b=H5NUP7oVuUsUfiDLxWTH6DGJ7bHuZptMRluxkOP5nj3SzNzIGxNFd+B0zNgrqEq1OX
         lka6LOGlfntVlKIv2lVTio2crJDsotT/1P84acAz7+5VQe0EXD6Xnsh2u+eHDTR9Jak2
         kfFI0aUHPTyKC7ga5sv02sovw2ePQDRS1WvvDycf6PTmBIFFqOlyfFpxyLgy6jg4w31t
         1nsYn+Dl2h7H+yuYxFZayNBpbZ83/05Kultw5lQmk5tEohs8RO+aqob4RFLL+YQ8YUA7
         YZEXAfWJ3KhoUrBrYuaCDEPcld6mWrHjl0mcQQ/dw2nDhzq1QfCg3z3h8dqTC5A6W25P
         4LQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=KHDnEJZlYbtguNecmw4Z0aoQP18cjcWXna880BlF2jg=;
        b=wBq7b6WjUl8UKN7pJvORvEErX0OUKyjdmdqQsNOGOrFn3eV4JWDAC37fzxTTK5nqvu
         yf2x0scqIcqUlXf/ykuLal5dC+Az8x/c8hpCQ70+rs7wDHwzS5sZ9wx0xTtNy6XpSsrA
         N6nd9NGnRytOZUgBWyqncD/Nae6FkPYjCvdMD0EKSaCGu8koA2jYVD8BslsB4boak6Oe
         DTPquRO1fFRwWvTRDGN2HHeH000eoogOv3VAW8TE6QYZbMQLgUJdL0mA+WfApZWaeY5c
         1PFuDPkxiH6bE4PbILnROyWK/TZcLPx0NRiWp1O1QHXrL/n52xWVZT7v+g2pIuq6Zisf
         aGAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ras6zX6z;
       spf=pass (google.com: domain of 3vcfoygykcbkfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3vCFoYgYKCbkfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id h20-20020a2e3a14000000b0024f1cf9b1b0si103026lja.4.2022.04.26.09.45.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vcfoygykcbkfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id v29-20020adfa1dd000000b0020ad932b7c0so2068043wrv.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:49 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:adf:e289:0:b0:1e3:14ad:75fe with SMTP id
 v9-20020adfe289000000b001e314ad75femr18987161wri.685.1650991548482; Tue, 26
 Apr 2022 09:45:48 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:03 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-35-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 34/46] kmsan: kcov: unpoison area->list in kcov_remote_area_put()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ras6zX6z;       spf=pass
 (google.com: domain of 3vcfoygykcbkfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3vCFoYgYKCbkfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
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
Link: https://linux-review.googlesource.com/id/Ie17f2ee47a7af58f5cdf716d585ebf0769348a5a
---
 kernel/kcov.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index b3732b2105930..9e38209a7e0a9 100644
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
+	kmsan_unpoison_memory(&area->list, sizeof(struct list_head));
 }
 
 static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-35-glider%40google.com.
