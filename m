Return-Path: <kasan-dev+bncBDX4HWEMTEBRBO4CRX6QKGQE2AGLWYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id B8F5E2A737F
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:03:07 +0100 (CET)
Received: by mail-ej1-x63e.google.com with SMTP id z25sf121312ejd.2
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:03:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534587; cv=pass;
        d=google.com; s=arc-20160816;
        b=DZqAJEqmLaaObKQiqc+IEHmqPQYk2olxzgBz6S4YMUoizjcpdCCm6e22rZ46W2n5Gi
         rO3BIHok6MLwY4mKupFHHhmY9aAFTZ5K+tn7V6BgqcsX6E2krCAnd1iuWpCBI4xn2Izq
         H6AfmiWiCp+wquBTwqyKk4PHU6rj98GgGMnXxLTxsOYQDgTYIOlzU9JZXM+KaKz2CV7q
         8E7aHsU4Xa9nCc+2J1XcrEJYsQTqxs+BhM7CYWhZXFlDY4bbp1W6CbM+sCrl1zAnO14r
         wIbl4wUr82a8zAUpJbu7qPKL2cSOTSSjX8DEdZmAzfwQUi3EHyroXDx4B5cJIkaNL/VQ
         ugOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=4dnZRXikiiJ8A5BqkoFZFsOAYoCJyDBEsehVp5+f9Iw=;
        b=GXXFF0lbekPn4winMVB6t0yjQRKzd2v9+JjEFr5vfAHm2qffybJkNy2T8oGWRDhkux
         CT4dmIu3WHtzGtOvB8kcsW4OtxJ4f5AlegsBctVmOOET7T+23dzd1BRYflGZRHzM44Cj
         oTwkKNXffuyw7mD/BvbwlgFe9WLPxwFoV/I2ohAG3D5cL0vdi4CcnXY88D9gBIvdRFYA
         sxTQcjHkLtbJn2I0B3uy9u56uD19vXc9ZEAQ/9ufzTRiYEflbOUxCqhYj7mGq/+HLafc
         A74tZIkxXmjWQVxtsoLBAXfUBCMee7eLIwxZpTjOuN+Hgm6h7yyUpcZoLdXxOUVQmK47
         ab5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U8jhak8M;
       spf=pass (google.com: domain of 3okgjxwokcu0p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3OkGjXwoKCU0p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4dnZRXikiiJ8A5BqkoFZFsOAYoCJyDBEsehVp5+f9Iw=;
        b=LrfSk8JMKebgkkdosw5VNgWDa0o0EHVsCbW9D2Gw3w6gc65vj9Pb3z0kQnbUR2hhSw
         XIGibyfQ834uVTRkLQsXaMPB9XhjGT9DggToMs1ylglbebkDP5ctT/gwmgzmpxpHBcoF
         iw1SsV3ZQlU3WDMx4CyxmuA2mx8igzZXBvyb3Jisi54JUvGKLPw6OWuHSEs/To4Th4VB
         f0gz/moCYUE+qioaKcDqYLiQ8zr3sDBOAkLKKQRqzhODM6muQWlc7yq2/mVc0plksjrH
         Harb+gZ4Nil8m+Cuzj8giC3iLf0/qVDSa2Bg4enNQH/ib2L46MriqChS2icQbfZb87Qm
         aV0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4dnZRXikiiJ8A5BqkoFZFsOAYoCJyDBEsehVp5+f9Iw=;
        b=lepJrTRIe9E8XLDYRVZNygfJGUhYw3iqTyE53UMH5rtS5q8Aus5kHhj3xZOPPrFUse
         z4pfHthewHxh7y/twE2lv7cKWHKDDqXqj+iwh02RtXg/VLPS+qyhqPxCqh8IEkOWP2Sl
         h0NJ6pkfVRe6w/6Q7dVfjVtS2QO2/5M1Tk3QXwcjBClAGogLDWx5qWK4YvzyTX5y9N5k
         C6RPmdXgrKhMkZA8qpR9eOfU9jMEKq2M7tcAhpQU4zwrxNlYHEpMPBRhSJYsEDphkvMe
         5ZMhNjPQiR+XG5QeOVccomjRyiBHYZXasr5dh4ncan5PkuxaUPoBDtI+dAXVATpMQ7SW
         UcaA==
X-Gm-Message-State: AOAM530nWOX9VsPCq8FH96W/PIrILnOHBZXL9u1X92qSN2wimni+pDzi
	6MHBFHowJwDhTxyG2m2nFFc=
X-Google-Smtp-Source: ABdhPJwD3MX3zFGvJRfd5oVcEzIoMR61DZRIyAjBAcQGL7vLHYMQXIauI3M1S87rJflPMHiCK9RMgA==
X-Received: by 2002:a17:906:9414:: with SMTP id q20mr564644ejx.384.1604534587483;
        Wed, 04 Nov 2020 16:03:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:417:: with SMTP id d23ls1820228eja.7.gmail; Wed, 04
 Nov 2020 16:03:06 -0800 (PST)
X-Received: by 2002:a17:907:420d:: with SMTP id oh21mr549489ejb.429.1604534586620;
        Wed, 04 Nov 2020 16:03:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534586; cv=none;
        d=google.com; s=arc-20160816;
        b=KzpI7Dxvk77jGaUv8Jb4OnQViO5D8wTiQlaAxxqAvmO4QSQ+PFq4vtKhH1n2od4tfa
         UzojbB3XEsNwi5wH1kCZe3i95OpSSzdX4CzmoKo5kH93R+T902sF5A7CFJM8QGUDptJJ
         8YTxzlzo6X9Q0wHzpOoiKFdLUmYNa8MZLxvCgDa91yUco7S9yxgEokb/Vslq+wDzzSpk
         W/b8nj7ubwpn8thNqIrDOUbrcYUWUS8flco/fwutdZLa+HVZtPPHVS9yizWRpHwoic9/
         nvyqTrot2AHBxdafNs9CuvXuL9dJkB23Ir+FaLPQCTdXKKumYYjhc3G+JC2EM3Cd2cE1
         zh5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=BMZ/M+WrZmZXK8ABsLpLLUMO5suYjkxoKy6+yIMHKNI=;
        b=kF++Gpduj5lzApNvsCiJGZETWL2pWL0SIO2Qkatc+whGByy6zZPMXjqOXHmITbhXlH
         6Iz0uoEqSnah5dwtHHdTvH0jx5k1nAcpNE/fHdyVDYOvLixpmzh7h975AmY4ROh4vG0i
         BaTfr4oUhbWbZFvIbKBjo0+2FjjBS8UXVjosU8SFESmhHCKbbXVXCxsGWqRo+phUUucA
         7Z2Xtu6F8a1Uq18t+lXobiyQxZjQ7euVmwYwRlIsR00dLjkNyQ4JxUZGH608rQSspBFB
         pCmD1LtGQVkIaFDY7/xaOxfanXm2JhPCk9yOrNvAD2D9KvwGOJZdx0tEe5j0aTjd/YQr
         wxEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U8jhak8M;
       spf=pass (google.com: domain of 3okgjxwokcu0p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3OkGjXwoKCU0p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id u13si68443edb.0.2020.11.04.16.03.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:03:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3okgjxwokcu0p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id bc27so42366edb.18
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:03:06 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:134e:: with SMTP id
 x14mr575217ejb.173.1604534586349; Wed, 04 Nov 2020 16:03:06 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:23 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <d21347b0bdbae6f0afe95b5015fcf9ea8aefb64c.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 13/20] kasan: simplify kasan_poison_kfree
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=U8jhak8M;       spf=pass
 (google.com: domain of 3okgjxwokcu0p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3OkGjXwoKCU0p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

kasan_poison_kfree() is currently only called for mempool allocations
that are backed by either kmem_cache_alloc() or kmalloc(). Therefore, the
page passed to kasan_poison_kfree() is always PageSlab() and there's no
need to do the check. Remove it.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/If31f88726745da8744c6bea96fb32584e6c2778c
---
 mm/kasan/common.c | 11 +----------
 1 file changed, 1 insertion(+), 10 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 385863eaec2c..819403548f2e 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -432,16 +432,7 @@ void __kasan_poison_kfree(void *ptr, unsigned long ip)
 	struct page *page;
 
 	page = virt_to_head_page(ptr);
-
-	if (unlikely(!PageSlab(page))) {
-		if (ptr != page_address(page)) {
-			kasan_report_invalid_free(ptr, ip);
-			return;
-		}
-		kasan_poison_memory(ptr, page_size(page), KASAN_FREE_PAGE);
-	} else {
-		____kasan_slab_free(page->slab_cache, ptr, ip, false);
-	}
+	____kasan_slab_free(page->slab_cache, ptr, ip, false);
 }
 
 void __kasan_kfree_large(void *ptr, unsigned long ip)
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d21347b0bdbae6f0afe95b5015fcf9ea8aefb64c.1604534322.git.andreyknvl%40google.com.
