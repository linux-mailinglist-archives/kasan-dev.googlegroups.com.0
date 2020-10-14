Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRGGTX6AKGQEZJA54WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D75628E7FA
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 22:44:53 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id i6sf244896wrx.11
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 13:44:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602708293; cv=pass;
        d=google.com; s=arc-20160816;
        b=swKCis5GNjahrwHm1vtuw7oyqr5eCK6/lpQanRn8RTM3Sg7d5AG1TB8GaAoh0iVLMF
         bn/XiBKua3t1Q2WzAt8+T+Hs+b3QhmeHdojQlds8ewnyIC5fbmIzdD6SPq8GwIUkY9nZ
         ycswD+vz1V2O0ov77mM/bEo1nE3jQ/iMwsTRZB6X52VmqYIpD8vZpIunjJ1zuuT+BOjo
         IC5tY2HY/Y2gsffy44/a1Bb7gX+0JLPLQSOpBUvf7kXRU9GKanamkLr9sYXoGuChzhCa
         hXPZSvTMKJuZ6olzRnqvOeQD5IXBxEWU5GAP7izcDgxC0mifj4MQSJopjtBtjBxfbItp
         3i3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=vDo1aMbgAfZeRF9F476kezctgOKRNy0skVlvtPZkIJ8=;
        b=sYUQuWcyjXhhh/i3zZrD7j35Z5A6kM024f8STkz+PuP/ygHOU8WFm/67u/7jeC8d6Z
         AwFj0kQWj4ap0SDSnkJZ9dWgL8i8eOMM9vhUQi5eGr0Lk4hI0kOUnH8rig8K1+N1ySH+
         xb0fRSmu/eBxhrKq+c3Rjxnnn8N/P8+G+lpSG6OzKZ4Q8ojD/XipaPZg+hHmgHHz5Pos
         kxXvo6WZyE8xkSZ/yHjIqR9aWErglXqD/pAo1fx0tI3B3I/8MapP9Zmg7vP84mCAMOAD
         02spxREyruPzOd5pFTdfP/nLELtVhqObXuVUPktFxSi1wvREL6d/Pa7HRjgoWwBXdRMR
         JEtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=muFweiHY;
       spf=pass (google.com: domain of 3q2ohxwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Q2OHXwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vDo1aMbgAfZeRF9F476kezctgOKRNy0skVlvtPZkIJ8=;
        b=hYhVF0MRX1o6LPD7Z8opQ1dI0Fw+B2NtnfT3qBkkgp3xNrZk60yxPyyyLHvj9FsB1K
         ywo920eP9mJc9AxjgbIkAl/K/kCBxm7J2NLtDgv6s1Ot7aHZF3vH6R8wyPIWrh016Tl7
         0z7+jG6eTvGOHHFhJjYTSYvvzNw4HBvEvRB7PgYuBvHmxRdmZ0gHznZ5JHqpuXGE7tVa
         cYB28KK0hWLTlPKWAD2pLXlPJWh4kfg2oelGIo3L9Y2YG/NzVONnFVgG1weRuCpy0BVH
         rEA7JHmP/0LEl1CR+wlz/gPba8gZ+jYJbrDAhA11WRoNxMzeA2R5WPllCuseg9iDv7QI
         8ekQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vDo1aMbgAfZeRF9F476kezctgOKRNy0skVlvtPZkIJ8=;
        b=Z0Hvc6diUL/C0KlgXCFZ9AV9Z/8uX7+oFxGPiAFv5bt8+XMtR/fukHeEQ+/H/ZyYi/
         7FGkf7gwqQJ58WGNnBR6veQSBPDWHYq7XeMc1m3ychYhmY/7zD2VF4v9JkGxzaRuTqjw
         maDQ1e3D0J5X+RPT3VQ0FfGujrCZJbPDlUeGmV/S+xk5OXxe0r9pZSwyZzMuX+RAw6p7
         WR4zeYSZAusEN8JXiD3jJdZiYDnEjzwzaJY20bnp1t5JhQEpLIhy0Q52KRuoaHDkblV9
         sMMZacBArlWb/3IjOtE9duf6tTUoivF5q90Jh8ztszKPeetp/u3X7BPnpdv2iorpZYfO
         JUUw==
X-Gm-Message-State: AOAM533zvrFOHdShHQXZEj6XULUchfSR+6N/guuCc7bXhZj619kdyNGO
	iiLVRUbG2MMxjJTj5Cu3uN4=
X-Google-Smtp-Source: ABdhPJx39rSDT+T/JVx2hwgpRj96GhEhuJzObyd7FhSrNK1UVLsQ90U0uKIcnrCZv08+nusXdXfqQA==
X-Received: by 2002:adf:f9cf:: with SMTP id w15mr569280wrr.185.1602708292961;
        Wed, 14 Oct 2020 13:44:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4a52:: with SMTP id v18ls764859wrs.2.gmail; Wed, 14 Oct
 2020 13:44:52 -0700 (PDT)
X-Received: by 2002:adf:e54b:: with SMTP id z11mr626211wrm.128.1602708292096;
        Wed, 14 Oct 2020 13:44:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602708292; cv=none;
        d=google.com; s=arc-20160816;
        b=U66CHlVlSn30o1TXS5FwPZjTUdblPw/nabyHA8p7KGfHMiyvGwjosIyMsHorioTg2Z
         JtVFuZCLl+u6Q5RXNYhFMNoUtKdZNfHnQ74NL08s1qs9BXa+QkzRmfYSZxZ1ujlnB7GU
         rPAL0tjNoTn60Uy9TrdQLPHKMcSG6kY01SlDHfSCi0Uh/yN2wl2c1iSQ43kvma2yuNUu
         oZcTrTiCiqekunKRTMLb+pHPrSRss00Wto6c/zkYcq11SGuwGRtbZpY6ZXs1SZ3RB7sn
         Sn5T1GUmpOXy9Rc+GzVQtQrG27jA/x4kMU0OgxWOOR4moqqEqP1S4MFKr6+iRLMaJUh4
         w73g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=7WKioc0F5nnoW2jvJmr0weBuEa6v4Kil5DUIEGSTVOk=;
        b=WJFH/96+maAk+MnMydp0qvunpNCMjtVc4T246XChA9HqT4LlM1r1DvR4UjEKHMJb9y
         XgcB9ropssbNbdVEymoQ/XtVEduTnqqCyli25m0k+1oMIde6LrlCL7Vp4MPY8USC6iiW
         rs5Czk2k1TkfabZi5uU2S+RxLz/rok5hsFsTWeKeRv+wsxI3YowAdDUolL2Gbdpaw7f6
         kBlE/hh0fFm/Y7ipTP2ei/hqOQ91aBL8Uigo4354CMJM83KSZFWSyLo6qBWlzlpUisAm
         j9OhKOk2BXo3l90m9S5z41BlnAJrp+45A6j/+LmFnLTHkF3sVXvNA5QIGuXGSOkdr0zU
         JOvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=muFweiHY;
       spf=pass (google.com: domain of 3q2ohxwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Q2OHXwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id f198si17044wme.2.2020.10.14.13.44.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 13:44:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3q2ohxwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 13so428431wmf.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 13:44:52 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:35c7:: with SMTP id
 c190mr568356wma.7.1602708291670; Wed, 14 Oct 2020 13:44:51 -0700 (PDT)
Date: Wed, 14 Oct 2020 22:44:31 +0200
In-Reply-To: <cover.1602708025.git.andreyknvl@google.com>
Message-Id: <407a7ff9d88cb484870507dbef6c5de833102556.1602708025.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH RFC 3/8] kasan: introduce set_alloc_info
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=muFweiHY;       spf=pass
 (google.com: domain of 3q2ohxwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Q2OHXwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
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

Add set_alloc_info() helper and move kasan_set_track() into it. This will
simplify the code for one of the upcoming changes.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I0316193cbb4ecc9b87b7c2eee0dd79f8ec908c1a
---
 mm/kasan/common.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8fd04415d8f4..a880e5a547ed 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -318,6 +318,11 @@ bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return __kasan_slab_free(cache, object, ip, true);
 }
 
+static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
+{
+	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
+}
+
 static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				size_t size, gfp_t flags, bool keep_tag)
 {
@@ -345,7 +350,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
-		kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
+		set_alloc_info(cache, (void *)object, flags);
 
 	return set_tag(object, tag);
 }
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/407a7ff9d88cb484870507dbef6c5de833102556.1602708025.git.andreyknvl%40google.com.
