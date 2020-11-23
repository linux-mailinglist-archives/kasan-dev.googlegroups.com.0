Return-Path: <kasan-dev+bncBDX4HWEMTEBRBX5Q6D6QKGQE3I3NQ2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 45BD52C1577
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:28 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id a130sf320546wmf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162528; cv=pass;
        d=google.com; s=arc-20160816;
        b=ngPxOkI5iG0XLX5sBrcqbi8rPv7jx8+Ns5PSbTuHLS+Q8VBdG7U+iEYoUmBJrv+jfp
         g1o0Igd3jTsfeaBicO/wpg4QNbxQG8m9ljd4fJgEO+7ral2mw1w+GpMJfmbgp59V2PSe
         Hm0TWDhcUji8O2RlTUV8zgJb29bTXNxHkiiTlGx2aqGRvaPNGF24/LhvtOA3JFHRJPgV
         LbhZkmoJgN25ckM8ctUIun9jrE4AG6V1uJPWjhEGAuswYp60IGu7W50NLwi9xWg+/ns8
         sxvbrk1vAELRJiOvemEfJ4cfrHvglkzlKMLpZ9dG7OGxyMIC7xt3kJ2b3X1/Ue7N+K5H
         SGEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=wPCOzgiNeQ3/a4GX0PHgSeZex43ZUhdr5l7MdlAlgBI=;
        b=gVyTbV5st0m4FEuEwmQFWwCHWdbJobTsIFQbnQ8bHssLKhbyDHHmKDsbgxV2p4a5cf
         vOgNRIEP9ANvFiwwIzZXEDShdQyHuTsKoKBC0oqq93Nt/UHdc2FQQRSdZoSYMYZJfcik
         w5iqrTp4lXdzT6l9QavpbZdmFbTIUXBSJQayAJc5Ca8TuYLQCqPXXTAq0DPqtQxeImEA
         7W9sELzo1zhBXY+y4V2h30yisSisKl6MC+bcMihJtoNL8yqLiIsb7WsA5914Dyk2uYBw
         pmoUfFG3kQHsVoMRp9wmlFWhqbYBPdY7bV3FWB64PBjPky8VhF9KCPONbAnOTlNZQ6y8
         GM6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K9aATwYZ;
       spf=pass (google.com: domain of 3xhi8xwokcymhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Xhi8XwoKCYMhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wPCOzgiNeQ3/a4GX0PHgSeZex43ZUhdr5l7MdlAlgBI=;
        b=jf09AlqdoUoz4pZWUwydKPVJHM0h7dY7KdLgEX7TNr5UV2UyemrYgqDD6Snbb02e2e
         po00/kAFUfhhGAy2NJXsCQjve+2VgJi6noaG9F2y2DaZPNWhwas8CBTyU6Bu6Uzk+3dT
         dzTZ489xeLdhvn0z7zSvcdmU2MMEHKimngpZHnEyCNg8sXQLIArGFM1fwNttHQSYQNHi
         QxLeZxU0K7uK3eJheURhl+aKDmTeVf8IyjjS4wRG/8MR6cKcN5jFgatGCFJy8+EX/cYy
         RT1j0IKN0fSGtW2j+XfxABt3OTyufnQaZxlPf9hWo0cubyuZauBxjV8o6vEbxiq8zP+s
         gJMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wPCOzgiNeQ3/a4GX0PHgSeZex43ZUhdr5l7MdlAlgBI=;
        b=lEAlAQWoiYsyu09kw+Ut5HKzW48RZmo2kDkJiItrYe8w9L3ABUmu3oklJxOevotzmF
         AOJswQtMRSPX2fTQffG97CHpDj2G++3udu9+8etzhx3icv29/ho/xSbwUFH0IBTcmW9G
         Pn2lscUKbInwxc000GKbHul+BjUZ4xdDfgtCMO9FTvdhbsumJHldnxX2mITa8JTtsqKo
         iLrI0VT+JIiEBjf+T4shPIIwK26XeSKWTiZ2MIA4ozdUa/OKys6W4i8Fssiv5ENo96+q
         pNexEltxVI6/047OW6ouI5JXDYwrquXn1GELU4XLur7jUmHWl/XIPs55ifaf2g28bnyB
         d1Bg==
X-Gm-Message-State: AOAM530D4ZRSjlWhwcjns3eBpZEyOPeSk7RcwJJ1+H0agJR5EbGTaAwV
	HDYLdoKNSVMCxikkCiXqirc=
X-Google-Smtp-Source: ABdhPJzO20JpQohwk2T4AHtrtWBKQwBlCkUes/Jihgmk6HLNeH8dcBmdCbWevy74+7LktAvg0DiVMQ==
X-Received: by 2002:a5d:5689:: with SMTP id f9mr1389305wrv.181.1606162528025;
        Mon, 23 Nov 2020 12:15:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a4c2:: with SMTP id n185ls168784wme.2.canary-gmail; Mon,
 23 Nov 2020 12:15:27 -0800 (PST)
X-Received: by 2002:a7b:c841:: with SMTP id c1mr612327wml.31.1606162527140;
        Mon, 23 Nov 2020 12:15:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162527; cv=none;
        d=google.com; s=arc-20160816;
        b=SaSdblTxEhKtSyj1vMEyLkLaWYOFMOesN/1JQ/5mySBSa0w1vUeiIUoko1slwXf6+f
         qiKF99DHOEYBe7M8RKVeWTBO2QogzAb0843+4VUeJofQCdgC5p7uYxiIbdBz184jJBz4
         VoCA1lynZBiUMxF0rwaQhS20Lxqsoy6AOUGFnyzSQY3QCrhzLixnfpvW7BErFPYedYoW
         xVwxJQ8vu+lCBTeO6RAA8Uo+nxqBCGOT1kryAt3t3dukmn6MrSMoh4inuO0mEg2KcNhI
         4chrn4uvlWxDgvmzpq9cimxv2nYe1SdMgRfIwHRUXX4zfrNoPJ+LF/+Y5izH1ufnZyEJ
         7zYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=FZtWTAUkAvRQTA+AtFREJR6Qo+0tQ7KPae8j2grwXDU=;
        b=y70Rlh01rUoK8Ja1SE4LOrv2SgduydFGpOcjYiWiSJY++U3Uj4CfakTFT1nyfzBtd2
         W7203G/clS4GE86F4D/P7/AOKspXIAnDsCR3xMenoVbL46MV0f1AUaYdOlGY9ml30Amo
         g68TC9h+DQGAeRxWZvwB7At7L1dtE+iNsu2F8tgOTZdx8RpkPLh0f1BhPhE1ur0xucvL
         BM3HSKMJitmMVsBe20fPkGBQUmHJbsoT/msZVg8gzIMHJw7rRv0ox47pKg8Aa2DPJIl4
         7MFb5Nu6EXtVbP2kdkV6b3oyI41fK3OUHEIr6O/BWw+qZlZCj2PiwWENrqbJjNphVjC2
         5zAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K9aATwYZ;
       spf=pass (google.com: domain of 3xhi8xwokcymhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Xhi8XwoKCYMhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id j199si21058wmj.0.2020.11.23.12.15.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xhi8xwokcymhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id w17so6185911wrp.11
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:27 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:ed02:: with SMTP id
 a2mr1480549wro.81.1606162526631; Mon, 23 Nov 2020 12:15:26 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:44 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <47b232474f1f89dc072aeda0fa58daa6efade377.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 14/19] kasan: don't round_up too much
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=K9aATwYZ;       spf=pass
 (google.com: domain of 3xhi8xwokcymhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Xhi8XwoKCYMhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
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

For hardware tag-based mode kasan_poison_memory() already rounds up the
size. Do the same for software modes and remove round_up() from the common
code.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/Ib397128fac6eba874008662b4964d65352db4aa4
---
 mm/kasan/common.c | 8 ++------
 mm/kasan/shadow.c | 1 +
 2 files changed, 3 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 1205faac90bd..1a88e4005181 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -214,9 +214,7 @@ void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 
 void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
-	poison_range(object,
-			round_up(cache->object_size, KASAN_GRANULE_SIZE),
-			KASAN_KMALLOC_REDZONE);
+	poison_range(object, cache->object_size, KASAN_KMALLOC_REDZONE);
 }
 
 /*
@@ -289,7 +287,6 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 {
 	u8 tag;
 	void *tagged_object;
-	unsigned long rounded_up_size;
 
 	tag = get_tag(object);
 	tagged_object = object;
@@ -313,8 +310,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 		return true;
 	}
 
-	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
-	poison_range(object, rounded_up_size, KASAN_KMALLOC_FREE);
+	poison_range(object, cache->object_size, KASAN_KMALLOC_FREE);
 
 	if (!kasan_stack_collection_enabled())
 		return false;
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 37153bd1c126..e9efe88f7679 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -83,6 +83,7 @@ void poison_range(const void *address, size_t size, u8 value)
 	 * addresses to this function.
 	 */
 	address = kasan_reset_tag(address);
+	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	/* Skip KFENCE memory if called explicitly outside of sl*b. */
 	if (is_kfence_address(address))
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/47b232474f1f89dc072aeda0fa58daa6efade377.1606162397.git.andreyknvl%40google.com.
