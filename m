Return-Path: <kasan-dev+bncBAABBXNVT2KQMGQE2I3NKMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id D1270549EAD
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:15:25 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id w8-20020adfde88000000b00213b7fa3a37sf873199wrl.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:15:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151325; cv=pass;
        d=google.com; s=arc-20160816;
        b=xwrKW7qkJGvsMfwHturAlbGbHJGtHe+rIyRY2rVxXzmwe8J57PstE6lAyxDeMMKe30
         QWimLISPXXp8MnQHoapuOPi9g/gwCcYYIdoBNmB/Ekyx1qtF3l7c7QDaZRLrC+Fpuk1T
         YGfrqpoap21VARsYn5KdxTQJ6Zc7sB0J+PEjhrkYuU/OX4QUANP9FUVisxC5LvLot3Vc
         djcki54lhCgdnCWMvJnDHZ5Qu+JgBa50ylSD9uARUjqt6J/zLBeHqDG989DpyheRVlXX
         HPgoBvnaTRhmw7e+4EczLf5GJtzk16SFMq8ZKVLmbqrB7m/5wZ4hlpb/ZTE3T6bZnVTW
         IUWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/WROneozrNYyCYGVivr6vuh4Z3zWCBemnppzXBV+H7c=;
        b=nUTqfBiiXTJ4NuSybPWfr04M1ELPwX03WaeOKc1JhU6N58Lyhzt34kyqQs7WkI5MHh
         xVcptA5I5czVKSchSv8+4Wms4Hio8bO1EatNkkD0KAaygTJXLm9dnrEoibFDB6KxkGMD
         5zE0fdyXfIDB97xisLZ+KNzBIY+zxR3QLUSD8jJPwerS+KNMmBWBtdAdXnsX9dl5H32T
         m/kwLZa4SFtsvvM4Z/LQHlobO/0+EAuJSBzAGdA6LYOpCmJ8LxRA7UzGyTw72iK+zIP2
         Nks7gJJPl1lDVCCEPL/8gtGkM1kuYXXN/YW0pmn5XPs0sSed96pi8TL5aCSq0RjqHi9t
         h5Ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=D7+1mF++;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/WROneozrNYyCYGVivr6vuh4Z3zWCBemnppzXBV+H7c=;
        b=VwLO1oy3d2/1C3DIiwpPrxYeZLG4qwKrpraHmMuHP8o/7VN5bjwyY3/6kexFHxGnWG
         9slPB61SFQPaqXp3A97Stb99NqcFER/I3PUTbB5ycqlmTkykWiKyme3wJ4be8z2IrYgO
         LRSZ5dv6sk9UIHePmm8I+3QxBl+4lFc14W99P+ALIga/a3c7XT0MOvGF8mTF1qPNpx6U
         Y9EeBCk7WX9TEEt7e90TFlKQ8fVlUGgZUGPAjQQf8J4gvR7GImbluEAxGAAEJWArhmtv
         GWvhgbGHGqUGjzQOPkMva3we87KngXCwRNGu59/SZOFzlK11vZNXjy85WhaQ9DZSOFvz
         giyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/WROneozrNYyCYGVivr6vuh4Z3zWCBemnppzXBV+H7c=;
        b=LPWGqmwg3IAYmavuTqtAzaEC9jNa995IjopqECNwJPUE5TuDrNjY29UfQqTUDcFZNp
         T+VuDj+U0leQma7YdhYSlmacgSktee73zxXbe2rnZU19azZlK365xn9GKX4N62Vg4o2w
         +pWHymgMLA+bPDpF8RBKSmjrbw+cmqrA/zWLPERdQPazoZ/nyA6kh6y52QCo2UaZFV//
         FdmbQ7jnMyMg/R1/AejpTg9aQF1IawdQyivDgxRoeRKz0Dl8GxnXatqpKieM/mVub5g0
         gdRC5FeJFuQYvcYgv9eDZe3D/GwFWf3bIVBpxI2tqZtN1AYkX/RM8Lzv6eTYnpyPiRou
         C1wA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+2j1pWijfZ+EwPkuquiK4QHG4FlfWC3pK4D3eQ8Cux2wg4M6LF
	8E7v6pSdlaNBsz4vBjiG3t8=
X-Google-Smtp-Source: AGRyM1vXvhRnnsz1rfuzcxrn0ygMUzalZYJ41BMtN4J4hbMLGw7i4vTqVc1/8LX5I/dNw6ObCW1LiQ==
X-Received: by 2002:adf:dd4c:0:b0:217:6a02:ea92 with SMTP id u12-20020adfdd4c000000b002176a02ea92mr1369882wrm.685.1655151325211;
        Mon, 13 Jun 2022 13:15:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:350f:b0:397:475d:b954 with SMTP id
 h15-20020a05600c350f00b00397475db954ls125880wmq.0.canary-gmail; Mon, 13 Jun
 2022 13:15:24 -0700 (PDT)
X-Received: by 2002:a05:600c:2105:b0:39c:381c:1e13 with SMTP id u5-20020a05600c210500b0039c381c1e13mr408342wml.189.1655151324483;
        Mon, 13 Jun 2022 13:15:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151324; cv=none;
        d=google.com; s=arc-20160816;
        b=Y/gk+uN1LP7Vj/mO+keG50h1U8JG+WXbjpsoIri3ahVDJcQ65UxDO+3RkZnAudGcvY
         OGQHybwJ+DuyyCQCbBa5VlyidZ7dx033zlL88S5jzUiaBlHJmqtuQD28smnDEkAzFbsf
         iQcPugo+4rGeN/S5328tQ8kj5DBPFoTfAGJylAtVCAJNxWc+OeiB7a+YorCTUNtPkNe2
         yz5poKznjmUwCm4TF9LpOkn4HeMr1SD7yaME2rPJe7s86D6Di3QOvLOpQZqPefkfZP29
         RMfpCmUH8CSG+PecaLAksZQdL0BLHVSVIYrgrxDaXjWMS6lNJKMi1z5lBeHhD+/sIZjL
         ATrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=M2+xlJvtrt/Ak+lac7lfuJjlG7HoHnjjsXRwZzO2wkQ=;
        b=NKtusaH5V9QhF9f9ZZnr1CxlT3iSxZR4DO0O7R7+znTWGHf8zDOE52O3NtoGhMO1ne
         kRN766VrJdjw4mL5FxWMPiOd6+4E94O/xOeYo1HVzj+wrAqSj/rNlIwmdnGD9ZqfrvBT
         uWuR0ydh/3iv1lS6KxGrbPR5QRL54K03oSwth5/BJcELKW+PeLdoAMQaVveeXsXuacpd
         TD013MO/M9oLjY/i5hwg3ZHslTaCq4b35JsVdGkF2csyoPP/7X199Hd4W2gnb9r6kBiK
         aMkk/eeYcjh1Kubk4cuZi9S8AVHrrXMO1lMlsdqsMKieMTGFD4z6KkyLmBaGGVc1dMhy
         EFpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=D7+1mF++;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id n7-20020adfe347000000b0020ee4f02214si241111wrj.1.2022.06.13.13.15.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:15:24 -0700 (PDT)
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
Subject: [PATCH 01/32] kasan: check KASAN_NO_FREE_META in __kasan_metadata_size
Date: Mon, 13 Jun 2022 22:13:52 +0200
Message-Id: <91406e5f2a1c0a1fddfc4e7f17df22fda852591c.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=D7+1mF++;       spf=pass
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

__kasan_metadata_size() calculates the size of the redzone for objects
in a slab cache.

When accounting for presence of kasan_free_meta in the redzone, this
function only compares free_meta_offset with 0. But free_meta_offset could
also be equal to KASAN_NO_FREE_META, which indicates that kasan_free_meta
is not present at all.

Add a comparison with KASAN_NO_FREE_META into __kasan_metadata_size().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

This is a minor fix that only affects slub_debug runs, so it is probably
not worth backporting.
---
 mm/kasan/common.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index c40c0e7b3b5f..968d2365d8c1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -223,8 +223,9 @@ size_t __kasan_metadata_size(struct kmem_cache *cache)
 		return 0;
 	return (cache->kasan_info.alloc_meta_offset ?
 		sizeof(struct kasan_alloc_meta) : 0) +
-		(cache->kasan_info.free_meta_offset ?
-		sizeof(struct kasan_free_meta) : 0);
+		((cache->kasan_info.free_meta_offset &&
+		  cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
+		 sizeof(struct kasan_free_meta) : 0);
 }
 
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/91406e5f2a1c0a1fddfc4e7f17df22fda852591c.1655150842.git.andreyknvl%40google.com.
