Return-Path: <kasan-dev+bncBD4L7DEGYINBB7N7RODQMGQECQEVACQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 16BE83BBB4B
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 12:33:35 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id y17-20020ad445b10000b029027389e9530fsf10006894qvu.4
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 03:33:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625481214; cv=pass;
        d=google.com; s=arc-20160816;
        b=x0MzfT+4gBpAYRX+2yBmt2iJ+53pVjlPs2baVAlZETjaQT7jzp8kFkixELxd3BC+jm
         Qxltpo0JnC1rYURWznbCJDaQ3VXmCrJjnVTLbts2hIyzTOFZwJt4ICL/azhrEDduP0F7
         mfmmAeOXdV59g3z2yasxk1oCW72dBO8vnHrhvc9sV7hAoLG7RpKA1SFX/Kz29b/Zbnrn
         K/Cq3APrc5fLsX4pTyFjO5X2lOhAATHUqEHb03SpatrwNSK34a9AydRrjreRbhiAxqLN
         K3SkOHI1Vbafz0lBVB8DKscks0kcSRRHEjB8ieGLTHKaGSGjv1Knn71GuDevDnmd4cPO
         1ZDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TEuTe3QiUSP4f8ekkFyqd4/MJsYicp6B23KlQUwaDiQ=;
        b=NVaO3tH0tIVNRRctisyCZj7qyqiMDlkvJJRK1/ZYXW+B+I7bY4tYrdo5jWEUS9+Ge9
         ewlEAWAfzpq2POvzk4FQ/0Rdm0UTmJoU+H2wIg8EWysTfTPYOOu+/gYkxZixLiFIw4DL
         tdD8ZJLXJ/rq8nejZqBoqnp9PjQFzmVBD+f3SjaloMocXaDA/pdY2sUgdhjVjPpLoyGY
         5+z7X3xJGt5/OD8W0VymaNanJmKt1acKdANBW7RaR+S3+Ev608XOnF7c5A5yBWm3B67b
         TOohA9OT0dcd2rTtlaO2D1Zlv2zCwvaBHjVUECykE5IXYj2UKtYQdOlFQ3dRYi8besqM
         I8kQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TEuTe3QiUSP4f8ekkFyqd4/MJsYicp6B23KlQUwaDiQ=;
        b=nOOoR8PJc3y8S42Vp0ha6U19KquX9nD+tWB/jiVjUNJz+d6UUx7kpWAqbpOKHtiJzy
         Zp8Ukc11uiOPARtWet67nWu4VDJJYskaVKjKi4LsbkjFvNN99Xz5E0emLbptyb1CNvBP
         OnQuE8AxYKz1+g0MreaFF05eGkp70MI2rdhnHy+ooDbIsGk/4/HUplk39BK0bNn5ktkp
         jX9MWmJpiW5TZJ5nCK/R80pM1prTsCMKoN5eojJNaODYYsNQ0dZbuXvyeRzwc3UQPiDc
         t9U6E81AXX2gkVZ92oBzHUuf4cQtGbO3XxeVuGMLWHRueBOer3DUcAsLEbWs4df2gFFn
         hldg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TEuTe3QiUSP4f8ekkFyqd4/MJsYicp6B23KlQUwaDiQ=;
        b=fsSzrf/5pQXTaiB7BJzPrq1JPXHvF0AnEECa0Ca6ERzxZDfRmsKHCk2C6JtjdzHQnZ
         ObV4mC6A/3276mzbTAjkZB0icejkJ78k3J0lVGEZsJ2iRhzfA3ev/h5wB86j7XQBBFnh
         8kvgvp3szJ212gVW0JZEOV3NpPMCU39f0FUSCemJL2IXHR6OqPjiHlE02dCj5j0n/8a0
         AhNAKPeNjPxdNSYDSRRuvmjd/bSNAf0HW84KiG30f4gTtthuD/AY5lnZe0MYJvmIyd4j
         BOgI3yrBMA7GQ1DRd0W/dSvRQF4Hv6SrKxuNxXYW9vTnxQP3J4NUsjaZLMBjqRAN1dDp
         nLsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531y/olpofoaUpoGvTzhA2DZ406kBBT2S3Tcysz4URde8JBDJsLM
	HWrwYbRvyzh+KGfsDaEhP2U=
X-Google-Smtp-Source: ABdhPJxYIfqYuYottAYZVdmYstbcsw6Vg875KtaioPzwdI+W0TFZBvrMHrCbzaPfeyV5FlFsbY92AQ==
X-Received: by 2002:a05:620a:e14:: with SMTP id y20mr13153776qkm.335.1625481213910;
        Mon, 05 Jul 2021 03:33:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ea15:: with SMTP id f21ls10780393qkg.7.gmail; Mon, 05
 Jul 2021 03:33:33 -0700 (PDT)
X-Received: by 2002:a05:620a:147:: with SMTP id e7mr1495128qkn.144.1625481213520;
        Mon, 05 Jul 2021 03:33:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625481213; cv=none;
        d=google.com; s=arc-20160816;
        b=1HOgytlFfXvvv5TfiaUCZ5NHQ4lBlOBS4rdvEnWK65V1aWxPJgFBmASzex0cyHkpwe
         cwJgGZkZ5QSKlDzHRHgvaiiP/d55gncxfIRaStnBte7HIp8Mmgu4n95zaqOK2AR+Tujh
         x23pbcrUWtdH0XaAQtL6PTvsDdZt/T6WRQC2iYcvRQCAy58ynPAt2ykjpu5ku4wdZnm3
         WOgDMywKtsZMP/Rb/qJnqWxCahb0hWo3zjS5Fc4pymLSinrTx0reiPFF+v0ec0b9/k4o
         mzI7A4P0IKUgAMIuvjM1qQgiX834doAUt64pItQSR6lY0/49YKI4HJhziwn/ncsGdLDr
         hAVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=ayLPuPlTrAdgUpdGkSUQJ+xvmZ5NcrxOu2vb6vL7I9Q=;
        b=DIftdKpDKixgRZ+STfgq4K832zgUr3CwXpX+ZvjcRV8g/jTeciMY5i14l84mZpXivM
         1lKIJUfj/gcA/JqYeYj/9IfCIgutWu6IVoF0XVtp7058Bmd85yCIOUKe8ZAfHoNJhNw7
         xg7HUOsmLZgvLzCNj+KyARL1fbLYYmUN5FfUOOw45VdxiHTbQBPNuW/g4p1Y2qXtvbl0
         3wgSXaIthKvFNxWijNv0q4SZGTt3ivbkVB1r6hR8AmPimn82j4fRwOXh0KRopZNLKtvj
         fnU3Qx47ygTvHyJa4aXLjzqNyYad9oblRrPQ3o1DeZkqVRstRDdN0WEHffgKRHvtbruk
         +2/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id m6si1396334qkg.2.2021.07.05.03.33.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Jul 2021 03:33:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 9608859d40f24c88ad40d555c4f80150-20210705
X-UUID: 9608859d40f24c88ad40d555c4f80150-20210705
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 742014454; Mon, 05 Jul 2021 18:33:27 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 5 Jul 2021 18:33:26 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 5 Jul 2021 18:33:25 +0800
From: <yee.lee@mediatek.com>
To: <linux-kernel@vger.kernel.org>
CC: <nicholas.Tang@mediatek.com>, <Kuan-Ying.lee@mediatek.com>,
	<chinwen.chang@mediatek.com>, Yee Lee <yee.lee@mediatek.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, "open list:KASAN" <kasan-dev@googlegroups.com>,
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, "moderated
 list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>,
	"moderated list:ARM/Mediatek SoC support"
	<linux-mediatek@lists.infradead.org>
Subject: [PATCH v6 2/2] kasan: Add memzero int for unaligned size at DEBUG
Date: Mon, 5 Jul 2021 18:32:27 +0800
Message-ID: <20210705103229.8505-3-yee.lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210705103229.8505-1-yee.lee@mediatek.com>
References: <20210705103229.8505-1-yee.lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as
 permitted sender) smtp.mailfrom=yee.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

From: Yee Lee <yee.lee@mediatek.com>

Issue: when SLUB debug is on, hwtag kasan_unpoison() would overwrite
the redzone of object with unaligned size.

An additional memzero_explicit() path is added to replacing init by
hwtag instruction for those unaligned size at SLUB debug mode.

The penalty is acceptable since they are only enabled in debug mode,
not production builds. A block of comment is added for explanation.

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Suggested-by: Marco Elver <elver@google.com>
Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Yee Lee <yee.lee@mediatek.com>
---
 mm/kasan/kasan.h | 12 ++++++++++++
 1 file changed, 12 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 98e3059bfea4..d739cdd1621a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -9,6 +9,7 @@
 #ifdef CONFIG_KASAN_HW_TAGS
 
 #include <linux/static_key.h>
+#include "../slab.h"
 
 DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 extern bool kasan_flag_async __ro_after_init;
@@ -387,6 +388,17 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
+	/*
+	 * Explicitly initialize the memory with the precise object size to
+	 * avoid overwriting the SLAB redzone. This disables initialization in
+	 * the arch code and may thus lead to performance penalty. The penalty
+	 * is accepted since SLAB redzones aren't enabled in production builds.
+	 */
+	if (__slub_debug_enabled() &&
+	    init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
+		init = false;
+		memzero_explicit((void *)addr, size);
+	}
 	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	hw_set_mem_tag_range((void *)addr, size, tag, init);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210705103229.8505-3-yee.lee%40mediatek.com.
