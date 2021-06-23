Return-Path: <kasan-dev+bncBD4L7DEGYINBBMPRZSDAMGQECAC6CSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id E01263B1B3E
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 15:35:46 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id o11-20020a62f90b0000b02902db3045f898sf1744419pfh.23
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 06:35:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624455345; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qo7zWBy/wEjKeuZs5Eol2C5wX8jUIn0E1zA5egS3Ss2qCCty2NCpI1lSlEDrGxP2K0
         2mhmlAQF4B+A8J/Pp7ZXUGucByCySrohgIns/TFQAYct/dfx+EUr4IqJO3/LIyydez9/
         E2hD94ef5zXZRXB4XNK7YPaHCNcQKrXFNLDsnOZE1FYF0xo9pOszVsgzN44GDsVJO3Qp
         II31Io06CkFU/Lxr3IpagYDjrvxRkNffaDbF4iPjVddsadJOgDVZ8vMY+rBdF7X9S+LA
         trvytJ5RFgWtovtJ9Xzkohyf8EAKLgg7GN7tIeCWdXUY01bUah5HTTDmaKZ/fz8Gb3Fx
         +UGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oeg+81+TIgH7HRDFBE2k5xkuNH1Ae1IM2hO6ioqF1wc=;
        b=1F5wi5ImYD1D2HdRlOW+/uAEhkIHqxUPJnwEP3afq2kdnZ9fqu11a425xobEjPHqnN
         fnE2Z68PeYry07dKvAArLQ4RAp9h8q2noyMTyDrssfhGZfZVQXUum67EmClC1KTGacTJ
         5khjRVi2MZYHKY2rPfKqSTJK8rwH3BTqNVe+A9wE6pkX4MV+VmiLDQRXsIj/E1RJNr7Y
         sZiIeJVi+O+nntwDNOogYV3Q1RP3SrzTygtpUmOdNJzNlLC83qbpotsKZrg1SP0DeqcU
         DzjSd8iAEVd49y6eVDK2rHy2yYGb7/JdCAs5eYBxqZg0lbIc965mQQLbGHc5VlE9NnbR
         0/MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oeg+81+TIgH7HRDFBE2k5xkuNH1Ae1IM2hO6ioqF1wc=;
        b=o8uEJ5LnUyAQqTJT9tN/y2KKMUtST/Djc+ej2zi/DzM62NG3uhP06oU51jzZtbMVY3
         61t/CbNJRjmBOXS/6mHjzTtJfuDL6xPLGrKI/7PQT6sAzGeDHkEHh5Nt++8PtKUxG7Pa
         6TFszZTrwgXucn0heMqnzIt1GzCuq4/jSSyb1hPpochMniR3bx+rkuRlcKRCYCR+coFP
         seyEjWlLwNmUc+eeDjF+MnmcjFWEvPdrRfW+RbfOiiaF+3VxfAtiB1uwHrOvAXImSlbX
         tbc+pawvrFjug5reFnB2AgCXUFRwoJ99hBNtD9lqVLbgeBJjzhVd3zu2XeEf8EG39Hn2
         Q+OQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oeg+81+TIgH7HRDFBE2k5xkuNH1Ae1IM2hO6ioqF1wc=;
        b=ZlVyKp8B1F0LnIlXIiqnJaddNGUMlmT1sEPMXAVPVepqhUt4lMqq600A8cJ05zAKHM
         Hg/KT2J/WByitd5yo6sAHpHCezVJhvbXT0VcsJYh+aDwIOo07Q5lLh3ZIoTc3TBdedZk
         eH//hrfVnJKiXuUT3uquDNx0gFoun2qbR3G/Y+ODE28OR5JH/gZbrwN7iSkJG0QlycfS
         wpWXb7t4TtwZ1P20d/g0+WWCcytjGCyKebVomyzXfBdfo/7/2zLSo+VWcN3vLNz+9+fT
         9ZNhkB9R5gfdYF9MzvPqUOm41iumWbemzKiT0MiJHXIQBz5Ez6/BXl38VAW/rTTA3O7c
         QpjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/0eS+W8YiEbmDFoEjtca+hRKOFWXOnK74Wyf4Bo4qPxj0Ekg/
	9dhmtiWOt4DJEb94/VVS37Q=
X-Google-Smtp-Source: ABdhPJxb7l6xQYhDihWcSx6i13hYVw5KUcEhd0h2953jqONQdUJkHWHSUs4AOEmklKGHFGicIJLZEQ==
X-Received: by 2002:a17:90a:6b01:: with SMTP id v1mr9669144pjj.10.1624455345433;
        Wed, 23 Jun 2021 06:35:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f3ca:: with SMTP id ha10ls162512pjb.0.canary-gmail;
 Wed, 23 Jun 2021 06:35:45 -0700 (PDT)
X-Received: by 2002:a17:90b:110e:: with SMTP id gi14mr9586275pjb.125.1624455344900;
        Wed, 23 Jun 2021 06:35:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624455344; cv=none;
        d=google.com; s=arc-20160816;
        b=px9Wbt35SMRVmYsUGR4pfk83dTuimyQSbFYiEpghcIePYKu3uCvVlWLoiqCsNnDZqX
         b7Rr2xt3RLgwlQiyt0nhKTT1w7ftzaVSuxGqxg5mpUav/goCm4cjdAGFtknQ8lY7ZnnL
         /bQwcjorNnUjWmjsFzGaGd8+mYJgJWK2n6OVUj3sB3lK2CVMm3ZBqjuRa/pArZa9OMnH
         mOkYkFAXVDvOr8Hz5j4fKqhaP7ZIm3kK8doqBgBRtG/nVkDWGJpkeN8YXEdWzh4/ygyf
         cq3TaW/Gykjrzx0uYgc90UrPuP6D/Oyiobmos8OrdCWEJDYFjxeULUNlrloIU5UCbuJI
         2M1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=tPtgua70Yv9Jyx7ctVGV8BsAJhHXL/CuYcaUuJ56fQE=;
        b=NHesfnMjRVbeKMY7PVfZx1FH8duU/G/zKIq8Ady3Uuti2ABXDSX14C7zeSEGJAnVkZ
         24GjRTC3l83IMh2wMg4oXtoqj/tIeQ/aebBJmZM4/jKdFwNubX1qyhAGgeMpeFAYNzvf
         4j7t7iotfqnlWcx22hBF2U6SRSRoIGPtg9UPj1FxVXJf/07emqcu/9xsAm5fE1mVUu1m
         80SKnvdU2BzSi5gtfCjKJrehNtLS1l8o5Ls3E9+VM24FdOPT4trNwz6H/era9fM9U1sy
         rZ98ewBz8wmtutkFjd0R6N2FtwfjugboF8h8A7MNuLNAoAXXolGQxC+V38NQTFX/Z8Ak
         AZeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id h17si178101pfk.3.2021.06.23.06.35.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 23 Jun 2021 06:35:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 2c1ef5406b6a47a0ab1eff22471b5ae3-20210623
X-UUID: 2c1ef5406b6a47a0ab1eff22471b5ae3-20210623
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 166794494; Wed, 23 Jun 2021 21:35:41 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 23 Jun 2021 21:35:40 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 23 Jun 2021 21:35:40 +0800
From: <yee.lee@mediatek.com>
To: <andreyknvl@gmail.com>
CC: <wsd_upstream@mediatek.com>, Yee Lee <yee.lee@mediatek.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, "open
 list:KASAN" <kasan-dev@googlegroups.com>, "open list:MEMORY MANAGEMENT"
	<linux-mm@kvack.org>, open list <linux-kernel@vger.kernel.org>, "moderated
 list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>,
	"moderated list:ARM/Mediatek SoC support"
	<linux-mediatek@lists.infradead.org>
Subject: [PATCH v2 1/1] kasan: Add memzero init for unaligned size under SLUB debug
Date: Wed, 23 Jun 2021 21:35:32 +0800
Message-ID: <20210623133533.2246-2-yee.lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210623133533.2246-1-yee.lee@mediatek.com>
References: <20210623133533.2246-1-yee.lee@mediatek.com>
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

Issue: when SLUB debug is on, hwtag kasan_unpoison() would overwrite the redzone with unaligned object size.

An additional memzero_explicit() path is added to replacing hwtag initialization
at SLUB deubg mode.

Signed-off-by: Yee Lee <yee.lee@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 mm/kasan/kasan.h | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index d8faa64614b7..e984a9ac814d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -387,10 +387,12 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
+	#if IS_ENABLED(CONFIG_SLUB_DEBUG)
 	if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
 		init = false;
-		memset((void *)addr, 0, size);
+		memzero_explicit((void *)addr, size);
 	}
+	#endif
 	size = round_up(size, KASAN_GRANULE_SIZE);
 	hw_set_mem_tag_range((void *)addr, size, tag, init);
 }
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210623133533.2246-2-yee.lee%40mediatek.com.
