Return-Path: <kasan-dev+bncBD4L7DEGYINBBS7CRGDQMGQED7GLTVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id D8DE63BB534
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 04:41:16 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id f10-20020a05620a15aab02903b3210e44dcsf6355568qkk.6
        for <lists+kasan-dev@lfdr.de>; Sun, 04 Jul 2021 19:41:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625452875; cv=pass;
        d=google.com; s=arc-20160816;
        b=csPoz9sa/+UfQQlAcs3gFFVNvPcdcJSfn5reoqFGhBI9UBJVfwdS7Up0AyTFzwLFxf
         Xe2KSzLW8h20Krg5qW4T3CT1HK4VE452zx4G/7MLcpmjpiVHympFk43GNZKN5sXFCNzT
         sSXQ60V17qN/aSdwh4Fmd9a+qI0vV2DYAifZ1WrHxjgJN18ydr7/3bEPAiwczAk9h0tQ
         R9alDltXjJoqs+0y9RMdzp8MiSG45T/yLaAN69/Ssm1JfFlhYouVffx2LK1vhkbYTW5B
         z8u68FFytLUWSPm/1V9F6W3XWDW8b3/h5tPSoA6VskT2D0EfI+NQfJirmRlbYQGOEW97
         yaLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dEs01DsUR2L5YePz9MPE+83syR2j2XcbfCiGS76/3c0=;
        b=q1gdxPTmQg/Ua/M5oZ8G5cxq5QJU6wFj+MHhGFrEUlNO819Iym/cpe2++tOHQuWvll
         KFd6w5nSf+9Wag90pjuoVLoZJkN0XAyMopT+RoG68D0xPKk+t2VFWveYkEvzw1qKc9+Q
         eJ2Awa1h5h2KDyAg/okGb0Gldh9Zt1ghCVqe26uoL8k6yOXoMRw1mIIMzUoH7j6p0TPG
         75Gx5vpM32dxfkX8x6YKvbozCsTMNAOinh/WOJMrTB4FwCNIlGjfyT2OzWTmeUZD8B5c
         6QB/aFKjtQn51akZ3ssg20VBoGnnXXzyzURd0/J3qZuFaXP3odzzE6r7xRkGFGFxcMh1
         O1Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dEs01DsUR2L5YePz9MPE+83syR2j2XcbfCiGS76/3c0=;
        b=Zu1N5wGqVxVugnOAgKXmo8yJVWPhJB0eU5pAla5wBpR1kZeVTMRk/UMNNK/7pKMJPZ
         uC9wC9eeaLVt/PyTtydFsolF6KI2CmacVVBwkHj6vczef2L0y6c7+uo8365ezIp8M/QS
         1SQImRXyb5MNWs0xZI+hMM6xue5EXQ6KCd0HhmddKzDvU+VlP2SttHfvxdrBQRMn01V6
         0eNhH2kUp5k4nXjR+w7kSJ2oFCxxuJvVZ/1Xo5qxOgdtMibIVBrqaQn6Dws3p8O6y1Lg
         kXKL/B3q2L2a+GZ2bDxwWRCotwC6mObwsJKGG+2WWobEji3x5IDtBQLSTf+TwmdrUQ7V
         hIqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dEs01DsUR2L5YePz9MPE+83syR2j2XcbfCiGS76/3c0=;
        b=Yt7/Tt4VgGzeehuDez7v5ZN3P1qKP60aVI1CQ/AYl06pgPLZpP++ms7LCiM26Q+FXo
         YaJOCo6SR1mXl5QDk7BDspNvBfcXzHThzWVIGVbOjovqzEwbYUXpA7duSTmjU/VS2W1f
         BLYnX2Ru25EbE4xbMrQf+5MceEpBqbJi8rBoXnk9xJks+r9wFZsAwB8ufIql/D2B4r5k
         TLyzzYy01cwioNs8Tmo6i2j4Oty3hVzUA8CFl9agHd70NbNHc1CFG3XxmcKdGEN2aaLY
         Q4ESx3fMTNcCKZlmtSQY4r/uJl7I7gWCXye3k7gkdU5gm+CcgDc6C4QjUThn63RkhGjG
         Qdaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531y1uC9ahSbFAoPdubCy7tztLzPHi2fiSw5Fy7sR9ieyTLMSyy+
	W19ZbffxE0zn6vAn2YVJzjA=
X-Google-Smtp-Source: ABdhPJzyKVqj4upZiYz4CU+6+GRlcs/UoMdWpnHdR7hOZTNj5cDEfDtx4b4CuF/cS43kP9kBXdNv5A==
X-Received: by 2002:a37:a48e:: with SMTP id n136mr8026687qke.467.1625452875870;
        Sun, 04 Jul 2021 19:41:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:edc6:: with SMTP id c189ls8670436qkg.2.gmail; Sun, 04
 Jul 2021 19:41:15 -0700 (PDT)
X-Received: by 2002:a05:620a:21cc:: with SMTP id h12mr12091560qka.342.1625452875410;
        Sun, 04 Jul 2021 19:41:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625452875; cv=none;
        d=google.com; s=arc-20160816;
        b=EdKOrrcbXJ4cWUqBOXATtszmWkFFDuAXS4fKFg+LQw3cGZEVdNrzsjqkW+pnmORYJe
         nccxOVqBH7dFQlzCNkZnfU+gXXSbClQ+riq6570NHcoQ+wFjLYa3z8xWM0P4EtDibxjf
         UpIPnu/hlAmQaWZ+SUyc7C/PqWYtR2cMUcc93IqJv8mAgNuAQ7EfeLm0+QnLrm61BIQo
         bpQplR9ucyNN00H2ZT8w98eQdybsuZzD9kJlcAA+0HF72MN7NrPnAXxnM1OSOH8vmj3f
         6TntW62jiqS4s4El0gYCjAjlegxIA7SYLhHV5xt/dZTHerEt5M04O1my8uDUrz7hJw1U
         ntmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=8hDuNPubD0iawmy+sLJU8ax9wtPI0eh+qjbOBCQoPxE=;
        b=WCc1Hnt0KxBex4DOnvyxPNPcfPWYco3hT/uVFGRMqUofQ6oXaabON9YPxw6Fh5rY9p
         2araqmAfRsk0hFrNSDWmJ7Mn39qvDmasKu2JkK/LoWc25RGMdZWZf3tfyN0WBHZmC+8a
         4zfbNx4ZrZcDQlAaDGSy8K9hfDerlNJmxrFGXrFs27DowCsLPxdsc4tFxs0DpJ3o9MAE
         cQF5afef8DVtZMOswHEZP72fPrSIhYeTXVz+B+75XIodgSf8bVp4jf99E4W9kQTKDyg+
         M9ZqdZfDHoTwl5VYr7uLJSL6LO1tBFsdFMJEqFDWRa2+x1K8gHarIcBB0FX5ORvqiYmO
         lTog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id s19si644636qtk.0.2021.07.04.19.41.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 04 Jul 2021 19:41:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 0de2ac8aea354174b7b4b19222f69d39-20210705
X-UUID: 0de2ac8aea354174b7b4b19222f69d39-20210705
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw01.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1225847933; Mon, 05 Jul 2021 10:41:10 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 5 Jul 2021 10:41:09 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 5 Jul 2021 10:41:09 +0800
From: <yee.lee@mediatek.com>
To: <linux-kernel@vger.kernel.org>
CC: <wsd_upstream@mediatek.com>, <nicholas.Tang@mediatek.com>,
	<Kuan-Ying.lee@mediatek.com>, <chinwen.chang@mediatek.com>, Yee Lee
	<yee.lee@mediatek.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander
 Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew
 Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>,
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KASAN"
	<kasan-dev@googlegroups.com>, "open list:MEMORY MANAGEMENT"
	<linux-mm@kvack.org>, "moderated list:ARM/Mediatek SoC support"
	<linux-arm-kernel@lists.infradead.org>, "moderated list:ARM/Mediatek SoC
 support" <linux-mediatek@lists.infradead.org>
Subject: [PATCH v5 2/2] kasan: Add memzero int for unaligned size at DEBUG
Date: Mon, 5 Jul 2021 10:40:58 +0800
Message-ID: <20210705024101.1567-3-yee.lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210705024101.1567-1-yee.lee@mediatek.com>
References: <20210705024101.1567-1-yee.lee@mediatek.com>
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

Signed-off-by: Yee Lee <yee.lee@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 mm/kasan/kasan.h | 12 ++++++++++++
 1 file changed, 12 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 98e3059bfea4..a9d837197302 100644
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
+	if (slub_debug_enabled_unlikely() &&
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210705024101.1567-3-yee.lee%40mediatek.com.
