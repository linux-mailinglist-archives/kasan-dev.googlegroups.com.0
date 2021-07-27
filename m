Return-Path: <kasan-dev+bncBDY7XDHKR4OBB5UJ72DQMGQEUOW47RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A2DF23D6D0F
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 06:00:55 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id e203-20020a4a55d40000b029025d87cea48fsf7783697oob.19
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jul 2021 21:00:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627358454; cv=pass;
        d=google.com; s=arc-20160816;
        b=SJfbRAtQpqNwGohB4Fi2dOW60cZLE3s33RUc9Ixnf19LhxqhxXBQ2dkARTUMUCCXaY
         0eN2mo2QRmes1kpoIt4+/5g9VJu/JvInU9BPWHWzGueACQai3qBB3TIqpWNBsbU3wmA6
         x1eOowBgV1OLDZYjnPWwG1PvAleDFmcXr1+vLlpoi3TTrIWfSsgEuqMPlGPhqGtW7asQ
         qrH3RcvR7YxmqMXZe/CMucJDkQ0i0lYv3v2O4FcPeEgjfl/a3yNc0pDR3vqjXD9mHhw9
         DqqVQ4V9blfUCVQTfoU9n2QkyJAojBdMshXaDLtLMgwWX2qJ67WF2UXHqecxQFxL7KgD
         0Wbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XtikzggF6dxn8BiR9PjO80ePhunFIM9C9UYFc48fNGA=;
        b=ZyhAfgWEebQyPv+YlTGa0t6j6RR9QyYSPaKzG0ijVTRB+Cvn34IWw7qgLTq82nnsXp
         KBHLkIsPs1O1iFefm9aA0hSLMONAqCYxF3gpg8eniti9xCkoNNzbhAyK9BJFeweJAHnk
         TimOjQLk9G4IvTSkyiEL3lhT3n46945WIxzxc3qLOO2g/aZ00gVYl058MTiL+zgYEDSR
         6aC+htcV52mLNZ7vR8jHLtlk8nmvGdyP2QAYshxh7N5JZmxgQ1wBuTfuqVFKiQFcAYML
         I4iVocl2N6xBMamSm0FcV9nOa+HtqM2v7S/7iwixm0DrKxmvP3DyremCqOo3DYAWHGTz
         8Dng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XtikzggF6dxn8BiR9PjO80ePhunFIM9C9UYFc48fNGA=;
        b=HZO950tyKufrmzWaCrAMyJPy81i0SepL0kwb0oQviYw+A6+yuS2YQ/4nW4th9q4Jp8
         qvOOajIGO3FFUj0MZKEapa2lEAW3iYFa/dMX/DjyXZt8W6eAXAB5T9n/BB1KjOJbYYY7
         lopKybLeDldez0HYUXiUIH/sf/28gn93KZgY4UQ+poqKzMBzgWMpnelFJK2zmq/E5alY
         r/HMEJ1vsXalT1xyOi6Zt858ftcWotE+13mmK1j5AZmPvRyNwDgEt+6TM0vp68NTKcgN
         b9LB5XN23l1RRspz3ebdJZlJjLVq1CRPpjhQPjcTUvGqyA0XeRk308pmjtcBNpGBRa7w
         31JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XtikzggF6dxn8BiR9PjO80ePhunFIM9C9UYFc48fNGA=;
        b=SRvvlDWUm6Zkg+j7aiifctejjXt6YGnStk+WCI6mZiQ+JUAj4uKHRjlQqITq/oa2qd
         AaxXd7q9Mqzv/z5gKZ1xJU/TfBmnP4E0s8HTmXq+bSRdMiTijxVR0TIKz1KkFZWLw+3u
         z9P4CEwU4IL4mJ4GR5QpQKAD+EHwtnTD7F4rKob/djYfKoaPnB1mSC+5m2uRSyZHVqBV
         oLjzdCbJuuciIZ+Hy7W1va6v+Rioz158yliYD53GDIbjeXmodwdvC2mQ5YP6WBSGSXSx
         4l5cmv6vuPF2xHC0FDyPqcAXC1TgrAUgI6cmmv9dhOvj3ipzq6HXBQhLQDhINnzLL20a
         bAMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531UikpbiLBWEV0iOBh11QaRz1jBMuZQprshfCGJ4UFWb3g95IYP
	7DelNPeKIyTq/4ZjMBazilk=
X-Google-Smtp-Source: ABdhPJwu7akjWOZTkIqCIoXp6YxZnpemhQor1bnKEJZinMRfLOm1LQE59Ux/CHZDGXKIgAqB4XypZA==
X-Received: by 2002:a9d:2cf:: with SMTP id 73mr14094278otl.314.1627358454520;
        Mon, 26 Jul 2021 21:00:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5903:: with SMTP id n3ls7123652oib.6.gmail; Mon, 26 Jul
 2021 21:00:54 -0700 (PDT)
X-Received: by 2002:aca:4406:: with SMTP id r6mr13313710oia.50.1627358454134;
        Mon, 26 Jul 2021 21:00:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627358454; cv=none;
        d=google.com; s=arc-20160816;
        b=NZrBWo9/46xElq9MolcZxrYC15zJsat0WiY31UQ0kPA+YK6kvWYLafQce0s9uRmCuW
         ZGWQy7lHwJAp9SylFDQBSYysF6xR1xnee29+o22O2FPbrvF5NOFklxz+QwLX6X3BWd5+
         350zBEgR86tq+upDOxMxm+mQcVS1/rd5kY0krv5UageMjat6A42aR4KJ02bgduPW9Bfs
         TwNfTQcp7+2XWuJqZZysFRy8THXYROaT1QWyi8mzvi2u0fosi6c04ZgWMSt74Ij7osvL
         v/R8ozX0FLrCYBCH0++zLLjGOsAbgGuX8F12+VunLP0t6kutqDJGStSozqhXKtb/17I2
         Ovzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=lr8InPHh6LTJUsidl3KY6dSGt8iSX2/gMEXUUr5S5KI=;
        b=gexuFkiN29VdVR/5t1GtRoOt80fiEKvVlD64Xror7hoRasnEeQredscKbgyJK5q8+O
         VNiZNnk8mGGIJIIcqRYXCvIjJSu1mowQbrZaPObm5n5Ex7lH5Fh6vBVklxWIcCMiCgFx
         zqr2zHsEv32WaaEs4Eh+PerTo3APsDq0cS56gZTTrqQUIj7IfGWVRdziu//uWuo0slAu
         8LmltKqZDjAGnKtBIJcBVSNrYomGFo6JdU479Bw/9/AZZ4TEx90zDjrGBcNEiBbz5AxL
         uwvHa1Z4R/wkdMAn1eK9rplrWUvq/9tceoWkeSe1yvNLgN8IrznRiQmUPgTPSdtpwPT9
         53PA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id j26si257714ooj.0.2021.07.26.21.00.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Jul 2021 21:00:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 88bae1ba30cc48128ea925fe74fe3f76-20210727
X-UUID: 88bae1ba30cc48128ea925fe74fe3f76-20210727
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1762002640; Tue, 27 Jul 2021 12:00:50 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 27 Jul 2021 12:00:48 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 27 Jul 2021 12:00:43 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang
	<andrew.yang@mediatek.com>, Andrey Konovalov <andreyknvl@gmail.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Chinwen Chang <chinwen.chang@mediatek.com>,
	Andrew Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH 2/2] kasan, mm: reset tag for hex dump address
Date: Tue, 27 Jul 2021 12:00:21 +0800
Message-ID: <20210727040021.21371-3-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
References: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
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

Text is a string. We need to move this kasan_reset_tag()
to address but text.

Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
---
 mm/slub.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 6dad2b6fda6f..d20674f839ba 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -576,8 +576,8 @@ static void print_section(char *level, char *text, u8 *addr,
 			  unsigned int length)
 {
 	metadata_access_enable();
-	print_hex_dump(level, kasan_reset_tag(text), DUMP_PREFIX_ADDRESS,
-			16, 1, addr, length, 1);
+	print_hex_dump(level, text, DUMP_PREFIX_ADDRESS,
+			16, 1, kasan_reset_tag((void *)addr), length, 1);
 	metadata_access_disable();
 }
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210727040021.21371-3-Kuan-Ying.Lee%40mediatek.com.
