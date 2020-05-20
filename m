Return-Path: <kasan-dev+bncBDGPTM5BQUDRBHGKST3AKGQEXEKTKEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 688DB1DB3C8
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 14:39:57 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id k10sf2430167plk.13
        for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 05:39:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589978396; cv=pass;
        d=google.com; s=arc-20160816;
        b=fqdGLgOQHa+6xndB8ZXLvx2uOqft1WyFEufn07Z+4cYO3aGDcrVqJMdaRzYHiu0WHt
         cubiEzVU9jjSmD60Ug8R0qLLa0osbOJ+LWRfxbmn0LQl7auS2NYSRARzIgVknJbM5sOv
         RTFZMywJAIP+SLsvhDPaenxUDBVjVKtsLK/bdrV7M1Je39XzU03fBB1m3csyCOeBDGPH
         Wcn7dgLxNfqPyJnFe+5Q4bcuucj85JgKH26U49NIU8kqpYDG0Zb/fwivK5OeJXTcpK3O
         emzAuB6YflNfYJkndOj3H3z2CrCrx5tNm+JJ15YLsXAYJtafjnsHPdtbgavN51K9RM5b
         jpdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6O+ZNIrg0Nnez6lKRGhA60TREb7pPlOn0wE2PfhkAvk=;
        b=KJIILmbhf4s8wOUwCqXzztFdvSzNLgyJsKQrkkNUDxZyht1oFOAroUSGxMmzHM2WVg
         mrp2EdF/viXArKyiO9aFOiWo8E+TYiJCjVaQQKFk9F11YrPb0+jbu3xCB01g8R0VvkBl
         GKeQpnSRG3R0TcJ6O8pcE495z5D1DDyyLYW3gGvlVKwaZILyrtTJ/XCzWUEq5HNqDmRC
         wy8tzRnGCPnVV/vU3Ji4eFpYk4LpR3K6Nf5R/f+2rP9yfDqN3ILdSaRq4zua2xEnBDti
         asisPlJgQoM1vK9AyM1VCqCsNHJLnle8QVWE0lL+XcVbQoIZUot9hT81rF5VxNzJeEbr
         S5gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=HImQAotZ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6O+ZNIrg0Nnez6lKRGhA60TREb7pPlOn0wE2PfhkAvk=;
        b=ldeTcbvkvhD5jVWrsTOzyjF8IAz9PPyo35ryQCJ01yh8cD13VhUQow5YIcNErjKeJK
         FL8Is4BMgcHkup+r3xG90dgoQmC9cvYxHgKX9XRBJDqwGmaoIpPYcrytCOmbydLNPdbS
         D8103+X4EgAsfeaE+gQIrlDsUyQryHeoulHlIdZSJtLXFTtgEkE1Bj+WCgUvJsTOsnXO
         EN57lGUGzrSKSRBKefD6fGuRP/CvLyk75W6cHdmnBaI6K38YCCSJvVk24Qt84f2YCKkq
         7qj5L/ajEYvkYdO6EbqBKrU7vpsnUtfjxNEiibWFcJRcMMbjj0UKHuCqyCJ1v9MG28b+
         hlxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6O+ZNIrg0Nnez6lKRGhA60TREb7pPlOn0wE2PfhkAvk=;
        b=O0yWRFNWaqAKaFi2QFXF5+MpTksf5gHLt87KBGgE0qb0ZBG298Q3V+Q6Xn3FdDDT/V
         dLcE/nevZ1VJY4jKNzVnTqDloZ+oXhkkc6+QhGPlK5IUb0/rnYBwLnAIkcKLjMRo7GD6
         sw5R+8hkbON42ghZA5iCilU6jrIGeTCqSOzmWO8ylyNheCuF3+120krAhg3Yz7CeEURI
         7mV8mShx/M9BnSKNpiTyaXnssqKxSq7nP1geY8bXoYAeghef1/oZBO8FX7Vp9nLhSbC6
         ef7zdTet6PEZSfhwqU1S0aEQNxoMG8myfFxDAWNMeKj1TZuV1AjLEPS7GXM65sw3WmrQ
         VjRw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jM+AogxLP5w6bZ82miC6wrvesWWGvCRMepu+PmFtojoj5fQHn
	nlRVqs6ztMqv0aq0gaFic68=
X-Google-Smtp-Source: ABdhPJxP52avtQLw46jMCBhaiue23IYx8CUeDpSYNz7jGjf17sbVxTKgGf3qmdfjwu8MAW3rnq4yRQ==
X-Received: by 2002:a17:902:ea8a:: with SMTP id x10mr4454045plb.220.1589978396142;
        Wed, 20 May 2020 05:39:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:12c:: with SMTP id 41ls1045371plb.2.gmail; Wed, 20
 May 2020 05:39:55 -0700 (PDT)
X-Received: by 2002:a17:902:ba8d:: with SMTP id k13mr4399969pls.290.1589978395801;
        Wed, 20 May 2020 05:39:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589978395; cv=none;
        d=google.com; s=arc-20160816;
        b=ksfKWHdaLJk1tMG+gMDGYNJpD12zI5fHXcTvT5DVl+yAael8OUofOaV5G/M9UJ+2nc
         J3OAAEfBvHJukxX0W2MSncmRke2ewzZ2Zc6usC6TJjkm55pfBW4CvBjBBWkFrsPtbGro
         HAPFUdxQbOe67QqXYt1cRIWBitk6MAVKNPMdvmKx23CGGWTDkxXcNc2MXJTS1xwQktU+
         LyNaflH+vxFCansIxDJgNsOBeU29Snuhipf9WyKhenMgyO5WgszdR3NqYTPfsgnyogLE
         PiBLxrUdWhimgPuW+m9vmH3U9+kH/AYosdpW6r84rPfNNs0JwPYNBxfQUWl9j9SrT2+o
         Lavg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=qIWtxoGuZ5P6mO49eH/CrXHztmv7j3tYchUpE2BMWOE=;
        b=aTw2puNuxy0t9U8JaXHXHDmsE59SB1AWtKgG9mCvGRd//4Ms4L4oRQ1ACJySqzbkX/
         jmgeNOjq37ROnLL1BZx1/icC92KHrPSngfGbUpgrCM9KxLY0yXMcV8yTPRmlTZzUQOo9
         FiGKQFGmfEx3/1jbvTINMehS+pRcapTFf6ISaqplTcyMleUE39pNf56skY8Ko73CSyny
         oLgTcYTPcVfVh2YAO20MdwxTFHyWSuFR2ySQN0KrigpSsoqZZgj4nn9FmJou318zu+KL
         1ws0Lw9l/y7ZQI31EYGmCpcAr8OV567hWC5UECeSThBh2Wq1I9KIOQDxjzrtDZ5UOPM4
         AzbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=HImQAotZ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id c14si324366pfr.6.2020.05.20.05.39.55
        for <kasan-dev@googlegroups.com>;
        Wed, 20 May 2020 05:39:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 5270448b006646d4879475dd6e2e2308-20200520
X-UUID: 5270448b006646d4879475dd6e2e2308-20200520
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 164112740; Wed, 20 May 2020 20:39:53 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 20 May 2020 20:39:51 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 May 2020 20:39:50 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet
	<corbet@lwn.net>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v5 4/4] kasan: update documentation for generic kasan
Date: Wed, 20 May 2020 20:39:48 +0800
Message-ID: <20200520123948.4069-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 53A25556DB809A33935C8E07C4C4E7616D5CC73601E447850F8F6E6A8049B3E22000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=HImQAotZ;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
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

Generic KASAN will support to record the last two call_rcu() call stacks
and print them in KASAN report. So that need to update documentation.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jonathan Corbet <corbet@lwn.net>
---
 Documentation/dev-tools/kasan.rst | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..fede42e6536b 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -193,6 +193,9 @@ function calls GCC directly inserts the code to check the shadow memory.
 This option significantly enlarges kernel but it gives x1.1-x2 performance
 boost over outline instrumented kernel.
 
+Generic KASAN prints up to 2 call_rcu() call stacks in reports, the last one
+and the second to last.
+
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200520123948.4069-1-walter-zh.wu%40mediatek.com.
