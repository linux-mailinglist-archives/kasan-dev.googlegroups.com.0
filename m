Return-Path: <kasan-dev+bncBDGPTM5BQUDRB6E32L3AKGQEWVT22PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 41AEE1E9CF4
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jun 2020 07:11:22 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id n1sf4437068vke.6
        for <lists+kasan-dev@lfdr.de>; Sun, 31 May 2020 22:11:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590988281; cv=pass;
        d=google.com; s=arc-20160816;
        b=LPR6PMvOwaDrbZEMUstJDdU6mrqxZjnkyueZefizdruE7XNopUElQcYmOOHa+mW/SN
         Q/fe3CyiXWennVg/M0ZwR4hqHJizcGPrDIE0zHFj874h0hYPeL2ZqZs9xs2cmfje50g4
         e3dY+OqntTJqLHSN07FQZX2Qoxn4Gmfv2pL9ZMQhE3IzXF/srtX28nZ/yrMRkVoWs3yk
         PI4spxsnC2N0FEzHLwTjCD5adUqiQW5mL5mlY6yKzu8Lggh3H5iAtBi1RtpwaZTCtDR/
         J+T45ZPgMpO3W6PnXsVM2kaj/OKTvrF6RoG4Ez8FSWddyXUFf3QQNnshDW36tTOJGFQf
         +4IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=QBxpMdWK88Icx0ShRe5PlzwF91FcL4h4oDUOYGSU4DE=;
        b=SlPcNwakWfxy/eZwTfxCf7m24RLmJDbgZBoTVh/CKFX9nCmIpUm3XFMFvgs/OZX2/u
         jnSnTNHRi7FD/ft9Qh7LUVyQwxH2k4vtwIY9iUWuq1N6keg9M+RGlW3KaIe0wMvZQMOD
         6H3KZnbAJT2vvkQxVdbFnyweFcxXj/G24ZSGBzyzA7xlAmkaZ6Sj8OEJbygSyvUfNwTW
         qLWJepqcpIiLtYFQZeWJkJzOukUgLZey/D1E+t/zKeoZZ58jAYFT6fM0HqTctdeSIsMu
         /3zlszxJvqQcjiMOZg+x11XbfFyeewiUd1gYl7QE40AqBjTx88qR8/DVLZD5zp78KOjZ
         HtaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=D4y2Wt2k;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QBxpMdWK88Icx0ShRe5PlzwF91FcL4h4oDUOYGSU4DE=;
        b=Q8/Z2pwHRH0gaPenFmZa1x9PUIK+pPjThckj+eI7QxPVGYrOsfjzwIeo+/Xih3GU7d
         3B9oJO5/HeZCfJuBcMK3qhqmrIweeVtNX8C+JN7Rpj+6XJuMzSgJ0YaF0XAuv4hg/z1D
         wZSX3Qd07dVlVTuz2YB1IKEtNH3oFJr260XfcuJV/vbI31nt/NO08oCW5pr3kE2jJ9Sy
         u143bo1Xv0O1S+lHZ+eWJCzhhiG5kLziRIZBaZpy6OgUfiKcDvbENpVe9RlLjcjXzB5z
         uY5D9N2WQRBIU3pR79/oNCoGtV2JwRrGMjgAaTQYmhwGw8lj8/BlOoxn/sm5LQqVtSnG
         OENw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QBxpMdWK88Icx0ShRe5PlzwF91FcL4h4oDUOYGSU4DE=;
        b=K+Sl41ikyu4tcmC6XrkyphJIG6/aac12g5Hx+IvcDESmwBOjdehzBDQzU8ksJfUA7/
         eUXVczTSuiBekXo6ct81YsmNqtCx75m7dWmyE2M93FnC8y7l5smFswgs6UZHqSlPObLo
         C2PTe8fhhdM/T1c0n+v6k74rUUwb0Q05FjO78suIz9jrGsgjqvw332+HITt4gJ6NlMWV
         7RTWdNZno2MOnJMai6bN/3IuN8YdmR9PGxCi9npMJHfEzqykTCEE58eTxKa6EPXSQcLX
         HwRBDaOQE0qdnROC+40GU/6eFMywAFiY8fI8XYRrfxfN/y9jmklYvRd9mCb3O7t9AwSI
         Ts7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531nR0+3nXmt4P2gnCXuId1293uayWPcEWYGgq7XePeYYVlEbTMP
	cF/k7KZPy2l73v8MzcWNIPs=
X-Google-Smtp-Source: ABdhPJxRJDr39ylAkiSgLpRzHr7LgI6gsJ1GNKuCNqsCXR4r0pMi1C5C9x+jKQHvtZRzaIzaj0b7xg==
X-Received: by 2002:a67:fb52:: with SMTP id e18mr149866vsr.168.1590988280912;
        Sun, 31 May 2020 22:11:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:2593:: with SMTP id l141ls29877vkl.4.gmail; Sun, 31 May
 2020 22:11:20 -0700 (PDT)
X-Received: by 2002:a1f:388f:: with SMTP id f137mr13284819vka.39.1590988280598;
        Sun, 31 May 2020 22:11:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590988280; cv=none;
        d=google.com; s=arc-20160816;
        b=CrM3v5hgBeD7VaZGqy3+SrIpIXkIF+1zm3XA7Ub6muytd5fWv9m3sgQR7Kd5S91rWC
         JeStdITIB1Kq1y8xwuaYaTV2dfpB3A7oIyyyQBl+feZGPCSb0LgaiWiNgPVwTHZCURR1
         /7ULZLx3s5U8DNQM757kYjPNJ5bE6dPizbvHWCdL5OCSEIUuXfm6eWTGLvgIMKXfz4E9
         Mf3ryo5QSD24PfavWH6P/z4M5ft5tekijBupyFXH3WCc9pOSgRdR47u15LfmcKoxyQj1
         yH8OTvDAmgy9Lfi/1UnGJ8y828KRz19/ww+KNa3WlORr/my9jKll0FoJcHoW4WsvcTD7
         tMlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=mSnY8KhqyWrchwEP6pw4hG/od6FJgo3wLIYoRyPzhfE=;
        b=VrptAlfG5xSka7QtvPhH70s1EqA/7MfsOJXWI/fSt4Bn2V51UN4LBEFGXYMijbPP1F
         hik0rqioq9wy5dSgCh7MOAKSw4c0lBwODkJHCLdMbE8vhG2HwoLreM57SJnUAEYakIuf
         Bz2ztNF1HteI8gF27sv5obGBecawqKzuWysnEgNzBHEPsnON2zM0moisC5Toi8R8u1T2
         6i2/mVZCb5JrKoqzZwq4Eb2l/metCHEBkwEOQZV0MUmAmnh2XfjieRYtYz4/tO2s/g2M
         V3A7ZpX0Hqu/eqeTvpE7dmJjY3jSGfkBD/A8vriTEtyJ8puv7Hi/+lviMioevqtF9HMe
         b85w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=D4y2Wt2k;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id f12si777212vsr.0.2020.05.31.22.11.19
        for <kasan-dev@googlegroups.com>;
        Sun, 31 May 2020 22:11:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 7834e9f67cc342dd8eaacb6655bc76b2-20200601
X-UUID: 7834e9f67cc342dd8eaacb6655bc76b2-20200601
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1839970914; Mon, 01 Jun 2020 13:11:14 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 1 Jun 2020 13:11:06 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 1 Jun 2020 13:11:06 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet
	<corbet@lwn.net>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v7 4/4] kasan: update documentation for generic kasan
Date: Mon, 1 Jun 2020 13:11:11 +0800
Message-ID: <20200601051111.1359-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: AD8C74DB6C0C24E053BEBE0CB306A11DA5F9CA9F00D17BE39A5608DC48F6A5BF2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=D4y2Wt2k;       spf=pass
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
Reviewed-and-tested-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200601051111.1359-1-walter-zh.wu%40mediatek.com.
