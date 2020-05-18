Return-Path: <kasan-dev+bncBDGPTM5BQUDRBOOXRD3AKGQEOPEN7OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CA121D70FE
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 08:31:23 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id g16sf2806867ooi.16
        for <lists+kasan-dev@lfdr.de>; Sun, 17 May 2020 23:31:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589783482; cv=pass;
        d=google.com; s=arc-20160816;
        b=qfJ+YKZlnOkni0eZpo8NZpioE6UyrNMdPOogLTdDjaof8uqgoViG2cIxmrWtK+guzd
         QICg4vtqzCszizEhYCh0izb3Dgx3CzB7STblspsnIpl3n/kcfML+Ll+HA+AE6zH5GeNI
         POMijnRHYAiEfSY27gKrMlopizq+WlluLHZy68Du+lVXEPe3fmPn7urq1XitTH0Gdrkz
         JQ7YFPvAVM0BZ1jiGihMWX64dV23Et605fwihjNuCuTStvP3l3oeitydFIdgeGMm7FyX
         6DvYWijnYBFcJj7zQoL7nVrIP1DLPDRMhD5pYO0O81ShJ890YqwGdy7YruVhu7hpomEZ
         +fvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZEV6TkTKpsQYpqu6RXo4K4m8bZ2GzxEM5Q4L9XdGY80=;
        b=kQ2c8mvNpmRGe2akHpBc/P/togZgn0V5pW8qLrALBJmWR62FxODUvGYfCIdnKTg44d
         zTkTLhYPgRscF3wqHUgeR5ZnQ6kxQ9795I0n1tSrYorhCkdpg1ODo2PtJKczPEy4KP+k
         uN35d0UYfMwFQxFcILqz71PiExzMIgS6dZuLJpsPReNThNoZjuBa8Q/FjfHUysNS8XiC
         p2vKPcDFQmxtP+Z6UQ7u1kx50lDCBGCP4VQFiuHQu4tAe6GBKwXnwylI2G6RMoJ6bFIY
         oFU5POoBp+ngK0Kw/aI6bcGodEyH3cQhx67lmNo6IX2xDPwsSV9k+7BC1QjWiz6eChro
         CX4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="b/cuiUVM";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZEV6TkTKpsQYpqu6RXo4K4m8bZ2GzxEM5Q4L9XdGY80=;
        b=fyvoqheWxhVGMp9/tPZp/iEsK4riurbGIEExVKBoiA+vLBFd+sbmcFR6hbvQoS5thU
         Ca6CJQtgMJch2PgCYZHeLf1ShYaWdDrhl7iI8GT58qk2iUJGjS+hUApOQouaKs7XXkyw
         656Buy72CHcJMyOpAHyBwd1Sh+I6xsy/JwAf7doxf4j5umbP7xZNQKLEdXTssR93k7kS
         RsW01foktFHaBsAQPDTLPVajsPbnxqUx7m7IysosIZAXDr4MhSb8gVmwGG4PLaOZko57
         2vGemlSY9inM4T7AjKi9uqxE/sY37AvML51+0GVE5scuGWc/rSD7ESR7pimLtYCOLz6P
         IurA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZEV6TkTKpsQYpqu6RXo4K4m8bZ2GzxEM5Q4L9XdGY80=;
        b=A44pkg7mcffbhbsly2v/iWSVudNe/w9iHQdu57iRr/q4h+ZvoqwHkBpjZ9y9wLhs8J
         +G69GPGnoLIdFzeFdlXtRGL906DhDUVubrVKl/7rtEnu7zXDLRjMA72cyp6Wm7ZPcqpD
         tN8E/wZylRFJiEtyLT/CA7E+cf4FfAUhG87Ihf4Dj2AwCp1LR34qMzA9X0Z/gc1X+XBR
         tenZPlnsFGrhTAd+wdULddJNx2PMXSWDtiGUxZjycqVyxbHaXaF3KYpnhgUehq+NAoQ5
         DjvoJvnrGZo6wZkT+vPf+Uy5R6XgmWZ0iFRqgq9BcRZtOaBDOEsD4i6vX75pQETwtTQ3
         f3bQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310unrcfaM8d6My/bd5XS3ptyaTRQwbhmdvEcD/XhZa+lD4Qvf8
	uQhdVW0r4ioxtxEEzb57O+A=
X-Google-Smtp-Source: ABdhPJxG1PJiV1XDzV1WKJrR/bUbx3OQZNYLhqxd/VwM4jTLQafsBIVnm4zl87rdQhCNGwGnPXLuEQ==
X-Received: by 2002:aca:d905:: with SMTP id q5mr10213540oig.65.1589783482008;
        Sun, 17 May 2020 23:31:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d656:: with SMTP id n83ls1695672oig.0.gmail; Sun, 17 May
 2020 23:31:21 -0700 (PDT)
X-Received: by 2002:aca:854:: with SMTP id 81mr10156550oii.162.1589783481748;
        Sun, 17 May 2020 23:31:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589783481; cv=none;
        d=google.com; s=arc-20160816;
        b=P+tR42S0HtO5AGHsNA4J3WK7f0L9Tdc4O7E4ysmjHO6ufYyqH4t6JWuaUwd872QBsS
         bxqkNQTgfWpP/66UXkG8tOAUZ/J4ZfFeOr2P+r4KHaAKBN3dEj3WOr7KbkoZ1xtPHm9K
         x+GNwCch2/7Lj3QNeUgU6CdahyJ3IKkMI71xgdnyMapCHwKWOE2pIF0SVQtXpea3MKcE
         l564NdLVzJ00Pd4OdlLHk6TRJNW3m6Lq+Y7jdGPE3Y/w7aPo4XXrS6n7yJbmel0H6AOt
         JGbbRaOXAc/Jl+ysv4p3WT8LfDaB6WDMGqqW9eJceqU6UclCCFjomaaCM2Y74dh9LUDz
         D8aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=opBrR/j4yNpYI9GLAoGb+LP86AmZJLpZ4GTLHbq+76M=;
        b=x2fTXmND2dpawDuv5tS/QMd+c8Efie8kpqnD7QqvxY0VYGENjQCgj/Jpc1BErDho7u
         +ZpqvcsLuidzPySg/IxQ+wC0JfEE/oZ1ssgmGjS8ZmBt1GAnIj062tg4eNP4uYRp7kb4
         KDJ99DrqDOUOtM3mh8ltBbY/ArNA3n7aDWy0uArVeUU5zm7MROURm92fpNSAvrtA//+e
         agN7SxyJ/dLSdAvnJsq9L60k3hz3ffcUgdnzHtRyXzRsJvQw1/2oSEfPknKfHviS4RTs
         1cRpeY0qQhsjPmv6SvaidyYIH5HNEXcjFUNYSLZWlngRW2eP1HS7rgGn0/a9gaBALg7f
         LYFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="b/cuiUVM";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id u15si932861oth.5.2020.05.17.23.31.20
        for <kasan-dev@googlegroups.com>;
        Sun, 17 May 2020 23:31:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: e71d4076d699494fb2225b6f20ae1b95-20200518
X-UUID: e71d4076d699494fb2225b6f20ae1b95-20200518
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 332144935; Mon, 18 May 2020 14:31:18 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 18 May 2020 14:31:15 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 18 May 2020 14:31:15 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet
	<corbet@lwn.net>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v3 4/4] kasan: update documentation for generic kasan
Date: Mon, 18 May 2020 14:31:15 +0800
Message-ID: <20200518063115.4827-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: ED675643220DB99B8C2E7E6E1D9CE046C7ED0213B08C9DA93969DC6F10C244012000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="b/cuiUVM";       spf=pass
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

Generic KASAN will support to record the last two call_rcu() call
stacks and print them in KASAN report. so we update documentation.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200518063115.4827-1-walter-zh.wu%40mediatek.com.
