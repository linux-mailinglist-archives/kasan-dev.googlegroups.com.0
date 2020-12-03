Return-Path: <kasan-dev+bncBDGPTM5BQUDRB2M3UH7AKGQEKBLIK5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 446F42CCCA2
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 03:31:06 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id b4sf204106vkg.10
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 18:31:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606962665; cv=pass;
        d=google.com; s=arc-20160816;
        b=wVmCW54wGZRMHBCjvGCOw2WDaQADJnmL6ZtveoUBvIGORtnGJrSOZ6fYKEARwyOFOR
         IdkPPVi7ONxjU+qxtRac4ltFAUR9fVD6hE6ZPpAG9AIqtiJTdg6AXhEkFcxn0ReXj5Z+
         eTxaBEI/8XA86DAer+ZNHGmWr9uKT4bayQvfSDtY4MsF+CN8VHKU6lX0RCc8eFrmvs6l
         q4s/uZBzcwrAGDd8bcyE8NCCMyRmE6p4m1TpMPHuJLBp7p5hsa39JANqxkf0sYQnaI+S
         fFvnd/MJNa/ZAoNxsYgeLbkvWzMiQdeW3jZHj85jGYuC6wuLkJHCfQhHFyE4SxTEYp9O
         F1Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=b8YE7/2iTxIO116IaDBtgK3hGhuHFoE03KrKX32ZZXs=;
        b=FNFnFmBs8//63KjZiI7ep3XYPpMC49vdLAViQeR0E/s4vJ6gJocwAg8CM7X18PIuHI
         fzq+aC0ALjHgmIf7LL9+xHcczmmLRjYQ63chCtEZuOs92F1PXNZ/e/m9JEpNHnFaZ1pC
         7nGaX3nHVEQ036sCh7QU4ZOJWjLdANP7xtgqp5Kl7Cg+pT0Fv4840qsXM9LgExUJvqw0
         gzR5cIm4h41cp6smPDLeAr2SaFm1rRwk1Zvtg4+YINk8RWGoPsA4Cz001T417ebty40N
         fmdIXoaaySZNbrujJqNN7BkPWBd0Ql5Jk1UyO7Z8E0NnoOyvszB/vGzgoAs0lL5KKu0w
         ff8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b8YE7/2iTxIO116IaDBtgK3hGhuHFoE03KrKX32ZZXs=;
        b=VwVQNggSpb2Ve46QdPnRf/95JpnL0LfDryzL/5dcniDuyziBGmd6Aqp8fePLZHi8Vz
         0NO8voiLDZ+k1OeM7elMU3lkDkW6SfTI7MRQhCFB5HyCuPVOQJIc5r3zduMCwVknsQjt
         JZly4moRmJkX8xQMZqKtG2xOv9XZkD6Rp4bGtqJouJCNvOJq9vhfn3W8AVJ7KrcFFJsA
         bnLrqoe9AjMt768aBv24mMnS5puekjZ7FYtqg9fdFQIJLfZtgtCefwTzTacfITfOxV00
         WXmT96FuL2lu0h7LBMGAQ7tDVJzXiW5uZMTSxwyMTTT+MUlzDcUztzt+r1By/tZedz0+
         jiRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b8YE7/2iTxIO116IaDBtgK3hGhuHFoE03KrKX32ZZXs=;
        b=FEgEuxp10scy9+eQAHjtaUBWFCZsafCt4vVDauxsHiPxIYOluU1Kb+muo0lQae4zrX
         H8RzhcfPeiSehYTqE1kbC+Urp6FD7MaKSLQlONc3BYw2O2M+g1Ti4Ufy4WlZsF6qUyX7
         qvXncDCBCvWmjkpPPs0LFLYWyw9+ZP8VQVrjIB303+BmyFr0ayIGUgSvil4sNlNnzFIa
         ThHSfMj1L9K9gHvgfWm9JlP+YIfpY/agIcGenlxBUTnEPu2ijxtOeWvcICzwhNL+ioz+
         faSXG2jUPUCJ2Y9FNgPvFPhFdASf0U+3sEQG38buFV1C2xo8K6p1DghWYUX4YkTvrpTq
         chFA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530fi+6GxHHYaVTXmY/nsYGKE2yKqecgG5VVSlZsprdJV123HMdw
	zb1Wv0yEgDhsi+z4GOPrBos=
X-Google-Smtp-Source: ABdhPJzM/USpypwfL+N72TJuTMfZpK+IB9UgBcKgUYUWmz+KeFEZpVWZrJZb/ChEzV8EBCeS/thmyQ==
X-Received: by 2002:ab0:4:: with SMTP id 4mr868137uai.122.1606962665354;
        Wed, 02 Dec 2020 18:31:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:638e:: with SMTP id y14ls332902uao.9.gmail; Wed, 02 Dec
 2020 18:31:04 -0800 (PST)
X-Received: by 2002:ab0:6154:: with SMTP id w20mr928691uan.54.1606962664815;
        Wed, 02 Dec 2020 18:31:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606962664; cv=none;
        d=google.com; s=arc-20160816;
        b=nftcTZEey2VDUlHJuI/L8XiSMrhph0CorRE5lCeIXuPv9qbcoXS2XW/ixui02DE6d2
         tn6k631W51g9i5XIiSUEr2saqWbO1C2hhdoAPK9bW3HM3EmtWThIpkLnhoxUaX8VH7I1
         5altlje3N7w6JscRuqH7zpKR8SsZAnaf+nrfwGHrQORvGukA0pHDH7jx+MoSHHhoM9Fg
         sjQ12OxBVDFX1H6XYfVcGl6r66Q2EGjcTiShTGLvYhbya53QfriXAgQSu39eVJPhzeG6
         XN4V10Mp07b+pFs4IxYesFGi/7QC6ylKtLk68AJZYG3v9gA+jLcXRMN2Jekju9iWM5sD
         7Wlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=jWcKMQ/JVqAycMM+EhF+OdwUxhQp+NzRmrcB3HO2q/8=;
        b=J9Hwp6fb2wcw8SBzM6k2hbzJYLOH1REKI/AxGp+cXHRrSqGadTjCImBWNutDQvrjo+
         MsP1kvSzpLgb7+LAHVfzJzgNyEgreC6qIOS+KxApv9MMaex1oKITnHkYBvaoPnzrv2tJ
         GHh7/wfaCrO6RDvhtLAD4X7kfrjlS2Ou+p0QmtIhA031Uu7XZS+w0tblTWYFI2dlAt5D
         uVs8V1aXZ4aidTtqtNfz9aknumxrIfdpuY/IVyiiGdR0AsSGfX6DXtNEDVMZnUQ+yKWt
         VW3nFCB5VJwRoHSWXXOjcKnC9bA8HgWZKDGZNFfNZecUiYjcBkYOWsOXIFITzW1+5iuM
         M7uQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id r18si53142vsk.1.2020.12.02.18.31.04
        for <kasan-dev@googlegroups.com>;
        Wed, 02 Dec 2020 18:31:04 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 6f5e8fa78bb74a52827525f34941024e-20201203
X-UUID: 6f5e8fa78bb74a52827525f34941024e-20201203
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 205625155; Thu, 03 Dec 2020 10:31:00 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 3 Dec 2020 10:30:37 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 3 Dec 2020 10:30:38 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>, Jonathan Corbet
	<corbet@lwn.net>, Marco Elver <elver@google.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v5 4/4] kasan: update documentation for generic kasan
Date: Thu, 3 Dec 2020 10:30:37 +0800
Message-ID: <20201203023037.30792-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

Generic KASAN also supports to record the last two workqueue
stacks and print them in KASAN report. So that need to update
documentation.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Acked-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jonathan Corbet <corbet@lwn.net>
---

v4:
- remove timer stack description

v3:
- Thanks for Marco suggestion

---
 Documentation/dev-tools/kasan.rst | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c09c9ca2ff1c..3cb556ceb4a5 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -190,8 +190,9 @@ function calls GCC directly inserts the code to check the shadow memory.
 This option significantly enlarges kernel but it gives x1.1-x2 performance
 boost over outline instrumented kernel.
 
-Generic KASAN prints up to 2 call_rcu() call stacks in reports, the last one
-and the second to last.
+Generic KASAN also reports the last 2 call stacks to creation of work that
+potentially has access to an object. Call stacks for the following are shown:
+call_rcu() and workqueue queuing.
 
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201203023037.30792-1-walter-zh.wu%40mediatek.com.
