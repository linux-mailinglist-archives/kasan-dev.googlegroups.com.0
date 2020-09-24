Return-Path: <kasan-dev+bncBDGPTM5BQUDRBYVUWD5QKGQEDGKCTVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E7E3276777
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 06:02:43 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id s141sf1181899qka.13
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Sep 2020 21:02:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600920162; cv=pass;
        d=google.com; s=arc-20160816;
        b=HAeo/7sSpUhovZjcExwLQcBhdENG1XI5EG5kucHH45ke4gDNd3npmEiOvYkcYCw8xX
         6YEa32jvYJgE18qnATIr8iAq213jnKI+m8z9L0EJJ7ceD+LfammazLESxEpyaybmGIxe
         MrVNSTbo0qKuEi80E+1OO5qdpPxHie76bRfQmumvBbKH+WIdyCs0GOf614zrOZWPTaAa
         0T4t31RaIMixo+/GYWoP6ht8QuTQ2oNvnv0ykP1Vxmvjab6hP8yUdvx7WffKjSJncSvF
         BDtWzVwuLJbrUQARQvqzFYLpCXd8U5ChlLz5pLqvQYuWTU0pIAaOQsI9W7pUt5KLjbzl
         0aLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ipaP3rdyjdwGjnVxGQkF52SdpLgN2bIQy0RdwvIB5o0=;
        b=FYLGeuJ3DjKenK+fbdVgRJutL67Pj0hHJvBgmwRe9Kg0CQKTw1xFfN+UisNecDsU4P
         c5eukn0O2vJl5OVj06fFco03F2q2RrBPnCG6MNZeBpmruBBRuQciY9njZmT7DtIZkfdF
         D43hri1LV9BtL1ZuVDWo/7RE1wrCF7TKq8eIkIpV7Z6ogdLWWlXNGB4Hwdt3Q3TUJw8y
         ZSmkqVoJV8PqYVD+CPCoUWrnaPbyswre8IsjguFKjaLfh70FM10X6QZjLRJRB5yBUfjD
         4y5/420+QzIi6uO2tJ+kuAXj6OMSIlqjEYRBYsZiVqcP8Be3by9yHGOsJPaK2WeuBOWN
         8GsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=RQvO7Iqa;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ipaP3rdyjdwGjnVxGQkF52SdpLgN2bIQy0RdwvIB5o0=;
        b=lcfcfaZskEQcr5VDoivE/dPzIUi5MZa2InBSpbG2Eus9o7+xxYkkTXCYSySxnnm8hI
         QXW5XO+MJTZ8GS3LStZUMVjaX2A2qMrb58kpktIdTq/QAJm5dkNk9Yeue+DJWP2qfY6U
         QTLRFtSyXsGJl/j0OIm4CTGb1RF3J7mcn+Wq6nlguBafzoHt/30aNdpSKiBLtn+Es9Dg
         hhhUi7hcpTWtwju/IzrvUKONazfAh+BQlRQKdzSg1GA71MeenBX1bSzP71aKbc8jRK7o
         7XIcZqkNa48Ph4u4EO2lGCvyk4uP/NJu0FMpJqZIgfAiie9uOfJ46E8onAZPuzkyRBKq
         D5vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ipaP3rdyjdwGjnVxGQkF52SdpLgN2bIQy0RdwvIB5o0=;
        b=tNUsZMZ7zPbYFEC0ijwTMUoN5ltmb2rykAnGhcCIcWXwqqwOdjeck+EaLc3jtkRYTG
         qFBpE/DvITVcSPZKePymeiipIewSFsdniAjmGl09/7IH4R2PTv+08IfNujHfDjQxChyn
         JPRr2rj8Albo60aSk3erQ5vIIARqU/9K7o5g9HeKSn0+f2JGEk0HcqVqyAwcAhgFmiY8
         OY44h5lMmvS9h7yhiwQUk/o4wtcm2wkyuDMjndGLhepULrpG3Fb/lzt0Fu7O1BrNgBx8
         YorBEPQkhDz68EDxFWBI1FgIhcfRtbOk58kBUulSoQGFYMSL1LaobFqPEOGrgObOBlpX
         Bycw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532oGljziML6OWmqYmfquw6kY1zxrwzgXmdX6r9jm1rJj4jqQGKg
	RXvdx61e3g8ZOS+FC5SwwEc=
X-Google-Smtp-Source: ABdhPJxndyx8sZONXQehw8TQYc8+Gz6dX4rKHVvncqDS5kmA5M/IIqQUGLZ/g/6q91CNLtY8q/DoAQ==
X-Received: by 2002:ac8:7b95:: with SMTP id p21mr3451011qtu.139.1600920162128;
        Wed, 23 Sep 2020 21:02:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4d4:: with SMTP id ck20ls493283qvb.7.gmail; Wed, 23
 Sep 2020 21:02:41 -0700 (PDT)
X-Received: by 2002:a0c:b21b:: with SMTP id x27mr3327697qvd.12.1600920161705;
        Wed, 23 Sep 2020 21:02:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600920161; cv=none;
        d=google.com; s=arc-20160816;
        b=dnPyUW+0Ec7lOYiDngkqfHs7GEvnp8e0aJq/wM6LqUUf6Evwr6SFth9OsLBZd3DCQY
         HVodhCNvFXLuAX0VKvvwK7FVd/9GLqOFFgE2PQ6pZyKt0lorXyOdVpqG7KpcJRkAFAP/
         F+JP3X27rguO0GvAFPuxoA8+TVs2uR2GGDV3AIZk6bAULOhDvskofwIZ2Z0WUGU+RPdc
         LXuCL6z7z3HMllqhpFU4hBID0DeQa/DnLOcxB8xH+ahwANUzDwZPDqBoHmBcybukMFDw
         z7ohsZno6KCL7TSlTZR0pqgNnAbtgMhwhBKX1Nv8eA87Fji55owkm401YALD+7S45Ny0
         YZrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=RdjwgzjFAA7kh4oYttC+KDV9EMdKnsHtZfsovneYDmY=;
        b=u4X3BQxNeUpQrKwGkUaPoxfKaCrOopQ+A3HRewyg9huJnT9jEJjESFNABgp0k/62ca
         7ouFJggW26lf2d5NSrL3qbEkTzvVwEAsBws6M8peg7wmoNlJHu1OZ/5fOQo0H8kZSr0a
         Ufre+5XMUMqWMFu/roxuaFQ+KxPYZfiHFnHpTvj5lwhfRGis4CvfLhJaXv9XXakS/WrI
         LJHv0UNK69amdI8jTkIU7U18OvYCaT0ae2CHoItHxrmzYSIsI8u8q/ug8mGEi+cfqGfg
         pFiVZMfiXix/kc2cmCyBmGtgtDIFDR2kzNT4cOpXO6PRIPIGlXoQEaHFlJt65a1NqVP2
         t6hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=RQvO7Iqa;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id a27si130780qtw.4.2020.09.23.21.02.40
        for <kasan-dev@googlegroups.com>;
        Wed, 23 Sep 2020 21:02:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: ea9a012e0b7743eabc5607017e117eba-20200924
X-UUID: ea9a012e0b7743eabc5607017e117eba-20200924
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 2008707020; Thu, 24 Sep 2020 12:02:35 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 24 Sep 2020 12:02:30 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 24 Sep 2020 12:02:28 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>, Thomas Gleixner
	<tglx@linutronix.de>, John Stultz <john.stultz@linaro.org>, Stephen Boyd
	<sboyd@kernel.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
	<jiangshanlai@gmail.com>, Marco Elver <elver@google.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v4 0/6] kasan: add workqueue and timer stack for generic KASAN
Date: Thu, 24 Sep 2020 12:01:52 +0800
Message-ID: <20200924040152.30851-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: FB7A3B37DFD44E891641141635D054C21024695F78B6E62C4D04FF435D1CC3DA2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=RQvO7Iqa;       spf=pass
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

Syzbot reports many UAF issues for workqueue or timer, see [1] and [2].
In some of these access/allocation happened in process_one_work(),
we see the free stack is useless in KASAN report, it doesn't help
programmers to solve UAF on workqueue. The same may stand for times.

This patchset improves KASAN reports by making them to have workqueue
queueing stack and timer stack information. It is useful for programmers
to solve use-after-free or double-free memory issue.

Generic KASAN also records the last two workqueue and timer stacks and
prints them in KASAN report. It is only suitable for generic KASAN.

[1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
[2]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22%20expire_timers
[3]https://bugzilla.kernel.org/show_bug.cgi?id=198437

Walter Wu (6):
timer: kasan: record timer stack
workqueue: kasan: record workqueue stack
kasan: print timer and workqueue stack
lib/test_kasan.c: add timer test case
lib/test_kasan.c: add workqueue test case
kasan: update documentation for generic kasan

---
Changes since v3:
- testcases have merge conflict, so that need to
  be rebased onto the KASAN-KUNIT.

Changes since v2:
- modify kasan document to be readable,
  Thanks for Marco suggestion.

Changes since v1:
- Thanks for Marco and Thomas suggestion.
- Remove unnecessary code and fix commit log
- reuse kasan_record_aux_stack() and aux_stack
  to record timer and workqueue stack.
- change the aux stack title for common name.

---
Documentation/dev-tools/kasan.rst |  5 +++--
kernel/time/timer.c               |  3 +++
kernel/workqueue.c                |  3 +++
lib/test_kasan_module.c           | 55 +++++++++++++++++++++++++++++++++++++++++++++++++++++++
mm/kasan/report.c                 |  4 ++--
5 files changed, 66 insertions(+), 4 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200924040152.30851-1-walter-zh.wu%40mediatek.com.
