Return-Path: <kasan-dev+bncBDGPTM5BQUDRBUHASH5AKGQETVPZPTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id A1245250E72
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Aug 2020 03:58:41 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id f10sf1831500pfd.18
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 18:58:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598320720; cv=pass;
        d=google.com; s=arc-20160816;
        b=OC51at06d/DfwZJ27Tj3V+zDY4HfkNEKKc8Lp8xo2EnZQnBk5ib9VdfltzMS3okB+D
         LepON0fNME1uPJ6snE7f9fZO5W5OL9DaOyza6tHQBAXpnTDh2H/B2OLBuLxDU04JbkIZ
         XPwmwPBxHKg6A5rzE25nDXSjio7Zu8dWryIrxOKDmovr0QagbbzLfytld7WilYNOKS8M
         5CEInGzFrqfI+e4Huq4aY7uCWVED3p5JXxuciUBXU9DReWQEYx7SPQ4LEngiaWd9X/kV
         aNE/Wwe9AtHt2qdgfBGU0ehNYt5OmiiPefBQhsMaQeQq+pMW1wkUV4EVJ5ScJLc0snSb
         HyMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=0PcBGZATdQKoeSXqLCzxSxa3BM0h8vFWXTdccJb7RkE=;
        b=kSMZCKNNuQm+vZlhoOda2sFP2cxKV+sULetwfjtuVplHy1NEI5xUyiyxzNrMYCIpC+
         MJuqI9Fzsi3aK2a+Ww1spH729P+KRYYh+yg3NThTgXlzj1QZOivTn8VmHUD8KmvHUezj
         bVMrv3j3d512yQCoiLG8pafyldSTMam3P2vOnxnNGhDP/k+aXqwRo9C7n5+5OlhVlCms
         Os3rgKRuZUZJdvygqUw+2q3kYvzNKhS55WmH7ILZWP8LxhdGE4bR4t5JzO6VFaczzdcP
         sT2LLo9qm74MPXMsj6oA/ndepyrECIJozGlvG6knaeK+/b/TfF1Te8Nb2dD4QvaqqJvL
         p8bQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ehXeURId;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0PcBGZATdQKoeSXqLCzxSxa3BM0h8vFWXTdccJb7RkE=;
        b=MwUw6KTR1dqrR/qI2rZ2VSv9tqShErCo6+8W/C8HwC9wJ8AugVEunUXAkvma9+sha1
         lF2gVzHy7axZvCBCao9KAz6gCLC7e8w9twpSZxZDVuV/BHHBH/SB3LHA9cw/pNRLYXtg
         iT8xvb9+LBv6qI+eP5ZeN53YD1UC4ZfA3bc1lD/9By5CfaCa84Da7VNgX/WLQ2ACW6Q7
         IMnark0eGMlYlsHWkDi9FsKVxzcrn1k7SgYf08RU1rFFy8RpPZMT8OHXq+YSFXVl/yiY
         9seLF12t9RhAbgEyinbk6e7kEHti3+8zn5+rIZh0oI7es6AUy+0XZrPoxvrrlsdwCzq4
         DBZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0PcBGZATdQKoeSXqLCzxSxa3BM0h8vFWXTdccJb7RkE=;
        b=iGG4PKzLnC9aBiMMgoP/slhpKAu7gBfBnpIK+8IA5k9XdF+FPSgs17h3UDshzko0DA
         3x5TqiM/FnJVkmqLX7i3fwzOJ2iNuNwrwnepAokZDJ9inxaB4/ne8zzDGk/rEIxfGw++
         odwN7k/KsUIOtUs9gzcoEGqdJ385YaP5qM5X81L/mrq1O9pcnNjAjb1v36Jcjxtip/2Q
         wGp1+DifbC3K0Xbm0R+wD8ZVtb6S2H8adbzVx2H1dtMjXCunGImLZMhKj6Yh6zJO9Kl0
         Eus4A0ieeljkctLp8uEaoGTBC124u0EURMCloQF8BdW0WxVmbXAWLyDgS73X5SdqIPYB
         7fSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cVIrpIQsEO8ErIV0mb6fnRDki1O+2tROMUgFnSCJ+/lXR9gRO
	fuknPXbhc8PNV5FQx6rrufg=
X-Google-Smtp-Source: ABdhPJwRV/l3jSVNadSQz7i09Rr1FaBrW3J6o04qI6zc1gZETbEqj/zhIaHw3jpmHaJB8g98BJFVVw==
X-Received: by 2002:a17:90a:1a02:: with SMTP id 2mr1626007pjk.95.1598320720333;
        Mon, 24 Aug 2020 18:58:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c244:: with SMTP id l4ls1844874pgg.9.gmail; Mon, 24 Aug
 2020 18:58:39 -0700 (PDT)
X-Received: by 2002:a63:ab43:: with SMTP id k3mr5386307pgp.426.1598320719876;
        Mon, 24 Aug 2020 18:58:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598320719; cv=none;
        d=google.com; s=arc-20160816;
        b=gWHGvsuG/LYdCiL77lpjoRk/ZhWv7V0OP9eoYYnYnwSGQ5VK+nhswAA13nsz01wgM3
         mVCU2Q9+mBQ79zqhxczZyTGJ1gmJpTpqFKObcG5vaqO9LSBkgJz4v80h96gPwjCZQK5v
         L287v6NkCLuDuCuemmLBrumocxDwzXq8EzW6Sduao0GKb9dEtfJXav03KfkOnf0msAIN
         Bl3rSMKm+9jYmEJht8gKWLDRXOY/2MYiZ65aQfG5vXa/ISHBhvruoquku3BcbHjHml22
         lo1yRn6Nwf0RStiKEzaYZEB+7KrXRhfMPCtjzs78sux3qDLliV+rYriVZL0efqQEGlce
         gFAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=QjiWiguuQ5aBJrBkNVTbpiMEZNHatuVj+uLpNS9djNY=;
        b=aMr3uYgJUciWqR6Kgbn/f7n1phRlrzHQlmpPcjha7WIrY0ZuYlfb8LBE4NpuTXTDw3
         2t6La54602mDVqxE/wcA+cORKPzZabRTUG/s9eO5Q6RuISXSwQ6YMRY0aJ3jkcIEQAhZ
         Og66QjumPmGqJbSqELHC2kTFJHNNVDxWXrWGHhAKjTBHFFO9Z2HDBqy6TyLl79UPulDs
         W0fsZqsh2iEe2ZDYuCCOTIdvoG9T1J+8+Fne+46Rqn1ns33eW1IWy3L1Z9hy54Z0wBGx
         iA8IdWyTSgVjVNi7c1kEEX/9uJ7rJRiOUDP5JexmiuyIojSHiLlkWS2ge/Dp1SqQF1kK
         JYhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ehXeURId;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id o185si222038pfg.4.2020.08.24.18.58.39
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 18:58:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 0684c9f2029942189b2e2ebe3781934f-20200825
X-UUID: 0684c9f2029942189b2e2ebe3781934f-20200825
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1742342722; Tue, 25 Aug 2020 09:58:36 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 25 Aug 2020 09:58:34 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 25 Aug 2020 09:58:35 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>, Andrew Morton
	<akpm@linux-foundation.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
	<jiangshanlai@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v3 2/6] workqueue: kasan: record workqueue stack
Date: Tue, 25 Aug 2020 09:58:33 +0800
Message-ID: <20200825015833.27900-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=ehXeURId;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
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

Records the last two enqueuing work call stacks in order to print them
in KASAN report. It is useful for programmers to solve use-after-free
or double-free memory workqueue issue.

For workqueue it has turned out to be useful to record the enqueuing
work call stacks. Because user can see KASAN report to determine
whether it is root cause. They don't need to enable debugobjects,
but they have a chance to find out the root cause.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Tejun Heo <tj@kernel.org>
Cc: Lai Jiangshan <jiangshanlai@gmail.com>
---

v2:
- Thanks for Marco suggestion.
- Remove unnecessary code
- reuse kasan_record_aux_stack() and aux_stack
  to record timer and workqueue stack

---

 kernel/workqueue.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index c41c3c17b86a..5fea7dc9180f 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -1324,6 +1324,9 @@ static void insert_work(struct pool_workqueue *pwq, struct work_struct *work,
 {
 	struct worker_pool *pool = pwq->pool;
 
+	/* record the work call stack in order to print it in KASAN reports */
+	kasan_record_aux_stack(work);
+
 	/* we own @work, set data and link */
 	set_work_pwq(work, pwq, extra_flags);
 	list_add_tail(&work->entry, head);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200825015833.27900-1-walter-zh.wu%40mediatek.com.
