Return-Path: <kasan-dev+bncBDGPTM5BQUDRBRUXUH7AKGQESD7P7HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id A2CF92CCC60
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 03:21:59 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id s29sf752285qkm.3
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 18:21:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606962118; cv=pass;
        d=google.com; s=arc-20160816;
        b=uOb3Ml2wVM6PzjFBCL4arp+t6Sx0kU6hQ/nZszIfsv3+uxRVySxCOyN+B6wmKIs7im
         O7+R7sTdxlEyaB+1VbwRuWeBMm3vmVC9rb4i+6wNJEa/g0Ytmbf5LjF2lRvh+r8IpXLf
         tdt+2znxnjnsi8XodLfFGt44Q6k+E4U18aNV2YPvAEgcCC1VpxlR1jG+kCb/VoRnA67v
         NFEyrdGV00lk2Uy33gCZpY9eY+fPjIhZRyvrQMsYOctp0/cEDJhyYz8Q+FXC9n2NkZ6D
         WUjGrfD9zOh5zqUHZWx/PUaToWXYuWQE5gTpU1Br6vwlfYPFA+XkjcfPzjTXiK8JCtHe
         OBOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=+isizjCe+bCTSTzWHvupVk0bOABKZeFFWulYRSGhjWo=;
        b=C8NwaW/2imaaEsc39RyxOu2iDxcKHExgAODlxdB7DC6zudGgOqalmIBtmCxLianknK
         A0Aey7Li4Prl6SvFJpod8MMUb7GwL+zsJulWBR2pGzu5odFD7yFKG7+OLRCYMYy7Lv9M
         BtpIfAroG505mb+2M/V3KY96TSt/zlFwqLGZwv/WloFDSWMqfdgbHRKmw20UTwVHheyO
         XVmGA6a4QJhiJR8+8SEQ9UQ20q6IIbk5ONCMWVDfdGelOpZcmG590Qi3fmv0qxI0LO62
         HeRHEgMa7F2ver6d5htd+1/LBJf/fbHycO/tfsuSuNfNSzeK0nXRETqZQTnE/x8mxDr0
         VKUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+isizjCe+bCTSTzWHvupVk0bOABKZeFFWulYRSGhjWo=;
        b=lOBVrsNspUC/e4WjqnWO9nZKsVM3dN4I+XyjOdngz5/p8VE5ZemWb5rm08I8IH+75W
         1mfRQZRV3QOJXQsAndLtNfaUREr3GWuLRjrvbkerWNNJIjq5F2HUVKuZeDZzsof3esUF
         wik8mCr/sf0UsZVtqAR5abpxTplyphdXwfvJ9VbFZ8X3lPCFQBPcxZvWqpSo1/mFo2bo
         EB49QRV/hhdDrHosyGNOXBo/9cab7Wy8r9QCTUIvzyAlVGUprSKSqC2/tuBPFvXz2qEC
         jd+Fu2babMHYjYUAhs4HrjFHhJ5Ku/zhh32hw4BG4pPZBIZ5tPwxxkeYe8imrCcuOFO7
         n4KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+isizjCe+bCTSTzWHvupVk0bOABKZeFFWulYRSGhjWo=;
        b=sDCus8W7SGDoNcd2E2nQKQ0ON2w7go02ozec8c89CvmmUwpupYIwzncERrsh0je/DI
         Fv2J122kY5Y8ZKa/D7W5cwN26wCgR7pPXcCajL52ZLkh3giQcVa5WWkINvfRM/MdJaX1
         nqGqOhTVFZsmVoF14nOxLQN3bLlu7LETnkcMqmisvZC7cbhd4zrxvmcTMW1zxLtPefCJ
         HxXq14e+OtdqXyh5cTbck41Q1j55x0AxTp184nMkkxHdtAWPgYaZXa/egW0DraOhEmcF
         kNLzHHIiHQMtx1yb68QyxSbP6ie2g9lTeRytiEqx4J8VjF1SdSkSNDqH//EAaEvCHkGw
         cUrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mM2+Eg2TV11xrSjJOglU6kZDQuh6jVKZSgsxnBiHc3fYgqbbu
	L5kERTJvkD17faXKyWKlc3E=
X-Google-Smtp-Source: ABdhPJyoooZ3G31y2J3X4gUypZiVIFniOKIu+NSrGWZrs+1OHE0aEImi6RjLo4zz8LtktFoT+6RAbg==
X-Received: by 2002:aed:32c4:: with SMTP id z62mr1240889qtd.50.1606962118638;
        Wed, 02 Dec 2020 18:21:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:36ea:: with SMTP id f97ls1417447qtb.4.gmail; Wed, 02 Dec
 2020 18:21:58 -0800 (PST)
X-Received: by 2002:ac8:71d5:: with SMTP id i21mr1270712qtp.4.1606962118053;
        Wed, 02 Dec 2020 18:21:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606962118; cv=none;
        d=google.com; s=arc-20160816;
        b=S065pM/k+q9j5w0wrpGPb2rdnHX9c7xAgqRh+8NXg8OKEGgdZ9qj89mKIJjqIjNKrQ
         MEUMlCsHExqrPca3aWogWKrM/AOwjA1+ZbWAF6l3x+2F3cLHzoU2B6Bdy36Kj+7lj1hc
         yYfMxbh7FmRQqjVg+wN5bmc/thHGgd9GT+HDM3Ci4OwA7zMH+jTzZIjTzxZ1MhOXXGSv
         pQQKuVfyTfbZeRM2nurEyNqCFhZ07AflA5sFoQfB0il/fELgcH1YgpBuFu82wEZsKmoj
         PnVZDF0OdYeEDn4lg8AlsRkVlk/4tq2NkCJXZTt2nrHT6hNGNH0juOovhjmzmYt3wlZq
         VYQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=2kTyQM18OjXa5jDe7ZCyNrJHu6mLY/DySS9qhlUox6k=;
        b=IonV3fKcG6dv4cxjx5XS2sN7pc0y9NgqtFyMiX2kVwtHuqDsMCHweWYqmCtPqTQfsX
         mOB3hYWpTsqLSmIuyhbpIWIjazkI2ysYqmi60jEkVbxfQ3e2nVf9lgxNEE3ETdCrYNU5
         xpb/XdxDcwBQOSzlB54ofBJt6sWtlJ0bldKfPLmmIEBZRr7LNc7J8VAhAIh6bBCG0TPf
         JJbDghALf6ginJP74xalG3/wuBPkfLA+tRwRWSPP41rCm6Tum078djjtMgNn5gP6EDL0
         CznStKe7fgB7AqOosthUCv6Ngtf6ByRoYfgsKK+ldx29GbR+fkgA4En5ZzKG7aM7N/bS
         Pgmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id k54si43388qtk.4.2020.12.02.18.21.56
        for <kasan-dev@googlegroups.com>;
        Wed, 02 Dec 2020 18:21:57 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: aeebf121efbd4d459fec7a872a8ac5b6-20201203
X-UUID: aeebf121efbd4d459fec7a872a8ac5b6-20201203
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 2076224499; Thu, 03 Dec 2020 10:21:52 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 3 Dec 2020 10:21:48 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 3 Dec 2020 10:21:49 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>, Tejun Heo <tj@kernel.org>, Lai
 Jiangshan <jiangshanlai@gmail.com>, Marco Elver <elver@google.com>, Andrey
 Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v5 0/4] kasan: add workqueue stack for generic KASAN
Date: Thu, 3 Dec 2020 10:21:48 +0800
Message-ID: <20201203022148.29754-1-walter-zh.wu@mediatek.com>
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

Syzbot reports many UAF issues for workqueue, see [1].
In some of these access/allocation happened in process_one_work(),
we see the free stack is useless in KASAN report, it doesn't help
programmers to solve UAF for workqueue issue.

This patchset improves KASAN reports by making them to have workqueue
queueing stack. It is useful for programmers to solve use-after-free
or double-free memory issue.

Generic KASAN also records the last two workqueue stacks and prints
them in KASAN report. It is only suitable for generic KASAN.

[1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
[2]https://bugzilla.kernel.org/show_bug.cgi?id=198437

Walter Wu (4):
workqueue: kasan: record workqueue stack
kasan: print workqueue stack
lib/test_kasan.c: add workqueue test case
kasan: update documentation for generic kasan

---
Changes since v4:
- Not found timer use case, so that remove timer patch
- remove a mention of call_rcu() from the kasan_record_aux_stack()
  Thanks for Dmitry and Alexander suggestion.

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
kernel/workqueue.c                |  3 +++
lib/test_kasan_module.c           | 29 +++++++++++++++++++++++++++++
mm/kasan/generic.c                |  4 +---
mm/kasan/report.c                 |  4 ++--
5 files changed, 38 insertions(+), 7 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201203022148.29754-1-walter-zh.wu%40mediatek.com.
