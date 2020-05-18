Return-Path: <kasan-dev+bncBDGPTM5BQUDRBKGURD3AKGQEOJ3YBRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4117B1D70DB
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 08:24:41 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 187sf6028339oor.18
        for <lists+kasan-dev@lfdr.de>; Sun, 17 May 2020 23:24:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589783080; cv=pass;
        d=google.com; s=arc-20160816;
        b=yuV6nO/EvGnys3dKioNrUi/yEjZEuz2koHuSAq4Mn3JVFIrQ66hxfdzEOBcLdwX/wI
         U816RL+8VvvCmqt5atiPHes41eY59MRizIWbDRmtF/p09yvrNwGvWJnM1iWRLAu75etb
         m5fbwA8sWNOAWs28RKlSG7sdzpKuCYsaWRMI7ATcCj+MzHCqNVwE2R4tBZ7xc7vDz8T2
         iJ1N9LAe1uXx6sT4oeREN517fUXBHT6h03GvkifGcxmPiq5q2xwo1eV4nx348zrnpHqy
         zEenLeysRrmKASsGrTh+Ov6JPIp2WKGMNbhAwp1BhCg87imRTddpIrnFTTU4h24ramK5
         3HIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=TPToW/Da9S/twHaGmJFe3NyoWqeobl7w4Twt1gVQSu0=;
        b=qlTbEH7Yn7VKFuxyd5MF69AxOZi0svWwkXilXmegL7vJlboz2xkcGF0NNKxgc3jZWy
         FiDz6fif0aE4BF8R1nXOkdqnJm4PMlSAx+FRuQk3qnGRcXdIm7Bcp3XEEj8s65w2nSe1
         iPAdBsdHGU2MTC/KnOLFnOsE5+5dQKKxNug4yicXWf1LD7SBCQ+NrNLKfDHqksGVhucV
         04/hzOOudG8d+RjM5jYA3pn07Lnzx60RDFSblgZGZ6IhRwWBuow4dQgM64Yi0k72Qdaf
         uIDTr6m4oagrZ7LIbM3SHtjbmWlnm5V5g3YBnSQHd3ou1acNjyYkgV0iuJuvm1V1TQmj
         I0fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=cKxnOHzZ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TPToW/Da9S/twHaGmJFe3NyoWqeobl7w4Twt1gVQSu0=;
        b=nHPtJLRlngw5Qbho6ld7saMfi3jhKvqCFF6dHOM+NPJ9gwI82Gk8DGKeSNAeWdBIxY
         yURR493aRXPmHzha0wlDqPZtwgNP33HYqWpTT6RpMRbvzYU1BKW8R6ZNPcuxeGHhrHq9
         hf8yz3FQ6OG0jUheQwmxCENL0Vad8+D9S4HvmgApVWKhgSTtF/VUcTNM7Y9xgGieMlNN
         y7wgW0bpFEwCWf/MroVYuzcV9664bSKRqbfP65CzVdPl2Q8fju310ZSoZwJty46rp3k9
         dhnKG5mjpnuwpgkWzgv+JbXkCiZiZWSeyvyvq9Pk+hD6Jk/j2TMh3u6AUzUt+QVcbNZd
         vf8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TPToW/Da9S/twHaGmJFe3NyoWqeobl7w4Twt1gVQSu0=;
        b=Oa+bnTvSVC9/6ciXz3b8kGiupP+XbEDYr6EE0oPkbra4jls0q63YsoHKI9Pns8XDB/
         ZTw6dFbg+KFYmvg20RjO4xOftAMKVVU2RXGf03U0s18xLOHPy/AnAzrtosnGDoIphrS3
         IG2jU3wrwczWLxn+DibwGef24WKKNv2ZlmYvWdGca8WNcqnBCCUuRQFjW64/6UVZohSR
         5bj3e8cOdFno7IpkUMI1Os9ifBBrSB6/qolZOTwymdUfn/LD9uY511/Z4zYIRSNnN+7P
         fmRVIHOm1NRX0JLWGV2WV3Q/eQVItIuorE6wwX4SIATNp3QJjMI3kjwj+yi3och5Prjz
         GA8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5303lVupbNRRCteUD2HGbXuC+aD2hXK1GGb74yDwpRdQdunEAPrK
	UuDO+ToEyQCSAM0gZc2HvYA=
X-Google-Smtp-Source: ABdhPJwEhNbFnmwaG9yKBF9f+3hfTZA8YrCLqzzh/21ohYbpS+2y294LQsL46plyV7SZTTHNfZ8BRA==
X-Received: by 2002:a9d:3f44:: with SMTP id m62mr10545250otc.38.1589783080208;
        Sun, 17 May 2020 23:24:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:61a:: with SMTP id w26ls1624675oti.8.gmail; Sun, 17
 May 2020 23:24:39 -0700 (PDT)
X-Received: by 2002:a05:6830:158b:: with SMTP id i11mr1542461otr.135.1589783079869;
        Sun, 17 May 2020 23:24:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589783079; cv=none;
        d=google.com; s=arc-20160816;
        b=FcGwdH6nnMzrjQEE9VDWvn0a04rWX5MNygfgxVXP+mbqMmydOVXbxHgKRrdCCgbkCA
         Ds5hqVxq3z39A4wwV5egTh36SXvYhjpe8sYjKkfi7LTTRiyGYdTxgcBbFW/90yOc5weV
         kvWtHF4lvKLK8OKP16LXtSQmaQkhI7zcFF0aMBcdsJNNhpFkMGlPtquj9+XTQ1jK1l8q
         xvLXX8KfUupO0h9Ddu2pQ5hQ+uvrDG9KX2FTQmCX1EMMl8dMg2qYzYrl625mPEgHKUm1
         5PfF1tlM74f3BrxQYckhpZB278uin/pMIHndvCe6b1dHIbAeAMG3MByvCmwq6ArIljhI
         yZ4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=YxP6/pRzTiTVu/hcxWJ9yeQQWJwxGnsvUO9djcnnF3g=;
        b=A3QwfPSKWyJ1Pw6UdSwIiRyRG1Jo0KTU3+Xp9caD0Bwd6Tc984TJ91oxBq/XcHtYWE
         tUzelHzWDKipAEc0vmNo7eZEFLj4I/SdpM9kMH4gsP4bz4epeTUUh6hQvh1zY1QkqAuD
         nggYoWbb8Evi9SYvaoGjpgAWAFxKxGHJLetTRw8PqkSwmrOQSq7tAeghOMWyEmLNX6x+
         ZRS+pGB+llVYRiJ5O2XN9avvBV8YglVXRz9YIj/jEage3xzxeDpK+1bQ+wB9eU3patg0
         QpmTWU31T4h7Js353FpvRfyPi6mS7m2vBAOI4KBvQt6Xue8S0k6/mlDy6tmFbDW9BY8+
         Pk+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=cKxnOHzZ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id t2si503835otr.1.2020.05.17.23.24.38
        for <kasan-dev@googlegroups.com>;
        Sun, 17 May 2020 23:24:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: f088d455daa247d4ad72ad03289935f7-20200518
X-UUID: f088d455daa247d4ad72ad03289935f7-20200518
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 442368184; Mon, 18 May 2020 14:24:34 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 18 May 2020 14:24:33 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 18 May 2020 14:24:31 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, Josh
 Triplett <josh@joshtriplett.org>, Mathieu Desnoyers
	<mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>,
	Joel Fernandes <joel@joelfernandes.org>, Andrew Morton
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v3 0/4] kasan: memorize and print call_rcu stack
Date: Mon, 18 May 2020 14:24:32 +0800
Message-ID: <20200518062432.4508-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=cKxnOHzZ;       spf=pass
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

This patchset improves KASAN reports by making them to have
call_rcu() call stack information. It is useful for programmers
to solve use-after-free or double-free memory issue.

The KASAN report was as follows(cleaned up slightly):

BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60

Freed by task 0:
 kasan_save_stack+0x24/0x50
 kasan_set_track+0x24/0x38
 kasan_set_free_info+0x18/0x20
 __kasan_slab_free+0x10c/0x170
 kasan_slab_free+0x10/0x18
 kfree+0x98/0x270
 kasan_rcu_reclaim+0x1c/0x60

Last one call_rcu() call stack:
 kasan_save_stack+0x24/0x50
 kasan_record_aux_stack+0xbc/0xd0
 call_rcu+0x8c/0x580
 kasan_rcu_uaf+0xf4/0xf8

Generic KASAN will record the last two call_rcu() call stacks and
print up to 2 call_rcu() call stacks in KASAN report. it is only
suitable for generic KASAN.

This feature considers the size of struct kasan_alloc_meta and
kasan_free_meta, we try to optimize the structure layout and size
, let it get better memory consumption.

[1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
[2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ

Changes since v2:
- remove new config option, default enable it in generic KASAN
- test this feature in SLAB/SLUB, it is pass.
- modify macro to be more clearly
- modify documentation

Changes since v3:
- change recording from first/last to the last two call stacks
- move free track into kasan free meta
- init slab_free_meta on object slot creation
- modify documentation

Walter Wu (4):
rcu/kasan: record and print call_rcu() call stack
kasan: record and print the free track
kasan: add tests for call_rcu stack recording
kasan: update documentation for generic kasan

Documentation/dev-tools/kasan.rst |  3 +++
include/linux/kasan.h             |  2 ++
kernel/rcu/tree.c                 |  2 ++
lib/Kconfig.kasan                 |  2 ++
lib/test_kasan.c                  | 30 ++++++++++++++++++++++++++++++
mm/kasan/common.c                 | 37 ++++++++++++-------------------------
mm/kasan/generic.c                | 38 ++++++++++++++++++++++++++++++++++++++
mm/kasan/kasan.h                  | 17 +++++++++++++++++
mm/kasan/report.c                 | 36 ++++++++++++++++++++----------------
mm/kasan/tags.c                   | 37 +++++++++++++++++++++++++++++++++++++
10 files changed, 163 insertions(+), 41 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200518062432.4508-1-walter-zh.wu%40mediatek.com.
