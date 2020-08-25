Return-Path: <kasan-dev+bncBDGPTM5BQUDRB3G7SH5AKGQEPIECRAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id F1A14250E6D
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Aug 2020 03:57:01 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id g13sf636501pju.5
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 18:57:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598320620; cv=pass;
        d=google.com; s=arc-20160816;
        b=VgUWD9w1FECuVRANuODmdptSn62K4pQdwIKOPgEMr3v1kWM2G7K2XO0tO12ggliyNP
         jUmCpUS5fEx+Mhj2I/pTskliw4TctyXAeu5Y2qWGnxFP4YPOt8t3oR0wPwUbjobfKi5H
         LklIpfG3Ld9uVCXmk25Pqv7PuhNoxbqTKzAN0AS8deoBzGR1T5VLfEVHLUw8p/5NhYCF
         KTlvEgEKJcb7xSwsV0aJ98zrki2tNdI99A4jAWGhUrEywdb5OpPINwK2vHFZrootIrVK
         N3aYm3uI9CsNKihxbvIBnQp68p5EYOcRddGWMaJ/ItJpnzFzkhOfUWdMVuyB7xSSIMJs
         NdJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=rGKyDCAcLHmpc7tLxGejoRJ4aqV1jYUZwRuPHq4Hy5E=;
        b=mHFBq3Oposx4t3GwEkrcypfEKLGfcH077LHIXE4zTUXGtgs/Ce8iUmbZww/WKMgLYC
         QKBKikvft7o1+log51BqGwOS01E9+6dS5ZfdBW4amAa8lT7sI3wolXDNx4YZbWm8FTAY
         agZIySKWmG53OPlINB5JkxvfAA1cgyv7nXxGeya6DgOtuGLxGO0W7LNPrG5uOxjq/qTy
         OWHadVNDUx5i/I7+AD5KfsAcoUEhNwkMdkBP7+9nYPvqXeL/bm4ZFykW9fFpZ0C7uvRc
         vmSLu4ybQz6NqQsViMWj/XnGP0383JBqoxIUV2L/kungamc6TBSJrXtFZ7LIFlN0/TQs
         FCRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=vIAQSCJL;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rGKyDCAcLHmpc7tLxGejoRJ4aqV1jYUZwRuPHq4Hy5E=;
        b=bdsqNyU5MkgDCybKKH4/ngzhWbjrUou9EsiA/UAaUnQ+jxCRW3kPZgDIMk0MVDt1m6
         20R0WuvRyU00gOguZkc/9qplZGpGd3mU1lLg+zZcTbIdLLJ3LUvIlFq9NH3wSt9rQDWl
         n08NWQAIYgo/XBxY6Z4Pn1lO2UfVCJN5YFwQ9VLFnRLXV1NvTA0JlUaujoMRjjysApjl
         +4VFq+KuqSdMcg+fkmDKLc3z93P+Uw7CpLRtmdSDZcKQoBo531rKsUQR2be8dVj0uKiu
         14AGiT9VJM/eBd7p6swKakIx0/jWNEbcNPQ4LVrxdFLrbe49sat6pF85SkwDiJFy3ZJx
         5eaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rGKyDCAcLHmpc7tLxGejoRJ4aqV1jYUZwRuPHq4Hy5E=;
        b=eDChVnc1/ka+6a5yxXiRvU/vcgN8rURGB6/iu3McHcjxt/A3YFNncC8Prnn5h+CSz2
         Q14Kh0kZgHJK8VNexcGiyvA4vELKUlJTHvrGGuEE7t0BzcMDNZCaalAgRPBhRa0xOlM6
         CVToW/uJ7t0JvIR2O3a/YSaS6URDSP+GmuqEeDAqfDmrBX1UFRvPlyzT8mrJGwo+5QHi
         EjAaeLR4N1RBrYGSscYQ8rrxncceNvx2YEgn5U/EgtlL200jzhlm+AxFp0IAYiTeVxZI
         5/zyHjxNGtmRBwNtxP3P+bTEAFWWYV8TJdREkOMhGa1dyk9hcmrb3TtRK0cabKNVJOFa
         YJkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gBNkugo7KgRhKT4zgcwZDGxswrYUFBTqICrRJXWPscs55WltZ
	X5H0ZSd+s32df9p5stuJxEo=
X-Google-Smtp-Source: ABdhPJyJnvyU4wAoMUqDo24Ne+JhRMWP+h6OiXNEeaRm9mcZ2I9RjkXAIV6lkUGvN9UBQXnwUdb0Ig==
X-Received: by 2002:a17:902:264:: with SMTP id 91mr5970738plc.88.1598320620399;
        Mon, 24 Aug 2020 18:57:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:384f:: with SMTP id nl15ls584636pjb.0.canary-gmail;
 Mon, 24 Aug 2020 18:57:00 -0700 (PDT)
X-Received: by 2002:a17:90b:1182:: with SMTP id gk2mr1778873pjb.172.1598320619946;
        Mon, 24 Aug 2020 18:56:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598320619; cv=none;
        d=google.com; s=arc-20160816;
        b=QYYFbQgP62Ye26oWTtzcEOSu8kzvZoZ4IKD/wUPBXBpJ7kWatn3KKiWKkluO2LKW6v
         NMz5lkpDVNHSS2G21fppnq+BeYKshLvMmqZxnZRsWtfuHHw5jurXrzuZrlMphXNvylGR
         Hormk3XNY87IdSHAbuPyvczAEEtqSc1UjlYzCI6/lrjxJgpwUmBdKfLBI4jyMB/k+EG5
         9IkSf7QRKAjIbOE8pi7DsTlU84RwiGC1qcroEfF/KAMAxgsvFwTUbnpny42/jqyo5Mz0
         6TxFEdbgajRT66gx77b3P9OubAILaJSRvSziaKDo64iLSqvJhzrVDO4S7tzvatFKHmUo
         CSmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=dui2EisGgR0+t0THBhS3OAXFKeQaKCwjzNylFyfsynE=;
        b=oVw6ZGCkkNQzS8+y/OhCOIoTLm7qgYX5+Ner0wtZCL6XV6g4n9MEAd8oEfoUiUsNwm
         5GVICf1G4NpoOPOo9VcmwXFu/YScSMp62CmWkTnuY0g8Do+IRVk6lAmeWf/SYD2YQkrd
         9P2LgWrSEWbkPZGuRL5ZeboohtoexGhiWwvsj8qg5tF3CqDT4wdXVGcMafjAYUMm/YbU
         Tkxs/rhsf9MfTAn6jgcdaXJowMTUA5ODh1EnIQLBrRrmHBWNbbVUEJzPK4iv3rXFt6d2
         l+qfQrg4bI8wkOkcCK4DTIb1tAYAhWHBexbTKohXSwjQC+m0nIzFTiW/ek8jsuHnzUF8
         glQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=vIAQSCJL;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id s7si482132pfc.1.2020.08.24.18.56.59
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 18:56:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: d2c409b765f64f23a75f83bc153bfba3-20200825
X-UUID: d2c409b765f64f23a75f83bc153bfba3-20200825
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2031445678; Tue, 25 Aug 2020 09:56:57 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 25 Aug 2020 09:56:54 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 25 Aug 2020 09:56:55 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>, John Stultz
	<john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Andrew Morton
	<akpm@linux-foundation.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
	<jiangshanlai@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v3 0/6] kasan: add workqueue and timer stack for generic KASAN
Date: Tue, 25 Aug 2020 09:56:54 +0800
Message-ID: <20200825015654.27781-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: A71BEAAB700B14FB398E93913C82E2C0D2E251B57762600FE97A0A54DAEC618C2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=vIAQSCJL;       spf=pass
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

Changes since v2:
- modify kasan document to be more readable.
  Thanks for Marco suggestion.

Changes since v1:
- Thanks for Marco and Thomas suggestion.
- Remove unnecessary code and fix commit log
- reuse kasan_record_aux_stack() and aux_stack
  to record timer and workqueue stack.
- change the aux stack title for common name.

---

Documentation/dev-tools/kasan.rst |  4 ++--
kernel/time/timer.c               |  3 +++
kernel/workqueue.c                |  3 +++
lib/test_kasan.c                  | 54 ++++++++++++++++++++++++++++++++++++++++++++++++++++++
mm/kasan/report.c                 |  4 ++--
5 files changed, 64 insertions(+), 4 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200825015654.27781-1-walter-zh.wu%40mediatek.com.
