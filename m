Return-Path: <kasan-dev+bncBDGPTM5BQUDRBVNVWD5QKGQEC2PP4IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id DFAEB27677C
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 06:04:38 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id n2sf1740735ybg.8
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Sep 2020 21:04:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600920278; cv=pass;
        d=google.com; s=arc-20160816;
        b=MhpD5my9TUiE4TQ7O/yG/ELTciDD3ADab6P5HtT8FhdTsLteFwLWKIgVy3NKC3jIzi
         j0zXPktELtKzPqaRH0UYBo+2HXhvdwnnC228L1e8Q3JvrFdbjSbywwJ2c89dsR82Q0vD
         cPS3h3nrWC+0q7Rk6lQp1EcByNIuD60uWECKGdCDZbBs8KaBjkmazzWHEbUQD23g6a2v
         z52aO2tzpxNbJfLZ5RNSb1xMLh5zJkFv49XxsoUkr0puiAcCEEL6VmjmQSeq4RhzPtIs
         t8JZzjFgPh1YaBfB76UYoMLXXpATEs9vWHfq58mTc0lm1m5ndbN3kAmXoSonvFEiqtC4
         xX3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6TsEi3C6SvgiRn+WTDgGNUYgFhV06KCjDoa5J0R/PP0=;
        b=GpIPXNKcLXJI8Lc0hrL8irBTnjG50sKJ5kaYBdTaEMxGnwzEDB118WtEuo9EEuE6YM
         eEooK97PiT4/91gKxWJvKlZQKylD2KYHBGcV2h58bur2oByVuwoDe7Z2GrS62hfrjpeD
         RTVW5B0NSiTRClAHMixidnrblX3n2FAXjqf5oZfhBy2O2KEuggFB6+zr2SBpOnGP4nDH
         CnWlnSvd6a98gZb7xZDjLPb17PmYYHeH/NAmJYmG6jPh/5C/+WxMbWRuZnjBB+3dvkak
         vnSKdyApkBXzYhj676cKTjlNdrLOhA1KGG53aFGG8+H9/mByXY0FqB1bSMTDrNSwpshb
         4tdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Abc3bR3E;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6TsEi3C6SvgiRn+WTDgGNUYgFhV06KCjDoa5J0R/PP0=;
        b=XXGs1Q6zDVhvbfUUHMQ7/UsNpQVFg3GTZkYefqDEWh9gDVi02igyBS8Bb7a2g5OVeq
         /bsiFy3PfA3ujifISBsRRaHt6Cev+S8ogXcH6T03inZTQ4uFHboV83Fpory9qfdQSd3B
         synhYT3dI9Hh4eqNt+1TrSOKI6+IzA0wnsF910EbVsYIyFX3OCAlfn+AxPEiD7IwnERl
         FcB+VYmNni+9u9rfCkw2Fg4c+tNkCrKdFFo1rsF+HBxDJRLNRq7ihmptFRqHYkeFFcps
         wyRI6MGcizLcdari44hxOh4G/tnwWnKsKi5/fAsTXkLK99/ZE19G1YW5Db11PEeZj+AF
         ZSIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6TsEi3C6SvgiRn+WTDgGNUYgFhV06KCjDoa5J0R/PP0=;
        b=flASGiIRXRleer3psh9iXk292vJAl/q3kW0RqxNslvNXZJ2MiczBXus7rd6a/E0wVI
         0/3DOeGCppfoylI6GeGjEOYm6bRupubzASJmdYuGMYapp2A9SI7VsR2AKPPw3ZVDOUYD
         lOEjUE6TB0ukTYov7LvPenzmhs/jQohISMjf5Jk7BdAXtbUqwi88XsGF6pufZfeeARJC
         PEABxFzkpjbZ2VchCNM4xyfHHZWnvj0Ll4FI79ymMTFd6qpQBK5N2S+bwDcNPGoYpxaz
         bHiub3peQSBOFIsdMSu/jrPiJgyqlzLEQ385NOV0ImluSuJm2MRToHw5/QCbIP9MbqRf
         kquw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Lw0mb0L32jnnWpIavMuxj615wrgqKzdXbXHq0HhVJhpgajRDn
	zkA6pHTrDvXwUBeHTx6dZVY=
X-Google-Smtp-Source: ABdhPJwKi89iutebQC1lw8SPLkkBl6ncApjpVxw0DI8Z9uMRkfT/dwcLCYt0dIXEVG8Y5js05UT5kg==
X-Received: by 2002:a25:242:: with SMTP id 63mr4581494ybc.478.1600920277986;
        Wed, 23 Sep 2020 21:04:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6d05:: with SMTP id i5ls1011897ybc.1.gmail; Wed, 23 Sep
 2020 21:04:37 -0700 (PDT)
X-Received: by 2002:a25:9386:: with SMTP id a6mr4507797ybm.69.1600920277424;
        Wed, 23 Sep 2020 21:04:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600920277; cv=none;
        d=google.com; s=arc-20160816;
        b=o7lz3uSpr9EHnORVm3J9jeARovt/wKpTKWWmIY2qA+4HS2vyFCJnoGgBZqG6VlcugC
         0Y8lijcGWch5SGu1+wIRKPwQQiLHYLzsePBgns3cQ65bcKfE+glyOotmxbsOz6W7pWX1
         jPjJE16lfISIAECyAb3uirWVEaXEp5HLH36nXLVk/dvOjxnd+e5K0nZfV1gNWR3I4Fho
         ERuPokR0ZKVwPb2eh18fj8A5q8M6Nl2pG3E/VczH5/HvsFZsFXzMoMTUvUiZ7fOvWZMR
         qVBp2GHSXmNQYwAM2t1p45S/QW8eZfpkkLImImdeEKe7/EJiSt0mWBtWvqy9fwX/1Cu4
         nT4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=yih98KEkzJLkFoWBf8Qw3xVcaUYkPNvBrd8fXNNVY9A=;
        b=hYb2ksYqQzAFzPtjSpaxsczAX8pwrNTdO2HGE7pz5jHanb0z6bOnfXdSdfozOixDsx
         krTiZTVyC5owGkDgl91VHBo1SdV29/FchctUkO/VVMHgmhs15SCFfRa7ZuWDCMgBa8x3
         D43X6r+5nU3Va+o/DZiWuFK2OizAaJBY1cAONj9JEsdmw8nH8MZJ5E02Z6n3rtD6SOzU
         8kVrLmlS1ODHyo3sDWrI98Xh1AnNKOQJWOY6TPH5ks9V/8fberrrrOZWuwsb8WGOMN/N
         lIEbcS9hQ3/XqCZcsrUFrw+kVkOq5xSkGjGvjQvkLWzNOcmykk8xB11o7LQPuHPgVA7X
         9s5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Abc3bR3E;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id t12si190298ybp.2.2020.09.23.21.04.36
        for <kasan-dev@googlegroups.com>;
        Wed, 23 Sep 2020 21:04:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 2c4428be2c694ba0a92af8d06a46805c-20200924
X-UUID: 2c4428be2c694ba0a92af8d06a46805c-20200924
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1562696609; Thu, 24 Sep 2020 12:04:31 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 24 Sep 2020 12:04:30 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 24 Sep 2020 12:04:22 +0800
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
Subject: [PATCH v4 2/6] workqueue: kasan: record workqueue stack
Date: Thu, 24 Sep 2020 12:04:22 +0800
Message-ID: <20200924040422.30995-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=Abc3bR3E;       spf=pass
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
Acked-by: Marco Elver <elver@google.com>
Acked-by: Tejun Heo <tj@kernel.org>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200924040422.30995-1-walter-zh.wu%40mediatek.com.
