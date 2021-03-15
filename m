Return-Path: <kasan-dev+bncBDGPTM5BQUDRBJX7XKBAMGQE6VREOKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FBD833A981
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 03:00:08 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id m5sf8861887pgp.13
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Mar 2021 19:00:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615773606; cv=pass;
        d=google.com; s=arc-20160816;
        b=K7Ca55v2I0YQNWcnSwNTGkXuyDQpzvxVUkz98dVWinspE6pmueQJIU6mb5Ox26kwhL
         a6+mTsQowLiMejxijfSCQ/nMz3A7Exhw0HEzjHbIzVhd4xjkSTZCokL5uBuNmp5x0+1n
         PoTKiv0EMkokekqj95IWtHfE4MiBFewj5Ee0dplGD5BQntDdOKDgO5MWUFnVdGBWUNv+
         XJD5rjfky+PcT0DTjexwb6G5RIni1HkgFMd3o4mbL21yWaJIKaAcVvzCrxxFiLHC08vd
         QxDoYkLoR2l3C4IT1OaQs1B9e6TWMve4lLwM2xsLeMG8XggLjTE8QsFTIQoKy6tUoCLI
         yMcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=BiebSyodWtIyfqW+2J6NZLt20ZDt9kQA7QpEg5fdiKU=;
        b=za1kcQ9m4XCBjb3uQjnSSVlekd+h9bsmqVTafodRNCJ0LQEZrkDWWS8d7jU+3HQDUv
         GwPZbymCYpN4IIjlKPYaIJaaH2HOabiwN8b7iAat3k6th2MsiVn/tn0fiBdWPxApBwUM
         2YjUb+1PlshNBonsmXE9SgrUOa0CMgzXKEoAhAY4qY7nGOVuE7qt9wM9ZIPh8bjlDHPD
         36C7aXI3z4jJZwEE5BNlLmhWam74ga5/vOjDJlDhHLcZl+aBdDmmud7DQ75PDLv01Slq
         nFN8voDqz8sMyJ/2zLzgcmSy9w5R8+6CpYnLRD9aLDPt8w1EYPYEwlRjngXS3/rlfEA1
         xbDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BiebSyodWtIyfqW+2J6NZLt20ZDt9kQA7QpEg5fdiKU=;
        b=mX+IhQF9hDrtQLgzPY3NEfd7UqDOsVj2/zsj2AuyPGuLYMm7KrC+Jhh2S35cbgsSV3
         RUN9a0xGVeycb3ByUdjuFxUfCAh2vEIsdE9H3fClUuxvLPmN9hyz3U1z+5WdcwvTx03j
         oTyzLFYvZft3bUFBARB9wcdymAOcG2IgK2w+WB1ZTNqGRkF2Vz1hpFeOm0gCYoLoaXw4
         JaApRuNH1+AW0kTnGcribFhVsoN8q7HbKKeZms5BM7XbWPBFwr4Flpdbt1gunsACwgEF
         IAwews9VhTYpZKnJ09GjVbv4qIj1ATOCD6U7Yi61MCpHRdd85my7qkbGUCiI0bWHW+Tl
         7KcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BiebSyodWtIyfqW+2J6NZLt20ZDt9kQA7QpEg5fdiKU=;
        b=LSSfOTOcTDrIHPqAPJjOrN30t/P9RLXl5Eg0P/uNRetnXB8Dgpa0OKwPxgSoqmfXfd
         8vmsUlA4BbBmHWXrJiLtnABgipgZFCoaBvCoNpn5bYtNdUXM8N3T1s2Ukjcr6MtI6st9
         8zmQEEMWhKhi1GDPwa8f73o7LgRvxxD3Zq5VF7uHHvDvuM1rsWDX4WSv9DIME2DROV5j
         KQmDIRTY+P9VznAtvfC5x3NRQVn04fVTJb62POJIgDpUPfpT+PTsDddGGnbJ8YIod8Pe
         jHA1/Gcrp3Od49iNiDt1V36eVD8n/qVBchclbnuYsphTOWCUwO3gdtjwH7iFgbgJ+7w7
         VFQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531IA/NacMGFC+wfNO+/CicMpql/V4v04SYqtHExdKE1+57GFl8K
	ZiGEe4wpbtq3CwZtbyypd1c=
X-Google-Smtp-Source: ABdhPJw6PN9ZUThi1nQHEueGmst5Mj8gBz+Brk4tuuuk3iuWfLZdj4axBrqJewDbqT7VcuVctmM4Eg==
X-Received: by 2002:a17:90a:e516:: with SMTP id t22mr10375170pjy.39.1615773606847;
        Sun, 14 Mar 2021 19:00:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8241:: with SMTP id w62ls2186869pfd.8.gmail; Sun, 14 Mar
 2021 19:00:06 -0700 (PDT)
X-Received: by 2002:a62:e502:0:b029:1e4:d7c3:5c59 with SMTP id n2-20020a62e5020000b02901e4d7c35c59mr8325073pff.51.1615773606214;
        Sun, 14 Mar 2021 19:00:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615773606; cv=none;
        d=google.com; s=arc-20160816;
        b=Zd6/ZhHfBvkybVp2VQlVxtAYn11PM5/84EUTmWMo9L2GzGzwCJYcXfKmUBY4A+l20d
         NI6e76knwuSNHkwB+XiKx9WRzQO48Es/evltZn5Glrn9dWCTrN//HkhDnIl6TZkNG/ff
         BqqX2RnNAL6WXwIkf96zyxOSmvApiNV17lUXpHfUaIZN5ktRIJm2X57bieAbS5tc0ivd
         ColQqldCJUSqkX/qZZCMTZ8M0dqf1rwlTV63Vt9zCXc+tZutDmzgdIOuewyk27TUN45o
         o3XHwcL3SeX4JGI9aLj4bUupL/m42a3iZW1Ge0onAuPZOASOKDnSKnlQyx0DbuKJN4St
         v36w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=5HfCD3O2tXZgP2r108py205iuF9RiYwviVCRWNaol3Y=;
        b=06Xz5dF4VxH55MRO4okwPf8wl6hqzl1KjA2HQyBYt33G1sbcoz8tTVXuxbPiaef4Rh
         A06x+zaCMW5yYcnbLOrOEM+0rvhSg4Q0EOYQ4a0TLqtOYh2hIVA543xKnuWEnWTG724t
         87m00yX3H55rq+BuIJDFpspPZM2iZNnIShefDDcR8rV0MZT9QA01Ls6GZQDYZgM5dm+F
         ZX98jWUhfj/X+fB+6hm/0t1cNXdCdiVixBHTbL0hvFO+CXaTPusYYTqrPNTgGDx3/dJG
         HKBZVXYIMZ20QuwM2+bGP/SV1cpUpz6VVq7ol5G+wLi97EGzQL/X7FakwRB5bvwWSChc
         eT+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id d2si713079pfr.4.2021.03.14.19.00.05
        for <kasan-dev@googlegroups.com>;
        Sun, 14 Mar 2021 19:00:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: ac1356e0c116491abcf4e1cd36c396f8-20210315
X-UUID: ac1356e0c116491abcf4e1cd36c396f8-20210315
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1286494231; Mon, 15 Mar 2021 10:00:02 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 15 Mar 2021 09:59:46 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 15 Mar 2021 09:59:46 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrey Konovalov <andreyknvl@google.com>, "Andrew
 Morton" <akpm@linux-foundation.org>, Jens Axboe <axboe@kernel.dk>, "Oleg
 Nesterov" <oleg@redhat.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH] task_work: kasan: record task_work_add() call stack
Date: Mon, 15 Mar 2021 09:59:40 +0800
Message-ID: <20210315015940.11788-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 9DA2466084124075C1C17447C85E61ECA4CB0544570674D733F2D6BE08A8DDD32000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

Why record task_work_add() call stack?
Syzbot reports many use-after-free issues for task_work, see [1].
After see the free stack and the current auxiliary stack, we think
they are useless, we don't know where register the work, this work
may be the free call stack, so that we miss the root cause and
don't solve the use-after-free.

Add task_work_add() call stack into KASAN auxiliary stack in
order to improve KASAN report. It is useful for programmers
to solve use-after-free issues.

[1]: https://groups.google.com/g/syzkaller-bugs/search?q=kasan%20use-after-free%20task_work_run

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
Cc: Jens Axboe <axboe@kernel.dk>
Cc: Oleg Nesterov <oleg@redhat.com>
---
 kernel/task_work.c | 3 +++
 mm/kasan/kasan.h   | 2 +-
 2 files changed, 4 insertions(+), 1 deletion(-)

diff --git a/kernel/task_work.c b/kernel/task_work.c
index 9cde961875c0..f255294377da 100644
--- a/kernel/task_work.c
+++ b/kernel/task_work.c
@@ -55,6 +55,9 @@ int task_work_add(struct task_struct *task, struct callback_head *work,
 		break;
 	}
 
+	/* record the work call stack in order to print it in KASAN reports */
+	kasan_record_aux_stack(work);
+
 	return 0;
 }
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3436c6bf7c0c..d300fe9415bd 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -146,7 +146,7 @@ struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
 #ifdef CONFIG_KASAN_GENERIC
 	/*
-	 * call_rcu() call stack is stored into struct kasan_alloc_meta.
+	 * Auxiliary stack is stored into struct kasan_alloc_meta.
 	 * The free stack is stored into struct kasan_free_meta.
 	 */
 	depot_stack_handle_t aux_stack[2];
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315015940.11788-1-walter-zh.wu%40mediatek.com.
