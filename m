Return-Path: <kasan-dev+bncBDGPTM5BQUDRBA5XYCBAMGQEUQDKFOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 28C9A33CB92
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 03:44:21 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id q77sf40585707ybq.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 19:44:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615862660; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hig8FSXhFPa2UnLUGneZJd1QT2unzRPkFPnWAPFSfyE7ggZkjonVSVo+DZRO7oqUrJ
         c1uCcD/Grt6j5OXYZbOsBZGiqndIS58vnPohwR/NWLws/43zf5m3E0WKx5eWdixgIr0e
         XlnGyCjVhcgD41s5LlOixdTnvQ6hFOxltuedC53ex+HStI+dc0hFE72JCV52DgCe5iGU
         F9ccsbExPvJkTEW6LvWrr2UMNfM6lOvgFsi0JHSD7SmXZwTzTuv6uBtkoVpUo460tuEP
         1idyXcGvK4S3FKHgL8FxxobwyUcC70kOFRu/uigvkNHx+Lkpo1IP0qHbidNO97g7W6Vn
         TTsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=WMTy2dBvJWl1lFo7dPVLa6YB0SYYL7EXFlDsZ6LsLOo=;
        b=JH7BaCOXAl6JrB0m1DohMoLQoKPcO9BtbXRiHXTtB9V1yVGmh9i3Eib6SRNqVO7ibt
         RiRIIbjOyXOiajruoCkzx2uiibklWYoOFbOIrdLJwsx8XB3iIgA8qv7kGvKVJgIP55eK
         r/HnuLfaGBU1WuQ1jlN5qslOfbYgaY0UInX47ViZSuUKY6xu18mPuakipPhGB2OuuL6+
         SK/53U/ZJ85CITYsvfqydAeceiTuEoDmdjgegosmL68UckfequtUOtYPbajDUOq/njg7
         jx1MWojoQHK2OkNqKGxeV6h1y9oOhjE4hbJf+Sr6oxtY4D5koBZh6v9sA+PrQYHf7xS5
         SUag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WMTy2dBvJWl1lFo7dPVLa6YB0SYYL7EXFlDsZ6LsLOo=;
        b=Q8Q7vY84RQFvkFZSeKiqd4zC+07z4Dh3eh2C5yyUNkBVlmSIGVJkbNHWez0VCbH1kn
         vICAE/QgGgJMlGLJTKP8FHdrb7U71tX8s1XDJkQXgCnC/c6gAGGdO/YxR4I9UEPJkdXm
         7XlouY+2wBMSwB2BejyLs9Rjo1uAeB3gPYJeb7xQLz+KTBHqhkyNKpt0TfVZLqhqXGgO
         1pStIgnW6OCDE9NULHnoqif82/+dsCLlycmecpJpZlFuYPK0hbiIv4iYoMrkHBDyFQ6Y
         9r/aLpfvKoQQPCiyLHrR9VMl9awEZK+Wzk/qabmxAKsSIwISfnk9gXrmc8HUCvpVX0sh
         lQMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WMTy2dBvJWl1lFo7dPVLa6YB0SYYL7EXFlDsZ6LsLOo=;
        b=rh2obHKLjWUxWy7UBnkKb7aKH0YP5smJChsMASrXj4D6fxH3dPN/bfnwppoTV+VG/N
         xbr100ekW8bzVGS8h5eVhaKtPWc1Pvi0jYd5dBfa/Ix3xhy/sTPy7MJJFpDVoToRAir4
         hvSM95F+8YlWWT6LpjMjtoqCLZ5wrtRaHc8yTrT4yaHtGvpuUp89ZLq54sPlGJVV8rw0
         7+MSTQsWTYiBxPossEji/cE3qN2mPBUKZjXR+WSVrMDpMBKB/twa5J9h80q6aBz3kPUz
         ebg4YZfBG33rhba+nnNdh8O4JGdOv1dsF+2r6Q/9VPbss1ZDNpLPm4zF8spJWGpUgva4
         JYNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jx97b0UuiCzhzEDl2dNLkLuaWfx1JlG/yTfmZXt6C/WK7/eZo
	bhs+OnYiHhifNxQd1UeBx5k=
X-Google-Smtp-Source: ABdhPJxGbOIKW7HczcyFzPrD58Rqm/QzmrNu4raY+KIk2T2R+4l5GEnmECerXK93wedtUZvXcmv2oA==
X-Received: by 2002:a25:74cb:: with SMTP id p194mr640959ybc.347.1615862660015;
        Mon, 15 Mar 2021 19:44:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d907:: with SMTP id q7ls1361029ybg.3.gmail; Mon, 15 Mar
 2021 19:44:19 -0700 (PDT)
X-Received: by 2002:a25:686:: with SMTP id 128mr3856648ybg.258.1615862659512;
        Mon, 15 Mar 2021 19:44:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615862659; cv=none;
        d=google.com; s=arc-20160816;
        b=Z/Ej+WBou3PIRWHMNHNg7JPRTocuUaFIFnIH+rqZqT8yuZ6qoWX0Hygu/YQgjmg7Cw
         r46mKk/gd4ZIi3g9KZUiKTbe1F6YA+sW77GSXHqOV11FaFPMEjRG2H6KxxDswte3Ozs8
         K2xFJJDmHr+reF9QP+Z4uaXt1dcfAyWYQTeuvWkY5TTIH9HkXJk2A2OeXSQg2BBEdFxJ
         fSt/OlxSLtkbg4OuxwH8aGl2aKz9m9AUWHLPkQRHhl1m8tFtpU3Um4/ImjPEzgfm36m3
         ht18jJjMMkD/SMqQCm/smi/uxCvBs0T+Usl3d/2q/7SR1BQArZDjlqconnMyYbKSRapb
         ow7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=KyOzZxvo9bBLo0Mrm5XRySVJWLgFDT8L9S2FjYYN7Uc=;
        b=MUbB6ES1gE47K1W83p3hEZbP8vna0vS+z2yBJd7EcT3wL6iu/JokQLSav7177MK1gH
         TAi+F9rapphXG2UzZHCNrCsrc+s0y6kty+u1GzI/HuAgaDDgwmKt1/9nO7fFs/e9m9jd
         FOannaNw05vl46/xCxNz2VmB160rZSciFxqyzHnRGedoyMaGmbP7r4EE7nVlFO4LxtLx
         9DSn5yzA3kE8w5dMtrQCOUNmvxNbw0jtzZWt4jyCNT+z32VX2BUhBHWcwlaeDcopRNtB
         Hu4E6hiJ99zTZ88ywFFzJOtF5znvuk33cIZqucXD0sXvySI90xFUpiDH/KOfFmSyExut
         cHnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id l14si1122943ybp.4.2021.03.15.19.44.18
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Mar 2021 19:44:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: c747895dedf149ee8043bffd5a27bc42-20210316
X-UUID: c747895dedf149ee8043bffd5a27bc42-20210316
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 859541587; Tue, 16 Mar 2021 10:44:12 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 16 Mar 2021 10:44:11 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 16 Mar 2021 10:44:11 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrey Konovalov <andreyknvl@google.com>, Andrew
 Morton <akpm@linux-foundation.org>, Jens Axboe <axboe@kernel.dk>, Oleg
 Nesterov <oleg@redhat.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v2] task_work: kasan: record task_work_add() call stack
Date: Tue, 16 Mar 2021 10:44:10 +0800
Message-ID: <20210316024410.19967-1-walter-zh.wu@mediatek.com>
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
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
Cc: Jens Axboe <axboe@kernel.dk>
Cc: Oleg Nesterov <oleg@redhat.com>
---

v2: Fix kasan_record_aux_stack() calling sequence issue.
    Thanks for Dmitry's suggestion

---
 kernel/task_work.c | 3 +++
 mm/kasan/kasan.h   | 2 +-
 2 files changed, 4 insertions(+), 1 deletion(-)

diff --git a/kernel/task_work.c b/kernel/task_work.c
index 9cde961875c0..3d4852891fa8 100644
--- a/kernel/task_work.c
+++ b/kernel/task_work.c
@@ -34,6 +34,9 @@ int task_work_add(struct task_struct *task, struct callback_head *work,
 {
 	struct callback_head *head;
 
+	/* record the work call stack in order to print it in KASAN reports */
+	kasan_record_aux_stack(work);
+
 	do {
 		head = READ_ONCE(task->task_works);
 		if (unlikely(head == &work_exited))
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3436c6bf7c0c..e4629a971a3c 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -146,7 +146,7 @@ struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
 #ifdef CONFIG_KASAN_GENERIC
 	/*
-	 * call_rcu() call stack is stored into struct kasan_alloc_meta.
+	 * The auxiliary stack is stored into struct kasan_alloc_meta.
 	 * The free stack is stored into struct kasan_free_meta.
 	 */
 	depot_stack_handle_t aux_stack[2];
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210316024410.19967-1-walter-zh.wu%40mediatek.com.
