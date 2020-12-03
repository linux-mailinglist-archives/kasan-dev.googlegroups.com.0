Return-Path: <kasan-dev+bncBDGPTM5BQUDRB4MYUH7AKGQE4N2HD2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 559052CCC82
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 03:24:51 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id j30sf433727pgj.17
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 18:24:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606962290; cv=pass;
        d=google.com; s=arc-20160816;
        b=qQtcmRcGnaYhmL9295I/EmJ/ZaTnQN1EqxvMBADrJvmXflIWIrbrCq9TyngiLoc1Tu
         K9PXEhnezutn5iCSORkAfT/7KabpbrgQ/LL3mqRVk/Rab0hUN5hPyws/mPQPU6zYFJtk
         RqWjv6Ak42YS5hmJ3ND4LlPawFlM7dNFpdHP3F/vDdgIogiE6ycb5tJ42PJJCbMH1H8I
         LFRO4InGeQ6zOppXBLAoisbI9YrlTb2f3u6ipRl8Wz+aDE7Z9Piep0opaIBH/rt5+hk9
         TQgw9i49gOsta0zVLBoU8EAzMHVtsHZvUbcgOZwSJSQnQV21u7yKYfnpBtKXYeCMe4mE
         IwvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=eEOjrY8LuWuhWOzoBx+vwol2U6oSFPSHylM1rhi9ROk=;
        b=ZIpdwfV0ZlWO4GEqtd5Wil5G30nh7+jA0aH35F20+EiO5gTA0F4d3mrgyoQCzrF1QF
         uvA2wmkZLrdeIcKv68p51hDBDxJ1Dkky96rMlBgHvXVhPkyF3Vf7iryrxISd+7KwYX5E
         0VVjcd5Lf0g8gB+99LrxDpwy8RxGa/z5xethE9LUmEZbaBZUNjZro/Mlks7GfuAFL07o
         wtlN4gqlpuPNoGEn9ep2cSibSA03a0NpWw52jfo7NBRkqk5FqykBzSqS2dSSQqK1KecC
         AOXqmatfSYOtACcR5e88xmfO04YHxjpxr9B6dBlZxJIqQRa39SCRyvaod7hQFQqrdeFK
         b18g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eEOjrY8LuWuhWOzoBx+vwol2U6oSFPSHylM1rhi9ROk=;
        b=oyUvohQbE1mmOFpD60BrN0mtCP+MZ5WFZtotMtdPkwnRyNdcKm9KT9BmLOV9bm59dk
         VuoJ4b/g2gxTNITmhGfvfIZM50OkJ3Oirxj88ZU7PjpMLrmUc3c/vd2jSri6BbbhjNnO
         6jufKT56Yj/E/650XVf7RkkxEP4fDazfRFD8TsfJOyNjcKCuTqiDqWANeJKRxOGaYOGv
         RqK62l6YoWEdzfd4UL+rYAlmJ7joykON6FM4P092O70JnmVtjUL80+1PBrAhWwmeUGTd
         RcXwgCFG3CpE6mwcdQQX4uFxi7MqbybvNq0qMVJsAs7ZmHRt7MH66U51apo7Znp9ZnLE
         IpYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eEOjrY8LuWuhWOzoBx+vwol2U6oSFPSHylM1rhi9ROk=;
        b=JjRVslSh4crcV6OcAOKpDqHGWWUawgqj3afLnkfEcgVb6q1gmun/cHYuhQP3gHyore
         qC1LHuSrP2ndX3x91O6Yi8v97ENLmsg7d+xIP7KnZT+jjCHL0WSjoHYQ8KDd0ull3uKr
         C8BaaZvo3Y2pk3jsAP+cgN5H248Qd+dCUMrkhoa8BX+1EAw+l+GadKqdQuUV+EFN7S4c
         svMZc+4D/sTpzN99doQ6Fx6nakpt9n319SMuctlov9Qnp52BdL0grKtss6jk+wTl3g+u
         /BNPdGxGby5d9Ae7QWfXkx1mamZRh+mJlzg8LAm7SGhVOJ8euTYltDgF9VDs61+NxBoS
         tnnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531s4yphrztuQx36wfitvu+qeknziS9Vr0K+UgHNmkWPZ+zSVCdg
	0Y2NM4jeEb7NQZiGbHOtWZc=
X-Google-Smtp-Source: ABdhPJzvKja/3YzlSUuRme2jLuRHJJoz6MTf5YcmQppcQWwYdJsninzrgiCP1qcv4vO5vX/Q5pMTeA==
X-Received: by 2002:a65:460f:: with SMTP id v15mr1073454pgq.406.1606962290080;
        Wed, 02 Dec 2020 18:24:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:451d:: with SMTP id s29ls1427799pga.5.gmail; Wed, 02 Dec
 2020 18:24:49 -0800 (PST)
X-Received: by 2002:a62:8f4e:0:b029:18b:bd18:75b7 with SMTP id n75-20020a628f4e0000b029018bbd1875b7mr915858pfd.48.1606962289470;
        Wed, 02 Dec 2020 18:24:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606962289; cv=none;
        d=google.com; s=arc-20160816;
        b=gO2PvHfVbiMAONAjgj85dM4fPZNP/OSXVtywuLMQrUMQBlvbIXqhUQ4n4IDUBlcTBi
         aGbuPSwUFqL1KkPXxXE8yr4+bd2fWW6u+RHX8xFtXpEYDn7T83AXDL1wRePa8tjhayJG
         ApVum03ZUnIFVN+kEaVLnBjQcGeth4FvZ4dNmaHHYogV0Y3DtpKVTiMfAZQFtblCRSZl
         A0c49MM9pDuRIpT5m0UUd08G7gLaAoxk3CwGCgV/2wcCoITb6B5c3+OmaucGvEX7QjXQ
         Mt2oAzj/wkn8G1if7A9KjhBaGu7t3ZNiBNi2vrhKxoSbAkjyxmBeRTZ2n3eCQ9iFI5vW
         qTJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=Wse/OlkkD0WLlbrge7ddZiK38tVQj7xeahRiVeCMSTU=;
        b=T875/8EkUbz3Tkj67rBeiuKFqNtqQc2dDRZqzR4hp7cQc0yuXknRQ9HtrcvleUlYyR
         i1J1zA5xJFdmU1ine1CJHkdcIU3rco5zdKOYYgJyDMZUsCGiCsV+GH1NfTV2D6OEhZiZ
         YA3pl9k/ve78QVPmQQAII76YInBTtWaqR8Q5Oyui2MfmZgk2OaFJTj+5G/Ho3FutjwLb
         CbOFReLPWE8cLJ4H6AJpJdq4Gxi/nF5Pc1fgw0wBX2RnVNN2gAA4gh71p5N6tDUssg4a
         wSI3hfv4o5u5GcTAlqO+5txk+xdGafkJAvCHWM8D5yXoBIQTUUWXd4feMcE/PU0HcXoc
         8ejg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id mp11si35769pjb.1.2020.12.02.18.24.49
        for <kasan-dev@googlegroups.com>;
        Wed, 02 Dec 2020 18:24:49 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: ea096dd091de4b12acf05e339743117f-20201203
X-UUID: ea096dd091de4b12acf05e339743117f-20201203
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 435552084; Thu, 03 Dec 2020 10:24:46 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 3 Dec 2020 10:24:44 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 3 Dec 2020 10:24:44 +0800
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
Subject: [PATCH v5 1/4] workqueue: kasan: record workqueue stack
Date: Thu, 3 Dec 2020 10:24:42 +0800
Message-ID: <20201203022442.30006-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
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

When analyze use-after-free or double-free issue, recording the
enqueuing work stacks is helpful to preserve usage history which
potentially gives a hint about the affected code.

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
index c41c3c17b86a..9dd65ac60d6e 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201203022442.30006-1-walter-zh.wu%40mediatek.com.
