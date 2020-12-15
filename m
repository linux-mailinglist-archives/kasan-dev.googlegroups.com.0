Return-Path: <kasan-dev+bncBAABBWV34L7AKGQEZSX5UXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1365C2DABEA
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 12:28:28 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id f19sf13910067pgm.4
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 03:28:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608031706; cv=pass;
        d=google.com; s=arc-20160816;
        b=CzWz5jk/OTQnHIkOxc88aE+ypEeeaXXTujwqvdIQHraLBlY8BQdaUp3lpnjJTZipci
         nIwTZJcgBHJA+sXHySZClMaiIzimc2VWTrPlm+AEPVZb6wjNhBmfZMHvDbXbErRe7xSE
         GZHfyuZ0yXeR+ytnujAvj+87Ot8R0dO9leyVWnPoiXb7x1caoskA7vkx21IP+x5e0saK
         nbwvwyIElC49ln3cCWV2V3oYyqMKBo2e3ToK0PiLrot6NZh8pgnMkaXQN6WVFk10G2Td
         MVsjlckLNcl4jMt6IoMVTPBd/5KPBfZKYYzLFvfM3bs/cxnzhm5iUDFNEkspykRD+5N6
         I5gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QGpysMQ7SjIeCueNUJVPTroWoCJjWhJ9U9e5ftjcfvE=;
        b=EFnVsNQLMFqGllFHDDlXpJ/KJAWoW9aeowRYMfbS/hFuScfPawlkuDxHvlY5axTx2U
         op9pD8gC+5N+y1Grb5WVrFs/aVI5jYXY6MuYhv1SSbOos+sLMVYgepUHIyOxp5F/GeHp
         KWkBpQ1GjPFVB2YYxqXAb/EvGF5CM8OW+LLEHw2OrIzREI42tgVErEBGSTABkRCgoCFJ
         Jr6TLOU6aM04DI0RjdmqAFeAutAQPXMAIw93IS9lFSIuTudZRXzf34w1XGlAKEnmZaMb
         j5V6VpH1aLmbR26agDfwL63GbRfWD1sUb4KT7al0DnkWsNHrcoQO83AExBxV4jqefvvN
         N+fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QGpysMQ7SjIeCueNUJVPTroWoCJjWhJ9U9e5ftjcfvE=;
        b=bk140900owhxHftBcHMOSgEOU9bUHvpE99vnzHkU329axlRek1w5tOHLGGdddsYvQx
         f/gluddaNs+Th8PMQrIDx2pvdY+7i++5cjmHWHibW7xcROPl5XAJBfpmH1SjT37BATQW
         clJdagtnTrjy0AhS3P/0ao6kyIPTtm1O/m3x37jwAK5b4xHJrnRHOGg5MP1iUVQ1XIm1
         UWTlvOal40M9MhDVOuLfEbQXHTlc80fBkK/qHqxPmSwg9oc0umgPdFq398NzdT5K1Dg6
         CT9itB+HeMg/FcDszdSvqzWxZyXKyQPJiCOW/A8Au6JJMO1MgFsZU1RztJpzoGc29ktB
         FlbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QGpysMQ7SjIeCueNUJVPTroWoCJjWhJ9U9e5ftjcfvE=;
        b=Vp8Q/J39eFvBZI7vbhzNVHACJaZqzqV1qesESelyNMiq/qdYdnMZTfNxL9DuLaCiDD
         kSfJdnoAB3EFB8DzQc1+EAjDs1JA1akWXhPmsqBB7fljO0DxjyuW4C2qybphpe+Vk4O4
         7c7BJYCGI0Abm4IkhiRu0n/jwjjMcG+ysb9KIj/tjz/v54+5HaLQPjF7FmqajIbBJeHR
         OeT8PSKO+jylqN+USCzuLUD8R6vcsUBcBrEuaVQbkWLAp/viBge8cpJqATHhIydAhWai
         kzjk/5kUntywIMq3rN5gc4hJjsDa9ltx4fWthlG5XJYJC7pilhyKuZDjnNcfejGjk44W
         DXHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532DTho87UK8RF4FPpuzYsL5xI6iD+QdWtOfQDuZI0elLoHIL+kt
	SYarJ9w8TCDK7o2f9Ou6tlY=
X-Google-Smtp-Source: ABdhPJxdIwd/nq5iiFe1lI7FwnBOeFonJDrGTBbOj7Kro/izp+lGG89Ummy8mpnkvcQe/TRjdUKoQw==
X-Received: by 2002:a63:5656:: with SMTP id g22mr28246365pgm.262.1608031706266;
        Tue, 15 Dec 2020 03:28:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9550:: with SMTP id w16ls7753402pfq.0.gmail; Tue, 15 Dec
 2020 03:28:25 -0800 (PST)
X-Received: by 2002:a05:6a00:2384:b029:19a:eed3:7f42 with SMTP id f4-20020a056a002384b029019aeed37f42mr28309371pfc.4.1608031705691;
        Tue, 15 Dec 2020 03:28:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608031705; cv=none;
        d=google.com; s=arc-20160816;
        b=zkRFMDJu0zAtk9YrWa3HYchU5HeJN59hOkTnEiq6IJdG+qQejiAMCLp90l054XVWLY
         HEFY+zv1Qfp27qqFrkaowRji50lmLwhgxfA8oJzARY8LLqBTlV5NKKgjKR7XKRbZ7l4F
         +gSbKQvzemF/PAx5uT39WTSOFcL8SZQT2QlD9gPNF+dVjqOWqTlsbw9d1n+tOdVFZJKs
         pS04A/lz62kgSDzP2bU/apUmSuj/AiE63Rqg62FiO2T1Om4UaKPJhTqwmMWvja4jk4JY
         hEtQfNAZ0sCgXUWQFWOGUR9HGGi7XK74ng04xirOq/a96cfOZgT8qdyBJmVbfR5pY/Nw
         NYwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=eqpUqc1tSm5AtLtfZeAnjAfpmAeZF6lgLXJv0RVbIhY=;
        b=vJFYRP2jqwf7pmD0BbehuciIHky89JEpvBv65mNhZ8hAIFk38n7GCEQ1j0UCm++sZ3
         XOHDB95PzwwPsGIaG75pTwp4W/gb3PwSuWuitAr9a+j0EPxz7+L2P+SIHyyDtU2Ts1Vx
         f4Ps+qL47EqXpcJ7OStyt7B8Tz+q1JdIj1YcDItJm+g3g3p6n6GeRBSpqpK2RnEfpKws
         ds0FPiCOWMVpkO4vN1eYg6x/S2HCWRhw0VV4e/nTmQ9rwVnsjD0xM3sWOPS/KVqfi38F
         JK/rRbGsh3o0Bod25cZPKNY7wObRO+ITLG3aYK5PWxYQKHZGJXd+NOhNxUbkyxnHCDgg
         g76w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id h11si95062pjv.3.2020.12.15.03.28.25
        for <kasan-dev@googlegroups.com>;
        Tue, 15 Dec 2020 03:28:25 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: d649938fcd7145598d56f9b38e2b3dc6-20201215
X-UUID: d649938fcd7145598d56f9b38e2b3dc6-20201215
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 2015639770; Tue, 15 Dec 2020 19:28:21 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 15 Dec 2020 19:28:07 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 15 Dec 2020 19:28:08 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<stable@vger.kernel.org>, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH 1/1] kasan: fix memory leak of kasan quarantine
Date: Tue, 15 Dec 2020 19:28:03 +0800
Message-ID: <1608031683-24967-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 1.9.1
In-Reply-To: <1608031683-24967-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
References: <1608031683-24967-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: kuan-ying.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
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

When cpu is going offline, set q->offline as true
and interrupt happened. The interrupt may call the
quarantine_put. But quarantine_put do not free the
the object. The object will cause memory leak.

Add qlink_free() to free the object.

Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
Cc: <stable@vger.kernel.org>    [5.10-]
---
 mm/kasan/quarantine.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 0e3f8494628f..cac7c617df72 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -191,6 +191,7 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
 
 	q = this_cpu_ptr(&cpu_quarantine);
 	if (q->offline) {
+		qlink_free(&info->quarantine_link, cache);
 		local_irq_restore(flags);
 		return;
 	}
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1608031683-24967-2-git-send-email-Kuan-Ying.Lee%40mediatek.com.
