Return-Path: <kasan-dev+bncBAABBGEZ5X7AKGQERQO5VHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B77A2DD14A
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 13:18:33 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id x25sf12754183otq.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 04:18:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608207512; cv=pass;
        d=google.com; s=arc-20160816;
        b=1HkhzVKW0YuPiVkRRuPOpbuafwbVV4mDMbJMCKN9azFFzjyTPj0BecqinSfQpUzYzx
         sF98TYd5YhGdagfcIHeU9QDEMpp+OltL4qlRZJkaW+VsZ6Tii1EgXUeebd0r1k7pCzNY
         EZHz8WNkLo6NVP74DQQqLUGHlPUxmAQSs7g/p9Wwlz6ulAv4xnLvZoG8OixwFQKPtp7Q
         coNEi4tAukF9TWUwyD32VAYsxo0JjAsThX6KydQWS3al4KcYiTsuXcq/hnPNZEcHyKOJ
         elYTIPPTA5XGd8fOguw/1iMAnxMi1IWDDp4InU1WLlPLx1BdSoV0tJEKAfFCJMUMFUk7
         wBXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FICLJwbBE5DaRILbGS8B0Q+fT8qKKt3un6U7nrfWEXM=;
        b=Sl7D+lfw8sw9r13rs3IaLaSmvStnCq7gBVAjdi5vRRz0tOoGL2TVvxAJKlN0e25Rvo
         p0Pb7gGRt+Xr9PQiVMp1p8Unh4gHICrI8JbG6qotFsDX5j6zD1rCg1kwXNvHajoLu4vp
         49B4vOLj6YX+FSX46R2/xe0S7tIAtbmrsSiCkGEzX2cXRoTuMQbKzJGCVwTLAfuEki1C
         4i7MgXOaOqnurJfI6WWnvMREUEZhNxbLOU/UhFrVGmIEQ4HA993FedORQx3jrhQCM6Th
         R1J+4NtRzmXy/adKf6Y2hfCGMDgfKD5jdzCsazjnkEJ9pno+HFandNud49HtRz0JmNkQ
         XSRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FICLJwbBE5DaRILbGS8B0Q+fT8qKKt3un6U7nrfWEXM=;
        b=YVxRWRRFBNSX+5BBQhFQ5UWU5WKd01NbAUB3ctK894evPbIWLt5FVwwO52c0goZfMq
         HgM1ZrC2v1l4q/3j7g0PuGogOoZLfN8RVOkgRvJ+7F6Ib8BPxCHqSn6lBfpPKx7iEFoP
         rxjWbpo42yehRRMCRZu71NmuzxbfUbzx4DIDbzFtc2XsBY5/JeDTAIcB9GJIvajsMG5F
         upKHeoRe1TPWShnm6pO7/8/td+xFyD1G8hEObPEkwigiNgSgIBTUZC8+6GIfn8AXsH2g
         AkJG7/hGHFuurOPDZ+erTOCkn3uDLHrtiEm3WggqUnIY23sDpgX20yN9vromEP6xVTah
         4tbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FICLJwbBE5DaRILbGS8B0Q+fT8qKKt3un6U7nrfWEXM=;
        b=VSft7yhJGGFNYh7mnGupUzW3I/IO6gU9trmgZH+QWz8DAvmrEjCPl3j/otB5jbmuzv
         9n3K4qWuiFo+EOhGUpuG04jj9gjNsoazuQ/AzwmNPMEijzhjl1VFPEXukuRpD0TeqGH1
         ogogFsOeb61HVCqVd0pG8F5P1A8Xi54nOxulD71WIzGyYvXyDsx4UKfq2QBdvMmeFAtv
         v4jDrHzjmVqagrJchd/Jx7j/7HqMhKZwbK6ZWZNi5feaFJr3/pcsIBgCz1CNxr+35Fz0
         CO3J9TeFyn6DdlQxcdAK8ewtQ/7YAlTP8AtjuirW57BHwRflyuaBD0sDra8ezIUxQqrb
         GktA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530OXFNb9iYyzseis7Nxz4SdvTeaxoXv4vJlQ7xiJHq4z2MoO8ge
	IUCytj4QpdOfxJPfGjjfTdg=
X-Google-Smtp-Source: ABdhPJx84PHGhwxravJCWFOiSsmdYOzpyZrDzDswqGS4B2ioSUJ/iKkPI+6ml4PGWdHdqZmx4jy1og==
X-Received: by 2002:a9d:875:: with SMTP id 108mr29436928oty.164.1608207512431;
        Thu, 17 Dec 2020 04:18:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cdc1:: with SMTP id d184ls6787465oig.10.gmail; Thu, 17
 Dec 2020 04:18:32 -0800 (PST)
X-Received: by 2002:aca:c3c3:: with SMTP id t186mr4610091oif.53.1608207512138;
        Thu, 17 Dec 2020 04:18:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608207512; cv=none;
        d=google.com; s=arc-20160816;
        b=v9uSQnBM8L1vlSoofLb9nQqTD6oJo8jmG67ODnc6KTlgB3o3m6vkl4fuyH3bjPomuo
         MqU9xfPPy2xH/uszXEIblMmig0G+jzi2caArO57GVTNyul+k8EowpFr5vy0B9GA4Ruac
         5PpecOf51YipdfMzi2xh/rhSYQBAuIjknNFt47LH3ou8fE3Jl1fZ6a9Ppmd3L1+UBdns
         1jN3wCAZkFA2QsCmmmJtajBLzHWSulJrAeWXRDbzt+8OT3kb/wFL/ETvo2mtCMiqPUUH
         M0DPz3wChpvL7GMJ0FLOPR22KCS/HinQ3qqsNIeRIa3ITJv0MoKZ9en3iOPK3MeUAY5/
         gK8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=97Q660UDVejClOihLCcBj5e2TaaJEpYU3w9ZWfPY92A=;
        b=IsdIgbrJ4d1XOplmQt00B/UL9iewByCEwpZV1UzIpndDNhTMC8ft3a4ZwaZWvd8Hwx
         ZjSl3/zNyjeKPti6vWxLJ68yKwDygP3DcvKze+uEvBEuJYnviuXu6y37Vlzd1FOFkMlL
         cgf1jKk3BIJ016MGtOE6xurRUNDq6M1vpn4WCjDxvqOjkqHTiFELuGiQx2wKCjTcLtkl
         3m0sIu6Kj98eZoX00VZ4Hx5t9AR400XhX/FLqTmLzVL/ciXQN9kyaLk7s8SoYCniRnSQ
         FyL84QqmgN0DW6D5KGaDDFdBRJv4YvP05ldbMCO9N7bFm0gF85X43a52upZV48toV5fw
         /gJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id t20si592117oth.4.2020.12.17.04.18.31
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Dec 2020 04:18:31 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: d8bec07d2f73466d908a195ff5aef059-20201217
X-UUID: d8bec07d2f73466d908a195ff5aef059-20201217
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 624995331; Thu, 17 Dec 2020 20:18:27 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 17 Dec 2020 20:18:23 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 17 Dec 2020 20:18:24 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<stable@vger.kernel.org>, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v2 1/1] kasan: fix memory leak of kasan quarantine
Date: Thu, 17 Dec 2020 20:18:07 +0800
Message-ID: <1608207487-30537-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 1.9.1
In-Reply-To: <1608207487-30537-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
References: <1608207487-30537-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
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

Fixes: 6c82d45c7f03 (kasan: fix object remaining in offline per-cpu quarantine)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1608207487-30537-2-git-send-email-Kuan-Ying.Lee%40mediatek.com.
