Return-Path: <kasan-dev+bncBDGPTM5BQUDRBM5BU37QKGQE6T4OAHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id AE3B02E34DE
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Dec 2020 09:00:52 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id f11sf6693525otp.13
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Dec 2020 00:00:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609142451; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y1bhBsmKy2AfcIRVHfWrrYMwuc1h43TWdgXAy5BCkwHfBkGHVu1JAa27td7kWeHCsV
         EmLSbU+cBRPAvgUHorM+rQUDSJs9oPw78HmSAKqDyIbQ8lh0K1ZSgby7lK40gFLmbPVk
         peiuUzrIZZx80FZ+WePSmsV6uCnntRb/4hXoh78szPRwqJyE4x7oA3DluoEZK2aEjZTr
         nN+HHttfqMZV35f1KyOE7SAhKhngH9YeyuZkjTEHcAb/Qp7CS8JegKMb8tXscJBjbYk1
         8C2ebcCEoldMpYoUTVLyA8/4hQekJYQ6rf36W6QPoleqU1mAa6z56qbIjIWj5gKIhV4E
         GkKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Xitk2fjVByy+2YbhTa75BR57a4G4NwYNVWigrK1aBpk=;
        b=o3uUvt8dl8G6S9x5AniGy8xPGcNqX+QHgzbXYizLT3wX6sdXoTUgEW7H8fJauawvAq
         /styK7/gFSIlhfwKQLZ7FZccDjD+6aIPd9WImu6EcFmhjUAqqoigCnrKSXuXQ+OJayzc
         aZUojGWE9zz8Kb5FlKVsqmJoFWu/PmGL5QyqlrAlue0EXF++KIFZkkelZfsT/LTjJWGF
         xpZhjtZ8igs/oCuGBltD2lZZdUHK04utbWYseC/EYL7Xn+LtwtZ5nFjeuBtSI3qaG2Jv
         LHjO8BddTVvygrMvvWdvmsIABOdCXVEVQWKMT23wC+3sOjcerImi5KeC3Um2H/HIP1B8
         s+jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xitk2fjVByy+2YbhTa75BR57a4G4NwYNVWigrK1aBpk=;
        b=EKiXFl0mkyTIWv8t1d0kTnuO24C2HA4eov3QIDgfDfJgAIfdHouS97gbmI31FlZheN
         qibCST2LL2xveMw2eGQeZHfBkejyB6gkLbNJ7zIuk81Dys5k9aqT+MfnBSkpeOhZsd1n
         eiOdWIZJpvDcOOeUhFv9iO0Y8rImY0+kkEdvayAAd9EYGPB9GVOC+qz2XrwUVa2MjJPj
         DFJlNg8AC3Ngv9WlR2HUKhzFZC61S3XDRYct+AhgENJoRcbX9e0fdWvlvLFcC9KnbpT0
         8oYI4jGn6ORSPn/LgfvpsyqsLyyp0ExFeVXd2hm0loRim24ShpX6J205bj4GN37pMltv
         lB8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Xitk2fjVByy+2YbhTa75BR57a4G4NwYNVWigrK1aBpk=;
        b=H2MpcQEUfO/7CPZDlgHT+POylkybN8ciX8jxz3sQh14ILNrrNF4FxoeeXmu+Y+LHIL
         vWQ4DhJnrMqZhKBQS8cveMN4bd6ajLfaPP9DLIqDyNk/Xm6MrMcfjT5sitBvEsaFt2G7
         bRaYd8yfjgL1AghfZINdwy2/SJ4cEKMG/yUPiHNyB529sbcc9XUCtAW8TSq9pyxYypJJ
         hyeo9hQH3h17XSYQvO3bDa46Nfbnr19S7ebgxhh91B7oXrPtizDRzg4PJ8v3V54aOH3m
         4XRHctAom+E+gMs5IAVM3XDaAiFFWHPu+ySUdRDnsnSeGBpJznvyhxz8VT807JivPCmY
         0PRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5314EwNV+v7+SEfyWIZVRwOuNCOmk4Nyw7LBnPGVEg+qva5tZgmN
	Bz5E6oZgiBVj4E5+uXwPAdo=
X-Google-Smtp-Source: ABdhPJw4WDw3lwg11NeLo5Pl03RWqQ6+QwAz78hJyBE7M8oiYvDJubG2xKgWeADIryj9ono4KHg9bw==
X-Received: by 2002:aca:2301:: with SMTP id e1mr11095667oie.22.1609142451338;
        Mon, 28 Dec 2020 00:00:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cdc1:: with SMTP id d184ls14007225oig.10.gmail; Mon, 28
 Dec 2020 00:00:51 -0800 (PST)
X-Received: by 2002:aca:a952:: with SMTP id s79mr11201095oie.140.1609142450999;
        Mon, 28 Dec 2020 00:00:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609142450; cv=none;
        d=google.com; s=arc-20160816;
        b=Mmjw7W/2lMxtoX1hPlq1ZbABW9OVxnsj1SrNLpXQa/xC3O3XTRqcLNA/+K+pQXTYJ4
         8H35v89QtN8B0HAdTKjspQHVFXEdvxktdR3/fTt1Sih4IyQvoZanUOfJiUrDaEn689nu
         ySfw5F0F69wm03MrmhzbygHSd+rJdMpLn7pJu9uRypq5WdDd5kQ+MJAgCOIkfrUt9q2l
         jEx5WtoRnijW0QdIZpB6FujuxSt2DLXi+k004a40h8OSgqYQextU08nxQaQnrJyzQweu
         xPOHfICC8+WtAthfGKtI2EIeA3QRK0f83qfs2ILsmRPADdsjJQmX7ZdPq31XHR1QXfRZ
         5K+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=ZJUOdakowzBWslnDmE85jwWBSF+f0kuYDsJt4RW7fWk=;
        b=Mea45lg1UpOuVHNEJNVZ2KwHpXI1AZ5rkUiIzlKTlrWrSBgRp6bHIMfxAQ7oBzqLe2
         v8B8k10rFpZSy30yT51FNEv7CxqujvqxANxDAFQ3pQqx7M5JLJKDbGFwUChBNiPnQU9o
         rwyIF5zg4JBGC2g6enQ7lc1fVCjBgWngR5F63nSP+vHhROGQ5fw2dEMq9Fg6BTsxZY9B
         eqzMf+G/iGLL1brIBNRVnpgQnw4VNdEp5XxCmr+YeP+U+3/aOtmGoi9SMgaPVu7hKI1l
         L4RhStDuWUpFtsPfmINwc9IPpaGZDg73s83KVcZvLud/FZ5mQjvt5SIofANpxaE6Jxb9
         4rMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id v23si3702746otn.0.2020.12.28.00.00.50
        for <kasan-dev@googlegroups.com>;
        Mon, 28 Dec 2020 00:00:50 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 016ed02e456a490aac99fbae16da5dad-20201228
X-UUID: 016ed02e456a490aac99fbae16da5dad-20201228
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1454072719; Mon, 28 Dec 2020 16:00:47 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 28 Dec 2020 16:01:53 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 28 Dec 2020 16:01:53 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
	<andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH] kasan: fix null pointer dereference in kasan_record_aux_stack
Date: Mon, 28 Dec 2020 16:00:18 +0800
Message-ID: <20201228080018.23041-1-walter-zh.wu@mediatek.com>
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

Syzbot reported the following [1]:

 BUG: kernel NULL pointer dereference, address: 0000000000000008
 #PF: supervisor read access in kernel mode
 #PF: error_code(0x0000) - not-present page
 PGD 2d993067 P4D 2d993067 PUD 19a3c067 PMD 0
 Oops: 0000 [#1] PREEMPT SMP KASAN
 CPU: 1 PID: 3852 Comm: kworker/1:2 Not tainted 5.10.0-syzkaller #0
 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
 Workqueue: events free_ipc
 RIP: 0010:kasan_record_aux_stack+0x77/0xb0

Add null checking slab object from kasan_get_alloc_meta()
in order to avoid null pointer dereference.

[1] https://syzkaller.appspot.com/x/log.txt?x=10a82a50d00000

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 mm/kasan/generic.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 1dd5a0f99372..5106b84b07d4 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -337,6 +337,8 @@ void kasan_record_aux_stack(void *addr)
 	cache = page->slab_cache;
 	object = nearest_obj(cache, page, addr);
 	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return;
 
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
 	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201228080018.23041-1-walter-zh.wu%40mediatek.com.
