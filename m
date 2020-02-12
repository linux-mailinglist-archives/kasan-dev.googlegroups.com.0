Return-Path: <kasan-dev+bncBAABBUUWR7ZAKGQE6FRQXGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id ED3D015A55E
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 10:54:27 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id z79sf1179465ilf.4
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 01:54:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581501266; cv=pass;
        d=google.com; s=arc-20160816;
        b=ArgLN+Pa8SQTKCuJ+wGHyrCEKTBefzg68+MfaLf1jKpK76c+mGqEMEpNR01cgFYsEJ
         MkpfMT5j8bGmV+lzHjsF3jW36qt4uJGiaaV+bMslAaRq76kCQpjleTUF97LS2rXEk/7k
         VOEVAvtyf97J01hZDIEC7LkdG37Dbzq8vajHkWl9EzJ19gWrOHa1tm8LWxTRaSWSljgz
         c4DZD/WInxa+zyZuicrgdRnZC+AdR1TEsle9MCCFiqFsCm0234LHOaYLVia/+YMu4rBc
         R1CU/hm0XDo7vtQDSFBeFs9rkfY3LtGWc3wpf7puEtmHI78+nJk0uSiE6hjyn/P8Sb5V
         /sbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=I1UoSzHFd0SmNpscLuRaZ/v3dUrGzvsRXDfSLAGuC4M=;
        b=lwkQLSSDsCmuTfcxWq8JNPYp+dMGFbG2YLoQJlRDX486Osu6gxrCmsk8xvS0483wqI
         oT/JjGJltUUljQ5Cj4P8xlbKPf/awJHIWijpZjmguIIo6oaCSTSRnmXHAwFhw+CY0W1z
         J7DvQf4EA+LMdeuyTCLslcApJC6qOyXfyOGcwEKPb7WVHw7YAX9iqbGNcVX0SzidE1ba
         jrb32dbMVqm0V2OPL3nHf08Ef4l1FfTDaIKcvwKljpeEPw96gMXylnytgIzukCB95RZ6
         xxdYxONoARmHmk1nBndMQ7A/4x8iKnoKCjOFwaOjb9hpHBCO9DPGhN974UktpZY8OseE
         IRbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wang.yi59@zte.com.cn designates 63.217.80.70 as permitted sender) smtp.mailfrom=wang.yi59@zte.com.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I1UoSzHFd0SmNpscLuRaZ/v3dUrGzvsRXDfSLAGuC4M=;
        b=FXdms7P/6Aekmh3tqQhdx4WeSP7RsHX8icxFxzdOph+u1ZWIhJxk3MRwECO+YtA1iD
         OSz5N47DDnOarivM6KqGsGeJ1YYjN54Uf/Li9GirKkcBnuDr24zyM7nV9I6aWP56OVFX
         T7X2Qxt/JREDnYqYenVnrhHyrp4TXkWILRTnTqF/MRJdfgtLjSvew7hM0NT0F4sdgBbi
         8hX0a0RT5JXNzXZKm1w/b+7Kpr8sHTuqtTD4eZMLZWD7QbOFkIvrFBUKZcAD48UIQgP0
         rw0gp7Gj0OQdhm9HyydI7MkFv8eLGOxVMHJnZZkussbxe9yGEsoyuNfgzg98g0fYMtEn
         5iBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=I1UoSzHFd0SmNpscLuRaZ/v3dUrGzvsRXDfSLAGuC4M=;
        b=mHNmJ5lkDo38lmo6G5FrtRmdBhBR0IRj2NBghgFtt8cb5yaWupHceZWPtqP32gYlZ2
         LCkk7xsVhnqCErpJqvtkTzskWdUHjFPkVKJabK44SgurUMBefuQzfjBOrG6R6cftGPoj
         6qmUSyIRA12QOXBphwze5aDhv54oqrlK9T+OWgaw1PyPdNpp4PdbmkAxwWsyhgAKyKnf
         mhsy2ZKSu3YyIpDtVHzDf+Iyfezppnu+ofqbJHVnNjYueizFi93POJJL5RvEz2+G92yE
         VllAlZVswF2aYi1tSnhW9KKO4iWrgLmmVxbh9YeC3g2YkSC1ue+3DMbmwmYRRZPoy6V7
         iBdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUAV6isGRQlGq2X6ik2jdE8ksbiIQWcgDNmO8V8NbZUeA5ZiAM0
	L+TaB5WZnL8FWdEcRLE1lZc=
X-Google-Smtp-Source: APXvYqzxBIwx+f/5Lp8vwVsNpiLtTIfznEwMVkRu0AJXAQOkObmFkEQs5krpxrgqUOAjshqpf79Qcg==
X-Received: by 2002:a02:c8d6:: with SMTP id q22mr3576281jao.99.1581501266505;
        Wed, 12 Feb 2020 01:54:26 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2907:: with SMTP id l7ls3506246ilg.8.gmail; Wed, 12 Feb
 2020 01:54:26 -0800 (PST)
X-Received: by 2002:a92:ba93:: with SMTP id t19mr10870641ill.0.1581501266226;
        Wed, 12 Feb 2020 01:54:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581501266; cv=none;
        d=google.com; s=arc-20160816;
        b=cph5GaiOJfjziSoEazWeRc/HfpfcxDUmR3HaK/6XEGS4dXbMDRlp7PE2k9AfYYFJIq
         dO7yFx6YOrys97YYC8rRgURHPh/0zpyxNyW74QHvFxsMP/SW5n/djVq2/OaISH3v3jUU
         EjbI/z2nPR6ylCaKJPClo2eoWFlRmTG3JAvtXp60AXIDQLbU+FC1iQp8n6Zxt+EZeRxR
         wX20UybvYoq8bGux0rTR+jwJdOFhK5ieRyO5uEBsD52kSVVc9SF34EOl4p4yi5CJ+Idy
         2YiTGOrffMOe6YN3QyiDUwCSuc8jZeSg9CozLZnCzcqKpIFDBfRlw8OJZvuG2Y1g2akh
         kYNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from;
        bh=HQo5M6jjq4NyFnwRrF/A8qEBNUzoYo6pUQY8vGi8pT8=;
        b=oOkADOluRCwUWtAOyvKgoH/GAK/GSGnBS7/P8ZESMHv1pZkLy/D5g6qRb1jciu2L2R
         6fPorZpa+LHhI51D3u4NmsihsZ9xkDkrCtZ1026AO9+zce115FsD/KAZ4L7NhtlzZr09
         Xsoh2MvMhH8AeQ+CIkxfYLQCVJ1gEn01ZNKDSbZj1Vx+stMJyyFRmmXhw5ig6qlIKXi0
         VMDZbwOAWeD3w+zQmlNYyMyrtiX6l5aDqQHI/u2p9A0F/vcttbWFYvY2pQd+8s5fvHHp
         3y3czgKPLZgAbeCfVJvwxCuWuoVbXKDMwaGF5QR12Aq8hD/oxShZb9d7D+ehuI1iCYmj
         QMYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wang.yi59@zte.com.cn designates 63.217.80.70 as permitted sender) smtp.mailfrom=wang.yi59@zte.com.cn
Received: from mxhk.zte.com.cn (mxhk.zte.com.cn. [63.217.80.70])
        by gmr-mx.google.com with ESMTPS id z7si1353ilz.1.2020.02.12.01.54.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Feb 2020 01:54:26 -0800 (PST)
Received-SPF: pass (google.com: domain of wang.yi59@zte.com.cn designates 63.217.80.70 as permitted sender) client-ip=63.217.80.70;
Received: from mse-fl2.zte.com.cn (unknown [10.30.14.239])
	by Forcepoint Email with ESMTPS id 84F9D3F3C3D7BE5FFB11;
	Wed, 12 Feb 2020 17:54:23 +0800 (CST)
Received: from notes_smtp.zte.com.cn (notes_smtp.zte.com.cn [10.30.1.239])
	by mse-fl2.zte.com.cn with ESMTP id 01C9ruoZ089308;
	Wed, 12 Feb 2020 17:53:56 +0800 (GMT-8)
	(envelope-from wang.yi59@zte.com.cn)
Received: from fox-host8.localdomain ([10.74.120.8])
          by szsmtp06.zte.com.cn (Lotus Domino Release 8.5.3FP6)
          with ESMTP id 2020021217541684-2102563 ;
          Wed, 12 Feb 2020 17:54:16 +0800
From: Yi Wang <wang.yi59@zte.com.cn>
To: aryabinin@virtuozzo.com
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, xue.zhihong@zte.com.cn,
        wang.yi59@zte.com.cn, wang.liang82@zte.com.cn,
        Huang Zijiang <huang.zijiang@zte.com.cn>
Subject: [PATCH] lib: Use kzalloc() instead of kmalloc() with flag GFP_ZERO.
Date: Wed, 12 Feb 2020 17:53:48 +0800
Message-Id: <1581501228-5393-1-git-send-email-wang.yi59@zte.com.cn>
X-Mailer: git-send-email 1.8.3.1
X-MIMETrack: Itemize by SMTP Server on SZSMTP06/server/zte_ltd(Release 8.5.3FP6|November
 21, 2013) at 2020-02-12 17:54:16,
	Serialize by Router on notes_smtp/zte_ltd(Release 9.0.1FP7|August  17, 2016) at
 2020-02-12 17:53:59,
	Serialize complete at 2020-02-12 17:53:59
X-MAIL: mse-fl2.zte.com.cn 01C9ruoZ089308
X-Original-Sender: wang.yi59@zte.com.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wang.yi59@zte.com.cn designates 63.217.80.70 as
 permitted sender) smtp.mailfrom=wang.yi59@zte.com.cn
Content-Type: text/plain; charset="UTF-8"
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

From: Huang Zijiang <huang.zijiang@zte.com.cn>

Use kzalloc instead of manually setting kmalloc
with flag GFP_ZERO since kzalloc sets allocated memory
to zero.

Change in v2:
    add indation

Signed-off-by: Huang Zijiang <huang.zijiang@zte.com.cn>
Signed-off-by: Yi Wang <wang.yi59@zte.com.cn>
---
 lib/test_kasan.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 328d33b..79be158 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -599,7 +599,7 @@ static noinline void __init kasan_memchr(void)
 	size_t size = 24;
 
 	pr_info("out-of-bounds in memchr\n");
-	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
+	ptr = kzalloc(size, GFP_KERNEL);
 	if (!ptr)
 		return;
 
@@ -614,7 +614,7 @@ static noinline void __init kasan_memcmp(void)
 	int arr[9];
 
 	pr_info("out-of-bounds in memcmp\n");
-	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
+	ptr = kzalloc(size, GFP_KERNEL);
 	if (!ptr)
 		return;
 
@@ -629,7 +629,7 @@ static noinline void __init kasan_strings(void)
 	size_t size = 24;
 
 	pr_info("use-after-free in strchr\n");
-	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
+	ptr = kzalloc(size, GFP_KERNEL);
 	if (!ptr)
 		return;
 
-- 
1.9.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1581501228-5393-1-git-send-email-wang.yi59%40zte.com.cn.
