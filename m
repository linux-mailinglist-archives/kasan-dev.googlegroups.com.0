Return-Path: <kasan-dev+bncBAABBRN2QDYAKGQETB5RLGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4598E1290C1
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Dec 2019 02:49:59 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id z24sf6495088vkn.0
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Dec 2019 17:49:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1577065798; cv=pass;
        d=google.com; s=arc-20160816;
        b=K2HOdMn9N430JHC5ZkO9A4H8NU2RcSq2bkpXSqvR2ztkYPDMZ1De3dirZjK6lm1xJz
         5cfcTZhlNG+7JufG8B8p+OKty1Q6xA0aH0+ryrXSIf/zTRmV3HfaiKz8TmohE3wuqGmu
         cB6F8zzD6GRyKS7YVquYkMO/L65EGfYRsHUkjMXXxpXaN2zbqnRf3BJFEffwdNLimPDk
         mI4cRFFpNbEgwPUNfV6ip4Ljj4Y/2Enkr3n9RyY3h4gwWS0dENdD7hRlNNn8FZ78PqwA
         IJMMCNQe6JAZlCrRj7U1n7CbMCnZG6GrzJovpEhIjs3kamdboHAz5Xhf5TDDHP72vUoC
         ch8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=7S7cxxYAy+r6g+HhgcTpACMBRPbBfYLqNg52OJ8Tg3E=;
        b=mY7KndO6P5S/MxFTIZVD8FdIaDkEhaPIClK7sv+CXgQFs8YCQVPY/GYst1wRKjFrjw
         IbzlAAG0X5OY/GYG65YAbHGN5H6PXe00aM5w1+o3YW4xR7Y5xmLwVnhxIkobnU38goOv
         1OdYGOiF9VAW4Ci7LsGbcWwHVNfzV4L5BAnYk77ZOimPiiMyfjwBGo7uj9LBjOFr0yVR
         xHroKRunetVaCNynoSK4cf970+TkPzyUCfO42jSbxC3tVnO3IB/8aGCz8FJUv1N9Tf4w
         NJjQ5PpEjmNNb0xfMk6hlyBzeJaR6P6oFHIRHYr3aHaURxkmjjYJYPBPC1ojQaQJiIWN
         Svug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wang.yi59@zte.com.cn designates 63.217.80.70 as permitted sender) smtp.mailfrom=wang.yi59@zte.com.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7S7cxxYAy+r6g+HhgcTpACMBRPbBfYLqNg52OJ8Tg3E=;
        b=EEajW/MVLs/Xd861dSWw12K8r3gIF0fIPrY/IsblSrXSWpmq98WRgNAKzTsVJpmm8S
         iSVucWI1GV6WcpTn2e/WWmgbXGEdl0nrxFuLxZZU8Hhz/HBQv0pLHZYeSTzCEk4khP92
         dOfHkO4oFIWoD/PLW4OGiy7ovpTc2plE1U8WI6Fdon+z0XH9bkG9OP+hIF0+/ThPSAMI
         Hv0KRnBRhFPhOayRlA184VRaGRCikpVNW6ic5s2Ibv1VW8g8nLuRIzU7QHDiCsM9ix50
         mkSFgtO3BuZ5U2EqY5ymD9WnNmRo1d5sLfTt5duW4xFeet3EulRGzFWsKJWq6HvM3sBb
         q5Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7S7cxxYAy+r6g+HhgcTpACMBRPbBfYLqNg52OJ8Tg3E=;
        b=VNV5bN6n6OE5K2+6SNM2knXDaOA7ZOE0l0ijOI7EaWf6ZyHXYkutmbMWhCFD91EHmz
         DWNqkotjNgzXn1r0VXasDVXNp3d1HKBZbkX2Qr5CAKY0ThxXYUCfUZzLU9vFg2pjo07C
         89DEhh08Cr4+/MHg9ysK1bYeRGWU8cqF/oWFcaq7pWJ/+i+fbzfissf2M/ulzDtLT1ff
         m+ZMmcMGXmeR64CwQbDaMRql2lTIkUv99oYdrgIaLAABot4fKECOcZrUFkZMBzqIN5wi
         8kl+mIziUfhx7XuKfduXvbfx1yw0n50fBhLUaliTf6w/sPmmYEo1nivOiwoT5AHr6DQ/
         e38g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVCKajfD2HZmz1ihVZK6MNFA5g6EyFOZ6uMhHsKexmhq1VzmyLI
	JELDjjyfYEV3+D86asrGKxA=
X-Google-Smtp-Source: APXvYqyhaB49aCMdvuRaR/0Zp8CWvQh0d0vf5hCIYMgUvHhJtXG92TeWUO9qFPEKBYihFLZv0796sw==
X-Received: by 2002:a1f:8cd5:: with SMTP id o204mr10945538vkd.66.1577065798009;
        Sun, 22 Dec 2019 17:49:58 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f94a:: with SMTP id u10ls1331417vsq.1.gmail; Sun, 22 Dec
 2019 17:49:57 -0800 (PST)
X-Received: by 2002:a67:f84e:: with SMTP id b14mr15183412vsp.126.1577065797730;
        Sun, 22 Dec 2019 17:49:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1577065797; cv=none;
        d=google.com; s=arc-20160816;
        b=bXPzeWgSGh45tRbRsMWUiCFnDuFbVD6xerW4L7mceL4BBRUkO5vatm2e44fNfyeeyY
         zfIMWstV8Cl04isSOatIlPTFe25KLGg4hyKO3BYXj++RAXwQeUOcGTAii5c3d5GLrnA3
         /lpW0QYl1j+C7GoMO1v7inpIu7UIyHH9pRmf+QoHN3I8yEv48o8lBTV2w57kQvFhPxdI
         FaynlmdDFocSOFTEjlGoK2Shwk3lXE8XxJfHYnf4fQWw4prLxiI1OygURqBOl6bQw160
         3k47KICv23qffWLj9fxozb/VrI7X7i30OvKFeXH+dgGqkhSzh8Kz0zcWcZLcP0+o6Vn/
         AagA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from;
        bh=hGExTlOzNBDbnyrDyEQkJpMzxNQGkzqXcTOsHgGyftI=;
        b=qFRGsLJmf5+nM83MpNl3nWL0YbndQfeZrDyQY72RI9RV0MCgQUk6vdwHPoJwUmyenw
         D3idLNyd0jKUF7/BiDEFzyDhTKOZ73zut8rd2CezN09tbhfCTvUnaymPU2dOy/HTpUR2
         6JbrMmaHIxxdIcEG7707TzDPP5d1pi/ftfAvWF5Bef9LWhRlJtgxdJbzj4RlhLGftadD
         KyOazcQ//cEaXx437nCawjxZ52eTI//LW4Pj9vmxRzyNIFi4ADyb7k6QmzHoRKGiiZqD
         SrHEfMGFPFZUyvAQ9dWnYVv7yxl8QH463QfXl1nAj/l0UkElNwfExT6U2eCugNwiGtbp
         9jOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wang.yi59@zte.com.cn designates 63.217.80.70 as permitted sender) smtp.mailfrom=wang.yi59@zte.com.cn
Received: from mxhk.zte.com.cn (mxhk.zte.com.cn. [63.217.80.70])
        by gmr-mx.google.com with ESMTPS id c124si663113vkb.2.2019.12.22.17.49.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 22 Dec 2019 17:49:57 -0800 (PST)
Received-SPF: pass (google.com: domain of wang.yi59@zte.com.cn designates 63.217.80.70 as permitted sender) client-ip=63.217.80.70;
Received: from mse-fl2.zte.com.cn (unknown [10.30.14.239])
	by Forcepoint Email with ESMTPS id 6DB6E44C4802612FF7C7;
	Mon, 23 Dec 2019 09:49:55 +0800 (CST)
Received: from notes_smtp.zte.com.cn (notes_smtp.zte.com.cn [10.30.1.239])
	by mse-fl2.zte.com.cn with ESMTP id xBN1nanf029636;
	Mon, 23 Dec 2019 09:49:36 +0800 (GMT-8)
	(envelope-from wang.yi59@zte.com.cn)
Received: from fox-host8.localdomain ([10.74.120.8])
          by szsmtp06.zte.com.cn (Lotus Domino Release 8.5.3FP6)
          with ESMTP id 2019122309493877-1467356 ;
          Mon, 23 Dec 2019 09:49:38 +0800
From: Yi Wang <wang.yi59@zte.com.cn>
To: aryabinin@virtuozzo.com
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, xue.zhihong@zte.com.cn,
        wang.yi59@zte.com.cn, up2wing@gmail.com, wang.liang82@zte.com.cn,
        Huang Zijiang <huang.zijiang@zte.com.cn>
Subject: [PATCH] lib: Use kzalloc() instead of kmalloc() with flag GFP_ZERO.
Date: Mon, 23 Dec 2019 09:49:34 +0800
Message-Id: <1577065774-25142-1-git-send-email-wang.yi59@zte.com.cn>
X-Mailer: git-send-email 1.8.3.1
X-MIMETrack: Itemize by SMTP Server on SZSMTP06/server/zte_ltd(Release 8.5.3FP6|November
 21, 2013) at 2019-12-23 09:49:38,
	Serialize by Router on notes_smtp/zte_ltd(Release 9.0.1FP7|August  17, 2016) at
 2019-12-23 09:49:37,
	Serialize complete at 2019-12-23 09:49:37
X-MAIL: mse-fl2.zte.com.cn xBN1nanf029636
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

Signed-off-by: Huang Zijiang <huang.zijiang@zte.com.cn>
Signed-off-by: Yi Wang <wang.yi59@zte.com.cn>
---
 lib/test_kasan.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 05686c8..ff5d21e 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -598,7 +598,7 @@ static noinline void __init kasan_memchr(void)
     size_t size = 24;
 
     pr_info("out-of-bounds in memchr\n");
-    ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
+ptr = kzalloc(size, GFP_KERNEL);
     if (!ptr)
         return;
 
@@ -613,7 +613,7 @@ static noinline void __init kasan_memcmp(void)
     int arr[9];
 
     pr_info("out-of-bounds in memcmp\n");
-    ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
+ptr = kzalloc(size, GFP_KERNEL);
     if (!ptr)
         return;
 
@@ -628,7 +628,7 @@ static noinline void __init kasan_strings(void)
     size_t size = 24;
 
     pr_info("use-after-free in strchr\n");
-    ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
+ptr = kzalloc(size, GFP_KERNEL);
     if (!ptr)
         return;

-- 
1.9.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1577065774-25142-1-git-send-email-wang.yi59%40zte.com.cn.
