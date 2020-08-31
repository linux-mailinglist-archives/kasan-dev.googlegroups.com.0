Return-Path: <kasan-dev+bncBAABBYP5WT5AKGQEET3LPCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C822D2580AA
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:10 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id v13sf4663957ios.9
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897889; cv=pass;
        d=google.com; s=arc-20160816;
        b=IPzyui6R2l+R3kwM8fhUvbt8WY6LOdlqZPQhW38pqixSqEmwFMNZ/onuCE0inAfZRX
         e6ZZZUrRX1XvymUDI+UwCuJMH0F4y9nFCQPkrP+JiZXRvkT8070zDsF3LupBBTQmnm8v
         ssVi+LzUT9hAMIgjobrqzBris+1wXB4nBXVmMpaxsLhcA2AwTEThAJyDliHZHd8g7Syt
         PsmGpJMgU0B0actWnHj3VCmi3kdaruI+ifWYfF/DlTOhcpncCSCJO4WDDcP1HdnOcUqo
         hjGqNQFlODDHEerHfxpZRo4DNeZNhufoh0up7jVuE3EcJGPE4TCc3sJTUgYZ/gM9V09A
         ZJdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=uE+9esSYd+6guKcVAwvEnJeR+vWb/f74wNi09Yp1NBY=;
        b=HIqFkhzdJUeWi/gQE+VsvRxj/sjx3gmEbpx+a/tITHfuYkd5rZGawWrfDrqrlEA+f9
         0h2szepxCsqxZ4l+UGcWZQatiy99CQMX4Ij//spu2u06T6pIoCUP1avWMlJwFB3qCQ5U
         Ar0YW2vsx7CQYwlfXWC+qFqdgzuzRO5OHU4VQ64w74So1N1VitRpy1K+VhA30x2NrGCn
         u+afMZMbzxiVDVJluUKaOZt4qnQG2NmnEEdwplkWjInsUXuuDFBOIse7o+KfE7I8kE4g
         nuo8QstkE9pVYN8qMvsiIKh+oVOfQb1a3StXfwDHRjSHDFPAVOTmQ6fsX21B8WVoU6A9
         uFRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=nJhWq4AE;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uE+9esSYd+6guKcVAwvEnJeR+vWb/f74wNi09Yp1NBY=;
        b=CmJ3hMaE+E3mDNVAgaQ5Fga2Hv5xaHkwqH6hCujT1qRwCPUfLCDlyY3439bjIjBiIr
         tTO/gX4RyjCreWAtRdx9CuZzDvu8/cfMvlbyz486ENb/SLnBpQ7Wshey54PvdHxnk70J
         7KD/5Ods5FAdxTqHRmnTR15SJueERZy+9wVhDJcY9T5MCEMzjtMbEkNKu3lApFAnjOg7
         mqiA4jZ1x4M6UC7yAeUZ7kLXDSK0/C1khT+DpokNnf1hEwT6d2Q99Vj5tw/q0JSBjEvU
         YYbrUJ1OW/xQGmgTG+2AYlo5fItO/0NhnOoemMl3Ab2LgDE05q7VxvYdyQImV1O9KkcD
         2ZWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uE+9esSYd+6guKcVAwvEnJeR+vWb/f74wNi09Yp1NBY=;
        b=kvTr9r5l3kBGXVdQGQXckANfZ67jG2/dRArgMfqvW9SDQ5CbGIlbvbfAY/Okwt/kjN
         B7u+g4sfglmpSsFWpIN6+t32tWeEfvD3O+kxOsZdApNKTLFVB3E+bSVpiJDYPGfCZtze
         JR0yDFNpXKxGqnFP8dV/NRf8o6bUnPWm+DyoZo+dQyaakByvNMzUbHc2qETwiSw7HFvK
         XEFaUyf4xtjckClnilHaz+gNdcqErI9XjaDAqosSRTBD/DZYkjJr1pC5UjthT6P+VS8Q
         2yeRLeopB2ma1hWBqfs7kgcXFbGThxcz9ljdSjzmsr/j2TAjxC3qnYh11UraALBpuzeB
         HzTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ALoRIHY7mtV1JhHsbAra2r+KKP9o3r+qiNP2XQKZubGfIcpcs
	yrvKZTNfpQx7QrvNbc5G04E=
X-Google-Smtp-Source: ABdhPJzlP4z46sUJpZK4pSwm2L5oVvo3sawQPuQJ94zh3LwfArXSZq6xHzm6medy3DNyyE3T0MKhIw==
X-Received: by 2002:a05:6638:144:: with SMTP id y4mr2317486jao.61.1598897889567;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:a1d2:: with SMTP id b79ls536712ill.0.gmail; Mon, 31 Aug
 2020 11:18:09 -0700 (PDT)
X-Received: by 2002:a92:d4ca:: with SMTP id o10mr2297762ilm.129.1598897889174;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897889; cv=none;
        d=google.com; s=arc-20160816;
        b=Mf1mVXSxmBDY2i80UokVjbZH9XBFn+KRI+1h2ewgqFzT4xLd1tOYkMSrGRsA3CuZVh
         Kp2DtEO7AhyoF4tmEgtfNLDzFWYpVBWO9DkJpCUlVpE+zfI83dzitCBtjSVKv9GaWkDf
         BCyh5K2BewuC5/5uQX/cOAzfsfVgCIwQqCTbdiSKdLC00aFmrKgUU4KOS+ErY1sT7ZlF
         j2J58PbtK+8hX1NBhcLwnQE1mFMBpUE+sC7KKdTL5OVvOh0gUr2dqFlxoPFeAkajYJQI
         qDSpvWd3yjQZMZKPuiOs8QOXa4bZLmcXwvCWwmXsAZIZv17BjLcKcdH3t0w5fpv5sVt2
         e0eQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=t/CjexgMIUOtM710VT35Q8kYu6EY43F2coNHYDmZVxU=;
        b=JNjX0fwn5vzd0XFfphakB6AbJbhODC5M4jG1IwDR0WzgyaB+ZvNKPeawaLRCdempHk
         cUDJqAefMIibz+WHG80mNkQwVQI6AStxwqv7L/juboynnTwcy3ErJPp/RMthkKGXkxg0
         HTfChrEJDrx1Vy/x0QKLvbwx0gTWtllUX+CZ5HiPWzBTFl94oW0raMt4drIKs9GUHfoU
         xluNtMNiGIYcjWxGtBnOF6mCz4wy6moruJWjhqcjHm7GPfJZzDC0UTtY9aIssEi5oA4D
         QZi4yV/bgqW6oztEEEa4Ty4W1IoGcp3OxrhYofIiWbh18EMc3HZY2Mr/qHwQ7/9V+7p4
         nylg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=nJhWq4AE;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j9si48767iow.3.2020.08.31.11.18.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 92A81216C4;
	Mon, 31 Aug 2020 18:18:08 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 15/19] kcsan: Show message if enabled early
Date: Mon, 31 Aug 2020 11:18:01 -0700
Message-Id: <20200831181805.1833-15-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=nJhWq4AE;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Show a message in the kernel log if KCSAN was enabled early.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 8 ++++++--
 1 file changed, 6 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 99e5044..b176400 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -1,5 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0
 
+#define pr_fmt(fmt) "kcsan: " fmt
+
 #include <linux/atomic.h>
 #include <linux/bug.h>
 #include <linux/delay.h>
@@ -463,7 +465,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 
 	if (IS_ENABLED(CONFIG_KCSAN_DEBUG)) {
 		kcsan_disable_current();
-		pr_err("KCSAN: watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
+		pr_err("watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
 		       is_write ? "write" : "read", size, ptr,
 		       watchpoint_slot((unsigned long)ptr),
 		       encode_watchpoint((unsigned long)ptr, size, is_write));
@@ -623,8 +625,10 @@ void __init kcsan_init(void)
 	 * We are in the init task, and no other tasks should be running;
 	 * WRITE_ONCE without memory barrier is sufficient.
 	 */
-	if (kcsan_early_enable)
+	if (kcsan_early_enable) {
+		pr_info("enabled early\n");
 		WRITE_ONCE(kcsan_enabled, true);
+	}
 }
 
 /* === Exported interface =================================================== */
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-15-paulmck%40kernel.org.
