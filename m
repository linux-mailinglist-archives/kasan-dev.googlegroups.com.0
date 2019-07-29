Return-Path: <kasan-dev+bncBDQ27FVWWUFRBDVG7HUQKGQEOG34WLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 046F97832E
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 03:59:44 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id u8sf22645761oie.5
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Jul 2019 18:59:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564365582; cv=pass;
        d=google.com; s=arc-20160816;
        b=XcFVYtMC3KFocjptNjq0lhwmigSbBoDrp7xhSikqldD6h4BAxnUM8AQR6G5I+h5tqZ
         YZfkabVwd4m9cd1xSIU8asDORFeRB8++dMzby+oR2HWyXHApRvLC3lbHGScv49UIMYhj
         2CIHZsemI70XLGWqKau8dJiNegVPldf7zoqmh5ixjW9U+/VF7MnvbTwkbwmLP7N85QEV
         lR7nQZn06kaq86GEtTNhy7dhyoviHWnuVndvXuOsJ8NS0zbDjevJPqf1WJptWQtuP7yC
         eYNjjHEprJut1Aj3iopj703Wpe2ukAtzWDHSaY4hi/jWcmzGLp1+MmJQVQiTDdJhvIy0
         Whtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=+ds7VpX1KFpNkbKnnpwDuBA7dNHaaZh3VrpdG1QXQEg=;
        b=DFl5WJ5AZXbU5AK6r/itZMJzLDkCG9o5uXKiONkRS5O/3urDFWtMInsAbEfrGhyr/b
         UB/XxM62aEQYcECghJhjYG5cypxI9zIT53prrn6zn9GVMlo17TnKpoyvoDJJB8i6P1Cy
         u/4Y/5iOkOzSp903sYmF2j/6VaWENCT+gt8nmTiutLunKEn08L9pukJNFox9VvZDnKjY
         FLnouP6DMLGVbu3MmXnoI/lrbnX0S6TWr4ud7qYsGAAeLFRBxDShJ4eqMa3kIK98slhk
         yqkS+s9/NxY/l3kUEJjJL3TbarcEH7nFlwYpNPCWx3w18RRaHw0K3eYTwVkwhf37GQIf
         jfxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="E6/bkMrk";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ds7VpX1KFpNkbKnnpwDuBA7dNHaaZh3VrpdG1QXQEg=;
        b=rFN9QKMgpXz4DXCSs4+bqiB+f7Mxn+S/FTXVB+aTXzWQN2v9wrwOtbcgN+BMIx4drj
         TS0SCyPZFGFGhV56BqhAdDndNKYux/dDFxOsiVOYb+czftqkMsUGHQ9QeojH/L3sKkfy
         Q4bu3wNGM8mIcrklv/iai5I7CBX2EGCwYLy/PJSVoCFDUbPheKIfmlqgWJk/HN0orz2S
         4IKvhK1l7kI4VHTtEj7BhfQMzq7sgFjZiwQXEGdbPhXn+fsTE1qcB/1o0bYmY2L0FATx
         InEUYuXDs1+Nv3PFaTGgo6atCSDI5J7NQ3C0j72uf5WokLW0iC0Vl7kiJl2Zd32I7KhV
         sf9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+ds7VpX1KFpNkbKnnpwDuBA7dNHaaZh3VrpdG1QXQEg=;
        b=WqyycXmokTGe/+5tAV08kE8usQXpEafKw3tGVYU+J/V4cMn1WLdj7Ub6TZHw1/2HFL
         J3Awh1oHrov1qs7y5r3PulbKZGxF1lmVLuuSaEI8YMnOx16EE2KVEhG7QmCiUUP1uqqq
         EpOxXzeHT1cegogCr4pbh0mZ6dR5R3G5lqvH5IE7BlSkRY/9hpspC7SDeWL0xjSNwX83
         Uu/i1DUFZoY4F2SY49T8s8HzDyC64MXgLEeyWudUWkx9xTEaMdMo3ab82WRQOBUrroZ1
         +xAH+T2QD6KEDpz7S6OMVcpoYSqB/SxcfdwCz/7tEU56I1k39/vU0whMOnge3GLpZ9Dt
         UB9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX+OJkeJfnMn6GLeZgHMmtIfFmfDpu0f00G7yPeUmqtL85GNZbX
	ssGcCQegX1xJxo5BxsytRRc=
X-Google-Smtp-Source: APXvYqyH9s7DNHWehMR1eXtsGJu/3dFYNNKX6dcqfpdco99+VCRE7LT9k0xAY+wEQL+7dOo6k+R3JA==
X-Received: by 2002:a9d:6f84:: with SMTP id h4mr37515490otq.354.1564365582513;
        Sun, 28 Jul 2019 18:59:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:5d4:: with SMTP id d20ls8609182oij.14.gmail; Sun,
 28 Jul 2019 18:59:42 -0700 (PDT)
X-Received: by 2002:aca:f582:: with SMTP id t124mr13228847oih.71.1564365582051;
        Sun, 28 Jul 2019 18:59:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564365582; cv=none;
        d=google.com; s=arc-20160816;
        b=AxeliMz79KJjtZRF9IhBwWMDqbYLSTU99aJJz2z5OxVXLaDJ1EWp8z9My+v7HOodZk
         o3Jafjf7BHPTqe9oY0v+hRTjnqjjYI+dMrQ1HF29cuBw2NN7uKf+/SLzAotyBKbN+0gQ
         6AEn8xSYGUB7ewOy0VP3CCJ7Mp4kOe4guj3zH98wdRCaVksxIDC89/76k47ei4wtuQLg
         I0cIj6KTMmVNu9hkH3nTu3Zi7JkZLBqAEWcfXdU9X0yFIL4HQT1lzXNkJKj1qMWWTsVh
         lf83LjGeI/t9BtwqOtZT1RFt9QHaDugKlhrfvcxXuGEeSx2ZEIvIoi7FY8IahXy5wRFN
         mwuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=lg3UqXF6q2ogG0aws2NzF1jHYSyhZVe/vA7oA+neKFA=;
        b=SJ/jQG4m3YiMxWVkodkvx1TEgdbswwJxYRQpxnpRstDgEyH+oaVGxAj7xqCJKjucML
         nmzpL4I4asaigbJGFbHiYUOO90LutprQ8aAR7fsr9GBHxaXKsIWcLG9DDUi4u0SFcQ9B
         +eUV2vAg3MWKdgMG6OyEhguA0DCzH5/4NznsBU/h+N6YCJJjx+CcTGNBlxOR1Y2Df1jA
         MfvG75rzy795blrEu09h5xwOROyFGvMIt3eZVx/jeMzv5CowPfg5X98UwOVcsNchyvoL
         2RVLm33cRMRMoG/edYyTypGAMYnFySa2FqdljZrINq5w73HRH2HJzK1fFGwIO/PRtKJd
         n1OQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="E6/bkMrk";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id d8si2429023oth.2.2019.07.28.18.59.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Sun, 28 Jul 2019 18:59:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id l21so27379868pgm.3
        for <kasan-dev@googlegroups.com>; Sun, 28 Jul 2019 18:59:41 -0700 (PDT)
X-Received: by 2002:a63:4041:: with SMTP id n62mr30789182pga.312.1564365580822;
        Sun, 28 Jul 2019 18:59:40 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id q1sm81000964pfn.178.2019.07.28.18.59.38
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Sun, 28 Jul 2019 18:59:39 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org
Cc: Daniel Axtens <dja@axtens.net>,
	Marco Elver <elver@google.com>
Subject: [PATCH] x86: panic when a kernel stack overflow is detected
Date: Mon, 29 Jul 2019 11:59:33 +1000
Message-Id: <20190729015933.18049-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="E6/bkMrk";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Currently, when a kernel stack overflow is detected via VMAP_STACK,
the task is killed with die().

This isn't safe, because we don't know how that process has affected
kernel state. In particular, we don't know what locks have been taken.
For example, we can hit a case with lkdtm where a thread takes a
stack overflow in printk() after taking the logbuf_lock. In that case,
we deadlock when the kernel next does a printk.

Do not attempt to kill the process when a kernel stack overflow is
detected. The system state is unknown, the only safe thing to do is
panic(). (panic() also prints without taking locks so a useful debug
splat is printed even when logbuf_lock is held.)

Reported-by: Marco Elver <elver@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/x86/kernel/traps.c | 13 +++++++------
 1 file changed, 7 insertions(+), 6 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 4bb0f8447112..bfb0ec667c09 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -301,13 +301,14 @@ __visible void __noreturn handle_stack_overflow(const char *message,
 						struct pt_regs *regs,
 						unsigned long fault_address)
 {
-	printk(KERN_EMERG "BUG: stack guard page was hit at %p (stack is %p..%p)\n",
-		 (void *)fault_address, current->stack,
-		 (char *)current->stack + THREAD_SIZE - 1);
-	die(message, regs, 0);
+	/*
+	 * It's not safe to kill the task, as it's in kernel space and
+	 * might be holding important locks. Just panic.
+	 */
 
-	/* Be absolutely certain we don't return. */
-	panic("%s", message);
+	panic("%s - stack guard page was hit at %p (stack is %p..%p)",
+	      message, (void *)fault_address, current->stack,
+	      (char *)current->stack + THREAD_SIZE - 1);
 }
 #endif
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190729015933.18049-1-dja%40axtens.net.
