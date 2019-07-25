Return-Path: <kasan-dev+bncBDQ27FVWWUFRBTMI4XUQKGQEB2J4EMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FD347469E
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 07:55:26 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id o11sf35019264qtq.10
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2019 22:55:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564034125; cv=pass;
        d=google.com; s=arc-20160816;
        b=kN1DwzDiSMBo6QvwnOOrj4sni4Q52xAKvKaQ7oNpXW0TXGSER88mUXqetDw2ZgWA1O
         pzTptgn/wwk6irSbYOmqorCSPTLz7yfw6VMKsdqaBqLsmQ5NZddCxpI7CyWDIOu4iBXW
         UdzxrYbXoddIs5MzFi9aFYBdUB6o+Z3wGVc4hdxfAOJvtbSWEtXSoh2dl0cdjwh6lDLf
         fuZXuFfFyg+ipoJ8smsaXGo5YwajGoK9wyMMD02dH7Ou6zSZU1/Z08Id0RQlonorbW8F
         +6edpSxyhk5M1STOKscmbJJb5Kg1U0ece9h4kSqwO+76R+/HMQCbKKTpiT7IwNdyuTOz
         VWOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gMHEgJ3mp2Ut5N0MNLoyjdL+mxV4wLGOk6hNEarTj70=;
        b=wo0/WDZ/LfZHzECP3JX5fmxXQwpkAhhJ9PKeSUliCDmYFZhHjAsZOoO8BTFxl2Y9vg
         EhbRLwNq3kCpap+7rN5+I1W0E749Hxpx1Ndg0b+kYG1rVtdP6XXYJvcbsof2Po4DovYm
         FtjYktsOzJQlSs9efF8zxp9ZeTuYtGZc5ggwu7NZHnxipFwq6krc4NYnIOle76ToEBLr
         WHXDBLtPG0K1J+6xa5U5H87/7W7874Lkp6Mb1OHHRZsfIKdo6CNvTCEMYdG2Zob+LM3k
         5DhgPmoVgZoB3GXJY21EXIXTaqqXR33Y0MkaJGuHru2368+/h7AQyqdOkjSa54wp+3nt
         CjKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=mV9UVVGI;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gMHEgJ3mp2Ut5N0MNLoyjdL+mxV4wLGOk6hNEarTj70=;
        b=sJ+bwSH145h8Tn8/YtAxekypYK+nvKEJ3JTzcbTDHCrkfee7JUsdYWjO6dYUfz5voR
         HH02jEXqq1c4o/hzA6Sk2ZXYVcd4PBJstVCRcg7cvrDleksHsVQXZ8k7KwiPT+nf0PYl
         wpxt0Jp4HaUDHhAytxUGOywsJ6CpiiaU7qYB4PF5nEpQbQs0Nsq0zore5XHzQp1rVG8v
         GA6LpdNerZyvl8PiFsmQnQSDcWfraXnt1HaMnE7Y6hrAJxsFLsaWManaDyfktF6fNX9m
         2Lk52TI4h9W0h55tx8zdicP0obGPYk5WCvR9FXMYj2Vqpewa9nwxn5Ym4mEywAc1Qeau
         n1Rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gMHEgJ3mp2Ut5N0MNLoyjdL+mxV4wLGOk6hNEarTj70=;
        b=UwIIiPdF3kpQXxSw5vnxQRb+CEFUcg6SdolcUuRw8ghQtrKDawMvzLFT5aN4HwVT/S
         BgWgCAGiKyBWkeGj0qvmsUyAT3ryu5sRYiEbaE8hJGgE118gmKPtGaxG/Xan1ZhMEwMX
         cOoz/mZgPAYFh/Otlqpte7uLP4jhDdtTQZNSa3At+ZQ8sVzNuRbmmjObjjV8j0GmpnaD
         xUs6py5ClwD4FL3Tkf+FSSWo3bk1fPWS04tP9hQypNPEZDfkyTR8W1z9thD3zWuNbR6g
         Ry221L47esNEhNs5Yi2B8yoB5pbD01tfaw8cewOmhxPbjVoLsreeWUJi3KEij8qr4ZuE
         CHNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXLCb90o5dvTjuVYLC0PS1RI/rMplt7SBOLoQhiSYi7BXrHE8FM
	y+fv9HG8AMtJjQnB0YHxoHA=
X-Google-Smtp-Source: APXvYqzGXCn1nh6SWRAn/bBWOGVj5X5fKl8TqsrxUKHeVwODdT4nR2ylMzPo1AHyhVKaKWO/8g4/NA==
X-Received: by 2002:a0c:89b2:: with SMTP id 47mr61820681qvr.203.1564034125534;
        Wed, 24 Jul 2019 22:55:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:d801:: with SMTP id u1ls4478qkf.13.gmail; Wed, 24 Jul
 2019 22:55:25 -0700 (PDT)
X-Received: by 2002:a37:a346:: with SMTP id m67mr58666166qke.237.1564034125313;
        Wed, 24 Jul 2019 22:55:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564034125; cv=none;
        d=google.com; s=arc-20160816;
        b=dQIbabUxNxi5nWCoTuhA+TesappzIAZ1O2yUE62gfcs6V+lYcQ7wMPsmTfLfEMPudn
         ynqHbEpUIYVAOQS3jd52WxC8Z3rczPkHTz5p5c36vG4BCzJrY5n1C17ibhSk5+dLSZFz
         4yVQePKa+rN5DLx1ygm9C1xufxkvtyIWXehYZBxi5N7iuG+EJ0hKljpsptd1QLGkCdkh
         aXcEmruIfK3+jQq+/PtCcWjaH71VTf4FJHRO4Wd1+apeMjnz+2dLr7YUzIl0M2awx0qv
         7P94d8HEujpzgyviKdI1OB3Ss9Nj8kEIzRY6ww4uofv7rWr1a4OfE1RF/o43/SQES1cp
         Xbow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fd9tgVPBKUqxW6buoyzOmO3+gT+PGf3wAT0jqJRA9iY=;
        b=zAWgiqYkrneGVrHjA9IclQB8s9DLCP5v97iuTqud1R4tw/QyZMMA0JaCGAnX28tN/a
         f7kcsrq0dCPq7H42QxIaCi4aZ7OxbgAGxPoYGgMkADRJUcMyKPrC/6nZfuOz3dfKVBuA
         l0GeZLakvKLZuI1LhM/6vorPzcRtJOrfMJaAlEBGI6uFc47o65T/SN0Q+8mUdG0bxpEe
         LZp0NZFgIxVYtsiIZ0EeMnCG0bzn+ymPzTsNURTrcLoOE6tkQ/IVtpf2AvDUbrvq60mJ
         W+XYrVruIyf5n0MRKMfPFZvsl6zjqbXJJqIdRBKvbuC+LYaS6kd0XbHrjzYo0UMcPREX
         AO5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=mV9UVVGI;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id l17si2161242qkg.0.2019.07.24.22.55.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jul 2019 22:55:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id x15so12087977pgg.8
        for <kasan-dev@googlegroups.com>; Wed, 24 Jul 2019 22:55:25 -0700 (PDT)
X-Received: by 2002:a62:2f04:: with SMTP id v4mr14551918pfv.14.1564034124163;
        Wed, 24 Jul 2019 22:55:24 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id p20sm75540475pgj.47.2019.07.24.22.55.22
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Wed, 24 Jul 2019 22:55:23 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	dvyukov@google.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH 2/3] fork: support VMAP_STACK with KASAN_VMALLOC
Date: Thu, 25 Jul 2019 15:55:02 +1000
Message-Id: <20190725055503.19507-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190725055503.19507-1-dja@axtens.net>
References: <20190725055503.19507-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=mV9UVVGI;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as
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

Supporting VMAP_STACK with KASAN_VMALLOC is straightforward:

 - clear the shadow region of vmapped stacks when swapping them in
 - tweak Kconfig to allow VMAP_STACK to be turned on with KASAN

Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/Kconfig  | 9 +++++----
 kernel/fork.c | 4 ++++
 2 files changed, 9 insertions(+), 4 deletions(-)

diff --git a/arch/Kconfig b/arch/Kconfig
index a7b57dd42c26..e791196005e1 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -825,16 +825,17 @@ config HAVE_ARCH_VMAP_STACK
 config VMAP_STACK
 	default y
 	bool "Use a virtually-mapped stack"
-	depends on HAVE_ARCH_VMAP_STACK && !KASAN
+	depends on HAVE_ARCH_VMAP_STACK
+	depends on !KASAN || KASAN_VMALLOC
 	---help---
 	  Enable this if you want the use virtually-mapped kernel stacks
 	  with guard pages.  This causes kernel stack overflows to be
 	  caught immediately rather than causing difficult-to-diagnose
 	  corruption.
 
-	  This is presently incompatible with KASAN because KASAN expects
-	  the stack to map directly to the KASAN shadow map using a formula
-	  that is incorrect if the stack is in vmalloc space.
+	  To use this with KASAN, the architecture must support backing
+	  virtual mappings with real shadow memory, and KASAN_VMALLOC must
+	  be enabled.
 
 config ARCH_OPTIONAL_KERNEL_RWX
 	def_bool n
diff --git a/kernel/fork.c b/kernel/fork.c
index d8ae0f1b4148..ce3150fe8ff2 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -94,6 +94,7 @@
 #include <linux/livepatch.h>
 #include <linux/thread_info.h>
 #include <linux/stackleak.h>
+#include <linux/kasan.h>
 
 #include <asm/pgtable.h>
 #include <asm/pgalloc.h>
@@ -215,6 +216,9 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 		if (!s)
 			continue;
 
+		/* Clear the KASAN shadow of the stack. */
+		kasan_unpoison_shadow(s->addr, THREAD_SIZE);
+
 		/* Clear stale pointers from reused stack. */
 		memset(s->addr, 0, THREAD_SIZE);
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190725055503.19507-3-dja%40axtens.net.
