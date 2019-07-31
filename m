Return-Path: <kasan-dev+bncBDQ27FVWWUFRBNMAQXVAKGQEYNX4FRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DE797BA7D
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2019 09:16:07 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id j22sf42586850pfe.11
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2019 00:16:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564557365; cv=pass;
        d=google.com; s=arc-20160816;
        b=YDTNeSdXWndfZcKpm9sZMVKXMub+7Er3sb3j3K770dGiZgrDFXtv6F5Yq10YYTPmPF
         S2T4cw0KiSCu6ZeBSm88frDATe0ECiAey+R/yB9rBzwmfEOEZUH6ZT/o1qvwvDl2xnVP
         PLISP/dW1ykyLwMmD1tgPeHjZA6q//nY92jcZ/ED2eq45qtH39MRAIRW17zBJGe58Kwk
         5Wtn2JXQR11cefOthG90A524DL0XjumUH6IZECvjDlpPIxiSR734SwvBuebcrjKWTu3r
         RaXjRJLH3XNqFaMbyfhnUBsbQb1murUZs46WBrXoopa/IgXZ6xkwjeSnOv5R/DOD4dGp
         InAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=sAlolhW2Luum4fdyD86+sdkDOn/kwkryCnV8X95T7FE=;
        b=VlMxH59MC741vGTG9iIlSKqdm+kTBLMXEEc0O7LS7p3Xda5y3Ky5FjcPZC9Atigomq
         2B9ajDdTp4ebJAsY8tmiPBbNa46rINnPH9gNw+UigaMGAEKWqJ/Jge0CG9xZfqcduJXb
         pwi6A9l97iKWaOlDJRyffBSZ8JPauK0TiwCxaUfe8qyW4cQIwbWCUzt6hHPRZkEZ6+vC
         d9yXAVRjdvbkIOkwAmKMxmUoJvn/b9IwaAdOTrZua/I51x03eZoITNdHxbnglO3/CytN
         VMcE7syVSKoERuTWao8Jdh4vk6NMh33qwtiA/oXWUP8umHbgk+9W3mWsfoXwIaSTC5Zv
         huWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Vb4l6hRe;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sAlolhW2Luum4fdyD86+sdkDOn/kwkryCnV8X95T7FE=;
        b=JEoGJtKYHA1ddPMKeFVEnfh54PA1jlPcjfWyni9rvupCYKuO2dG/2OeeO1QyyeGzS1
         bhTlHz0VU5o2Ltn4V3Qq6n6UTu5Cw5Uic/4+FCkQ08vGyt6ILNvTJaJ4sO67oXKSpndy
         GHFOWiiA+RfIOgZ+P44c8FZWBtFMjS5kCDgWlIlvcQNcW5+itjd4lRuoM6RJSUbj3BeZ
         Dx7g4zhZb6cfq1NJo51QbPNa8bstR0dwuXVU9XWQhzDPglwp1rJ8/oNCls+4FvGhk0X1
         P68F5lY+uuXb5ZAbbGQtuW06ctoQPeIAuPXV3cKLET8vHKy5iZdbD2EWk940kKb/GSd3
         rkcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sAlolhW2Luum4fdyD86+sdkDOn/kwkryCnV8X95T7FE=;
        b=DpYJBzz7HSsghHsbNRQhxRB3glcb8kYDn/Za4qVEC1g/rzStqeR8UzJKdV24CiIF1q
         ITsFod81iy5s5nI0isGum1QT8fhZ6BPcjcZI5etq+5MgqexU9Qt13sY6N+c3wYJ9bryj
         +XRoe47Cs0ZQaQ9Uoh68l7dQorHSmWSjtYtbNiRf94/xwxwZrxHaCqns3xsI8bIJmT4v
         wdiex2YWkQWOiDeUJUJIojMSf/zEagVTEeRyTD3sR98A4OMtxBaoc6AVVImFLICV74fO
         cB+wZSy7B96Xc4pzDVWRA2s0RG4T6so1+x8s9BNzJKIddSZHji7TVuLYgs/34SG1ZTH5
         A/BQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVhaDqM4IOwmO1xPtzSxLNAdgwa9kgvaB1MyNmenzjxyzAi4CP3
	ht9G4ticoPnbPsbrZd131Zw=
X-Google-Smtp-Source: APXvYqyrp+sWHt9CO/Q6dH4H6R3KcAIq9yuy2mvZTRF2V20opaGAw64lqor5jY7EdXRCUrZxxYSFWg==
X-Received: by 2002:a17:90a:c596:: with SMTP id l22mr1470261pjt.46.1564557365473;
        Wed, 31 Jul 2019 00:16:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9406:: with SMTP id x6ls14564043pfo.16.gmail; Wed, 31
 Jul 2019 00:16:05 -0700 (PDT)
X-Received: by 2002:a63:1310:: with SMTP id i16mr110957413pgl.187.1564557365141;
        Wed, 31 Jul 2019 00:16:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564557365; cv=none;
        d=google.com; s=arc-20160816;
        b=X2FPuSSQbFsXz32FqodgcyUuA0nJqSd/e+LOGQoiLyJtvECmP5+497lCwuYHHGfhty
         DwAGVO7GoTqmmqnucSzhT3vUoKnHwn5xpInW1xYOJ+1f3WfC+xf4wk/kcG1iqoyzNyES
         kwaSbbrpUx4u05F4dawLzt7c04HdhysguEXjvXomxg2Yf4e1iJaohezvo41EHfk24w3P
         9Ewf5mqmQIVhWg7KTxeufuaQScEe17RJYUmq9NUSy1TrOjnFbJHEkFsVTr+aqyZlvxYV
         YH4pAembskx8jO3i+2eJI2E3cYoY2vrVZHOkpyLZu5r6UGOS+70e8TMF98POWg6+1/Kl
         ajoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=w7zQctoUbbEOIFpo2YzbJpxQDN+pRrmLCUjs8vOkAsU=;
        b=a7wGYOG9fJd007rOLNCGLoPf4lQgQr5/dj6DUckc76j9fZyK9LayARR5ow+iKbtvAY
         BVCHuLXHs+gy7wL+TqfgPtlo8nRzkLIvqQvSJD4O1yzf8q9OVABOzj/MQoc8cK14VQNp
         97SkEea3x6Igw+IQz4P1Cr/QXzkpx/5YmFRazDWpv8zxh8Zuh523m5QK7Urs2wMHaRjX
         BsNNyQwcGlzmtuUZHD7LA3ZTVsvMqqKlXO60jqt709MQWq5e8Q1lq9nzRA2AnEcY4vZa
         mnYh3koMWykRafX3Ez+hE7RTso8UID77bFT7rjHRC5EqV0Q4O02LwUyvonpLY9h+AvLF
         GjoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Vb4l6hRe;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id b12si1790135pfd.4.2019.07.31.00.16.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 31 Jul 2019 00:16:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id w10so31485773pgj.7
        for <kasan-dev@googlegroups.com>; Wed, 31 Jul 2019 00:16:05 -0700 (PDT)
X-Received: by 2002:a63:e807:: with SMTP id s7mr109013541pgh.194.1564557364627;
        Wed, 31 Jul 2019 00:16:04 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id f32sm597045pgb.21.2019.07.31.00.16.03
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Wed, 31 Jul 2019 00:16:03 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v3 2/3] fork: support VMAP_STACK with KASAN_VMALLOC
Date: Wed, 31 Jul 2019 17:15:49 +1000
Message-Id: <20190731071550.31814-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190731071550.31814-1-dja@axtens.net>
References: <20190731071550.31814-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Vb4l6hRe;       spf=pass
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190731071550.31814-3-dja%40axtens.net.
