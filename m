Return-Path: <kasan-dev+bncBDQ27FVWWUFRBVPWWPVQKGQEFWTVNNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id B4DF0A54B7
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2019 13:21:58 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id l64sf15561460qkb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2019 04:21:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567423317; cv=pass;
        d=google.com; s=arc-20160816;
        b=nCBBDuOlV0dZ6oIS9GhvE8FLfG+JwL/p2NDclKwp50rBZ8tYP6rW0faINO0hEiaW4L
         /5foObts57Lrpt11Xe/9pLr8bl0e/zldr12n8yWNYluyAUnyQjRJHA4Ym8nT7hj+K8Tt
         DU5aWb9KmteMVIpAI/SVwV+GBOhLRziMagETwP5qg399yfxiBtqtw97FR8j3ozaOXbAM
         p8p7/nWbjnvHXulU7+my6KCfkkD83VDoCuwi+zsIr8Fc9mUguDxSen4I07aiUv3H5+B+
         fYtUE8ODivKKNwKk1buK/HlhjBv/vwdf7imHdtqToCNvvTAt1cojaU4XtOSSzp5BxS6z
         ps1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vrzmiOzE0ohJhYn1SevkYHXQqynYJrXHQ12r7rE4edw=;
        b=iULzyL414zrc4eHvXDDAnCLo7RCdaeqfJAmaO58xK6C0rW1NpvD2ETwo/tLBFm+v76
         nAX1zQaKfH3Ly9gLRr1tvg8Z6m42CVIB2DYPVfp4hoaJegNz/xBjilutKFSIpVZEOu2M
         qe/gMdqkExHw9EZDK6/mexb0VUqtWpai929Cy6G7XsCMbBxL0By21jFBFnO+CtXyr5Sq
         +VmDVC1kebyVMYW/GRuTzNviT6AfwhMcfi4rDZqy/sALlt1MtMeqscRCnVp0dT+lF+dm
         jUATXA2WgmjjD/ZqowZLf9dt7Na8v5xRT6Okc3g9MiUY6666mXsaL7QiFxCYiX4KcKVB
         xO/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=KJvuFZFe;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vrzmiOzE0ohJhYn1SevkYHXQqynYJrXHQ12r7rE4edw=;
        b=juwVl6x0/s077PGJ/++n4vzRCBOjhqzM6+MrcGtddql4OdmzLLGvMTorONHC3PtUrD
         ixeMEfEC9TlZByC314xVywqJbRkhPXmtvxUxFV3gnDSy0n3oKKMha7KEOv9oev8BjYqz
         xGIpaqCIRnxhIWxADm8dl7DixzuCHSGCqMNL2E5JgjlG+FLWdPwQD3ChI5co62r3Cxyt
         MQ+LM4yo4t7Ar1vQXcSOiyq86ocLXcRu0YVxULoNNOAS9QkwUQALhZoTjdwrxB9NSrGs
         cJtslkGzmvjq2p5ZDfJZVMMOIEnwWg6ODoarAvpRxXgab6GqGuKnct6v8nDsDmUyxkrk
         AnzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vrzmiOzE0ohJhYn1SevkYHXQqynYJrXHQ12r7rE4edw=;
        b=S45oGsYtHarllowURnAYWFueYM86QQS5gmw1ghRZgmkI/X8dYGIfdCr8H8N3AMICs+
         /GkRyiZ+Y8AppKwY2t4V2qYsUX6T7WW/LCdhErravPQPhiUZKCyzEIhI2yDTEvVhuOyc
         eoO6Vmp9N1R3M+WcFkCEjIAW/KKc2Jd4r9yt0zei2HiRoiq8bDWkNP/o25/kJisL2Gmk
         dkuUCwq1Y/vC2laiI6YzjARTQipX69RuYqn7zeAxA7UZKnDEBuhk2G5GorWNlHZEjSZE
         fMo80s6BiwqDqffP9NuBdjar9G4p7uxbKtJkD259c8N2ioEbFvRA9dkWWw0h/41TGx4M
         yBNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXFOaw0Y7MI1sqGAE6rryJUQkhvLPv/XOprtxETaOWsEXjhF1AE
	n5hyDJgBb98h3mOF4ZSYk/0=
X-Google-Smtp-Source: APXvYqwrDUtjhWfpxP3AaoLmZ278h3PuxLsNefWO4NjM+owSJFpNt7wvyKcPapYjJQU4dMdQcZVAig==
X-Received: by 2002:a37:6e03:: with SMTP id j3mr27020487qkc.362.1567423317797;
        Mon, 02 Sep 2019 04:21:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:e30a:: with SMTP id v10ls3330747qkf.11.gmail; Mon, 02
 Sep 2019 04:21:57 -0700 (PDT)
X-Received: by 2002:a37:ad01:: with SMTP id f1mr6000937qkm.213.1567423317595;
        Mon, 02 Sep 2019 04:21:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567423317; cv=none;
        d=google.com; s=arc-20160816;
        b=ROgXygooJSedA2N18E2rXSJAo7/aE8zqiyqurQUrTTSsv+1zVVQX1F2OGY4xkG2d5w
         v424TOhRqnGSjq2Rc8zG7q3yWN+D5se2350XO2AdfPorkV2CCO7KS8QhrZiXtw6i8zgw
         NZkdxwiz+rhBHX9tuFLLqdCulH/GEO4osSz7ErfTVMcWdw13QEcxX8hcS+MRsdlQnzg7
         oPCzr4h0PmFBxttmPumiwHCHTebTAbCxB7b2ok+2DyaKKJJPzA08OpcuYN+ZQPbq/knE
         xejTA7D+SZsZFc5ucPZS6WKxs+QWFl2t6MLkvB9btQCV9xDLk49stqAcEVzxSmlyHgfh
         fVwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ltnYvwXNt85pQWYuu3Woofu2pXYpHtCxsiErjju1VKA=;
        b=o4SET8z1FzZyBMK01CcmsOCSlurob1yWBInvNRxaspEKQo4oxaWl1QTDCChGZbRkza
         2Tn9uqOAPbJYaoGYfDkYdhlmK9sK4kUSQaikqdcgGzVKQT4HzCjDuE/gzbon+22H8gqd
         ynPNTExtq74T7CPdJyUADh6YxjXqTEZ25sFr0NDt1G/RDOGQ2a77KY9cH07pYlRuzfSv
         msTiVQ/fBcmexA4y59URC4D96xUFvcZuGFECOTx3B9f/rCbCTGLBQ3HId+9PScHIHjOj
         NDlPrHP2oE13xY+wm1jgJXdUG7sTpwIul9LDGIdBhYfEEYA0Hi/hkWP+LgpBvqLrsHqH
         Hm7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=KJvuFZFe;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id 37si843047qtv.2.2019.09.02.04.21.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Sep 2019 04:21:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id w10so7345534pgj.7
        for <kasan-dev@googlegroups.com>; Mon, 02 Sep 2019 04:21:57 -0700 (PDT)
X-Received: by 2002:a17:90a:30e8:: with SMTP id h95mr7353865pjb.44.1567423316484;
        Mon, 02 Sep 2019 04:21:56 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id k5sm21422793pfg.167.2019.09.02.04.21.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Sep 2019 04:21:55 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v6 3/5] fork: support VMAP_STACK with KASAN_VMALLOC
Date: Mon,  2 Sep 2019 21:20:26 +1000
Message-Id: <20190902112028.23773-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190902112028.23773-1-dja@axtens.net>
References: <20190902112028.23773-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=KJvuFZFe;       spf=pass
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
index 6728c5fa057e..e15f1486682a 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -843,16 +843,17 @@ config HAVE_ARCH_VMAP_STACK
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
index f601168f6b21..52279fd5e72d 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -94,6 +94,7 @@
 #include <linux/livepatch.h>
 #include <linux/thread_info.h>
 #include <linux/stackleak.h>
+#include <linux/kasan.h>
 
 #include <asm/pgtable.h>
 #include <asm/pgalloc.h>
@@ -229,6 +230,9 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190902112028.23773-4-dja%40axtens.net.
