Return-Path: <kasan-dev+bncBDQ27FVWWUFRBCEGT7WQKGQEQVJ7ADY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 66CB6DA312
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 03:25:30 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id b24sf572269pgi.5
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 18:25:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571275528; cv=pass;
        d=google.com; s=arc-20160816;
        b=FutOBY17jSdELn2d6nBPXidDvQGEhEfUZyqHsZXvBGcM+R56hEOUqDZ9vW+vBloHG7
         RUC/rpLY5URG3nnp8oEq0w6lxLS5qsxI4/aCxwgxif/Ve8lO96CeHUvpi17XYMtvvyKE
         5voqaDPooaT69/AXg+9rK3nhPDiweuJT/X8m0TA45+cLSfQQ1X616r03vTHhT9E8+fli
         zktYP2vB5hWVVkd/diyAzUIqR3/WHDey5JwpN01OEkQNgnITcCqNRBfVazS37jRQpWL5
         gO2T4klQAmOvrEnQ6VYvLXxPv7Qna13yirP+XaweW0nuuoZZ4cgBEko1yNF40a+2Z+mO
         xm3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5iL4Q/iGzuSFFqCBHPOZtGzQinOc8X5PTx2Fv4z8hVs=;
        b=vlnkSNY2qIQctmUnSqpF5M8IGeFc/wVGcMrE7B4L4IHITiUjDtnIq0y846jlVGUAzd
         5sKauKX0ZAXQbb9IZEsiFOQZ7z6BOux5MV8bVEsc+swRZNo+xcDZnfg/B/rnIXhHCFDl
         lze7FRgiUw0Eustm6Zs1AqrWwTwzFy5Co1tsCUcddFgyt73D4ecyEc2MZr1rHXVXupWA
         3O6D5MEcE48yUXP2otqtUF/ooae24vRnNb2uMB+IjvPj3tV8uVR6ioSOh+wG4R5rhktu
         WLA3j1KE50WiXAPwIOsW/2PnynVHUv6D2WFhexj5NNrhga+DMWlXa2846JaDq/1o1nIk
         W8IA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=YSJ6KAHi;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5iL4Q/iGzuSFFqCBHPOZtGzQinOc8X5PTx2Fv4z8hVs=;
        b=UQ6ZQz5mnZR/ZfhPHQX+BwYxpyo7Q8w31QyUbJsR7xmJ1tqK/gJx5eqmhF2tinAavo
         llyoaX/9FU+aFA2PfP97BGgJbK8CZI8cPIK3CmCHAgWYyg6flOEE0ykP8/v4LghE2XV+
         mbtF1mxl0wC9iGxB4cxfuHFcAd6Nxh6WyuLRDCaCuggcSui1MsRKFtQX4LTnoev4VOGf
         Htsgi/SjUq/6JNWJME9ieBrZFnhv5oeF3tJYbaiHlt3MenjiMAYmP1rl5eu87iekjh3R
         pQ9UTqS1BZcQAoLGSgg+39JVnZN3A9b8a4ENWX4HnVbKtGZzhbKOVkznVB2Mj1JbE97C
         VwcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5iL4Q/iGzuSFFqCBHPOZtGzQinOc8X5PTx2Fv4z8hVs=;
        b=ROQrKZ3JwYcg2O9sIqb0CH3B+9isIT1atA0VHtGT6sQmJ8wontTW0gcs+ubxOeelCX
         dNTwhurAAUX0jmmmXnFXaqhPxZ3yZRqyVqTplS/zBadPcJIq77dRhPiVbI4Zz2McFpae
         W+qR6CK6zGv2LFC0CUTL2IqczsCam/GrdAbRN1FJab9hGVSTh/NvdS1RXXzfQ9IoPfxj
         26xlpd5Wz8Vz7+rQguakQcV5RG2N4imcc4UEL9LnkVxOfuDqvRkMb7F72vyMZ8HE8s15
         VHgSLgX4sviigUfrubF/lpoVz/md2QmMLS32Do5icMTlZffEn1ceihH6o1x4OKAG02WN
         lZCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWQraKkoBEmKPQAlNqZIP+w7dXauATKCPZMR7m2KgfSqFLBsxm2
	NnsuX3HtmCmVwOEcIwDaPSw=
X-Google-Smtp-Source: APXvYqxZSRP9Do/QwZQDhNUKLG2aSX0EuKMyC54GnI/QvzLDtyYulxpUpN0j9wI66dvOz80PUaAoAw==
X-Received: by 2002:a17:902:aa86:: with SMTP id d6mr1275621plr.268.1571275528749;
        Wed, 16 Oct 2019 18:25:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d68f:: with SMTP id v15ls136363ply.15.gmail; Wed, 16
 Oct 2019 18:25:28 -0700 (PDT)
X-Received: by 2002:a17:90a:bd01:: with SMTP id y1mr1111684pjr.108.1571275528442;
        Wed, 16 Oct 2019 18:25:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571275528; cv=none;
        d=google.com; s=arc-20160816;
        b=EVgM0Zo7EvjQpiSnWRZSNMDA3XzN00etiC70gGkXhYy8U/w/pp/cHfinVEpwRMFsM8
         lCpDmIpFNeutONLRlsuP/O16uuX+1OCIYp99ziX5P3OnMohGz4Q0PGLDKZyoQFUJi8Wd
         Y6WcxN+xJ0auw1XSEaGzPQqNBdLdhdsDHqPA0iwbENsunrNZJaJeI4u2kbp43dKO2vCE
         HBYy8t3tBQ1ASyrIl+NTLv0EqRlbFlV/AO6urgD32qVj3/K0WLj0z4mbSUCKJXE+NlUQ
         LCeCJxkTHTAVxWrXNJ0ewX0UdAfpzGKlQe6C9h4IP/+Hq/N3CbKtSaWALU4fPvtgPXZ0
         JyCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1Qk9PXHlMYGMSaAT4No+OXlpNbokcwpw05BcYMTN8o0=;
        b=A0/FgbpCOBQubHWi8chcyVO/EdcD9KtPmoMlBtnXG2i2PI18ANmYdUEr4sULTO9aSf
         BpCvQnZdh61aklLJmGA2w9fBl3wLGSp9KIek46T3Fvqs09bGNGLTPvX8GBPled1WMdA+
         xjOJrYnwjrPFHRoi9VN4bm0t6tLglQq0Mbl4Jl6JSKk2Wqk+hS987af3sStwexoiNA/+
         FeN+r1UEY08++7g2Yy18NNpCb30iMbz5I49ZHEvZudX2n7SxTzqt88VGrI5Lvzu3Tubu
         InU8wYWhnYEQGyXZnvTDfaJwB9ZDJE6cZ08beBrG+VAP7HqGlrlZAuaiiTvgUWUEGhZm
         A0fQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=YSJ6KAHi;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id z22si521435pju.2.2019.10.16.18.25.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 18:25:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id t3so294749pga.8
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 18:25:28 -0700 (PDT)
X-Received: by 2002:a17:90a:868b:: with SMTP id p11mr1154784pjn.58.1571275527734;
        Wed, 16 Oct 2019 18:25:27 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id 127sm351343pfy.56.2019.10.16.18.25.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2019 18:25:27 -0700 (PDT)
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
Subject: [PATCH v9 3/5] fork: support VMAP_STACK with KASAN_VMALLOC
Date: Thu, 17 Oct 2019 12:25:04 +1100
Message-Id: <20191017012506.28503-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191017012506.28503-1-dja@axtens.net>
References: <20191017012506.28503-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=YSJ6KAHi;       spf=pass
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

Supporting VMAP_STACK with KASAN_VMALLOC is straightforward:

 - clear the shadow region of vmapped stacks when swapping them in
 - tweak Kconfig to allow VMAP_STACK to be turned on with KASAN

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/Kconfig  | 9 +++++----
 kernel/fork.c | 4 ++++
 2 files changed, 9 insertions(+), 4 deletions(-)

diff --git arch/Kconfig arch/Kconfig
index 5f8a5d84dbbe..2d914990402f 100644
--- arch/Kconfig
+++ arch/Kconfig
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
diff --git kernel/fork.c kernel/fork.c
index bcdf53125210..484ca6b0ae6c 100644
--- kernel/fork.c
+++ kernel/fork.c
@@ -94,6 +94,7 @@
 #include <linux/livepatch.h>
 #include <linux/thread_info.h>
 #include <linux/stackleak.h>
+#include <linux/kasan.h>
 
 #include <asm/pgtable.h>
 #include <asm/pgalloc.h>
@@ -224,6 +225,9 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017012506.28503-4-dja%40axtens.net.
