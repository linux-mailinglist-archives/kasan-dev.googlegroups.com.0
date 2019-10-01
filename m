Return-Path: <kasan-dev+bncBDQ27FVWWUFRBM7SZPWAKGQETAZU3PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id C6462C2DA2
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 08:59:00 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id w14sf8700340oih.19
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 23:59:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569913139; cv=pass;
        d=google.com; s=arc-20160816;
        b=DuOnVpVtIFtc6sO+maXY2q3Z1e1fAPjz2WDI7zzemYC4YaMVGtHx1Gvt6kF5HZ8T8x
         WDhRlDXPJm7YXO5C/s1+OdJjgSxBATSzrW4sCm8Zsk7r9DE2BQRYzcEIT/Z0UvOEf/TA
         B49hXwD7KBhUYPx8swtVxfD0YSQHrEmKJ60osbcxAvUjsnkpAdSgUTMVaCrihyEQaLsR
         RDNPGch3iPrt1ve1kRi115ca/76ll02M6OnOtwE6jJs73pCY7TQZ1QXOWPGQ0mvOHXRa
         4o0yYv9JJObKkKIJUK8nckZ5jAoTEPyx0uCtI5rLfCMbBFnol5V7x7QLa809XbY4e+IW
         kcIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GK5sp9fXu++HzAtwQ4ilLHYug2uK4gEAmw8O0cvpOCg=;
        b=tmBAT+0LqLa1nMpqcYs2fvaQzQJb11ZK2qeDYqNtY08LWQRWz/OkraAFS5I+lA/+yW
         YsUqzzAdp4/uvxwNHr7SSgPGEvub1lk2QKvwF2IFnWM3yVnbHXQMWNCcFpA6Er0vuDRb
         yCVl2SHWfNiQBF0qIKBSaNJtDYDrQszS9vLv2QBJh7cfjOjCCgECpYK6Av1jpjsKhkoT
         Pmc04dRQBAN5dK2DcoN7tZaGkfD1s+eF0aB0Dj4UmDTEYjiUMaXamvQr4GecMiK4XI0g
         SGCmX9yXGhSIR9njQwslt5q9PIlW8f1jGhbabwRNZWP5IRSA4R/dCZ0nr/ImQkFfTW7Q
         viYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=PkKrMZvk;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GK5sp9fXu++HzAtwQ4ilLHYug2uK4gEAmw8O0cvpOCg=;
        b=Qx6TAu5ndUt52NLasmokrPRis45HlFRZgFifcOVGFqDVTYoJCfwdTrClonvyzguXWC
         Wy8kQt2mG9n896+pv8Bt9Gs42VcLmppWO6Lgb7B28zAjODuA03Yug3/AoFBjlqxq3EQt
         Bswf4rScPgn1q7KEu1CBE9RjXheXIJzBZB0eM3+3XisOjInSZdNvhmIgnd6/4FwIsvgW
         9FRTSw1JY21gvOwrpOsvFfoHIFikDVV130iczxKfZ6khXlT9XTTbGU2aiU78XZ/5vucL
         DzmbF+PAvQYJ1f2vkRHVF4agtDeqYrIoqkwN20UI1IsEL5m7XqGN/LdYhySX+srSL4uu
         WNiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GK5sp9fXu++HzAtwQ4ilLHYug2uK4gEAmw8O0cvpOCg=;
        b=esn70Z7R3gtDKpz0W+I5mo55mEwX3nlkSedN+FiWV2NQhEOfBdE6lRgHxyVSizv/Mw
         AC9jAsBE2cl7FrBBLZpIi9qvyvRBuSHpnx3PHl62BXvtE3yRhv2UbnqkYJgiOpsC7nQs
         krCArumEGiBVSftE1zU7FHQTiqpGHlWaQpIektTTeVxwKKwc7bDpnvlml6O8/mCrRqok
         wB9JdN4UrqFXGmVb0ksbD+d0zwgWsj+bUSLqqBH2I4E5gKs/5hhreeZVAgxflsVYa1nM
         62mJPsb4Bbi2M/qriQJEZEyPcgvNor5JjWgh2xLxlHSQ2iNxNjlLTOtuvjqFdUiPCmJB
         Pp/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXtn9o5x3nR9xF9Ywx2Q3803JDRj8O6fx6JWCwgEQUV/YVrahKC
	My2YqKtiCWX1S96tL5q6bGA=
X-Google-Smtp-Source: APXvYqw72YpTeTFaE5UY2BGUzuT60z/frc9b88SX+abLDz0VSacP9lI8gvQH1h32XttuDxbcwVU/dg==
X-Received: by 2002:a9d:6310:: with SMTP id q16mr1599499otk.4.1569913139193;
        Mon, 30 Sep 2019 23:58:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ad92:: with SMTP id w140ls2990831oie.2.gmail; Mon, 30
 Sep 2019 23:58:58 -0700 (PDT)
X-Received: by 2002:aca:cf13:: with SMTP id f19mr2572595oig.154.1569913138877;
        Mon, 30 Sep 2019 23:58:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569913138; cv=none;
        d=google.com; s=arc-20160816;
        b=LopZKdooxDFYB2pCFR1Z+jbjkEd8g9Mkdrn1akfWlQ99xSitB/y+6FY7hE2LPLclWJ
         8niDpSJpmHKIk7wN7nNNj1nEbxWh6KEBnidtLOOcbyrTxeIPF3/XD9sV+uImuaaeUiJi
         LDAlk79GDkwphNJJoJzgHcLiSzOImw3sWCo+OnC/gKLcv9v6ZaiQC8NCIoEWO/9Hv3Iu
         mVIzAx22ZPWgLfnhkuNJfaQRL3lVcfZNgqm0Tb4ZLMxDLUlOq7y59CQ9GU3WXF4l3+kL
         8chMnErr7noXVCGUqw0UnQFaCosSWDKa98PVAEZ+g33DXI7IjWDMoQgUDaDlWxoIWMKf
         UCxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ix0tFBRmdQmDh77QwfWZLAnX69tqINWfajYEldnceVk=;
        b=Nyq5pc13NJccSqI39GbPSmT/iNxmFRiyq0/bhUi0u7atKdHsSdVCmLwrLnTO51h80i
         gEo/mmEWZCYGBGZgtHKmwhyLHfCQr0vnUaXNqY7Lk4Hk2t3KfhmzzMFM6HI4pFsUiD0x
         J6CY9OfCk2FMXH4bVwML7vf1CIRRXcveCkC8Y440DiHVH0P3X0QPOnx+nKOBkKHZ63CY
         FGfDcRtegdVhdw012GGEkHog5MvBvhVA2r/XjWGUFebiuZk1pCpI4EeA4it/yJhfp/P+
         TelQ7p40l6khthM32yCIZFWH/bfUZdS6nymmBw7Umy5eEF0zPGSzYUVVcth3X9EqeJoG
         nSrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=PkKrMZvk;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id n63si796305oib.3.2019.09.30.23.58.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Sep 2019 23:58:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id q7so8913103pgi.12
        for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2019 23:58:58 -0700 (PDT)
X-Received: by 2002:a63:7d10:: with SMTP id y16mr28593557pgc.368.1569913137887;
        Mon, 30 Sep 2019 23:58:57 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id x12sm14654380pfm.130.2019.09.30.23.58.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Sep 2019 23:58:57 -0700 (PDT)
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
Subject: [PATCH v8 3/5] fork: support VMAP_STACK with KASAN_VMALLOC
Date: Tue,  1 Oct 2019 16:58:32 +1000
Message-Id: <20191001065834.8880-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191001065834.8880-1-dja@axtens.net>
References: <20191001065834.8880-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=PkKrMZvk;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as
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
index 5f8a5d84dbbe..2d914990402f 100644
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
index 6adbbcf448c3..0c9e6478ba85 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191001065834.8880-4-dja%40axtens.net.
