Return-Path: <kasan-dev+bncBDQ27FVWWUFRBQP433WQKGQECIPCVMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D2BBCE7F22
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 05:21:22 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id 6sf9777182ybu.4
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 21:21:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572322882; cv=pass;
        d=google.com; s=arc-20160816;
        b=qqqaTcU/i3lEfjjR4v8HNqlZ/D76c0S0ps5zaajp32Y4I4FztsTt0y/VrTs4zGkXwW
         kbVGB7n4F+Tvl+07HCsVEKIp/KCLBH4v5WhcVwfarvNnKfcyTE3+u2YXOCyVu7IBDJbn
         hKriBrKCPsmm9IgpjEiStXUUXjXyzJKtijUPdVajjBFoeorDhW1V7FxtlBOkr0ldbvXz
         az/bw5DHYRAPozJpI9jmPCI92uFts1yoIrrIPDdw4qxRyA/Wa+Xf7GFb7N1HKZkOTG6g
         WagQEZRzHD0C0VLnNQz7cqHHPpv6AjEeM3SzeKwLKp0jrX8qArl5G7fjJa6cod3yzB/u
         M69A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rD8iQnM/zhT3h7NCbshuRkmjI6K2KoO0Z2oIyqimG8E=;
        b=OPy+creI9ZOC3i2RQT8JxIQiypfypvgFZOClWizEjlbVxO9c8r2ulLqq37h7ymrp6s
         qHRzGzJzw7esfDetExCReV+5IWLwNteo53Rh0R9pug7+H2P+H1uJeX3ytNbd7hUDSDYv
         5wp7er1MbwwA833+eRtZIGRGhDjtFw5t00RSY+2Rb/jueUCvXuisGd2W3P3IasC/bvKC
         cPVjXCc8w0dWXu0R/n3cpEMs2oKhQFK7+QCAVDmiwu03Zv1nkmvAY3NLUBT4BCFBhFMe
         JWq68peU40EbWuASwpA1/4m3DpKCOeg7IOHuC/dEWhISskBwaDl3P4MM2I6/41OM25hq
         0vSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=p12QlXY0;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rD8iQnM/zhT3h7NCbshuRkmjI6K2KoO0Z2oIyqimG8E=;
        b=Q/B48gxhfvQeTwrY+OTVvRci98Ay3ITh1d91GwyCrMQKEzERiKezKq7cfk4wWxe34e
         OLvvcsAS1VG1DXIpIQiXxeijS+8oBeBX7fDh0ekWsLXQrRp3t5qJ37J5kzI5uekuajwa
         K/WuO47a6eMHduXx9AWisBps1uLReBXn5nVgL2Sq6Lm6eH0E/Fx1xVu+HzvHEpF1Q+3J
         sNy6hqI7bq3Vfuf+BBx2RWJjwoFBnGjmuMVD5mOAt/EJI5WKDA8Uw0IpVA7hzWXzRtRE
         lAY7nKwGgYuapjJMsTKrZX6Skd0SIqS5W5aa7k6QMYe4hD5nAlzlrknxbVQK5jPGbypE
         PATw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rD8iQnM/zhT3h7NCbshuRkmjI6K2KoO0Z2oIyqimG8E=;
        b=ho0ropEYhxsPIX5RtPZsyaeCUUTdH6J/OIJ0Fp/fUzLoSiHAPn11XBatbXDf9Ya7OM
         jYbUgsKrTNhUdyLSlcYePsFqK+wMIJewS4FZLDrMecs+J51aPpARADyTBe4tFGTyvEZ6
         1OtuNU1WzruW5a955FUt5yxY5T5E/84+cc0vnzin3CQwLGcIWiBiqRXas6Xp5DrjgsFT
         MJXG098us3p4NDNLj4kvnNW0eHvARhXoVxhHx/iKbtX0LSMbJg7Hdf4oTwhBuG6xIsdO
         zSYzsgzxaXVLmdF2YRgAyfSHT9mfTLh40hWNnc8KN58LE05lKwp2i8pGoDXQEtXHt7rk
         da7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW32xq2OaNMQExnV/tqNJx+Vvul0C6whNfnIXlJd7DFnurE69jh
	WIe69HcA6ewUNvx7gVh3HTo=
X-Google-Smtp-Source: APXvYqxL1jL5IzRWuR8vG9xRjdlIBhbgc48CaNC54mK2IpnW/qnl8bC7UTspENImllUNRxq1D3UP5w==
X-Received: by 2002:a81:49c1:: with SMTP id w184mr15877544ywa.264.1572322881802;
        Mon, 28 Oct 2019 21:21:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:ea09:: with SMTP id t9ls2324914ywe.3.gmail; Mon, 28 Oct
 2019 21:21:21 -0700 (PDT)
X-Received: by 2002:a81:9342:: with SMTP id k63mr15659979ywg.261.1572322881416;
        Mon, 28 Oct 2019 21:21:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572322881; cv=none;
        d=google.com; s=arc-20160816;
        b=IGUp29zU3I6qq5NT3HxUS1iCdZvJZ1sRkZjfYu+bsaAT85EBcETBTQRl4hBQtfNo2t
         5Xx0Q1GZi9Q0Fxh6mKEy2/s9rkENJ4ruQwLprgU0gireD/rHNyESki20X+MaXjRN1OEa
         vNfq7aegxM8CksLWeEWzwv274E0OU8eUvi6sLoWpBwTMsLnynAYOq8P42c1OFSd96ZIX
         cqaPDzzLSqwaTyuYxnWmDX94wH5AVX7VGvMarEAJOkgshl0VakTHarP/nIFo355hB7NB
         DJgBgX9dL1LGwBNlrrBPhS0tcCtUBBNy4gK/knVt9hp3z5qorsycCvhm1pdFFq5Jels/
         onOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=D9aL7CIPgVBLEowXwwKDN7h7+lLHlmYeACx0xfz4QPU=;
        b=r5G8CREBsNh895oCUZcF6Y0UyiWaeMTXh926DS5CZpoJzp0Hn8ae5USpmvCCYFDEsq
         ZQ87l7LzfeCL+c60I3phE/LW/vFNj9Rl/2vCpUm8TJW1UljJwI8+jT33wE7SboKjju7A
         xKzaCoxDEzXiOGld4xHdDJwUIHYa7kkN9Ro2ncXAwVHNrhtGK9tu1xjfxDfAQF8cMG+H
         qzwk5KQrAJK4T969ZsPmRIT4aHjirAxACREPEO9fOZR3umFFD2t00TJERk7vi6SxOjII
         v9Pg24r40cmsui92wM/OCVvikjVVwA5uu+AkFIiFECJyHhnAKfw4Nbr7cmGZt2iO/xiE
         z36Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=p12QlXY0;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id v135si83984ywa.0.2019.10.28.21.21.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Oct 2019 21:21:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id g9so6299236plp.3
        for <kasan-dev@googlegroups.com>; Mon, 28 Oct 2019 21:21:21 -0700 (PDT)
X-Received: by 2002:a17:902:bcc2:: with SMTP id o2mr1697695pls.281.1572322880361;
        Mon, 28 Oct 2019 21:21:20 -0700 (PDT)
Received: from localhost ([2001:44b8:802:1120:783a:2bb9:f7cb:7c3c])
        by smtp.gmail.com with ESMTPSA id a5sm3908450pfk.172.2019.10.28.21.21.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Oct 2019 21:21:19 -0700 (PDT)
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
Subject: [PATCH v10 3/5] fork: support VMAP_STACK with KASAN_VMALLOC
Date: Tue, 29 Oct 2019 15:20:57 +1100
Message-Id: <20191029042059.28541-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191029042059.28541-1-dja@axtens.net>
References: <20191029042059.28541-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=p12QlXY0;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as
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
index 954e875e72b1..a6e5249ad74b 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191029042059.28541-4-dja%40axtens.net.
