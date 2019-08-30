Return-Path: <kasan-dev+bncBDQ27FVWWUFRBQPAUHVQKGQENLHMMDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 65B5CA2B7F
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Aug 2019 02:39:31 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id y67sf5523996qkc.14
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2019 17:39:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567125570; cv=pass;
        d=google.com; s=arc-20160816;
        b=z0yW7dhSMTBrKc5OGHQ/A66R2RiKKYc47fYyz7388tTmppggiwJ2SZ6/7WaZNhvuYD
         3tBtsAF0BMY2wvefYVVKjzGOfKgiIf3qGB5AaykSMTB0t/sanz6M+HY8g9GjRF5zMGll
         cVI6vqgyvwjovKQ35UwPZK8vqQrawjcIXXhG6bBxRUUqQOB/ayGTF76dtmZxvZaHTNes
         mTaBrv4jM1tu8qXJcDfdRzlanv9Ga6qUyTyPuHJggrEbTFLPE3gpaW71t7yRntXypFtj
         9TaoIBOLfWWk+GbI4c51itoofVaLCgrg6W8gFt0UMcRkhTK4JceEG6L50oNbDJ0PZFft
         bFEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FQpa5z2tMc0Tj+H5Usym1puZOu4Zg7wMl3FC0GWhLkM=;
        b=Vl47kVriF+9kpAk6w1K213f0awagtdeJJWFlBMEJyEUwX6yyif9O1DBd3sX5r4D87P
         G5X7atPvmGLWjArv4yLCCsso/vQDnQkA2Rj2Q2XM4fB++TyF5+rPSxOlJZNNV0hRkrTU
         FgCYNxTAGJF3voRyOzx978MZWWOjF/LSSyAEZ/2NtWQkxWBslTaE2kEke+4dbjTVEoWB
         gyBN5VVJ+Zn7FasdXD1wPnhgz68RlsYHxGf4WlhAnZNNjGph0nfujyyP75gAsT82r00g
         cj5dsdQ2ZfGXaAkPnEo87OdP9fymNJLIeimO1v8aya+Vqr8lOQlSt1BYYO977u2HAF0o
         DOaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=qZFO1ufn;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FQpa5z2tMc0Tj+H5Usym1puZOu4Zg7wMl3FC0GWhLkM=;
        b=J0K2b68I3YfUzB4PytOXWGrKBSVSJgFRNtWBI4gpXaZJlLBSHRpPZQGxSVxvI1zC6d
         oCigS/DzeIOVbMGQsvoiA5Ca2H8n6JlC421+Zu0Fo3/lg0+XaKalw8AFSHmYqTuNk7hR
         gRVnpJP9Iteb1oCYX5w8xOgTCGIkji9eP3xrrnpY7qbapXH7DCEjmH6vSEOiq6WYunhy
         mvkzlrxBpmnFu+oT6aKBCCjjjh284ZFhbcrJfTgLnV7fUNgII5ZQOLewCOenQ9U/VfX1
         zKEwcKr6yG6KccTWW+2gM0Eu22z35RbgFb1GrFCFJyG1yICbRGy0OJ2jDHovHl0t1yEe
         HF2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FQpa5z2tMc0Tj+H5Usym1puZOu4Zg7wMl3FC0GWhLkM=;
        b=CZFlLAnQqP9jw4hcgs8hzJ7rkQZH2zPR//MaCIzZKev6gRK4Talm/IyrtnTx6B0xgy
         +1e3Tt/w1gg5WwQC6TjOFoOYug2av9uiZDEsokzbhG/bXFG8XhVPJ0hThbYSwkdwmd/V
         Kz5Uj78Xf7bhqeg1/5QTZSQJcTKAuMmtlYiJFFa4yBWVXG92dYzcUV6MndvAcJ2rWBF1
         ybi8Eaiq5n1sK+UTI0EJtjccmpipjvGHjlvmp5JtEbcEkZiLmoUdgCezFXSusdbKUIwK
         2SKZG66OAOjEwzm7QPU0Zb3tBtjjxX1UJYwwQEL7UCSCJmuwI1NK+ByPuHaH2RXaQFmU
         VB0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW4slJueXlcmbrYoqAaGQdnK9xT1m8sGSc+zxtf1hdYP9SlqGII
	rjXVc2TWkSQ3ZLFQvxsCHEw=
X-Google-Smtp-Source: APXvYqxVGdJgcKn+HeBAYqYszw8TBbemy86EL8Tv+npk3bCg9TESeCC1VOkrkAMb/MYw7upaJwlMkg==
X-Received: by 2002:ac8:1a68:: with SMTP id q37mr12790448qtk.253.1567125569836;
        Thu, 29 Aug 2019 17:39:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:b387:: with SMTP id c129ls450979qkf.10.gmail; Thu, 29
 Aug 2019 17:39:29 -0700 (PDT)
X-Received: by 2002:a37:9e0d:: with SMTP id h13mr12870811qke.473.1567125569662;
        Thu, 29 Aug 2019 17:39:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567125569; cv=none;
        d=google.com; s=arc-20160816;
        b=Jt1wA1fY9k8aZgoD/cJ2KjWlKyQCrziSzS0Gjty6qqPiaJTPqVE3oKfJBNbqa2dxRU
         W98ZqqfueiZHV9n+9SCWdFeOt3udW6/tC9WWfR9/lAv8SmxQCadEClIRNhNwOka2ZI1T
         G7qNVxU8PFguOltDtHff87XFR1kxoexIOUGM1wdyUAVAJx8NwhurppQafazO2P63Jk36
         SNS4Ep0bmgdzsryokQofyKUkP9z67laSX54b4g9WzQe1xKEh29iVUH3lLxKRDyyt0ZKp
         sDk+8j5U/xTALNvEZr26DkCTy0LUZDyRSVfDEheSekwYhpoYYIjjpOvuuVXLN/9FUdgX
         ZGZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ltnYvwXNt85pQWYuu3Woofu2pXYpHtCxsiErjju1VKA=;
        b=k48S9/dRO/Q7H35ER3o4BbHxu4SF88NpLtqezZUNPrkrssfcEdPbEtJffNc5qDwiZA
         M/rll2HP8sGEWwHoXUoJPgRRsatFu11dtqfo78O+8HzdTczXK03bVAhk+33lPYOqQ1gL
         Pcpt04IPrIA2z0nb8lrunYDtcWOFHAWZA+DEZJSY4ZFsFCA5Tv551QoHk28mwAQebP+E
         h0sPMYGyp5Zg0Isd9GLUcBfiEXPPCPJ/1KYnx1VeN7B1hcIemBeiyL7qfGbpU7evjeST
         vBHvIdZfOzVGD6l2UVJflxclRunGwa0S+loKgTYVDXB94yIgdLc4ySpecsqtFqxEm0Lh
         661g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=qZFO1ufn;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id v18si136311qkj.3.2019.08.29.17.39.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Aug 2019 17:39:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id g2so3337145pfq.0
        for <kasan-dev@googlegroups.com>; Thu, 29 Aug 2019 17:39:29 -0700 (PDT)
X-Received: by 2002:a65:48c3:: with SMTP id o3mr10685138pgs.372.1567125568304;
        Thu, 29 Aug 2019 17:39:28 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id i4sm2211696pfd.168.2019.08.29.17.39.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Aug 2019 17:39:27 -0700 (PDT)
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
Subject: [PATCH v5 3/5] fork: support VMAP_STACK with KASAN_VMALLOC
Date: Fri, 30 Aug 2019 10:38:19 +1000
Message-Id: <20190830003821.10737-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190830003821.10737-1-dja@axtens.net>
References: <20190830003821.10737-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=qZFO1ufn;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190830003821.10737-4-dja%40axtens.net.
