Return-Path: <kasan-dev+bncBDQ27FVWWUFRBUWX5LWQKGQEQF2GGXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7ADA9EACA3
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2019 10:39:31 +0100 (CET)
Received: by mail-ua1-x93e.google.com with SMTP id d8sf909122uan.4
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2019 02:39:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572514770; cv=pass;
        d=google.com; s=arc-20160816;
        b=meX+hjkfrRo6G2UXiljcutAasd6gB8WsLoSEqk0B8yMVeGvLeG/ZTsY303DF8XH3mA
         tvirATUhF5TnUtUdFIpzMHVP7q1hzVEtEZ1/5+sD/ajMXOK/hL9TqWRpQYOCke+Tn3al
         +FRu+YIqp+zpmjATrrRnNpC5xcOEg0CnBGl6+a5UGK6HuHB+kiR6QNGRwhW41Dn2I1E5
         qi2f7Jo3daRqD/aKca5pXW0/ESVoINS5iEBkk2ubYMpyvrhJvvD2E2sJDxatkl/hsVcO
         WaNcvmjKZRlemlTdJZF9kCBeYF8kEMJx/fuBl01+V/oFmryBrwcCbau3a+ypWErRBmtR
         KBPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FmSz8VMK8PSEB0xkh0fdJL8DKI31mjN1pSjXPxqEE0o=;
        b=UJ39Cn5mdp2TT1FDXhAoTcbKno1fklVTxgIDm+zYlAqsEdTjCOPjsq0UmS+zzd4Fd/
         pG5E5zh2r4Ew+nZF5t40ttlSh2J+NFqKvbRGRlB8E1sZF85ekwLK2FzRALiozKYBMkQF
         PjPi7R9rE7UNu3shVAoDXEEbjg6pSrfstduZ3NKY4ipKF43N5ifJK7VsoQDPbzSWvoBa
         Gv/aRrhDZkpzFm74U5cESbl45Jm2RGSmMbDLpoCvo0JRul4BfRPBWugzW5Px+IdrfxKl
         7wIHmRyoiXHUjD8o3nwwd+J9ChtXrPnoPTHUpPsKuxxPN6CDZTBdS79zUZmUti3NNEzu
         LLTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=eV1YePql;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FmSz8VMK8PSEB0xkh0fdJL8DKI31mjN1pSjXPxqEE0o=;
        b=OLeDicPaSwIYkxPdrl6fJi0ky4vBj+6RY+yVpt7Kr6FQdjG5J+omWRagPiRqtBzQ+h
         0jz7FPxi4mmYDCmwKAoP6MmAAxNF/dK/gVynJYvkTwBgAZicMuxlsIXt16G+ZQLlpy2R
         5MA45dm7MfLG0eeUsO1PuI3cwZnmiaTs5PDHCBODAl2fJkcncjqovSmhvn+EioteeGtR
         cYEnQbdg3VFZynlUGTehgwh4kAkangXgrk0FMRKbDpn39uaAcfiQbJ0gZnHuSREhQixM
         f3Ph0Qx4706dS3mZIL6Mc/z8/KyoKaBDgAL5bgZgJWxChbU7qqvPffH2gAdkZx8iSRXy
         FLTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FmSz8VMK8PSEB0xkh0fdJL8DKI31mjN1pSjXPxqEE0o=;
        b=SIqyjDTmXc82ECTk0huC+elYcnaEJS6RfEl0Uq09dGdyO3equ1/igyhoX+sgmZOk+r
         Y/cYOGQGhWG41wS3ftXJ9TGHaAjSr0Isjj5OivqsWqARWG2aStfpDyoTjoJDAR2Zki5r
         vZCVj/em7rXFp6zdXhmBeHD+umaG/RSzOsEwL/IpetLaUWOCNhzvqVIgUm9y8c29etTR
         RtFUDlQZbfcoyJw0nVWesSvCOi5Rxj+ZfhuihV8URBGNc5rRniKeKv2nEUni6bnUbBZi
         9sF/CBX2attHUMyTu4RgYkqSIVjKXTKHYR7h4wGcGiQtlAVVaBSfh7xGDEu5wIzbg5TU
         BJ+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVTyrV04hyBSUHLJGORzuJlYRbr4/DXByW5tXiStymuhSzPWi9e
	1eZhCSY9e/ti20Y3TSf+nF0=
X-Google-Smtp-Source: APXvYqy2yX/OK/1dO28x+Q7hG+FsvF3ssELiLkkzvUqx/7QP59zeyRnw1ThjgVGOKwSu1+7Hfkm+kQ==
X-Received: by 2002:a67:f90c:: with SMTP id t12mr2203977vsq.37.1572514770603;
        Thu, 31 Oct 2019 02:39:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:d883:: with SMTP id p125ls91129vkg.3.gmail; Thu, 31 Oct
 2019 02:39:30 -0700 (PDT)
X-Received: by 2002:a1f:adc8:: with SMTP id w191mr2036560vke.82.1572514770157;
        Thu, 31 Oct 2019 02:39:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572514770; cv=none;
        d=google.com; s=arc-20160816;
        b=bOzVqkrKdKnPQSchL0/QFRUZulHgZ32YhVdkZiyykDi+45l6WdCcfdbcKHIfr+r+aB
         6cY7fwJpqQngHYqRwM8N066jPIV2Q/kxit1szGCAZcaLORYFnbl2X0XnXg25TpR5ig40
         eixTsNLFLuGjfr2AMCoA9kcGx8BMEz5hs+iikj5ILyXiCcvpt75Hn/DpT17yMlV0cBoe
         kJpoOuxKKuVxqgwgwV9hyizaGIPAzkXy0xTQ9E6pf4Tqng/Vp0XExDfMmcvnzZsG7Axt
         MRXA7PJ85OYagsMKzbdPrHxTQEvMqiRS5tpT/4ymp2dRSMWv9zvRGHDKmbGbi+EE4h5o
         BtfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=v18HXwwUv8fdcmaD7WznN2j7mmagzU8FAwS/lrMAbV8=;
        b=zA1su2OO0OiuBpOxhPfuJGoq7/OGV28ITqjOv6zfHT9kXf8GjJGwJXITpbG1btnj3C
         N2YqSyJqo9SA8PdEUeEDOAJiWNTvvB3ITxtokVJIRmrjyTgKBNpjzlj3aCqQo/9TGaIz
         CjpZ5rcABj138PRPjxy79/mLEFM/qjWt2XZDxkRQ5C35C/gg12vAK8bM8DpbOJ2+1b2o
         om7DKUUiYObNHIaAS9yveecptMMwpEDEnG2xjriTAMUph+DWeE/g60OASDkPUlqL4gjQ
         xsc2cXor5OyDrT4jNlySofoOI/FRNPAUAIyqCwEkF/zwINFMjNDFBs9WfPuogH2ADD7j
         9U9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=eV1YePql;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id s197si254866vkd.5.2019.10.31.02.39.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Oct 2019 02:39:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id x28so766211pfo.6
        for <kasan-dev@googlegroups.com>; Thu, 31 Oct 2019 02:39:30 -0700 (PDT)
X-Received: by 2002:a62:2f43:: with SMTP id v64mr91811pfv.13.1572514768894;
        Thu, 31 Oct 2019 02:39:28 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-783a-2bb9-f7cb-7c3c.static.ipv6.internode.on.net. [2001:44b8:1113:6700:783a:2bb9:f7cb:7c3c])
        by smtp.gmail.com with ESMTPSA id p1sm2503669pfb.112.2019.10.31.02.39.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Oct 2019 02:39:28 -0700 (PDT)
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
Subject: [PATCH v11 3/4] fork: support VMAP_STACK with KASAN_VMALLOC
Date: Thu, 31 Oct 2019 20:39:08 +1100
Message-Id: <20191031093909.9228-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191031093909.9228-1-dja@axtens.net>
References: <20191031093909.9228-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=eV1YePql;       spf=pass
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
Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
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
index 4b2a82eda8e5..0eef4243019c 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191031093909.9228-4-dja%40axtens.net.
