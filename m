Return-Path: <kasan-dev+bncBDQ27FVWWUFRBZMB7TUQKGQEQ4C2FIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 47FFC78DB2
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 16:21:27 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id k20sf38334136pgg.15
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 07:21:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564410085; cv=pass;
        d=google.com; s=arc-20160816;
        b=fjht5kkZu87SKHVb8KgB1fpd1RW+3EAS0mZtyPRX2sK/t2S0W2Q85cX06YGu50bu93
         dHO7n9499Z1YxhrODmc2hsCiXN2j7QF+5o7U1JxSZeMGp9SAF4sdutxuKp8nD3+mZhmh
         sJ7zfUMH7fGYk1riL6JyoGIM5Rkxcyh3Tqirbw9zkCfdVFZ9kL3dEanlI+jDr9+CNUlF
         ewlq7vfmO1KOv4phCy/JaCajsXw7/ksEMqm7qFFI5/mXqk0yeyUulsUndU03MpOEGxP9
         vHElUkl++GUkwz+lF9kyF5wjU5ClAv1iGR7xINPnxf9nD8MaRaRUF6RHwQjLSlew7Xqe
         Vr7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=W43LrmVyVmbhHHvSaS1W+w5pYeBOvq9a/JHhPfMLPJ4=;
        b=AKoTsGXKvirPOuEY+KQK4V/RLdhTQ2auC9lHpux/yqD90rZyUcMP4dWPEi6RqpX4SR
         sQlxbKFsoeifcUZcXLpgG6FpYIZHKaJE+x8Oz8SNcbHkpa2FXc6RMhbX5fIbvnR7N0cS
         usx8dgeN5++5NJmbKsYNmqJybDbiRLbbJrCm8F57C5D7w3GdNVfXOkmEHfRh5iiiTnOa
         o+9UsXn8EA3yEuY6tQNG2eiCXbei0EJTmBuhrlwAj/DMUXsgSzsuXXtsRBkooKAkSEEr
         dwXS26l3p9FNGZifhwUbjNHGxoDfT24Fe2Sp+pZDCrxCdslDV3K/GJDoPh/jdEKq2jP0
         AJqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=kZwz3XiA;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W43LrmVyVmbhHHvSaS1W+w5pYeBOvq9a/JHhPfMLPJ4=;
        b=G8Q5GDJXoOAuGD1l4roGWmiCe7Z9rXkxYsPoHKsGPw4iWCWsNG3Uzft0jkwN5WbTV3
         AFH2ZijpvZjhTbpzU+BmnPR2q8rBAFnj8Av22OQsNXaycx3Hc0NhH8z8uOrgXOczNJWC
         k8KpnmJyM/aRMxjB5+zk8XvhcOcLqVLXkCyXMNXaDafA2OcA9U5/KWviGwMJXaCq2rtH
         hcS1sH2mOOeo/Ow5/VZrklhNxLTpyJfKyk9U/mzN25QHLIMGK7kC5hQx9nKBknjLrs9/
         OoiLR6wtJjOotHwVTEsgjkIhEgtOKxQg66vTX/d7ctRRw8Rv/yVeLAOSln3ZDb/zqY5z
         ou8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W43LrmVyVmbhHHvSaS1W+w5pYeBOvq9a/JHhPfMLPJ4=;
        b=mIicoQqZmtUvUwboNjPcTxyFZLaRhzouKa82Z4okjEjZhXAiVNI5CMRvibuYC9mK43
         jWz6iV6wCYpiad9TBt8Xd6lsnF3JzZSU8AP4UWRzaTTrnmINxUKl7GyYJHZcCMCFynjh
         DEjNB33R2dInd++9hfQe43CitfLUaTckT53IJmRDIjK7/znfwrz+AIOMlzziZO30UzzF
         HcH1ZV/qpAfj3P6MJFGQiP+XOr39vZcA6NaYwO5zwYsKrTtTX7KVRnOFXtABbgPJWR6c
         36pzHz0ANvFMIOr7DIQkFyMWuQ+rOhBboxWZB0eDwdrq9+CsIt7stOCWGFiNMcf568/Z
         vEEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU7P5pnfaHmfYVyQTV+CryXUDja1CgGjAowYYFGdCb8/REQNK1x
	75aUuIAI3PiSXQ36ejpKme4=
X-Google-Smtp-Source: APXvYqyU1DTwMulbvQHheqt9cX+lLSSkUZ57FGSK7EPkRUU7ua4+8+RgqnQB2UJUimXrN5m/SNNsCA==
X-Received: by 2002:a17:902:740a:: with SMTP id g10mr111129986pll.82.1564410085772;
        Mon, 29 Jul 2019 07:21:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1c24:: with SMTP id c36ls12363720pgc.14.gmail; Mon, 29
 Jul 2019 07:21:25 -0700 (PDT)
X-Received: by 2002:aa7:8555:: with SMTP id y21mr24500187pfn.104.1564410085512;
        Mon, 29 Jul 2019 07:21:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564410085; cv=none;
        d=google.com; s=arc-20160816;
        b=HZlVMmd2x9+R1qEeRdeJxGsnUA6ZQQQHhTuAVVZaknSUSC+Bld2zevTygE8xhxqamW
         /BWJjMvlupS6AnXpq7PbAsfLUP0Q0pzOC5YNZ7xcx/sSSWSkusAz9ixlEa3YyArn9WJJ
         BRN7Ycf+2cjY6b4GKuuB1OQpkHVwS8DEVOJb2xaCXo+rvK/SQ8sOzhgYXADwzZ28hxnu
         H36guWKjhA1woeSKAQOXMi//j9Od+AWrk484X4gt3cmik6a77uog84/3kZ+P6aaA+zDD
         di/2mgcgSl9+zTtbA0Cn8Areuiq2PiN4LQZPbh13nVdRp04lsJuJMMOYdU70YYkQzhqq
         fB4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=w7zQctoUbbEOIFpo2YzbJpxQDN+pRrmLCUjs8vOkAsU=;
        b=eDeaih8wlCHwRZmZCWtbnSfgPIpwUwoF+W7kAy0y7CuL4fXWGrtqZdvr7d56zVV4DW
         9p/AUUJvGq7JC/8bM9oy5z1CtFfcw1icveWwCdzhHbWgSweYTFVEuPavnEpbbkn9uer9
         gvoIHZyIlakFS0VgrwiflxL2YlWjr75ytuyms7/ZrPfRaVAEswSGPT1tksPWLIv3Tt6t
         8qpYpnkhICuQwp7QkPyQRQu4iKwq2Z2lNJx8hyWF0k/7CTpkSmT61E9CeI0s35mMobTf
         lMMR/TP8pH2Zf/oj5gl1SwMCgmC8iBTO3R0w4h+QFbXVxmorncT34sNHi3N/SRdNvfnH
         6H0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=kZwz3XiA;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id w72si2486619pfd.2.2019.07.29.07.21.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jul 2019 07:21:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id f20so19117466pgj.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2019 07:21:25 -0700 (PDT)
X-Received: by 2002:aa7:8502:: with SMTP id v2mr36039354pfn.98.1564410085043;
        Mon, 29 Jul 2019 07:21:25 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id x14sm78684881pfq.158.2019.07.29.07.21.23
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 29 Jul 2019 07:21:24 -0700 (PDT)
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
Subject: [PATCH v2 2/3] fork: support VMAP_STACK with KASAN_VMALLOC
Date: Tue, 30 Jul 2019 00:21:07 +1000
Message-Id: <20190729142108.23343-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190729142108.23343-1-dja@axtens.net>
References: <20190729142108.23343-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=kZwz3XiA;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190729142108.23343-3-dja%40axtens.net.
