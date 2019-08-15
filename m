Return-Path: <kasan-dev+bncBDQ27FVWWUFRBAGJ2LVAKGQEAHFZUBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 816358E1C2
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 02:17:05 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id d203sf595325qke.4
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2019 17:17:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565828224; cv=pass;
        d=google.com; s=arc-20160816;
        b=dsCBXW2ILhtuS6RN4DgA2ORecqJd3ortgahKqdmhmEDjmp8C2q2xxFw5HV81sriaUZ
         XR3aOGddN2uEgS4mJXVbZD7t0I/WkGrOI3vk770ANq5toFyS4V+cvhyocBf4Cge+sYKd
         vHq3Y9cfRBSv0/L0pv2Ql18acPkThY7SVarAKCbFJVd2ZxQbDI1ulT7JIXUR8rpYnC6f
         6l4YEbDZ9aPU0IQsaqEBu7zTeTuwllqtb5bJ1pF0Cm3vxeRY2ZyHAWyInXcoJHvb9FHF
         k0XYahBSSQ3mbJaEj9zKYwta1OxZHMcOyBmp9DR9Nn7c/v3XY3ZLpUejWaiMFHXVlzWU
         ZrFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7ZkgKRNZeTmoLi/qPr7KlJrhsYyMJwu8BLAV6ey/Dp0=;
        b=jcu+q9zacIZok7uv9/Ky4PEN8hl7rteK709mtbSIa9tl8qVgkLrCTomZDyi5IUs5ZN
         7q8Nft0KbmWHXgLc9aO5TsdX5Vd+OHp7q2yMyMvaiqvsbR03tLp4nu4LSu8MifFO+7Gv
         8NFY8PowmkeYNKtfN1+T1LSs07iHBybdXavkjcMaRyKYFxLZDT8MBWp3+VHzfUVuNc5H
         6RMk0D/i46yjpwS0U0VhNSACL+dNiOJbiX3iVHRCe3JMkOJq60TBDSqXkPjFG4jsXB60
         483vLDqCu1lTD4i77DdkPVFK8iescoQr3HEXNsEnVhPg+j7rUBFgAF25IrKeuKju5ybW
         wujg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=qWlkfAGQ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7ZkgKRNZeTmoLi/qPr7KlJrhsYyMJwu8BLAV6ey/Dp0=;
        b=GrJdJ7RfY619SFwqO0s6zQRwvry26iu+BksH4MUq3jK0U35BrrVFFmZXN8MxRrGrtC
         UH2AIj6VPY0pUaOr2n4Fifq4AnNOFTvZXNPXAhMXiMx/kZnNSyc695nkD3YbXtFHLQiP
         yeu2lTR4p9zMpMzIp5IG4TT2uwEn7kAsMEuWPowjVxQYsMV6bpc2i3d7uChB1A65B5/Y
         EtNKbSDiMvl5syuDo8Igewp4Sa0+eAR/D8bbWrE9p0tNxbOVynm3VhGLqWTHljqwYGtB
         j4sFnO91Qn0W/RIwfJuhGIgXjSOGoM8N2kfDiTUpwQjlMXZnsKYdm+Khyyp+tT4rDnlO
         q89w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7ZkgKRNZeTmoLi/qPr7KlJrhsYyMJwu8BLAV6ey/Dp0=;
        b=kPzpcWYqZKTG0VywcghGZ096oZk79OztUEsOcTfvy6IAI2vR5685yxg7VEpInfwW0Z
         uLnH3XyzGHXnXuZ52TeNV3xQxZkYH02bKG7eLxemk0IF9qkvzax+/dLWz5fAfV7AYF7P
         ngTEEprMFNvhyHvG//dj2Sm5bgxZ5aj+pyVfGuRVXvwoDWg+1KQDqKKV1Mh9kro5IeaH
         6YjAjNo09o54wfFiQCI4HbO9IESGHNcJI/YiXpJoZzWwjxRMFZs8y/a2paOzq/dF58yS
         Lx8LSh6O8W+fvFuNxZhuJjmAkJWN05xq4k1JUcELszmKTyL45sJdMdrQ60sDqu4c+xvi
         alNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXK8cyh3rTW/3F/fPGJYK6AYAl0y5/saeDtomb+K8hUOtBf6AMu
	rwKTvt1YGAEQF3QrFAZkaGo=
X-Google-Smtp-Source: APXvYqwsvmbXT65kt1G3QTdEudIfTtv9WcFpF4dOl4ZZo/v4F95YCAuPzGkFqypQC7Q3neJgP8CP1Q==
X-Received: by 2002:ac8:36da:: with SMTP id b26mr1804083qtc.284.1565828224646;
        Wed, 14 Aug 2019 17:17:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9d4f:: with SMTP id g76ls1050779qke.0.gmail; Wed, 14 Aug
 2019 17:17:04 -0700 (PDT)
X-Received: by 2002:a37:f50f:: with SMTP id l15mr1901422qkk.326.1565828224460;
        Wed, 14 Aug 2019 17:17:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565828224; cv=none;
        d=google.com; s=arc-20160816;
        b=gcMceVMA4Gr49IOmGLUHgruuJ3kmd5/Z8nXUj5fVNWFnuHOOuJZF0y493UMePwvPp3
         MeRRAsIWF6F4wlrXsWk6iRIlDX8XyUQsz1tBcW4FjkX93yEvzra5M8P7G6OpvaapEvB2
         qjPNzH28tPZLUNATXBNRfblL3cUUxjeo9zuZCIWBVCsUTr1nLaFd/LriixLewHSMbRiP
         raTEWYeiVF2AA0smmma/8k8vhACQrz9FGlCXogjxI7ydV+w4seBKWBhmbi7WKukpD5gj
         liunNnpx2y+uqmI4tInRk4GIdR3qHyM0OWWKdfrynuN3eLEYmpxN9JF7vAo0DivCxB8u
         D9uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=w7zQctoUbbEOIFpo2YzbJpxQDN+pRrmLCUjs8vOkAsU=;
        b=cHLIG0Kz0/jhiIE0+aYMfhBF7qc7yvmNlcDq0XGLcPBDoQenKwUnDutM55icmKaCI8
         fmAC6G1Voi89hEeBMeUwj7bMnlqHZ6CXQjMmuvk8w5BGI0jSPqXeSl/Pa4KimDGjN2aN
         kdm3m+yXBHiKlUdzO30TsZ65iYV7AIAE5tUyuy8jmdfmY1AzunGouaTVUOIym884kDB3
         ptSgLX3w2uibf2WKGBR9IfnxQ/RrwhB+1j1JNc+q3+4BNp3lUCvtJusr6IlW1FN2zT/C
         uYaqteKk0IWz9F5tWL0zZ0rmZZKhhPPHCTqPzd9yOl25RSF3QNnX45BUmYvRPre6FwNz
         EiGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=qWlkfAGQ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id p24si94180qtq.5.2019.08.14.17.17.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 14 Aug 2019 17:17:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id m12so353097plt.5
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2019 17:17:04 -0700 (PDT)
X-Received: by 2002:a17:902:b698:: with SMTP id c24mr1902458pls.28.1565828223382;
        Wed, 14 Aug 2019 17:17:03 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id z16sm835454pgi.8.2019.08.14.17.17.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2019 17:17:02 -0700 (PDT)
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
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v4 2/3] fork: support VMAP_STACK with KASAN_VMALLOC
Date: Thu, 15 Aug 2019 10:16:35 +1000
Message-Id: <20190815001636.12235-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190815001636.12235-1-dja@axtens.net>
References: <20190815001636.12235-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=qWlkfAGQ;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190815001636.12235-3-dja%40axtens.net.
