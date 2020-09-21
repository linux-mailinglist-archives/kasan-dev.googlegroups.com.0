Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH6UUL5QKGQE4JOLEKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6274A27256A
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 15:26:56 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id l19sf2097021vka.20
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 06:26:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600694815; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ywha1aVazxOGnPpesazW+lrMC0Ot4QO0xR+4PIA1nwySsqVn4Zjpf3ZCgMc9HozgZo
         CgQOY76OUYMC3FVQsQGfiLH3UGURRRxIBd8CL/SPRTj+tqtHJVm9ekmD01V6t+Ly3Bdx
         upbrRzFVEDrfrXdOdz1iVVLooEYJDFfF8VLfO1D1+TEE0WQGPrUf4Xj3QtKkwV+SAFiL
         5nKO4p9mAKuzBE3f/48eEtZda4nmDm2vLW6N+bxvl+yWIZfsOoHzZOVZemtcbifa7/wg
         Eo7PO9vVQcpo1JXeed5gqrNYRFgEDZnZWIBcFtJ4D27zZViKzA/Jkp8vBnDyG+hYD+hv
         45Xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=CJci+rigRVsmyKdSNqQS0mXgTKeENrDgSy3IyKLYOQg=;
        b=w+V6/XL0ht5aux4QZWDqSK/uTuzYk34RhU3mqZ3PgFG9xCLdYIByUOJio7Ee1q6pA4
         gGYBIBnk+Fq76kNuT7iAXzZZMuurqt+poaz+mEECBHf3iwqTa6gSSncP/QUVnKk5w4xJ
         entKj2SUFHRdiB8koL0Rm2MDAAjBhFIusYcPRM986l9rWNdWpZmld+Mtvf7zTXGAkAPc
         JpJumH+paLoGO0q7ZWICRmuB35km5s34aqkO989109Wzthh88QrqaIJZAtW5GzfAfJW0
         PQun7R6O5TTXTZYZlBIGm6WZeqdEHCA7Q/YATPpoC/avpP/KG2EjAJjlKJ4R/A3TWxek
         arhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="t/PhPbvg";
       spf=pass (google.com: domain of 3hapoxwukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3HapoXwUKCRY07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CJci+rigRVsmyKdSNqQS0mXgTKeENrDgSy3IyKLYOQg=;
        b=USNh97f21kByQyot+SytR5YaKwiXoL95HDFU2HiN49zBiROJC2OS0iP9X8YU9djECN
         L9q5PgVp0t+nQAzWjVXB5TSo2r+9kv2MBLYsOjAozWBFyfjepRtVsJbghor6sQlvNANF
         jKDJepBIX0dma2X4HUgpFxP+IdReYHKvLtP7GEOfQwtj5t1lyLDKzlF8qQtoUZIeQE3r
         FUcA+E0+2z2qpwjsHwpyDjn0HUttT8qggKS7lz6lfu34xu4ltXemquw/aX7I15z4PHSa
         woy/yPQkWWpelcNWh6xyERYfR7XGClALdsKipPpRX2/SmdE1BQ1mhBjIzyQk8hhYCB3e
         pFDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CJci+rigRVsmyKdSNqQS0mXgTKeENrDgSy3IyKLYOQg=;
        b=q6gc+o5Wf/2psWtsxM8ZJvth91TxjXzQpm02cnaBP6B0phNFhWKRvp019RaWBYWoRm
         BTTRmIrp2uc4Oho4b0a08sCXyeX5WAPraeMDvtJ9v9kMYjlejGmF0SHvrTi6i1NnBGn0
         xbQCiP3CU82g4yXYMncJhUbY6OzrikorM+eB9zaqgqqg3uf1EgQOtf57rSq+62dAzQBB
         ojo65V4NMNlu5wl+v4mbbxXfelhaUhEG4B2Nhjvbb8H1UI96CLvr7YYLPXQXXoJF/atB
         8daU38A0daMv9BlCMyVcqrcliiwP8GdxIIdC0zBxxf6g+vSGnY6W62UjB/0inj+/t+o7
         PbkQ==
X-Gm-Message-State: AOAM533D576qU1NHPOft4G2NYpAnejXmR5f44YnFh19sXQig8WAvbdGp
	mx1VK9LRemAIX6DD8kLwGLw=
X-Google-Smtp-Source: ABdhPJzSb+NhBmJgh/LDsaesiNSdQ4AyhvFMbjEZVWi/E1ccY25RVE2X4MD/fLyt++vmDLL+sTsU8A==
X-Received: by 2002:a67:7d51:: with SMTP id y78mr27664360vsc.12.1600694815158;
        Mon, 21 Sep 2020 06:26:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3124:: with SMTP id f4ls1469636vsh.3.gmail; Mon, 21
 Sep 2020 06:26:54 -0700 (PDT)
X-Received: by 2002:a67:328b:: with SMTP id y133mr16553vsy.10.1600694814647;
        Mon, 21 Sep 2020 06:26:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600694814; cv=none;
        d=google.com; s=arc-20160816;
        b=K1i7nfQJNS0ZYWkgJo+uXi+TeRgiGtr7SjtjcbLKkZ6uErhsj12nOpnxsUg82N5Lgh
         8LdPkXhvMn8PWgrpwTmGNLhzeKVnTDDKtRJ55BZclt2G+4v26AQlUcoNI2K/FLW6vzzt
         6Z+wAp/QccEoHfDGPevCMHiRf98avyr4TE+8MPOMxa1SdTt9YNeW9ZhwsthFkttZ58Qi
         38Pwi0irXXrErzSjn7rO6LhksICVOBp10sgVjc+fPJ0K0yR2MI+gx1XVKC7qyyg5GZyv
         6dbsAyi4LgpSsNgLqAmgYMNw4jnEgxwVaYzxxUxQ9P7gUmqG+IP33TZolRAqtfAcqCUz
         DR7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Xu8t61b4dNKr+fiQ7+DCPl49hEzGiBe/cMhyep8752Q=;
        b=In7T/FzCJg5ImvUKDJH19als38x8f0FzLziLnIWYKnYhOvOYl/gicDrXnDl8Lw5TSj
         QNcXphBziqBEypw1mTdyJEWU2yws0C9/RYGgUb2n5/4gE9IuCooV5RQ5HtM4S8DDcNQh
         ldv9OzTZRc3WbvNZN+tdwjek5RU3F0LS3T8nARIqjlcrE7ttbBcmtKL2DgQkSMftEqOx
         xcY+vnqcgywKmxNQtkRJ1zXGBMydEK4X18iYFI0QSxNWHbJmIqgZ4WXgCzi5DNZ7CnMB
         fXPl/LDQsBvRgFg9tG8/FrC+RYIz9V79D1KRqewiCISjQF7So3V1JsRwcjZ0JxYjodZM
         ti6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="t/PhPbvg";
       spf=pass (google.com: domain of 3hapoxwukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3HapoXwUKCRY07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id y65si664885vkf.1.2020.09.21.06.26.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Sep 2020 06:26:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hapoxwukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id p20so8929199qvl.4
        for <kasan-dev@googlegroups.com>; Mon, 21 Sep 2020 06:26:54 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:e311:: with SMTP id s17mr28925297qvl.45.1600694813892;
 Mon, 21 Sep 2020 06:26:53 -0700 (PDT)
Date: Mon, 21 Sep 2020 15:26:08 +0200
In-Reply-To: <20200921132611.1700350-1-elver@google.com>
Message-Id: <20200921132611.1700350-8-elver@google.com>
Mime-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 07/10] kfence, kmemleak: make KFENCE compatible with KMEMLEAK
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
	penberg@kernel.org, peterz@infradead.org, sjpark@amazon.com, 
	tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="t/PhPbvg";       spf=pass
 (google.com: domain of 3hapoxwukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3HapoXwUKCRY07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

From: Alexander Potapenko <glider@google.com>

Add compatibility with KMEMLEAK, by making KMEMLEAK aware of the KFENCE
memory pool. This allows building debug kernels with both enabled, which
also helped in debugging KFENCE.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
* Rework using delete_object_part() [suggested by Catalin Marinas].
---
 mm/kmemleak.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kmemleak.c b/mm/kmemleak.c
index 5e252d91eb14..feff16068e8e 100644
--- a/mm/kmemleak.c
+++ b/mm/kmemleak.c
@@ -97,6 +97,7 @@
 #include <linux/atomic.h>
 
 #include <linux/kasan.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/memory_hotplug.h>
 
@@ -1948,6 +1949,11 @@ void __init kmemleak_init(void)
 		      KMEMLEAK_GREY, GFP_ATOMIC);
 	create_object((unsigned long)__bss_start, __bss_stop - __bss_start,
 		      KMEMLEAK_GREY, GFP_ATOMIC);
+#if defined(CONFIG_KFENCE) && defined(CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL)
+	/* KFENCE objects are located in .bss, which may confuse kmemleak. Skip them. */
+	delete_object_part((unsigned long)__kfence_pool, KFENCE_POOL_SIZE);
+#endif
+
 	/* only register .data..ro_after_init if not within .data */
 	if (&__start_ro_after_init < &_sdata || &__end_ro_after_init > &_edata)
 		create_object((unsigned long)__start_ro_after_init,
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200921132611.1700350-8-elver%40google.com.
