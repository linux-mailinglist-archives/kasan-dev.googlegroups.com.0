Return-Path: <kasan-dev+bncBCS4VDMYRUNBB2MEYKNAMGQEPWVZCUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id C15116053AB
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 01:04:12 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id il7-20020a17090b164700b0020d1029ceaasf768636pjb.8
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 16:04:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666220651; cv=pass;
        d=google.com; s=arc-20160816;
        b=0cBVCKx99cd4oX3/cjFsSPcw2W2BDkn+8VwoDY43dMGV9B20BXhpX4G387u5HB82Y0
         A+MXdqmyYO//ruuS6tzFwjEvR9nloovCf2FSvobJoexCSQp1afhZfJkK3LA4H39ZyUi9
         TW/MxkA9HXQux6wAqBUShEtmb5Rxfwb33I/llD0vvBQrqoBbTAWnM2e9asMEYUuw0/Kz
         yR/mvKCIBQpIKU0eCIkVXel1h2+RLiyud6nggrJdOkfiQKcFTElt6Yu69qGSVhbY7Og1
         SyvnddY1zkDj6JSW1AGGS0J7jkGfCNCLRw8Sj+a9fO9QdOP0h1TtWpQW32ypbha+e2N7
         QBPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VXBQ5uNw9E63YNbzyIJlM7UwgwZibk3r5wZASXYkyM4=;
        b=xq57sWwvlPMjr6D10kiGi4AmWd0XW03pLg8VyYkO9OhORSvrA4uxpgwf4YyqnfSjaX
         kQ9ul/aBd2yl+kQ2jSgk30RNEOXxJWyh36cFjHK14jgx/ScKs1I/83JVOG1nM1xsmbe3
         QRup+5wXNMzyWI7sbJAGESppUdUxB7sMmUGGI3mc4kOctInTMBEW7ZIeCMnVg8JwdZnw
         PxnURpQXq2WALYbwJLHKi1CYIblTikMnc5himzAGI4htX4PsjAyi7vOGxhw3snc00XBF
         M5M39yKEEyWF5+zGU/2rsU7Co2+WBLR161IezVo63+QpWBYI1TDAOaM6hSJVZZ/8lpLs
         3FEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="EdE+Cx/4";
       spf=pass (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=xkCN=2U=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VXBQ5uNw9E63YNbzyIJlM7UwgwZibk3r5wZASXYkyM4=;
        b=O0g/jNL9GIiQoSYYNquTdNO/j87loUK4AMvFgkOw/+VELia9Dg0Rc4R316E5F2/dYw
         J7SfrOVtrOGu89rh+u3FfqL6ecAhGvV9y6Kslny6Dlyq8Ayxsz9HNGu8uSoSVWKqogUH
         pX4qR+zkrNBOKOL7fYgJlJfQxIuavJISjLkuxogK2mXahyJ2lij9/U0RXsrBUy68p/vH
         oPNyE/YONmxzbaF5sVVCQ0xF8m6ydfEo22/hq406fjEXsp7U6umJKL3VVcXRSB2GM8vg
         EWwZFRXt5d89VJMOjh3rvCa+kXCVA17BPjGZUcSQEy5EfbnyenW+v26pC68R31IQZS9R
         XwoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VXBQ5uNw9E63YNbzyIJlM7UwgwZibk3r5wZASXYkyM4=;
        b=a0JYlRu9M6unzCi+txtVsqGntypU2WkZMIkRMoHCrfwY7DoGgGHr4b9/eE+AehoSjR
         dW0PHWUUY07T/F7kQXI7wgMm7H/jYIm/CfSyMj9fmOxZVvlnVsDKa6fuQKEwD4K4bHJM
         2Q+Rgi4Hf8q/IMFCFvVcOGipLl6DbnlxzRN9EIGT/gs/0/xQsM2GIENcB2xBOxuf0u2s
         B1KPRkwvI6Ld682ZrSEx/XqIJBPrxCa33YW4mGtf4//UT2APYPKj1LP4dESrvlTXqOp+
         ZPbchn6uLZ2toem/XLIMn4BxaUQCezEi3tIuUpEJs6mzrCly/ugBiysDhh78wBmDn+eu
         SDUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1P+0/0x/LjOYF9kY81Zqa08BRfsD6Rn/rKX7gxHE/9I5rVkr6k
	fEZYOYv+b2mjIzuYRpZr2ec=
X-Google-Smtp-Source: AMsMyM7ZOnIiq7PxdeYR8aZXo+pifF2z57kp81fYAamvavhp/J/btNv3o8yq3L8oZKco9GLluJatcQ==
X-Received: by 2002:a63:235c:0:b0:459:5fef:88ab with SMTP id u28-20020a63235c000000b004595fef88abmr9363442pgm.312.1666220649964;
        Wed, 19 Oct 2022 16:04:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9b91:b0:16d:6f9a:131a with SMTP id
 y17-20020a1709029b9100b0016d6f9a131als13526258plp.5.-pod-prod-gmail; Wed, 19
 Oct 2022 16:04:09 -0700 (PDT)
X-Received: by 2002:a17:90a:cf82:b0:20b:3525:81ec with SMTP id i2-20020a17090acf8200b0020b352581ecmr12253203pju.42.1666220649166;
        Wed, 19 Oct 2022 16:04:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666220649; cv=none;
        d=google.com; s=arc-20160816;
        b=z0ZyZ8aW4Te5kOw6JzPFXft+ektJDCWoiKCyIvEACLQfhCpKvHTixAmOxYxmyZOHT9
         sqXyi3NilOD6fZ2J4R3anvMfbni0AvLWadQuqiHXEsKBxtlVASv61axtxPNQSsPwWvcM
         aHDgELl8RAzPcNB4AxR+PBfyFqwQ2G0X8wkw4mowh3BiqKnNre9Zs2wEw0cM6VH0xlgD
         uOX7/vazQJHExdMT1o5k74FyFWz3AaewFNxxeOORtc3ggG4s7fWhnhQQBOW3PGv0wh42
         536CsQ7DWN7+/WAf9KrExRYrGj7QgXnWx+EnBIfFCCxsM7RG13iUDDYI4JFYQHmTCggz
         RNbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PshftWsvo+9EfwI/H/9Yj9OK6Y4o0PErgCiBjyjkGJs=;
        b=Rn2chj9+0Iv9REROWQ0S+5rpZyOdTGcQNc6TG8EKK8R59GXAa6lc6NXJR13JeB2jwP
         s9RFffRXc/VF4SIEuiKrelbPDYa5bzkJ4rLu9s/5KFoMN5xxsR9roiCIDzn1sqXWZr7+
         yyQMU11EqVag1rxxdVbuVX9PBoaqnkBkNoGECxVygz8fcCDcNQol5rSBa1RWWJMnNNqE
         6SpO1IjUVDMCmzVlrM/9slixyDUNdBIt/3ttItArVxXQrhdKK9nEf8e8Sz+F3c6ahwBR
         nHivnSpWl+Vexc46DVc89XVdHjqhQmfRXGp9u2TWE3xdz3TBt9PK8MVcndlyKjvI62/j
         AWtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="EdE+Cx/4";
       spf=pass (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=xkCN=2U=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id k6-20020a170902c40600b0017f7fffbb13si667344plk.13.2022.10.19.16.04.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Oct 2022 16:04:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 9DC13619D6;
	Wed, 19 Oct 2022 23:04:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 73A26C433B5;
	Wed, 19 Oct 2022 23:04:07 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 2A0DF5C06B4; Wed, 19 Oct 2022 16:04:07 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	stable@vger.kernel.org,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 1/3] kcsan: Instrument memcpy/memset/memmove with newer Clang
Date: Wed, 19 Oct 2022 16:04:03 -0700
Message-Id: <20221019230405.2502089-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20221019230356.GA2501950@paulmck-ThinkPad-P17-Gen-1>
References: <20221019230356.GA2501950@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="EdE+Cx/4";       spf=pass
 (google.com: domain of srs0=xkcn=2u=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=xkCN=2U=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

With Clang version 16+, -fsanitize=thread will turn
memcpy/memset/memmove calls in instrumented functions into
__tsan_memcpy/__tsan_memset/__tsan_memmove calls respectively.

Add these functions to the core KCSAN runtime, so that we (a) catch data
races with mem* functions, and (b) won't run into linker errors with
such newer compilers.

Cc: stable@vger.kernel.org # v5.10+
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 50 +++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 50 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index fe12dfe254ecf..54d077e1a2dc7 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -14,10 +14,12 @@
 #include <linux/init.h>
 #include <linux/kernel.h>
 #include <linux/list.h>
+#include <linux/minmax.h>
 #include <linux/moduleparam.h>
 #include <linux/percpu.h>
 #include <linux/preempt.h>
 #include <linux/sched.h>
+#include <linux/string.h>
 #include <linux/uaccess.h>
 
 #include "encoding.h"
@@ -1308,3 +1310,51 @@ noinline void __tsan_atomic_signal_fence(int memorder)
 	}
 }
 EXPORT_SYMBOL(__tsan_atomic_signal_fence);
+
+#ifdef __HAVE_ARCH_MEMSET
+void *__tsan_memset(void *s, int c, size_t count);
+noinline void *__tsan_memset(void *s, int c, size_t count)
+{
+	/*
+	 * Instead of not setting up watchpoints where accessed size is greater
+	 * than MAX_ENCODABLE_SIZE, truncate checked size to MAX_ENCODABLE_SIZE.
+	 */
+	size_t check_len = min_t(size_t, count, MAX_ENCODABLE_SIZE);
+
+	check_access(s, check_len, KCSAN_ACCESS_WRITE, _RET_IP_);
+	return memset(s, c, count);
+}
+#else
+void *__tsan_memset(void *s, int c, size_t count) __alias(memset);
+#endif
+EXPORT_SYMBOL(__tsan_memset);
+
+#ifdef __HAVE_ARCH_MEMMOVE
+void *__tsan_memmove(void *dst, const void *src, size_t len);
+noinline void *__tsan_memmove(void *dst, const void *src, size_t len)
+{
+	size_t check_len = min_t(size_t, len, MAX_ENCODABLE_SIZE);
+
+	check_access(dst, check_len, KCSAN_ACCESS_WRITE, _RET_IP_);
+	check_access(src, check_len, 0, _RET_IP_);
+	return memmove(dst, src, len);
+}
+#else
+void *__tsan_memmove(void *dst, const void *src, size_t len) __alias(memmove);
+#endif
+EXPORT_SYMBOL(__tsan_memmove);
+
+#ifdef __HAVE_ARCH_MEMCPY
+void *__tsan_memcpy(void *dst, const void *src, size_t len);
+noinline void *__tsan_memcpy(void *dst, const void *src, size_t len)
+{
+	size_t check_len = min_t(size_t, len, MAX_ENCODABLE_SIZE);
+
+	check_access(dst, check_len, KCSAN_ACCESS_WRITE, _RET_IP_);
+	check_access(src, check_len, 0, _RET_IP_);
+	return memcpy(dst, src, len);
+}
+#else
+void *__tsan_memcpy(void *dst, const void *src, size_t len) __alias(memcpy);
+#endif
+EXPORT_SYMBOL(__tsan_memcpy);
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221019230405.2502089-1-paulmck%40kernel.org.
