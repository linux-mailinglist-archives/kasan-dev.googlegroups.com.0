Return-Path: <kasan-dev+bncBAABBONGTLZQKGQEYXPJ26A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3a.google.com (mail-yw1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 39DAA17E7CF
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:27 +0100 (CET)
Received: by mail-yw1-xc3a.google.com with SMTP id v205sf14904332ywb.22
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780666; cv=pass;
        d=google.com; s=arc-20160816;
        b=cAKqbm2Ei8li8qcfqyjGOvlkrwhnEEP0L8NEqcdCnRAOR7mQKGcr8Je4AL9NWFBCId
         CRCvAaLTPk1/Y+sQo+HdwSAtV9j93fvGShmOC+ju35yEcjY6PIZMghn0s4IMhvUXIGWV
         35kIBKOMaCAOAy11/Sbhb+ksjzxqquKXZR1L9LFAaDcNzZPIU40TSiC189ecjKe0ubFa
         gc9jusPEnqK3rGI4I/MQgmC9fWt5UzeiVFiyonWpMBRGHT9lYRsz14XRA1TcVWwv2yu2
         GcdmbZSl3/jZxcfYWxvdwc4PfXv2CLs41IM9BBH1UlWKTiwqWUsIoB1Af6hYA6FTJYzW
         HLpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=D4oBa4+nJUWGN5cKR4Vefvle7t/WD3zcCk0V5JEct/0=;
        b=CcR3M/rlZKyQ2TDGbGLrxqelOwZSieh/KT/fClgchrVtKfUFCjBdFaRm4JAXX8p9oV
         o4ZsIqJ2tl3oxGjL4MxIzKK1fQ2JRSC2Is8c/sSJHYmgpqFaUQY8nEFRK1orYSI60DC2
         /HT6+y+WYX7asmuPFLyKvzU7OJdKRAGNe6WBxoHiY2vxzWcpZ8sNfonu0tXJkkXFp8u+
         zhmsgpVgUEZTiTItnU4LAigqlAMKhQkaxSxdLMp+NpU4yNavi/IBt4WCf+dY6IUYsafi
         FM8XWmkWmXTii0+mYLKgh27e8bn4j/HIWINFSx6UNqp73f2Mb0DBnCPK5Q2Q8jUg/QbK
         gj0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=B0g67XEe;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D4oBa4+nJUWGN5cKR4Vefvle7t/WD3zcCk0V5JEct/0=;
        b=duRuO3tlQ+C5K8qM/BSag+lCrOO8qGsNQxTvmQeDmkh36yFrRso8kUT/wFeCQqE3DT
         5qRGPYZ2QgvrRhE4Jv7JZVy2P6vTeA4YOsnubppf1p12NJsCxJcKT8wbfxNntihA+Dck
         2PHoS2wkQ2+1bRXvnEWNlBq4m203d0ZcRguAose8pJXX7WKKJiunD2DB9aHIFUZ1Akzh
         nKXA2S8UUt8Jyn/uXlRwqQFUyyg6CTo48NaS9y13kP5Mqw6AkBcX3dknPfioK6ABJwkf
         W06SrZgRNHr9qXIxJ2hPB5JZHL3EOF/TpxnRbgU+73ZjHTAnS+dw4hJhQlwhhsCESVZY
         khRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D4oBa4+nJUWGN5cKR4Vefvle7t/WD3zcCk0V5JEct/0=;
        b=t1YvI1t/0nuO6ap94SF9yyaTAE2A9LJ1ShrpHeia3S/b/iNNe04l100j8oxZUYRRmu
         0loX49sPfRdq0sVCuzLPX4g7pobdK0pKpIeIhCMVR+H+5CdGEefqMcmsNmjA1PCmoq1K
         2ngoJdKQCJFVR93InW1cHMyyzYBd2WYRZCiET94YEOLz/UPKZ6Xc5eFy8W8oEPjFmdP2
         994E1vAuRzIz1x2eXWBHzD0MgqMfJBVxoQSHQ3llIJmwFQFzl67ewP8hLK6L2ma3WmSM
         7Yh3/PNzYL/l7lscI6uzJTuDyHpdWEPUMeM09K5sR6jHiRQNbp8kBcB+Bkb8AnkAAQcO
         q7+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2vDYqlq2+2grNL+hNdbbdF19hPwF+zeashdHp711+L8/Gg2Vs0
	PKtESyx7/FOx28VVKBnnm0Q=
X-Google-Smtp-Source: ADFU+vueUE40s4yqn7ndcO/BL6OmNx4yw7bWVqOOQVlhZ9qi5NpJy47YYuU1NEMs/e2SzVDZSZHezg==
X-Received: by 2002:a25:ae65:: with SMTP id g37mr17660193ybe.432.1583780665976;
        Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aae8:: with SMTP id t95ls2928294ybi.8.gmail; Mon, 09 Mar
 2020 12:04:25 -0700 (PDT)
X-Received: by 2002:a25:664a:: with SMTP id z10mr19548706ybm.461.1583780665634;
        Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780665; cv=none;
        d=google.com; s=arc-20160816;
        b=J8bTdNJ742VOgPVUF6vjdDqWyZXZ2nUhD5xnxvopXJ0OfysGvX2c262Ne1+7DkVEHF
         ikWOtrlMQsxe4K4G/H5K6yzo2fs1NSZrtvlVzWJ4r/fzxBE28dzBA1zyUCjiekLUllCa
         AwU2vCnLqoW8gd8o4O+20pfieJphMwHic1FpCFyRTNaMprTuuDoNF1bGgxOCBpWfHjB1
         N0monMAPgMzx3n3X5LszYyUa2lrvtYBGR/jyv3gCyXLr56eFZdpuuuw7goxdvK1rRPFT
         tvn68fxf94pmJeInuuEJkRJn2orwKsVYVsLwbppJ/WBNuNKWrI7/5LvDmpY0R2vwSdHP
         BSkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=OjNDtsGIpga5S9MOnXexdGMHy+4NqHcErxXZGV+lrvc=;
        b=igVUbNGVOEMUJBT+4CcU8jJ3ILqapmHT1IRI/91GyqyWE0u9qNrDbOZBUd3vyFojke
         /ZsaUEYnygLQKCQ0sVCWK0J86ATkwoDjkmtU3bpZQR9ioHNeU6a4U61rma/XcPuzDAlD
         LGsPu0vt5TbeilVGQfOf/1r0RKOUt0qjdHyVX2uGVkBgo7ZH/62VQtmE9JH6+wWk02sT
         rDxTk2CHGEWZl6mZMy9qTAziLlUQrHbKcYO8DI82QyQ4j38SmnV+Pay+1Jb24N1aHH92
         KABZ1dl8iF2VfBuk8HYrP4gBC1+gvV+1tbHihqoQgB/FJcSIrP8BvylepLac9/BnH0Iy
         lIKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=B0g67XEe;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s64si611071ywf.0.2020.03.09.12.04.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 952C524656;
	Mon,  9 Mar 2020 19:04:24 +0000 (UTC)
From: paulmck@kernel.org
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 10/32] copy_to_user, copy_from_user: Use generic instrumented.h
Date: Mon,  9 Mar 2020 12:03:58 -0700
Message-Id: <20200309190420.6100-10-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=B0g67XEe;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

This replaces the KASAN instrumentation with generic instrumentation,
implicitly adding KCSAN instrumentation support.

For KASAN no functional change is intended.

Suggested-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/uaccess.h | 14 +++++++-------
 lib/usercopy.c          |  7 ++++---
 2 files changed, 11 insertions(+), 10 deletions(-)

diff --git a/include/linux/uaccess.h b/include/linux/uaccess.h
index 67f01601..8a215c5 100644
--- a/include/linux/uaccess.h
+++ b/include/linux/uaccess.h
@@ -2,9 +2,9 @@
 #ifndef __LINUX_UACCESS_H__
 #define __LINUX_UACCESS_H__
 
+#include <linux/instrumented.h>
 #include <linux/sched.h>
 #include <linux/thread_info.h>
-#include <linux/kasan-checks.h>
 
 #define uaccess_kernel() segment_eq(get_fs(), KERNEL_DS)
 
@@ -58,7 +58,7 @@
 static __always_inline __must_check unsigned long
 __copy_from_user_inatomic(void *to, const void __user *from, unsigned long n)
 {
-	kasan_check_write(to, n);
+	instrument_copy_from_user(to, from, n);
 	check_object_size(to, n, false);
 	return raw_copy_from_user(to, from, n);
 }
@@ -67,7 +67,7 @@ static __always_inline __must_check unsigned long
 __copy_from_user(void *to, const void __user *from, unsigned long n)
 {
 	might_fault();
-	kasan_check_write(to, n);
+	instrument_copy_from_user(to, from, n);
 	check_object_size(to, n, false);
 	return raw_copy_from_user(to, from, n);
 }
@@ -88,7 +88,7 @@ __copy_from_user(void *to, const void __user *from, unsigned long n)
 static __always_inline __must_check unsigned long
 __copy_to_user_inatomic(void __user *to, const void *from, unsigned long n)
 {
-	kasan_check_read(from, n);
+	instrument_copy_to_user(to, from, n);
 	check_object_size(from, n, true);
 	return raw_copy_to_user(to, from, n);
 }
@@ -97,7 +97,7 @@ static __always_inline __must_check unsigned long
 __copy_to_user(void __user *to, const void *from, unsigned long n)
 {
 	might_fault();
-	kasan_check_read(from, n);
+	instrument_copy_to_user(to, from, n);
 	check_object_size(from, n, true);
 	return raw_copy_to_user(to, from, n);
 }
@@ -109,7 +109,7 @@ _copy_from_user(void *to, const void __user *from, unsigned long n)
 	unsigned long res = n;
 	might_fault();
 	if (likely(access_ok(from, n))) {
-		kasan_check_write(to, n);
+		instrument_copy_from_user(to, from, n);
 		res = raw_copy_from_user(to, from, n);
 	}
 	if (unlikely(res))
@@ -127,7 +127,7 @@ _copy_to_user(void __user *to, const void *from, unsigned long n)
 {
 	might_fault();
 	if (access_ok(to, n)) {
-		kasan_check_read(from, n);
+		instrument_copy_to_user(to, from, n);
 		n = raw_copy_to_user(to, from, n);
 	}
 	return n;
diff --git a/lib/usercopy.c b/lib/usercopy.c
index cbb4d9e..4bb1c5e 100644
--- a/lib/usercopy.c
+++ b/lib/usercopy.c
@@ -1,6 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0
-#include <linux/uaccess.h>
 #include <linux/bitops.h>
+#include <linux/instrumented.h>
+#include <linux/uaccess.h>
 
 /* out-of-line parts */
 
@@ -10,7 +11,7 @@ unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n
 	unsigned long res = n;
 	might_fault();
 	if (likely(access_ok(from, n))) {
-		kasan_check_write(to, n);
+		instrument_copy_from_user(to, from, n);
 		res = raw_copy_from_user(to, from, n);
 	}
 	if (unlikely(res))
@@ -25,7 +26,7 @@ unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
 {
 	might_fault();
 	if (likely(access_ok(to, n))) {
-		kasan_check_read(from, n);
+		instrument_copy_to_user(to, from, n);
 		n = raw_copy_to_user(to, from, n);
 	}
 	return n;
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-10-paulmck%40kernel.org.
