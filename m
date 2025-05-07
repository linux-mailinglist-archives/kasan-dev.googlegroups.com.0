Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHMH53AAMGQEWC3JRVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 53015AAE5BA
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 18:00:31 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-442ccf0eb4esf241325e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 09:00:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746633630; cv=pass;
        d=google.com; s=arc-20240605;
        b=CvAJEDLf5LOgdvhge7ISPSZxq8nJpLDkvyqSwD5g5lFJYp/xAfHJwsSUYyWb7gJJBo
         xapjkvV7LtrAvqLWLEpDg5c/K81RMXD6z8GfcB7EcByo+zRkdEAHZNWG3qDwHpn1NrvH
         tft3hdxeIYlUQPH6lLBRjIU3rkQY5W2FrCN2GTNJtZYQ68kcaX1SrLvT4rxg5p9mchJX
         c4iw7sUJReqFped1Q63GKzhKHXtxxrCrOP17WqtmgNb4XQYU/rzZdqoPy5h/YWZnB2lp
         b1/gI9eOTGYbriyVno2kBQRLv9qnvtrJRkXh6Fhn2Qf7KUGP2OPBk9o9Bibn4AqsQd5x
         D+Iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=zGJRKmTO6TM5nfqDcdKpM2m58QF8iIc5LHDY86YWBAo=;
        fh=sw2WGB8ZfsYd7YZkgCfe+yGJkDDIXala71ayHnIdmkA=;
        b=L/6+m22jhA/uXe3guTZEOP/+uIQKiFKUA6HY/ZgTUDUGtWhu4DDFnYS2Rnqh0YbbqA
         yqtdbxHC5RoZd56rT84RHqncXi/hhRN451oBdFn0QpqYiG2/m9DITcSvvwWIY8lG7cXg
         MFcJyMuZN3s960sUJjuWMPwonuh7lO8ZccQzJYopBtDBmuGmuDS2/ixQ8YIfL6THkVOD
         Kts1oh3cIm8vpBSJ+Eeh3uNNjkb/munWqv1bZf0CHqybEzbwZUnV1iKIQFb48dN0SmcC
         c1UQhOZNGFAPWiFQi7rKzX1cN3yB/v4s97XE0XGBbyJSyFX0jylPzmUPhVmzCh2HHQr2
         fykQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nvFtcrdY;
       spf=pass (google.com: domain of 3m4mbaaykcvg6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3m4MbaAYKCVg6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746633630; x=1747238430; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zGJRKmTO6TM5nfqDcdKpM2m58QF8iIc5LHDY86YWBAo=;
        b=Ggvl8dZbn3eimsgjk/cM9cVs9FPdWpooPXwnSkqKxgOpSlNWnQSm5jfipP7yy3+DnO
         B2/xt7FJNzXBMijYIxITc9pJDh1q+CHxK2rq44m3KNsrGYCDMx6cVLTEjzUjLZwZHctn
         IA6a/9NweOFRE9tP7ZtrwMU6hspbSqqkh16ZtRTsUBySaCo2tuj0BxtgmBq0L0Xgqthl
         r7UTjp++Ly+nsbqv5oUxCNqQzfulDDCTKg45wuDwf6dE4qNhp05yiKpxt1fba5OzbXzl
         XQi7WYh2FtRq+wfDpOUoNFmiGdZ0B7GlYtUuoCPq70XB+z9sCy1cJm0rryJWWlO+JLbO
         wlzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746633630; x=1747238430;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zGJRKmTO6TM5nfqDcdKpM2m58QF8iIc5LHDY86YWBAo=;
        b=EqYP7OzP0WyDeCJLu3SkXRB5vDBW6oJ3mVGAC2Ox9+PYt2fUDzoQ47YiTTNaAAxRXF
         jq2CZgHVWPaZz2PCDoVVGy0LqrN4S9DT9E65jgUom1OKMEirci9vzLenXC8QuSTyg7Rk
         6MkYBq1LJHAfs0nC/jdmVJYzyw+4CZSweJv2EyfvMhtQCKpzBhLoANUQTkhj9A24/75e
         s+nnj12v0RiFbt9FRpJz+PdoK5/r7U552cyTLImAml+bp8xbDTR678ID4M6sjgfJWeHS
         7gCgoLHyrhXYg1nYvt9jU/Jt0AjaODW/MAOQhmGlVSC5B4OMmMiUNBxTwFEtunb3RdGx
         kWiA==
X-Forwarded-Encrypted: i=2; AJvYcCV2q6+LZ8wdXh/YMU6l0QY6MBWo+sRfRzd5f8GGocMoVyDp4a7aYP/k/wEmYQmdKfsXQBIvyw==@lfdr.de
X-Gm-Message-State: AOJu0Yw4ZKewe+znObBmSqju9JyrusQHPKfSrpW5HhS3xh8JVXam893z
	DinGpFXpM7Q8310JHOOqZJHgkF6k41bZDqnPK8vyV9enVsCLOmcc
X-Google-Smtp-Source: AGHT+IHrYQMQDQMvE1kI/Sat3mjc4sSGPR/kZ753V7aY4fPoQwIa+NvMA+pJ92nf6lzy4bWMXpGcIw==
X-Received: by 2002:a05:600c:35cf:b0:43c:e481:3353 with SMTP id 5b1f17b1804b1-441d44c9369mr31509425e9.17.1746633630474;
        Wed, 07 May 2025 09:00:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBG77iWJ7p5dKKI1sLmLclL+ppDrYlfkSCu2NLsY7e41fA==
Received: by 2002:a05:600c:83ca:b0:43c:fb0f:d9ae with SMTP id
 5b1f17b1804b1-442d03519dbls44355e9.0.-pod-prod-05-eu; Wed, 07 May 2025
 09:00:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUvLWryH8TQO9/UNU77jxd1QJ7kbsSoznEb+0Kg2Iq5q1U2B/Q0ywi9wegYybtMWh9PguaMdSuAEKw=@googlegroups.com
X-Received: by 2002:a05:600d:2:b0:440:8fcd:cf16 with SMTP id 5b1f17b1804b1-441d44c9917mr31628655e9.19.1746633627536;
        Wed, 07 May 2025 09:00:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746633627; cv=none;
        d=google.com; s=arc-20240605;
        b=VgEzADvoGbapGqnH0YtGOVGm/UrMMUMofswszn8TcILrSpcoecdHxPzCuLlN1uvFsC
         ImrvR8MaVc74Ik4NWBpFYa3zpHi70h0UTC4V7C3j3WmoXcrJJCf2IBZNUaFWX3KfEvwc
         UT0GUXeA1pJZhpOU6dIwpTpprOKmpSzgexM1YDPHgGEgHx1YHAICChlbsvuMDHefSS3f
         3ia7sx6oV71GCPPCepbe6KHWz7x/2AryvLKUiTF6BQNEnw/SoiBZlYsWj4xiu32xvaEV
         WSnRfHh9N8CzqdjVC0+V27DjFOp2g2rOSj/lBNtiGjpakbE3e6qDpcAqDYbKQjKX6qU5
         0F/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=KJFmPHpAjo9itenoi9XTrC240347opuYhZoN6Yf/YdQ=;
        fh=gfdMtj+acA2wUbdXL/zs9YIdZhLY8b+BBr7w0yES9f4=;
        b=h+lbKqShDSJka9/AEwPLNCq/q8vv62vSs4G9dUe1d2bA7LRONUwYs5IwO3UdunKGjR
         quF1D5m1hsAG90Frq7l2AU5V+y/I+K0gC0FUo1vXYJNqYXbnN4RaOYRRITsopS2Osy9R
         NK4IrliCw6aZIkbBBjeAX1ZJred0z6GYe54X1ICK9KDsXQydnMiQMGwYm8rocrRMamWm
         S1IMDlThPT55hciT3z0J5j8lx3NPiAe/W8OATC3w+KHiC7R2C/QIsob9lnrF0u9ybMmh
         8IZaNxnuv6CDKTHmdJiP11dDHT+GI7sY7Cd7qIxWY3IGkvee5eI8sPPmrDnH1Z+Sj1E3
         DhdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nvFtcrdY;
       spf=pass (google.com: domain of 3m4mbaaykcvg6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3m4MbaAYKCVg6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-441d11a9570si2118495e9.0.2025.05.07.09.00.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 May 2025 09:00:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3m4mbaaykcvg6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5fbecca2c90so1166922a12.0
        for <kasan-dev@googlegroups.com>; Wed, 07 May 2025 09:00:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUJr2YMb8wBGees0qKMReRZe9wXNIG7GVvqAuYMae8uaHF2/TPbVqUL3P2qfLMfd8QVJQruDs1WiBk=@googlegroups.com
X-Received: from edxf17.prod.google.com ([2002:a05:6402:14d1:b0:5ec:cf38:1b3f])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:3813:b0:5fb:fb49:9cff
 with SMTP id 4fb4d7f45d1cf-5fbfb499ef2mr1646769a12.7.1746633627031; Wed, 07
 May 2025 09:00:27 -0700 (PDT)
Date: Wed,  7 May 2025 18:00:12 +0200
In-Reply-To: <20250507160012.3311104-1-glider@google.com>
Mime-Version: 1.0
References: <20250507160012.3311104-1-glider@google.com>
X-Mailer: git-send-email 2.49.0.967.g6a0df3ecc3-goog
Message-ID: <20250507160012.3311104-5-glider@google.com>
Subject: [PATCH 5/5] kmsan: rework kmsan_in_runtime() handling in kmsan_report()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: elver@google.com, dvyukov@google.com, bvanassche@acm.org, 
	kent.overstreet@linux.dev, iii@linux.ibm.com, akpm@linux-foundation.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nvFtcrdY;       spf=pass
 (google.com: domain of 3m4mbaaykcvg6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3m4MbaAYKCVg6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

kmsan_report() calls used to require entering/leaving the runtime around
them. To simplify the things, drop this requirement and move calls to
kmsan_enter_runtime()/kmsan_leave_runtime() into kmsan_report().

Cc: Marco Elver <elver@google.com>
Cc: Bart Van Assche <bvanassche@acm.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/core.c            | 8 --------
 mm/kmsan/instrumentation.c | 4 ----
 mm/kmsan/report.c          | 6 +++---
 3 files changed, 3 insertions(+), 15 deletions(-)

diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index a97dc90fa6a93..1ea711786c522 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -274,11 +274,9 @@ void kmsan_internal_check_memory(void *addr, size_t size,
 			 * bytes before, report them.
 			 */
 			if (cur_origin) {
-				kmsan_enter_runtime();
 				kmsan_report(cur_origin, addr, size,
 					     cur_off_start, pos - 1, user_addr,
 					     reason);
-				kmsan_leave_runtime();
 			}
 			cur_origin = 0;
 			cur_off_start = -1;
@@ -292,11 +290,9 @@ void kmsan_internal_check_memory(void *addr, size_t size,
 				 * poisoned bytes before, report them.
 				 */
 				if (cur_origin) {
-					kmsan_enter_runtime();
 					kmsan_report(cur_origin, addr, size,
 						     cur_off_start, pos + i - 1,
 						     user_addr, reason);
-					kmsan_leave_runtime();
 				}
 				cur_origin = 0;
 				cur_off_start = -1;
@@ -312,11 +308,9 @@ void kmsan_internal_check_memory(void *addr, size_t size,
 			 */
 			if (cur_origin != new_origin) {
 				if (cur_origin) {
-					kmsan_enter_runtime();
 					kmsan_report(cur_origin, addr, size,
 						     cur_off_start, pos + i - 1,
 						     user_addr, reason);
-					kmsan_leave_runtime();
 				}
 				cur_origin = new_origin;
 				cur_off_start = pos + i;
@@ -326,10 +320,8 @@ void kmsan_internal_check_memory(void *addr, size_t size,
 	}
 	KMSAN_WARN_ON(pos != size);
 	if (cur_origin) {
-		kmsan_enter_runtime();
 		kmsan_report(cur_origin, addr, size, cur_off_start, pos - 1,
 			     user_addr, reason);
-		kmsan_leave_runtime();
 	}
 }
 
diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 02a405e55d6ca..69f0a57a401c4 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -312,13 +312,9 @@ EXPORT_SYMBOL(__msan_unpoison_alloca);
 void __msan_warning(u32 origin);
 void __msan_warning(u32 origin)
 {
-	if (!kmsan_enabled || kmsan_in_runtime())
-		return;
-	kmsan_enter_runtime();
 	kmsan_report(origin, /*address*/ NULL, /*size*/ 0,
 		     /*off_first*/ 0, /*off_last*/ 0, /*user_addr*/ NULL,
 		     REASON_ANY);
-	kmsan_leave_runtime();
 }
 EXPORT_SYMBOL(__msan_warning);
 
diff --git a/mm/kmsan/report.c b/mm/kmsan/report.c
index 94a3303fb65e0..d6853ce089541 100644
--- a/mm/kmsan/report.c
+++ b/mm/kmsan/report.c
@@ -157,14 +157,14 @@ void kmsan_report(depot_stack_handle_t origin, void *address, int size,
 	unsigned long ua_flags;
 	bool is_uaf;
 
-	if (!kmsan_enabled)
+	if (!kmsan_enabled || kmsan_in_runtime())
 		return;
 	if (current->kmsan_ctx.depth)
 		return;
 	if (!origin)
 		return;
 
-	kmsan_disable_current();
+	kmsan_enter_runtime();
 	ua_flags = user_access_save();
 	raw_spin_lock(&kmsan_report_lock);
 	pr_err("=====================================================\n");
@@ -217,5 +217,5 @@ void kmsan_report(depot_stack_handle_t origin, void *address, int size,
 	if (panic_on_kmsan)
 		panic("kmsan.panic set ...\n");
 	user_access_restore(ua_flags);
-	kmsan_enable_current();
+	kmsan_leave_runtime();
 }
-- 
2.49.0.967.g6a0df3ecc3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507160012.3311104-5-glider%40google.com.
