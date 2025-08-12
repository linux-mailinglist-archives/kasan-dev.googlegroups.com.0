Return-Path: <kasan-dev+bncBCKPFB7SXUERBCHR5TCAMGQEOQNN4IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id DCE4AB22756
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:50:17 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-619ac72cc3asf5089098eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 05:50:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755003016; cv=pass;
        d=google.com; s=arc-20240605;
        b=REDKJnxDXdFAnAo/C9hhi4y/CqDayjh8AF8YzH/E9uDIktEcKD35tEbSOzV75O8V2e
         7egvtdD/m29JPxGZNQByLC3Q+N6JJMhcyp974sU7vMriRlFbybPFdQIK8nstaZDxW1Z8
         42Uh75ENOZ/Jnv9sHxIwYUCRMF9MyksVLx9fCh14UF05WFZJ+fMl2oe+kFERH+zwNcNL
         6vsrJdTKXit+CWxAEpysXP52pORJVmpnkyJl0uikkkwh26r25L5y5//4T1Ps855x1G50
         5N0yTyLpUibJR573Rwh4pZFC0w5OGJvL94HhFQMA2lIMnvyoRYsndiCLOw5we1dCFBhW
         mPMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=tAtjb2P08eAza0zPsjM1b23+fUGoqGeR/JXVbuYP8iA=;
        fh=mAyyHirdjqisd4JS44l5645bt46r2b3NL+l6uq5Hz5I=;
        b=LeLjHnyd0Eo61d9InFCuSJvId2dqWOXOhhvxEi1tP9j6YS7+ylLsZF1vYjIYlAzTfz
         EWAKaOyZbldP7EOfc5GrEtRfgF7rXX04XzohENRwy2tFJcRFXBAToTOvJBl06bz0sbWf
         3qm0xCJzsf79rspiFw6u7ktxnjfv8TdhVB1gr4ascxtx9+uhwFnELPr6ED6I9tTsB606
         zjLHT8FZ37RLThHADjS/ixA0QoRpozjhOiI7iYlW3ISue5D/nLWFgZ1j/l/9pfOye0vJ
         EH7WCiez2inLEDk1VV25ebnr+gNOkAnePn/4FS/yIPUJgGnB0YdOcKd8M9HrQsU95mFh
         ytqg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AChmoBPd;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755003016; x=1755607816; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tAtjb2P08eAza0zPsjM1b23+fUGoqGeR/JXVbuYP8iA=;
        b=upRx24jeTz1mXxyd2ZKWotx/C0WEOSTnUlCojoeY0ARyWWuRaUoKi4pC2UFStdk6UW
         TV/+1HS01LuMv8/VTbVBuMx5xwupk7+o9byUT7l6RYZni/rv9HBs1Il3pTPEqXDlHryb
         Lg1Jtzvzy3XAj6GBHxMJaYbXrniu8hHmUTMkfliWglAWjVv/kd6mE1dKSKv47ysYfMEA
         NJPGW8YcVP2fk7FrAasl70Q2eEGaJTTzi5hV9UTbb9kOwlvnV2KFZJAryw+7ycbavTpT
         mL2eBaIYA+x7WNLciyCyeQk+Q4xI43+BSNFPDRT3jxY0erKT9WO7vr9sQU3lv9Ci982A
         nTdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755003016; x=1755607816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tAtjb2P08eAza0zPsjM1b23+fUGoqGeR/JXVbuYP8iA=;
        b=d9wk2x7U80PtrMU0W7dfLbKyavMl5qxR2LBdMECUuQe0Gud5i+ByVyPmXICRRhFSzI
         by8n1nqBVge5r+hFMZsoe2tC/pw6lMlCFrgAvJqHrITNNw/yBUBdSCyYdp23oZ1bXlCk
         a/9VReA4E4yBO7itrSzSs//GPMWddT4rNx3ZWmUUHwh/xA+FuHeNv7mAX+MJ0zrhU/d9
         e51fYae3XAjubCIqA1DM36RhWsjDkjQHQCE79+Efzabx42IkiSIQLSDyIdkY8jfHWnej
         Y46XSYeiHOZ6/3YNPF2QE9RuNfip8l5Ir4jQ87tZvqE3gFx3nk1TUOodsPI3l/SNYmvk
         hLjg==
X-Forwarded-Encrypted: i=2; AJvYcCX/Eq6rwi62Y3NP/IKP1ZsKs1ckO890PkmfF7ivuV21EhOCVSxJFxaTRSA4x/zZKvcxpD1DzA==@lfdr.de
X-Gm-Message-State: AOJu0Yyng8fyAT9WT1f/ONkj3bGhKynTppJfOAsHpajiO8jLtbSHM8zX
	mjJ/MCSkojhAWsjlOVrrb8EBz19sbT3GS7QTUCxhF1rT2+nAqHSaryAj
X-Google-Smtp-Source: AGHT+IHTnLXcYtBp4d0MnC6RHbJ8co3zXSJVeTxuZHoH8AlBmw+pTKS6OOymLJ5JESfN0y7fjDLx/w==
X-Received: by 2002:a05:6820:814:b0:61b:9c4b:4fd0 with SMTP id 006d021491bc7-61bb5d7127bmr2109538eaf.7.1755003016249;
        Tue, 12 Aug 2025 05:50:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdYn2jexP8K9I2oYGViVzHLnLuwYdh5pShVxK00w6otmg==
Received: by 2002:a05:6820:a112:b0:61b:5ae4:7669 with SMTP id
 006d021491bc7-61b6e03e09bls1428219eaf.0.-pod-prod-01-us; Tue, 12 Aug 2025
 05:50:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVqku2rnruKTlrGgm2i22FS/8U0yl9AUykT40phJNIZyk2IpLTLMkTfuAQVxYfCnxdHqnFHnNtgl3s=@googlegroups.com
X-Received: by 2002:a05:6830:4601:b0:73e:5f2a:3e42 with SMTP id 46e09a7af769-7436688d50amr1801067a34.6.1755003014134;
        Tue, 12 Aug 2025 05:50:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755003014; cv=none;
        d=google.com; s=arc-20240605;
        b=N4Vmb5KeyspPWJ7lhL7NIa9UQddrbOZxrPMc3EzMOdGkQHRY64bHGxit0Df+9fBpYb
         4YjlFLKepOuILU9Hj1+N8jjFMzhq6q4IuCcka3zl7uw6cgeAikhxm/mXruIm4cWVZOqV
         8oShvmZGMDE82ms1rS0fcpuT2AZ+lDpVYd6XXpuF9DMjed2Oimhpjfg/RhFN3igXutbW
         VF224emKUdN5uY3wD7OB97v+vHuY1H8NPnuK0McX5/bYTYENiy4rmwD/Ocia8f/VMfEc
         QABF95Wjcm29h6/MByP8VeRrTUOhg6tXJm7/6V6m34HGQ30p61HIYDK5r5cZtBu2SwvT
         jIKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oEDfd5YwQwP//qNNRp60/4j9gVHcNuQdiFWm+KANNic=;
        fh=ZQiobZ3avnYd2dMV0+zhbhF+LZ041TMixvjrGLjsPak=;
        b=P+GfLQwruEZQHIKTNMl62CX/N9cis0wPCs6WpcCqvanU7rdjp3IQUNiBxuMZMHORLx
         CR9ShIxz8DAdMDNM/EGahlZeHahWRJiH7dfLJ/FV5l5OyvVfM8lXPw630Y3sdlBMPNJI
         BaaIgELFLwqaNstN2M4WKSGev8OBAVvo1jqPzacti3/4MeXI1xYg7PMDVKGPWujZNPnh
         8HpTOVP/XvcNwEicTmXhjZBgg4h6F25tTSAgTY4DispQTUUz6GVFJe3Qa5xhg/39hlVy
         mMlW4lk80WO2P2uaXCJvKuQckpAGq7AUDXSTTIWrZmwx3yuBARpQmiQwG7/xVZh4E8Un
         dHnw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AChmoBPd;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61b7c9a44e6si604031eaf.2.2025.08.12.05.50.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 05:50:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-25-pB9e8V-hNSCSigDe8LiZ2g-1; Tue,
 12 Aug 2025 08:50:10 -0400
X-MC-Unique: pB9e8V-hNSCSigDe8LiZ2g-1
X-Mimecast-MFC-AGG-ID: pB9e8V-hNSCSigDe8LiZ2g_1755003008
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 8214119560B1;
	Tue, 12 Aug 2025 12:50:07 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 6E97330001A1;
	Tue, 12 Aug 2025 12:49:59 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v2 02/12] mm/kasan: move kasan= code to common place
Date: Tue, 12 Aug 2025 20:49:31 +0800
Message-ID: <20250812124941.69508-3-bhe@redhat.com>
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=AChmoBPd;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

This allows generic and sw_tags to be set in kernel cmdline too.

When at it, rename 'kasan_arg' to 'kasan_arg_disabled' as a bool
variable. And expose 'kasan_flag_enabled' to kasan common place
too.

This is prepared for later adding kernel parameter kasan=on|off for
all kasan modes.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 include/linux/kasan-enabled.h |  4 +++-
 mm/kasan/common.c             | 25 +++++++++++++++++++++++++
 mm/kasan/hw_tags.c            | 35 ++---------------------------------
 3 files changed, 30 insertions(+), 34 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 6f612d69ea0c..32f2d19f599f 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,10 +4,12 @@
 
 #include <linux/static_key.h>
 
-#ifdef CONFIG_KASAN_HW_TAGS
+extern bool kasan_arg_disabled;
 
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
 static __always_inline bool kasan_enabled(void)
 {
 	return static_branch_likely(&kasan_flag_enabled);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 9142964ab9c9..69a848f2a8aa 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -32,6 +32,31 @@
 #include "kasan.h"
 #include "../slab.h"
 
+/*
+ * Whether KASAN is enabled at all.
+ * The value remains false until KASAN is initialized.
+ */
+DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
+EXPORT_SYMBOL(kasan_flag_enabled);
+
+bool kasan_arg_disabled __ro_after_init;
+/* kasan=off/on */
+static int __init early_kasan_flag(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_arg_disabled = true;
+	else if (!strcmp(arg, "on"))
+		kasan_arg_disabled = false;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan", early_kasan_flag);
+
 struct slab *kasan_addr_to_slab(const void *addr)
 {
 	if (virt_addr_valid(addr))
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9a6927394b54..377e9c285a74 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -22,12 +22,6 @@
 
 #include "kasan.h"
 
-enum kasan_arg {
-	KASAN_ARG_DEFAULT,
-	KASAN_ARG_OFF,
-	KASAN_ARG_ON,
-};
-
 enum kasan_arg_mode {
 	KASAN_ARG_MODE_DEFAULT,
 	KASAN_ARG_MODE_SYNC,
@@ -41,17 +35,9 @@ enum kasan_arg_vmalloc {
 	KASAN_ARG_VMALLOC_ON,
 };
 
-static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
 
-/*
- * Whether KASAN is enabled at all.
- * The value remains false until KASAN is initialized by kasan_init_hw_tags().
- */
-DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
-EXPORT_SYMBOL(kasan_flag_enabled);
-
 /*
  * Whether the selected mode is synchronous, asynchronous, or asymmetric.
  * Defaults to KASAN_MODE_SYNC.
@@ -85,23 +71,6 @@ unsigned int kasan_page_alloc_sample_order = PAGE_ALLOC_SAMPLE_ORDER_DEFAULT;
 
 DEFINE_PER_CPU(long, kasan_page_alloc_skip);
 
-/* kasan=off/on */
-static int __init early_kasan_flag(char *arg)
-{
-	if (!arg)
-		return -EINVAL;
-
-	if (!strcmp(arg, "off"))
-		kasan_arg = KASAN_ARG_OFF;
-	else if (!strcmp(arg, "on"))
-		kasan_arg = KASAN_ARG_ON;
-	else
-		return -EINVAL;
-
-	return 0;
-}
-early_param("kasan", early_kasan_flag);
-
 /* kasan.mode=sync/async/asymm */
 static int __init early_kasan_mode(char *arg)
 {
@@ -209,7 +178,7 @@ void kasan_init_hw_tags_cpu(void)
 	 * When this function is called, kasan_flag_enabled is not yet
 	 * set by kasan_init_hw_tags(). Thus, check kasan_arg instead.
 	 */
-	if (kasan_arg == KASAN_ARG_OFF)
+	if (kasan_arg_disabled)
 		return;
 
 	/*
@@ -227,7 +196,7 @@ void __init kasan_init_hw_tags(void)
 		return;
 
 	/* If KASAN is disabled via command line, don't initialize it. */
-	if (kasan_arg == KASAN_ARG_OFF)
+	if (kasan_arg_disabled)
 		return;
 
 	switch (kasan_arg_mode) {
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812124941.69508-3-bhe%40redhat.com.
