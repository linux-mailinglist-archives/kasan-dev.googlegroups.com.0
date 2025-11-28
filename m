Return-Path: <kasan-dev+bncBCKPFB7SXUERBKNQUTEQMGQEKK6EHKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 20899C90C27
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 04:34:03 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-4337853ffbbsf11155345ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 19:34:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764300841; cv=pass;
        d=google.com; s=arc-20240605;
        b=S3AQ16O9i/QPPDSgIdWB97dCk+XxnsRXdlcMpiyyGqV9Y0OkYsik9Qqc6StvZ2SJpT
         og6/sWsX6lJ+CwyeiHkM/CmOJMqShbr0URJgTdUgOKdr4doPkho2Tpft+9rKj+NJdt4c
         t+VbzcMBdbIJpo93lrqwrORJnYQrLR9nH4Zn75y/6UQCa+a9O8PX+GP41Swon0upBBbu
         WqDhbAxtF6bW9fsyz5bJdtiFz2Kcg0RtKHmKPZJiHykf+CXqCN4/ch02AlsAkH2n13m1
         mDwOBUTgT5FAX/ccjhcIX9pF5KRNHOAcHBELqiniJD6RVlOakBTSBi9aF9iey83GQJU3
         Qgag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=jd2izxMtfy5juqqV95orwnKfb3A3BK77G6cz0C6zdd8=;
        fh=8tQF63GYK13hx2I2kkN1Cja67cCt2/S//Qz8zoOfYf0=;
        b=ABKv2EyT+ReEENT0mEmJBWRCkBjSJtL3csi/xyxHTTc0g3ocyhSoK3M3ospLkASGan
         ruRII55qd0yuXTf5J1o5aYV/Cd/inqZUy2PjX5OuKxuhVuQPhPHR0KrTRxqQA4DUgi0a
         d1pTXVoFyD5mXym0fC6xsRYYWjYF0tyZvpVlC9Zxy0Qhl5yjpiMez5JhRJQep9s7hifj
         /PGrFrkTJ+0QdALiZhhnAXOecXzwBSmn4Spv72FLuRnwbKUwnPNV+6AePvwGyaJ4VdU1
         bokpYQfIQstfJml2mUT5QZBK/NOFtJXkF+ft2a6woXP4e1eV32R2o684IkZWjjLjkTZ+
         tiHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="Z/ylJZF7";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764300841; x=1764905641; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jd2izxMtfy5juqqV95orwnKfb3A3BK77G6cz0C6zdd8=;
        b=VPbOYlt3HLH75ban2nDV8QHkKdqpFyJsVqfIt89eAvMbPkyUjerV8Boal7hx6W1HaB
         czLjyhahT5K7mIqRrqMcqEjB0Kky80JnvlUSoBiOj6yHEq0UJg0YJeL+33y5EErB12lV
         q+q+JTOazEj7y7rulcVOD2K3SlL52kZYr+edksXV+RTg670HDYSYY+DGdlvEnaGW43QD
         BCeQmgI53PJsEWJBhoQWXdgQ1M16ySYbPir2RKR4MBeogVxGBlH0rkMevZlKKeumZFNT
         MXaOolypF745qRs4Un4x+xEpMXTn9Zd0JBs78tQ6SF5fut2+eN1teSoChUGRQtkUnCDc
         5IQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764300841; x=1764905641;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jd2izxMtfy5juqqV95orwnKfb3A3BK77G6cz0C6zdd8=;
        b=NJ//na//yLQDG3LL2aPTYPsCASmyRypgL+S2Pp1CeEwQAPk3fCxK9ST1Fpf0Pq1Acd
         b+Ma3Jt8I6P0aGUfTEZRybNFm8InIumHdBZf9LUYvZ7P8Bnj+A58vQcM2NNzmEgwxNwl
         4Q3SVpSKekCFoWpLqGwin+3s+k6mMejnqbdTkNCfVOUV8pSce87YJRVCceI+pnzbYDpR
         HDGchco+InqbI9jTZ90AD+dWb7yi6UvUPwMb1lDJ+z1Uqx7WTsZvU/rb3f6KpOATUA3U
         SvmJFWDo6gqEkwz/57J2NxQcpO71ReQ5tHQCJ1FiNznYqwXwaS3Y1EjWcEo3YS+gU+Em
         6N/A==
X-Forwarded-Encrypted: i=2; AJvYcCWHr4YiBxM4s4u06XCH9VOQjuK+6+ooLPQcB4OCYCCD45uZxPKGC9PP1IAxy2PCPvFAEybHqw==@lfdr.de
X-Gm-Message-State: AOJu0Yy09J5MMemGfx9C89Bh8k+tBlV909tPC+29b989ZOdHx7+X0N7s
	b/Euzwn7wYem9xx0p/uLBMWl88iHJxRqBBf4hFXRveneMJc4lY0sWlGE
X-Google-Smtp-Source: AGHT+IEn8kLt+HrIyjE8gkpZDm8XCzmxa+poRqYTfHpfci9hOyYIMa+Xs5j/ASSNp7fXZ9EtkR2Qdw==
X-Received: by 2002:a05:6e02:152b:b0:433:23f0:1ebf with SMTP id e9e14a558f8ab-435b8c181eamr224653365ab.9.1764300841514;
        Thu, 27 Nov 2025 19:34:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zjuhp62hVAMwW2vh1T9N3KGhtET8l/1g4K5cempELE5g=="
Received: by 2002:a05:6e02:152d:b0:42d:a925:aa25 with SMTP id
 e9e14a558f8ab-435ed4b4d55ls8181535ab.2.-pod-prod-01-us; Thu, 27 Nov 2025
 19:34:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWG9P5TseiET3Cuzs+XUGo//3CL+wMGW25tHMjx94L1xjjhO4hxvBndPTElZ27y//ajb0qrezO82UM=@googlegroups.com
X-Received: by 2002:a05:6602:6301:b0:949:12e5:aa2d with SMTP id ca18e2360f4ac-949475350ccmr1850958139f.9.1764300840562;
        Thu, 27 Nov 2025 19:34:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764300840; cv=none;
        d=google.com; s=arc-20240605;
        b=c2wBH+q3OL6CFbmsNysNPi5fpTu1l2CTabNM1lQibIhXMrJcKGUn2GJfL//TNIoWw6
         qzKnODgleVl47YBBv0mKrZARQ3gqSLXoP5ocoujT3OplmR94Wc2j48ZiMxVpUPh2avlO
         XsrRriZjWaqp2USrAeSAgTG7H8Gjkv7+37QStATdtpwh8Qh/J2BTnMIxNhzO9FgfyTaE
         +NjK8jH5IuwgbUdw5JagmUgyZ9tS84Tq2kznWloRS2dGo01gVLJ2gHDUzNQRCcPDgQvL
         +A1NNsLFLVC4iDyJKdSrWYRAbn7lax8H5QlyBdllbojO/SCddoteENsknMwWzaV1j1U4
         E6sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=G3gPrOC7MauvGRj4YbxCiDaSAJrqi5DShDaS5sFXKjg=;
        fh=5SDByJ3Hs0yfOCoQGEuG1sRE6NAvqIWBUeJICelOz9U=;
        b=kXJZrSrk1Am/wb1G3SZQzguaDXZSttn4KinZo4s95SsD657IhqGSeb3J4xwXVexwec
         PX6NkoGWCkHv2FRtwnNOsJqO7jIlSHAW70/PBlT4A+OoSawZ2cZRwP8XOdcyi4FjbF5f
         aPZmaZpL6iPXLS9xY+Iew/218bGWegqLcxcZfHTeeZY1+nx5QUiUIW20kGTIR/avMj5l
         9zWUMURkF+h8AOOOy3DsOoILWgtVZGny1hpuWWWKjnOKgUq4miXrAS0MAoZCxHQh4oiW
         s8F502CHVHD5Q175CCoH4uvnE3krSM8Fh1Vhbe7w42q/rCUeVwK6ZSVFmGo6QFEkzavX
         pISg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="Z/ylJZF7";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-949900613f0si6523239f.5.2025.11.27.19.34.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 19:34:00 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-346-uEumHcseO-e49imQKWSn1w-1; Thu,
 27 Nov 2025 22:33:55 -0500
X-MC-Unique: uEumHcseO-e49imQKWSn1w-1
X-Mimecast-MFC-AGG-ID: uEumHcseO-e49imQKWSn1w_1764300833
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 657891956088;
	Fri, 28 Nov 2025 03:33:52 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.7])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id A23FA19560B0;
	Fri, 28 Nov 2025 03:33:44 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	elver@google.com,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com,
	christophe.leroy@csgroup.eu,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v4 02/12] mm/kasan: move kasan= code to common place
Date: Fri, 28 Nov 2025 11:33:10 +0800
Message-ID: <20251128033320.1349620-3-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-1-bhe@redhat.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="Z/ylJZF7";
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
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
all three kasan modes.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 include/linux/kasan-enabled.h |  4 +++-
 mm/kasan/common.c             | 20 ++++++++++++++++++--
 mm/kasan/hw_tags.c            | 28 ++--------------------------
 3 files changed, 23 insertions(+), 29 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 9eca967d8526..b05ec6329fbe 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,13 +4,15 @@
 
 #include <linux/static_key.h>
 
-#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
+extern bool kasan_arg_disabled;
+
 /*
  * Global runtime flag for KASAN modes that need runtime control.
  * Used by ARCH_DEFER_KASAN architectures and HW_TAGS mode.
  */
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
 
+#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
 /*
  * Runtime control for shadow memory initialization or HW_TAGS mode.
  * Uses static key for architectures that need deferred KASAN or HW_TAGS.
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 1d27f1bd260b..ac14956986ee 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -32,14 +32,30 @@
 #include "kasan.h"
 #include "../slab.h"
 
-#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
 /*
  * Definition of the unified static key declared in kasan-enabled.h.
  * This provides consistent runtime enable/disable across KASAN modes.
  */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
 EXPORT_SYMBOL_GPL(kasan_flag_enabled);
-#endif
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
 
 struct slab *kasan_addr_to_slab(const void *addr)
 {
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 1c373cc4b3fa..709c91abc1b1 100644
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
@@ -41,7 +35,6 @@ enum kasan_arg_vmalloc {
 	KASAN_ARG_VMALLOC_ON,
 };
 
-static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
 
@@ -81,23 +74,6 @@ unsigned int kasan_page_alloc_sample_order = PAGE_ALLOC_SAMPLE_ORDER_DEFAULT;
 
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
@@ -222,7 +198,7 @@ void kasan_init_hw_tags_cpu(void)
 	 * When this function is called, kasan_flag_enabled is not yet
 	 * set by kasan_init_hw_tags(). Thus, check kasan_arg instead.
 	 */
-	if (kasan_arg == KASAN_ARG_OFF)
+	if (kasan_arg_disabled)
 		return;
 
 	/*
@@ -240,7 +216,7 @@ void __init kasan_init_hw_tags(void)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251128033320.1349620-3-bhe%40redhat.com.
