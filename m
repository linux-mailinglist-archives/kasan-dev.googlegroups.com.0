Return-Path: <kasan-dev+bncBCKPFB7SXUERBKV5SXCQMGQE73JMLAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id DD52AB2D388
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 07:35:39 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-30cce57c20asf11052850fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 22:35:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755668138; cv=pass;
        d=google.com; s=arc-20240605;
        b=kXgJuvyeHJyF/JMibLuVuc5ZY3IENbLgjU6RvdQPhBc6tS8t0kVIO+ExYS7nwwMfZQ
         Exf3xljiXy6O7Nd6PI46EE8zRs4QOLoVnme1kRm5yeemQThEyfZ9usiYuPJPvrznVzog
         q3DeMt0EZOhh/L3sDMPsIjMeZNaimGjwXvZRdpooHJXg0bI4LHhLPoW0/XjIuBwUwisd
         AS2MnJHtKmSvEL/ZkELrzouvQtw33aa8Xpu4M+p/1uwGLHbmOHfaeqoUdkb4kMHojFUC
         BHFILCpgGX7AeAGJ7M3pbVAgxKss+nLyOUukAmub+8CAusWMh8pensZQnXviNh+rxXi1
         np6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=mZSBPVi9ZNCf4v/KL1FsK2K441NgXPy7eFN+Vw6s10Y=;
        fh=z52lN3Tco58jCaMhoqk6/91/0bQVK3iRfIqZ2um4Dxo=;
        b=YO+4pDj5Y9v9eNO8kMCD0guGo0/vL4mby7dibWyqyasRYvvg6rPtw7iuJ4BaKR/Ynm
         3VynXfZ4a5uL/o0wIsI1mqBgWi5QsmmKuRkadUpq618LqzcSUN3mESsotRtL5UglfnvU
         5w2DKpXYWkHL/oDZLuwVyzJ0t+GCeMhV8smgJzk3a338bDbsmdUJpTPFspT8s8SZh59W
         85uC9cJpNCLAkANJ2QMPhbuyXMREaJILC2pHHJKiU5d7p2eecTYbEy1aUWzovWTlIejj
         BY5VCCCO5ANI2xvyOPacgAN3O5gKPhZPPJhoC9xTzalLotS27qTUqMgrU+AkStBrCUj0
         q9yQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GLSPaXMh;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755668138; x=1756272938; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mZSBPVi9ZNCf4v/KL1FsK2K441NgXPy7eFN+Vw6s10Y=;
        b=MZN1lVGMWoaaSP1JRkzJJxEU9CxyoccOLgl73BpnxOj5bcIVwupPfLABKQKsU40jSE
         tbpms+SroiLpBIOYwDGM8y1oknoAQXQVxwGPP0CfuLTBeFYVPfIIpKvLdGixCAs1Kw2f
         p3TsV7iSFIRXyVJTZHRfzbjTw8NAO1KrSNL+ZrSfKVQZIQ/wHdpOJQvRrjngndpnu6uN
         fw9NTNjqZDzMToRKyB+ir2vqQ3kvLLBIjR6DOYkaq9IAiQexINiEEHMjxemm6ydIV8Au
         /Ur4edm6fgFaI76t4AM0i4RssM4vt/tMMfHvvItReLoV6eUjYjRwkeXoe1fKOqZ30fH/
         poQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755668138; x=1756272938;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mZSBPVi9ZNCf4v/KL1FsK2K441NgXPy7eFN+Vw6s10Y=;
        b=W73vw88UwhdgLWr6NEa51JYIYjLybGk6FjP/lhKMIuLLxjq2vGjLTrhcLlyqMqNI2o
         uxRG7PBSNDRHLZVG9alD8Hh9ZDfVCBcEU0IUZpRqu8jWDEbV0bsNXMw+0oVPtuHEggIg
         Rea8FoXaAz/eMnR+mzfn+ZvfmQP6Uea9i1GA8RPE/p+/6gLBSxM7ByCl6RdsAnStsBi7
         UV1+KJukeXexkhV8DDLN3wG8GlcYa5h7+eH3rE3K8+4LZi/bhzRNxxi1aI3Iijfz9Y3u
         1sUZiOqvYTGuMrmhsfy/3eWRybBILASU15QT/GeVju8uI7TwstTcrj07tU7B9hq9AzJN
         ks6w==
X-Forwarded-Encrypted: i=2; AJvYcCUUVDWtz2HQHE+kEwf0VG6FtcXvpQcJBkvNNmQm3Yeaeozmfaf7tuAaay9d0vDwDWFzDVTedw==@lfdr.de
X-Gm-Message-State: AOJu0YzM4KPDHFMfmMy1yc4lM+/U3750ZcAnJGg48EMKX2U3GIctunNV
	/JC5qyDIJFxnEerE3oN+CIxnqozglIymd8iwGerlqGLjTkJ/aOraz8x1
X-Google-Smtp-Source: AGHT+IHu/+6z+FkcdtG+r1Yxs3XCr/ThkpsIWEsM79pDM3IgCUljNndu7qb8Avlap8pE1JF02Aluow==
X-Received: by 2002:a05:6871:4097:b0:30b:7d73:617d with SMTP id 586e51a60fabf-3112294e1cdmr925807fac.25.1755668138449;
        Tue, 19 Aug 2025 22:35:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe5T2OFTM16uurBFTFRxvfqn3goSR9nqegrrhkR6O0WTg==
Received: by 2002:a05:6871:7612:b0:30b:b2fd:9588 with SMTP id
 586e51a60fabf-30cce588419ls1683296fac.2.-pod-prod-03-us; Tue, 19 Aug 2025
 22:35:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWa9eC+n5woZpfhaMohVjC1c+CfOXFbNpwXxSHzHRNqYmlubXwwPRgRvAK+Hbx+1CW7uDB+k7RPKtE=@googlegroups.com
X-Received: by 2002:a05:6808:219b:b0:434:82b:f10e with SMTP id 5614622812f47-437720b6c6dmr1023670b6e.22.1755668137590;
        Tue, 19 Aug 2025 22:35:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755668137; cv=none;
        d=google.com; s=arc-20240605;
        b=cX1vZKEWbdjb+TmdGIkCenfhStxIgBpC+aFxCd1G/hQAg5spAhRnDw2IyJ5A9Ewf7P
         4aLOrg/c1gZTiKpYeL2YZNyJUrp98JIypXn1/5KpBWMjTMJvFR2qjyg0AVtQY0SrHAxH
         fAq9Kk1LYx5RkBLTuPFXMZo0er+/2NIGC5/I6HNmj5DGLOYBi5L7YBeo4D536N/q+TTA
         zUIVacDKtPltyRJkvUTgu8UQmKUr2bRhRgssZ/1RpuKAFACnOipgeNl1gl5qNPsrB8UP
         C6zYOZ1j1acui164YBmm9/Lk58ZUZa3esauKjisA7jQj2lHe/bgTcKlNYVu6GWnxVLHF
         L3Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oEDfd5YwQwP//qNNRp60/4j9gVHcNuQdiFWm+KANNic=;
        fh=yx2TOEA8OAv6JgprDRqBo1i40dkdP17DWUnpFH3PSuc=;
        b=D5ymcm/tm2xnCGv6dcEnQzjXZZheuuPqiZfItLTzNkSx1e7qWTHZts+DWHGbQWdt6/
         GV5mdCLogwRaf44Xq8LEEw/uAa73oF2264oLql6cw8VYxFnSdkQcU2YSdqSNqrUM9kX1
         MpUygQ8xJ7wpAVRgfWxuhWK44iwsiVWjjIvC8f7ufcVVrSX2/Q1U8Yg/ClN9A0VhDIZW
         5m/P8MjDfDSgh0u075jCWv6B0VAtHbGw1M1zcTIxEO1pbSwhKdzfCFpq2R07P741YPUT
         v+xUTKFIvxPOpaV6MiuV8Yx/8WGTeRTAdSofstAeVDPV2qnt+FN2qvLpDP8va3A/YHGM
         O56w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GLSPaXMh;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-310ab57b3fbsi613600fac.0.2025.08.19.22.35.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 22:35:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-210-apjXEsCbN2uozEJ6S1Khlg-1; Wed,
 20 Aug 2025 01:35:31 -0400
X-MC-Unique: apjXEsCbN2uozEJ6S1Khlg-1
X-Mimecast-MFC-AGG-ID: apjXEsCbN2uozEJ6S1Khlg_1755668129
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id D44CC1954203;
	Wed, 20 Aug 2025 05:35:28 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.99])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 9B85D19560B0;
	Wed, 20 Aug 2025 05:35:20 +0000 (UTC)
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
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	christophe.leroy@csgroup.eu,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v3 02/12] mm/kasan: move kasan= code to common place
Date: Wed, 20 Aug 2025 13:34:49 +0800
Message-ID: <20250820053459.164825-3-bhe@redhat.com>
In-Reply-To: <20250820053459.164825-1-bhe@redhat.com>
References: <20250820053459.164825-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=GLSPaXMh;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820053459.164825-3-bhe%40redhat.com.
