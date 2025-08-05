Return-Path: <kasan-dev+bncBCKPFB7SXUERBAGHY3CAMGQEAWVKABQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EDD9B1AE30
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 08:24:02 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-7e69dbe33fasf472928785a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 23:24:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754375040; cv=pass;
        d=google.com; s=arc-20240605;
        b=VHSK3vsZIq3htSVBVUCjXTJQgV+tDQakmH5eKdsnbdE/9qhMUCN3vkOKFHH8OjjvNy
         xDrDchC+Z/TD7hPML0h0TrVLtGkiDriOi9RQaIiiSrjzjEQH2Ajd1McK6R7bjI4RCRGw
         MMKfrbPEcgNoGmOI1Kflf9IFn/9qWVqGZlyi/TiixIImrulXsc6wcFy/0S7+JAaTn2NO
         Es9K5ioLtZUcDoljqKSHK8XCht5t1CF6//JhQGfhTVZCJ9EVRQp0o8KWDFLyZUhhOMIW
         2TDdt/N4VYNyQlgRd8SfIZFFcx2Pi0HaW80hnkEik6fU/di/DrWHiYCa54JdigZ7yy8k
         sVLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=IUDwXhuT2MdgPiTqKMAriyrREJOd1eEDyEasdeATxKM=;
        fh=JkgFBLKgZCELuHjt6lwMe6O7SL/L4btl61Olh7+B/30=;
        b=IvFjdBjkTIyyRPDQZLkibJ8cd1r1NLteqAfmuNFHzTezQuj2lGuSC+U7My5o6SKh+S
         B+d53SFqA2hRZz70/tpOMjnls9yLORDtWRXu6Rb9iT0hFd+kgPCXnGix2Ha9ra5ZGt2P
         twrpC0F9BZfDWS76KWwIfZLfv9KJpFTH/gPxy5+FKyBNM1wFl22TGaPBzQeLyyo6eVxy
         ffwaP+NbzpFMn9+vM3G3/Es4eCi2E0gwnD7XwSWuVnyN4Yv1Uj3HnkYN30THer5VDuDg
         i+gfpDqRvj3fcbRS2nB4nqqNG9m4gK6smNcTvoexXNVBEFaOCfgAizsmxYefCE7VbQm/
         ky5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="XZ/k6NeU";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754375040; x=1754979840; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=IUDwXhuT2MdgPiTqKMAriyrREJOd1eEDyEasdeATxKM=;
        b=WpQIGN8EJMXJKZAk3qKx3vKgE21i1F3ti1QHkUwAI7lVNyiAOzXgwJe72S0W2aDFOh
         GnS9en3b9Mec7DpSrYOduEV4imPqdwpSX5AAzI4dzH+1e7vwP5L7a2TxlpDsqGjJTmRq
         msHcY/0uSZMBwkPSypWgjEOaEYeKmPoeG1AisTEwipv6JZCLmIsheP1Yjz4iTrCUFUwr
         t+iRAcBfnw4Ey0Sq9Qy4gI/zS5CGy1JDhQXGFBELfBHwvoE5DGm2YJithmuRW9rMviuA
         HQ8TQYj4dDb7407wuP73nlRVQCFl7FvJ9Lt+IMDwBcEaasoEn31GfG182FgbWZyReDgf
         hixA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754375040; x=1754979840;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IUDwXhuT2MdgPiTqKMAriyrREJOd1eEDyEasdeATxKM=;
        b=NO0MHrQZ/6KalBVCib2erpFUluvNQTYIgH7ZKxCJBLR2dqb9YMtWItV8KJA7hEKCQh
         V92BInA2mjra4rZ/QEL11H2D9U0+wQUmsys8TQk06Dx5uaQz/kbIVmumQMRvqZd6MZ64
         TXPs2MEaq7j3Wmhce+rUIxjNkDtN/432HxzIqvccfPgHXgMK1c/Y684LfAI75tocTIKa
         c4lyb+OMkwP/Tv++RA/pm6e+q60VQPY6Lda8iusdKMjffiN93RxihBhYZvyHdfWkU2ep
         yCmV2W+cyKle6r7chPuSPmybBZiutIR/OfGqRpFy3TR2ntyEqlMetOmc2xwSxM8aS2zU
         U6pA==
X-Forwarded-Encrypted: i=2; AJvYcCUiJvVjQv0xVA09B/r4hB8c82rUEUxKgLKp39jf+f5GfkJzapUKGVB8lN7h0d8L5wKD9JlwRA==@lfdr.de
X-Gm-Message-State: AOJu0YwD5qY4f3pU1tRX4sH34Op6dEmCWe9lnr0/fujuTaYHED/ycEhI
	0IEPCqpc50qWnQ1j5xREm0SCe5FC+ymlB6PWf6h8DcF2a4eDVDGZPwLO
X-Google-Smtp-Source: AGHT+IFOPSVzntgzJEFlXrAlHtf0oVUpWQt9u/tvxxpu3oNWwUX+zGOBsSKzCHOgFYSQCulf3rxtNw==
X-Received: by 2002:ad4:5747:0:b0:707:3a96:9f08 with SMTP id 6a1803df08f44-70935f1e470mr157839956d6.8.1754375040515;
        Mon, 04 Aug 2025 23:24:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfZ7xRaIxPFDN69zQLixLaSdXIkWJZ5G965UcDX8b7iOw==
Received: by 2002:a05:6214:b68:b0:6fa:fb65:95dc with SMTP id
 6a1803df08f44-70778d6c838ls110739116d6.1.-pod-prod-01-us; Mon, 04 Aug 2025
 23:23:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW8MgfuS4g67zeQ++GvkJp0rN4fVCxIQKqDVxC89fjW9CXIdWp77ev15XC4t6i5ndT63EU5+gKNs14=@googlegroups.com
X-Received: by 2002:a05:6122:c84:b0:539:4284:34ae with SMTP id 71dfb90a1353d-5395edbd02amr4769366e0c.0.1754375039696;
        Mon, 04 Aug 2025 23:23:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754375039; cv=none;
        d=google.com; s=arc-20240605;
        b=CBS+WQUJjEoZmf/3QI+9XCtEBvXKeCS6Rs4Ewhlvu6mNLDnLzV8BHwI521lPWUh/hM
         EoSRkOmyntW0SKSRqQSuw49f6VMyKIQnvxOJyHHchBPAmiO87lqx+Su/YqB6WFWgktMn
         0Dl4x1eizM+tNjk8WhSTbKSmiY19BHNmMKLdAShOk78Rk+APrR+Ose8z8ShnsKKmwXym
         DAMfRWcKjg1Yy7c3XE3lC479FCHiPpkzO+Gtgw1waYEnbZdvrqc/s0uhuO8ZoxFKVSGu
         UB//tjUoTUGdM9FDB8m1d6yNBvARdyPRcXSDJf973kSzNaUSP1K3VjH/4vExYUQuBP5a
         29kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gZBsPQV9kOkkozOpLxZBEzL8oHtewXXrqpcjTZWsiRU=;
        fh=zdgUGJ5AVcpjW6c3+faZMlslsU1+4WtDOSxOnvwQO5s=;
        b=kEARUg+c25CYwkwx7mv0IfJvtyvy+pvgMY0+uZDJJ8DkcKshvAgxhj6uAS+4t1XS99
         zdves/ZwjrrUut8zQLP/l1C2dpQKURdKS5bUH2QZuK7stWUvWXsE7v4I9pwpP9DWFI89
         BMm023bMeQgYQEMBP7ldeS6pNBJMkIkYMLp5Fey4KOJrKfIf/VyyeMf/lZUbFYb+CrNq
         Fle/08jO+LtOlOoRjffntGkAVUxDtl0os0okA4RvR0IkOWCWOkAmbSQiVDdTd3U5qKI9
         grjcEmzB9ZKKPMy3mQ/sdvfoqj+e/KaZ+aZThBW38Qn2wk7X64FjEbbTbrcjVWcfXJUV
         YuJA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="XZ/k6NeU";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53936cd8773si507562e0c.4.2025.08.04.23.23.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 23:23:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-26-TZy3PSbmM6WgBfqMCjg2Sg-1; Tue,
 05 Aug 2025 02:23:57 -0400
X-MC-Unique: TZy3PSbmM6WgBfqMCjg2Sg-1
X-Mimecast-MFC-AGG-ID: TZy3PSbmM6WgBfqMCjg2Sg_1754375035
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 7E55E180036D;
	Tue,  5 Aug 2025 06:23:55 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.136])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id C857B1956094;
	Tue,  5 Aug 2025 06:23:49 +0000 (UTC)
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
	Baoquan He <bhe@redhat.com>
Subject: [PATCH 2/4] mm/kasan: move kasan= code to common place
Date: Tue,  5 Aug 2025 14:23:31 +0800
Message-ID: <20250805062333.121553-3-bhe@redhat.com>
In-Reply-To: <20250805062333.121553-1-bhe@redhat.com>
References: <20250805062333.121553-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="XZ/k6NeU";
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
 mm/kasan/common.c             | 27 +++++++++++++++++++++++++++
 mm/kasan/hw_tags.c            | 35 ++---------------------------------
 3 files changed, 32 insertions(+), 34 deletions(-)

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
index ed4873e18c75..fe6937654203 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -32,6 +32,33 @@
 #include "kasan.h"
 #include "../slab.h"
 
+/*
+ * Whether KASAN is enabled at all.
+ * The value remains false until KASAN is initialized.
+ */
+DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
+EXPORT_SYMBOL(kasan_flag_enabled);
+
+bool kasan_arg_disabled;
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
+
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805062333.121553-3-bhe%40redhat.com.
