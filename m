Return-Path: <kasan-dev+bncBCPILY4NUAFBBNMVWO6QMGQE7ZFODHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 44F23A32B78
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 17:22:15 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-2b85ba34ec4sf3951679fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 08:22:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739377334; cv=pass;
        d=google.com; s=arc-20240605;
        b=d+v9Ciu/ECB47yXBayG6bGkcIOINNtGJTnSa5DjqHGRdAP0qr6mfhycfepHUPwNoYJ
         1tCTov5IMO6M+qNkRJVOJChRuOzjOTpZTJ7r5IG4w8mHW/thMqhHihJqnIY64cXrglUR
         S6+3bDA6KNeMajb7ZMB5WUa8033W8FpM2NP1Qs4F0CJNcSbwe70CBMo4JeltR/qCBRcN
         eqD10mCaHF+FIsqjqjA8DgDfafbxVhh3Fxq6Y48oVKeMvEc4n72zmzSmH1V9gFiQ1kA3
         ec9bGJ7kjnenIwqcKlJ95f85ndFLnMs2lHaZgJ0AkXT426HbDVHANXS5SOD+4zRTzyfd
         L0YQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=FaygA1OgtVZJD16fZcfed84C156+NWmuj7DB7yFs7dg=;
        fh=7JKzrmzUVshA22EoVGxtm6zwciTarg5GanZXB0dXiYw=;
        b=ePY0bOY6Hd0R2cZWEJXSiJXnE8hNm0A5+sCMTvJoPRfB0IYIOLI5K5ERSOcvJCEu05
         NSL7jKjXFliHle+fI/ZJrX6E9QsOR9s5WaUmSNbeCGBt0TUywXP/jrmpNlQWeVhZ2ExR
         hDq3zDYxxJ/8E1ldE5TBUhdC3oc0TlBlkGXWD/dsn2D3JwpwwwF2NZlhoQ7zfhO6n6o+
         gPrlsj+lESycwkUneA7xgabB+lATs5ma+A4+qKAg0RLiAthjRAhGfZTRd55uB+ywd46n
         4yga+Jc+NaGDgYYJY6VDZsrxjGIEt0RiUFjjThvthpYLUMX502l+ZZS7JoBcexw8bfjc
         uljg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=d9GmcSLx;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739377334; x=1739982134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FaygA1OgtVZJD16fZcfed84C156+NWmuj7DB7yFs7dg=;
        b=F5YAhibEKsHTIGJRC/Y0OuHnynS6xUe058qdg7J2QNsVIQjruDZqMqBSZFuiD6kRtm
         pd7RsoYeOQeWIOB8dD07DxWF5FQvxUmmpS6UDLGBUqzDcnUeQulM1rWfxUsPwoX9VLLo
         hnFFfGVyfVp1K5WqJWXN6aizBbC/xegLfLXCLFJxX+FY3YeBP4TuzAdKgzgEZGzyKngW
         3a5naC0y2qDRCfD5zeGEuB+w7P/t5Nyj1i4NSs5Ew6YJ28/uupTTId0dzIrqJ9UjhZ0d
         1XMKArjotx7maHxCgFbRt2G579JCHBDNBC89gS3LMClrWl7a4dpX/BY1ehfcMcTt38Zn
         hRnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739377334; x=1739982134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FaygA1OgtVZJD16fZcfed84C156+NWmuj7DB7yFs7dg=;
        b=vtgKxsKOW2zMIxbsI05uLDxvL2cHs5+hfMeaE+AWbY1jN1Oj5NQy/iAxsCGi9vgQl5
         AYLodgZw+PoH1acpiE3U9rHQbSiUW6ZGE5tB2iKHB4oHpM4Tt1UgAOwmttI/2t5WOeEp
         V2Z5O4a/gx6ZJV7ekjlfAWjeubxTgwlwWaqDuTGkVfunw2FrMTBmC2Tyt/7uALIRjtoP
         IMkxd5JXzxaHQgeyeU39xcGDyQ5nRkDMxVyTe67arGuVfvwYUQKaU4envb3oaqL9lFVN
         tP37wqd9Z6sIZfIZqrhpjXn23jjkgygu4t0NNJhC8IHMBD9E7aPQLvoEW5U1313Nrsus
         WIqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVAVBneWIm/oeiw/dxzEro22uwHAeVjnWAbJk/9CcLP+T3ZS8VOtnLnK5nozjj89Jed+yRekA==@lfdr.de
X-Gm-Message-State: AOJu0YwKlcj2B9xXx/CFSFsDdbE6F+8TWuimILA/3Dpt6cW8pZ8ZJCjO
	u1WJXV7e5aCG4ehHru2PLSdY4uncMRech07ejbWIAc8UaI6aSiGI
X-Google-Smtp-Source: AGHT+IG9zrawVe2UgH4EtSjHX+pv12zTH7xuIHbt+kWwcYOAmxcXHSP9xjIKf/ZWI7D0v5TGjdF0tg==
X-Received: by 2002:a05:6870:5490:b0:29f:b1d4:7710 with SMTP id 586e51a60fabf-2b8d67b8c03mr2388312fac.24.1739377333966;
        Wed, 12 Feb 2025 08:22:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE+D8zb0ob1Rv4CpVYQBFilWWj85M1e1E8Q4xjpBd3ALA==
Received: by 2002:a05:6871:284:b0:29f:f1cc:36ef with SMTP id
 586e51a60fabf-2b83e75f2c4ls671120fac.2.-pod-prod-03-us; Wed, 12 Feb 2025
 08:22:13 -0800 (PST)
X-Received: by 2002:a05:6808:13c8:b0:3eb:5ab2:5db2 with SMTP id 5614622812f47-3f3cdaaa70amr2863788b6e.37.1739377332950;
        Wed, 12 Feb 2025 08:22:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739377332; cv=none;
        d=google.com; s=arc-20240605;
        b=N1oVhxyea+8j6eEYEH9HBvfjOFgqhKzT1MsdQ+kA97Bp23zx+qy9pQdWphqpvm/jPG
         fhrwTlnWyYL+RVveG1vFIvkQAc3UnGKDOAQyT7ZmIwFZfmehQjVZaK6eQmHMSSYF4y8N
         1FdiL++vVcdpLN8YLVc4MJT05BoJEhC51LpFFv47oXswz3+UYw9beZdK4Mmojl/5SQ99
         gu6pMKmEdlWF42ISrFG+UQm4gL9fwr3S1R7eV5hzsgBPWvup48jIb9TLQ3gYh/+toEXt
         63xRwbpyJyDX+J26Ak6POmJD+FDNZlcluskYjmjd3rGpyN+be2yi9r34l/YvflmfnuEL
         RnAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=3mkeENwhXrVCnkP0vqjiIG1p6lDK9GeK7SyVkLKRxtQ=;
        fh=tILIASgG1SgYeARKVo/HeNKRyt6mMPxF3kkYIhMEYfg=;
        b=E9yDcKB4ULXIw4ULBgOb7IHl5fA90iUwKDkpVPZ6w4TfLl6w74DVj3qnpMckHideQR
         tzKzFmegcsWrV1A29wdLHTVDbo+up9ULY0vbSeICaCm7zGaV7pElIcPpME3f2iKGKYCM
         tbzHXo9hSDK7ACGY+WadC3910MgJ1fzKSZmT3GZeKw5Qa4hEI7qT0AjIwL2iYJl9glaj
         QnZ2l0AqYqMHO/TR18Df9qSEtKlKhbzDZRltIx/FIVTGEYKbTz7+za1WA4zlVajJA382
         DAlPIDG26ep98qEiizsUZvUS6I2zxdFkJoxfPsJvggKgXmTTDxGYIHE0kADrPooWTBky
         hTZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=d9GmcSLx;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3f389ead4ddsi637214b6e.1.2025.02.12.08.22.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2025 08:22:12 -0800 (PST)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-464-gENj6CbJMx6w85Nz5YcQ9Q-1; Wed,
 12 Feb 2025 11:22:07 -0500
X-MC-Unique: gENj6CbJMx6w85Nz5YcQ9Q-1
X-Mimecast-MFC-AGG-ID: gENj6CbJMx6w85Nz5YcQ9Q
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 68C7D1801A3A;
	Wed, 12 Feb 2025 16:22:05 +0000 (UTC)
Received: from llong-thinkpadp16vgen1.westford.csb (unknown [10.22.88.238])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id C78DB1800359;
	Wed, 12 Feb 2025 16:22:01 +0000 (UTC)
From: Waiman Long <longman@redhat.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Clark Williams <clrkwllms@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	linux-rt-devel@lists.linux.dev,
	Nico Pache <npache@redhat.com>,
	Waiman Long <longman@redhat.com>
Subject: [PATCH v2] kasan: Don't call find_vm_area() in RT kernel
Date: Wed, 12 Feb 2025 11:21:51 -0500
Message-ID: <20250212162151.1599059-1-longman@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=d9GmcSLx;
       spf=pass (google.com: domain of longman@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

The following bug report appeared with a test run in a RT debug kernel.

[ 3359.353842] BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48
[ 3359.353848] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 140605, name: kunit_try_catch
[ 3359.353853] preempt_count: 1, expected: 0
  :
[ 3359.353933] Call trace:
  :
[ 3359.353955]  rt_spin_lock+0x70/0x140
[ 3359.353959]  find_vmap_area+0x84/0x168
[ 3359.353963]  find_vm_area+0x1c/0x50
[ 3359.353966]  print_address_description.constprop.0+0x2a0/0x320
[ 3359.353972]  print_report+0x108/0x1f8
[ 3359.353976]  kasan_report+0x90/0xc8
[ 3359.353980]  __asan_load1+0x60/0x70

Commit e30a0361b851 ("kasan: make report_lock a raw spinlock")
changes report_lock to a raw_spinlock_t to avoid a similar RT problem.
The print_address_description() function is called with report_lock
acquired and interrupt disabled.  However, the find_vm_area() function
still needs to acquire a spinlock_t which becomes a sleeping lock in
the RT kernel. IOW, we can't call find_vm_area() in a RT kernel and
changing report_lock to a raw_spinlock_t is not enough to completely
solve this RT kernel problem.

Fix this bug report by skipping the find_vm_area() call in this case
and just print out the address as is.

For !RT kernel, follow the example set in commit 0cce06ba859a
("debugobjects,locking: Annotate debug_object_fill_pool() wait type
violation") and use DEFINE_WAIT_OVERRIDE_MAP() to avoid a spinlock_t
inside raw_spinlock_t warning.

Fixes: e30a0361b851 ("kasan: make report_lock a raw spinlock")
Signed-off-by: Waiman Long <longman@redhat.com>
---
 mm/kasan/report.c | 47 ++++++++++++++++++++++++++++++++++-------------
 1 file changed, 34 insertions(+), 13 deletions(-)

 [v2] Encapsulate the change into a new
      kasan_print_vmalloc_info_ret_page() helper

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 3fe77a360f1c..9580ac3f3203 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -370,6 +370,38 @@ static inline bool init_task_stack_addr(const void *addr)
 			sizeof(init_thread_union.stack));
 }
 
+/*
+ * RT kernel cannot call find_vm_area() in atomic context. For !RT kernel,
+ * prevent spinlock_t inside raw_spinlock_t warning by raising wait-type
+ * to WAIT_SLEEP.
+ *
+ * Return: page pointer or NULL
+ */
+static inline struct page *kasan_print_vmalloc_info_ret_page(void *addr)
+{
+	if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
+		static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
+		struct page *page = NULL;
+		struct vm_struct *va;
+
+		lock_map_acquire_try(&vmalloc_map);
+		va = find_vm_area(addr);
+		if (va) {
+			pr_err("The buggy address belongs to the virtual mapping at\n"
+			       " [%px, %px) created by:\n"
+			       " %pS\n",
+			       va->addr, va->addr + va->size, va->caller);
+			pr_err("\n");
+
+			page = vmalloc_to_page(addr);
+		}
+		lock_map_release(&vmalloc_map);
+		return page;
+	}
+	pr_err("The buggy address %px belongs to a vmalloc virtual mapping\n", addr);
+	return NULL;
+}
+
 static void print_address_description(void *addr, u8 tag,
 				      struct kasan_report_info *info)
 {
@@ -398,19 +430,8 @@ static void print_address_description(void *addr, u8 tag,
 		pr_err("\n");
 	}
 
-	if (is_vmalloc_addr(addr)) {
-		struct vm_struct *va = find_vm_area(addr);
-
-		if (va) {
-			pr_err("The buggy address belongs to the virtual mapping at\n"
-			       " [%px, %px) created by:\n"
-			       " %pS\n",
-			       va->addr, va->addr + va->size, va->caller);
-			pr_err("\n");
-
-			page = vmalloc_to_page(addr);
-		}
-	}
+	if (is_vmalloc_addr(addr))
+		page = kasan_print_vmalloc_info_ret_page(addr);
 
 	if (page) {
 		pr_err("The buggy address belongs to the physical page:\n");
-- 
2.48.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250212162151.1599059-1-longman%40redhat.com.
