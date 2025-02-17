Return-Path: <kasan-dev+bncBCPILY4NUAFBBRXSZK6QMGQEVTV4OSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id B5CF0A37A69
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 05:21:28 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-220ec5c16e9sf55776605ad.1
        for <lists+kasan-dev@lfdr.de>; Sun, 16 Feb 2025 20:21:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739766087; cv=pass;
        d=google.com; s=arc-20240605;
        b=B4qG5ckNzohx0DE9mOCbWyhLHsG2BAaR+3FTecgX+KfB+izU6jWFBxnOxGW3TJ9S9u
         SPdWZR1XZfs/+ypaEdXQ+ppaV1e18pSo3bVuaXCqegu/vQdQiA0PRn6Z78rZ2GqRTj2D
         0Tb3UOfwjKcU5y09sPR+hCFUJUAMuzY/3WqdonGck6MDSodYkzmJIMKDIVfL621J8fXG
         RdFgUf2BlzjXpR+pjBYca31O6s9/KGlMAJynaH7eFua7CO7HfJvvXI8LyFwa9TYXgv4Z
         1bWRgKymBKDnwvUherCDMjWcKQlxfi/soo4z8v7vdt3bqObD2GdmIT1HgN3Zg2d4pNXy
         rZ+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=TLFK8wXTzbWB7ADSJ0Je358lMAw03071ziQUnVQKufU=;
        fh=HNnM0M0943ToTztWI6XAXaaaXC+0kCn424TCxO71pxo=;
        b=hgP8lKvrHA09zSbNoSU/ErO2rXsamm7x3IWmqzdAikIlMCiBkQDUI+HfKiVm1befc5
         uoMJZ+h+BTDxg/D5eCUdareVch6mD3hbrj8wRxdmNZW34epCWcIjTgMwDdT52GSphrMN
         nABnZo4ZoJuT50EBS1nXOjNVZtzcGWhu+202WF2W6v4bSwgMKqCWPVV6bKK+7fGhQJIV
         mR6KVTFyAI0qYhhNK0Ss7BGiheSFzbYbhzHngl69jpPvimEPTU90kjtL+xRSwruPbJ9Z
         32Ul1bCMXe8G4jpNd2Q1qZEDr0IElhUj6rs8cllGz+KXZMA0ozwbl80MglYqNP+h4au/
         0ULQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Npj71b4t;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739766087; x=1740370887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TLFK8wXTzbWB7ADSJ0Je358lMAw03071ziQUnVQKufU=;
        b=CKBAUldSLHa4Dtbq2/t0rpj7BrWhq9R6P7rX8QNJj3qHcs72jYCzWNAUJrwMn58q3x
         qEKVXVxaD5++CrbIyhehRtmBTls+DIZXEhuH1zPIwzgnBnO7gd3zPptlXihgArqLasD/
         YqzSV8R2TOzsO0okMVlYUufwYGoe3sDFRo5I+WlI5q7+WVs6Xg2x+luXAYtqqPIs6pHo
         yF83axqrcxowSc2NnWWic4rlU/R55+/HeAXw/r1kzlwlCmpd9zDEpCoHoCaCKF+M8rbc
         mczEzKO55T2GGWHM2P3Uc6WAQpg614FTtrPMq793Vqqts+tCviz9RaBsiOBULSk3fZ7O
         ZDKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739766087; x=1740370887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TLFK8wXTzbWB7ADSJ0Je358lMAw03071ziQUnVQKufU=;
        b=X6VaEIS1mGqmlW+kniezKf0yWyKB6AQ8fcK+9qtcYRwA2IPwFSo1HAROlahO7F6akS
         jk34DKVcXhdH0JqBLDq4OXWruJQbvU6QKx8c8lJI4DPKcOdKO96ydrpsLieiWlGic14l
         9n3g7HCNfNJTxyXAMNanPY+ozp5Sc2OnYNn7Zmvq6F05gEkmaJh6mvHCEG1Y1JsX1gyt
         6lv5Pb9B28hX+voyH571gLs25jTTfUGTAzUAnTPAZs/HJe7BsC4/B90MXxUNbkXiVg5d
         wumL6h1TI/6b572N9njcJQB/ApHcJYPfR3dL0X/5i97uuAr9hoG5F10XtlJ0HhYAPN/N
         Lj6A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZ1aJI5KD9oaSLPjQR6T+ze7XbjRJWeASo1ZrwwPyqwehyowIByfms4NW1PsKCrntz4h4FXQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx3tBX4zBGLsThfNhBxqhPfsa5dvnKRQ4fI4eMzmGlJj/BsKbiJ
	4Ljdn7YWSlBLKzMmg3CEd6kUssgoQObMVEJCnRDKoiumd9DXxYQh
X-Google-Smtp-Source: AGHT+IG7E1FPbImlifMkSAs+tXWGQSe7DmuVE3fya32UWgvhu+Yb81cu0t9U4uSQ+QjuZRprG7N83Q==
X-Received: by 2002:a17:902:d4c1:b0:21f:4b63:d5c3 with SMTP id d9443c01a7336-22103f13ac9mr138020565ad.12.1739766087067;
        Sun, 16 Feb 2025 20:21:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFS3JDXSqAK2ZzdCLUkkr64rGbUbbpmY3Quarh2E8pMDA==
Received: by 2002:a17:90a:d18a:b0:2ef:9dbc:38e5 with SMTP id
 98e67ed59e1d1-2fc0d57c4fals2451716a91.0.-pod-prod-02-us; Sun, 16 Feb 2025
 20:21:26 -0800 (PST)
X-Received: by 2002:a17:90b:17c1:b0:2f5:88bb:118 with SMTP id 98e67ed59e1d1-2fc41044ffemr10480377a91.22.1739766085796;
        Sun, 16 Feb 2025 20:21:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739766085; cv=none;
        d=google.com; s=arc-20240605;
        b=fLsG/ySjdaF/BMkU6vV7O0O6p/krxXo73T/rCq9WN74YdAmcSGGocdVQnGl7MzSubm
         HoKqETCk1ZmudQ6J0nr4lVRSXfYdiqu5C2VemugM3YG5BrWvnB0T+ZRF6vn5bBAz+bKZ
         ATnMbzapV3KbT7bpwfkB7gpLnBW36sudziPdRKOr/4uJg1skXsItGL0H71E56nVtrAFv
         N7XuEb66Q8Bq13d13Zfht///iUA0fuxHuQldk0gYHVSzA/WUBLNSH1csOGJhC9StjoDj
         QoaXpgulcNKxrtygg/tTdO3jArlin7oitErLLjvgzrtyuCfdMnNiMg/gq5uuRn3elpew
         uSlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=YqbMpBl1Nw5n1bOPGE94JMKO6OVu4WYCnIOo4Qkr9yc=;
        fh=tILIASgG1SgYeARKVo/HeNKRyt6mMPxF3kkYIhMEYfg=;
        b=VbgpDt185L1hlAoYCLtuukkwQaObMOKtwE9+JwaAw91Bq3auX/f7PTEPVTxJkSGwF7
         Vg8e06P3ggZn+E7wGl2Jhe6QoQCQ6joLhT3EJg1DZAQIquh1jKXjAlqMUfKaP87aJO0g
         Wt7s3knvLwPIMm/ZAiihjEWf02o6HR5FcfoPnqUaN5YEYaRdVN9eLovTtarhPz0CXjiy
         veThyJukTGqS73BMTK0N/HOmXd1/IpLXBVU0xGkO0dLZV3jHUEyXhudBeuSJt7PZjYzJ
         tVdMduENJBpkJVLfkBi2NO/HretV6Iyi00ePsqBjwrlI78JblvTDZOsJr2jBNRGk5BPR
         bekQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Npj71b4t;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-220d531acd1si3421305ad.1.2025.02.16.20.21.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 16 Feb 2025 20:21:25 -0800 (PST)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-59-72Bo0qNkMOOtvPEmGFO3cg-1; Sun,
 16 Feb 2025 23:21:21 -0500
X-MC-Unique: 72Bo0qNkMOOtvPEmGFO3cg-1
X-Mimecast-MFC-AGG-ID: 72Bo0qNkMOOtvPEmGFO3cg_1739766080
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 2541D1800875;
	Mon, 17 Feb 2025 04:21:19 +0000 (UTC)
Received: from llong-thinkpadp16vgen1.westford.csb (unknown [10.22.64.83])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 31E31300018D;
	Mon, 17 Feb 2025 04:21:15 +0000 (UTC)
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
Subject: [PATCH v3] kasan: Don't call find_vm_area() in RT kernel
Date: Sun, 16 Feb 2025 23:21:08 -0500
Message-ID: <20250217042108.185932-1-longman@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Npj71b4t;
       spf=pass (google.com: domain of longman@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
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
 mm/kasan/report.c | 43 ++++++++++++++++++++++++++++++-------------
 1 file changed, 30 insertions(+), 13 deletions(-)

 [v3] Rename helper to print_vmalloc_info_set_page.

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 3fe77a360f1c..7c8c2e173aa4 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -370,6 +370,34 @@ static inline bool init_task_stack_addr(const void *addr)
 			sizeof(init_thread_union.stack));
 }
 
+/*
+ * RT kernel cannot call find_vm_area() in atomic context. For !RT kernel,
+ * prevent spinlock_t inside raw_spinlock_t warning by raising wait-type
+ * to WAIT_SLEEP.
+ */
+static inline void print_vmalloc_info_set_page(void *addr, struct page **ppage)
+{
+	if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
+		static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
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
+			*ppage = vmalloc_to_page(addr);
+		}
+		lock_map_release(&vmalloc_map);
+		return;
+	}
+	pr_err("The buggy address %px belongs to a vmalloc virtual mapping\n", addr);
+}
+
 static void print_address_description(void *addr, u8 tag,
 				      struct kasan_report_info *info)
 {
@@ -398,19 +426,8 @@ static void print_address_description(void *addr, u8 tag,
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
+		print_vmalloc_info_set_page(addr, &page);
 
 	if (page) {
 		pr_err("The buggy address belongs to the physical page:\n");
-- 
2.48.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250217042108.185932-1-longman%40redhat.com.
