Return-Path: <kasan-dev+bncBCPILY4NUAFBBKF7Z26QMGQEP26NTNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id A6CA4A38D9C
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 21:44:26 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2fc4fc93262sf4242837a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 12:44:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739825065; cv=pass;
        d=google.com; s=arc-20240605;
        b=X40ET1/s+VwQ4GqmeSMDBLCDk3mpL1uA3Qsa8qrMk3ZIdXn1LOYT3eQ7NXfQrwAguU
         Hl2kEhMqZBALpb4So6RsYele32eGs12cVSrwMEfWZ8ALUt+AzVNXM5IPn1evAxFaVQTU
         kLo7sbpMEjye0OwAOh9aumS75LzZnnL9WQrIeTrfQZAGKhWSpGcC+/DTB72nWfA95RJ/
         u/jIOxvUmj+aoq5O2UZHIp8L/DVwvWih11Ty97ypJBQY9ez6ga3jeN2zQZy8GhCclReA
         qO15hjg7VaiGj6CKKHWpyGJ5wxzWmR8lzDTnL2rVk8LC7cQmnOacuvCuCvlUt8q8sxPT
         fGQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=tF9vUwtqVSRp2c1nBWNxDFqsHgvfIU8iMvdKo/50sPU=;
        fh=BkoL/92L9KggZrclOHBo+LN5g5h1OlL1Pl1zwdlrl1c=;
        b=c+UQ2ssfMHl4DL7FVpbDDa1n1zFcXsMQGsm0YmAmmx7jv7K+rjZ4/xjWrAe4V4gKxC
         S9y9Nss7iJlLraMCRz3+72tOiDngQ/dnspCczibvm5/po0/ntlj25p62RZCdFj5b8JD4
         nwCVIdUfRkFnwhKo+PAecPYPVh912JHMP8aB8NAHr0Q/15B9uIsFQuZGslIeftvaL8nC
         B8QgyPVyo4yMEkSH56A2CAcOThq6QfBsy+vDwT4XfWfVPG2uw5n6e4hIHQoB/y+cos7Y
         Y/ALauLA3npTb9ygvsrBkqFwsJAd60pBT9uN3tl+jTcqUrIeZ2YBQz/VNFYgKecyClgf
         KQeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=OvFtJShs;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739825065; x=1740429865; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tF9vUwtqVSRp2c1nBWNxDFqsHgvfIU8iMvdKo/50sPU=;
        b=F0DdHXl4gGxsCPHDMqdMgD7cG/jeQzDyO35cynw+Ufm7cm1umSzw8DLR8fwfhgB0z5
         4diyYdSnY87S/ZQR/4mlxTQSeyrjkEdbIFkf1gb9wNI7rzbi1Unuo4O+u3nO1sN7QhWP
         Uajb46F2EfB/Y0I3r+GVZ41F03LebT6jzOtjwq9TrSzT3lDotj4V/y8CWHPTupZexqeA
         ZT3Bv5VMtlTPUCUfTIH4+wnEplUQ2phus61RYqejRAQ6ogOmejb4lwp1q+t0317ZmSMw
         qHBz5+TP8NXmVkOu0JOzJvL+ZCqu8KlNsTcF8P/9r1y2HmO3OA0m25uXvpGj0Y6d4mw5
         CMsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739825065; x=1740429865;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tF9vUwtqVSRp2c1nBWNxDFqsHgvfIU8iMvdKo/50sPU=;
        b=QjJjtCu5359P3lgFE4NV2ho8KrHIW7POMwiRvsVNujaIqyx2S/bVUKET4I52jqEhNr
         gANRpfq/yvMx9PUeE+r0iJVADFOfROFO+YBqPwJNG/vfShxhRFFqw/nnACMd09BPmqhq
         znx+esSWyILa8qZPhT4bIFoYPQ6Kfgh8CJPqTfsB6+AdsCF2eDf4GJbhCtv3C1bxphm5
         i1NW2CmZUdmArsib3Qs82XhitMOcDqkT0pEBHuXmrONRWnQHBJQuW1kibcJv/SI0G6Gz
         g8Qsm29L5eQQx3TpdnMxBSIWPwznFTSxvjVgjW4GCbQn5MeE07oLYj+orH4ZJ5mTxgdQ
         ajcA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXxmPuCwNXGcKZ4/j3Kr0UTA52j/mVj2UDmUIYtGEdY7FAJVf406HXZBf9U/FNKnx9FZQrQWg==@lfdr.de
X-Gm-Message-State: AOJu0YyigcJjz/VE196SH6//LJyr6t4D8Ghpne1Pgq5keXu2vSSDk5wy
	nwc6ew8WFNZorsn1Ur/n2tnRBbT/MGi1+dQvGMPPpKXN4ksXvv8+
X-Google-Smtp-Source: AGHT+IGqv0gEsTIjzFR7TR4QAlDHH7fCqNMuz7JK4riv3gYnTbMBRhMV7Uz5ZZNprsyYYuhgNIpGdA==
X-Received: by 2002:a17:90b:350a:b0:2f8:b2c:5ef3 with SMTP id 98e67ed59e1d1-2fc40f10ec8mr19546670a91.14.1739825065209;
        Mon, 17 Feb 2025 12:44:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGDT2agR1uenf93ZiUZb8VWGOADdF4zJVXeg5u0NgSGbQ==
Received: by 2002:a17:90b:3656:b0:2f8:3555:13c3 with SMTP id
 98e67ed59e1d1-2fc0d759b5cls656191a91.2.-pod-prod-09-us; Mon, 17 Feb 2025
 12:44:24 -0800 (PST)
X-Received: by 2002:a17:90b:1b4b:b0:2ee:b2fe:eeeb with SMTP id 98e67ed59e1d1-2fc4104505emr14293154a91.22.1739825063897;
        Mon, 17 Feb 2025 12:44:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739825063; cv=none;
        d=google.com; s=arc-20240605;
        b=Tl8lAPbIKbETzu3zQ2zTwfdBSfJz/YSPbyNlcOnhA/Rv/uYVghWXzPzznIyuaFY8UT
         nkcxqvQ8M8JK8hkhv1NWvJu8/7R1b55cdD9AM5OnvAaEDVLL4+/+xgTX6S/kzkH7IThk
         +Nh9oIGnPBg88PoO1MXZfVfMZV7HVex3MEWDUJvxR+C+3hEw61ygCZAIUcAV4cH9ionC
         NPtHaEfJuW3BrJTJKG1w4srXoEo7jtFeEQ8X2T5fyJDNgjK6/BnziV8wvw6iet0W7otv
         uTy9KspY1J/fslEGf/fHB8EX7iIAr1oDfI0N8hqlQ0c8X1xGDkVIRH/y2BTL6HYk6xkt
         XH6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=2QmrLCQEQpkTfPHbNiLQH+djwRd+v9Lt5IkB8rbHV3Y=;
        fh=tILIASgG1SgYeARKVo/HeNKRyt6mMPxF3kkYIhMEYfg=;
        b=E5GZs6qeCWUUwcDoF5Vbdp1DiDU3MxBUcdjewMBLjjmQaiBCIrlQv0+E7WS+A7NOxb
         c0CRIuq7AsjYQNi/Tv6VEmJpVGelpgjRl3cUZS/R82ooUkfgVGfijduXFtMzSO1QPYPj
         ED7ogSGpHUIMJfqtjqNxCYyjVwJ5k7XfRk41tqNhqLbrfoj9lM8h5LAVySd2TVeEfHuM
         jNjqQeKdYNrQQru6WkKvKZc6U1arUPYkPyM1lB9l7iSae0+L0gORvfxW59nsN9G3M6Si
         QivosEEAj+zepDgO5p1lLYQFyzNtMpYUYtNtxC9Q9UgCUQ6ORWZFpCVJvwk4goZImqrp
         zJEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=OvFtJShs;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-220d542d60asi4106675ad.11.2025.02.17.12.44.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Feb 2025 12:44:23 -0800 (PST)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-76-yUKzqEUaPyaxt_hlM-890A-1; Mon,
 17 Feb 2025 15:44:17 -0500
X-MC-Unique: yUKzqEUaPyaxt_hlM-890A-1
X-Mimecast-MFC-AGG-ID: yUKzqEUaPyaxt_hlM-890A_1739825055
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 05AF618EB2C3;
	Mon, 17 Feb 2025 20:44:15 +0000 (UTC)
Received: from llong-thinkpadp16vgen1.westford.csb (unknown [10.22.80.243])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id C115B1800362;
	Mon, 17 Feb 2025 20:44:11 +0000 (UTC)
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
Subject: [PATCH v4] kasan: Don't call find_vm_area() in a PREEMPT_RT kernel
Date: Mon, 17 Feb 2025 15:44:02 -0500
Message-ID: <20250217204402.60533-1-longman@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=OvFtJShs;
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

The following bug report was found when running a PREEMPT_RT debug kernel.

 BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48
 in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 140605, name: kunit_try_catch
 preempt_count: 1, expected: 0

 Call trace:
  rt_spin_lock+0x70/0x140
  find_vmap_area+0x84/0x168
  find_vm_area+0x1c/0x50
  print_address_description.constprop.0+0x2a0/0x320
  print_report+0x108/0x1f8
  kasan_report+0x90/0xc8

Since commit e30a0361b851 ("kasan: make report_lock a raw spinlock"),
report_lock was changed to raw_spinlock_t to fix another similar
PREEMPT_RT problem. That alone isn't enough to cover other corner cases.

print_address_description() is always invoked under the
report_lock. The context under this lock is always atomic even on
PREEMPT_RT. find_vm_area() acquires vmap_node::busy.lock which is a
spinlock_t, becoming a sleeping lock on PREEMPT_RT and must not be
acquired in atomic context.

Don't invoke find_vm_area() on PREEMPT_RT and just print the address.
Non-PREEMPT_RT builds remain unchanged. Add a DEFINE_WAIT_OVERRIDE_MAP()
macro to tell lockdep that this lock nesting is allowed because the
PREEMPT_RT part (which is invalid) has been taken care of. This macro
was first introduced in commit 0cce06ba859a ("debugobjects,locking:
Annotate debug_object_fill_pool() wait type violation").

Fixes: e30a0361b851 ("kasan: make report_lock a raw spinlock")
Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Waiman Long <longman@redhat.com>
---
 mm/kasan/report.c | 34 +++++++++++++++++++++++++++++++++-
 1 file changed, 33 insertions(+), 1 deletion(-)

 [v4] Use Andrey's suggestion of a kasan_find_vm_area() helper and
 update comment and commit log as suggested by Andrey and Sebastian.

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 3fe77a360f1c..8357e1a33699 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -370,6 +370,36 @@ static inline bool init_task_stack_addr(const void *addr)
 			sizeof(init_thread_union.stack));
 }
 
+/*
+ * This function is invoked with report_lock (a raw_spinlock) held. A
+ * PREEMPT_RT kernel cannot call find_vm_area() as it will acquire a sleeping
+ * rt_spinlock.
+ *
+ * For !RT kernel, the PROVE_RAW_LOCK_NESTING config option will print a
+ * lockdep warning for this raw_spinlock -> spinlock dependency. This config
+ * option is enabled by default to ensure better test coverage to expose this
+ * kind of RT kernel problem. This lockdep splat, however, can be suppressed
+ * by using DEFINE_WAIT_OVERRIDE_MAP() if it serves a useful purpose and the
+ * invalid PREEMPT_RT case has been taken care of.
+ */
+static inline struct vm_struct *kasan_find_vm_area(void *addr)
+{
+	static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
+	struct vm_struct *va;
+
+	if (IS_ENABLED(CONFIG_PREEMPT_RT))
+		return NULL;
+
+	/*
+	 * Suppress lockdep warning and fetch vmalloc area of the
+	 * offending address.
+	 */
+	lock_map_acquire_try(&vmalloc_map);
+	va = find_vm_area(addr);
+	lock_map_release(&vmalloc_map);
+	return va;
+}
+
 static void print_address_description(void *addr, u8 tag,
 				      struct kasan_report_info *info)
 {
@@ -399,7 +429,7 @@ static void print_address_description(void *addr, u8 tag,
 	}
 
 	if (is_vmalloc_addr(addr)) {
-		struct vm_struct *va = find_vm_area(addr);
+		struct vm_struct *va = kasan_find_vm_area(addr);
 
 		if (va) {
 			pr_err("The buggy address belongs to the virtual mapping at\n"
@@ -409,6 +439,8 @@ static void print_address_description(void *addr, u8 tag,
 			pr_err("\n");
 
 			page = vmalloc_to_page(addr);
+		} else {
+			pr_err("The buggy address %px belongs to a vmalloc virtual mapping\n", addr);
 		}
 	}
 
-- 
2.48.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250217204402.60533-1-longman%40redhat.com.
