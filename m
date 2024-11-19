Return-Path: <kasan-dev+bncBDNZPCPEZ4LRBAP26O4QMGQE3XBKNVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 46BEA9D2FD9
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2024 22:03:02 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2e9b2437b19sf5616481a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2024 13:03:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732050178; cv=pass;
        d=google.com; s=arc-20240605;
        b=YjV7mbnCXAG3PlXHhyx9e8YKcXe9i/cyiHocGYxwy1fbrhOb3CJTvH9ELAbaZ5H8VK
         9MRUkSh8ohc00Y3aUf8kP0lz6VmAviMrTxlNCxf4xxL3WHl3IkP6LNli6czDUMqQitr/
         FcLqBQw4QuvF4OjQJlNd+R+PSvxJN7c1ZVMs32xCtZoO/E7eMH3uEDQkrdKb8Be2h5Dl
         lVLODrJhTCV+RdpPaVXM63b+Vk4i0acduGD4PiXxnGMmjyg2moWcy4QU1sqSeh/VYNDR
         +AlZsKYuqMWi2tTWOYMtJ+1o4NMiY84bKDQutm/giCiE4HlpOFhAQnmS3WWJ/qR9fgfq
         UAJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=YAPsX5ZtUO3r3J9eOK5nKvd2uZjyK6MQmBEiSBxeptQ=;
        fh=OfDuh+ww/vy6cKJL6lxSsMBaYsQqbU5PHauQxJ8xRrw=;
        b=UjeyYG5Uo1gIYWhHrUG7nnOHwTVr2AOKQWRMUpK26epYREC4tdW5G2Zl+4ZJ5azEqy
         O/yM6jjNX7y1EeWCCeuywearEdA6g/ep0MYgt7A1YkxWdKOVAtOBZxr49ht4FyiA9+J9
         +hCwKkXUhlVt5m63tptSbudccMgnYg3x4ZtrYoq7be0KhGnmmoXMPMzLZTNRkR1UKdKj
         xYM1p5H6q5sotyxcGUopxpFwY9q3nAvc3Ta5MgafbUmFZTqmEQFkeQdDb38SsMI7mOJA
         PrhC7KDsSNBUzl9uCmT1HAJh3L+2EWUyZd0n0uSxLdWd738iGr1QQdlskIUmMpEdzjW4
         pEmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fllQS6h7;
       spf=pass (google.com: domain of jkangas@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jkangas@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732050178; x=1732654978; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YAPsX5ZtUO3r3J9eOK5nKvd2uZjyK6MQmBEiSBxeptQ=;
        b=Snt15PFGgNKFf5GdxRH0WDoToSQJaJmgK2QUqlRNpQ66UH9h63cMz/jtFRGmAn2qa0
         /L3bIQxTYXzpoZtmTgQva6qY3Rv4361fXYw1WkzXHX9NSidsv74z+aOX4EZEjvcrWQ9O
         VZfm/Y4PLYinBy9i4+9OyCxiCQ2k0z90G+APYgTV0wXE8pG/K4rddTWz7SDSn4sBAWFe
         SZouPqnfviOwn3Sv/u2+Qbv3+cg1L/dpjjpelDcJemvom/51AM0L1LQi5MVGa6GolydI
         bjQm35PynMGzX6rB3PmWUBjiLwbXTXMnzEXS7iob8XK2S03ophTFd+TY0khK1aOjpqPS
         Inmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732050178; x=1732654978;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YAPsX5ZtUO3r3J9eOK5nKvd2uZjyK6MQmBEiSBxeptQ=;
        b=nj648mZ9jFIecxEWSY+PcsYIIJPyEB/h4Dv9WYC7cGnGSXhb0gTE2ndX2dmFnbWK6J
         oI+eCKP6IMbDI1JDVlETS/vOc7LR95bjVpHzhBmXBpcZi6K3FBV5kEJX02wXei7a0gKd
         7fw1ZVAAzcgIunaSqNBXXJjUXs5Hcrn7iN+dlsj0YOI0qhERiJqwiJmyfqYlDynoU11C
         HO/sgkUOb6DU7lkinW3yW9KpjR3sJ6v0Y7opbKrQZMxBcJmfdzgvLjWqG1HAcmidZB8B
         iw9bxIhLcxU0jyHXL1T8DV+0Ibskr0+HNLhNjnXbyWkbtRlwgx4WTZ1SGU7iL3600W6C
         m9Aw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV2L1Zic/wWZTdhOMqbi/J3z5RCgSKiu6KXKR0M9iu5aOtXvbzOIqfpogh371FlHjrb6v+1Tg==@lfdr.de
X-Gm-Message-State: AOJu0Yw5DoYTc1+wy6Xq8dq3dL+x6aPopW24SapDIUDqQwRNSNJW9mQR
	AOzj4NrtSZ0MR8h9VPsDQg/nypuEzjVO8X4khoZW9gCbZv7E7UN2
X-Google-Smtp-Source: AGHT+IHr+McUqKSXZXOTrGm/cOc4RiixnPl5PJalD7rzv+kADLLh52lFg9y56J2Nhr4lOj30d1t/JA==
X-Received: by 2002:a17:90a:d40e:b0:2ea:4e67:5646 with SMTP id 98e67ed59e1d1-2eaca7c8917mr234758a91.24.1732050177738;
        Tue, 19 Nov 2024 13:02:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d814:b0:2ea:5087:39b3 with SMTP id
 98e67ed59e1d1-2ea50873e9fls2370667a91.2.-pod-prod-03-us; Tue, 19 Nov 2024
 13:02:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXm+ec6F4JthtG/q768pqBP+lD9dS6MHQED3Shk+RGtTW+LAGiavHRM6qNwEVnkartZyRJAHJdPAIU=@googlegroups.com
X-Received: by 2002:a17:90b:3945:b0:2ea:4150:3f80 with SMTP id 98e67ed59e1d1-2eaca733265mr209724a91.18.1732050176452;
        Tue, 19 Nov 2024 13:02:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732050176; cv=none;
        d=google.com; s=arc-20240605;
        b=KHl1SnQvtbWzYBbB4XhwDOlY8ALbtMr95nluN2DNIDQyW4LvK0m8fnBlITVacBzG5I
         kAhsUPoUkL2Q8v0dORH1pCQ5kKGdo+TpncCYFasDW15NDSpMzaZBGf/zqQJ/G2rZpuHJ
         YjDGmNF7Q54Zd/rW0J7Sn61VosCCVI2628gI2Fr7cauE97BgIW8xo7s0Vc9uy34vS00M
         Jq0CfWV9U8siFLpmTwlKGinbcelb+p9F8xdNxOphbUrTh8mA86tCoIgv6T1cU/+bE6Hf
         Ces3/p3dfwkdIJ6jqOqZbvabwgfDUCTvf4XvbP3gd573q4mexyG7uuWsPyJ+fRSRMIM5
         zhCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=t3TBOVGPHnMk/PpScx+zP3qwXBcwdGmVH4QE3u2wmIw=;
        fh=+g4TGh6Z+lajqEtz7Exek2qp57nSQlNuvLxO8c9pDp4=;
        b=Y6rXmw7XmKauQ4LZjS+eEcOHWtXOWoUVLK8hupsR0Ve8qnVhAaYOnKuBmH3VtTJxLI
         zp3mlGf2Licd0IZG/PxJ3QL5p5lPLpSQyiDzkMW65ntTgnXED91FZxGTUaWIhosbErrG
         1l3pQfXz+gFPxcNn7XzHVmcrRSqb0wdrKVutilOpYYm82CwDfBgVNPC7iK6NNO0xuBds
         GnfGLQOxljKWQ3WSibpi8cbbMj+LDMbFtdgO4gk3O0W9MGfsfIT6qyixpdq3klpsyqZk
         i6NK/0WzBwnk47JfZH58WepPbONFg+S/ZZNCT9T0x2XiLZTkKRKKQzyUPVkcLgUQpf2R
         RLwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fllQS6h7;
       spf=pass (google.com: domain of jkangas@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jkangas@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2ea024be90esi825656a91.2.2024.11.19.13.02.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2024 13:02:56 -0800 (PST)
Received-SPF: pass (google.com: domain of jkangas@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-il1-f199.google.com (mail-il1-f199.google.com
 [209.85.166.199]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-140-iWGzlWUnOUSWrZpsZtbfEA-1; Tue, 19 Nov 2024 16:02:53 -0500
X-MC-Unique: iWGzlWUnOUSWrZpsZtbfEA-1
X-Mimecast-MFC-AGG-ID: iWGzlWUnOUSWrZpsZtbfEA
Received: by mail-il1-f199.google.com with SMTP id e9e14a558f8ab-3a768b62268so29133905ab.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2024 13:02:53 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV91ce7Ue+AaqfJxbzhMyt8lP+/uq0bmwVdKwNjrCGSqRsRWvT6e1viXh9//IXVytVQcQQnLtGm/zU=@googlegroups.com
X-Received: by 2002:a05:6e02:2163:b0:3a7:7dc9:a4b0 with SMTP id e9e14a558f8ab-3a786457e63mr2505495ab.9.1732050172828;
        Tue, 19 Nov 2024 13:02:52 -0800 (PST)
X-Received: by 2002:a05:6e02:2163:b0:3a7:7dc9:a4b0 with SMTP id e9e14a558f8ab-3a786457e63mr2505235ab.9.1732050172398;
        Tue, 19 Nov 2024 13:02:52 -0800 (PST)
Received: from jkangas-thinkpadp1gen3.rmtuswa.csb ([2601:1c2:4301:5e20:98fe:4ecb:4f14:576b])
        by smtp.gmail.com with ESMTPSA id 8926c6da1cb9f-4e0756b0e35sm2987964173.108.2024.11.19.13.02.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2024 13:02:51 -0800 (PST)
From: Jared Kangas <jkangas@redhat.com>
To: ryabinin.a.a@gmail.com
Cc: glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Jared Kangas <jkangas@redhat.com>
Subject: [PATCH] kasan: make report_lock a raw spinlock
Date: Tue, 19 Nov 2024 13:02:34 -0800
Message-ID: <20241119210234.1602529-1-jkangas@redhat.com>
X-Mailer: git-send-email 2.47.0
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: 6eRTphCWFKNlC3Z6bhnfnpjR_N3H5kKH0lig3gbCX-E_1732050173
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: jkangas@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fllQS6h7;
       spf=pass (google.com: domain of jkangas@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=jkangas@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

If PREEMPT_RT is enabled, report_lock is a sleeping spinlock and must
not be locked when IRQs are disabled. However, KASAN reports may be
triggered in such contexts. For example:

        char *s = kzalloc(1, GFP_KERNEL);
        kfree(s);
        local_irq_disable();
        char c = *s;  /* KASAN report here leads to spin_lock() */
        local_irq_enable();

Make report_spinlock a raw spinlock to prevent rescheduling when
PREEMPT_RT is enabled.

Signed-off-by: Jared Kangas <jkangas@redhat.com>
---
 mm/kasan/report.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index b48c768acc84..c7c0083203cb 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -200,7 +200,7 @@ static inline void fail_non_kasan_kunit_test(void) { }
 
 #endif /* CONFIG_KUNIT */
 
-static DEFINE_SPINLOCK(report_lock);
+static DEFINE_RAW_SPINLOCK(report_lock);
 
 static void start_report(unsigned long *flags, bool sync)
 {
@@ -211,7 +211,7 @@ static void start_report(unsigned long *flags, bool sync)
 	lockdep_off();
 	/* Make sure we don't end up in loop. */
 	report_suppress_start();
-	spin_lock_irqsave(&report_lock, *flags);
+	raw_spin_lock_irqsave(&report_lock, *flags);
 	pr_err("==================================================================\n");
 }
 
@@ -221,7 +221,7 @@ static void end_report(unsigned long *flags, const void *addr, bool is_write)
 		trace_error_report_end(ERROR_DETECTOR_KASAN,
 				       (unsigned long)addr);
 	pr_err("==================================================================\n");
-	spin_unlock_irqrestore(&report_lock, *flags);
+	raw_spin_unlock_irqrestore(&report_lock, *flags);
 	if (!test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
 		check_panic_on_warn("KASAN");
 	switch (kasan_arg_fault) {
-- 
2.47.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241119210234.1602529-1-jkangas%40redhat.com.
