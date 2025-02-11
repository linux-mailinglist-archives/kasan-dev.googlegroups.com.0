Return-Path: <kasan-dev+bncBCPILY4NUAFBBBXMVW6QMGQEYIE6DBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id CE28FA310B2
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 17:08:40 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2f9c02f54f2sf11611790a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 08:08:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739290119; cv=pass;
        d=google.com; s=arc-20240605;
        b=BIoI5xwGlh0d23o5EJ1XVmI6yO2Eoi4eEe5neWhnhUfSyX/10DdbNVQhLkeGIQ7zCJ
         iHegcpJJgfvhuyNqjhaRjN58fFePldpNDaW/nUTvSbL1zoky81jjM5PG1LqxpqzboR/c
         BMIecMGeRiFqosPDilXVqMAVTdzt5BzFaEYCxWCoF9mZOGHaOJNSLbygcKxl5f8+K5ho
         4ImRZCuOmoPtSXNT5/4oAQXmmlHGRQ9Ys/UW6RyB/IYFRRDkUyOL+s/3topTa7tEYK0p
         oFhaVgjXvxcSTX7dGEIMlAbeoSgenT1CEUpvPQEWxZ095ETgol2MQqcw8uoPH6bVtLO6
         qTGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=KQ37n+AvTkx7Kopu43MF7jeBpgSbI35G3+YQvhdLvXY=;
        fh=D35ENBNQwQJkXcJ+DE9Y17LqiFMZ0ihv2wIhzq8Gr1s=;
        b=iqRdGRND3oWxD9qSg0ZPL6nYzzjnS13wiQ1Bj4o4xUcFzr9/kXG09UepD3GWH/Jocy
         dwLswj2iU4YKwSj+9RrCHIB4GtCLzNILtJ3/EWWXM+A21xdJl73wnLG92f+MrPTbhkpq
         BVwHWrfJq/i7s6yIu2hxfliYMnL2NRP0eRoNFDuymP8lDUOY+KlcScBV5+8cpfQsHJTT
         PwrD0vH1C565hRFH3r1JMCgHGxsQhDP6c5gVpElEpHn5VRRRvz/dRPK0rgXChr2gvZ3H
         q7fYgdwmZOEv9m3WQL6BAYw/4zld5OgQ+9upcwkCtGi77cwbIMDrKwYLU/SePW2ziFa9
         O+PQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JamOGWSb;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739290119; x=1739894919; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KQ37n+AvTkx7Kopu43MF7jeBpgSbI35G3+YQvhdLvXY=;
        b=oOW6PHArd/vMYswifd+kNJFOCRDYdwBA47KWTIr0d/xKERNzz4odrT7YZnqlQiTzZx
         TL9XkX6k1PU5NdAiEp57Ylp3b3xQi6ftNb8MO6ue2WMmbvxjr7On28vMOhCY6fu5Mx5w
         KVWSN/E9quQTs/o1qjzfEt7v0r+Sz+Kpz1Gx/4XbS4roYUH3kxUpfamSFbUtwLug/UbR
         xxEt+czCGs1QVnU0HfWbFl1z4CLYbLrFwSHWh0THFHN5Kd2//9o2U7SKdjJ5BQaZuarZ
         vpziu3nCWZoNrjIL17eYif5ufwAqQ8vyU+etbjffb+kioDhSaJliMl2hsenJERIG/GZU
         qy9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739290119; x=1739894919;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KQ37n+AvTkx7Kopu43MF7jeBpgSbI35G3+YQvhdLvXY=;
        b=VfM6uefGRvLVMZIE4bfFoUuC/ylCsXAaEPCv86nMOcQctTpwVe8cJZS8iNo0fZgXzW
         Ahsn/pd+Ds4CWV0kdwOAn57zis3RNDCObQG+OKE+P3swFdCocRpQuzg/qVOpB/jMPsyv
         hjnNml/xIvMUrivxnDaNZ+Gi647s9GLuYQSUh2Wfdf+TFMllQsZkN8NL8je79L4phx03
         4AY69IHqhN2dMJiCbNtAb8veUc2dwY7NTQF0+ezOqGWfnBRxGRDOZ15YL/w7x/DAg0Av
         0imX4kGGhmpOiey6tNe1ePRuu+N13Z1L3ppBiDCh7oPyOnN+8qqBBc166mbUiK1PQctd
         CSQQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZnko9AiNV8bNCBO7iJz1oHflqOFC4+Bkw9FbqV3AWDBZEYcNtqFMdGtg4Bd9Q/7i+9lC2JA==@lfdr.de
X-Gm-Message-State: AOJu0YzZgl/EPBEqaMObz2dT41AIiSHOANOrXRXs0HEWcdJJZ8KeTfya
	egLKF20Ulz5d0MkpFXheI5yFkJ2vKWsIjNbw4+dMVSdCkWJpQQYJ
X-Google-Smtp-Source: AGHT+IE3Ar13GpTzxjEhSa7cu4At/8n1+w9hLVIk6xCmnnnBgNyUu+1PEJDbHtfyFcwnf+UeIlunOw==
X-Received: by 2002:a17:90b:1d52:b0:2ee:aa28:79aa with SMTP id 98e67ed59e1d1-2fa23f423e4mr22739208a91.6.1739290118990;
        Tue, 11 Feb 2025 08:08:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE2jxUKaJfWk7RvydSM4wC7zKdDzN1bWIpHXMkc/8Cb2Q==
Received: by 2002:a17:90a:9513:b0:2e1:1d4a:962a with SMTP id
 98e67ed59e1d1-2fa9ee4bf96ls522953a91.1.-pod-prod-04-us; Tue, 11 Feb 2025
 08:08:38 -0800 (PST)
X-Received: by 2002:a17:903:947:b0:21b:d2b6:ca7f with SMTP id d9443c01a7336-21f4e75a0aamr311206105ad.32.1739290117777;
        Tue, 11 Feb 2025 08:08:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739290117; cv=none;
        d=google.com; s=arc-20240605;
        b=Qz7yv/sPs6+0oK9FfJifgwyKHIuIwsaveyPl8XlEMYTytrsVh2VmzP+GHEkh21xLmh
         Fz51HLxyimjvu7qnYtNUF5T3Nd1OKw8QPfk0rRa3oMsKocuutmiSGdg6Ki2I5NMLxnnJ
         rYuqzXMOwNDm9Pi0qJPyxqKtZwi3p449v/pqnJT12bVykrqaKoV+xu5Jjx4ttF6ewnwr
         ZKPzB4gM4K4SS8+1Ox4Olq+arpY/C2f/RVAj4K384mDoBQP5T5NrFUxkl/j27O8oKlKQ
         wkrbKn7Fkl3GWvY8fyw2r7n5bRKJfLU1RGaRWV7pewrEwcNjW/x8jNClXWgQD2nhxsx4
         641A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=UipiODYFsFgVF8vxMUdu6AW5VgLIbfrFFLlK7TYmKsA=;
        fh=tILIASgG1SgYeARKVo/HeNKRyt6mMPxF3kkYIhMEYfg=;
        b=BKn9GiXguCZoDKCIAtadSX8/HNlOucF0B81/XRqEJ0I3mw/c8ZX+lrmdSuQhbu8I/5
         spCw9LQwXUSadIafpW9dJHLfkFV0XFQItY4lOD31wzVSD5GF/SQd98p/EeDAUYOVnYCc
         6I8svrqadZYPqqnF+9vQAgS62vHVLkTc62NecoY2vW5vhVsmipFmlgCHxsapYG43kSOD
         a+5pASU7OWeWsnFUEoWL9AxE/DuJu2LQwcZEUjX5MRKQAz86ldRGEYTJx+U/DGhecm1Q
         ZJaaaoroye62Ede7TpgjdgXIIuP3EwIh7JgHZNbRk/Pzw8NkOODsf/HboOYYg55YBRGa
         0V/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JamOGWSb;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-21f8c26c97asi1834575ad.7.2025.02.11.08.08.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Feb 2025 08:08:37 -0800 (PST)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-487-o45N5vneMBKaSqLBsS2KlA-1; Tue,
 11 Feb 2025 11:08:33 -0500
X-MC-Unique: o45N5vneMBKaSqLBsS2KlA-1
X-Mimecast-MFC-AGG-ID: o45N5vneMBKaSqLBsS2KlA
Received: from mx-prod-int-04.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-04.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.40])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 4F35C19560A5;
	Tue, 11 Feb 2025 16:08:31 +0000 (UTC)
Received: from llong-thinkpadp16vgen1.westford.csb (unknown [10.22.88.207])
	by mx-prod-int-04.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 8964A19560A3;
	Tue, 11 Feb 2025 16:08:27 +0000 (UTC)
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
Subject: [PATCH] kasan: Don't call find_vm_area() in RT kernel
Date: Tue, 11 Feb 2025 11:07:50 -0500
Message-ID: <20250211160750.1301353-1-longman@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.40
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=JamOGWSb;
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

The print_address_description() is run with a raw_spinlock_t acquired
and interrupt disabled. The find_vm_area() function needs to acquire
a spinlock_t which becomes a sleeping lock in the RT kernel. IOW,
we can't call find_vm_area() in a RT kernel. Fix this bug report
by skipping the find_vm_area() call in this case and just print out
the address as is.

For !RT kernel, follow the example set in commit 0cce06ba859a
("debugobjects,locking: Annotate debug_object_fill_pool() wait type
violation") and use DEFINE_WAIT_OVERRIDE_MAP() to avoid a spinlock_t
inside raw_spinlock_t warning.

Signed-off-by: Waiman Long <longman@redhat.com>
---
 mm/kasan/report.c | 20 ++++++++++++++++++--
 1 file changed, 18 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 3fe77a360f1c..e1ee687966aa 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -398,9 +398,20 @@ static void print_address_description(void *addr, u8 tag,
 		pr_err("\n");
 	}
 
-	if (is_vmalloc_addr(addr)) {
-		struct vm_struct *va = find_vm_area(addr);
+	if (!is_vmalloc_addr(addr))
+		goto print_page;
 
+	/*
+	 * RT kernel cannot call find_vm_area() in atomic context.
+	 * For !RT kernel, prevent spinlock_t inside raw_spinlock_t warning
+	 * by raising wait-type to WAIT_SLEEP.
+	 */
+	if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
+		static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
+		struct vm_struct *va;
+
+		lock_map_acquire_try(&vmalloc_map);
+		va = find_vm_area(addr);
 		if (va) {
 			pr_err("The buggy address belongs to the virtual mapping at\n"
 			       " [%px, %px) created by:\n"
@@ -410,8 +421,13 @@ static void print_address_description(void *addr, u8 tag,
 
 			page = vmalloc_to_page(addr);
 		}
+		lock_map_release(&vmalloc_map);
+	} else {
+		pr_err("The buggy address %px belongs to a vmalloc virtual mapping\n",
+			addr);
 	}
 
+print_page:
 	if (page) {
 		pr_err("The buggy address belongs to the physical page:\n");
 		dump_page(page, "kasan: bad access detected");
-- 
2.48.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250211160750.1301353-1-longman%40redhat.com.
