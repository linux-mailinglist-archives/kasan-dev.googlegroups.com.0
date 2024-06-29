Return-Path: <kasan-dev+bncBCT4XGV33UIBBAHE7WZQMGQEW7ZRI4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CB5E91CAAA
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:30 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6b5809d6cfdsf14596606d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628289; cv=pass;
        d=google.com; s=arc-20160816;
        b=RurjRLh6Ma4f+seDQRS3z6cPI+yj4pWxgvcgxSo9bwsXxHgIXmFTgTUMR/vqBdk730
         ag+5WpNibqZ737kp3YCs8K6TM0WQMU1GXsItFzBgyhH2qH0z1e0e7wGNS2FKK+UUGweh
         TplilxdGOna1vxE4U9LI7YBq0Dy5Y2e//fz/g+AhqxyN9OotcmN5j1HUAo0nE6sWmx6q
         IL0RP+KoesFmMxMNo72r8qVyCLPi6DAIchj1JdBNzUET8eDU6yajX2Sz7NLEQ+KlEDc7
         nQtmXvHztE2IfldpWm34564NwqpBK5NGJyiEu7ucQPclfneBtx4yymMbJEAyJ1bF6qGt
         H7Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=zmw/tTK6x+lRUuEp9UDy9KVVgZK+ZBD0g4cvmii5MJc=;
        fh=wfTSAv8Zgaq3Dh20LA0qwCR0UgWtiq5NLJmY9X8DVcA=;
        b=H2i3VvmYa98W54vgXSpvUZFjfGdMl3gyrL212nA1Ncg5Ct5IvHCYDuvGkVZTTf4vxL
         sCehxaM6W5+xXzAbNzHkb+jkDcIEz5OpjMKot8LTVhSjSNHkTz2G1pM7aj2dnWQl39Qq
         LZVMP3gVqjyib9eEMRsM77E5sUXkrEiibag9xFqPvzud6OxPNmDFJhyKxQBAfSeKWOxo
         6bWz4UWTLr3z/JiTgLGAzddV2pvITDfQ7nChJ49A+KTOzh00y1G1rd9F2wFCldXkmGUA
         auiaisIlmx9QMJb2C76uh8/cfuCWrDVvq8iV0u4l7e9OmzWvWQLeJry4LDcJfERRy00y
         2AMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=MD+ee24G;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628289; x=1720233089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zmw/tTK6x+lRUuEp9UDy9KVVgZK+ZBD0g4cvmii5MJc=;
        b=gTe2TkM4cbCzbIx9Mo/Zy9y96G0yjclkHLTtU6Tx/PJXSpYD1MPeyLaxCaIRC0xk1U
         3bdtov2740jLgI1gr+VySGHWd0RolpoHMjyNbrSkPqDm4ScBk6gFTeLwlit0MeV0Qxsf
         a3z3i3BrPcFa677SLSvf+D5ioNjqDuxkC6R49m7deQsgU6TO9WufhWhi7jJnt0AYb8+N
         2edBM30wDLTq7hTuCG6fGGvxa+Ipgijecy7FVl7J9jPa6A/XEnQ2dY7rolpzHbmFpvCN
         uCjShwLqqoV7G8dpbw40SZ6xHm7cJTduf5QylOM9i20Fedu0EELT2Zm7HZuhbmLW9c64
         7/Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628289; x=1720233089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zmw/tTK6x+lRUuEp9UDy9KVVgZK+ZBD0g4cvmii5MJc=;
        b=MhIaPaeiWLDQ1jbjizXoUSHkBnyqqhmaiKE/vU679FgHX2qXHXzSqFe1bjj6nGpBsr
         25vdE+C2DH57VmvnX/MF6CdpIVH3TSqCy6SZO/6Lp3Tn6M6GDvUCZsaAZ8Y5vs3NT2zX
         PqcU2VpQyTR/TFhvSwQ96yWTBYVWDBo8BM8EaKakGptLnRJ0yoHa4qDP3dOFZ3imuyE9
         Z1F928O/6geTPNIoR4vIEKMwxv0leXeONfm3J3X6cY/p4jrOtUR5UIX9a81VKwW7j1zg
         w83laMeQqJRfieDvAoiekF6MJ8v4vawz4JEAQJHOyATMM5h6hrhofKVSUzg66Y6gjunm
         oG4g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUM0fbI/OZGp4uq+XhmB5LPUbpR/ytooajK136RPySg+FA31tJqgL/5rIBFtlJos9YFMGc8jQVXjNgV+SkI68SkKFaFhmzgrg==
X-Gm-Message-State: AOJu0Yzn1H4AEEfUB6332u0cFwv9BCxu2yQ+wO3Nhthz7kxQnwbfnZo1
	XPdBm43Rr4e+peOn1yrvTicsde0WkatY6K2vhm9//d0zwJ087DVs
X-Google-Smtp-Source: AGHT+IGkIc9WLM8bxzxH5WBJP/GSgIkpzL016Ia6YhPrGHaqYnM57LKZ9nEA0W3c1m9Obsp5D3zLCg==
X-Received: by 2002:ad4:5aec:0:b0:6b0:62bb:ab9a with SMTP id 6a1803df08f44-6b5b70a3a68mr176026d6.19.1719628289084;
        Fri, 28 Jun 2024 19:31:29 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4107:b0:6ab:8f81:8496 with SMTP id
 6a1803df08f44-6b59fcb82a8ls19810506d6.2.-pod-prod-01-us; Fri, 28 Jun 2024
 19:31:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+qjFzQ7L3YzWAUHdo6Hc7dUMxL0PKJe7IHIrqmzU7pqlAcpEXKM+O+uQ9v00h8peKi56xSLdT8kUY7IUetLni7aoNzjGv0+GXzg==
X-Received: by 2002:a05:6122:608a:b0:4ef:668f:2438 with SMTP id 71dfb90a1353d-4f2a5511b8fmr85796e0c.0.1719628288384;
        Fri, 28 Jun 2024 19:31:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628288; cv=none;
        d=google.com; s=arc-20160816;
        b=SIvHiAAMNwSVQ/N5m2gclbH+iEazscq3i6FI9U8AHSYxFjDJp5q5vBaq1pWMZwIVhD
         rb1OZNQuXRS32hzQADEOEp48FApa/IX2etf6+1zIeZTall4kJzS2WgIqBrLRwKMMWMNh
         DwzmPvHe2ya0kDFTX/k4GHzrxpajAHqJtMkAex//dIHq0QerxyvRwsmcrLNkBPA4FwYE
         +osa2TWLBlGJWzZV75bcJePMGGojwcqeoQo0RpsVISgx6aiDeWuyP45h2qYYC9GtLZon
         eyifXYUiH63BMi9E5GUTol5wrF1CADHkH+G9l0RYrrb+0SumIOvl5g9cl9Zvn1NVHeN5
         2qkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=3lKhH4DM0Gf3rX3LXM/8SnsCJLoU+X56rFNSVR4AQvY=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=x2xSh4Quxeq0h8FCIsF3LvT4iS5KSrvND1lmMYHBiPWLq5CeokZp/Bt/kC/huGo2eg
         yzKmtgxwDCM99/JcnfiNR4cwVqAtM3vTUbJ6mzMUoyBGzck11RpkAP23l5XSGP+CH2Sj
         IVDYzF6mXv/gBxYtJLIg1SWtJzVkkyecsVzH+JDaQtL/gJ30zDWYL4Ocs6Eo/l3ObhFX
         eA3UPka0iDkfPhz2ppwfKBJFnM/6eGL2+j6bwVnB4NciYrndm1sw+O7Hz0E/dyswv5wh
         aw00qSorwDYf4jZzIZCWXm0Gre5EC4aK61euHp3VfUYyfbeVuqwOtNcfgz49dR6mPcbq
         mv8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=MD+ee24G;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4f292265fb2si185985e0c.3.2024.06.28.19.31.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 1047ACE4348;
	Sat, 29 Jun 2024 02:31:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3BEFBC116B1;
	Sat, 29 Jun 2024 02:31:25 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:24 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-kmsan-implement-the-architecture-specific-functions.patch removed from -mm tree
Message-Id: <20240629023125.3BEFBC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=MD+ee24G;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The quilt patch titled
     Subject: s390/kmsan: implement the architecture-specific functions
has been removed from the -mm tree.  Its filename was
     s390-kmsan-implement-the-architecture-specific-functions.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/kmsan: implement the architecture-specific functions
Date: Fri, 21 Jun 2024 13:35:21 +0200

arch_kmsan_get_meta_or_null() finds the lowcore shadow by querying the
prefix and calling kmsan_get_metadata() again.

kmsan_virt_addr_valid() delegates to virt_addr_valid().

Link: https://lkml.kernel.org/r/20240621113706.315500-38-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: <kasan-dev@googlegroups.com>
Cc: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Steven Rostedt (Google) <rostedt@goodmis.org>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 arch/s390/include/asm/kmsan.h |   59 ++++++++++++++++++++++++++++++++
 1 file changed, 59 insertions(+)

--- /dev/null
+++ a/arch/s390/include/asm/kmsan.h
@@ -0,0 +1,59 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _ASM_S390_KMSAN_H
+#define _ASM_S390_KMSAN_H
+
+#include <asm/lowcore.h>
+#include <asm/page.h>
+#include <linux/kmsan.h>
+#include <linux/mmzone.h>
+#include <linux/stddef.h>
+
+#ifndef MODULE
+
+static inline bool is_lowcore_addr(void *addr)
+{
+	return addr >= (void *)&S390_lowcore &&
+	       addr < (void *)(&S390_lowcore + 1);
+}
+
+static inline void *arch_kmsan_get_meta_or_null(void *addr, bool is_origin)
+{
+	if (is_lowcore_addr(addr)) {
+		/*
+		 * Different lowcores accessed via S390_lowcore are described
+		 * by the same struct page. Resolve the prefix manually in
+		 * order to get a distinct struct page.
+		 */
+		addr += (void *)lowcore_ptr[raw_smp_processor_id()] -
+			(void *)&S390_lowcore;
+		if (KMSAN_WARN_ON(is_lowcore_addr(addr)))
+			return NULL;
+		return kmsan_get_metadata(addr, is_origin);
+	}
+	return NULL;
+}
+
+static inline bool kmsan_virt_addr_valid(void *addr)
+{
+	bool ret;
+
+	/*
+	 * pfn_valid() relies on RCU, and may call into the scheduler on exiting
+	 * the critical section. However, this would result in recursion with
+	 * KMSAN. Therefore, disable preemption here, and re-enable preemption
+	 * below while suppressing reschedules to avoid recursion.
+	 *
+	 * Note, this sacrifices occasionally breaking scheduling guarantees.
+	 * Although, a kernel compiled with KMSAN has already given up on any
+	 * performance guarantees due to being heavily instrumented.
+	 */
+	preempt_disable();
+	ret = virt_addr_valid(addr);
+	preempt_enable_no_resched();
+
+	return ret;
+}
+
+#endif /* !MODULE */
+
+#endif /* _ASM_S390_KMSAN_H */
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023125.3BEFBC116B1%40smtp.kernel.org.
