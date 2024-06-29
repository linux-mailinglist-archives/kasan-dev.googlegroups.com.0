Return-Path: <kasan-dev+bncBCT4XGV33UIBB47D7WZQMGQEITJ4W2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 871C091CAA1
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:16 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5baf3993393sf828824eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628275; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y0cu6Z+ZIifAweRk+u5CZV645JeayH3fe1NbLNq98bQZb4Ux6pemlxfGBxN4ksR9Wo
         UTGGqftqbLg+wP5fitzn+t4Z1No0vuwMo31jPv+5Lue5Zk3CBsM1CzReLZGPuoS3yod9
         bbOmvTq2zvQGU8WNEAIncFyAyK8Ur5A/OmemLtV8Y0H6zpX52V+7HaN3n/GGNz8d9LVi
         Qn1oa8y+xWtPVGZexOp75ONAZ6RInjCL8ZTnbsyb7hM5Sl8RfVQ5kvtf1HFzG3GFAXTW
         mEhuMLF93fcGUObE5JkP0oIw3bhrutdLHIPbOskvCSMXJPxC2zrTrikOSDLzpYYO5lrz
         V/hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=eHFWJvn/5HETH4awHB4jXedXuk9zcWH+Og02E7Yw2Bs=;
        fh=CuzjWqohmxeOiqpRy84Yq0NsolqE5mptFL4ng0RSHzU=;
        b=whzHZ56egqgPhA8RlelR6jjyR72sZt++CQSzU05kmiT6ioyyBZ9u6c3jiPnJLlUES4
         Zw4oY8Xpg5tVtJ/fhU59fdhYq4/Mcq13oXt/IPvPPlTnfAu41Hvuo3qJMTDqwPDG2TFp
         2IM+3p3NBUqVmLvz0KXIrev3eJemXCtdctqcuEJG0RHefABZ3OWxvp3WO6N9D4t0YsT0
         YJIRJ7+6hALWMOBiSEvL9tDYHwQpBaLjnJAxJy4+EbILWhFNKDDUnfjbHzJseCYSxzKx
         YZ6x8UoWanI+PsIb8jAZ0J2KBcTyRux+B2BABlm4UJy/Zp8VuAq6vlRZfpKzGmRKDmkJ
         pJQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="s2/ieGGM";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628275; x=1720233075; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eHFWJvn/5HETH4awHB4jXedXuk9zcWH+Og02E7Yw2Bs=;
        b=tOnn3bwpLokrydjmCy6CqY00T3yyIYU4x2vtLKSSWj+vtGoCTRKp3V7Smi0KY7HknJ
         HCH4hBnk50hAI3ZY7ylB69/S5WkvHavKZrYmfRz6/65a401h3SXTK4BzJKpJ4GxNZBqF
         2rHzxVrV0+MtfsK1TaNOPwv8bwaflIZ0fWHDJyWqUfxc4QDsN3yomIBJjROrH13g+N8F
         syVhldnaY2E5hsOl7IqQPoVs6dtORTlALKIHRRzQYkMsHzTd0QHa/Tx4sP5lwYMq4jC1
         ntzCmu/73nIsnaHLJIDeFmn7MUG3/20ETflcbuEomyiOOCucjH22l596FTbV6IgGRdD9
         BY0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628275; x=1720233075;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eHFWJvn/5HETH4awHB4jXedXuk9zcWH+Og02E7Yw2Bs=;
        b=sMtyGCsIpYt6hwwK+PZDo5XkqNKxjCqXAT40IBYiSE/daa1m7zthIQXI9z8ljU5lwc
         i6ty5TR+OdbmZf6P5HLEbeQ8/1S8V7MvmNVTgWq2CfF894PcbYQ0qPCMZLloKs4K6x0l
         bX/ZPEiBEi6jML1roQOhfNWoWmOLR6V4AcvWooDYBFD4zRboiQP/9VKohVBDjCewlxxf
         tcSOgDKRwvoqIBUpCiKFUe+VQWet6EyaEKs1mRs3XWtgMJtbnVgU7J/0xeyq7naoaOLF
         nBS6eWChemRKG45UM6NDzb6vZ934E/x+LL7mmBlABCB+jhlrX3a/jjpSapGVorYRSPdM
         RXKA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX+OZd+1jrWzyTYzwmWy7LBA525h0oFqDAjYAVpI8YdFfIYyw8cD86yEfMUfPAc3jYDrmDD/hxVKmjoRzS/Hu0abBvBWHURsA==
X-Gm-Message-State: AOJu0YzavFyKCyIm6tvM85x2id0wf48t43vAz9XTyB2YHPa0CGFQRAj0
	0Ho1Q3gKihJiSsfBBRT0qysWJ2xak55xJ+odzhTZ+yTch3YO6xPq
X-Google-Smtp-Source: AGHT+IE8IgzA5CL9qPyGs5TEH29N1F5oiU9E1W4cJ5aQFE+w7Qjn537/Quxkc7TP0bUSiZOsUHARNQ==
X-Received: by 2002:a4a:7646:0:b0:5c2:1bdc:669c with SMTP id 006d021491bc7-5c21bdc6fa4mr11901422eaf.6.1719628275256;
        Fri, 28 Jun 2024 19:31:15 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ae46:0:b0:5aa:44f9:9b11 with SMTP id 006d021491bc7-5c417eac6dcls1093846eaf.1.-pod-prod-05-us;
 Fri, 28 Jun 2024 19:31:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV+6xgaieRtnMCqYmfucfyZjpmDHcVfzdVkUy/noqrq+zrByQVtln1QSpDjGGOsmI+FVcH5k11OLu4n6Bd/I+WIpiTK41BO9f4QNg==
X-Received: by 2002:a9d:5e0d:0:b0:701:f369:168a with SMTP id 46e09a7af769-701f369173fmr6753107a34.22.1719628274451;
        Fri, 28 Jun 2024 19:31:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628274; cv=none;
        d=google.com; s=arc-20160816;
        b=sMg5fvg2736nbDXj/rmE8JwXeIpjPZZJvGVPu6LBqECSCjAzYqEEJX/fwFwyAYhE1k
         d1Am3rF2wKv3vjSeFsJLSyfdXNnKGDki4m90hFf7gtb5Ba9X2ksm2zft2nFb6NhlaVYA
         M3hIN2sMfJDzE/oAJvt92DVy05sb/5FGXghFpofGDp7cqcFUsBw4qZMHuKzFN1MhTWfa
         D16TXX1bz7cVueU495x7yPXCPV0cF7sRReQSvI0vF8NCPR08bPjgLnhRf/PCNwacfjYb
         MmTrvX9D55WdD34wlCGmPlbMFG1saJ6JV9xDpz7br4giLKPPdrEbCFBTxTO+SP7cHZ3I
         sqQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=Bxj5Sd1xTqt9cbGukRCFzk8Keg/NEd81PltqX6/3ESY=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=kTs7wd6g31j0b+0qlDR4ayqIIETs9RDYZRH8bGOrwY2mzGOZWRr8UBrYv4VGuKRtXP
         OllhOarSNR+PK0KBG9B5DSng3whslKPNvDa0/aDWXY5ctPQIqCP8i7FDSeEXKusPa7UJ
         8sY7fdwoAj8oSef6F1dIt0a8gm/Kxuda6qGZ8FNeBe7i9nN28TjMc8yj1A3GQFSPitFJ
         AqoRgt9xcOzSyZtxMLGEocHg+0H64T0iZLBCq8TveVUYdv5QDet4NMxZ30HnQQjkgTxE
         GntkKROjs4CDFfhqwJRX58iilU+6NELctMiwTil16/nycSktCX/Pa39r0hOr7ZE+nuPp
         lxSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="s2/ieGGM";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5c4379fc953si793eaf.1.2024.06.28.19.31.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 3C185622BF;
	Sat, 29 Jun 2024 02:31:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D6724C116B1;
	Sat, 29 Jun 2024 02:31:13 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:13 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-ftrace-unpoison-ftrace_regs-in-kprobe_ftrace_handler.patch removed from -mm tree
Message-Id: <20240629023113.D6724C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="s2/ieGGM";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: s390/ftrace: unpoison ftrace_regs in kprobe_ftrace_handler()
has been removed from the -mm tree.  Its filename was
     s390-ftrace-unpoison-ftrace_regs-in-kprobe_ftrace_handler.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/ftrace: unpoison ftrace_regs in kprobe_ftrace_handler()
Date: Fri, 21 Jun 2024 13:35:13 +0200

s390 uses assembly code to initialize ftrace_regs and call
kprobe_ftrace_handler().  Therefore, from the KMSAN's point of view,
ftrace_regs is poisoned on kprobe_ftrace_handler() entry.  This causes
KMSAN warnings when running the ftrace testsuite.

Fix by trusting the assembly code and always unpoisoning ftrace_regs in
kprobe_ftrace_handler().

Link: https://lkml.kernel.org/r/20240621113706.315500-30-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
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

 arch/s390/kernel/ftrace.c |    2 ++
 1 file changed, 2 insertions(+)

--- a/arch/s390/kernel/ftrace.c~s390-ftrace-unpoison-ftrace_regs-in-kprobe_ftrace_handler
+++ a/arch/s390/kernel/ftrace.c
@@ -12,6 +12,7 @@
 #include <linux/ftrace.h>
 #include <linux/kernel.h>
 #include <linux/types.h>
+#include <linux/kmsan-checks.h>
 #include <linux/kprobes.h>
 #include <linux/execmem.h>
 #include <trace/syscall.h>
@@ -303,6 +304,7 @@ void kprobe_ftrace_handler(unsigned long
 	if (bit < 0)
 		return;
 
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	regs = ftrace_get_regs(fregs);
 	p = get_kprobe((kprobe_opcode_t *)ip);
 	if (!regs || unlikely(!p) || kprobe_disabled(p))
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023113.D6724C116B1%40smtp.kernel.org.
