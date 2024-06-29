Return-Path: <kasan-dev+bncBCT4XGV33UIBBTPD7WZQMGQE2MKPPXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 738EB91CA86
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:40 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-6c7e13b6a62sf964287a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628238; cv=pass;
        d=google.com; s=arc-20160816;
        b=XMYgC7dWMNYs/oHrOOlfHg7IeS+7OJvKC7BQrjgihQcaSmEh+ANqKN0artX6YAjMPB
         zQib2EPE/U37r1CGOyWWiS08ups0SfrnHj5XO1tNceNbH1RbgOt6szfPiLu+c7hgVDho
         0vJPvqy8CSZ3hlSfJN9+EP6fB84nvLoz7agfcl2vDJ/E2JGYMIrpY+gujpcO1d11eYPI
         jRDHZIX2aS7O7A42FlWzOBEGCDnAiztuuhHlhKAAuqP7I/jwqLV4o9l61Ulcu2WPIY9q
         l/U5Q0kb1xi/Vvoh4J3ESpztLxgRBPb8AHy7Uvd9CVWlzgFy8DUOr5lVsC/CM9p2irbw
         +1NA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=p3R/wBBbWqf1fVTjUdeDOQt8jaXEwfV12emqJcPYe98=;
        fh=yaXRgUlXVXSXNI3swCSiIUyiVKBTBMl1nCDLpA6wLcs=;
        b=Po3tjLVlt338dMioPXZVXr9csFwA6sepfrj1hRWUNuVcOxuPKAwNglQp0/yAR/q3JQ
         NUdtAxaYjww8SNG21W/FlughAAvadsuV9sEVUAgaU4MQF1/S2SJyjAQfJCe0E+76MWcv
         luJKGnNp/fmOdqdvtoIJLj4KRDkIk0q1zfLOSWszuak6q8UHCaTLr/BRdVWW+lh07A6F
         4YxgBU6EgI+4yMQ9XVP8D0znyigCsB4Omc0AuKi9j3Jt4+OrM0I7X3HBkOaSEP0GMccA
         vlHDdrS4dkjLo3yAOOt/fkYCuLRTouAUP+1LmWTwqn6lbpPgyP8F1yc708VRv0wxnQmz
         DLcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="SRv/oYKU";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628238; x=1720233038; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=p3R/wBBbWqf1fVTjUdeDOQt8jaXEwfV12emqJcPYe98=;
        b=BXfxvJ9HRwhyW1/X494XT8ZKQ5ZJW5IejqszsRyhLCScs033Wi/LM9hlQW4dXiFUSC
         fuECFOSyHTsB6LHjMqgU7QgD1UPrkrOYuyfQbDJ1dNVVS1StpK43O4QgAtZJIxLlX2Tw
         wAfUtEMvwFEFTKVQglR5PoCF24/x7H61WKMC2K2bMCoaRToDa3IhRh/VnBoolYQ7pPYr
         GY1B6HIxv5i51pW3uZ+CUEvkAcn+cFIRLRbA8/RJ5tcEaic41zr5xJfM8EiLu515CUfV
         pITI9WtH8ZXE8Y7Dh6KexgGcFKgE8hSbJpm3BHwQH9+96ecV/H8fRqaFo0IUKz76iuzE
         Kz/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628238; x=1720233038;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=p3R/wBBbWqf1fVTjUdeDOQt8jaXEwfV12emqJcPYe98=;
        b=S9hFtH5tYLkNxo/GCr6nC+n3w4YPieoGrtPcwLKtNLj0hjoaBll5pKAjl0XJSoxctN
         XTfPME1QFJ2KLrcgCtgHm3zGdt4246nxEIjBFAIkGhkfBW6dg7thFGzcljGLMC2W1SYf
         8dJqJ5pzaCWu1Vq35Czfe/0aYKEWw30o57HoF+PLaeLCZjh7FUTWYwWRRbNukhwKVN0W
         RDmfMlZ5Cdqa42ObwJdl7btmKPOLpWxE7SsX6QZ14ya41TyJbtzuyiz02tKFMiFkhUIN
         +KcMHqN9IyyERi6eAA7pqsej9mgCO7mz4xAPGvC8NW372FSTU32saNhMORYJnSxJlQ3v
         gdaA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbCOeIrFz1V6bcU3NhT9mSnKESBdxVzLW+Wk4gYSA4Z2wZ9/Gdvms5KVzoKckUD1SL9lxPJVRu6rW2WwKy56advMoO+GkXKQ==
X-Gm-Message-State: AOJu0Ywp6xxcn7wsOy9OQq8efDdjdp2KuXwacQ8Cx173OUkhG2dbDfio
	kG369SAlDBEuYvglhfHIc6yqs79z7QG9pqKt9WwoRuMu7Bmj5qRK
X-Google-Smtp-Source: AGHT+IF8BO1yi3QrXUKgLsQA9mjc/HXbAuHcSCOkQthtHGC8dhfs7zAkRJWqZda8X0FgElVqX4VxiA==
X-Received: by 2002:a05:6a20:2587:b0:1bd:1e06:9dba with SMTP id adf61e73a8af0-1bef61245c5mr82010637.27.1719628238068;
        Fri, 28 Jun 2024 19:30:38 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4f41:b0:2c7:e17f:422b with SMTP id
 98e67ed59e1d1-2c92491f82als640661a91.0.-pod-prod-09-us; Fri, 28 Jun 2024
 19:30:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU0t55BJaq8buz+v8vlrHBKW+f+PeXRGriXjo0Vr4ytxfk1Gf2gYjUwzwm0aCj8WDc9ikih2AZuLnu67mWmyp5JyiN5keCYaUSsiA==
X-Received: by 2002:a17:90a:b014:b0:2c2:c149:ca4 with SMTP id 98e67ed59e1d1-2c861434ea9mr14163835a91.43.1719628235491;
        Fri, 28 Jun 2024 19:30:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628235; cv=none;
        d=google.com; s=arc-20160816;
        b=Iyx6NKtXvPD2mVDJyiG57zNqhT2gD/hbM9n3MFSbwSCT+QyoDbg0GEFrPXuB0m33o6
         Tj+i282IjjS7JZXNbfUJTrJl51JIC9OQOiGGffhOHkJi4Rc4MZ7jUJ5bNPmicx+2phBm
         lkKNyPp43Qtg7ixKFGFut3pAu/dersTpJ9BuF1wiXn3lI0ER/GXKutcHmSO8ONICRR1t
         ndxQNcx90aE+raZNT2P0ybdvoV7bhszrsLOmHAGp19ucIduSIUjK8IeQUOcOmC73v8t6
         EsEO07zaDnM0/XwT/oeJ6Jwagv5KdizNepCMVUdpEdB2D7vYF3zirAbHDFibf7lQK7LU
         cWFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=plrfCWGQF2B8phC4apKfMB/dMIfbfaAFPzLllBzZels=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=D555yOY13A6FE8uGVQBKvMDR6nl+bjl31+MbbqHD1hVQSavoZRaK+PqUmwUgrLpCQO
         gygbbIgUN5OT5OYy/RyIvowTRic6x92evjU0qmprig9uF05O6BoGi/mCY9l5LAKmtXyP
         MTablfc+/XGOXCAcsMtp1+y3h9VheCvfC/6lULXMtl8jHudyeWqx/a5jqQ/5WNK4YezK
         cCpg/OLBiZ5pIQV/d2DzIl61p9SLi6SsO49g0h1xfck90yTsKx+ZXT3V7V5Hx7i/FVB3
         nJAznv7JB8pVenNcxsqK3RzCGCqHik7C2OikGwmruRubMYAneeC2K7g9pdgVFTej6Eu0
         bWLA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="SRv/oYKU";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c939cc19dasi37775a91.0.2024.06.28.19.30.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B5BCF622B8;
	Sat, 29 Jun 2024 02:30:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 58833C116B1;
	Sat, 29 Jun 2024 02:30:34 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:33 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] ftrace-unpoison-ftrace_regs-in-ftrace_ops_list_func.patch removed from -mm tree
Message-Id: <20240629023034.58833C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="SRv/oYKU";
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
     Subject: ftrace: unpoison ftrace_regs in ftrace_ops_list_func()
has been removed from the -mm tree.  Its filename was
     ftrace-unpoison-ftrace_regs-in-ftrace_ops_list_func.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: ftrace: unpoison ftrace_regs in ftrace_ops_list_func()
Date: Fri, 21 Jun 2024 13:34:45 +0200

Patch series "kmsan: Enable on s390", v7.


Architectures use assembly code to initialize ftrace_regs and call
ftrace_ops_list_func().  Therefore, from the KMSAN's point of view,
ftrace_regs is poisoned on ftrace_ops_list_func entry().  This causes
KMSAN warnings when running the ftrace testsuite.

Fix by trusting the architecture-specific assembly code and always
unpoisoning ftrace_regs in ftrace_ops_list_func.

The issue was not encountered on x86_64 so far only by accident:
assembly-allocated ftrace_regs was overlapping a stale partially
unpoisoned stack frame.  Poisoning stack frames before returns [1] makes
the issue appear on x86_64 as well.

[1] https://github.com/iii-i/llvm-project/commits/msan-poison-allocas-before-returning-2024-06-12/

Link: https://lkml.kernel.org/r/20240621113706.315500-1-iii@linux.ibm.com
Link: https://lkml.kernel.org/r/20240621113706.315500-2-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
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
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 kernel/trace/ftrace.c |    1 +
 1 file changed, 1 insertion(+)

--- a/kernel/trace/ftrace.c~ftrace-unpoison-ftrace_regs-in-ftrace_ops_list_func
+++ a/kernel/trace/ftrace.c
@@ -7407,6 +7407,7 @@ out:
 void arch_ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 			       struct ftrace_ops *op, struct ftrace_regs *fregs)
 {
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	__ftrace_ops_list_func(ip, parent_ip, NULL, fregs);
 }
 #else
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023034.58833C116B1%40smtp.kernel.org.
