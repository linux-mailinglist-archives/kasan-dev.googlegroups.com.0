Return-Path: <kasan-dev+bncBCT4XGV33UIBB7HD7WZQMGQETWVUETY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 67CEE91CAA6
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:25 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6b50c903a87sf16567156d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628284; cv=pass;
        d=google.com; s=arc-20160816;
        b=DQgBQ9Zezrs5vAvBMUYOvhoTsZpEQPf6gIACidTMtKWAERs3jIWogprrQrS+yT7IWt
         mCske35j70iZYV1JYycIIggFM+yJTTBGTPKQf6YsMo9rH9twXuAF1VxFE+JOCUttNJlt
         f07UxT8xDbCoYgGNS0/9lGsaK/5d5D9L8AiHe1pGFQqjW2oqqrpXaE1dzRZfeP8OuC4M
         SNc2pTp4T255gvoxh7oHqDTcOiKaKj4hOiiSVv18WSF+jwGLL1Y2VvExZ4VY9SU8m2rF
         RF78tmfPG88pneh33HVrJT8HN5ScMtDWMPOwMkh76QD0YQv2k+1Hf2xk+xzyyB3QfOdg
         31tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=CJiIzoSPbaAMsooWfdWuwbntZNFytXK/jCEAj+0dwPA=;
        fh=2HC+WuoHORMinQ80PLSqN7CtBaigro6JmOgwfy2RGK4=;
        b=z+T++NbYOORugL4Q7O2UdnZ95h+006ZqyNz0Ztid0lLbA5A7hKuJ+Dd2NJUR/Gr7K6
         jJ8fG2zR5KLtXLrglTpne7gifGps2q3QWkYnmcCrHYy4X/YUDxrVwavEws1o91gCpFMW
         5+3nNbb6dldxQONu8aSVOaYXJOGcKOZDt22YWDaoXcaZvZdoOBByP0EEY2ZYY7MaY3CZ
         7e8mME5TEXmZK+dT1nY+Fv2rJoIGLBAwOctOJ3j0GUE05MyqUtFWMnUBHhisUPVWgpO7
         nCd8yVDB1+vCpyDgxrBOyvD92P5Q/ks0pou6vfVTLx9zCIKoqEVKITiJqN/DWrCgeJMU
         ZQZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=RRBzHHKC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628284; x=1720233084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CJiIzoSPbaAMsooWfdWuwbntZNFytXK/jCEAj+0dwPA=;
        b=fQo+Gxm2AfSKZOFXveWjsWM4vSPpeZxulF2zIT89wvEiWzvPCarxaTNGFiT67hUFLI
         Z/ai/I4QFAXF85X3PfIGTUyBMZBIXCFQ6drR5jwTx4yEd9VXKiHw9OkBTtTA0uTQxmV/
         ATyvuxYl7lXDvu7ePQdITR1bY4u32p/kSSzd1GwDO6ATOA4tDhgzTCy/RX+JQ3niiYpD
         x8jxksARt1PrmVp24JxduTzXVyHlp6LuPJGZThdMcWG5OrXmah15ydGEnbsDgaxxGioq
         OQgVnRVowZ6FvV6ohqv0jNvzwdf09vt34/dn4vTzrctpGsaT4+XDkchKfJVL3QGF+qMR
         3x6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628284; x=1720233084;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CJiIzoSPbaAMsooWfdWuwbntZNFytXK/jCEAj+0dwPA=;
        b=wN4fr8FqEL18NG26ZAF/fnraTdyOc6muvoTANgI4cgefuwr5ZqzOLFU3ZSYkP0WyOr
         xpkRe9dSK2j8tr4VvyEvV41owEvZceuUbboyR4bGkw1kwY60KbRZwM3xr4vtaEdWa65k
         GISP+30X7CD9WwXu60fDeIF8Mtit1fI7szH7xw7p2Ghu9O1hbYTHp6P5hONbHstwLwh3
         4dgSc3SB4AfwPCGUUT6f7GqeirhLbVaSrXx6cIqk829G8BsgVO47vjTpxxZvoyMzvsXp
         UsSPzXUFquCcNDS+1yd4I1rH+6zXKuP24Bq5boArdBT0m8dq0GqhLg5euOeVqbVB1HkC
         M9nA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWllzJ7z23Az3T46RgtK/OhTivhPIUxOVodGxOGky5Gn14ZCpTdn5mWUYh64ly48z4wT3INXBrEt8JvBK0Sf6s4jabEZwyR6Q==
X-Gm-Message-State: AOJu0YxHJEFqnzanXHeKtqCLUU1BnV6Df/VwR2P8FLOR6XweiNdOyGZ0
	HTTTS6HwLAkX0vX/zKkVBMv5jSyM6mOArU2v3t1d1YqsPpSxuaF2
X-Google-Smtp-Source: AGHT+IFsZS7Rlq0eg3OcsZ0cWjg0FpeoeWnH6ydrMqUVEmVLUCVvMqZ2YymnYF8FZfl8EYiZ8kADgw==
X-Received: by 2002:a05:6214:d61:b0:6b5:6331:4d4 with SMTP id 6a1803df08f44-6b5b71794f8mr68656d6.51.1719628284215;
        Fri, 28 Jun 2024 19:31:24 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:528d:b0:6b0:88f4:b00e with SMTP id
 6a1803df08f44-6b59fcbad07ls17501976d6.1.-pod-prod-05-us; Fri, 28 Jun 2024
 19:31:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZVzVYHmJJZAY1v19f3r5IJ2NCQu5IkpOETUHdRTdwVJXd4gHEwaAYZv0z4HtZP6bUz5uaDB5CDL/a/tqxcZ4VUnXsqnMMCRPAog==
X-Received: by 2002:a05:620a:a03:b0:79d:74d2:4a84 with SMTP id af79cd13be357-79d7b9ee83dmr2121585a.16.1719628282937;
        Fri, 28 Jun 2024 19:31:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628282; cv=none;
        d=google.com; s=arc-20160816;
        b=dDNXxnX8mvt4qnc2tX2hjJaQvKuTDf3BZmgmYQmapElCFV2+8IZfDf/E9FF0bwn8e6
         8d2ODLf3h5LRzZz27Hn/I37lHrecSPtP05Kw0VhybjIYJbY/rTJZj3mfMWJoAyLwLkv/
         yUN2YDT1lwvDbuth03MxUbeGlliBXceTbH3Z8X5zC4OIf69nWKmbx9B48wNArDKzqy3k
         ncGFWc26hb0za9NFa6hoJEnvaEILrZGe82WLPtryrO8hKE1NGra34ZrTeZ6mqAYJbPNU
         d6p7hKrKNKqSHYOr068m0+V4dxFvgoUp8k8z9SU0anoJHlpA0nSPMa/OAwI9uopPMZYJ
         e1yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=jU/Oii/xMblQVZF7F6Fg33CXo5H/O+ancYGEz6pKt9g=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=EgZHnVXBdT1vW6RjMMGdJVL9UDWSWnu7sdnH8Le6d4aJ+4oLEOTDoGuVhK2b/ibFvN
         Q57wlUTGdV2Iwr6YtdSXTwHALQZIDqGP5xjGW+k8JTevlGiKJFPYubjaIh8AHl9gf2Il
         ODRfj6qMzAJmIUuzAIO1dYkilLzUjNJo3gr4wDoVHqPLvNl0zjDPH+sK6TlqU7FoOrry
         NGS1JXQeqDfcXvrzEC3JEkZMj8zVXXtmaz9gcGWXt/70T7nv0LeuwcCGDG3G8yExWYYm
         l046CauHgIpFC7pQyYRnzPIBTsPJvxhW2JT7HsYvwsPzEIUx6YwgQEddb7zZymy7y+e6
         w9yA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=RRBzHHKC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-79d692706aasi10339085a.1.2024.06.28.19.31.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 584A1CE434D;
	Sat, 29 Jun 2024 02:31:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 84ECAC116B1;
	Sat, 29 Jun 2024 02:31:19 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:19 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-traps-unpoison-the-kernel_stack_overflows-pt_regs.patch removed from -mm tree
Message-Id: <20240629023119.84ECAC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=RRBzHHKC;
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
     Subject: s390/traps: unpoison the kernel_stack_overflow()'s pt_regs
has been removed from the -mm tree.  Its filename was
     s390-traps-unpoison-the-kernel_stack_overflows-pt_regs.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/traps: unpoison the kernel_stack_overflow()'s pt_regs
Date: Fri, 21 Jun 2024 13:35:17 +0200

This is normally done by the generic entry code, but the
kernel_stack_overflow() flow bypasses it.

Link: https://lkml.kernel.org/r/20240621113706.315500-34-iii@linux.ibm.com
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

 arch/s390/kernel/traps.c |    6 ++++++
 1 file changed, 6 insertions(+)

--- a/arch/s390/kernel/traps.c~s390-traps-unpoison-the-kernel_stack_overflows-pt_regs
+++ a/arch/s390/kernel/traps.c
@@ -27,6 +27,7 @@
 #include <linux/uaccess.h>
 #include <linux/cpu.h>
 #include <linux/entry-common.h>
+#include <linux/kmsan.h>
 #include <asm/asm-extable.h>
 #include <asm/vtime.h>
 #include <asm/fpu.h>
@@ -262,6 +263,11 @@ static void monitor_event_exception(stru
 
 void kernel_stack_overflow(struct pt_regs *regs)
 {
+	/*
+	 * Normally regs are unpoisoned by the generic entry code, but
+	 * kernel_stack_overflow() is a rare case that is called bypassing it.
+	 */
+	kmsan_unpoison_entry_regs(regs);
 	bust_spinlocks(1);
 	printk("Kernel stack overflow.\n");
 	show_regs(regs);
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023119.84ECAC116B1%40smtp.kernel.org.
