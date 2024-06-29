Return-Path: <kasan-dev+bncBCT4XGV33UIBB4HD7WZQMGQEJ3ARETA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A5E5291CA9F
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:13 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5c411cc2757sf1256536eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628272; cv=pass;
        d=google.com; s=arc-20160816;
        b=qOE3IESXg38Y1g8Y04LkqMGi9ZGvZwxb6D2GKZoqPPMLmCHvd3jFCJgo/p8hjCk7GW
         V9K4WQ3msH9Flp2DZ9ycuiYl0Ud9MTerkuFDvkcGetMnGuUD7Hp1Jyz62PKLx0Z4JZOg
         9Bp/zW9Iu18Se7GpPSOftXdmVji4Egf8Ct490yfG+w/o+fceDElJboImlfiyTAO0hm9/
         TA6PAvQcg8kr5oWgwwTP7eRmY7B9NnBe4YvN9JahQ0HOuAmR7LWo2Mg+AtuGmBVTcx/1
         6hy42ntAxBEicD8Ab58QpRmgBbVQ/uiFD8yEOaUNeytZ9v5FUhDxvELJc+3qLZvg7XxZ
         wblQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=eNlyChQvQ6YuhZMte80fK+3XYoq/XAa8seBCE35T86w=;
        fh=yUIXsTPtXnipkfh2J73rLPkKY5LpjMHMsFJ0ff9dioE=;
        b=bNvtDaG/coXGe2v1Famdcrug0jLyTlKsk1YRnQSajjUYuGeCMecU+4rdOoNzpfP/KX
         QX7MjHK5VoLY0YxikPCrlok+htmrL12IVn//s9ATzkyITslyNevx/CMjs4RsfL3362CX
         CPi8+uHoQGfcHdR1mq73MEpXoqwDgBkD9aEAR96FJ606IfkEx1KpmjLaetbpt3k6Xf08
         DVgZTcU20MN9zzif+Gs9ec7mImj1jwaRSBMgNHLTfBTARQP2o+kOeVUerYZl4Xj9G61v
         6p6UiKhFkQrpX6OvMuq/8FP1WpZ5RxHK2uJqd5BvZGvn9bte2Yx19dywHSdtUhNk3riA
         eJ6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=l3K7sHj+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628272; x=1720233072; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eNlyChQvQ6YuhZMte80fK+3XYoq/XAa8seBCE35T86w=;
        b=BB8XP5UrjG+VT583tn1LCYLwft8+NG/y9zxz3rjIyM7XALCWvvxWm7ZZMEWXVPWErR
         V35PTqLfWWiFr5AH+bQ5T3UmRwLwjDl0PIbdeTn2SpV71tvbrI6URVp2AUVrfEL8Iloq
         nOjQ+SFcdaRoUNGs44Wi4p07P2mUY7ewXC3OrvWH4dlfA+u/1USgpa68lm6y98Y/oaxw
         AF1+KW32mazYWudhhdcSc9BMjXv9w3MiLt8aTK/idFoq9mULuFEAr4zhncz7vcB+KREm
         NDLWr9Q/hfPLDpi0QRMBtzKG6QZY5tbROjZyotUWFobGuPKb3/K649kaeZsfjn5G7mlY
         vEDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628272; x=1720233072;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eNlyChQvQ6YuhZMte80fK+3XYoq/XAa8seBCE35T86w=;
        b=vFJmyQa4JrLVzAAfSy4JbEaobHG3Tcp3vv6t5/UpIsch6PbXvRBvkYp1FInKedItnY
         KFBshE5Inkhiis6BTzPLx3kjzGhVQr3zxz8tIrGMv20/OMLRHi3HV5fPuFU5/i8ZF0oY
         g51FXRQGRCayDr9tA2JncsZVa7/Y8Sxxrn+RRMnC91Jv+M23iBSPcxjb/WUkaiDKtQtU
         0xLTHOLp/qL0DflqcmRPZm7+6Ok7oWGvW8lBFnR27OFOIAicL56dr9T/5D9INVNZQUv3
         ODGck5o9NfXTLsl5btSgWmng5S08t3ZlqJXdcXjQwnxixHoFYO5p8VrPG2qTR+6QJesn
         XBFg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVjHcxS0OCzAChNKHWL6jytOawrAyprGRSZwSZy5O1o7lsKjgN7byBF7Tnd2aVG+Y4j1p9AfCC58C7DRy62Fyemruns8uFVDQ==
X-Gm-Message-State: AOJu0YxHOzkiHwrK5oGHCUJqZgNt5lPnK8PYObTDB0dLQ0pKcQEh4UP9
	mT/ALnxyeK/dzAJXRVOFZjQiYQrTabOHnACjKuYcfTOYwd0+lGyb
X-Google-Smtp-Source: AGHT+IE/Xs577OJ0c0u7kbt2GdKoiQ0zF79p6CJ3dklidTAwuB4Q/g2fDzbp8rLspdImk21/J2iMHw==
X-Received: by 2002:a4a:5a02:0:b0:5c4:2eef:262a with SMTP id 006d021491bc7-5c42eef27f1mr1061352eaf.4.1719628272364;
        Fri, 28 Jun 2024 19:31:12 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4885:0:b0:5bd:b810:a87e with SMTP id 006d021491bc7-5c41f1667a8ls1026943eaf.0.-pod-prod-08-us;
 Fri, 28 Jun 2024 19:31:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVUjmP/Q/xMr504HCmOanRRUGp6/7Y8wOJ+d5eTdi+GwtuwibM8f7UJgSEZKo1PyzsDBXt4xGTs6Ad/03NowDLisPh48q+9jKNnBg==
X-Received: by 2002:a05:6830:1653:b0:701:f18f:77f1 with SMTP id 46e09a7af769-701f18f7a9amr7721960a34.7.1719628271591;
        Fri, 28 Jun 2024 19:31:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628271; cv=none;
        d=google.com; s=arc-20160816;
        b=QJfKL7tPj97GFdCpW8Ym3WIOVOZZzevhkGqDWjpF5VzT4jog+iwCWqLyZDgw4AEQ09
         tBFLJQB4BB5PB6IXpJQxQaNHQJ+MRgO2KR64cS3OJl7rx1KbCNcaCmrB3NCjTRSbU+EU
         l7K/73r79WqalyaG2yc1agqWnkj/N6e7OGUFLN6hEljfAzxN3belKIBbc8vWOLuV3hGy
         BTfcnL6X/Y921hP6URwtPKeTyxldjZBFjFUZIddpLIouIMUWf17UyM6ySq7W0jfuRIOU
         1bIROAp+BmhOhFOjd3wqBOeOivF5PXVTE9NleonlfA0phjwIP1LyfUIK54rxeCkVgmh2
         sdFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=xfEcqlhQxJ3EiHqAaE5qVRVuCji4rohlCmtPpjrjJOo=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=C1+X2iRERH21VM3Vt7Mj5kLaSaMNj7WPKiuqVPXaVi98toAfY8O8I744Z9ZAj7Q/nR
         l8AThxb5rVS11WS2iQUhR5HvK4KWY/dpooHUBTwT/u63pDBFupUZFgNiplyN/61kGuel
         +3r16ckTcMdhgNSy99QLlRnCQFNa5d4nJX8J5R6ZKYaoAeKaq0yQVI0sxR8Pd/rEBAnD
         o8mwyaytVvFjbWjc9aK2sgzg2o52/QLtDS26tQXuXoEtd4QBF/EoU3jRC99pnbwE61Hp
         V0Hw1GbnyD1eMVqzSspTK0VAOUs2J3zvThht4CZRe/F/K6n7Z3k8fddk985ZY0sHE2qy
         D0lw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=l3K7sHj+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-701f7a974dbsi135963a34.1.2024.06.28.19.31.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 611DF622C6;
	Sat, 29 Jun 2024 02:31:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0A6E1C116B1;
	Sat, 29 Jun 2024 02:31:11 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:10 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-cpumf-unpoison-stcctm-output-buffer.patch removed from -mm tree
Message-Id: <20240629023111.0A6E1C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=l3K7sHj+;
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
     Subject: s390/cpumf: unpoison STCCTM output buffer
has been removed from the -mm tree.  Its filename was
     s390-cpumf-unpoison-stcctm-output-buffer.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/cpumf: unpoison STCCTM output buffer
Date: Fri, 21 Jun 2024 13:35:11 +0200

stcctm() uses the "Q" constraint for dest, therefore KMSAN does not
understand that it fills multiple doublewords pointed to by dest, not just
one.  This results in false positives.

Unpoison the whole dest manually with kmsan_unpoison_memory().

Link: https://lkml.kernel.org/r/20240621113706.315500-28-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
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

 arch/s390/include/asm/cpu_mf.h |    6 ++++++
 1 file changed, 6 insertions(+)

--- a/arch/s390/include/asm/cpu_mf.h~s390-cpumf-unpoison-stcctm-output-buffer
+++ a/arch/s390/include/asm/cpu_mf.h
@@ -10,6 +10,7 @@
 #define _ASM_S390_CPU_MF_H
 
 #include <linux/errno.h>
+#include <linux/kmsan-checks.h>
 #include <asm/asm-extable.h>
 #include <asm/facility.h>
 
@@ -239,6 +240,11 @@ static __always_inline int stcctm(enum s
 		: "=d" (cc)
 		: "Q" (*dest), "d" (range), "i" (set)
 		: "cc", "memory");
+	/*
+	 * If cc == 2, less than RANGE counters are stored, but it's not easy
+	 * to tell how many. Always unpoison the whole range for simplicity.
+	 */
+	kmsan_unpoison_memory(dest, range * sizeof(u64));
 	return cc;
 }
 
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023111.0A6E1C116B1%40smtp.kernel.org.
