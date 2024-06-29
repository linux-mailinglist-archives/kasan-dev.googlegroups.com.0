Return-Path: <kasan-dev+bncBCT4XGV33UIBB2HD7WZQMGQECXZN4HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 7498291CA9A
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:06 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-6c8f99fef10sf1078540a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628265; cv=pass;
        d=google.com; s=arc-20160816;
        b=MRY+Th0yS+XxAMk9rh29wqyEknwUbMgylsGSJoI9bbrCEussWpxUjnIPSh9mjtsFlQ
         0iyfL6Wj+B6ZuMOc0QzaiinXAs4heBLqpztqTbXbh8/JC9b/Ut+l+YZ/MlCv7HltvDdt
         iUQea8XEc7Kvc/4mtbWJltHWWODjWg70Nyb+dF2qeLR+AuKi21laUKpDQ4mxI5X490dq
         rCxam85jUIf3+BI7z4uQrvBWeItdkw+4Ve7xGAlCtOWF4aXBYX9YHRC2fr6ZQJpkicHj
         pcFgtyMsI/yDq7cswWScxHoJAmcJf5Y0Yk16TnuMWJ4Eu5p9ciUrBwnzTUbCQBJxGPXJ
         JNsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=duN3CFWXVuK+eufeKeGvl04qE5DGFsmxIzf+2FdnFYs=;
        fh=eF+YVFN5l71AkadzcwQkM3p6JArrR1xFyjJ0aJth+Fw=;
        b=sfqwV9jz5tV5grGQVqAKctpJsQy2K0YCweya6A50GBaz5CjhVUoTy979OE4qfncqM4
         b/LCtqyiiJOsBkfw6gYAHin21Hpx2jrJIi7hHNbAIsOiKkoG25v6pzrr6DuWgTG+kT7s
         cjgrET11wMNJUTk8og1aRzQpM5iZ+sthUZnjatEjmfU+pU8W6psX3beciGoUcSsKg0/u
         4eDVuXhz0EtsEUECBnp2Y8lcd6CkJiG2oRgpWgSOYPylk0Vf8Ql0ig899H4AGmcp9nh6
         Xt3DMOplWzDOnEpAPLjYegnE6nSO5Eydacu0Lz5F/4mTxbEiBxUqa/5gEN6KxwJDpIlq
         sKcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=TGdyhHgU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628265; x=1720233065; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=duN3CFWXVuK+eufeKeGvl04qE5DGFsmxIzf+2FdnFYs=;
        b=BElgrktpsb94UxCEA5Z6EK8tHnPThZ+Usbqge/D8houG+WS6mxx+S4U6LeXUvs9DYo
         9OSAchY/DvgMycSmWuJHEVPq6+PACpnqfvVf9hB0rCjq+zxTape4q9+v1Y1eIDnlgu1C
         STN8ZopU+HaCMK/zlZ8ADsgBexvU5cxILT/GaCYn/mPAIU60fDvB/40jZEk7ywrMMVks
         GcXnbXsRqrXo7xuTEOYTVbDBFm7xbK7fGc2Vio8oXsASwrvS4cxj2AYgdQER53sZVJTD
         yBXSSbeni41YDazYIOMwyppPw/HpOo9+fUr3tnmN3MrnTCh2Iz4k3YPg/sFjizTrc9a2
         4zXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628265; x=1720233065;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=duN3CFWXVuK+eufeKeGvl04qE5DGFsmxIzf+2FdnFYs=;
        b=wTJ+OaBf2k/T6f1gXKcEcdF5saqGnWBgJqyF2HCMmOfiTg5U8/NtQrLf98B1zOWKLp
         y5YTxnmPIBAMKG3KKYDkkoDgdACE0mKLyQs8FTXkvOV4hhIOhTqFqS5uQGZzo/9mozB5
         pRgTYG2EqVbWCC7puB97IL3IRRjCa6Jps5lw0MpJbdVsGLio0Q+l4mHOcUoEP1n2jFbm
         f42x538V3Du7SYTS2VA7SiOju3lIFQYxbXpGWeTKyouBwgG3RJhAXNvVhfJd2B5nwK6h
         C8MwSLuZsoBl2YJzmZD7pvg5PdJ2tFC+CciMxEfJa3JirIWY2K5koeSCgHU9Do020J/o
         iePg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUwJkSDLCmG9QUChysOFtHL++3x+gtDs0hFVFSmORgacipddn19qZc7NUeOswr6Hk0f5zYSAEm/QVy+42ttCNQJEmgDjP7zUg==
X-Gm-Message-State: AOJu0YxebZkytqwW0fpQL4MloZpYOkW8u6/N1e0P9hulNPmMXtCRngDK
	jS1cq2pHgkiltprxuHkjBLw5qgE9sfR5aBvGOPWoy8QDSxgPDEZ2
X-Google-Smtp-Source: AGHT+IFodVqmy9zXuUp49wQpdoCLQ5joR0nE53nfNEW++OJ4FCesVcT3L+4U8UbqzW7tPzn17DCqsA==
X-Received: by 2002:a05:6a20:a124:b0:1be:c7f4:b42e with SMTP id adf61e73a8af0-1bef611cefbmr89135637.20.1719628264839;
        Fri, 28 Jun 2024 19:31:04 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b46:b0:2c8:1a7f:5bc3 with SMTP id
 98e67ed59e1d1-2c921c48b54ls680823a91.1.-pod-prod-06-us; Fri, 28 Jun 2024
 19:31:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCNGgQiPXYMhRgemNeGJLhCf9m3UPgVzi8yGJwBe7N0a6387s2OTmwd7xf9teR88N3/1F9lW+DACiCjDzmKX8bCmykQpJNKMEuhw==
X-Received: by 2002:a05:6a20:a106:b0:1bd:2a21:fc1c with SMTP id adf61e73a8af0-1bef6216dc9mr84984637.50.1719628263566;
        Fri, 28 Jun 2024 19:31:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628263; cv=none;
        d=google.com; s=arc-20160816;
        b=h9nGgAWE1G04hGdmE9y1wCsHDP8J073aDvevVB2JsXAqXSiA4JW/l72CQ6A1ujKry8
         fnO8FWZuX+Ms63I9clEYyFrGynlt7npaJ9Hh3Eo+V1M0+XvsQcOHPVsBznuQfgPnCUQi
         xQGm56bbmYItfnuuqcyP0NO5c9jh7pFPPXUaxqE0Rl021saC/6KgisTUd1N/P10ERu/I
         CxoMH88MkN1X8ke/oHwHaZNhNzfyN6VlDxkhayWV7SLAa+4RmW4RgSvxDLkGhTU88zyS
         MTdZ7jI/y0Xpgi++3mwiLOWYtAVgImDjhh9DUAONrsMArxHItuWznCx6crtuk9Cygljd
         X8mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=ArnokG4ib0TRDj/07SNTykMfMIs+zrwD5SbdsJzyRIA=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=J2eyTJmVL+RLKZLVm1rjwXu7w/FZnul7hCM/PBESMc0HDZTLqLCyP+/em2A95whO1X
         rQWeKqq2WFqS70j6usUor2dGYZCivvWRhVNieg8O6kEOUOFxLQJZvHO7p/L2rKtNwh7x
         7+c9IgqonM2+vh6kqHJw9nJksXLlSumJPWi8qPGAF4AFq7AE3UaGX2MkI2lxrDM41gKJ
         3YW8M7vLGzfLoS4Ox4esODWnEWmffvfQfIMx/btNOH3wwM5J5lWiwgalsnXZc9NgQaQ5
         HuhVfShKfhgwm+6VfgRFqjF8pyVNh148u34o1ijGwoqjYPOLtSi09ZxjOmWmskx/HfPX
         ZfXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=TGdyhHgU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c939cbf109si47475a91.0.2024.06.28.19.31.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id DA657622C2;
	Sat, 29 Jun 2024 02:31:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 833E6C116B1;
	Sat, 29 Jun 2024 02:31:02 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:02 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-accept-ranges-starting-with-0-on-s390.patch removed from -mm tree
Message-Id: <20240629023102.833E6C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=TGdyhHgU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: kmsan: accept ranges starting with 0 on s390
has been removed from the -mm tree.  Its filename was
     kmsan-accept-ranges-starting-with-0-on-s390.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: accept ranges starting with 0 on s390
Date: Fri, 21 Jun 2024 13:35:05 +0200

On s390 the virtual address 0 is valid (current CPU's lowcore is mapped
there), therefore KMSAN should not complain about it.

Disable the respective check on s390.  There doesn't seem to be a Kconfig
option to describe this situation, so explicitly check for s390.

Link: https://lkml.kernel.org/r/20240621113706.315500-22-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
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
Cc: Steven Rostedt (Google) <rostedt@goodmis.org>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 mm/kmsan/init.c |    5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

--- a/mm/kmsan/init.c~kmsan-accept-ranges-starting-with-0-on-s390
+++ a/mm/kmsan/init.c
@@ -33,7 +33,10 @@ static void __init kmsan_record_future_s
 	bool merged = false;
 
 	KMSAN_WARN_ON(future_index == NUM_FUTURE_RANGES);
-	KMSAN_WARN_ON((nstart >= nend) || !nstart || !nend);
+	KMSAN_WARN_ON((nstart >= nend) ||
+		      /* Virtual address 0 is valid on s390. */
+		      (!IS_ENABLED(CONFIG_S390) && !nstart) ||
+		      !nend);
 	nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
 	nend = ALIGN(nend, PAGE_SIZE);
 
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023102.833E6C116B1%40smtp.kernel.org.
