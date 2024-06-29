Return-Path: <kasan-dev+bncBCT4XGV33UIBB5HD7WZQMGQEFG6EQAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 24D6591CAA2
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:18 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-79d112a9f8asf140104985a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628277; cv=pass;
        d=google.com; s=arc-20160816;
        b=IPQVu1qHjs9tWoj2dFyYP73JCnrkVft/6Cp5iBXu6o2fBXiOwqurMj11OU8kT2IDnq
         WZ39FXmg9EKYgxUM7uXXbYzYO+mbM56Ih4GG3uS6SQIoJEXwcMiCdoqLAcW5cIBt0RKp
         qvlr0x5NbJgboBn5GzsXm4cOhox6eU4UNvfdcGC4udEF80zU36qwHuYi0AH4H5hbU48f
         EvxfDK0F75aCL3yaZBtljKlEeZKrxEun8GtgKIfv9Ju3ArCdfFgEpDPciG+ZkcuZlcPW
         rH+RJ8879fbYlBpGfCLTUmj6BxfyudVt5kzfBaqCA+EkAtbfroLeyz+7b4NZlfQ8xD5T
         TXyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=LaDcXjcQiyL6SdKK9xbN/hXuSUnfBt+IG5ipJty/GNA=;
        fh=12I83a4elvrWvAgJ21Q3ntzY9yMlIOjfYkIAT1gco34=;
        b=O0pAPEd+Nva2YLagK2Ndc92vHTT7wDHGfKLMj6TEAh6zQEqud/hJw2W3TrihjPYaSN
         ze5V45efdqR5EwmbVo9vLJV/jQSbDV/CkppeB2kCeUKr3bHTbUNvbkOB/PxFt88Z2LVT
         8+cB213TiL9A24yiYMFh+ZrO+viQEPbP2MK4SBMXIz1HcltxgIHl1qph4Z6kKzfLlTwb
         JN6SadgRQihnUWSh6tjnXQ1TKbkLNrWL7UCZZHAT31e/ZJWWLpCfISCt+2AWrUGxnuLQ
         rsPI00Ksae8B+fCLDudjaekH3JY8ej7YEShQRXmHHshvEvienYh9XKDRY3LQLeHo+iE7
         7FZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="OOW8u/1B";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628277; x=1720233077; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LaDcXjcQiyL6SdKK9xbN/hXuSUnfBt+IG5ipJty/GNA=;
        b=Y5JTTTF1Mpwo8Hglw2ClBKKDZH+0A4w6hI9mUNIj1ibV+PxdnbWFcbQvIfa+XjCYN9
         I25OJrO5VJssC8TUufaWKd5x/Nuw1tk4AGMxrpZEdpeWHogG7lO9MFyF5H/90oGuVlzI
         ZBVlxKwfOrkW/tjLA9h+WSbN0q/MRdQFqeEJRvqYWusgQKKRWMrUWVDG79110FAh/1p0
         lEbqZMTZ6IQZNDfihefjFaWGg0gNavCkMLuQL67TpeAfommipH7FlkxsAa7lVStossvd
         LiRh2aEoCfUsvZWdqVvVcaFpVRAhTsaGEABaljPWiX4m8gYyknoJXSHAsMQ3BTPT2lT/
         PJGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628277; x=1720233077;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LaDcXjcQiyL6SdKK9xbN/hXuSUnfBt+IG5ipJty/GNA=;
        b=gx5raOFnuJ7HR9068nUSYO7a2lH/2s5cbIs2ZkXk/kt5YDxrog+O7GkW+dSzu6PoEy
         gMqDF0oLOORdfjvrNsGVN4IHLxii/0VQHEcodCBE2x0bpYlc1flTjqHkjVZBgO7hHBYG
         JnoisAppsLjz8Fu0VU6TVyvKCjpAj+K7aOXwozExYSj1qdSMlAvYe097d7kC+dSH4djb
         pM3nGYk2K9nrgR8wc7510HK4IPzoRZlfxxo79++LUFXS7SfJGB+Qobhap/pLxVyh678I
         Ns/A/Sio33HUy6xhvuUUufjYvckozY+I49CDbuAFyfMyC9shU/YU1doX+Sfc6ZXFfeI0
         Qj8Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsbpSg9bLaKsJ0BuqtD5grO4+nsamVwUVnkB162FHbP/85rB6N3CRfszzNBz8rETbAtiG5EnnU8GeErn1rckDNfWN95vmz/Q==
X-Gm-Message-State: AOJu0YwdVcUPaDsjmB6FrGnq6EwXOOP6wYRnPOrLA4mCz/PutP3475Vw
	HCNdW2yS90zdI+dBc9FdpMvaFgXUVgpWtv1sGAHyMAHiJQCNZ0mK
X-Google-Smtp-Source: AGHT+IG8dGXuMZEHJuudJBFh6KdAqeKUrKoLjG24KrfCgWj3L025zmZjctxxkCsDfr4olhlmM1b0nA==
X-Received: by 2002:a05:620a:88e:b0:79d:6cdf:c3ce with SMTP id af79cd13be357-79d7b9ac09cmr2170985a.5.1719628276986;
        Fri, 28 Jun 2024 19:31:16 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:f2b:b0:6b5:684:b446 with SMTP id
 6a1803df08f44-6b5a4c7441els17754096d6.1.-pod-prod-09-us; Fri, 28 Jun 2024
 19:31:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWhIiROsqWYDUbSBfpG8q3UuwrW9HZJdYLsBdr47jXre6Juf2YRKxXhb89D9JeLlk754LWaAY756xDQKt3sVvL5KSgovy1Do5Rx7A==
X-Received: by 2002:a05:6122:1b09:b0:4e4:eab4:ba2a with SMTP id 71dfb90a1353d-4f2a571a84cmr51481e0c.16.1719628275732;
        Fri, 28 Jun 2024 19:31:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628275; cv=none;
        d=google.com; s=arc-20160816;
        b=RrV7aBTypeKpN3dxINO5TZb5B1LUBkM0vd17xOXPKi7pkcDmux2TnH8T+ljzTY2hJc
         zl9yvqEhhH4jT+RZs2WWz237JW6fsP3REe8xQowxCVvWpTYinqCp27jSrpA479sqm1WI
         LU/UKJOe4T9m03uX6IJekSjKkF/ucCa5p2/clnwTzbbmDCokRvV3i+1MrKKNOcZ7Tcyn
         mE0O3c5gRE52Ze0Dfxy3nR8kgQqaCZ9iUjxhYBk09H5/n7C0v1xzRUc1swGSYRfnSZkK
         nWFYK9xeixGM2P0Lo6gr2QI1wOtKRF2KX7abBmiOQcW1TCRwlONZqV7b5J7MoZnPzTSv
         nPaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=+W74XABcx4oczmuR+F94AWWcGbz9DqRMWd5hZhy8+7I=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=aJGt5nCLZOnyM0Xhbj0Btb3IAEYvl1W5qlrpPUkkW8+jh9sbgDkWa8FEQ3uvX6fUvV
         /y3kh8g6QOdxhPZTusyNwRN6QJVVxhjZAJR6UKzn7vJ5AfzPRLEOiJawcpwmR8a8Ayf4
         tXx3Ni5+JzgO1iCK3rpKn6FWA8IxbAAe7H3EAef0M4ddEoiIm0mUO/cQKfjb1yH31p/Q
         HtBwrLgb/azpRZrq3XHNquJkAdZkI1vBWNgRChIsT3XBLMtqlPA4RrVeFAY3FHVppjmC
         aqq2YGiQZulol4Jmcv4OP1KH/kXi9jDwsX1QSIWjWyNtZWqfUe+ll3vLjodPj7/qo2aA
         AL7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="OOW8u/1B";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4f291624c06si200258e0c.0.2024.06.28.19.31.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 45241CE4334;
	Sat, 29 Jun 2024 02:31:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7279DC116B1;
	Sat, 29 Jun 2024 02:31:12 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:11 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-diag-unpoison-diag224-output-buffer.patch removed from -mm tree
Message-Id: <20240629023112.7279DC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="OOW8u/1B";
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
     Subject: s390/diag: unpoison diag224() output buffer
has been removed from the -mm tree.  Its filename was
     s390-diag-unpoison-diag224-output-buffer.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/diag: unpoison diag224() output buffer
Date: Fri, 21 Jun 2024 13:35:12 +0200

Diagnose 224 stores 4k bytes, which currently cannot be deduced from the
inline assembly constraints.  This leads to KMSAN false positives.

Fix the constraints by using a 4k-sized struct instead of a raw pointer. 
While at it, prettify them too.

Link: https://lkml.kernel.org/r/20240621113706.315500-29-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Suggested-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
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

 arch/s390/kernel/diag.c |   10 ++++++----
 1 file changed, 6 insertions(+), 4 deletions(-)

--- a/arch/s390/kernel/diag.c~s390-diag-unpoison-diag224-output-buffer
+++ a/arch/s390/kernel/diag.c
@@ -278,12 +278,14 @@ int diag224(void *ptr)
 	int rc = -EOPNOTSUPP;
 
 	diag_stat_inc(DIAG_STAT_X224);
-	asm volatile(
-		"	diag	%1,%2,0x224\n"
-		"0:	lhi	%0,0x0\n"
+	asm volatile("\n"
+		"	diag	%[type],%[addr],0x224\n"
+		"0:	lhi	%[rc],0\n"
 		"1:\n"
 		EX_TABLE(0b,1b)
-		: "+d" (rc) :"d" (0), "d" (addr) : "memory");
+		: [rc] "+d" (rc)
+		, "=m" (*(struct { char buf[PAGE_SIZE]; } *)ptr)
+		: [type] "d" (0), [addr] "d" (addr));
 	return rc;
 }
 EXPORT_SYMBOL(diag224);
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023112.7279DC116B1%40smtp.kernel.org.
