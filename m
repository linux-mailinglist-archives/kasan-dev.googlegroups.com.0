Return-Path: <kasan-dev+bncBCT4XGV33UIBB7PD7WZQMGQEVFF3VOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E1E991CAA9
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:26 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5c22485b47csf1201178eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628285; cv=pass;
        d=google.com; s=arc-20160816;
        b=yjUk2HHN2Eu27h2tDLIEunafSQOaGBicTWahJrzZpUS+yUh3R7H76dQqf83DavUiMS
         xtwwqBvJ721zm7OddN+tnKoyoDLuD1pa+egWrJLNu4ftM4scKaL2BH/xdmwEt6HIfe/a
         HV1MUFDeSFOt0SZK/iWGNSt9yGZHzVVbsXN1qrXT7wFRriFezuvvPyTIXFvytqEWbNke
         nOnDFWJEQ3JvlG5LcXNvio0xhAYl84+OO5CGU5C1Xv06tLJnpEz8dY8scDzI+YZM83FS
         uD6Wc87Ato4uPkc+t2E3M3wzz/1MQKFAcvplFoSf2gQdD7Xy1tMtBI0T0fsbe18i3MHn
         TNeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=UmxCu/OCaMgbzCPiYTjAv6wcVDrAEur0F0WkhkEVAF0=;
        fh=nDEDx3j+pObGt06YPfGnfnHk9M7xnGMN8tAfXIALXUA=;
        b=v4FykiEUTaywnJVVnyU2NF5NHizomXEtAE7IdivQj0XouC00qKfRjb7JB1xcb7mi6c
         r9eT7ZLZqeBdKg8h7SDe2h1eGsadgJV2p3QtKA2VSYrelm+AftGnIqGRMYircptdkfIK
         BVVNJANAe5Lzphy8zWMkCg7Bb0m7aba8qbt04t7JUnemuTkGHS010XVdm7sYfplNa3BB
         IsKCx1a08Hk138iAQsvTrNaGZgvL/GhDKxLKGH21PJgedsu9cHM6QtJPiALGr79ybToV
         D+tI3GVNTIlFzXI69XQTYbZJ577xr8e1oa8a0grv2+lSJ9RJCvq4tv5UA04LYjJeQjVj
         7YcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=cOTwCEqa;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628285; x=1720233085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UmxCu/OCaMgbzCPiYTjAv6wcVDrAEur0F0WkhkEVAF0=;
        b=v6NbEeVaDi/3UzHZIldl/Z2Sj38chUT/sOCYY9Ztc+f0ymFZx7dBg49/UH57pI4O2j
         N1TJijNjfJhaoOoJFcL6v7czA5LQvxS5h6gpfLJBg+Y2VH6mpopSx0CN27280f0feUkD
         1qJp6AVbs0trYim7uaGWYgmZd0mMEH7blpLBE/IOU4JSoTbujkzvAnRELpXXJq6eQkP5
         R1seeXIDDYFWs6HF3p2AXzM7gjEsEDjemEA5Gf8IsbPmz4ZGZybJkhG+/lMPGRTcxZex
         j7RszgS+WHgkVuDqEnK8ko2kZMOXGdze2fY4R+r6RWr04McGyG3pdTK/t2rZLpCLJIHA
         i2Eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628285; x=1720233085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UmxCu/OCaMgbzCPiYTjAv6wcVDrAEur0F0WkhkEVAF0=;
        b=Eh0K6KV0ZJ3Eos2iLv9vU2cY311A5w28YSdIumQCVH+wsJ/f5iXS7+6wp++mWeNmkV
         3MUUQEN0mHcGIVLwAEY3cuPOfOmGxjhA4GXxHU2bTb/lj7ULY5Zu6ZtutK+BP8KlEKl1
         Hr7k/YGmlpQ7l2e4wJ2n7nFbq1eS4fJRDWJfwQObMlM7H8mLktlNjqYsljoiPPKz4A5r
         5Oq2obbKT0izaWxB4KyV9Pyo7hloAJGvbSfj87H8oqMBCdzUNsNKvBxVU26bPKIGVHfP
         MlOeOF6ANmNsvjI4VoqEV5r2mso2VZyCT/CIZiQbOuiSM+tZcPd7bNp288KyZazTg8Wv
         ylqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWpI9IVYahGLPkkHlYgHBg2g0dXUCwfgvuNY6QvJGB7RcyfJPNxxmCmj/lNHuyWKzis62Aji3lZIaniEWe4v8WqQ9j6f+6xug==
X-Gm-Message-State: AOJu0YzkSDWW3zxBOk3Bjl0Ni0T76JF9D2/PeFK7lTxXF1nZzxQmfzJH
	EYy8WNZdQaVwQxu47EWUtbKRPpmZ9WoK2Y9KQD7oTnEQpxebUYz/
X-Google-Smtp-Source: AGHT+IG3myOCPTB03xarBUB6jviI5RCQwLERVdO24z6mQuVT76Srl+kzimy76sMteiTdhiGgY8OCgA==
X-Received: by 2002:a4a:1541:0:b0:5c4:10df:c479 with SMTP id 006d021491bc7-5c410dfc61bmr5564333eaf.2.1719628285211;
        Fri, 28 Jun 2024 19:31:25 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ad8c:0:b0:5c4:ee1:8321 with SMTP id 006d021491bc7-5c42006fefels897082eaf.1.-pod-prod-09-us;
 Fri, 28 Jun 2024 19:31:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1wLrafq1iNBZogc9hQLOtM47AwphajvXH4YNb4JEOO+1XedojDav/fRaDiUXc6yhDuu5ovcIA+LnhsARo/4nZxzG1M/Qxk97WUw==
X-Received: by 2002:a4a:5584:0:b0:5c4:fc6:c7f5 with SMTP id 006d021491bc7-5c40fc6c8cfmr6230306eaf.5.1719628284381;
        Fri, 28 Jun 2024 19:31:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628284; cv=none;
        d=google.com; s=arc-20160816;
        b=GhWN4P5MGkDDq7k+paR0RjrbbzzIhAfbPczhXJozBhFtnEIr9jsfhF57K37HIrrHif
         4hlgNQs6tHuKiCVtdJN27eVpVV6YGmImFbZXrS5amTGUm8EhjiUL0+wn6i0h2OAE9faE
         dXE6t5SgQotuSNfSKGYdgKcXAflxa3iVXDI5h4GY6H/shL/23Pdgna60JIOHCkUoXR48
         C+6v0PQrn3C2uQaaQSXmHabcxxEScgdN6fH1FpXkzCA6IkAnUKqeVL6LOjMNwOkLt8da
         ezFFz4BZQWSIyMmHn04i+8GTdGY3DmMC4TVnbkRZ0I3PgTigXELeVqxpmeBL990bFz7a
         Ys9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=ET1hXfhAFPoqFCGcKWMmioZENLpbULkiuV0x640Eu1I=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=GiHsql4XYqC0J7p68beAiiRay8chTrrUPh6Ux8ysk0Qp+kptnApcqVyR9RZHG8GBgc
         3Gg/PO1RCx6wjYv/x4MPTcRY83/HB1ybuQHrZGdUFv0NWOURnDfkHuphZRR26PHOQjTE
         DBNpf9C4fms3POYTLla3So0D/MIYxJ6sh8rsDsqpSbH1qptOWN/KYsTt4r57btxODeo1
         BjUfLjVowjY5Whyi5JI76v28Gq4y//rbn3fuUucz6LU1ceq9Z2QsN51dT/BoYqLrlgMb
         /+PR+4RZu0WZGjapvHkZm+95TyVkt7rc70dX+Ta0wVyDbbdDO6HD99iUgsNJtIvByJVA
         ubjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=cOTwCEqa;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5c4379fc953si800eaf.1.2024.06.28.19.31.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 2E5B7622C7;
	Sat, 29 Jun 2024 02:31:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CAD51C116B1;
	Sat, 29 Jun 2024 02:31:23 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:23 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-unwind-disable-kmsan-checks.patch removed from -mm tree
Message-Id: <20240629023123.CAD51C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=cOTwCEqa;
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
     Subject: s390/unwind: disable KMSAN checks
has been removed from the -mm tree.  Its filename was
     s390-unwind-disable-kmsan-checks.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/unwind: disable KMSAN checks
Date: Fri, 21 Jun 2024 13:35:20 +0200

The unwind code can read uninitialized frames.  Furthermore, even in the
good case, KMSAN does not emit shadow for backchains.  Therefore disable
it for the unwinding functions.

Link: https://lkml.kernel.org/r/20240621113706.315500-37-iii@linux.ibm.com
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

 arch/s390/kernel/unwind_bc.c |    4 ++++
 1 file changed, 4 insertions(+)

--- a/arch/s390/kernel/unwind_bc.c~s390-unwind-disable-kmsan-checks
+++ a/arch/s390/kernel/unwind_bc.c
@@ -49,6 +49,8 @@ static inline bool is_final_pt_regs(stru
 	       READ_ONCE_NOCHECK(regs->psw.mask) & PSW_MASK_PSTATE;
 }
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 bool unwind_next_frame(struct unwind_state *state)
 {
 	struct stack_info *info = &state->stack_info;
@@ -118,6 +120,8 @@ out_stop:
 }
 EXPORT_SYMBOL_GPL(unwind_next_frame);
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 void __unwind_start(struct unwind_state *state, struct task_struct *task,
 		    struct pt_regs *regs, unsigned long first_frame)
 {
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023123.CAD51C116B1%40smtp.kernel.org.
