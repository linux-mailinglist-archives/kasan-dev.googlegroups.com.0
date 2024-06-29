Return-Path: <kasan-dev+bncBCT4XGV33UIBBU7D7WZQMGQEVFEMK4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C47391CA8B
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:44 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e035f7f715csf1111608276.1
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628243; cv=pass;
        d=google.com; s=arc-20160816;
        b=EF+wux9OULfnKySHOqMTOGDXR+gLq3QggN+l91xGM0KnrSvfUZ1wnOMlqcknCpTibO
         tt4474sFQ5MPpGuXHu42bhHD+5ASLr+JlUJlR9QMt56ZgB/8OzmZvDDMMsD6acOCxKzp
         JqCJxPwAm1/XSmofbzTMVWmsctDoYnER86H0b7ywFqNpWw6GbyuYHU45L2j+yx4JqZN8
         HDDOtM0Dcl7Ue5o6moy60I0w3oSqDJ5akFD7f/KDu+a8dEAZaeeZhnot54NkH2WIdoA2
         s1Ah0G5zz5l81ADNnNRPTeVoxbB807+cKIpBJY+sllKXpcUv6OmixJ38aAgN1HrJ3K7S
         Q15Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=mBCV4hoazpW16uQfZgMAHCGRaY1MlY/Z7Dxyopq4J1A=;
        fh=3r8mZ+ifXlmofhxUFsHk6TS3TZE//m4+Y9iRzdYKqko=;
        b=INxUz91tmiQguWrkILndAIDsgXpl8Rh5D+VeFYNFze7t2cpnxvzWtW8N7gfOLCiDGu
         XyTfIQTiKu1owGtqii4Pu7ocd7WlyRXGhIK1+i7SEPin6A0BQ0piwOWaiWtBGsDl2OSY
         D9I+R6frUQ+q7Itsma/aYpsBguseh0PaghpOl2tQlZF/ZG/5T1Ku9LXxGJPR93mVBLZS
         ymrASG6u1husvJeJNoYzpjvv7mOvh/pe4n3MwAWYNvOGiQqW7iowugIi1BqTLuOH7Wvz
         aKXlDr9mddbqL9VkjvkqvUOEl+LOi9N7Veb3uiWT8v8jheSMqJDvrfH+vry5JW4m6zK1
         5qlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="j24uv/Lu";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628243; x=1720233043; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mBCV4hoazpW16uQfZgMAHCGRaY1MlY/Z7Dxyopq4J1A=;
        b=o99IdvjY6ilPGc9az6XjilKlfxVXmnAf6Yuo+tNFBmW1b0tKiEUmWMYqE2JTils02f
         X7H+Hc6hzIFVPjxttQo7q+EBedbSdhv3a8k4VZTg/0cUsiW2x50xVo8zahYWPq1TpYAh
         iym9Eeiw88j6hCDBxTBe2ifNYUpuK7r3jOoFEGhMsU8ibbub0fEgbI9C+n3n94AfAVcp
         tBdzhREnW+nMXrgX50Om4nJwQbLnni2dz4PZZlHyuzgYgQ2Slq+4BsOdMWhBMc3X2IF5
         PK1RsW/fL9WHnGfZo2zt4iQZjCbBxKK2iQnAEki5jd/yVVOG4QIhYRqdI9A/1iJ1S9AF
         xW1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628243; x=1720233043;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mBCV4hoazpW16uQfZgMAHCGRaY1MlY/Z7Dxyopq4J1A=;
        b=AfK+P9/KQfrSWDYVca/z02zF/tT3wppqhKvrrpCQ1B+mL/YSJbDNrTxLXyrbOqVbCh
         b5dafLftFHUnGnU3XQ9/RKJAVbbm6HKSfiMwZWBXsmVRiGgWy2HxBOjRdCSZ1M02xGZ8
         QaPki+CjifmLun+impz15jY+uyoc6Vq0iiNisnmgwK8D7/rAGiatB1jKj3Hfhl2eWczB
         owsi5KyRheOj+kP+kBXcXq6Pdw7xgRNHBxbmPH60PmJCqtASBr1LH4Uu9YndB76i5/03
         mXPsqESjv5YMawrfmj93BjgLRtuPDkfCYbGT3Ciq/1xI/sNM2obyxVjtEHppGl5r5eda
         4Zqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWYAgt9Syd0r1ezSass6EEoqFIDRwpyUBWvmh/b26IQBHsHy8iKYHB3vtXNnF8p9RWDLRyQ80H2Bm2qK7+5nEVrQu/cfUWCPQ==
X-Gm-Message-State: AOJu0Yzb3CW8grHcQWKqvWKSMpEYwtTWh7WkES5KaxCrdWLFj4ks5wWN
	4FJxT7riS+iOUpRhXpH98N5NG0XB4vBmLrSk/PlEUrdjHUG3La40
X-Google-Smtp-Source: AGHT+IESTisEF7o5ESKKxia5VmRdG92ZL2gyWOjp/wA0l+Ue/zPN80V0w5q71FtrfFwB62CHangstA==
X-Received: by 2002:a25:9d08:0:b0:e02:b873:7ed3 with SMTP id 3f1490d57ef6-e036e0c6af1mr18872276.29.1719628243190;
        Fri, 28 Jun 2024 19:30:43 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:150d:b0:e03:62ce:ce8c with SMTP id
 3f1490d57ef6-e0362ced085ls821217276.2.-pod-prod-00-us; Fri, 28 Jun 2024
 19:30:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVUGkz97H+7QzJuIQG8FRp5BDSWOazekj9emirY2yNFBInBJiiuStic5zh0+bzGCZEQ0jQqOrBC6Uk+8jMoVy7Sc22L0masynUU6w==
X-Received: by 2002:a05:690c:ec9:b0:622:c70b:ab2b with SMTP id 00721157ae682-64af304094amr22341657b3.2.1719628242314;
        Fri, 28 Jun 2024 19:30:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628242; cv=none;
        d=google.com; s=arc-20160816;
        b=qN7qRbyrKCoLsw27vjnbu931sNtAewUhxYqZQATLuxAuOSRMW2snGTS59nnKa9+MRY
         uTmG1fE/hIL90VAk6NEh7h4hZB/UaDD0I+ETTvwSTUxtvuDpivlA7ZtTb9cdePXsPGQs
         CcFCkMlv3TK7i0gbeEf2fzIYxEWZkOs5U+KTeHjYDLmkc+A3b30HEGTmalvHkC5v1rew
         uWgCawogEdirqM+5DVGNNQtIB1fsQ3ZfYlpqomOJbuXrnNqhG7n9ucRS71RRV2Y5tVOA
         SqC11bbsZ3rfaOrNAQItGsHsEThTKvutk64XRtrnQu9imqAFTGyiVexAos0VfEiAuFWf
         zbDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=UQIDHvbqQCbgl5Uw7b+X1q5Jt4GoSt4RAJCn+iKzB8Q=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=QMecyztD9+Lo9TpcrJ+1W+TU26NvZID73KMHJA1aoMq6OsTJcMTrrm8KzEwdwSM9D6
         ig2/rD0JeA0V/EBvTf5JODvcYBdi0flXJnOHhoHVmmEmRWYlDrANiCTRSMNmrRAabpB7
         Y3n7Bbo/AYZfhFNqxiU2kP7YOLZ+JGl5wTldwVs0i6CPmNaYl+ws9M21bfH4hMYUdgV4
         rk2QGSNncqj163dZesHTVRV8gMB7Ch9nQUqG0ceAgK4Gyw5z2fDcPFcTfbJiH5sL5H6X
         MXeOw2IJYFj5QIVhzkSqKMfxpSYPAKLPUqB1HiuaQAFZtgCVyOz8CncOJXNq2/hXGGl9
         CCVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="j24uv/Lu";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-64a99a76e7dsi1269447b3.1.2024.06.28.19.30.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D7226622BF;
	Sat, 29 Jun 2024 02:30:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 802B2C116B1;
	Sat, 29 Jun 2024 02:30:41 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:41 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-fix-kmsan_copy_to_user-on-arches-with-overlapping-address-spaces.patch removed from -mm tree
Message-Id: <20240629023041.802B2C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="j24uv/Lu";
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
     Subject: kmsan: fix kmsan_copy_to_user() on arches with overlapping address spaces
has been removed from the -mm tree.  Its filename was
     kmsan-fix-kmsan_copy_to_user-on-arches-with-overlapping-address-spaces.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: fix kmsan_copy_to_user() on arches with overlapping address spaces
Date: Fri, 21 Jun 2024 13:34:50 +0200

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap.  Assume that we are handling user memory access in this
case.

Link: https://lkml.kernel.org/r/20240621113706.315500-7-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
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

 mm/kmsan/hooks.c |    3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

--- a/mm/kmsan/hooks.c~kmsan-fix-kmsan_copy_to_user-on-arches-with-overlapping-address-spaces
+++ a/mm/kmsan/hooks.c
@@ -267,7 +267,8 @@ void kmsan_copy_to_user(void __user *to,
 		return;
 
 	ua_flags = user_access_save();
-	if ((u64)to < TASK_SIZE) {
+	if (!IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) ||
+	    (u64)to < TASK_SIZE) {
 		/* This is a user memory access, check it. */
 		kmsan_internal_check_memory((void *)from, to_copy - left, to,
 					    REASON_COPY_TO_USER);
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023041.802B2C116B1%40smtp.kernel.org.
