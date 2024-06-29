Return-Path: <kasan-dev+bncBCT4XGV33UIBB4PD7WZQMGQEBEUNILA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AD3491CAA0
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:15 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-37629710ab1sf81635ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628274; cv=pass;
        d=google.com; s=arc-20160816;
        b=HDgyc613I7VjNF5fGqy6d8m5oz3XgDDhG5y2Agwl15xra5nh4UB9aNHhNROLrY2xBH
         INHl7FMq5/V00V65m86MM/KkcV48FkvRhOWiMLkDuig4o7/0V7eexSLeuTx7JSlLdGcQ
         IFpt1a2x+JoyGkR5jeCqbNjt8CEfhu8mMsQYdxRfzcOyVq0kyHiGr2JsC02hWlGhr18V
         XmoUg2fHv0b9xKv++I5HkkiTby/j0DU9WDJ/xlghzCHHCYL7iqB36hqhcWq5Hmbt54VW
         Pc5LEwuiCC2qjeEjtzeU3djEfBWbFLJYIgS9+aaigmA/GJ3R3Q53zdIHy1+ynRWJjgMo
         vpiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=c5P+Z3/g8hQuWr5FBXnoIyLTETI9t/NRliK5OsIognE=;
        fh=SWeBk7ZfMnYaHJoOwSDFEaeh0b/26ydCOFROHmv23wk=;
        b=R6fjk63ZY9hng+kmOC+7rC6apnVI+nIMQkf881RfttM5tFKoLeXusBvcl3xig9RbEF
         5gzrxcJyjGMLfXGPKgLoaCMp925aZhXNcT6l01FHconMOa2FA2wEVnGfDgFE1jy+6GDw
         tKkHMTb1YIUifxQgN4WSKfmPv55+5P7/HD3uwHvkAQgxvPWA20lu9Lc3zOCOE8jDbJBM
         zimgH9ZKKxHhBYnBz78UiW20pLsnboZ11UdQklC2utcSjAP4tUUoAo4J87clNhKo7VrB
         sbdZtMA7ouGinAulj9QHLx4d88/vUWcRrBh74FVxbWWUsVyl+VURjIJcKAcSvenyPw5Y
         pxUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=b5WsbHNb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628274; x=1720233074; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=c5P+Z3/g8hQuWr5FBXnoIyLTETI9t/NRliK5OsIognE=;
        b=gIF3/nbHWy8/vWUuwRFwbdI34/xF3dkTaWWHemA07SEADtHo6Up5jN8KqL74OP7t7K
         ElnAqsbJ4QPsMNH4OjXzfo2ggPQAW+vmmZMvgUJ+BliZN1Gtjd237GPlrwk35v2DE/CC
         s0duX1YcpddYwH/Qn1ZjBZIsQReymrigjVRlb3lFzLIPr8wHaJ/8GLD8uE6f8k2n43k5
         WN86cVvUy8NUXG0ZON3TSQK0n9ms0xXbqtQMtO9mpe7Cj+2cFilT9WEn4fmxAexMH8RF
         aRVTp9dU2NZsU4jWhP6/LLmD+ru7Fyp0PZjxf7V7EfoUTMAjNgf6pEee/oxn8RHXZ55L
         F/5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628274; x=1720233074;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=c5P+Z3/g8hQuWr5FBXnoIyLTETI9t/NRliK5OsIognE=;
        b=CmAVCf8mg7Ep1pgV3loEWQpvu1RezrDiXg/KuOALpT1Bt+AOQggp47aauzKOjepwlv
         +G00ItmTfYQ1kS+N7W0ZCxdnfx78vAkHZArane62/EIgmLXZ6mlSS1w+dm+UiD9Wyp9O
         31bDe1iB8c3di1gIpHSSJiK4Z9oYk8gAa6R0i5uezPsoRd1G0RcSnIDu5FWsVvHEf3YH
         n9MKEAUybq5qzHzE3n0VBkgDQQ8lpeoyYQ+VqEZDRoxbvHMdpTZ7/EjAuR3tB2QBheHt
         tdnYqTcWLJsIKOGl39kPp8esrGhn8XUcU2UdDN8pgl4zBOvixlxsK1e3lkk210+7++vv
         z7ZQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW9bGc2OaoyTv4QCKITdRrwYSUDlWWja210eQQsXDSXHoWteSo+2ZSrC59DA1P2uUn1uR+5pfcyNGkEQxC/Hfs2vOEZPmnvGQ==
X-Gm-Message-State: AOJu0YwmSlYHpR/JDhHIk6ru1s2u+agw17PKupGQroSvVtl0axmVhkAX
	plpXMkrJMdsOzs9x2Df4Wyi/MVGeX/oR3/bLLtiLyt1VR5a8j7GJ
X-Google-Smtp-Source: AGHT+IEgpsqefxJnk67gLn2R2LqstKyFv1uQ/lW4uoi5i7tLoRAZSASKU0qXzzA+Wzp547z9HD5xCw==
X-Received: by 2002:a05:6e02:1583:b0:375:d7d6:e78d with SMTP id e9e14a558f8ab-37c683f3f8amr810905ab.27.1719628273902;
        Fri, 28 Jun 2024 19:31:13 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1b03:b0:375:9d70:4e85 with SMTP id
 e9e14a558f8ab-37aebcd47c0ls12312355ab.0.-pod-prod-03-us; Fri, 28 Jun 2024
 19:31:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXd3n0I5uQ+cQNOX8CH8E7HJT2zwnJ/lnm9/SYaBx9JRxMW1rhxHgPw8RSoU6BpnS+GJWTRa+jnWSZ/bUoyNbtWiB3pMt93+vhl8A==
X-Received: by 2002:a6b:7314:0:b0:7f6:20d2:7a96 with SMTP id ca18e2360f4ac-7f62eea0bb2mr5795139f.14.1719628273135;
        Fri, 28 Jun 2024 19:31:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628273; cv=none;
        d=google.com; s=arc-20160816;
        b=t4zKGf3rDfWyQWzZ++7YZw0+ivjlE/GiF6d2hefaAiKjkrB7lfVUQz4UCNXd+Oxous
         wtKaPW1hjW1yjc3tD/XsdxAChtxM02wy56gF3HwBKE+hFKzMgJ6XMFTZgauG6likWFpZ
         jxjE9/jpBBUcqWJQxBXnwbiXO7TFHRJVqIUuFi5TFm19u/7eFh8W9sQm6j72p0r9VFMT
         wArUroaPN+66RtQwqpdN43yinlzXbp/gA6qrM5AMf1axUlHoM5m5C2TY8R0hrdP0B5Pl
         JnsJLDkstlpMTO0+xP9Q3oJbjwxDyZlFq1+HOXxSe92a0CXPYguSTFNWJx9508qYA4GA
         cogg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=g2Ok+pIAL02kZdq9l4dWD2v5mZLAlup6M9Ue4XfPSLU=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=uu8vqCSQZnSZX9JoDJH6nG+00gKfsKgXRbOXIj58xbb3Q/OXhYeDIhF/XF7dsEDNSD
         kfz2XKQ1DcAQGYCs6VFcYQDXFQ31/iH5NtooG9B+53obByQMwmim2zb5ouHQ9h+fnyrP
         yYl4ciDGrFBtunhRtfSfzLH98mfuKuiJpN7Q9j3C+SW1SH/v+41wTEkah7l7c38q7D6k
         cTMqfJnjyGqHNDpU56JgKcWSSFE8wC9coBkgAj2Z7e1ItpqljARxrzZpD1YQKjHAWm5w
         525jW+saZXJFYhpQjDbAI9UjQPZRQ5pLBV0sAT1yuZ/eNFUyDrbBlqZffFng7XbPPxd0
         fPqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=b5WsbHNb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7f61d207920si12588139f.4.2024.06.28.19.31.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 68DE8CE3C29;
	Sat, 29 Jun 2024 02:31:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 94555C116B1;
	Sat, 29 Jun 2024 02:31:09 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:09 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-cpacf-unpoison-the-results-of-cpacf_trng.patch removed from -mm tree
Message-Id: <20240629023109.94555C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=b5WsbHNb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: s390/cpacf: unpoison the results of cpacf_trng()
has been removed from the -mm tree.  Its filename was
     s390-cpacf-unpoison-the-results-of-cpacf_trng.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/cpacf: unpoison the results of cpacf_trng()
Date: Fri, 21 Jun 2024 13:35:10 +0200

Prevent KMSAN from complaining about buffers filled by cpacf_trng() being
uninitialized.

Link: https://lkml.kernel.org/r/20240621113706.315500-27-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Tested-by: Alexander Gordeev <agordeev@linux.ibm.com>
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

 arch/s390/include/asm/cpacf.h |    3 +++
 1 file changed, 3 insertions(+)

--- a/arch/s390/include/asm/cpacf.h~s390-cpacf-unpoison-the-results-of-cpacf_trng
+++ a/arch/s390/include/asm/cpacf.h
@@ -12,6 +12,7 @@
 #define _ASM_S390_CPACF_H
 
 #include <asm/facility.h>
+#include <linux/kmsan-checks.h>
 
 /*
  * Instruction opcodes for the CPACF instructions
@@ -542,6 +543,8 @@ static inline void cpacf_trng(u8 *ucbuf,
 		: [ucbuf] "+&d" (u.pair), [cbuf] "+&d" (c.pair)
 		: [fc] "K" (CPACF_PRNO_TRNG), [opc] "i" (CPACF_PRNO)
 		: "cc", "memory", "0");
+	kmsan_unpoison_memory(ucbuf, ucbuf_len);
+	kmsan_unpoison_memory(cbuf, cbuf_len);
 }
 
 /**
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023109.94555C116B1%40smtp.kernel.org.
