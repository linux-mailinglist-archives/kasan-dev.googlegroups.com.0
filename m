Return-Path: <kasan-dev+bncBCT4XGV33UIBBW7D7WZQMGQEQRHAKBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C00091CA90
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:53 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2c90118bd5asf1898305a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628251; cv=pass;
        d=google.com; s=arc-20160816;
        b=GjrqghaF9DdJvD+y1/8udZUtlbbjySf/Im1ngNKIw1XybQOoIvpFYLNKxGe7oveUZC
         jqWs7Ph1wdLi4G4wCu3bpAxoXiT6bRvS+T2DIZ4gh8t6MhecjSzfbs/seu41Wd/mF8Rp
         Ik1+ou8tn0uBU2KFr25M/8pCXupLm03/JKAly2rf6HKRfhbsrDneHCxzt01OvqqisAHn
         N0LAAb3CQS8VQ7aNnyGOuZfjqo2hzTSg3tZ+sKMoM+a/pXKDOskBc80+AzqnyModcYK2
         o5eSw5InwE4i6cb2PnGwLf9snlnOSdC8PmD0wpyaZYwYYjlYout6Tkglq8Cek4qWezfj
         ZCjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=opZ4FzWC4L6W7LcqGc0DxX+sf6dX82KrVIKUiUawbvY=;
        fh=gS931JAKAJsQIY5IHDyhFmy0MN6GHvbi7BM5LHVFSfE=;
        b=nHy1+HDdjbLR4BbNDL8isXl+P93xwWv5c6JT5BTJTRDzkQsqNEJdjYUlHGT3P+fN2G
         k1sNqDPyKgmGdqvB6HkteQYNbnhhve+dgZq+zILdUo4ZzPHB4d3DWWulgeLK+suf1m/q
         UF4G4b4btvkNMYYnGwCYr6tqi6RBVWWeNbmVKmJGvbFXEOajFPWFUGYjmyngq+2rA1uz
         DHgxVE+z/x2zRGrkwqEAgEPPMoifmExhGonTyQhROo6LvUNuP0KI60WJFvU260Xq4NcL
         tUdFt6HS6rJxix2pnD8nxZY7179shBBjactuELIofZjPIAyseZDomJ7Xpp7EDPJLdXc3
         io6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=g+gF+byy;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628251; x=1720233051; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=opZ4FzWC4L6W7LcqGc0DxX+sf6dX82KrVIKUiUawbvY=;
        b=QpGWUweDMycB9DnJlI7nhZggAdS8fkj6p6Fwsn14XZ1xAEivWfc7V/OvPViDj1uoSR
         e7fpJOg1jxEmemR/3aeGwSpuZlVyODCilKaV8ww2nehnaWubWEyWDJRJkeb0CgJ/0Pd7
         tGyQhom/IF+fa5ZyCT4tagqkAZrm2uInKAQ7LMxY+nXetzBc94XPcEtzlKpTaaOCa2w5
         XGIyCQg2d62R5xDX5N3XtEvdlc63np4iTLglpLQaHs6aTgo+6iH5nuWrC8B/lj08pqdH
         bm2Ar5GyE+yyjbVHdx8LkB3RNy+fqsdEseyXXW17Wffa/ZlLPD0D2QFDfTBn1acDrreB
         SMdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628251; x=1720233051;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=opZ4FzWC4L6W7LcqGc0DxX+sf6dX82KrVIKUiUawbvY=;
        b=twFKc1fBJIxA0yF4sXVBDwxQM4tXZdoKTO+hzoTdD9oA4/n6DO2WD06TlrkoBE1fd8
         3bFuFJFrWbZEQlP3ZTwkHJucx9ukLmSCQ2Om603qx1qm1r+0tGaREnc6ApWl1WXRGae1
         6o6nZ3m/vNWfcrRAU9unlTSHPE4FQBy5rm1rQUufBVOF7OHun4ka9hz3cNvENVcfHiRz
         bZOEsqE6Ti2og08i0Q2WXzLKAM8RDOmTr4g2HovLMS7CKE2rpkJJfSSVV0QoBVqV3s/2
         YCHhmsgbamOWWz/y0nZt97fFB2rOInCaHTklmjLRr5hxSYsm5vDALRnHReWe493vXc4a
         /Pvg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdOt/gq9jKs3UyPq6pQq4OGoCaebSe4Elt+v8YirrlnUUU/89SDJ0MMdOsevcDDF3bSBInhogNlpbbi9DO9fTOpB5z0nERhA==
X-Gm-Message-State: AOJu0YwXEMB7M9+TYjj5n9cM5luScdst8bkYSmkdlwZogz+RNqPUGM25
	GHWZk2d3ljnLS6TNyEgFKN5i6wMmdQBFkLot2aBVV//xD2utbJsu
X-Google-Smtp-Source: AGHT+IGGZOBzm04jy13BuvizfaTdCDdiRgdBXdrpIe9oS/bsvy/2p/BlmFGN0CfPd6M+ldJwE/4UHQ==
X-Received: by 2002:a17:90b:3603:b0:2c9:2d00:44f with SMTP id 98e67ed59e1d1-2c92d000b3fmr4725029a91.12.1719628251413;
        Fri, 28 Jun 2024 19:30:51 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:be07:b0:2c7:a906:88da with SMTP id
 98e67ed59e1d1-2c8fc3e7a40ls1371112a91.1.-pod-prod-00-us-canary; Fri, 28 Jun
 2024 19:30:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV556quzvx2MapBDPXql8H1xISiEXlUVnqWXSnCbEwCAaHZu+vR1YKIlSj0ilgnogwb+djBv70GeDMQVqk8sF7QMzChrQBnbHA1wQ==
X-Received: by 2002:a17:90a:c090:b0:2c6:f5bf:5175 with SMTP id 98e67ed59e1d1-2c93d1b99b3mr88744a91.10.1719628250158;
        Fri, 28 Jun 2024 19:30:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628250; cv=none;
        d=google.com; s=arc-20160816;
        b=r4Ht2VDkbRureVHmWO+b4szB8Wy7omb3zjd0sLSobqb1IJaJ/DHdQ9wEM+3yC4l5e6
         CpUXblu58ekEXdF91CddSXsxj0LblHqtDvzacyKdG1AxNlFOw2X1vyp/WZjyiz6rVUsk
         HxuIEKw1aqPXeCVZTFna/HFlIj10sBSIFpkq241b+MJmEMSLYORfM0tu8Q6aF+rWzYtx
         icX12ceq0QUF7pz0X5eVHFVZuplrVM8YM37RP7QaltAKIvYD4qBXU8O+8gaScbJQr7qu
         ItHQvC3GW9H4yjLosobHhBQoznqaWpEwRuY8oGbEIj514HeSIKD+5qLi4iR+MK/VNNSf
         5k1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=0NBrzYdqJz7/D6spZGjJHvJI04QeF+KSHnbKV7uJjZw=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=oYXh1fSpOyphpSQH1TZq68vDRXEHS8PgsnBoX0Hoap+V/NQp8Q7lk5haQ68NNpvcVh
         CO9Akqbs1l2YdHSVx705xo5v438jwIAanW4CgHYscJOxLnYL8szdY1NJbfHNuRAeVPA+
         n+1g3xnJAf59GpnHWTWaTIAjTqCvbfWCKOZMKwxCRju383F/jc3iKJHkhHvaZbLSfkh9
         TQTsBRt2buCeKWCunGc7duQDb9K+7avcYasL8RM5BvA729FtKE8jODH9sgr2x4DWvt6l
         7BKYrHd8pBDoRatN/ssUxB3cjzVk3+EcHT8mj7HPyqpZjujQCGpf6xqaMVnGv661NzaK
         MScQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=g+gF+byy;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c939cc19dasi37789a91.0.2024.06.28.19.30.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 07AE9CE434A;
	Sat, 29 Jun 2024 02:30:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 32BF1C116B1;
	Sat, 29 Jun 2024 02:30:47 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:46 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-export-panic_on_kmsan.patch removed from -mm tree
Message-Id: <20240629023047.32BF1C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=g+gF+byy;
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
     Subject: kmsan: export panic_on_kmsan
has been removed from the -mm tree.  Its filename was
     kmsan-export-panic_on_kmsan.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: export panic_on_kmsan
Date: Fri, 21 Jun 2024 13:34:54 +0200

When building the kmsan test as a module, modpost fails with the following
error message:

    ERROR: modpost: "panic_on_kmsan" [mm/kmsan/kmsan_test.ko] undefined!

Export panic_on_kmsan in order to improve the KMSAN usability for
modules.

Link: https://lkml.kernel.org/r/20240621113706.315500-11-iii@linux.ibm.com
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

 mm/kmsan/report.c |    1 +
 1 file changed, 1 insertion(+)

--- a/mm/kmsan/report.c~kmsan-export-panic_on_kmsan
+++ a/mm/kmsan/report.c
@@ -20,6 +20,7 @@ static DEFINE_RAW_SPINLOCK(kmsan_report_
 /* Protected by kmsan_report_lock */
 static char report_local_descr[DESCR_SIZE];
 int panic_on_kmsan __read_mostly;
+EXPORT_SYMBOL_GPL(panic_on_kmsan);
 
 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023047.32BF1C116B1%40smtp.kernel.org.
