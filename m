Return-Path: <kasan-dev+bncBCT4XGV33UIBB2XD7WZQMGQEEE6R5RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0093991CA9C
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:07 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3761e678b99sf93625ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628267; cv=pass;
        d=google.com; s=arc-20160816;
        b=YKyv3FjFNtXg5ZmtF+iaSgZNCg/bUL1F6LZZt6Qr4DC50sacX0/mHq+Jdyu2aCx51a
         Hjw3xtI5h251eTsKdNBZO1U/jbNkQE3OUdSXj7SMTdSxt5lYUOv1vBvWz7b3CCRUr2le
         3cUYHXCpLNmvJvLIzfBQqW/gJswG3uhrLHxRCux7CO+S5IMPUsuV1fxPrBd0VpRBwzJW
         vGgh2KeHvjYRde2aakLrazSFYOMXgK4Wu2Aq6edKzAdrmBxttqy6CeKF05GNb0sT7A8C
         d/pR3+a2VlcEb60F4c050zeejlZX/dFnkHj7f8yw9qONdseftiWtqIpA6mCwK1zyKU7G
         Za0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=BR7C47UEBliMky4vPYzcL+1V5PlcyzOybuID3VAw/9g=;
        fh=L5VL2hDnoQTDabHJ6PMQ+YAcq5JHpVeEjRQRw7GtvLc=;
        b=n0/q0LMrZtjAGghtMFQjnfceFH9j8mpYAiG/9Le3tuPfSgbuq7NlsEST84LkDWvD5A
         8tvwQ15G0uZm1nOOBrLuFeZvqGVkJzTPGN3REHbj/N0sLLcy91zSmUz4wRaM505qBCrq
         WtSN34KLZenbETmXtyRgq9eZg6XBZaf1rBxmKNVr21FV0Br69mQaPoBowuBFPTek+n+O
         nXgiuF/I8gvGbn2uN+mGZ86VOEHFnQBwH8lFadLmaVQ7KCvYWlHIgS29P9Lf/jA4IqyG
         /AfFaxyE43PH94XrzvmpE6bAwXT9AaeWzDvLn1wzB8ZnxOQYZ8eF0F7/ETeagbMp68GJ
         xW5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=qWFOjcXD;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628267; x=1720233067; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BR7C47UEBliMky4vPYzcL+1V5PlcyzOybuID3VAw/9g=;
        b=YYO05aez7P2KOEdxdo59865TDmFEMZOpnZzfgO7Zegidl0ssBf7unji8+X9WhbCKLn
         aJvvB0VfMxnaPgQ7VnnnLbG/lpUtTTK7wT6zO1jzCc6N5aXgn7+JrEcHvsWgz+bp5+CW
         DHfkdXxDkMwX1tSE5s9jxi5pV0xytw8qe25n1nAG+luWP1WRLOu0eZiw72fFRRFK/CFC
         INHfKqfMMm7zadIPB/hwZc5QE2tDRuQRVNNUzq2j7z0gzplTGfb2FabkCtrIuGwcFr5d
         5Gjm4RevSir58V7PZbeFoORuUqmleK5YnxjohgQGddKIr+tUxzLgRVK2rjKZa8TgbRL+
         8dDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628267; x=1720233067;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BR7C47UEBliMky4vPYzcL+1V5PlcyzOybuID3VAw/9g=;
        b=ovhsn9cXwbAV/o9kodjEkZMD+zLP2ijOvVuMT9H6jU3hgAziukvIgsfuIVAYd25bcD
         doZD8ujCYq34a/GRDAJ3JiTv9JOLVlRdp34hm0iFYPnQ2293wqIe0HtsfWh8lt81m0lC
         Sc/eHLQPP+ZWXjA6uBIPc9G/zCth27b1lZ29Q1NXuMn+mvpqjwCyJgjTYxoS52RVRAMG
         2N2VDKnI6J4qPtNIy36wNcVOhE5e/aS5JtxSs8Ya12NJPPOG2h7WB6M1ppzZTGHybcm1
         IcdHjFM5vP18E2OGoxOmeRXnCp9IyEy2ZLhwD1Ohzcipwop+k2r9MPVDlLcgX14yT/O7
         J6zg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVteTIK6Z6N9xMbW/QVk5IJGuTslGa+1/dMkb2TOEh4/Uf5s9O4mNomp3ni8RDKtz2kY3FOrk8SyIER89Hkwa6MFc3MzrFETg==
X-Gm-Message-State: AOJu0YzPhXziTU03FBy1xLrXCE2av8fsaMNNJ1yrInfrXRxQn9cbrsaD
	HFPSSNLES5Y7wzLmgRe/8WrTk8Do6Yj87xlY2klylyz6MB/M3JeT
X-Google-Smtp-Source: AGHT+IHEmkJWEPMhBfQptPF9PV01VAwuwS6s+M1qXK5gFzZXvlmmARUug6afy7mbMguzBJc5mz7tlA==
X-Received: by 2002:a05:6e02:1c42:b0:376:3a2d:2385 with SMTP id e9e14a558f8ab-37c66dd7befmr852735ab.5.1719628266830;
        Fri, 28 Jun 2024 19:31:06 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5558:0:b0:5c2:27cb:68fb with SMTP id 006d021491bc7-5c417e3e394ls1139784eaf.1.-pod-prod-06-us;
 Fri, 28 Jun 2024 19:31:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVBrXfhMTrqEBP8EEYAEDPIjo7fcXHejKr7Wk+2mqsoTujxksyEvnMx5hXeTg6QJRU7zqycEzJ+quBUydJCZKKmDrGejGosDr3N5Q==
X-Received: by 2002:a9d:6c86:0:b0:701:ff2a:e50c with SMTP id 46e09a7af769-701ff2ae640mr2277395a34.13.1719628265905;
        Fri, 28 Jun 2024 19:31:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628265; cv=none;
        d=google.com; s=arc-20160816;
        b=obVjsEWXypsV1GfUfPlTj2S/o9yV5CbuiZacpxFkMwZgEObFoTsLKf6xPt6de9VJ6H
         6lt2QuO8lo8SY95XipJRpyivd8EyTxpU46hU8nlUGLOfXcBETAyDmUeJwUkCkzDoBJwN
         rrycTGceHtVSbVgDerefQBCDITOki4UuMU21L21qh0aKfnXxOQLGgwcTaITvcWnrf4fr
         MZNX1VseuFjORPMRZCX+FzKd/l97yVZMF76ZXTTamYO0mcmiaeLTydV6cQF0h0AuuoB4
         Ah7jn6pW4iZ0+gEdP7r3tBw30dLOsxAOh8tx2UvLt+juztTNzTeTXT6PCms8HlbM3zTp
         UZag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=5MXW48Jw9v9d++Dp/d4Nd0hZraZeCsba/O4ygz7WFv8=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=zPlBgi5mEDEWYwUiutRQfQ5RuCMfYPi0JrrCpduUHg3Wf+x8Q0WexU8kLXqkoSb3ZH
         ODC4FXq7okb/g7K5UvrJeAsab8sbrqCZSriu/4R3DVdo1yWo2i0ua1oNHyUaA+puKODN
         rTcTiuzr2FOlaKYq9cEI2UGcoxuw/HxXvN/YxBkIaK8fx8YCcBWgQTeI3Z9vEYbRl6VO
         PpAfeGYm88SAzC5cYqQ+tynTdLlZYZNzNH9P1CeJBN3i4YV1VCXNCTK12e8AcCcv4WiB
         Cie2emqLBWNAGBgJPvp344uvfxd2ZGfHsAKbkTBDYUMKnNupatZt7KwPs+m2KO5idH4m
         Wypw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=qWFOjcXD;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-701f7b7ac45si123261a34.4.2024.06.28.19.31.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id AF33D622C0;
	Sat, 29 Jun 2024 02:31:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 56C38C116B1;
	Sat, 29 Jun 2024 02:31:05 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:04 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-use-a-larger-stack-for-kmsan.patch removed from -mm tree
Message-Id: <20240629023105.56C38C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=qWFOjcXD;
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
     Subject: s390: use a larger stack for KMSAN
has been removed from the -mm tree.  Its filename was
     s390-use-a-larger-stack-for-kmsan.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390: use a larger stack for KMSAN
Date: Fri, 21 Jun 2024 13:35:07 +0200

Adjust the stack size for the KMSAN-enabled kernel like it was done for
the KASAN-enabled one in commit 7fef92ccadd7 ("s390/kasan: double the
stack size").  Both tools have similar requirements.

Link: https://lkml.kernel.org/r/20240621113706.315500-24-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
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

 arch/s390/Makefile                  |    2 +-
 arch/s390/include/asm/thread_info.h |    2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

--- a/arch/s390/include/asm/thread_info.h~s390-use-a-larger-stack-for-kmsan
+++ a/arch/s390/include/asm/thread_info.h
@@ -16,7 +16,7 @@
 /*
  * General size of kernel stacks
  */
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN) || defined(CONFIG_KMSAN)
 #define THREAD_SIZE_ORDER 4
 #else
 #define THREAD_SIZE_ORDER 2
--- a/arch/s390/Makefile~s390-use-a-larger-stack-for-kmsan
+++ a/arch/s390/Makefile
@@ -36,7 +36,7 @@ KBUILD_CFLAGS_DECOMPRESSOR += $(if $(CON
 KBUILD_CFLAGS_DECOMPRESSOR += $(if $(CONFIG_CC_NO_ARRAY_BOUNDS),-Wno-array-bounds)
 
 UTS_MACHINE	:= s390x
-STACK_SIZE	:= $(if $(CONFIG_KASAN),65536,16384)
+STACK_SIZE	:= $(if $(CONFIG_KASAN),65536,$(if $(CONFIG_KMSAN),65536,16384))
 CHECKFLAGS	+= -D__s390__ -D__s390x__
 
 export LD_BFD
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023105.56C38C116B1%40smtp.kernel.org.
