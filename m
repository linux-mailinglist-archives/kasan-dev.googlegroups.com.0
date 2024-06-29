Return-Path: <kasan-dev+bncBCT4XGV33UIBB2PD7WZQMGQE37EQMEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 8553891CA9B
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:06 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-445034e4312sf196541cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628265; cv=pass;
        d=google.com; s=arc-20160816;
        b=i/TmifTmfP/rYMMnlGyj9OwWe4SDGlnqA0uDoiWjC6CgdAkSeMe79YvSnqfW4kSh0o
         EzjrpFnNwlwHs4rd3+6fWDKFraKgtrCfHZnMF/GHdxDrCpmzxb6CXdtRCe81RALLa6Ub
         SukN894/xR1ZXSPeiad1I54O+DYV6SZnDFjW8nNVvF/+azlOuPliCFOUWwPCchx2m5P/
         Ql1DsseTIdFwHRSUzOIeVJ97BSjILVgjPEFnS7fTUM7d8iulmVqdH7dFEnUC65rdWP9w
         nvgYAwIThHGmlM3zg4sdOD/QtlHrGUx1lseExAwELJX14kWtN/MDYjMQKMPG0fa+AyD0
         cXAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=jza4B2XTPc1wQcO+yUeh+ErWR/6zKWoOfoDbqs6OAuw=;
        fh=+cNrjjrDaqZMF2Zk8dyWeAQZisOHdy3Jv4x68qn8jVQ=;
        b=Dmv3BK7Yd33kr2u+/OjAwv3oJ5aSxNapcjeWtEQf+NDqA8oz5c87LJQl/UBPux8aw7
         orMFZmBpuhIlMlV7sxXsoyr1x9ikyioK+MivCQndu94VliZJ+uS21qYFSYjZH4kiGbTw
         YwSCPWOWLouzl1o1CeZ58q5isNO3XobP8ADLS/stP2iBEONlVxhj9icBsGTPyae1+E1H
         nO6DNbAUKdz22eZbruwH+BvYg0vMUDEMMghRqYjGiYtEOrw46SdQWWMAZFAACXoI4+uE
         cEpH/p11UySwGDQAWNVa2IcTIlKpcWlbsg7bvKrq7wD7tR0WPNyWkU9Fjf8u4ojWoKGi
         hmHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=DVuvTSmN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628265; x=1720233065; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jza4B2XTPc1wQcO+yUeh+ErWR/6zKWoOfoDbqs6OAuw=;
        b=BP7z7YRZnf6OC1Yl2NrfUo5TMsTNAQCaA3nE0fO1Ev+iDsIhZ+SgsQY6ig3Hg0tLnQ
         Wa5zoH0Q6N6NGVEqXKpy0e9QUmrR3Pwf7awFQOVjAmM0BfKChE6bw1VWn40ta6a6ZvTn
         /8QCevVUyV35AIQq/l0J+HjQWmkhr4zeFv6rBgfMm8O4tqamfC3cNSREVOkHsZ3ZBm8L
         ewvVcX5UcPmCzWXNDS5qvkqRL5M+ggpq8mt5+k/5zQjw60xDzsw2QqoUwhGxWuEwIkH4
         kVbXIj/rerC/65UK/eIHwuUqpij78sTfyAL68Ppo7NI9bIe10RFfBUrKehxeUTfdBdoA
         cJ+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628265; x=1720233065;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jza4B2XTPc1wQcO+yUeh+ErWR/6zKWoOfoDbqs6OAuw=;
        b=NELahAysTD3fbL9ZJfB+FTM5Q9bq9B4hAS/7duBpa5bh4+JcF4UKx/HcyIWokFjWzi
         edBS9y2J6dCLruEc42W7AzWq6iQQBvUfMs1i8EEehRLALoPh2F51ZYt0wfbCUEcY/tXC
         JiVoKe4EVn5rEoiIJbqq4OyqHZlqbYvtXu81qhTtydqtiTwgIZ0IAxYNn7Vj5tVuhl//
         QxaZFxFhSGrvOZN8ZAXDlDoL9PVbuHY4wUIbXRaWKYiwOBWARxfkXj7otrzQbgvxDzXz
         oSYW2/i4RQBA4cYv0by2pEQ0Mjxt9HP2dU4YHrC2qebkenS8tM4FIY8IJQGToWBgPab5
         ZOgg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWqblxeahIF1S2OAqa0t18Nnc6vdFseeIxuSUHVLQaHnorozgw7mHlGqfnyXoSHAjOXYX6nGL1IMfnyuWU5v69mzXgfxPZruw==
X-Gm-Message-State: AOJu0YwpOHok16kc7+vg4KVhWNXsZzS/zUYTzFkCLqK4/22Hi4glFm3f
	p3YIzq1c2wiHW+DnAKYlojINCctiFm9Gr4lJHmVAdcj5x93kp/mY
X-Google-Smtp-Source: AGHT+IEPP8Q+ohrPJx3uNRDSuCt/CNhi7d/4lCqVpzTYmM3E6lUYiWyYeBbtxOmvjnIa6bDIQA+Yfg==
X-Received: by 2002:ac8:7391:0:b0:444:e0f6:8a3c with SMTP id d75a77b69052e-4465ceec05fmr1560791cf.0.1719628265435;
        Fri, 28 Jun 2024 19:31:05 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5de9:0:b0:6b5:d99:4d3b with SMTP id 6a1803df08f44-6b59fcccaeels16614196d6.2.-pod-prod-04-us;
 Fri, 28 Jun 2024 19:31:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV6MF5FMvD7UEiA5gtNn1n1p3EFpMaF+4+lf1nDzVug2OQghwpANyc0BxcZlfuUpeXh/7j0ScTDQHca40gj6uGhKzHtfJ34/5IDLw==
X-Received: by 2002:ad4:5ec5:0:b0:6b0:91a4:eccb with SMTP id 6a1803df08f44-6b5b7149015mr115936d6.48.1719628264716;
        Fri, 28 Jun 2024 19:31:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628264; cv=none;
        d=google.com; s=arc-20160816;
        b=BbVvHGeaxcxH9f+jVhuRoD7z9dxRn9butyGeLHzgLZiJ9wOdpUGUUx8e8eAw3un9D1
         a2Y6+Tjh4WPcUCQISkvrovch7+OOlu5+7bikQTfP7FFyjs90eqxKnNNkDLCVzeHG2XKk
         4WV587RQchwA0kzuNJD3YqGwyZ/z6fA9Q9Tdx3LD3qWgSD/usMbjDTR8h/ZQIqhguhiN
         kRlO2IYhnOEPBnGdtAuUgRaT6hNrERm4lX1y658xo6P0dk1sXRjYfmzeKcK0iC0j/9W7
         JZPX1D75ZjJR90qu+razkdhGxMkllSvGwAft/LQIB+iN2wZTMtzz3jp/tG/h20tgfZO4
         aO9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=wcT7bJ0dKYyperLswFdWRtw0XU+d+p4/udOwlLWKchY=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=cPCEEsmcZT4V4/j8Rams4nqvAsPpbW9/f8549uTzn04hSYK0a2QwRiRtIMVIbWdbp3
         U9ZZdjdRYKl5jLz20zPu2AaiamrFZdasCNuCZWtSjPO0c8gAY0t+7C4p+MDoWJV3WVDM
         tv7GfoixIKqoaWOzEuH+7b4Jqh7SGIyWVUtZQC/WCC9wMneo1yQ/LXdVaAvS2tAE5qif
         3aSSxZqD/MCd2ZyxAm1C14/ZbdKh6tdnOTIKNtATFmNeqS0hOjGsytSpXMAY30YKsGSO
         CgvnOyMlLT+GVTK6WItUG9cNKWgD75itfklvHCpT5IbaE7wzdf9W1If8iakGfXXp5JWg
         hsTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=DVuvTSmN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6b59e5aec6asi2232896d6.3.2024.06.28.19.31.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4D240622A1;
	Sat, 29 Jun 2024 02:31:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E9C04C116B1;
	Sat, 29 Jun 2024 02:31:03 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:03 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-boot-turn-off-kmsan.patch removed from -mm tree
Message-Id: <20240629023103.E9C04C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=DVuvTSmN;
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
     Subject: s390/boot: turn off KMSAN
has been removed from the -mm tree.  Its filename was
     s390-boot-turn-off-kmsan.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/boot: turn off KMSAN
Date: Fri, 21 Jun 2024 13:35:06 +0200

All other sanitizers are disabled for boot as well.  While at it, add a
comment explaining why we need this.

Link: https://lkml.kernel.org/r/20240621113706.315500-23-iii@linux.ibm.com
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

 arch/s390/boot/Makefile |    2 ++
 1 file changed, 2 insertions(+)

--- a/arch/s390/boot/Makefile~s390-boot-turn-off-kmsan
+++ a/arch/s390/boot/Makefile
@@ -3,11 +3,13 @@
 # Makefile for the linux s390-specific parts of the memory manager.
 #
 
+# Tooling runtimes are unavailable and cannot be linked for early boot code
 KCOV_INSTRUMENT := n
 GCOV_PROFILE := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 KBUILD_AFLAGS := $(KBUILD_AFLAGS_DECOMPRESSOR)
 KBUILD_CFLAGS := $(KBUILD_CFLAGS_DECOMPRESSOR)
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023103.E9C04C116B1%40smtp.kernel.org.
