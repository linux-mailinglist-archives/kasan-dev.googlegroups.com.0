Return-Path: <kasan-dev+bncBCT4XGV33UIBBZ7D7WZQMGQE5MRBX5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 760C191CA99
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:05 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2c7a8dc68aesf1122580a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628264; cv=pass;
        d=google.com; s=arc-20160816;
        b=ljCx/ofdOnVbIwTOJ5l1pAWXJMQh+hpQ4noccxWoF5Jlf10ifCUHMzXO6tRLFSgrrQ
         YaDO+ztug9cDawZ1+RVnCGBBtSJXm2vwOFJJK5fcgtNPoTXdppEjiCYVPjVVPKu3KiQS
         eYa7ZIksTMZcUYhdud8D5bHH28zvdE/dQUd1wqykqWqVzZIzw9hMqI8DLUBde6QDVkyr
         k0yZpEFh9y+bDEfVvAsJhEpD7hrWX8ateuuqK/C0XbtMtiQ+eijDduVSHSokToMeLd4C
         Y7X7foJAIF/hbuEaCVeevU/hEs1i9A3WWBHUb3LbpKSQahne5b0dNrbi0pslCvQwSh9f
         2prg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=Ge7Bxh8BiZn0No7/pmzx4qeSbF/YY1z7njML0LfOmc4=;
        fh=IlzE25ZKCUqN+fhLwOYpTZDQCvCnRRjBJrvOald1DpY=;
        b=HP1JwCrUrNne2NWnwkPZXG0878Qa8RMBNDMfC0cFwnfWaEjfcJZ2Vi9IhJZxbkxH8o
         mU7roGeW7+2SmSFqX1Eb+Z4v5Lgys/grGiEJ7eWsQimUc2d+EAFF5iGrnuUACE33MJrq
         i2wYzm2FRPGGiMXP3qJnbEJwJgEJVPype5reDGrOHkNQVUYT1X6zuwQYoYx8HMBtmBfp
         Kx7c4wPpmAg/EDyFQKheIzupbe1K0a51FxPLWlGXbnnj1S6Sf4JZAbTsoDxGEUlsjRiI
         AEv0sEpm0NBO8/b9fxY5h2ShTAxhNTaWQM9NnNffunQviGYrWt3wASnFXBB9svpHxJLO
         hHVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=UaKHyIDT;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628264; x=1720233064; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ge7Bxh8BiZn0No7/pmzx4qeSbF/YY1z7njML0LfOmc4=;
        b=a6b50FRKEPgkLqfGZ6iW8KofdUDMdewe/95r65hvRxEgFYAmcNHFuV/CbH3SWgUqyc
         ykhjOJydJ9ABmdQgmtnkoOV7fiWPhNvFOHplwTHCwPOuzICxchdbQBw+sGVi9w6S2d9j
         ah6nkfluhGLgF+0TKSvBqJ1/kYkYLObpIupfAE7EAtej7O4asClu8f59inKYMOvdN21z
         ov7wOIkofoTGWxCHgIPbA8rUUKod1cXpnfvc8pWo4dwIuO15lERbBMKdJ046OmUuP7jW
         mnjI5zPexzg557jHyzgUMXJz6QCrpGizjPyhnOsfNJPFi0rrz8dRQllRvXfX/vRHYT0f
         VTbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628264; x=1720233064;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ge7Bxh8BiZn0No7/pmzx4qeSbF/YY1z7njML0LfOmc4=;
        b=SgDM3bYkeLniWEGINLh/E3A2Alo8Qila06xV7ENMRLUPQQGah3fPfl5Uk7LO5Rwtm7
         Uco8+KnS2APBaSy8lCRw5TG6Zze9V9oZZIeFMpJipZgW9kB0qDQja0idkG13Rh1KGiAu
         KBt7rjN/23sspuL3+gL9+tRGtXixvSB08ZE+gGCaTIDg3VBOi4kyK65qjbHHb1fmiMmA
         hSxl5zA2AWRJNY/9sJa97TTp+bvI5Ms986Ya7tmJiTj1+BP/p35LpPFxWiTp17p9OpQY
         PtMLVRoZHcwnEXFqzxzVlYub4mV8hFX4Gic6FFjn7mMEWG+WLuUL+CVqlPp9bvJXrQi2
         ha4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUsoRr4trFvI0t8Gi/PWbqFepBnwp4jQmVBaxMOhrajijkttTl9/NK1jt7RsQ6ITm3O4V8axKXKYj3ZWSkdVPiNAHq5vVp5zw==
X-Gm-Message-State: AOJu0Yy9wbqmB6bgzgnRhm03r8ipVOr6Bt1gvfMvxVW/rJquL2Db/L3M
	8eg1eZFwwYJomH3HbPC2sZvCS5xp/dpm4Blt84dUF3+9xXlLisx1
X-Google-Smtp-Source: AGHT+IG22fA63KLC4aMbLCXR2Fvczjtt2EogwFOSEnQT+j0HX2dwV7Nbsw+9Tl3RzWndeB+AFkC2rQ==
X-Received: by 2002:a17:90b:34ce:b0:2c2:d243:e8b with SMTP id 98e67ed59e1d1-2c8614ac695mr13364301a91.47.1719628263847;
        Fri, 28 Jun 2024 19:31:03 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b46:b0:2c8:1a7f:5bc3 with SMTP id
 98e67ed59e1d1-2c921c48b54ls680819a91.1.-pod-prod-06-us; Fri, 28 Jun 2024
 19:31:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPdoMfECVJ+wq/9mN52zzIWX4BfpZEX5SqTZqaibWp87dfknxcchNXw6qK/JP5cB1DeqRVA9uGMv59E0GYdMsF0aLr1uNdXuwcjw==
X-Received: by 2002:a17:90b:3a85:b0:2c8:f3b7:ec45 with SMTP id 98e67ed59e1d1-2c8f3b7ee0emr6024857a91.36.1719628262620;
        Fri, 28 Jun 2024 19:31:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628262; cv=none;
        d=google.com; s=arc-20160816;
        b=glFXN7HwkCHUHsL+C7fAP60j3xdmjrEnoWWFPmBhjbK3kIOhGiY20txEEiRLsD6W+H
         b1qGNKVONeC2ng+1beb0mXxb/Y2meBkbGBQErj4nEWk2Vmq4C8r9t/lMNfEwfZMo60S0
         i02PAw9bTH9DNozsR6ac1GAAWHVX8fRiJoaDLDeQq1LB/UKhj7XTrvpJ6b3kshiJINPt
         8Ptmf2ktnBqPB1hOBxpQl7z2cqz+ccTNHO2NaGOA7hyZnkrbWjmE7Z3HYU/t2Yz/N5pI
         HRYoE41BRDgg2ekuFVFemahosR8hJrFlqSJRyAGvYYsAetin1JXJ9G0gA1apV/BOFgYA
         OumA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=xOAhMIUHCoPellD9aHDOWUlASSmPJoubVFJWbTEJI6U=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=mWsInOFMIU42pMJITBba4Jdl3jCQEoguurWF+yGE5t8OZQ8WcwwdgLfA9HOP0PRh2A
         qD9flxIDojo5J/uCrBR4PotOndPFa00/CZ9+CoIBoZ7+pdDbNs+lkhBkUFAGvA4h3hzF
         PcVbvQXJg0POCbWwFOA2o6GwRUCxpQCXEP3Ak9N4nkh7TwiyC/LN/S/dQR7B2PXzuv/M
         LOzBB5rxsKvJdk2oyB445kga3DgNDXd3DtFKien/BLZmqbROeEPrVi6Ddjz1oawJKqeN
         uwCPq8Rd0Hc64fuvZIF8ZyWk5aD2e2bsuCuvn4MjwW8BnNO+A7lnAixcWk35e684fgaA
         974w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=UaKHyIDT;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c93bb01755si26190a91.1.2024.06.28.19.31.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 778D5CE3CDA;
	Sat, 29 Jun 2024 02:31:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A3948C116B1;
	Sat, 29 Jun 2024 02:30:59 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:59 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] mm-kfence-disable-kmsan-when-checking-the-canary.patch removed from -mm tree
Message-Id: <20240629023059.A3948C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=UaKHyIDT;
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
     Subject: mm: kfence: disable KMSAN when checking the canary
has been removed from the -mm tree.  Its filename was
     mm-kfence-disable-kmsan-when-checking-the-canary.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: mm: kfence: disable KMSAN when checking the canary
Date: Fri, 21 Jun 2024 13:35:03 +0200

KMSAN warns about check_canary() accessing the canary.

The reason is that, even though set_canary() is properly instrumented and
sets shadow, slub explicitly poisons the canary's address range
afterwards.

Unpoisoning the canary is not the right thing to do: only check_canary()
is supposed to ever touch it.  Instead, disable KMSAN checks around canary
read accesses.

Link: https://lkml.kernel.org/r/20240621113706.315500-20-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Tested-by: Alexander Potapenko <glider@google.com>
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

 mm/kfence/core.c |   11 +++++++++--
 1 file changed, 9 insertions(+), 2 deletions(-)

--- a/mm/kfence/core.c~mm-kfence-disable-kmsan-when-checking-the-canary
+++ a/mm/kfence/core.c
@@ -305,8 +305,14 @@ metadata_update_state(struct kfence_meta
 	WRITE_ONCE(meta->state, next);
 }
 
+#ifdef CONFIG_KMSAN
+#define check_canary_attributes noinline __no_kmsan_checks
+#else
+#define check_canary_attributes inline
+#endif
+
 /* Check canary byte at @addr. */
-static inline bool check_canary_byte(u8 *addr)
+static check_canary_attributes bool check_canary_byte(u8 *addr)
 {
 	struct kfence_metadata *meta;
 	unsigned long flags;
@@ -341,7 +347,8 @@ static inline void set_canary(const stru
 		*((u64 *)addr) = KFENCE_CANARY_PATTERN_U64;
 }
 
-static inline void check_canary(const struct kfence_metadata *meta)
+static check_canary_attributes void
+check_canary(const struct kfence_metadata *meta)
 {
 	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
 	unsigned long addr = pageaddr;
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023059.A3948C116B1%40smtp.kernel.org.
