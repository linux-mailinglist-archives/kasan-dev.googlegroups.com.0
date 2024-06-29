Return-Path: <kasan-dev+bncBCT4XGV33UIBBZHD7WZQMGQEXUMMEDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id AF26E91CA97
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:02 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1f70b2475e7sf9371195ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628261; cv=pass;
        d=google.com; s=arc-20160816;
        b=bbq96N53cgweyCYcb+L1WPt14aKxe4KVvtUrAgYOTEy9gUTt2stjvxoP7sOLW/2Xi1
         UPr4k4WfOD0SQSleMuIhTJiUjxNdiojAtT5G13Hn1iXKkly7wNKgjJaEAxHxbiD0onOh
         giI/scflHh+U0gwVpGaT8uppkNteFqQwh16Se6djV7LjgIK8YWueFQA8aP2wM3pNPIzT
         /A9iSPSfnjHz/xWx9+Jm6tDc99XyH2kwG6MlRb6uOdJo4AberVu908P1q1iSdemmnCRc
         kp5dlpggtBpuSafqf1ry4nY9ukv5t5pTMz5FQ4DXI6OXTqsQSIkOuMuDZucscx4ZtQv1
         64Ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=UvjBdRv/c7RuJ4lqmPvcPAw3GHW14Ifvd9NlCv5z7as=;
        fh=+DPbvokMDu03do/IZHFoJgyO9zHz7fIAqp6gKARbeiY=;
        b=o99cYpaHe84XJULM4Us9pDMHHrBk6OTq97FrZTRWbHTXQb50TJegKuW9lk429rLJ7h
         9YN6jUXyobdFMW07Yw9c4udNJkKLmC/qH1Ds2fNCi7RWk8mvAC1YKgIijjwKduCTo+/h
         NmXcqKjkF9ufxFhSI/qI4C3sId9k8DsRDSZxjlXdRjAYEyoiN9eGR4y1xcPOxv03GYS1
         Kf3VHs5wqUCONvOgKYVtqSWo9c7LUrKWEBGN/dmkBITGfcWjYCLdZZDect4/d8pXFu6F
         ZuOQGVoQXs3jW+2n1LvbsXHLcKM+bad13pI1aKVmv6McxTpTqCYCyKLzHvbc604yhI70
         sb2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=vWL1GSuJ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628261; x=1720233061; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UvjBdRv/c7RuJ4lqmPvcPAw3GHW14Ifvd9NlCv5z7as=;
        b=VX6wGdfm0luexjW6A+3Cl18k+8g0cPew3dDdSkr99+GgMj3DniGRCdRJse5xAXV5pm
         vpSeBv1pmkjBrXw3cA5vlG+BfNca4mzsHEiktUwNw4kGgdhNtM3yld/UMPA5ZJvpYySY
         TD0HJldsvXv31u2xybONeO+8kQBQK9z2sb8BWOdkMmcBv0D5IR7akdFzC3qjkJ7WwJBa
         /DGocZOgDS02QbW1nStmIjA1EodYZLiGK/d1z3MJ0ufht24xU4Hubpnsbj15OSTpLKx5
         5Rt1PYeRKJUbZwxq+omL2V6o2EjOdyfhmludrK1xkDh+gleNxGWN2wlexdXjiY74nPEe
         QgcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628261; x=1720233061;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UvjBdRv/c7RuJ4lqmPvcPAw3GHW14Ifvd9NlCv5z7as=;
        b=H+672XDJpgbiTmuAmgwpDsdHCwSuwozrI7VGQ9VzqaieyEc7wcYcsUxUO1zOx/QbsL
         flTy1OwykKQR57t9ePItTbshgIGs7nXCZeMRdkf5E1khhI+8NmbA56hcg7F6dj0Ly2F/
         yAF4XaHvvfh6ViW2I/IUdMpDDznYp/M0CCfUIs3wnuRE4qes72HfN7y7wdqYA6GlykdD
         RIjIRqzJkE3YjJHojdScv22u9k2HgeZyXUazAxNxyGRBZxAI325Pgxa6TEBLttHxqdHy
         mtRTvCQhdAZ3TNrx2fNjWAHLrZlIrOvPesYtTqO1FoCFl6L0S+xf+ekmcaCciVwFqzJg
         lR7w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW/zvx3xgJWMOedHhwK0pzkWj3hLeH4HpGdolSFm0r8/xJ07BpXEWYtgSMiqVJriHcksmbAYDRwsgaTeIgEovizJP2NeGILXg==
X-Gm-Message-State: AOJu0YyUB2IMVvfuSmzD9TMtGgqMXoohcRFaO1Ut9uwzlyVgaDcAqUBL
	PNtZdNimx9EBwFQ2FslNXoF5YlFawX1awigmgHFUWL5m+adPDA+t
X-Google-Smtp-Source: AGHT+IEIdTxb2U0TA7BgLHsuCFeBZMMjk4KARmTw5lxlQTNp6TvU8llnlVn7v27QeWwy/+xbVrbeVw==
X-Received: by 2002:a17:903:18d:b0:1fa:1f31:e78a with SMTP id d9443c01a7336-1fa23f07182mr188522465ad.6.1719628260887;
        Fri, 28 Jun 2024 19:31:00 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:234f:b0:1f6:faee:c7e4 with SMTP id
 d9443c01a7336-1fac44cf15dls8665525ad.0.-pod-prod-04-us; Fri, 28 Jun 2024
 19:30:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVpMlSQnQyE9ZL7Awpy4P2ld2abyv4U1lN4cXXr+14RbAw3T8qWrr+u0HYMvg8gkaxPWk6qb61IZvrADur4FBRt2FLlzhbD2Aht2w==
X-Received: by 2002:a17:902:e5c1:b0:1f9:df83:8ab2 with SMTP id d9443c01a7336-1fa240c518bmr212813645ad.58.1719628259671;
        Fri, 28 Jun 2024 19:30:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628259; cv=none;
        d=google.com; s=arc-20160816;
        b=qP2haVmBU/B03WL8B8434zH2eDwx2wgmSiWydTm53rYE0Y9Z/2xvx7gJzS1Xk0vcmK
         s2O+eHjHsPWGcdjM9HaHhUq/YhSZEWdR/7dAYP+HQ7KT9XXBV1ZU6F9hbKpEkHfFGySi
         vFmWU19F9+wIzyY5pAdPhlp34L+MgL9QyPzDuEY5cZUQeXgsY0ZcuFrgVj8vvtNwC6GF
         bs2ASyzPWowaSoEinXdNN4SG9jEImzX60MHA9u84xHjW4XWfEdk2UIndn80PrAZJEPXu
         ecWgAFOu+8+MxvKn3UYSzxD4i7ZFZgGlmO4J8Rd3lMeAgT01xYpr8KXLj8V9WicUnYxt
         r2AA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=mF49lJTqj6jFIB2QxafEuSXVzi8PyCU5CO8rYEI8KW4=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=Vvi/oVkVGEimg8MNkJ6E6ce3sE/1RJi8E9m4TAOmqBLGIIxYAzTvKDbGd/4Xub7ZwY
         I2kgapgrh6HYJBGdiqM9g+sWBmS62cVBd+6VRGW2qPJsRcQteIAYT788N+R1Rcs20NQV
         8DErVhpXf52B4iucYsJjvPU573QV4KdgeGCi8YbU2sa3QdbynLsiWAeL4P1lmPoCUThl
         LZ4f9s63cIpsfRl53FEGjXLLUPgkM3k8Kt1q/bysstkW+PEUPPp0qHVZ1jCUUhWqXQJ5
         bXUk1C9h9Q6bfEQNxtsTWvOXFZLrtI0AcNEroc2pvpGyjq9IvItfBUKfSfoHlq6pHRAX
         zz5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=vWL1GSuJ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1fac12f6710si1175885ad.2.2024.06.28.19.30.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 9B651CE4334;
	Sat, 29 Jun 2024 02:30:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C7FB3C116B1;
	Sat, 29 Jun 2024 02:30:56 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:56 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] mm-slub-let-kmsan-access-metadata.patch removed from -mm tree
Message-Id: <20240629023056.C7FB3C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=vWL1GSuJ;
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
     Subject: mm: slub: let KMSAN access metadata
has been removed from the -mm tree.  Its filename was
     mm-slub-let-kmsan-access-metadata.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: mm: slub: let KMSAN access metadata
Date: Fri, 21 Jun 2024 13:35:01 +0200

Building the kernel with CONFIG_SLUB_DEBUG and CONFIG_KMSAN causes KMSAN
to complain about touching redzones in kfree().

Fix by extending the existing KASAN-related metadata_access_enable() and
metadata_access_disable() functions to KMSAN.

Link: https://lkml.kernel.org/r/20240621113706.315500-18-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Acked-by: Vlastimil Babka <vbabka@suse.cz>
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
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 mm/slub.c |    2 ++
 1 file changed, 2 insertions(+)

--- a/mm/slub.c~mm-slub-let-kmsan-access-metadata
+++ a/mm/slub.c
@@ -829,10 +829,12 @@ static int disable_higher_order_debug;
 static inline void metadata_access_enable(void)
 {
 	kasan_disable_current();
+	kmsan_disable_current();
 }
 
 static inline void metadata_access_disable(void)
 {
+	kmsan_enable_current();
 	kasan_enable_current();
 }
 
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023056.C7FB3C116B1%40smtp.kernel.org.
