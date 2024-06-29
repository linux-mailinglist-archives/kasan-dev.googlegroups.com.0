Return-Path: <kasan-dev+bncBCT4XGV33UIBB6HD7WZQMGQERA2W4VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CD5A91CAA5
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:22 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5c22485b47csf1201156eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628281; cv=pass;
        d=google.com; s=arc-20160816;
        b=iFpAdsEYi6FPOoaA/axlddolTyWaWnDxtEb4ZoERkobj2lPnqG+IDkVztv7kO/xVEL
         Df3gVnxg6DPllH03HIgSoon2oJ6VJWw8mzDwSC+TchVNKXPJE4HfJZUG8LHjpFiwEewE
         Je3WBifFq6uYJMsk/jZS+wg9z4vhEXuiKt2ohDWyJDevvzHv59tidJKj1sYXrFQ9yBhF
         gq43WLmIOARauQsWhhFVGgnBnBhq7o2oTMfo4SB8Fz+BTR5DbC/LRgR45PDsPlDfNs6q
         NgAoftPiFZeuzmySo8797Pkvwhq+99q03pBJRqhgEqHxO2y2WkDg83Ll/MyEvg0SBYb+
         sjmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=dDazUXNKihGiaIhn2akBkw9NmIWnjYu2L/+UZBzqivU=;
        fh=wURuqIJl46tVfbr9odpfaU/GVtCuaAiyKK2lXdwNSN0=;
        b=t+hpmB+14S5/ym03kVpvUDWZHAYI4Xj5zWecV9a3Ns+rUuLNL8rE+3PBAWhNGxycX/
         ENKdKNJCXdaPVNLEwlvkKUYFDJdhAyXndoS6hPlc0RUvp6ePWuOfdxwX85Q5NN/dqUue
         tAo5/TED5fXAiQlXUvJJuffxSOX7D2P2/Jmu1YIxSR5OriUFKSUFdB+gyC1roVsKKMib
         NseA01MVt1gvZ3+hrhEw6Syt3BOylUeZbsXkb+TfuoEJVUq+0vYsK16UUa3zwRX3xXcj
         9ayM9Fhcl3d59FBAc5GgjvW1yseaWI2KkYQOAXAfw7DLqt/1gwiUTmHbeCbczLUSetEN
         k8kQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=0TpOQc7U;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628281; x=1720233081; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dDazUXNKihGiaIhn2akBkw9NmIWnjYu2L/+UZBzqivU=;
        b=bcrcnM5NFcDiLAUDi+Hw+haoCLjN+6gCGrZHCDTHPfg/Gnx/tt7mUkf+z0bTjz7ePM
         52nj28rkbQO5pFeEIwcL5gt6tz3cNSOBv7b68J+meB2wMc0mWgUBtX3y/WmrnT9RZ5Cd
         zNcRhjvqN9YPN94nUnFtKZJrsyQhtUmaxqu6kcaTejbcxDBUeCSkakN11pd5a5CZKmYh
         cKcnqK3MJbh7BEn1AFdPpwR0y1OgQaK8pyrJY56H19hE4fGXia3Xky1esbZPjHA/2DhO
         hnVbSaFBaXZQ7YrakbrR+CsHcAZe15EGMcupwmxUN0KiaLZx0QY3jO2bYoWTsUs76KsX
         12hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628281; x=1720233081;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dDazUXNKihGiaIhn2akBkw9NmIWnjYu2L/+UZBzqivU=;
        b=FhPaIdRKNyV7x8n1w4cBu+i+zEe+eluTK8/3gKxpF5Hf8F8jvw+PWCioucClz0/gFm
         5S0/SXMfBjqH99iZH4gd7axTcyfZBXQRn1yiVAHbAkpe+0ryPR9Ei2t2w/KB239NQIDX
         hpLJYzoJmODpFvlvEJ8PI2yVOxCOzegmdYoaZeF98VHQGwQHDSLXrw4EFoAvrqemCErW
         VNECksBPf8K9QSu2YnwUJb6Hn1PWDImS4RsQQ9F71e6DOxNM5HtFK7ve5M4K+aevbbJ2
         gnoFSjm3ojOGsIXnUk5dJEG2eeSjNuNxxVBIAcblnN4Vyl/I+VkW3oHe025m5Kdpuakl
         jahQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUvtZjS+WV5wKfKFx50D85Y17v8JxZAmXKwUZ74ZM0ORJukwecSxWbhvnZeDwkSu/UxAw9dfU3wkyngGJcK+sjsm5SXiOi/KA==
X-Gm-Message-State: AOJu0YwnMGKe736kAAXYRNU0ATKjgW1SbliuuUR+bvHDp7h1Mrv0Ro4u
	JrG1eXCTnP2FeG+XZ8+bRgsLdcKOpWnJG9kclUcbL/4LHu+WDewO
X-Google-Smtp-Source: AGHT+IH8SKMHMZ1hVwv+ACJ4UCxZn6AzWyE/sgju/KspIkzVjiPIzJtoC/8TSLI5x/WeECSxegIjFQ==
X-Received: by 2002:a4a:8289:0:b0:5ba:ec8b:44b8 with SMTP id 006d021491bc7-5c1eec27800mr19274689eaf.3.1719628281051;
        Fri, 28 Jun 2024 19:31:21 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ae0e:0:b0:5c2:24be:40c1 with SMTP id 006d021491bc7-5c4200cf293ls1107638eaf.2.-pod-prod-09-us;
 Fri, 28 Jun 2024 19:31:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWVPTciTjOK3xsMr8hZgetf64pCXQusQ9CUSet+xjXNEuXj2yWqKG90EXqBLaPrITUoo2JT5SyYlL6vWfn6C5QvynLk1h+DWnS2bg==
X-Received: by 2002:a05:6808:2211:b0:3d5:3698:edb5 with SMTP id 5614622812f47-3d54595d9f0mr21809767b6e.11.1719628280154;
        Fri, 28 Jun 2024 19:31:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628280; cv=none;
        d=google.com; s=arc-20160816;
        b=KRPeqnVH0rH7TqGaQdtdq76X7/uuUgVaW5nfjrDJY733PZY8eWVADbye7+10uvbXS/
         v6R4jowmMYGtt+9uRvB9oa97bAbs0CPYI3gSfh7OdkBMReIeQCyEyOfTAx2jOcfNHdvp
         RlUjRuZ9bvGndVyIuc3Ai7cS3wFS4+8JcRyYhc12veuaE4fU4zxKhhUqolpArJcKD0sC
         T1NDdAFv/q8zos44tW1eLEp7fIRNPEmljhPRZc275uyLNouuw/XiQNkgYvzEp6LEfGgh
         7VbWmF8vohLP7Bj7nBm4YEHJg0ezP5WTfQKsbGrYnxrMXjaw0727dRb1tkdQN4xgb93u
         +7SA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=o+ADE3hU/o4pu9DJAaHm1nINZgZ3XuuCYSXJGOzA7G0=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=TyFpdYfICcK7u5SoFDRBcR/Hg/K3pLcNlCPmDaZaR8ANg3LrbMGRxDghwqUulpvqkK
         FOz5XJjps/Cb3qzMYYxn2BDG7V1qojA7ND7N027Z5zxcFmq09ikL3Ysx7Iq7m4hO8gSj
         sjmjYV8NBLZSINFsA60ptwFGoDjTW4VCq5JKbRDNhTc06QMqwOCXUc/m1742t7sBdooo
         txTMAuL8Xo0MZrKtD/0rqEPQ2zEYv+Qg06MaYIEJgcxws5qY/0MYeGAteBWnzx0QwM3E
         Vf+2/tDW3J9c4UwL3esNY27IXx4fQBkqCEGIHBXs2qyhrR4C1SIodN53VXjVjN1ye1Qm
         XvlQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=0TpOQc7U;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d62f9c3786si132582b6e.2.2024.06.28.19.31.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 8F5EDCE3CDA;
	Sat, 29 Jun 2024 02:31:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BA8F9C116B1;
	Sat, 29 Jun 2024 02:31:16 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:16 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-mm-define-kmsan-metadata-for-vmalloc-and-modules.patch removed from -mm tree
Message-Id: <20240629023116.BA8F9C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=0TpOQc7U;
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
     Subject: s390/mm: define KMSAN metadata for vmalloc and modules
has been removed from the -mm tree.  Its filename was
     s390-mm-define-kmsan-metadata-for-vmalloc-and-modules.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/mm: define KMSAN metadata for vmalloc and modules
Date: Fri, 21 Jun 2024 13:35:15 +0200

The pages for the KMSAN metadata associated with most kernel mappings are
taken from memblock by the common code.  However, vmalloc and module
metadata needs to be defined by the architectures.

Be a little bit more careful than x86: allocate exactly MODULES_LEN for
the module shadow and origins, and then take 2/3 of vmalloc for the
vmalloc shadow and origins.  This ensures that users passing small
vmalloc= values on the command line do not cause module metadata
collisions.

Link: https://lkml.kernel.org/r/20240621113706.315500-32-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
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

 arch/s390/boot/startup.c        |    7 +++++++
 arch/s390/include/asm/pgtable.h |   12 ++++++++++++
 2 files changed, 19 insertions(+)

--- a/arch/s390/boot/startup.c~s390-mm-define-kmsan-metadata-for-vmalloc-and-modules
+++ a/arch/s390/boot/startup.c
@@ -301,11 +301,18 @@ static unsigned long setup_kernel_memory
 	MODULES_END = round_down(kernel_start, _SEGMENT_SIZE);
 	MODULES_VADDR = MODULES_END - MODULES_LEN;
 	VMALLOC_END = MODULES_VADDR;
+	if (IS_ENABLED(CONFIG_KMSAN))
+		VMALLOC_END -= MODULES_LEN * 2;
 
 	/* allow vmalloc area to occupy up to about 1/2 of the rest virtual space left */
 	vsize = (VMALLOC_END - FIXMAP_SIZE) / 2;
 	vsize = round_down(vsize, _SEGMENT_SIZE);
 	vmalloc_size = min(vmalloc_size, vsize);
+	if (IS_ENABLED(CONFIG_KMSAN)) {
+		/* take 2/3 of vmalloc area for KMSAN shadow and origins */
+		vmalloc_size = round_down(vmalloc_size / 3, _SEGMENT_SIZE);
+		VMALLOC_END -= vmalloc_size * 2;
+	}
 	VMALLOC_START = VMALLOC_END - vmalloc_size;
 
 	__memcpy_real_area = round_down(VMALLOC_START - MEMCPY_REAL_SIZE, PAGE_SIZE);
--- a/arch/s390/include/asm/pgtable.h~s390-mm-define-kmsan-metadata-for-vmalloc-and-modules
+++ a/arch/s390/include/asm/pgtable.h
@@ -107,6 +107,18 @@ static inline int is_module_addr(void *a
 	return 1;
 }
 
+#ifdef CONFIG_KMSAN
+#define KMSAN_VMALLOC_SIZE (VMALLOC_END - VMALLOC_START)
+#define KMSAN_VMALLOC_SHADOW_START VMALLOC_END
+#define KMSAN_VMALLOC_SHADOW_END (KMSAN_VMALLOC_SHADOW_START + KMSAN_VMALLOC_SIZE)
+#define KMSAN_VMALLOC_ORIGIN_START KMSAN_VMALLOC_SHADOW_END
+#define KMSAN_VMALLOC_ORIGIN_END (KMSAN_VMALLOC_ORIGIN_START + KMSAN_VMALLOC_SIZE)
+#define KMSAN_MODULES_SHADOW_START KMSAN_VMALLOC_ORIGIN_END
+#define KMSAN_MODULES_SHADOW_END (KMSAN_MODULES_SHADOW_START + MODULES_LEN)
+#define KMSAN_MODULES_ORIGIN_START KMSAN_MODULES_SHADOW_END
+#define KMSAN_MODULES_ORIGIN_END (KMSAN_MODULES_ORIGIN_START + MODULES_LEN)
+#endif
+
 #ifdef CONFIG_RANDOMIZE_BASE
 #define KASLR_LEN	(1UL << 31)
 #else
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023116.BA8F9C116B1%40smtp.kernel.org.
