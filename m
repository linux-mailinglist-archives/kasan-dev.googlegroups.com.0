Return-Path: <kasan-dev+bncBCT4XGV33UIBB3HD7WZQMGQEGZPCWNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0079291CA9D
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:09 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-7f61a2adf94sf125391839f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628268; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yfe4grxIiuEuFH+Vjkk1Rl2QwObvlXQz7R5588F52nHZuCp3vtxsa6aiShnvD+f/fw
         +gGWkoZUrGnPZs2ruL4VbivCc5f8hBCVI7JSfc+v7uPEcl3dSYIHVtq9ae8MXHbfSzuv
         q4xakc/1JYhzjcVX1bNod92wnD/LZXKXZk1RtMMCPMKcgOPzbsdaR82E9jL5ylLCxux2
         E+dDoaVPwa6zOH3vc6refEeEpbqhgKT5dtF7410/QBOTGd9iqLMt8tS0vZbdi85OxIL/
         MqgWAA3SRbgb3sau7Xl7fOntznfHvl+1u3tuac13o5LoIEFgpsYpp52JUWQgETLTtnla
         S7/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=xe7c260pcaxP3u6+QiDl7lJ1++5j6Z4FB4zjMEs22mQ=;
        fh=O493K8ZwvVvepOIG9KxeWoIP5nVvF2lof5Zmnhf6Urg=;
        b=M9SNepvxKjv3XXnOlHIndNxf92s3/krdSHvsprgJ3ZI5cGlpTl1InY/YZAGytoxW/j
         aKstet6SAsFRHV4sTW36Qa08YZ61dGhXiH5MyPuSY4M1VNGf6U5y6fzvBU2YKG5V37JA
         DccXfEAuqIzly4hNscfwyYL6quUVpDcsWOfhnF2q/x9jRpxAaZ/XlrRUtQPxppvC9Kiz
         qX8+pCvdT/+hAuFczZfSwO8QnVCLFdBtOrf9KQcZwhCj+k34efoX3BKib/9dqDwFZZLf
         f4JOxXd3yDrdSYTXaTNnm6qt6yv1s2TFPYz4kik4GZTEcvDYhMi+ZZvaVef54h9SE2HR
         6i5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=aSjJOMLq;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628268; x=1720233068; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xe7c260pcaxP3u6+QiDl7lJ1++5j6Z4FB4zjMEs22mQ=;
        b=cI/zFE9gHBQoTuL2zKyOS4q+hnVGQHSmtmqwSgwX9Z3Zg+9+e98u9EyyOXd033o7DO
         RuKTzR92BPtL0blO8O0Evapka3LYChbWohHLmGw0shmWVsIw7bUHaqvnj6cyL/uZq+h0
         kM8yJ9Gb37IBUN9/z7WOzXaIUArhbNrxhaGG3iUo5W9PzZthyCEdl6IpY/kMrEALIbzT
         fNLdTsyTw0cBIeIYRV7+opeFakahBl1BBsqLQlyHHI5pwedQ86blNTLtBsVNscms9ZyT
         HqFJZXI6rNli7TBOwbnze/IulpW4H4FPxEn1gAYPnYQeAu2+D5ZiD6K4wfiP9RL+kpQi
         eo7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628268; x=1720233068;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xe7c260pcaxP3u6+QiDl7lJ1++5j6Z4FB4zjMEs22mQ=;
        b=GLWYah9gPwigXQpAMNziSWtrEaDAV4OazE5Y1D9at5d3vfStaIucjnfYujYnC2KxB4
         3y8L5pw0y6P6HlMrqlpX51z7lBsIsRBYgruek9GCwklxoxoHp/TW907/j0tkMooj4QOE
         wHraGb2Zhm1AxdWq6uCxuCKKkQcTyaBn0B+qO8kstJOf1uvM7a0b+A1EYIGMWE37v8Rv
         d2cwEWgYtMn+zNqOomiT2aiUgVya08GEKfPrcZJiAElGBU6GWX/GLgrLb1Kd4BtG7rfx
         9uNm0E2RGMZXHvkuLc7NCMhzsIgWj7WRLffFKsfxrs2PhmPhEWL0CLuoGjvXiHJMbLbk
         WeVg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUFszTkxyC/RV0jZ6UIeRIXuh4iVGasJxZs6mwp4aXUO7udYlSYnoKamjIeCsgeezr1Jc52Y/CuHx+BFiIiRLV74wpPULMJgg==
X-Gm-Message-State: AOJu0YwV1gN2Dmpi/3MjOmFpFkLHAXPpnwmyG+Mb+kdAGrjYRCroKnuj
	k50HfyL67Ig3xJGThsLbkVnEuRuAimMeLzCrag6GbJwh/vYDWMSI
X-Google-Smtp-Source: AGHT+IGKMjJg15YzKxr1GXbSQLfAdaLNoablEgGfMS4cd0Z5vqhz5c2MZSy/47e+3SQl21X1LkwdCg==
X-Received: by 2002:a05:6e02:188e:b0:375:ff24:f04a with SMTP id e9e14a558f8ab-3763f708d16mr231867225ab.29.1719628268434;
        Fri, 28 Jun 2024 19:31:08 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:216c:b0:375:dc18:bb99 with SMTP id
 e9e14a558f8ab-37af1564792ls11149305ab.2.-pod-prod-04-us; Fri, 28 Jun 2024
 19:31:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXa1sdPrABYUx+OTn/zWyrvqMbNiJwV4Irz0UGYaEi00YazXu2Y7rcjLtjidaX8cpq3nCGo3J7ZHPTX5H1oxXhRQx0pyRwPFJ4wlA==
X-Received: by 2002:a05:6602:808:b0:7f6:15be:a6e0 with SMTP id ca18e2360f4ac-7f62ee82b0cmr6105139f.20.1719628267617;
        Fri, 28 Jun 2024 19:31:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628267; cv=none;
        d=google.com; s=arc-20160816;
        b=Z4ubGbDVeWN22W6uL26oj0ZxTbKL0dzZjwTJegYIQLQOmn+JUBvbGKp2+iq8D+zra9
         sOOXdrKkTSkE3LxvZeQ+5n3VlU8NDQZjTfyNx7PcMTbZBhsm2RzjMOBvflcuV/b76wO2
         UWKbBm+f5XmAHIBm9TY8u0jrE3scOJzlNkUtwNZN3IGW6OVLA0CdwidYkxmgVliXaCHp
         nHKpZIss2/U1eGoAcZuxBX7mOsHOBrQo6Tt2Xqon/kRZ+F5+YyoWn+PJct6Bti660KnL
         E6K2VlZOgZYc/gvtz124W7gwDOkc5qkUTExTMrvRRdYCSmuaIgZKraYd/jtVuJJa9Y2X
         AvSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=a9LwF7HgOa0rSyewzQiitCwpMeBlSHAMsZazuYOWpTM=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=oAfZBXVgzb9sAUew74vRgCTAS/VAMnglJ0Zi//Ayv48kSHgsoalNPfIQ/ZCXHZJOBc
         LrH8Kvlu6K6ijCo/+RyqloMJdIPE5k8EbrHoNbSJkHqIYG/d1LXsyTie0mUhded+BYdz
         gn76Cnhl8HkJP9n00+rtRs9GIj1RwdXuDkIsr1a7H8Jh3NkT0PHRuyMHj83WUe4TzO3i
         0ke6AsPXMtKykRAUUiSLYE4g3iZK2rbpwHo/4rKIDm5nMnPe1niPjJVg8LJR2TWAYVnx
         fLssDndS8+JXCsqqtZSebrD92EQnCeH7Rbyk1TrjXU+oUcammqKZk2bQ3vmOK2W3uWZx
         gTLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=aSjJOMLq;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4bb73dc2f60si116861173.2.2024.06.28.19.31.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 25631622C2;
	Sat, 29 Jun 2024 02:31:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C2342C116B1;
	Sat, 29 Jun 2024 02:31:06 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:06 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-boot-add-the-kmsan-runtime-stub.patch removed from -mm tree
Message-Id: <20240629023106.C2342C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=aSjJOMLq;
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
     Subject: s390/boot: add the KMSAN runtime stub
has been removed from the -mm tree.  Its filename was
     s390-boot-add-the-kmsan-runtime-stub.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/boot: add the KMSAN runtime stub
Date: Fri, 21 Jun 2024 13:35:08 +0200

It should be possible to have inline functions in the s390 header files,
which call kmsan_unpoison_memory().  The problem is that these header
files might be included by the decompressor, which does not contain KMSAN
runtime, causing linker errors.

Not compiling these calls if __SANITIZE_MEMORY__ is not defined - either
by changing kmsan-checks.h or at the call sites - may cause unintended
side effects, since calling these functions from an uninstrumented code
that is linked into the kernel is valid use case.

One might want to explicitly distinguish between the kernel and the
decompressor.  Checking for a decompressor-specific #define is quite
heavy-handed, and will have to be done at all call sites.

A more generic approach is to provide a dummy kmsan_unpoison_memory()
definition.  This produces some runtime overhead, but only when building
with CONFIG_KMSAN.  The benefit is that it does not disturb the existing
KMSAN build logic and call sites don't need to be changed.

Link: https://lkml.kernel.org/r/20240621113706.315500-25-iii@linux.ibm.com
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

 arch/s390/boot/Makefile |    1 +
 arch/s390/boot/kmsan.c  |    6 ++++++
 2 files changed, 7 insertions(+)

--- /dev/null
+++ a/arch/s390/boot/kmsan.c
@@ -0,0 +1,6 @@
+// SPDX-License-Identifier: GPL-2.0
+#include <linux/kmsan-checks.h>
+
+void kmsan_unpoison_memory(const void *address, size_t size)
+{
+}
--- a/arch/s390/boot/Makefile~s390-boot-add-the-kmsan-runtime-stub
+++ a/arch/s390/boot/Makefile
@@ -44,6 +44,7 @@ obj-$(findstring y, $(CONFIG_PROTECTED_V
 obj-$(CONFIG_RANDOMIZE_BASE)	+= kaslr.o
 obj-y	+= $(if $(CONFIG_KERNEL_UNCOMPRESSED),,decompressor.o) info.o
 obj-$(CONFIG_KERNEL_ZSTD) += clz_ctz.o
+obj-$(CONFIG_KMSAN) += kmsan.o
 obj-all := $(obj-y) piggy.o syms.o
 
 targets	:= bzImage section_cmp.boot.data section_cmp.boot.preserved.data $(obj-y)
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023106.C2342C116B1%40smtp.kernel.org.
