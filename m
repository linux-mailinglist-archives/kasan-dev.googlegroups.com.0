Return-Path: <kasan-dev+bncBCT4XGV33UIBBT7D7WZQMGQEVWE5FKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C6B7E91CA88
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:41 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-25ccbf14923sf1416433fac.2
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628240; cv=pass;
        d=google.com; s=arc-20160816;
        b=MJy65flUSIB5QnoYovlt1p85NVm8XvBiPI8lJRBAda2bnRTJNeTIbOCooHFCWXrVjD
         sohOYwvnLKGPncZzmousEOpq5HWvt0JSzIVTNUPN+1S51VSq26dAQMArQXCCJ3CyVF4D
         4vgR63hOvZvy+nzn3j8tCXtU5fDBVt5T6Nlu2gSnBihYnElPsGJggDSVaHiRw4/WhNBi
         1hmLXeWsyBES7P8YJewnPSp0MQt8Zk7PtFu346bhFFvRslaXNI6O+ygyVk+5DA4e94QT
         aQTspS5cUro7zEo6skHXB+lWQWbBpQSMlTgtqzv3rRbXpvms2eBiyBqt6y949unZ2jvc
         tfLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=k/gewV6ZtjJ5pT5nZ34GPUs/HFXJL3jBbnsdzitTJ4k=;
        fh=Kqgc4mrq9qi/9E+YtLZEXoqBDpb2B/lf0v9BBWTz2hI=;
        b=jhh+z9rQ3CluITzO5DKzVD58gP9QW0KjQNUfKvRkJjL1Giy54yb/r9roOQKqzVGTTo
         UWyLyowVTCeEXr2tU6hmKzjZx6wIXfXktfHEz+ArGQtaerQ5UPUMB4r0LnFryRXxUeJL
         dask0YUfN4RjeDvTaew4mPnt6fl7eqTVDPm6bginhSxciaYkbFOggEv5KP4LG7H0w0WY
         sDSbs8T5LVQQGB43Z38cZYph16IGbQD1RwrgN+4oHWrJ8Yq9t4zIw4uQDM+9JAJZBuEX
         MJ1dMfuKyxBcphb45VSdUElg9CNbWtSwV98v/g9s2LUOFV/N0QkSGcysah2Slj+vdc9e
         1lzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=T3TgrCM3;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628240; x=1720233040; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=k/gewV6ZtjJ5pT5nZ34GPUs/HFXJL3jBbnsdzitTJ4k=;
        b=A8d+dEwfuFdgmmomOpOwBfuptYyiPulLl0eZneN9gnWm7Fsse7eiQUdEoN4Df6gGHU
         md5+YZmXpgadkYO2pmTzF/wLbrGaWCiSYYtc4gPyfRqm//cG/eRpQrzwbx6p8BIveqCs
         OheyMGflc06298hRoGkoouoC3zN7XtcMgh5cPtT/HOXBckWoDENUAKY+N8Gkn0+Fr2/Q
         uadplGxRaihoi/t0dM5z1nFSN2yM4iKYM9YjVXyVdcTlsV2tRAsvFeSM3yyPZ0PsZ/f5
         xQR7wYxGjvPCEtxM3FjCgMWdWHbdCUcMPhdeLmA2uhvIXf35FEXPnD9F+2ogKf3xT+fg
         PhYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628240; x=1720233040;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=k/gewV6ZtjJ5pT5nZ34GPUs/HFXJL3jBbnsdzitTJ4k=;
        b=d8m1T5AZLnsatviNTL+7Q/DcVxPgcAQ+JXE/AK1/4fQ9O66RIOYWkoAPF+QuzeLXtd
         N5JpWp5mTktkG3ZgQ4c8NoxTq+UiuZGcSHDgPueLZEVMUYNwL4M47xSg39zTv7YxeRcS
         EVET4YZDKD3lpOPlMBhR7u5g/4o73yzNEYbgLzpRwTP/5bbzetk5JeWRYQBeF4NtBzLV
         I6ujkXQbtH+tZwFOn/JdLBXsSBaEAzaG1o0QzeEyjl5uJOyKNFFs/fjbL//aOEcWK80x
         teu8hygkpYcLh2G4GrXXna0PZJxQL40xvPWKTeuW6xqtS2BdG1b/CVNJvMltnXTAxXbP
         WK+g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUU62VegssnQjXpiFBi3brOjFtL8MqiAu4anAkF1kDR+6OLiKQq9XeV6ALn/iEO80FSDv6gAM2fkRB2/n35unp1F4pr29E4/Q==
X-Gm-Message-State: AOJu0Ywd1WtdEcVI4I8Pp7CWJ3oS11CZbWx6PPJ/tbI4NEqF5l8q46GL
	ffdSOP8kgXKTvep/w2v+FyJ4tlRURdA+/ZmGXb35fBu5HdGMZ3Uy
X-Google-Smtp-Source: AGHT+IE13PTQRtOw1NhKbjYwVafLGHgjk5q0b1HnHXaMCk7Q58Fd86QBcWEfEqvUZDSCT+lLnl4ztA==
X-Received: by 2002:a05:6870:a40a:b0:259:86ae:bd22 with SMTP id 586e51a60fabf-25d06c1b572mr18804983fac.13.1719628240020;
        Fri, 28 Jun 2024 19:30:40 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:e785:b0:254:7203:f69f with SMTP id
 586e51a60fabf-25d92c4c100ls1076719fac.2.-pod-prod-05-us; Fri, 28 Jun 2024
 19:30:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWI7YDpP9RP7pY5r/X/XCubT4fy6D0RU1CZWPIysGxDxObdVCwYcNbVw56G9iGTYrE0xvLS4k8nlM+3/FsrDp22UxG3v4f4FAxGJg==
X-Received: by 2002:a05:6870:331e:b0:25c:7c8d:e2f4 with SMTP id 586e51a60fabf-25d06cd02b4mr17653662fac.31.1719628239250;
        Fri, 28 Jun 2024 19:30:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628239; cv=none;
        d=google.com; s=arc-20160816;
        b=ARvg9b2YKtIAohpZ79jEoUIJZwnp5/bXuSgDwgJOrUXctIikAtZFt+RXJnH+gDAhRP
         0p5t1cWgM24/drDDLO4Cf99kl2RgCk6LvFTWWq+K3TrGnp4BjG51U11+m7DIDjExZRrD
         X9Jaq8cj2aSG1dRT+H84BsgRGZajpbPKJj+LL91J3qHFq40VDcetfikgpf5i6QLf4Nxm
         EM85yUC2BTBQas+7xe4Q9+bgdcH1OJj2lZSBGOMghVdRdaCqZG+mA9Jbsqqyofzawsf4
         SxOKIaWeiq+Xllnf3UWE2tmQ+s+QSNh1ohy07lCXWYMh+LYXfBkAE1qBPP59hubujy85
         N7gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=YlgsQK5sCUDvPNHzS1YMmcUIiQHmorNkfW+49N16l4I=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=fnJ7fjGw0HuBCpZpAec2tsdTRNJI1n189Fkat1hHIxFR833QqK5T8Xi9xvjbWTUrhR
         Cc4Z1sq8s9QdHfX0GWrPYTtV18S/Qa2WCR7Mj5tI4MeSyVBo7y9k0PTDSoW0mdqJWjDJ
         VBd0NvNOZ3yHQA3V53JnNh9m80HlliMtQMl7JbMZWTOXORk7Fl7+IWvMBF9B9z/+efOf
         qdj63wZBG4DSmBPJLaMF9fPagt4FnS5n5zRcBwxUtyItO8uQk/Ejnq6bTyiLVnl/cxZv
         f07uX9eLUR9akPBzoyCuISgMs5ojIjcWZMjDgmzM1BxyOEXTBTdXReaDun44OSEnzUZ3
         jruQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=T3TgrCM3;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-701f7b3ddabsi118320a34.3.2024.06.28.19.30.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 04CD3622BC;
	Sat, 29 Jun 2024 02:30:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A103CC116B1;
	Sat, 29 Jun 2024 02:30:38 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:38 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-increase-the-maximum-store-size-to-4096.patch removed from -mm tree
Message-Id: <20240629023038.A103CC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=T3TgrCM3;
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
     Subject: kmsan: increase the maximum store size to 4096
has been removed from the -mm tree.  Its filename was
     kmsan-increase-the-maximum-store-size-to-4096.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: increase the maximum store size to 4096
Date: Fri, 21 Jun 2024 13:34:48 +0200

The inline assembly block in s390's chsc() stores that much.

Link: https://lkml.kernel.org/r/20240621113706.315500-5-iii@linux.ibm.com
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

 mm/kmsan/instrumentation.c |    7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

--- a/mm/kmsan/instrumentation.c~kmsan-increase-the-maximum-store-size-to-4096
+++ a/mm/kmsan/instrumentation.c
@@ -110,11 +110,10 @@ void __msan_instrument_asm_store(void *a
 
 	ua_flags = user_access_save();
 	/*
-	 * Most of the accesses are below 32 bytes. The two exceptions so far
-	 * are clwb() (64 bytes) and FPU state (512 bytes).
-	 * It's unlikely that the assembly will touch more than 512 bytes.
+	 * Most of the accesses are below 32 bytes. The exceptions so far are
+	 * clwb() (64 bytes), FPU state (512 bytes) and chsc() (4096 bytes).
 	 */
-	if (size > 512) {
+	if (size > 4096) {
 		WARN_ONCE(1, "assembly store size too big: %ld\n", size);
 		size = 8;
 	}
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023038.A103CC116B1%40smtp.kernel.org.
