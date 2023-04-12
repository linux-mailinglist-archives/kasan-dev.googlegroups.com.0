Return-Path: <kasan-dev+bncBCT4XGV33UIBBPF23SQQMGQEZYDE7VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CB146E0075
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 23:06:06 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-5144902c15esf218228a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 14:06:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681333565; cv=pass;
        d=google.com; s=arc-20160816;
        b=ypHq+lmH7F6Gpkqo/TQVtoLoRPT1B6A9qjGv30V9V+PcFvbI3osul+aAfGofkPLvNl
         f1WjJ4Jxz+hltl3uz3qZLKqUBqs1gWJZd2TVFeXgYb/9HijoiuRNUr3QcOBse0VZLPao
         EiCGTc09oeaqO26qYw+YONrZdm9ZvPyzAoFqfw1tP/++jpxqdLgnb29EGxeYiC+aaYb2
         FjPzYYv+dp0rGzxK46LrF61AjRF01PCpaVVxv4WVQP7+aEpZC9mIwyb35k3qoxl25Ar4
         Zx4uHeNXIKYchvydH7Y8TJ+OoKt8aRojZSgD3EgD9jjGYCQbfYb31PSf11wrvGV/0I0F
         2YIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=UBmG+0SYDyS3iBkurQ7cVJMhcuZazPduTxDBvHEV5Cc=;
        b=STh7AF9fFFk6wyZukasNBR6N3LQGy61qHVaugG40ijWZAwGYtwTXwmovkI1bbgINzS
         biKVn4LmPGB6celOw6xcRibrD7TR6gEOGFKA6rXnR+3eIvCjQsCWN4xOZ31Yzc5JANfI
         FaIYmz+2SA1S/FhRI9XeiVUoaTnkJQgg/h3Xys4lPw5q2lkxViZGQSZJLiGtwEO1NJLL
         sPX3lQ81B+A8TxIKkPtYC+pQerYQC7VVtkYRjp8SbWwiGiU1aL1THsDG1wOFs0GHhqvz
         WGRAirWSEtGR0w/UjMzHegW5OkQ9GaBX+RNRQerm0y6GnPpr5xVkfv+no3dq2LeKeF1e
         TiRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=rmhB919g;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681333565; x=1683925565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UBmG+0SYDyS3iBkurQ7cVJMhcuZazPduTxDBvHEV5Cc=;
        b=EameNeOTbxPr9DIZAZ/Z/cRy4sWWxmyxxPHHf1d9XuLBts/LFlmmR07WxoXl+Fp4YX
         IM6stmlxoc86hx910tUujPlz0RFkkA1NiTlyhlpLGMPqZjcuon4kbWGpox3qBnsU3vBU
         MlBwc+IUoWzaB8KO31aW2Nk8z9IHxokRfcmDgl84kLUHR5xKmMpdASzFsQME6tqesE/K
         OdNuKCicaXMign8xIR4OCDHgpX3T0NlED2pYLoddpskFH4tDcBNPJW1YeLE2x730Y05o
         IYEuOO7TAyVxqbJMbLcw/gz9MmHv1WTpYfNii5KqcquL0Ow/aUr/U52cl7q/Asjn225R
         P0VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681333565; x=1683925565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UBmG+0SYDyS3iBkurQ7cVJMhcuZazPduTxDBvHEV5Cc=;
        b=L5h1uyUQeQAfvIfPcMp12BG/46o9Bd4qrIjZTTqJ7u1lAusqMvI6HlAnJ9w9IMl80T
         xGgYv/jL0khYmbv7/j2n8QEdw1k1s96qRwqDcvp0r/lujkRcl6QGbBTsqh6xk58pyx2+
         5iwwU6jOCFIaDCGVZ7djqJiHW0egcQLoUIV0diktrGAc7y2+yrc9ObWVksxKfFBsTRgY
         ik57lROBivdQrgPWl3/w1xXMq3p0ipgTNbcbroVeT0kaGMRq54mdMxjEKHVNMgwX4cPG
         Wo1nb7EJ3lnSMLjVq0QA7oJMIbG15Svcuhd/RIhwgIlZJK0kvEtU3Hu+EEUlr9gktQtk
         DeuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9fnQ8Lm7kZ/IynvojzkYNY8HUaFAFRtJbiScCqur/eGuiBDGOiE
	RAKofYXddX0J6qQPF9z8yuI=
X-Google-Smtp-Source: AKy350aGo6LAB/jJBe+PHcDCnGfYruPj3KzlM0l2rxngd4hB7GbZkmIndARMZIoTGkdY6/R1JWb9jg==
X-Received: by 2002:a05:6a00:1a56:b0:626:1eb8:31d7 with SMTP id h22-20020a056a001a5600b006261eb831d7mr144086pfv.1.1681333564788;
        Wed, 12 Apr 2023 14:06:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1106:b0:19c:b122:6f2d with SMTP id
 n6-20020a170903110600b0019cb1226f2dls36195517plh.2.-pod-prod-gmail; Wed, 12
 Apr 2023 14:06:03 -0700 (PDT)
X-Received: by 2002:a17:902:c98a:b0:19e:e39b:6da2 with SMTP id g10-20020a170902c98a00b0019ee39b6da2mr187018plc.29.1681333563843;
        Wed, 12 Apr 2023 14:06:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681333563; cv=none;
        d=google.com; s=arc-20160816;
        b=m3qvCXUYdE838oiCWY/9L5F21gCfB+clsrj18PNwyMsxZ7FzM0vbFTDGzwYxCRNWDl
         lfOZAZj43tnAVD1BOp/ogfrkSY0kj3FcooeCvmzcnzQmtPrRoOX0iNLlvWwlBPzWpsAD
         DVPrWrlP1EiS1wfpLCo1tqTnzdLSvZzNvzoHP9KEv3MhoEi7I7rkUawEZmRUp91ACdSW
         XILArgqZEkC/PAXw6Yxy4STdhamMINiqlfI0DGQw8MxR43yulXZckcFq1lpLzGoebjIp
         vEHCXwaDN1uvJCGXgo0NHIrnzEBzo4z5fTuC/y/UWz3UCPlvR9oAVaW3a0vYYN3SHkSC
         D7Cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Z0afRGpRq1Vpns8Pw9AAC26EBbhrOaj5U3Yn7vgqQ0A=;
        b=qU5NYh1JIlNqsKupEZ3GBkywXOGGP+YUFwNAc6KRiW+sBz1J1+JczCUFYdRVXzp3wx
         68aHKHon5Xtww6LdpKVGHmhaBSkxR54jltJNt23p5jBy9oHzvutpVgtvzNQjhLBlpw4k
         3m/8AKkZFznZTDYOMIWQ5eKQ/FFif8QFkjZUucAuqLsHYcPcvtrPsOARdLh6HsmZIoS6
         3GpTdKSNT6eSoSUso14zUef0EEbHh3w0fbJz/yUBKYuBZFKgyih5GB/zPSMud0w7VJUp
         XS7VUf/v8lvJf77t8jiqbHbsbnFoRPbARovKjg9L3TXiwN2gad84dsfI+DX7odtUS80s
         HjxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=rmhB919g;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id e15-20020a170902ef4f00b0018712ccd6e0si6393plx.2.2023.04.12.14.06.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Apr 2023 14:06:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 471DB62A2F;
	Wed, 12 Apr 2023 21:06:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 52D2DC433EF;
	Wed, 12 Apr 2023 21:06:02 +0000 (UTC)
Date: Wed, 12 Apr 2023 14:06:01 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: kernel test robot <lkp@intel.com>
Cc: Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev,
 oe-kbuild-all@lists.linux.dev, urezki@gmail.com, hch@infradead.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, elver@google.com,
 dvyukov@google.com, kasan-dev@googlegroups.com, Dipanjan Das
 <mail.dipanjan.das@gmail.com>
Subject: Re: [PATCH 1/2] mm: kmsan: handle alloc failures in
 kmsan_vmap_pages_range_noflush()
Message-Id: <20230412140601.9308b871e38acb842c119478@linux-foundation.org>
In-Reply-To: <202304130223.epEIvA1E-lkp@intel.com>
References: <20230412145300.3651840-1-glider@google.com>
	<202304130223.epEIvA1E-lkp@intel.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=rmhB919g;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 13 Apr 2023 02:27:19 +0800 kernel test robot <lkp@intel.com> wrote:

> Hi Alexander,
> 
> kernel test robot noticed the following build errors:
> 
> [auto build test ERROR on akpm-mm/mm-everything]
> 
> >> include/linux/kmsan.h:291:1: error: non-void function does not return a value [-Werror,-Wreturn-type]

Thanks, I'll do this:

--- a/include/linux/kmsan.h~mm-kmsan-handle-alloc-failures-in-kmsan_ioremap_page_range-fix
+++ a/include/linux/kmsan.h
@@ -289,6 +289,7 @@ static inline int kmsan_vmap_pages_range
 						 struct page **pages,
 						 unsigned int page_shift)
 {
+	return 0;
 }
 
 static inline void kmsan_vunmap_range_noflush(unsigned long start,
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230412140601.9308b871e38acb842c119478%40linux-foundation.org.
