Return-Path: <kasan-dev+bncBCXO5E6EQQFBBI6FWKPQMGQEKQNDGHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B6DB6978C3
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 10:15:17 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id 66-20020a9d04c8000000b0068d48d4e873sf9254036otm.22
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 01:15:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676452515; cv=pass;
        d=google.com; s=arc-20160816;
        b=BWyjcCEU/6dpaYpzLEFz6ejcM6fY+iFHVhmAozESBBNrf1VnKJLZBP+2aEY1e6cEwE
         y/sDM5Pjfr/gNYdug2539vWFBDE/Ugut6atKdKac4qhjRmMciPPJBEvbADzWMPl6ULu/
         3uG3zW9a8/mTAj5fkt6o0xfNKLpL6mJ5BQPGyX4aqDJl+/2lD8PCh42R5ZGqxOF8eWAZ
         li2IndnrUcDwSQe2x9rnLTrXXiBKMVEMKBllOLf6hZiL9eexdAJJkCxXEnKmTpMm7cGG
         v647/608m/60pC8vmrfS57oxHJFx+f0jFYa9uuf4Z02qBnPddsSoOrU7nmuLTIRR6svj
         cqGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=QZEwfew3At1CpB6/+5fIigFmoIOTNxzHZcwyhSsANvc=;
        b=Hc+XTVFdxMbwaN1khI41TeGNRg2g6/6GzdqGKV1If5Ha8Ufb7JfbPT6RFG3//cODjG
         LQ4Y8JPoJb8y05+6GrBvP5o5VzsaUe43prCIyn1ZVYtO26L6wL4cgfDwr/N4D8+tqpW6
         +Etq27n8Ct7QqA5dhOt72MtpSmp08RZFtLGTMWO3Sjn2GLvyi+nFon0Yz1qBmhC2/3XI
         KavEmszFiSxBMr0H35OrE7l1qIdeg9iNE7fWzLzD1ClTIZuDA0bSyxDMlHrm0xgTDTcq
         Hf+u5JHGp9ZKzRwUPJpnUBJ/KSJxMt2HkdZw/M0rASw1wN3ItvpFTpkgg/Injn8/sO+G
         oBtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AUqnqPEa;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QZEwfew3At1CpB6/+5fIigFmoIOTNxzHZcwyhSsANvc=;
        b=MjaZPKiDvyhNjbhMFiXThEuzErcLxqgSUaLfbwSmjUjdFmRCjpYZhbBvlX2dk1R7Hy
         OeIBN6miMyl68z4i5gI1/8xSh+65qnSLT1mpwDkSDj1bLqNxB67QnBgsARL6P6vSTMqw
         9pL8YunhHnWwCv/7hYtOqVAcB8B3NT2avqU+CtyQYLfpnd+yW9fBKKijWHS2YPAwe1fa
         BmThbuCUPvjmG8Po5danK78x7b7BfPkGlKfjDwpqr0Mi1HXvvSgHiJUbMgqsOQ36Y11N
         ZSyfaig02HLIox7v+t/BSZDGpSvOLWL6tVCq5Av1mHdB10Uq8dk/qMh/Je5Mi1izqPhE
         d8ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=QZEwfew3At1CpB6/+5fIigFmoIOTNxzHZcwyhSsANvc=;
        b=6rMBVFUZHfLH4/1Ne+Gl3fmnF1s7DfSrItuPwzEy1HEeKG+fD08pWlfV+CmXY8Bt6A
         F8k0SkNiq7WaqavKPA9axI8UG02Ikx2zECbkGQ55nPWCcRye9ognOgFSxg1T4GSS7gp+
         C75KgzpclzM+XjvV4l1Jvkdx8H5WGvSKZJdoGXCmCZxn7xVsf2PEc3M4XtYU/d4opTdJ
         MvqXlflj0uKrmxuY/gAC3iEHjOtX0brj8PjqZcQxDj7A/QbnPXSHW+OZsOhFl5Pgz1zc
         oHgdhs8HEf+q3Sr57c/vKVPBqM/V0wyafQLA2sPCE3+yqSvngmGScMbIBin/DDmq1MS7
         mjvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUBldH6odduqLzOgRcAiGdyO63VDhlrKH0sQ2A2bMzViHVj/jh1
	yy3PLTK489sHIMAA8jLce6g=
X-Google-Smtp-Source: AK7set+poXE52SqmrUPQhOCms/McJN+My88k3vdtarnY6cPbrkKXdUL/xR/0Gd8+9Ln6t0TSVy3YYg==
X-Received: by 2002:a05:6808:f94:b0:37f:7af0:9244 with SMTP id o20-20020a0568080f9400b0037f7af09244mr36663oiw.299.1676452515485;
        Wed, 15 Feb 2023 01:15:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:86c3:b0:16a:cfe1:9803 with SMTP id
 tb3-20020a05687186c300b0016acfe19803ls7551036oab.5.-pod-prod-gmail; Wed, 15
 Feb 2023 01:15:15 -0800 (PST)
X-Received: by 2002:a05:6871:54c:b0:16d:ddd8:a727 with SMTP id t12-20020a056871054c00b0016dddd8a727mr796016oal.10.1676452515063;
        Wed, 15 Feb 2023 01:15:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676452515; cv=none;
        d=google.com; s=arc-20160816;
        b=P413HylPKGhy/fizzuaYVNIGHXEFiu+xfpgSAgjHXeAYoBdE3/5sGgEGci9SYGKxXy
         XpEUY2nBKY2A4+7RzRoS1dFhx/+RmTpBc2+8/82cMEUHhIcLVJy3RJ2HUiG4rO765Jxb
         P1pVs70dimMBVbk5JHHIEb8WR7sjoiIDbvXLQ/EuYsY+zFaaJi8BPVc2YQNeVmxAI9B5
         BMfYOSX9gbJOc4pttdgQkA0JQzhC4R2DdSh2bE2PZaCqNCVop2+8iwrUoFYFbRZhlbvA
         ZY8l61lMbYV9oIwERSGhuMx6U+NcX4ku2P3TX6+PDlOzoqCGETtSN42Htf7VLhB6qt63
         TA6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=tVnX8LRLrV28bZnN0HkIOQtiDzMRz2i47aCP9xbgkyc=;
        b=Nb8iiwNUj1P8KhXKtX9wAoOFBpmPwmhzWhn4aFIfGBTNyI9BLX7TUtObnCDRp+IDRj
         wXHHmJXLdypw+cSLqIya4pXUS/nG3uQf06vI96ok9rqe3upIXonPQDnsJyu0SVN9lAi4
         VJ8ixtLQOnnLEiKetjbyswc4ijOrnY4ELEwiizkhzNKZhVtO2CqatpweNb8W/ZZBFoMD
         8mEbO16mbJnqXgXLIpbf3kTkziPYV+YKiGv+j5qB4vSfykzBw+hovuSsNH+h5qzB5FB8
         8nqeoReVDTQsu9lt5E+B5ARMRpLlGx1mFAxywvipdokjgYxBRvJWaBLEIFyyIlo1ZmEh
         77UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AUqnqPEa;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id gv3-20020a056870aa0300b0016e33b80e87si357300oab.2.2023.02.15.01.15.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Feb 2023 01:15:15 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B6B4561AC4;
	Wed, 15 Feb 2023 09:15:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 194F5C433EF;
	Wed, 15 Feb 2023 09:15:11 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Miroslav Benes <mbenes@suse.cz>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kcsan: select CONFIG_CONSTRUCTORS
Date: Wed, 15 Feb 2023 10:14:48 +0100
Message-Id: <20230215091503.1490152-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.1
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AUqnqPEa;       spf=pass
 (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

Building a kcsan enabled kernel for x86_64 with gcc-11 results in a lot
of build warnings or errors without CONFIG_CONSTRUCTORS:

x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/copy_mc.o'
x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/cpu.o'
x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/csum-partial_64.o'
x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/csum-wrappers_64.o'
x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/insn-eval.o'
x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/insn.o'
x86_64-linux-ld: error: unplaced orphan section `.ctors.65436' from `arch/x86/lib/misc.o'

The same thing has been reported for mips64. I can't reproduce it for
any other compiler version, so I don't know if constructors are always
required here or if this is a gcc-11 specific implementation detail.

I see no harm in always enabling constructors here, and this reliably
fixes the build warnings for me.

Link: https://lore.kernel.org/lkml/202204181801.r3MMkwJv-lkp@intel.com/T/
Cc: Kees Cook <keescook@chromium.org>
See-also: 3e6631485fae ("vmlinux.lds.h: Keep .ctors.* with .ctors")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 lib/Kconfig.kcsan | 1 +
 1 file changed, 1 insertion(+)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 4dedd61e5192..609ddfc73de5 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -14,6 +14,7 @@ menuconfig KCSAN
 	bool "KCSAN: dynamic data race detector"
 	depends on HAVE_ARCH_KCSAN && HAVE_KCSAN_COMPILER
 	depends on DEBUG_KERNEL && !KASAN
+	select CONSTRUCTORS
 	select STACKTRACE
 	help
 	  The Kernel Concurrency Sanitizer (KCSAN) is a dynamic
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230215091503.1490152-1-arnd%40kernel.org.
