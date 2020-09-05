Return-Path: <kasan-dev+bncBCIO53XE7YHBBXM72D5AKGQEZJ4ABGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 551CA25EB65
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Sep 2020 00:23:27 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id x25sf2810129otq.1
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Sep 2020 15:23:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599344606; cv=pass;
        d=google.com; s=arc-20160816;
        b=dJqcLt+E18zLh1IYBioV6CCxl1JsvAW0AcvyKL6o5uCXgH6zfJ6VLk8DPPGRYPgE7Z
         IayhpQ+iYLDf9iGonMvaDFk8LtEEXsN8O79RHoYoXucfa9U7jd657/2lhPLXW1IbH84d
         bc0TDmbEn4NQDuCusFPHlk0uICAgtjZGfWQjbYglzvh7pwpim3YZWhsIuoldQvQrZMhf
         Mw7+EBZuWqp9GWO/WjTC1UuybNd/AeDJTres2EsO622DAHjPxGhyZ/tCFGG+fX3tBBYC
         ABFyGGgCeliqFdBUI/FaHwPr48Mu6HxciVwTTBVIpFEW8rgGav7M15ygoa2hjG5yOi4J
         deyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qSblF+vIVUkrh+ZBeQWoJ/+MUL1/sDR14j0cW9wyByQ=;
        b=eUUbe50TuEjDf1wIFnBe/pVURqtDDgZoxfoh5uQERKVk/D5mLIn43UQaQhisb7dd3B
         qznOXhm7Op5rOFcJ1Ai+bCFyhw2mxQIMjvy8JvxMa2F2fQy0yq7I1xHKMjIAZpRyBVn5
         B8xkw4ec8ezSBD3NCsnjQ2bdD32ccEKNkUwUi78pZQa5L9tGJLmo9OKbsAQWk0olH8wA
         EgwQc20BUVWgcDr/3OFyPGy3SUEBYJMZZNaGdugxkszAr0EsJwH5q8TjBbj59I2syBeJ
         B1ct55g21h2EuHkQ8iWiMZ3xYl2VvBc7AgARYv3ATdGLArNAD5YWpBHrfPE4TJYz0woS
         qbAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of niveditas98@gmail.com designates 209.85.160.193 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qSblF+vIVUkrh+ZBeQWoJ/+MUL1/sDR14j0cW9wyByQ=;
        b=LWFnWhEWLr13IT32HRnNR6ofHSj8hJ+5K+RsgilNwSWPbtz2ZSZZb/+pGRInSKbpRv
         7FtvUw/2MC7mL1rP6XHXufVIfe5Yec9llflEnq32PpaOzs5l3zL48CK5fmdyd4AWs2SD
         benNjGwYSwU7ogaIgdnHgBkIncekqi79sMBx3swBQ4n43gcskUw5jrATUwGdzbIcbbcp
         q3Tf64dTK9b3sEgEnGIcFH4PMxQ5miEIFK2JvXt9nsVZfVOw5Y4EtXJBk7uhNJsODRS9
         bAfU0Kit8YNRlE4ZKK3XaDqPD1Vu4W+iTQdh7yk7qyJ3zyDyW/MgPP/t+1sz0Mo1BinV
         ggSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qSblF+vIVUkrh+ZBeQWoJ/+MUL1/sDR14j0cW9wyByQ=;
        b=SYJTayTbyaYRkKaaqD78EXIRd4ESluL7C2UHfcQt1jRQXsVjQ0s5BDa/ZISOVHwweQ
         udNNZzns4vTEkTc3YWh//c5tu6pJhEE8ClLJQUwgtDtP86Hc1DqeprSm8Zzts9NkQepZ
         apKgjJyMRUp82BlAK2WX7vQLbSYzDBkvOHpOaYHj1C+85qJ0TCtZBMoaABOOTQ/pqYU6
         QLCPdn8jRLk5My+MBHPbmSzBn+QsBV54qLiXx/3SDfyEh/3OZGlrKIn+qES9atzoRwXB
         U11FPe7+rtJxIWeZ/QHYa8juDSPiCRWNsF5fIsZsZWWDUH+CjEM03mKqDjLX2DpIAvJM
         2AHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/8Slr1Mie1Plwroe1wC3E5gwwTiAzR4LeUYuekjFOzW38UulK
	qV6l+YVKaWV1NHT3OhmXDVk=
X-Google-Smtp-Source: ABdhPJxgvlMAkx+2/eBp8Md24iR0eyEEP9iojejfgmbETxfl+4sKz4SyBTLzsuTMXgDRw8oL18Et/A==
X-Received: by 2002:a9d:2382:: with SMTP id t2mr2370055otb.1.1599344606056;
        Sat, 05 Sep 2020 15:23:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5e83:: with SMTP id s125ls2906821oib.10.gmail; Sat, 05
 Sep 2020 15:23:25 -0700 (PDT)
X-Received: by 2002:aca:4b95:: with SMTP id y143mr9170873oia.121.1599344605702;
        Sat, 05 Sep 2020 15:23:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599344605; cv=none;
        d=google.com; s=arc-20160816;
        b=UnXPe7QXePPfDUrKtGetM7/b3SMrU4mB++30BCD43tLYTpiIdS0ydjJgM6/DfYlkx1
         k0fNSZfMV/dU0HVdWaeH5UQl8Bmi4Mv7xQQuDHgo4ZCZfz53Lzb0058FnKDnVqcIiTVc
         frRpevc6nslSUDQC1fEFKANxB4sb6O2YbxZKaeBkp43VEunc+ksLAjj7lw3rxwC1ysBk
         kb20kSmT4GQJCcSHFxVO2xv99kNQ4jEp5YqWVRLDc/4Sxvct/Ok3AOU5aXLIoAk9xleL
         rjXi2Aum5fNDWHhWBzr/aOqzJ399XHYNWdNPWwhXVh4FzA9uBizau2jmXKw/eoR2OjLj
         HVFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=jfCbsJHJIpPjEZXsAp6VZMgqo72dfp1L92iresHikKM=;
        b=zM82oc1ZfDhST+yyuQIwiYa3el13uPvfvTKzqoa7qzv8C8qrJ7lAJToS3R6dc+MXz8
         x2lP7Z4wbzLb/M3W3H28PCnIgdVamKvzmdTCcWeze4wCA2J3m6on9P6a8oS/PXfTyUNv
         pZ5ptVItTsc7IXcqdavJdz62dxB7+bj+dKif+DvMFsIxOtob38hIi0lvYwKRPRE1M5wB
         V7T9pdrn1WcYcCkdIEoenZPt/9RKxST1set/Bl0vyG61LKRPqFw7UTH2gHoke9BdESuN
         LNGGBLPJUkbFdamZcOseD2SsBxChDx81EuZT4YknJJOGfIgeCJzWkuaxaMRDIoCe8jnt
         8UWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of niveditas98@gmail.com designates 209.85.160.193 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
Received: from mail-qt1-f193.google.com (mail-qt1-f193.google.com. [209.85.160.193])
        by gmr-mx.google.com with ESMTPS id d11si618046oti.2.2020.09.05.15.23.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 05 Sep 2020 15:23:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of niveditas98@gmail.com designates 209.85.160.193 as permitted sender) client-ip=209.85.160.193;
Received: by mail-qt1-f193.google.com with SMTP id v54so7470780qtj.7
        for <kasan-dev@googlegroups.com>; Sat, 05 Sep 2020 15:23:25 -0700 (PDT)
X-Received: by 2002:ac8:5b47:: with SMTP id n7mr15000945qtw.7.1599344605186;
        Sat, 05 Sep 2020 15:23:25 -0700 (PDT)
Received: from rani.riverdale.lan ([2001:470:1f07:5f3::b55f])
        by smtp.gmail.com with ESMTPSA id n203sm7323886qke.66.2020.09.05.15.23.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Sep 2020 15:23:24 -0700 (PDT)
From: Arvind Sankar <nivedita@alum.mit.edu>
To: x86@kernel.org,
	kasan-dev@googlegroups.com
Cc: Kees Cook <keescook@chromium.org>,
	linux-kernel@vger.kernel.org
Subject: [RFC PATCH 1/2] lib/string: Disable instrumentation
Date: Sat,  5 Sep 2020 18:23:22 -0400
Message-Id: <20200905222323.1408968-2-nivedita@alum.mit.edu>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200905222323.1408968-1-nivedita@alum.mit.edu>
References: <20200905222323.1408968-1-nivedita@alum.mit.edu>
MIME-Version: 1.0
X-Original-Sender: nivedita@alum.mit.edu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of niveditas98@gmail.com designates 209.85.160.193 as
 permitted sender) smtp.mailfrom=niveditas98@gmail.com
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

String functions can be useful in early boot, but using instrumented
versions can be problematic: eg on x86, some of the early boot code is
executing out of an identity mapping rather than the kernel virtual
addresses. Accessing any global variables at this point will lead to a
crash.

Tracing and KCOV are already disabled, and CONFIG_AMD_MEM_ENCRYPT will
additionally disable KASAN and stack protector.

Additionally disable GCOV, UBSAN, KCSAN, STACKLEAK_PLUGIN and branch
profiling, and make it unconditional to allow safe use of string
functions.

Signed-off-by: Arvind Sankar <nivedita@alum.mit.edu>
---
 lib/Makefile | 11 +++++++----
 1 file changed, 7 insertions(+), 4 deletions(-)

diff --git a/lib/Makefile b/lib/Makefile
index a4a4c6864f51..5e421769bbc6 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -8,7 +8,6 @@ ccflags-remove-$(CONFIG_FUNCTION_TRACER) += $(CC_FLAGS_FTRACE)
 # These files are disabled because they produce lots of non-interesting and/or
 # flaky coverage that is not a function of syscall inputs. For example,
 # rbtree can be global and individual rotations don't correlate with inputs.
-KCOV_INSTRUMENT_string.o := n
 KCOV_INSTRUMENT_rbtree.o := n
 KCOV_INSTRUMENT_list_debug.o := n
 KCOV_INSTRUMENT_debugobjects.o := n
@@ -20,12 +19,16 @@ KCOV_INSTRUMENT_fault-inject.o := n
 # them into calls to themselves.
 CFLAGS_string.o := -ffreestanding
 
-# Early boot use of cmdline, don't instrument it
-ifdef CONFIG_AMD_MEM_ENCRYPT
+# Early boot use of string functions, disable instrumentation
+GCOV_PROFILE_string.o := n
+KCOV_INSTRUMENT_string.o := n
 KASAN_SANITIZE_string.o := n
+UBSAN_SANITIZE_string.o := n
+KCSAN_SANITIZE_string.o := n
 
 CFLAGS_string.o += -fno-stack-protector
-endif
+CFLAGS_string.o += $(DISABLE_STACKLEAK_PLUGIN)
+CFLAGS_string.o += -DDISABLE_BRANCH_PROFILING
 
 # Used by KCSAN while enabled, avoid recursion.
 KCSAN_SANITIZE_random32.o := n
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200905222323.1408968-2-nivedita%40alum.mit.edu.
