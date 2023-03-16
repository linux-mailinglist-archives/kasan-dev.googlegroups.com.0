Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5NYZ2QAMGQENHAVBUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 063AA6BDBEB
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 23:47:18 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id bi27-20020a05600c3d9b00b003e9d0925341sf1353946wmb.8
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 15:47:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679006837; cv=pass;
        d=google.com; s=arc-20160816;
        b=i6nAntw1QiDmTVXnjPEbZPJ1cGGMTBP4+9MQRC6yDOi8eWcidbzWIC+096xWbCGfE4
         mgIXmUhC/8RC6UjhAlwVkpNe1jJ75H8KFrrX04YM88pG+YFKz+ie1rPnacgBErKX4Gaf
         RnnWHO0gRq6EPgXbpPqYC4AFpiUfqkJROxbLTlH8qViJS9XUCK6FxaLrajM8rKoKsANJ
         0HJKLFncwhMXIwoR9R5FI41De25iW1PRuSnwl/uHzIuaxWcjVB/81OUN1bNVqcUiNj89
         CaV1MiRtEenuTcHfKIUYEwf/lVtsz6jqYgm6NBPwr5R3awxXKsfmZzJSZiceOldsHBRQ
         csJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=IsCYF2+FYg7W45FoG5iP14RnDzL19YBNtuhKkk3BL30=;
        b=OzivZ3zLdcuJsENtcOH6/+o0QWvewR5NqgKMuehzHCVTbqeSM+3DFrH3+n16QYEx7C
         eePT5wrs6mTmCIapZ5aCjtWCwyihha140cMHchoJ8wuE/DEXq68DLCec6L70nbRHkm9K
         XKdIEgA/kmw4fNm8LNPnjUNCMcgc6c38a7x7GKIDOqf7IdlrK/K+lh8LtzOSSL2TYord
         O4j0t7FFDCLUsepPAFKygxPhnMg6yied3p8rAOQ8p4D8T5MhBgiIoNilkyYUbAQvMAot
         PqU7RvjstDVCP+GkT47jI59kevUmBdlJOCN9ZHItTjEZgXmgwwl4BygBshSNxI/m6PX8
         qFpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dG1Fj3EX;
       spf=pass (google.com: domain of 3c5wtzaukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3c5wTZAUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679006837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IsCYF2+FYg7W45FoG5iP14RnDzL19YBNtuhKkk3BL30=;
        b=QwrtZFnOiwfdv/SLwAlc/Rfw20tcUdgvIoOwST+LdsPZ/pj9VLFyZzq1C+xr6yw/kM
         SCsO9uLcgwYlRmSpU5xDThPacZ5EHl+MXs+w7q4c/4SytEW6aX1ESH4SsbWRlo+tDkYm
         usg4Fi5cv0g04Q5zDHshQ29haIO2VLX3JL1BwrFsSVz/KgX71vJz6SuR6vyFC/D14Hta
         9g46Sy6pr0CrZeJ8BgF7j60IAmMXJfgKdojyXzcFogYT43IIxyK2dst8nWc91lnirKkx
         +VCpLtfI850DnbqH1y3ZeEfiPUGF7an/PXleyZJCrzGKo9bXDZC02Vk6PbmrEgty39HB
         X2kQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679006837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IsCYF2+FYg7W45FoG5iP14RnDzL19YBNtuhKkk3BL30=;
        b=6zY7vv5N5PkrV06+a/XR0HXOjBXM6oTzZ/zZhz/+CQrGaeYLOGupc/i1I2RxJh9b+J
         3yPLznJIiZnH8OLql5Y8cS8QI5XnUgkK9orYk0HSHvK8n9NDECAlqwijAh864h4nA4cP
         5X13ArV5MVBiOCR9CCU1eQnTnmg2BQ5IQqgrhxtBIf644OLq4PjPig8mJ0zAg8i5F+wt
         KBQguL172OgMHdZ2pbHNnfkbiiQSSuBcmBvE4uV1d3lJ3+/N4YOTBRG7bLNZFCFput8k
         swezfKeYACiLWXDYr9tlHDFrl6WiJb/OcSoyBPyQCdLAQROzMV8SmiyfDRQRXU8klg8t
         UCog==
X-Gm-Message-State: AO0yUKUJrSTBTvo3DcoJF+7rWIFvFH2qnqVs05rb0JKzgnIt+bvvC+fs
	prBd6OD6HDcsuuOyWZdJva0=
X-Google-Smtp-Source: AK7set/QA58WfI5yRkl3M6CIL+Pyv/Sb7ELjCgg4iIfOEtwYsyd5hor+vLc4kLdZJniUoWuHtef0EA==
X-Received: by 2002:a05:600c:3c84:b0:3df:fc69:e977 with SMTP id bg4-20020a05600c3c8400b003dffc69e977mr6805853wmb.5.1679006837284;
        Thu, 16 Mar 2023 15:47:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6023:b0:3cf:9be3:73dd with SMTP id
 az35-20020a05600c602300b003cf9be373ddls3801224wmb.3.-pod-canary-gmail; Thu,
 16 Mar 2023 15:47:15 -0700 (PDT)
X-Received: by 2002:a05:600c:3b11:b0:3ed:2a8c:c8c3 with SMTP id m17-20020a05600c3b1100b003ed2a8cc8c3mr11601679wms.11.1679006835805;
        Thu, 16 Mar 2023 15:47:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679006835; cv=none;
        d=google.com; s=arc-20160816;
        b=ver5Qk7q8e32i/SlfVqwL2gjSZFnlgQgPExaT6mEISleAYkHbcco3JgqCfjUBAsdBK
         wXDJ/zlEwud/9w19/RQK4vxHdVNRr+RW3Oa7IPVtc2gHr8T7isf7kn6eMWJoBq4YQWBW
         OeqMr4ZY6OJrPQREd6svs7Zy0qhTga7UI3E4gUE3DkbUDecHZOmCw6wDYl9tDBGpUnnv
         3CkqRYxvnInMIagkfSouJhudAZHdSzXHcyDdXCilkkgemZ1H/8q7juDqihrXcQA4K3E1
         APCK4CEyRM20kTdN3sf3whBcnwj1M95CdOlyrkRJqSOP9XRfqLfin12b6KtBjCU3Ta2x
         KhAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=mIMhApGgO8tdqBq7ln4mUoYAtVQfctnuG47znmR3Hdk=;
        b=zXPEuP1TOg8dFKxuJKM1CWxgw1PSmphO5HVy2Jdk3LAEzER2e/OBDfIQRK2FlNwtJb
         JKOeOAWEihFZrFfZudEGfvyq2uikpO3I13E+xPHjdGOU3KgQn6KQLgd7Z/9FRy5Wp27t
         6/pUYWiS3vVvKoOfzboaTCMyEGX0c0DDNbH4pW0x8oJQhjWF9JVlSXUC93Dz+rjwBwcH
         FTjo46lQDD59xy8jvQhn/LMFl5mnmisMrlcAC032gkWdHoRse/hZOL/7Nx5n4F125p7s
         Fon8BYC2prcWwYp5231KA7qxBt3KAO+Rr/D75VIn87PGQavcbtNlEay4b2p0sJWyk8iE
         dMHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dG1Fj3EX;
       spf=pass (google.com: domain of 3c5wtzaukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3c5wTZAUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id fl7-20020a05600c0b8700b003ed22457910si35947wmb.2.2023.03.16.15.47.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Mar 2023 15:47:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3c5wtzaukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id en6-20020a056402528600b004fa01232e6aso4979341edb.16
        for <kasan-dev@googlegroups.com>; Thu, 16 Mar 2023 15:47:15 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:f359:6b95:96e:1317])
 (user=elver job=sendgmr) by 2002:a17:907:8a01:b0:92f:b8f1:7239 with SMTP id
 sc1-20020a1709078a0100b0092fb8f17239mr3202420ejc.4.1679006835449; Thu, 16 Mar
 2023 15:47:15 -0700 (PDT)
Date: Thu, 16 Mar 2023 23:47:04 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.0.rc1.284.g88254d51c5-goog
Message-ID: <20230316224705.709984-1-elver@google.com>
Subject: [PATCH 1/2] kfence: avoid passing -g for test
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Nathan Chancellor <nathan@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dG1Fj3EX;       spf=pass
 (google.com: domain of 3c5wtzaukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3c5wTZAUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Nathan reported that when building with GNU as and a version of clang
that defaults to DWARF5:

  $ make -skj"$(nproc)" ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- \
			LLVM=1 LLVM_IAS=0 O=build \
			mrproper allmodconfig mm/kfence/kfence_test.o
  /tmp/kfence_test-08a0a0.s: Assembler messages:
  /tmp/kfence_test-08a0a0.s:14627: Error: non-constant .uleb128 is not supported
  /tmp/kfence_test-08a0a0.s:14628: Error: non-constant .uleb128 is not supported
  /tmp/kfence_test-08a0a0.s:14632: Error: non-constant .uleb128 is not supported
  /tmp/kfence_test-08a0a0.s:14633: Error: non-constant .uleb128 is not supported
  /tmp/kfence_test-08a0a0.s:14639: Error: non-constant .uleb128 is not supported
  ...

This is because `-g` defaults to the compiler debug info default. If the
assembler does not support some of the directives used, the above errors
occur. To fix, remove the explicit passing of `-g`.

All the test wants is that stack traces print valid function names, and
debug info is not required for that. (I currently cannot recall why I
added the explicit `-g`.)

Fixes: bc8fbc5f305a ("kfence: add test suite")
Reported-by: Nathan Chancellor <nathan@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/Makefile | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kfence/Makefile b/mm/kfence/Makefile
index 0bb95728a784..2de2a58d11a1 100644
--- a/mm/kfence/Makefile
+++ b/mm/kfence/Makefile
@@ -2,5 +2,5 @@
 
 obj-y := core.o report.o
 
-CFLAGS_kfence_test.o := -g -fno-omit-frame-pointer -fno-optimize-sibling-calls
+CFLAGS_kfence_test.o := -fno-omit-frame-pointer -fno-optimize-sibling-calls
 obj-$(CONFIG_KFENCE_KUNIT_TEST) += kfence_test.o
-- 
2.40.0.rc1.284.g88254d51c5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230316224705.709984-1-elver%40google.com.
