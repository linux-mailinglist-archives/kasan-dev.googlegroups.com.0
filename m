Return-Path: <kasan-dev+bncBDTZTRGMXIFBBLUN7P3AKGQERYSUUUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EC7D1F2396
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 01:16:00 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id a16sf7003978iow.9
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jun 2020 16:16:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591658159; cv=pass;
        d=google.com; s=arc-20160816;
        b=hgNtc35giRFL7FcOeklhj7vgrRDgUhLXgI8nnlP3TInMtXsV1kOtNwMxRy8ToydSaT
         ZNWANwVOV8OGtbIQcxXhQ+uxDQb3JdxjJWq4rRNZHcHVaqFCa3hWZiNdaDtisKSdTJjr
         A6onLdrJQaVRM8sGjnZjcmE+/6+vSiqxyVlUUY06kW6ItFS8Mjv/pIsBaTchcJ55bFN2
         fXjaAzQYfD4erPOTgomm0KHcn4Icp/PxWvGYRPEZvoReMPu/UTcj0FOR4uLspWopicwe
         fzrwc6gHLlkPl35UuM9I0R8pExQFPhh/x7tt/WM0kEdReHmQWf/0XAUuxRhjJB3QA4cs
         Wbfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zPJIXNELefsZR7QeChoZ3jlrGZW8ysfGkIXiwsQ25MA=;
        b=SpzbNWfnLNveMORgkE1FhhbabQMtj1vLI9GRDD0BUjE7gF6ZcRsAhVIX5hTI8MoU8W
         uP0LMs6MH15+bvcSPSymcaviJCHgGqYLN9QjrwZ4CuU/D9XEryZrM2W4hm1aBqi/LDf9
         1mzFdDKfBAuyEMQ4v7Do2nsNm6X6Ay+9d4LQOyX4jgUruUQfJDl6yeqNzcTk0eBtwP5t
         vFdiHeXfAv+u341ZukkLYjp9ykVfJNo63eEwHrCTgXE0ewQ9LtfleWwXAdoggc1x5nET
         KsrV78VTk2ZmpIkTCIh+l2oYpKy7+W8iC1I8Vd8k9Gmz8NmFxpiBKRm9LrR+2AXD//be
         k5LQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=jKMP9b2K;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zPJIXNELefsZR7QeChoZ3jlrGZW8ysfGkIXiwsQ25MA=;
        b=LxwPVuzHQClPD+J+34/+WNmhQDykqCSPw4k8KpKAJJFTWFbwDYmSGeYzzst9tgQwSd
         miCxZRFZHCFZXntVZG7DgYvBX4pTFZI0t/ixsPT8oYMcdguaWhnymr6rcWIO5p/8u1OB
         /qkrlSnkKJlKYgWXoBaBfpbZE14aGVcddjfn7VrdkDV9DBtEkcI/AwVrRRKZm7cIrlsr
         pbZleO42R0D+hZnyxwIcEZWNy3j5P/WWxPtMyr3vSGtBXJGfRhyErCAMsQFY04DDgdHy
         gLrRN2OcWzaBXfGqCMMwaGpPVCIdXj96jlM17oI3ba2ayvDJyxNVBY33ARG/4tdw5CVM
         mgkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zPJIXNELefsZR7QeChoZ3jlrGZW8ysfGkIXiwsQ25MA=;
        b=uNCE7axh8Y41mvAB611DzzHPhFTWe2oIqsZm/VtuqIa98+p5fR9gjxHDia7E+kDcAO
         pV8eSOcma91XORTjDek6QErH+tUKjHuqiACj8RLgnMZnmt4+81mLTHjataWbrGnOnIvj
         q7Gu7lMIbM9IHot4saVUBB/yL2N5fiWuM+AZjv8M+Y9Ax6WbEjHvTpB9MP/WphQR35gv
         GyvyznALYdxuEZ3x970aEfQwQps3X5hsRyhvf+NlefKpXdIeQ+PLsTZu8INkbYj/E7QJ
         mxyxJRmt4vEMg9dOVsNjUPorcO+lJvJ2ax40HGH/pYBDJ//VnrXbAjfdZ17Czh8xAFeO
         13vA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533LweCwk/BBLFPiBtk6Sqf+meAtZysP+xB+GW3+dFns8iTQZvEs
	MP7qphGFirw5KqLLY0acSUs=
X-Google-Smtp-Source: ABdhPJyxivVYj11kihTeOGzPcO5nwjPdOsm9uX+ooN0J39LM5szi3qenwIJJ7JjoWXBbO6xM8GuXnQ==
X-Received: by 2002:a05:6e02:cd3:: with SMTP id c19mr22543841ilj.102.1591658159032;
        Mon, 08 Jun 2020 16:15:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1584:: with SMTP id e4ls3247195iow.0.gmail; Mon, 08
 Jun 2020 16:15:58 -0700 (PDT)
X-Received: by 2002:a6b:6818:: with SMTP id d24mr23958190ioc.57.1591658158700;
        Mon, 08 Jun 2020 16:15:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591658158; cv=none;
        d=google.com; s=arc-20160816;
        b=MEyZsegulReJ4g42JusdO5o07aUZdHfL31nbIsrdG1I5ZX9fBc35SRfKvH3gkvDvK7
         ttBIcUoKEjUZDL+LiRSQ3GANxquOPY55xBtbKm13wU/EPA+p2+z6bvHfnspovlr5L+kx
         5i1KldGcwklhdZkMqmsqmJGySAiOUAJKuS+w3jA67G8YjIr0KTHhNcmVjP5m03m/r1QO
         9Kxr6VELUNbOFHIdcsuHocOkGfAM6uheC+pFxtP7NkqQCNnJsW5t+2XvfRlE+tz3bWyf
         j/ksM90k5V4nIG9BoZBRV4xOB0MMEMlZBSVzoYSbtNCE75S9TRrxsYrjk/Mv79mEUOJK
         EPuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yqEHY8sI8EGgx8Y9qubl7yC5q+gc0PRo7B2wBeEJ3Ew=;
        b=Bp68ouyklfjY+bTAnGwn85Ds4S7KGL/0avDTZd1ceqVAwQz8CFGxy/YMxqOLBdu91L
         lmEN50E/0NlZiiV2aQDmwJjm7XMeLfubWyBHSg3L3Dc00m6llQo/gNMJrIiTh2F1d9Nh
         mI/f17PsGz7QKPM1h4C4N/sav30uL2nX3xvMjedSOQV9rv3cICaBcLcVrzLhCePvBW8C
         Xg8SGsty3JvKsQf8A8f7vDqOpCN2pYFlv60xGXK3Z/rsiGvgPqnfCKgYZvgvfuvo2/Bu
         /0/IoP2awiqC8oNDIHz1c2XLhOoqhD1pedDQ8h65ILx2G+ZNd3fmZW1/oLQ1+YOzwSh0
         fDmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=jKMP9b2K;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b1si750086ilq.4.2020.06.08.16.15.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jun 2020 16:15:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from sasha-vm.mshome.net (c-73-47-72-35.hsd1.nh.comcast.net [73.47.72.35])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B42C120760;
	Mon,  8 Jun 2020 23:15:56 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	kernel test robot <rong.a.chen@intel.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Qian Cai <cai@lca.pw>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH AUTOSEL 5.6 188/606] kasan: disable branch tracing for core runtime
Date: Mon,  8 Jun 2020 19:05:13 -0400
Message-Id: <20200608231211.3363633-188-sashal@kernel.org>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20200608231211.3363633-1-sashal@kernel.org>
References: <20200608231211.3363633-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=jKMP9b2K;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

commit 33cd65e73abd693c00c4156cf23677c453b41b3b upstream.

During early boot, while KASAN is not yet initialized, it is possible to
enter reporting code-path and end up in kasan_report().

While uninitialized, the branch there prevents generating any reports,
however, under certain circumstances when branches are being traced
(TRACE_BRANCH_PROFILING), we may recurse deep enough to cause kernel
reboots without warning.

To prevent similar issues in future, we should disable branch tracing
for the core runtime.

[elver@google.com: remove duplicate DISABLE_BRANCH_PROFILING, per Qian Cai]
  Link: https://lore.kernel.org/lkml/20200517011732.GE24705@shao2-debian/
  Link: http://lkml.kernel.org/r/20200522075207.157349-1-elver@google.com
Reported-by: kernel test robot <rong.a.chen@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Qian Cai <cai@lca.pw>
Cc: <stable@vger.kernel.org>
Link: http://lkml.kernel.org/r//20200517011732.GE24705@shao2-debian/
Link: http://lkml.kernel.org/r/20200519182459.87166-1-elver@google.com
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
---
 mm/kasan/Makefile  | 8 ++++----
 mm/kasan/generic.c | 1 -
 mm/kasan/tags.c    | 1 -
 3 files changed, 4 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 08b43de2383b..f36ffc090f5f 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -14,10 +14,10 @@ CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
 # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
 # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
 
-CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
+CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
 
 obj-$(CONFIG_KASAN) := common.o init.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 616f9dd82d12..76a80033e0b7 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -15,7 +15,6 @@
  */
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
-#define DISABLE_BRANCH_PROFILING
 
 #include <linux/export.h>
 #include <linux/interrupt.h>
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 0e987c9ca052..caf4efd9888c 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -12,7 +12,6 @@
  */
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
-#define DISABLE_BRANCH_PROFILING
 
 #include <linux/export.h>
 #include <linux/interrupt.h>
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200608231211.3363633-188-sashal%40kernel.org.
