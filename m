Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBNXMWKTAMGQE5F4XZAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 807C276FBF0
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 10:26:31 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-4fe275023d4sf1853434e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 01:26:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691137591; cv=pass;
        d=google.com; s=arc-20160816;
        b=GI+iH7QTGfbEBmzYg31zHtP7I6Va0RCNzKxhQNyp1hNdv4JFeDNFFScorUFtgz9GUI
         ZiX2qW+h2UCdc1ITmGl/4c4Ru10Hi3t5wEuIk+QNyIA0ejOevUEl9G0IKPSgB9MHb7Wx
         WRQXwgxK2REBeNkobAWKLnWelY2wberDrDd5UpYOqqNwqRiRuWMWAVPHmgg/s2rLIqcN
         NkTh5n2ehigg7Xuut26qswQ+pcq6KbrskBZmsdHGqDOiLU5/vhkad8s/h09bQwEXHO1t
         to7X7Or0hNaHloPklHvt8K9xXFWGzhUyb5u7FQnVJ53iqCcr/BBGpX+/y35RsuVkXLkR
         zwpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rkcJiDuIyKk8bGAmOuXxzMZWSBJ3ak5TjRLQ3gp/Fg0=;
        fh=ubSGe9Pf/KxTId9rGYzy0xYsiY5Gj5OI3uWYUzuWZkk=;
        b=L42VAQR8TkbDEJjSvKHU+svZBt0Gq7TdOWpMfj5iyKMptVGnfoqqYvBFFSC/mVd+xN
         h8TPg+l7Z5AK5ABKJTh9FUNAgWzB9JCHJqM0PFOwh1HQs1RUoDg1kyYra9YdoirkeHqv
         g6TEhcG52Hhm04KtOfucgor5nI7o1Td/8QJUFcSsrvlYvOr2loj3fM+mNWvtWWjG8ii7
         RiVqi9S9CyLRTPXlV1w3EPbGEXC0OiCs6OP27XxvRvc24LCFJa3iGf/KvcZfvhYcMG6h
         YfYwKzURa+cV2DzSB4NcCITh8w9qXDp2BJ2ou/Vf3MhVPj2BNkKfq3qeP6w0XEvb3Kzm
         6yOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HbSlMCaz;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691137591; x=1691742391;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rkcJiDuIyKk8bGAmOuXxzMZWSBJ3ak5TjRLQ3gp/Fg0=;
        b=KPDSHgi7HyPuoGg1l3IS/YjSas2HqZoNw5vKR+ktVyFm+yeMQ1ZTzhPR6byy85nrg3
         qZrmmtw227udaVZ21oq9srlx49wfBCF0C+uZFLiDszapXI+RU8ip9vSvV1cjDwEIidBO
         HYP5OiCGMV6HJqLo8w3KylEg681YcDJWgPaAf0kYedDRpRnioLKryFD8Q0CH4SPhN7Qw
         DHdmcDqGrPl7YS741DIlDkZW0eIeCwQm8UTaWShNH+lPxMGDznBn/uodd9Hb1N36u5XD
         NlnFhC4bHZ8Q0qVw+vn3rFT+Eb9WTlj0b9br4FMubcOfrbwnYJR6R/9UVfwHjIZtYV9I
         TjJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691137591; x=1691742391;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rkcJiDuIyKk8bGAmOuXxzMZWSBJ3ak5TjRLQ3gp/Fg0=;
        b=RGWQOzf2d+6osWSTQ2okHqIhWoKNY5/rs0RXloeNMitlxwKUIM4p+YSrSlLloaf9nr
         SYNOKAm5jVbuM+w55/IVclKAlJ14M/nsGYPardxElyC7vRsMAKsV49UI901JZw7C1/q9
         D1MwTl8yjWlfNz2py6gyHEJlE3OkYG423e+PQKIxk7JVjr1x/U85KebAHJdZxzxX0CRW
         lb9V/SdljLotHhWQWA6IlHKQu5Y9AUpa5/cT0ORTDJ3A+tNOLn6ux0oXHpAFqsEVE8lO
         j6/QPsGFk3sxmTvSyLPka0WyfYzmpQ0tWlyHbujrEbNZ9BkUzppIslx3rjLG1U9E8EUZ
         YYgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywql7r0DzVZK40A7/CEzFBAJY/0G6hwdajfX7B1DbFklW5KZtiA
	SQi5bsEYZoBlm9+4x97UtEI=
X-Google-Smtp-Source: AGHT+IEft1uYFiHnv/yDQeJXeGDdCegyWlNeFFSi9wJ9fldYxz++kL1a0RYdRa3hc1bQmkyPCXrAuA==
X-Received: by 2002:a05:6512:49c:b0:4fe:79c:7269 with SMTP id v28-20020a056512049c00b004fe079c7269mr715871lfq.67.1691137590348;
        Fri, 04 Aug 2023 01:26:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:464e:0:b0:4f0:9517:7df6 with SMTP id s14-20020ac2464e000000b004f095177df6ls1153645lfo.0.-pod-prod-06-eu;
 Fri, 04 Aug 2023 01:26:28 -0700 (PDT)
X-Received: by 2002:a05:6512:1598:b0:4fb:8bea:f5f6 with SMTP id bp24-20020a056512159800b004fb8beaf5f6mr1010364lfb.34.1691137588623;
        Fri, 04 Aug 2023 01:26:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691137588; cv=none;
        d=google.com; s=arc-20160816;
        b=WL7L1RhXqzLAFtmx52/pYlEU7p2T6Vu2QKXK/e59VBPeHTBOpJCRXFnvflhlyfLAOx
         yDs2qMe9uaWvvm5KQO21NXU1mLJtkWrvxqh6xFPXEPNRPIlytzXoKL5W0FuP3mfqpV2i
         mt/VTl2jDwvoFQN/mm5hTeZSI4YmQJ/DS6TU5Qt3LVylu/RlBb8D377+AfehE18uOhkn
         HVuT0r5Ugs1QSY9DijjLuK8kJst+bmbYH+dgbxbCojbGfOrN34CFoT/wuhbsvCE3Mbkh
         Xi072x6BHXBKip06olDcUB6Vcm0uFDjaNZApAtmhxRhVftyyhlLl15tobEFVqZuSTVO8
         qxrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LiQZHN/gFI7kOzFyx0EOhyFHwRC/sfDcBQ2mnTPX6fM=;
        fh=ubSGe9Pf/KxTId9rGYzy0xYsiY5Gj5OI3uWYUzuWZkk=;
        b=WMh3ttA33V5cc/axlgi8joWbT1ahmKSHBBg/HlPuAB53RX7SpAOdPkhfYPH+L5Jz03
         J0C2y2DNux/vx3HuznzpHY3iV+FssbAY/O7FJ1+lMWkHKSTLx3/IgXKS/n/qfYUjw+V8
         bXgRW0UKVy1VpEgYL01oP/9UYd9DRtiS3Tjztjp457OfRQxTdr7ngfcIgyMHkGiUJkJr
         vSdjTjU/JEV3dMWiNSEQ+Mh4CeLhbVKlUfhM0QV10pe3L0/js1QP4gprupq+jp+QDpfZ
         yf94wAc6Y8zBJ8q5s5+dQj4zPXwuCOLonyuw2uO9JMjAKbbW+opT5GesMynecZ2wn9Y2
         ENoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HbSlMCaz;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.31])
        by gmr-mx.google.com with ESMTPS id m1-20020a056512114100b004fe157ebc07si131265lfg.1.2023.08.04.01.26.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Aug 2023 01:26:28 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.31;
X-IronPort-AV: E=McAfee;i="6600,9927,10791"; a="433952160"
X-IronPort-AV: E=Sophos;i="6.01,254,1684825200"; 
   d="scan'208";a="433952160"
Received: from orsmga006.jf.intel.com ([10.7.209.51])
  by orsmga104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Aug 2023 01:26:25 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10791"; a="706907757"
X-IronPort-AV: E=Sophos;i="6.01,254,1684825200"; 
   d="scan'208";a="706907757"
Received: from black.fi.intel.com ([10.237.72.28])
  by orsmga006.jf.intel.com with ESMTP; 04 Aug 2023 01:26:21 -0700
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id 8F3DF1341; Fri,  4 Aug 2023 11:26:32 +0300 (EEST)
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: [PATCH v1 3/4] lib/vsprintf: Remove implied inclusions
Date: Fri,  4 Aug 2023 11:26:18 +0300
Message-Id: <20230804082619.61833-4-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.40.0.1.gaa8946217a0b
In-Reply-To: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com>
References: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=HbSlMCaz;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=andriy.shevchenko@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

Remove inclusions that are implied and guaranteed to be provided by others:

  compiler.h	by types.h
  string.hi	by string_helpers.h

Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
---
 lib/vsprintf.c | 2 --
 1 file changed, 2 deletions(-)

diff --git a/lib/vsprintf.c b/lib/vsprintf.c
index 63afffab4249..eb0934d02722 100644
--- a/lib/vsprintf.c
+++ b/lib/vsprintf.c
@@ -20,7 +20,6 @@
 #include <linux/build_bug.h>
 #include <linux/clk.h>
 #include <linux/clk-provider.h>
-#include <linux/compiler.h>
 #include <linux/cred.h>
 #include <linux/ctype.h>
 #include <linux/dcache.h>
@@ -36,7 +35,6 @@
 #include <linux/rtc.h>
 #include <linux/siphash.h>
 #include <linux/stdarg.h>
-#include <linux/string.h>
 #include <linux/string_helpers.h>
 #include <linux/time.h>
 #include <linux/types.h>
-- 
2.40.0.1.gaa8946217a0b

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230804082619.61833-4-andriy.shevchenko%40linux.intel.com.
