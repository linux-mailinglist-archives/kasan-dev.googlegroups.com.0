Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBNHMWKTAMGQEML4VMAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B4C976FBEF
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 10:26:29 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-3fd2dec82a6sf11609445e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 01:26:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691137589; cv=pass;
        d=google.com; s=arc-20160816;
        b=df1MSYVdzfZkP1//E8T09rxnPLvPDJ162Bq7UszlrMJa0Zbgz2ri2I8K0I7w1AwZ47
         bOB6K4k/7F5v/BTryZHw9xkN07HlKWdeAHTrcyQVTfV0/lTtx82NyA9L3+LZzA8tqf0q
         kz1CFoQQ6S8uzxY7S/jYj12Jf7CwwW43Z2RZo2Xv0/CBf5TU8Yn1rld4KSSMDCaMbjxu
         5EGJnta4wYvKEiArwzD7hgP6ZUn2pyD4ge/kXC7LC8cEjdeVU0t/Ud7foCnk2YzIzHo6
         SvhkbceMW8pLhSvoF3s8mtmQdlKhyxgz3xb5TurtN/tzg2R4fqtLZpEuC2vztLVa9sEO
         mHvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=usQyLdDdt+KNmlW8NMLlsrG2pWzdmjsC8ZQQ7ePzujc=;
        fh=ubSGe9Pf/KxTId9rGYzy0xYsiY5Gj5OI3uWYUzuWZkk=;
        b=ON6/QVflopVxDdSISB1M2bNanGNFTxEMRHnNvbSfmM4hKtR9oIs+IdMOoKnbbO5hlv
         4vSJg7SajG3k+dFmnDgQLv/draiW/Sn4bik62jv/Emde/whPJSKUbxVgaGwaQkE+Zj4u
         9z5eiKwHPizyCc8vFqP5O7LtHm2Z5OvOh19MM6jr8zjq1sLdWNxVB2vPdjAsn1wTpKpX
         U0D12Hhd7YRqWhqxoAMXcgfTKwz+/2jfjygz6seQKCeMxj3gSrpKlfv545a0Chp5C+mw
         GgM+ESBUQS9W8tVyuRqbyx9TJEKpQVDskrddtm3LBXO98JlFcGgkNsxpupAJnf9Ki7hp
         MJ1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=EHo7JzZY;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691137589; x=1691742389;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=usQyLdDdt+KNmlW8NMLlsrG2pWzdmjsC8ZQQ7ePzujc=;
        b=klAqRXUfkQDoa+Y05XmilLcdETAhctuoR49ud2ewmyA0q6DzeOqzhqz77yJUtFccsL
         IcrnMLKFjkGc5+ylbmQVm/z8U5ReM9caLxUGpk39cAbBD24cpPMLtdAchYwWHZ9S7bPw
         C1iSD6cbxa5rwmWuKrh8yaudoC2+/MYQU+MFov61J2PJhMGuBR7+ALkMhGdrbEGegAhW
         BFv2GNrxK68N6/pMhC007KZR1Qxtk+AoxBh94mLYtns9h2kDUNoZAjdtg8nK53C3YzQF
         N6Lqy1c25D0YbVjmeanhDZW0P+EFhJkqOoSyVbuEpxD7pS0S1J0tOL8gm08SupiyGhWr
         R00w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691137589; x=1691742389;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=usQyLdDdt+KNmlW8NMLlsrG2pWzdmjsC8ZQQ7ePzujc=;
        b=UoqDLbTYcOizpOHOW9WE09djuCCetwbs9NPbbgwxx0es55q1kUSleIve/oJTAZ4bIW
         TMXeFl68Bu8QEJkgpchnLbc5d5Ha2zSDWdlBkNV4JXY485+rYJu634ieJCx06pNHyNiz
         ETyfgdDAj2JsWxroS4XA1x/NLfWskWUzwtlSKnQEOs9HiZgWyHSN+3+wF3MQRsSuAi9V
         xHSra3vVObf3P4e2ywiceT7Ct+HBWX/2IC0htzIag40fczpZmgw5xVCY9E5FTsF64WgT
         8sElnna/0L5TYQGQlT147gUwaa3+aBpg/uELaDa5qHqeOQSCx8YLS3k5emhYa7td0ig4
         2S5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx3+vzVVmR6PsErDTKPTMqxxe7Sx1oWOWnG2YRVY7eGOjcyxpXD
	QAOv8DGYg7msa94jKddt1zI=
X-Google-Smtp-Source: AGHT+IHaI9jtSTdzVPYZYTwYAdMllknD2FPb72Z9grlN1VdHulZPGfZJn2EQ1+dA6BwGrd5k7fPhsw==
X-Received: by 2002:a7b:ce14:0:b0:3fe:179a:9eef with SMTP id m20-20020a7bce14000000b003fe179a9eefmr894777wmc.40.1691137588858;
        Fri, 04 Aug 2023 01:26:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e13:b0:3fe:259a:c89d with SMTP id
 ay19-20020a05600c1e1300b003fe259ac89dls2394914wmb.1.-pod-prod-05-eu; Fri, 04
 Aug 2023 01:26:27 -0700 (PDT)
X-Received: by 2002:a7b:c4d9:0:b0:3fe:2186:e9a9 with SMTP id g25-20020a7bc4d9000000b003fe2186e9a9mr1009827wmk.30.1691137587344;
        Fri, 04 Aug 2023 01:26:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691137587; cv=none;
        d=google.com; s=arc-20160816;
        b=jlRuYgHajfoMyk6fZbHM+VGbYyBlOB5nUJ9I+dEifroynrPxQ3dJ5Zn/7SuvNEiFb2
         yIEPDzBwdub1Fy+jYFTql57CTD/MLsS+yK9+85mxqnvLJxuOgGGxyE36d4Bgg3D21y9r
         /5uVcekOOcnaG6FiEQR3aMzMhRxfoIz1zGgZHC2L5w6a3r1DO78RNkgrlwjupylkUNmh
         E/Gfw4eyRHvUgRNgEyVrIz4lz+ecV4/eKOUkiIJfhlCYqEqaAVqwNYl2w7M5iYz6Sxfv
         LlzjeJb9mB4av5pDgXVXdvyxTAjml/muK0/TDDfJwQcOUea87+VPeV7vPZRCN1g+Bwbv
         Av4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=J1mmLG9dNVbbXWxrtX+A+p/h0rMc/GZ2hwewP+0fv7Y=;
        fh=ubSGe9Pf/KxTId9rGYzy0xYsiY5Gj5OI3uWYUzuWZkk=;
        b=VbGxHnCo21dW6544yZNECtyEP/9dKLnQT+EEXgMoS4OnMCu8zfoYNFMYKAZY3BEGfZ
         ZrINut3HZeD6hFewRPoqIfvxGOURCxpipR5/MWv04Zl1SeMA3ZjTZWi/meA4nKE0ysk8
         UIU3qLVPqNVXLz97p7IGGhwgSv4HMTR87RP+tQbOk7z3N/vQZx475zyfdyXS8LE7IAV+
         4at8wzXJ8/9RLxo8qZeM2u/PelRi8ojvSxo6Sr2fjm2es52qxgzeTbUI4wPr4kfRAILC
         q3PZtX3WTbHfM+o1AjYRKM2/KidxA/SZRYFl2Zhv2izdwLf1Qh3KQdqmim+aQ7hiF3sw
         Kjrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=EHo7JzZY;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id p27-20020a05600c1d9b00b003fbf22a6ddcsi146408wms.1.2023.08.04.01.26.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Aug 2023 01:26:27 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6600,9927,10791"; a="370090219"
X-IronPort-AV: E=Sophos;i="6.01,254,1684825200"; 
   d="scan'208";a="370090219"
Received: from fmsmga007.fm.intel.com ([10.253.24.52])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Aug 2023 01:26:24 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10791"; a="733132238"
X-IronPort-AV: E=Sophos;i="6.01,254,1684825200"; 
   d="scan'208";a="733132238"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmsmga007.fm.intel.com with ESMTP; 04 Aug 2023 01:26:21 -0700
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id 868F8F4D; Fri,  4 Aug 2023 11:26:32 +0300 (EEST)
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
Subject: [PATCH v1 2/4] lib/vsprintf: Sort headers alphabetically
Date: Fri,  4 Aug 2023 11:26:17 +0300
Message-Id: <20230804082619.61833-3-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.40.0.1.gaa8946217a0b
In-Reply-To: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com>
References: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=EHo7JzZY;       spf=none
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

Sorting headers alphabetically helps locating duplicates, and
make it easier to figure out where to insert new headers.

Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
---
 lib/vsprintf.c | 38 ++++++++++++++++++++------------------
 1 file changed, 20 insertions(+), 18 deletions(-)

diff --git a/lib/vsprintf.c b/lib/vsprintf.c
index 6774cf84e623..63afffab4249 100644
--- a/lib/vsprintf.c
+++ b/lib/vsprintf.c
@@ -17,42 +17,44 @@
  * - scnprintf and vscnprintf
  */
 
-#include <linux/stdarg.h>
 #include <linux/build_bug.h>
 #include <linux/clk.h>
 #include <linux/clk-provider.h>
-#include <linux/errname.h>
-#include <linux/module.h>	/* for KSYM_SYMBOL_LEN */
-#include <linux/types.h>
-#include <linux/string.h>
+#include <linux/compiler.h>
+#include <linux/cred.h>
 #include <linux/ctype.h>
-#include <linux/kernel.h>
+#include <linux/dcache.h>
+#include <linux/errname.h>
+#include <linux/ioport.h>
 #include <linux/kallsyms.h>
+#include <linux/kernel.h>
 #include <linux/math64.h>
-#include <linux/uaccess.h>
-#include <linux/ioport.h>
-#include <linux/dcache.h>
-#include <linux/cred.h>
+#include <linux/module.h>	/* for KSYM_SYMBOL_LEN */
+#include <linux/notifier.h>
+#include <linux/of.h>
+#include <linux/property.h>
 #include <linux/rtc.h>
+#include <linux/siphash.h>
+#include <linux/stdarg.h>
+#include <linux/string.h>
+#include <linux/string_helpers.h>
 #include <linux/time.h>
+#include <linux/types.h>
+#include <linux/uaccess.h>
 #include <linux/uuid.h>
-#include <linux/of.h>
-#include <net/addrconf.h>
-#include <linux/siphash.h>
-#include <linux/compiler.h>
-#include <linux/property.h>
-#include <linux/notifier.h>
+
 #ifdef CONFIG_BLOCK
 #include <linux/blkdev.h>
 #endif
 
+#include <net/addrconf.h>
+
 #include "../mm/internal.h"	/* For the trace_print_flags arrays */
 
-#include <asm/page.h>		/* for PAGE_SIZE */
 #include <asm/byteorder.h>	/* cpu_to_le16 */
+#include <asm/page.h>		/* for PAGE_SIZE */
 #include <asm/unaligned.h>
 
-#include <linux/string_helpers.h>
 #include "kstrtox.h"
 #include "vsprintf.h"
 
-- 
2.40.0.1.gaa8946217a0b

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230804082619.61833-3-andriy.shevchenko%40linux.intel.com.
