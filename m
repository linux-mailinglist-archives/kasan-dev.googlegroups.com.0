Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBOXMWKTAMGQESMYZV5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 78DAA76FBF2
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 10:26:35 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-4fe4aaa6dacsf1772998e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 01:26:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691137595; cv=pass;
        d=google.com; s=arc-20160816;
        b=iyhWuv9WZJJuDM9cZWid4acKnW+K3csAK57r9ApxLTT2Sp/rza9z+J3qlob00VMJt5
         6Aps6Zv+pyur+cFBHSHR///fybZhOd4/Bn6Iml6v+SYSFbs4sJ4dRYuwFsFLevFR6F8M
         ejkSQAPDD4YcxLyZkrFoc0ezO8Xua1yRemDnNZpeiSkmPb79bN28lc28//RpjzpMYnuk
         mvornUVLflqKe994P/w0pj0A/7SEjs9EPfQQrzZiDAE1eWYvpUkbD+DPh19PIGUcys8+
         weTYLEeaUCpz9JjlPu3B2Ym8+z2V6Ns0hGrH0rzLbKvdUe269Nh5M1tvONIYJfMrNjk4
         hyDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FNsrTuMO/8UpbaMQX45WuixBd59J3Ozexsu4JNnBHo4=;
        fh=ubSGe9Pf/KxTId9rGYzy0xYsiY5Gj5OI3uWYUzuWZkk=;
        b=tFWyzjXdVbmzhxDWri5U+oGUQLEw1Ca9ybgrVQSow30FiGwZLQ+5Ie34GePsOSAyOJ
         3wRJEwvfQ00LjHoDnIggP7V+i4UEowXvJDZKaBBRDN90GECUgFlqe2p8pSgfqn4gb5A+
         9peJD1Lsoxh9EK05XqzJRHhqmo8wJ2YLNCzXPQ2SVZAJDk+EQD+ouwJCy+kaQghV/BnG
         /fjhkKomO+moXNLIMiaAC9o+CIfFizTaP/FiTQXmp+mF+duFm9qtqPJ6yXwPqy/s02Xv
         /09Lo9p129SVIEl11RSmRta/g4DKijFFNFVI5br9V5nWKiKgRmo15WynPvBN7KxD7rsD
         CZZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=KXKqQOOc;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691137595; x=1691742395;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FNsrTuMO/8UpbaMQX45WuixBd59J3Ozexsu4JNnBHo4=;
        b=bOBLaJk41P/x+1X+zdC2wmyrfU/8h8at+VOnWsKI1SNcP97FsgN+dhVw/5D4zvJABo
         rgQ/CecvPHOsir2ipOOZ6XXU2c9deCaJGPZFjqWDVc2IacCwAwybmEBgADExAzrrZUDJ
         PAQ7p3J6O1OKP5wm+r8R0UAS/q9e0Pdjj15T9u3c7N8g5MUqJwBcMkOBwrd2IW2HojFT
         8KmaYEHZlt82ba9SzN7BJYPB56vtRcMQqqWKvk4g8OnDaejoVa07Anynmxa3M3HDH05U
         hedAm8gqBiAuIAIxv//hYdbLqeHgz7QBMflihB2pwmJ1URFnNRrlfyySZZrCuLOub4uN
         ayvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691137595; x=1691742395;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FNsrTuMO/8UpbaMQX45WuixBd59J3Ozexsu4JNnBHo4=;
        b=GNwGFXTTsUKagipeYZlQjZuwrlIWH2iFCZhvWVQQiZtOf7dg2I6DApxtBsknoUt/AM
         epeG/a5Xvs7r+FKsfl4GXgaV2ougBYJcS3EnWW4HEpnYrYjQ/+hNHO00++7A1tr8l55H
         eWsZtV1DdaOFvrkHRxPJ7jk+cjLFcNtEeGc4HkgMSzzNRk4+ACiTMnkvFA5Gz9ap6Idg
         7qeQ7EEIKOpguMMKmeyYXO4rOLyq6L3/X4SiufJEUfYwTMICiH0oFAClvP3oOxhhQd7l
         vjwOa2tspQMFpBn5nRBe+jOn0ykuRPe+CcdFCHZA/czmvwZUU2QU26MIVaPM8nOCXBbK
         /Mtw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwI+GWCYljPmSvMuFH3f0284XfEOP8D+NumJIbv0+EON/tMK4MC
	QMrHF3vilsA2kB/9zsvZuhQ=
X-Google-Smtp-Source: AGHT+IGd0m0+5hV1Ni/j87SYWxsYlbJGkpsy5+wQ3R+KbbTEVGtCbVFJmDiG8bjZyf9meMMiMwFqyA==
X-Received: by 2002:ac2:4d8f:0:b0:4f8:4512:c846 with SMTP id g15-20020ac24d8f000000b004f84512c846mr815431lfe.49.1691137594467;
        Fri, 04 Aug 2023 01:26:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4649:0:b0:4fe:2f15:1701 with SMTP id s9-20020ac24649000000b004fe2f151701ls1047162lfo.1.-pod-prod-05-eu;
 Fri, 04 Aug 2023 01:26:32 -0700 (PDT)
X-Received: by 2002:a05:6512:525:b0:4fb:a0f1:f8b8 with SMTP id o5-20020a056512052500b004fba0f1f8b8mr721519lfc.63.1691137589920;
        Fri, 04 Aug 2023 01:26:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691137589; cv=none;
        d=google.com; s=arc-20160816;
        b=WUh13x5Xib72R/hfqiSsmSrfmuwjAhHFHqfhdf4LpwcQS+2hKmq1gjzSvfanyvKqyY
         zLWvKw1VYCJBjJB7+UpE8TKoFZzZz6+ycFRETIl67D1JGWNMmr8moGOf1Mm7Z45kn7RX
         b0rEjCo7W1of3EjnoBdERLdWRjTu5KhwomDYJ9yr4qG4RFkPuFEcd7MksDMbeHS73QOb
         mthXHp+EEzQMuJVYdRpT0+ENjeOYCDJmUhIr5o/9D6S+biLTHytmOuhVCfSCeOPhTSvo
         b8PyMaKXFYdvO6tqU4UMFS8mBFx5voDC4kuyWs6ia2PfUMIBRffhTYAQtSNy67hIIjCb
         4k1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zA/dH5Y7WcTQ2A6+oZfsEez4kkDuyoFFdNy1mTJzEFY=;
        fh=ubSGe9Pf/KxTId9rGYzy0xYsiY5Gj5OI3uWYUzuWZkk=;
        b=WXYpk7drS3VQA/0qSvPf7/DgMtKdGei8knHuehpCnY8KZwKKy8msO+TSSiVWrzWfzF
         Sq4sf8favTnk80LTDZlwfxzc1wqPBUARf0KD19UxAtnfg/liUkbz8n2WP7Ru+0JvFKZy
         55skeYY+WfOJlMccRxLh9D2l9dO9UjABWIt2yWpQuYUAALnMrIC1dF8ZlHu5MmhYzi3R
         3uvFbHFQxzYQoKLJ1Q50a+BRK7tKsrWF1K6BAiV/IVuP2Yh4VRgZgVWMymEabMVvquvF
         YYhao8wNW545t9+uhEh5dUi3yxo+n6NUgzWlCnZH6o205O6zyX2F/SbpFZQmRS9IVYcC
         Ro2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=KXKqQOOc;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.31])
        by gmr-mx.google.com with ESMTPS id m1-20020a056512114100b004fe157ebc07si131265lfg.1.2023.08.04.01.26.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Aug 2023 01:26:29 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.31;
X-IronPort-AV: E=McAfee;i="6600,9927,10791"; a="433952151"
X-IronPort-AV: E=Sophos;i="6.01,254,1684825200"; 
   d="scan'208";a="433952151"
Received: from orsmga006.jf.intel.com ([10.7.209.51])
  by orsmga104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Aug 2023 01:26:25 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10791"; a="706907756"
X-IronPort-AV: E=Sophos;i="6.01,254,1684825200"; 
   d="scan'208";a="706907756"
Received: from black.fi.intel.com ([10.237.72.28])
  by orsmga006.jf.intel.com with ESMTP; 04 Aug 2023 01:26:21 -0700
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id 78DB16A6; Fri,  4 Aug 2023 11:26:32 +0300 (EEST)
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
Subject: [PATCH v1 1/4] lib/vsprintf: Declare no_hash_pointers in a local header
Date: Fri,  4 Aug 2023 11:26:16 +0300
Message-Id: <20230804082619.61833-2-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.40.0.1.gaa8946217a0b
In-Reply-To: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com>
References: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=KXKqQOOc;       spf=none
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

Sparse is not happy to see non-static variable without declaration:
lib/vsprintf.c:61:6: warning: symbol 'no_hash_pointers' was not declared. Should it be static?

Declare respective variable in the local header.

Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
---
 lib/test_printf.c  | 4 ++--
 lib/vsprintf.c     | 1 +
 lib/vsprintf.h     | 7 +++++++
 mm/kfence/report.c | 3 +--
 4 files changed, 11 insertions(+), 4 deletions(-)
 create mode 100644 lib/vsprintf.h

diff --git a/lib/test_printf.c b/lib/test_printf.c
index 7677ebccf3c3..9e04b5f7244a 100644
--- a/lib/test_printf.c
+++ b/lib/test_printf.c
@@ -24,6 +24,8 @@
 
 #include <linux/property.h>
 
+#include "vsprintf.h"
+
 #include "../tools/testing/selftests/kselftest_module.h"
 
 #define BUF_SIZE 256
@@ -41,8 +43,6 @@ KSTM_MODULE_GLOBALS();
 static char *test_buffer __initdata;
 static char *alloced_buffer __initdata;
 
-extern bool no_hash_pointers;
-
 static int __printf(4, 0) __init
 do_test(int bufsize, const char *expect, int elen,
 	const char *fmt, va_list ap)
diff --git a/lib/vsprintf.c b/lib/vsprintf.c
index 40f560959b16..6774cf84e623 100644
--- a/lib/vsprintf.c
+++ b/lib/vsprintf.c
@@ -54,6 +54,7 @@
 
 #include <linux/string_helpers.h>
 #include "kstrtox.h"
+#include "vsprintf.h"
 
 /* Disable pointer hashing if requested */
 bool no_hash_pointers __ro_after_init;
diff --git a/lib/vsprintf.h b/lib/vsprintf.h
new file mode 100644
index 000000000000..ddffde905824
--- /dev/null
+++ b/lib/vsprintf.h
@@ -0,0 +1,7 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LIB_VSPRINTF_H
+#define _LIB_VSPRINTF_H
+
+extern bool no_hash_pointers;
+
+#endif
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 197430a5be4a..fb28c6abd58e 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -19,6 +19,7 @@
 
 #include <asm/kfence.h>
 
+#include "../../lib/vsprintf.h"
 #include "kfence.h"
 
 /* May be overridden by <asm/kfence.h>. */
@@ -26,8 +27,6 @@
 #define ARCH_FUNC_PREFIX ""
 #endif
 
-extern bool no_hash_pointers;
-
 /* Helper function to either print to a seq_file or to console. */
 __printf(2, 3)
 static void seq_con_printf(struct seq_file *seq, const char *fmt, ...)
-- 
2.40.0.1.gaa8946217a0b

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230804082619.61833-2-andriy.shevchenko%40linux.intel.com.
