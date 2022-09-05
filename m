Return-Path: <kasan-dev+bncBAABBP7L3GMAMGQEZ2FBFVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 0307E5ADB54
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Sep 2022 00:18:40 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id p19-20020a05600c1d9300b003a5c3141365sf7968410wms.9
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 15:18:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662416319; cv=pass;
        d=google.com; s=arc-20160816;
        b=01A9FGQq7qK1YE2lnlZrH2T69Mmwi+i0oNnThUZ88PRCPHk7tBykqU3aRx69T9jzSF
         M8yVAwEMCmeq6GCsf/RQCHMV6mBJqrOhZzF4EDuDFd5f3Owiei/CzS0/OW7y6Ny1qqlA
         4TybwP0MUQ+e1oI6EidrXZ5sUpjzy3aYlXHnaJfn2WfSYCpBMqPbKiBeef88nLUdUWhj
         yZEc8y1/9xu1mVCKSRV+H0ZZxPif2twF3/00RsmNo12Kqp0x87aI+ehNo/EvrOhOR56C
         VJpCIIgBIY+bSeTayY0SQSPf4bjwNWEko60Tve8n7zP8dAp5V9OUr0Ja/p65S61RFQFq
         wUhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ATcPMyRN8bEdJUx7FANYLFJAHv+s0wscsIj2JVotA+0=;
        b=Le1nRobk/T0GfPNBRe6m1DB9WaQQPAw/381t06mqBpSd53CW/U5FpcmnvaAKtFt7ge
         e0A8yPsN4429Fr5VCsZpZE6YwOTbtb4ln+G20ipl2iCAVQY4XB88nxbS7nvVqReNZi8F
         I4HmPNZLrDo7fc3pTWXJGjUdivc6gj5aOPf4MD0/ynZTcpRU5VWoAN/wHf+nA6H+/BwO
         qXwtv/ZPP4kB7CW0LR/jmdcvrjg92LpIGCBn1uwH8uN+3fWeVQy4uTQOHyEKTZrR/fux
         2Vy9iZwsWXbniZBOVrJiGwHajIs3OmhHIJB5MdesKLiEgyWb4DqXyd+3S3pOvDTkCQSt
         O/Dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=foLluK7p;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=ATcPMyRN8bEdJUx7FANYLFJAHv+s0wscsIj2JVotA+0=;
        b=LZ2pU+TlwA9nxPnUnVP61+3iUjSGMx3xYj37cCChTQTD4LkuJTEet+/TawNHvYH3tD
         CninLJ/+5SZlziei1yI4uxZ7wI2U3S9WCEZrif+gpxnN/9q0Bwin0XbWRMbDgg/kudkN
         FdXXgYFEaF/L+0QogDqjAUYm6PhliwSRlDIn7Aa33pqQmJ/H4YkGkLLrguBTDoPZbYW0
         ch1Naww2CQtIT4MnOqkoIgIktz/sg9UHcf2WbfxSrZgcnIZ8MsW9hv3d5ftVJgervFH+
         jeR24vHTY3wUWj+4TG2xGy+wiOYh+knbiK/tYnrOIh1KqTPDC2V6/X0kOxJ1GPRqj/g7
         DaDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=ATcPMyRN8bEdJUx7FANYLFJAHv+s0wscsIj2JVotA+0=;
        b=xDCBbHpaP+13ABlB5ccU/sX72rVo1b91I+YUUohb6/yDXEejgjCbDIlg76pRpTC2xg
         NiKH/+B62uM5OE220IEn5Rx9ICh3Rn1HAEQiknUOvE4dJaHjtQLLNX/kuPwbU8dMd5rc
         3llKCO7Tisuuwb5yLiu5lNq6A8X+7btYrCt3p4yYGhGYDFw5w+BxAGXtYa/4HWpmMAP+
         BYWP1Jsd26Cd5cjoib81XcVgnjJsumS/APdjjiwhjwCYHKMa+asn4RYC0Zip7sINuZph
         HKfGVeCC0dIGN6gbqd/aUbPEywn6FaP3p+cXN4RZAbtJGbb30WrtwUwmTAhZOcEjwaDs
         i0gQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2jq6/OH9/+i90FBX7l/DWPiVfLQGnUDg05fJDnNDyRwumqx7hH
	nIyJTsBjKKZLW7oQ93ajl9E=
X-Google-Smtp-Source: AA6agR5eyOy8+qP4XrgOqV8nDwFv4L/hXK4UBp2QQTH9GV38NkXv1rnFzcfuPNny+VjKomjhbvefhA==
X-Received: by 2002:a5d:6e8e:0:b0:220:5fa1:d508 with SMTP id k14-20020a5d6e8e000000b002205fa1d508mr27142292wrz.337.1662416319592;
        Mon, 05 Sep 2022 15:18:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c343:0:b0:3a5:22da:8671 with SMTP id l3-20020a7bc343000000b003a522da8671ls4192981wmj.1.-pod-control-gmail;
 Mon, 05 Sep 2022 15:18:38 -0700 (PDT)
X-Received: by 2002:a05:600c:19d3:b0:3a8:46a0:149f with SMTP id u19-20020a05600c19d300b003a846a0149fmr12043582wmq.185.1662416318889;
        Mon, 05 Sep 2022 15:18:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662416318; cv=none;
        d=google.com; s=arc-20160816;
        b=rcXCSQPhHdcuxsknZ1q3SQgplj59oUjBCD1c2nhuC8NX7npsH2cfkvjpYf7J/k/R2T
         DZSOSD+ulqAq06aGHG7q0jcEUOhrHJM81Fkdopl/HaLEcYCh+EXC9N0cK8Nuhsb2nzgx
         zcZazRwGYgxELYK4AGFvnvsK2lVBSF/H6T1vRHHG70alH/lTc+0fb1e/P9pXgt5BRRhb
         xRLCm1BfAmnglHkTuhRS2ylLi0+6/mw5DfgRWwKJ0mVXCOAp9PTW0Z1kI91JMCJ80L29
         tgl7p0LBN1XvdARFC5OAV3JekdW+iiYdzxMfU69kGJkJ+5iDcOyG3dcnVMOZfeqqgjhD
         xqcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=86vkn1lngiubNGWHffOAiBFa/gjw4IKkbIc5Z1/odHo=;
        b=WNTn0+eI62oxHZPmShNb7Y3oikX5tJOTilaL1RL355eyDsFdnd12yEaDWVyxSwYEQ1
         5GV7hu1+wNzuVF2OlBdPKSL4XFrYrtlmod2I5YoqIycJzQF7mxqZq5fPYyo6ktVytQ4L
         SV+UnB+o3O0/d6xCXr5CDJRZ47Uez15YH48SySowDVLf6rL/oM68o22niMANaiDnTbjN
         i0gP01ck9L7kH7LocNl26oQAk0+/NUr90p1ntbkuZDjKwjjM9JhCzef/hFEejEYPxzQS
         0FeqLl6qltOIK56tgbDlSo4NCARJlyIiPOfxIifLQqTWsXzwzAqjEv040AQwUDXajQ2G
         u6Vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=foLluK7p;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id ck14-20020a5d5e8e000000b00228d6a43531si108971wrb.1.2022.09.05.15.18.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 15:18:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH] kasan: move tests to mm/kasan/
Date: Tue,  6 Sep 2022 00:18:36 +0200
Message-Id: <676398f0aeecd47d2f8e3369ea0e95563f641a36.1662416260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=foLluK7p;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Move KASAN tests to mm/kasan/ to keep the test code alongside the
implementation.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 MAINTAINERS                                             | 1 -
 lib/Makefile                                            | 5 -----
 mm/kasan/Makefile                                       | 8 ++++++++
 lib/test_kasan.c => mm/kasan/kasan_test.c               | 2 +-
 lib/test_kasan_module.c => mm/kasan/kasan_test_module.c | 2 +-
 5 files changed, 10 insertions(+), 8 deletions(-)
 rename lib/test_kasan.c => mm/kasan/kasan_test.c (99%)
 rename lib/test_kasan_module.c => mm/kasan/kasan_test_module.c (99%)

diff --git a/MAINTAINERS b/MAINTAINERS
index 589517372408..31b3e4b11e01 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -10938,7 +10938,6 @@ F:	arch/*/include/asm/*kasan.h
 F:	arch/*/mm/kasan_init*
 F:	include/linux/kasan*.h
 F:	lib/Kconfig.kasan
-F:	lib/test_kasan*.c
 F:	mm/kasan/
 F:	scripts/Makefile.kasan
 
diff --git a/lib/Makefile b/lib/Makefile
index ffabc30a27d4..928d7605c35c 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -65,11 +65,6 @@ obj-$(CONFIG_TEST_SYSCTL) += test_sysctl.o
 obj-$(CONFIG_TEST_SIPHASH) += test_siphash.o
 obj-$(CONFIG_HASH_KUNIT_TEST) += test_hash.o
 obj-$(CONFIG_TEST_IDA) += test_ida.o
-obj-$(CONFIG_KASAN_KUNIT_TEST) += test_kasan.o
-CFLAGS_test_kasan.o += -fno-builtin
-CFLAGS_test_kasan.o += $(call cc-disable-warning, vla)
-obj-$(CONFIG_KASAN_MODULE_TEST) += test_kasan_module.o
-CFLAGS_test_kasan_module.o += -fno-builtin
 obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
 CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
 UBSAN_SANITIZE_test_ubsan.o := y
diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 1f84df9c302e..d4837bff3b60 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -35,7 +35,15 @@ CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 
+CFLAGS_KASAN_TEST := $(CFLAGS_KASAN) -fno-builtin $(call cc-disable-warning, vla)
+
+CFLAGS_kasan_test.o := $(CFLAGS_KASAN_TEST)
+CFLAGS_kasan_test_module.o := $(CFLAGS_KASAN_TEST)
+
 obj-y := common.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
 obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o tags.o report_tags.o
 obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o tags.o report_tags.o
+
+obj-$(CONFIG_KASAN_KUNIT_TEST) += kasan_test.o
+obj-$(CONFIG_KASAN_MODULE_TEST) += kasan_test_module.o
diff --git a/lib/test_kasan.c b/mm/kasan/kasan_test.c
similarity index 99%
rename from lib/test_kasan.c
rename to mm/kasan/kasan_test.c
index 505f77ffad27..f25692def781 100644
--- a/lib/test_kasan.c
+++ b/mm/kasan/kasan_test.c
@@ -25,7 +25,7 @@
 
 #include <kunit/test.h>
 
-#include "../mm/kasan/kasan.h"
+#include "kasan.h"
 
 #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
 
diff --git a/lib/test_kasan_module.c b/mm/kasan/kasan_test_module.c
similarity index 99%
rename from lib/test_kasan_module.c
rename to mm/kasan/kasan_test_module.c
index b112cbc835e9..e4ca82dc2c16 100644
--- a/lib/test_kasan_module.c
+++ b/mm/kasan/kasan_test_module.c
@@ -13,7 +13,7 @@
 #include <linux/slab.h>
 #include <linux/uaccess.h>
 
-#include "../mm/kasan/kasan.h"
+#include "kasan.h"
 
 static noinline void __init copy_user_test(void)
 {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/676398f0aeecd47d2f8e3369ea0e95563f641a36.1662416260.git.andreyknvl%40google.com.
