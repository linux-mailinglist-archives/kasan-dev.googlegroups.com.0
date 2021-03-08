Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBFM3TGBAMGQEQA5OOBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id AD179331321
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:15:18 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id y22sf2792943qkb.23
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:15:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615220117; cv=pass;
        d=google.com; s=arc-20160816;
        b=QqLC6awrLK0E0CdWJUwOYtY/7nTLDJ5IxPmIznIU0tlMZlS9FAM7oAgxCii6IttRnw
         r6CE3PFPi+cXu6ioEYh6/tyC4erlrH7QfeEJ2y7uCBiw4A9y5vyf/N5xWOolXrXf6a5M
         r9xUI2umIkeUAfue1URJbNjWup+fdrVd1Lx66Zyc+qGFUTnOcx00wVap9N7wZBiQFTLf
         RAdPleDLimzlgQnVenrvJLl46vCEKVtk/SyJBqn4zAarPzL4z1QnMvutmPfPchl/AwGF
         yjLhMxsuFnZc8kK8DZwYyN8DN1vZNvSCaut+NzPNi7Q/CWzgrveWw9d4MXOxHe2vg9dT
         O8dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3BqtuMFzgXijAuDfrpZjACF/yGoF9YC6uxvQ1U70Ck4=;
        b=m0DdE1ACb1vDtqSP2+aXWR2ViKceZN4h1t3fsMDvValxN0LnRiH//Igj9AZ0wl0Mfm
         CPh4rtAl1n6ix3AtzNtRmtogdjpXpMfGOJ7P47Idid/FW5lnEUVKHOCIkaQdb9/mwDxF
         j18OCecLDKM2lGs9kFDXb2FWhKve4m2JwXIycc3tfjn85O//70ljoA2LFMXYTGb81eIz
         WCagByQDY4uvB5j01E9SQjb2wWbE+uUME0Hr7pAaKisLEzsKYmtCqY3P6wUldK5Mu9G3
         IW3oMTCLQdsZOI9j2voCKcEclND+OnK4MM+K+ze9cjxbeQJnY2UG4/HW2MMa76i/gClH
         m9DA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3BqtuMFzgXijAuDfrpZjACF/yGoF9YC6uxvQ1U70Ck4=;
        b=o932/snxwb4f9/RSieH7vrvKvcGs49/bgH7k7NdCMobWXmSbOcYUVBYKb6SF82poon
         WW/ZH8F5c/yzXIbzi4WHVMpOM72JryZlpWOoxHhq+9LbcHkrOKAd6N0jRL2UoPNbvipp
         r4hFB9Y1CWjAlg20F/58gsZSUL57LxQPZ6YPbBWBQ5fhpRL+7ppOKX1Y7CAwXbr6daYR
         jjhlB5v5GFGFSkgpfzY8E5XW0jHkm2Yp+u8IRC7VZBMMBSCDk23W1gwXvb4aqLWRl17X
         ZqLcDjzGcDueV3nMxFaSUk3rq6SarNdsEGTi+ifqNakyvsyzae7EBdGRmx7x7F9zFXHO
         mIhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3BqtuMFzgXijAuDfrpZjACF/yGoF9YC6uxvQ1U70Ck4=;
        b=Pk1MMgNzqSVn3PazzEiGZJDGmC3+yg08AiQIB5aj7xuFmX7Z/lcDqgra2UvTHUnA+N
         Bks5HeUBc/UHR7MVsCG8eS6YTW4Kpei+zJd9K9tDCDV21Iao/pbFZ3njNR/ZgdldlCxA
         oBDL2QSBNb9iRzox4Ywp2uP5QiMkBqIFQe05/CWR7cRiNt3jbi0lJdNup2maBxFFOYIA
         boj2FrCzyHOkHXcx1S6GYzoFGbLAHeTaNzX1uQvsgtn7FT9y8XD+BMpBvDBJd+GJHdfM
         Jy+mA1WoHDzGXBtl+NKLZ/wdcjeXGrQ556d+kF2MAZ74Q+V8itts4jITjdunGtDsczJU
         OYGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5338rZFCL9umsmMior9g5xwQ79huMInF910r5CXnV1tCIepilLWu
	aFzvwnCNnGoUaF2nKlLRqGc=
X-Google-Smtp-Source: ABdhPJyyWoQyWCN/PoWXZFn69lDwnpzVDGieRRbxagL/g/uFytuCduaQ8wwxr1ghujWJu34JHo3EPQ==
X-Received: by 2002:a37:4947:: with SMTP id w68mr20930171qka.94.1615220117812;
        Mon, 08 Mar 2021 08:15:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:ef0f:: with SMTP id j15ls2689961qkk.5.gmail; Mon, 08 Mar
 2021 08:15:17 -0800 (PST)
X-Received: by 2002:a05:620a:220e:: with SMTP id m14mr22078957qkh.303.1615220117392;
        Mon, 08 Mar 2021 08:15:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615220117; cv=none;
        d=google.com; s=arc-20160816;
        b=ZiXJC+henatBy0gmtb1kLJI6AnoI+ZwNO/l26roB5/cXBxArIGXfcycieeYJ5eVcbM
         v/wg61iyU42G2jvYgTL25vUoecpuzoJ2mZsDxODyCxrioSw9J1e9qecyWBnVy9Un7GTl
         KO6LB4ZMhB6KyOzmDQxGImUI5OXZYnmDoQBDG7q+Dzr/JDPHtbPJgKXe/0XBI+i+nSi8
         Z0M0N8HVC2yTql+ogd9lxpvry8oMBSAJTLaXiouZy2m39PlXI3FizJVZuGZnw9Qk7AX9
         fvF3hp9BLicmjh4GEu41AyprdSqG3y52+vXMHQk/Zg8+8y80UIT96kM7/rY+nukZt2iz
         qp8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=T03MtvbpaPlQelBLOigL3a4Mq7YEU1PTkqsjk6/wW6g=;
        b=KGtNHM8EiICcTM6DdicWIecb+E9UL0IkTlElhkcaEljunQM0GbvXIksjcA0FvhEtjO
         NgvvD++eDrHngqLwfsTcjj/RvePy6crpryxFZnkcW2WDFD/3+9dErl6XOJSPTat/u3yo
         /nSInPxUEihB2v9TEp9mtr1Y4EozhA73Ik//Gz8ABBI7da3cmbfpHkGOiLGiux18rjTq
         5MTfB7RI7aZg3COaDa+ypnVkoVPyjlT+CGHgaOv0KgCB/P88gVaMPQ4umlrOXJXGUXm9
         E+KIfhf5FjH2E99g/lsS+q3tyFvOy1rxaAO2zTenTuCELFgUeTVlxnJS+AuOGpcYfLpJ
         GM9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j36si617932qtb.2.2021.03.08.08.15.17
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Mar 2021 08:15:17 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id BC3671042;
	Mon,  8 Mar 2021 08:15:16 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D92963F73C;
	Mon,  8 Mar 2021 08:15:09 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v14 8/8] kselftest/arm64: Verify that TCO is enabled in load_unaligned_zeropad()
Date: Mon,  8 Mar 2021 16:14:34 +0000
Message-Id: <20210308161434.33424-9-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210308161434.33424-1-vincenzo.frascino@arm.com>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

load_unaligned_zeropad() and __get/put_kernel_nofault() functions can
read passed some buffer limits which may include some MTE granule with a
different tag.

When MTE async mode is enable, the load operation crosses the boundaries
and the next granule has a different tag the PE sets the TFSR_EL1.TF1
bit as if an asynchronous tag fault is happened:

 ==================================================================
 BUG: KASAN: invalid-access
 Asynchronous mode enabled: no access details available

 CPU: 0 PID: 1 Comm: init Not tainted 5.12.0-rc1-ge1045c86620d-dirty #8
 Hardware name: FVP Base RevC (DT)
 Call trace:
   dump_backtrace+0x0/0x1c0
   show_stack+0x18/0x24
   dump_stack+0xcc/0x14c
   kasan_report_async+0x54/0x70
   mte_check_tfsr_el1+0x48/0x4c
   exit_to_user_mode+0x18/0x38
   finish_ret_to_user+0x4/0x15c
 ==================================================================

Verify that Tag Check Override (TCO) is enabled in these functions before
the load and disable it afterwards to prevent this to happen.

Note: The issue has been observed only with an MTE enabled userspace.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Reported-by: Branislav Rankov <Branislav.Rankov@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 .../arm64/mte/check_read_beyond_buffer.c      | 78 +++++++++++++++++++
 1 file changed, 78 insertions(+)
 create mode 100644 tools/testing/selftests/arm64/mte/check_read_beyond_buffer.c

diff --git a/tools/testing/selftests/arm64/mte/check_read_beyond_buffer.c b/tools/testing/selftests/arm64/mte/check_read_beyond_buffer.c
new file mode 100644
index 000000000000..eb03cd52a58e
--- /dev/null
+++ b/tools/testing/selftests/arm64/mte/check_read_beyond_buffer.c
@@ -0,0 +1,78 @@
+// SPDX-License-Identifier: GPL-2.0
+// Copyright (C) 2020 ARM Limited
+
+#define _GNU_SOURCE
+
+#include <errno.h>
+#include <fcntl.h>
+#include <pthread.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <time.h>
+#include <unistd.h>
+#include <sys/auxv.h>
+#include <sys/mman.h>
+#include <sys/prctl.h>
+#include <sys/types.h>
+#include <sys/wait.h>
+
+#include "kselftest.h"
+#include "mte_common_util.h"
+#include "mte_def.h"
+
+#define NUM_DEVICES		8
+
+static char *dev[NUM_DEVICES] = {
+	"/proc/cmdline",
+	"/fstab.fvp",
+	"/dev/null",
+	"/proc/mounts",
+	"/proc/filesystems",
+	"/proc/cmdline",
+	"/proc/device-tre", /* incorrect path */
+	"",
+};
+
+#define FAKE_PERMISSION		0x88000
+#define MAX_DESCRIPTOR		0xffffffff
+
+int mte_read_beyond_buffer_test(void)
+{
+	int fd[NUM_DEVICES];
+	unsigned int _desc, _dev;
+
+	for (_desc = 0; _desc <= MAX_DESCRIPTOR; _desc++) {
+		for (_dev = 0; _dev < NUM_DEVICES; _dev++) {
+#ifdef _TEST_DEBUG
+			printf("[TEST]: openat(0x%x, %s, 0x%x)\n", _desc, dev[_dev], FAKE_PERMISSION);
+#endif
+
+			fd[_dev] = openat(_desc, dev[_dev], FAKE_PERMISSION);
+		}
+
+		for (_dev = 0; _dev <= NUM_DEVICES; _dev++)
+			close(fd[_dev]);
+	}
+
+	return KSFT_PASS;
+}
+
+int main(int argc, char *argv[])
+{
+	int err;
+
+	err = mte_default_setup();
+	if (err)
+		return err;
+
+	ksft_set_plan(1);
+
+	evaluate_test(mte_read_beyond_buffer_test(),
+		"Verify that TCO is enabled correctly if a read beyond buffer occurs\n");
+
+	mte_restore_setup();
+	ksft_print_cnts();
+
+	return ksft_get_fail_cnt() == 0 ? KSFT_PASS : KSFT_FAIL;
+}
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210308161434.33424-9-vincenzo.frascino%40arm.com.
