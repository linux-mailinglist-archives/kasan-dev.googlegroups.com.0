Return-Path: <kasan-dev+bncBAABBGVVT66AMGQE3Q6WT5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D477A127F1
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 16:56:12 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-385d6ee042esf4101107f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 07:56:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736956571; cv=pass;
        d=google.com; s=arc-20240605;
        b=N2fAMdEcELwUKklbpoWk+3+xM49QtFP68TXdkOvUXi3cbkxs/CiLR8whEhx/rocxMV
         QDQY2UKMODdmKl1UBrA0xKZhxQ54ZqkX7XqRQ/iAcI+VV39cCijaviVhQusXCXUvkoq/
         X2C28/xVuZiC6DSzFmdJuO5lzhCax8nHS4sZro7+yk7W3j8YMInWTwoOGv4w64QMC1Ha
         uaUryMwokhpaIBsZon0mT2zJkPnDtnI6kad60fnYSl3KpIZKtw48mAlmyvXWRu/y/2XT
         fvhLAK0tK18gv79t0YG+mYKRsRYQWaz0omzUQdlqtV02sjA/wWQp5tfKUEnfKoKkaeDh
         X+Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=TgUVw9j6c8E2cuqxfAwqedIB2rld+rVUtBBXJokFU+E=;
        fh=EDZXgX4Pv7eijyXJljZ7ei5Ly8EOgRYk2m3Fr+asNbs=;
        b=ZsVfttHwaTEyp/YQRigsT4AXj6bZo1k/FX/+uTrVPC5vup43nSZvltbWNssPOsYgJc
         8+hhV66TutWz77iTZ0GaJh8ZFbtHa8FsHxzz38joET9t50CT2PX/zgZxKQeJa5Ov26mQ
         s9kSrhO9SgxJaHE1azOEb3Sxdf+viLExE2O18M2GSZcMNIK+V39CC2OkydaP2I9j+HmN
         j40jaknkD4XRsHhgTxLtFeWAz2nv7WdUc3a3Eh/tVNiHJduiY/tXoZ6XrFX91185Q5Td
         L5pIzQY+vQDhKa9BHRe1dR0LODzs2T0yfARA6856X16/jUfpFmeK1ww0lcIzsorLMpTt
         FlZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jx1C7duu;
       spf=pass (google.com: domain of thorsten.blum@linux.dev designates 95.215.58.186 as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736956571; x=1737561371; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TgUVw9j6c8E2cuqxfAwqedIB2rld+rVUtBBXJokFU+E=;
        b=J3aMQaJmG+BlAy8SynVVBbLxd4mKr8jAUJCI2IAgZg4nUogXFpnBiAMOFKAnFNsKZR
         7DExxT8cxiyTcq9Yz0qnLdyeNIIOEbtsbj2X6eb+FmEv2/s6C7Z4zBIiMSGh8N4iilR1
         B0yqqlJoIgWaYGSoetD/rohnSbUjb5MtLcshdFBY4wybPmTi69wUKUcXc/W2adA9njZu
         7752ir7D/pjjR9/FmykkGrkC4KnwGp3w1/G9Bs+jhDM/CzFzt6YYiEo3xI4jmlGwEFGq
         WZilocChecWYU2+qxFrP5Ulbl6c1VxDIhPyhhbH8oP1QBZIqZHDFopmgd+9RHRmKmbxc
         Xhjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736956571; x=1737561371;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TgUVw9j6c8E2cuqxfAwqedIB2rld+rVUtBBXJokFU+E=;
        b=h6zJHrZ+Qw0xFve4Khp+SCzd4k4Qz0JOcItUsevsSiEoTDfD/dZ7ceFPrtjrvcLSNh
         BNufdwZa79HLj7OlxG6lvQjxyMgbwUF9rgxpyewLMWzjjZnroFKmJ3TJtzoy1unFjIEA
         qOJV+mAdq1BOKBkhR+wBw/heJdtPkidjgLCrZxwliNQ8tS4g6Lmk8jX60MsfnX+2b8DS
         qpqFWfazu+P84BRO1dkKZLgk9sqJNIMAqxsI5wRndJtdt5KhaFolC/ze9hvtnraMC9vo
         Vsj3CAWo2RR8n4tQEpjMtycM/swQYxrGFRYOXcGx+v74+efvZpJzKreW1yBXmF1O2WFH
         sxeQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXPNo75Zam2iF+gbbtzJ8YAhyYY54svnqiWKWZ5XOleQ3xYByyW0FKuSCgcly800K6+YDE7Qg==@lfdr.de
X-Gm-Message-State: AOJu0YzTxA7CFiGADt+YyNtYWgXsH7nbrxShRkxxxfMIQj9G+g2cTwQf
	meVn4AhJZW7tbjuxCefi2+YQbWI0saxV7vEvYZBxwuBzHgMX/Aku
X-Google-Smtp-Source: AGHT+IEikeUj1WjDI5IWtUSte7cpUAiMVyFChE0i/JdIEK6z9mWxWI/ralnVvo+pMxkv5xlT1Cs++A==
X-Received: by 2002:a05:6000:1a85:b0:38a:4184:1520 with SMTP id ffacd0b85a97d-38a872eb1eamr24914209f8f.27.1736956570382;
        Wed, 15 Jan 2025 07:56:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:870d:b0:435:9218:d76f with SMTP id
 5b1f17b1804b1-4388ab3dab1ls76965e9.0.-pod-prod-07-eu; Wed, 15 Jan 2025
 07:56:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW8ZhmQdkQ1PHqBHgfEo2cU/ldHJXZSnrMDSXA/T6a6SJ/AsAjTlnfbeczK/GgR8dq3F/q+YZuvIxI=@googlegroups.com
X-Received: by 2002:a5d:59ac:0:b0:385:dedb:a156 with SMTP id ffacd0b85a97d-38be9ceac79mr1233750f8f.6.1736956568683;
        Wed, 15 Jan 2025 07:56:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736956568; cv=none;
        d=google.com; s=arc-20240605;
        b=dbrmwXeBBkHBr85IH599ZLEW64lbVBmc7dyNqpTzWC5mZxuTL/61acJWso7STVGi1Z
         n1si4RF+S9q5ItFndIIcuvaYGnshyjRNEmLu/dFeyC9WR3EUzn4skxYbZdKtwTD8LrlT
         b/uI7ff/FnIFcXYOElYTXtGuwz1BhuW7hwg7ppMCh0HaxD9sGEoMpax8KE+Lh3atm9fQ
         4MQlr0LY9yRdqwU1u/NsOQjX7rJcaGFYEqMlEbzURP3CJG+/MO3Xg8NDEJViqoU3n4NM
         fCI63lO69bXvP0kpf0NCMWMGEScBcb862kRCoFfKeseyWgnRHyxEQ3KPozRakLJYhQt8
         9iEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=iDlX5Gzy2AKY576SbA7XW5gmU33x7DeFH9ESiKU19Z8=;
        fh=lhmfq0oRmaWPvA9cvZGJfzNA25Hk2i3dlfqviYNk3Rc=;
        b=f4TNnkpk2ON/nJ3GrzakDfPWCLEOIWblC4AXNlVHngCwtPVq2qb5j2j1IEe8LeXAso
         I8UVcjr/R8Y/wspqnhVuSfjjXJad3McIcmBZ0cVp8/Kjrqvcu8Pg0rKpLln+IwHx3gfy
         J3ma1PF7Mcjw8msIvt5A0m431vwC6t2/72bkV1lKw3MEEsfgPXMk+phCL8o8KjkjzeNG
         aL8WUEMXQQQzqeqLSrLVO+ruS09rA1L2ugz6ISqrUFE6avwFZDblP4qknDQc6/8NZBqr
         v4eJpvvatc4zQtpOIdAWY67jC+4f4N2HL/DliWfnHLOW9Tlxp3HwwQbGAwvaE9eJ5WLo
         sv1g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jx1C7duu;
       spf=pass (google.com: domain of thorsten.blum@linux.dev designates 95.215.58.186 as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-186.mta1.migadu.com (out-186.mta1.migadu.com. [95.215.58.186])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-437c166380csi775455e9.1.2025.01.15.07.56.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2025 07:56:08 -0800 (PST)
Received-SPF: pass (google.com: domain of thorsten.blum@linux.dev designates 95.215.58.186 as permitted sender) client-ip=95.215.58.186;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Thorsten Blum <thorsten.blum@linux.dev>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Thorsten Blum <thorsten.blum@linux.dev>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2] mm/kfence: Use str_write_read() helper in get_access_type()
Date: Wed, 15 Jan 2025 16:55:12 +0100
Message-ID: <20250115155511.954535-2-thorsten.blum@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: thorsten.blum@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=jx1C7duu;       spf=pass
 (google.com: domain of thorsten.blum@linux.dev designates 95.215.58.186 as
 permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Remove hard-coded strings by using the str_write_read() helper function.

Suggested-by: Anshuman Khandual <anshuman.khandual@arm.com>
Signed-off-by: Thorsten Blum <thorsten.blum@linux.dev>
---
Changes in v2:
- Use str_write_read() in report.c as suggested by Marco Elver (thanks!)
- Link to v1: https://lore.kernel.org/r/20250115090303.918192-2-thorsten.blum@linux.dev/
---
 mm/kfence/kfence_test.c | 3 ++-
 mm/kfence/report.c      | 3 ++-
 2 files changed, 4 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index f65fb182466d..00034e37bc9f 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -20,6 +20,7 @@
 #include <linux/slab.h>
 #include <linux/spinlock.h>
 #include <linux/string.h>
+#include <linux/string_choices.h>
 #include <linux/tracepoint.h>
 #include <trace/events/printk.h>
 
@@ -88,7 +89,7 @@ struct expect_report {
 
 static const char *get_access_type(const struct expect_report *r)
 {
-	return r->is_write ? "write" : "read";
+	return str_write_read(r->is_write);
 }
 
 /* Check observed report matches information in @r. */
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 6370c5207d1a..10e6802a2edf 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -16,6 +16,7 @@
 #include <linux/sprintf.h>
 #include <linux/stacktrace.h>
 #include <linux/string.h>
+#include <linux/string_choices.h>
 #include <linux/sched/clock.h>
 #include <trace/events/error_report.h>
 
@@ -184,7 +185,7 @@ static void print_diff_canary(unsigned long address, size_t bytes_to_show,
 
 static const char *get_access_type(bool is_write)
 {
-	return is_write ? "write" : "read";
+	return str_write_read(is_write);
 }
 
 void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *regs,
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250115155511.954535-2-thorsten.blum%40linux.dev.
