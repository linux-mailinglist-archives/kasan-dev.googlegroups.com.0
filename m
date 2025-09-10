Return-Path: <kasan-dev+bncBD53XBUFWQDBB3MXQTDAMGQE7AIFX2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 02B2FB50D2A
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:26:08 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-77283b2b5f7sf13148060b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:26:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757481966; cv=pass;
        d=google.com; s=arc-20240605;
        b=J60gE6HL7LrONaIEbRwuXtJyRN6D4hD+QPQLOBEWB/ZJDowLUlObaF4r6ieYMuMB98
         OeOrRgqyP+AiN3zUHIT7WTRqKV+biLwU+qOTFFDVVFSS1dxotVmXFIyFBXCDdr/zm2JI
         aXgVfAYuLCApx3XZv7xT7ik4rzC1XCZvAKntOWDwRZ73DjTMl9EdgAftNdc23rv/8G+v
         Qe3DNqGs+0epAYSuW2eriA2Zck1r6AQYns/ZmarrI2IjDrfAK8ZO6fl4U07F0GjbNb1Z
         OWAiNVnPU5r94pO4oB0m6mhShUZQlcVtv1XXAYg47N2moRy2leojP20hQVIj3lNnCqb9
         Tlnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=9XlWkVJtWlthersXtVeXfnHubC6TgNVcG1nyEkvwvxI=;
        fh=QOUGSVj/NzE8QecwyrHnFKDliKnBAOc19vpzuRTQc9o=;
        b=VCkM9pgd1QxnC0+7hWVMlaT6PDaqlfRhU1u9xsTazmwgRhAPY8dKKvp1mWvmU+QCdB
         vmRQ4Zx4a2PVjZhh7BTj7l+7OIRmum4F5Nk4UxHQN3f9+elXMak4D4Q6oIVsGkUeU1bZ
         N0qTri7d6P5wl/tiiOj0JlWTL2j3CoPTED+vRR04/rBCyTrujOusBr/N3L2dWvhmTKoq
         MTMMw9PWK7l9mw1P6qZB+reGoo6+q8yEOks4GEJ+BsA9NhDw8HLeROfew8l++Y38T1uy
         3JbzqeZENjJOaf6WHVaOrnABd0ueuSzZfTTz2h7nHemC1bAnu7RazWcDG3xxkRfC1QpO
         wzJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="LMBG/BRU";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757481966; x=1758086766; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9XlWkVJtWlthersXtVeXfnHubC6TgNVcG1nyEkvwvxI=;
        b=ZeeBOrhuca7tQyyDRVmAcW7QnO2hm1tzC5mvTQker9iagjggfhqXvGzvFujVCTqFCO
         BoLAozNFgKdxGB3Qwo/KABtARB26maPI80ZTQRejWHN9hJ/orVxk5YUkXopXSjw9DcNl
         y7dvxbOu586vHGlMt7YsoZwUjn+QfyxuxSjHeJCVAMqaMfI0RvDud5qld2Hd9UpG0bej
         jV3SqjNeGbl17liStv2RPvhVa3za+z+BCeJfd0+e3f/IE830dgraRl/d0nb83sFLWJub
         66BR65BeFgWtEzFGeC1laS62DeYBypWnlxOBCX2ZTkZxEypPsiUlM+UKI6hXNoCTjwAG
         ECWQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757481966; x=1758086766; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=9XlWkVJtWlthersXtVeXfnHubC6TgNVcG1nyEkvwvxI=;
        b=NNYwzG2MzHAkPCFJTTb6C8mWD/W0Iru0F21ylJV3OVVMWsHwI8lAGuIRM9skp5rg+e
         6ka0kYwchu0jBK+uVzoG4g2XzRp9ME8CojE/YbvFce9RKlzLUk4ksv36Tv9Fas8XcsHa
         wc/9q5IJgifgiBFukHfQJeOMMnzpqLOX+4zl28evScD/heX9rJKHO7r/+K8Ozv3NuAjm
         wl8m9sqFVQh5520FFi2bJoUuKv81QF29M2g3hSBV5AUEJuStnLOOngCFBsp6eG4VSLMc
         4coYchEw3GUFwFEISJGn+2fo28P9ON7Ujb/pejWA3g5PBdeke/XTYYdD7IEV6jmQ1BhG
         QyOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757481966; x=1758086766;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9XlWkVJtWlthersXtVeXfnHubC6TgNVcG1nyEkvwvxI=;
        b=BP9glbt4bRXP7I/qnlc5UmKTkTrqvmguCHTGZjdwoOpxFzIyzAmEtr5s+tq57gfIre
         XVXFUrfnVAAvs9gfsCyoAAaoZ8wXU/3Dy1dsyS6f7DXlGdbowTw83ef/DMEzT/dtC25x
         hveXyvds9zsdJe6AJOhCwBEuJQnB4nZQRsj7nGk0hIa7FjS5stPUhtspgUpHZtsMwnxa
         GmvpZxbYW0t6ti/zTrUDJxx7nxr3QN1PFpdlu/e09WImNpzNG1fUNB/uBeKClxYxF3GW
         jvik0i4zWse7wT2nc/fTt7WD5KKKoka7fSFU1l+4GTFN122YpiMvSAR5si6zWPxPm8e+
         arnw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU97+tcoom6WJLQ+rds0+RaqhSz5Xefpx5fEKmYvSSY9fmNJL3WISyFv/3gPQJdXOTnMBeVpg==@lfdr.de
X-Gm-Message-State: AOJu0YwQamfu29l5FxVl/iN2o0OosItdI5gz0mlfy27PJQ7LsbXHszjw
	N3iGos9rAOXXmpGcIEq/yJzUoLlwDy539HZoGaylpfN8TQwIzQGAye0y
X-Google-Smtp-Source: AGHT+IEYuCB24D5xBR6Iqu13+/th49VEkKMLaoYfUITrLMZv8SGUPW11TI9zH0ms9DuL/WWj7s2dng==
X-Received: by 2002:a05:6a00:b4d:b0:772:270f:58ab with SMTP id d2e1a72fcca58-7742dea483dmr18791118b3a.15.1757481966608;
        Tue, 09 Sep 2025 22:26:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfSnoYn8UHakXyX8hPSs4W8euSdYAqTE+ouHGfbUzZobw==
Received: by 2002:a05:6a00:2d29:b0:771:f987:3f6b with SMTP id
 d2e1a72fcca58-7741eef7c40ls4845765b3a.0.-pod-prod-08-us; Tue, 09 Sep 2025
 22:26:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVdXJwpAPXUzEQUe/UPh67JkStaxLHeZlUSfWQWOQ8KqXrg9JrrkGfs/ceK6u+lnF0HlfvMiTM5V9U=@googlegroups.com
X-Received: by 2002:a05:6a00:23c9:b0:772:6fd4:4bc5 with SMTP id d2e1a72fcca58-7742df11e55mr17165220b3a.28.1757481965041;
        Tue, 09 Sep 2025 22:26:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757481965; cv=none;
        d=google.com; s=arc-20240605;
        b=fmBjxc5PVI27o0aLTMyuPn87zFyT+Hv1+akuiAQA4z0iqevzm4xPfULSRtQ6Y0/oGq
         0c4djqFMdFyr9M/N6J0x+bLmbVF7p28sMD0WTzVMsJBAelLtYZBPKJZkbdcQ1a+Sbi0T
         xmm5qr3jIQPyq4jvUSKgpui4E9i7KL4Yo2p1cHXGz6El+PSbb1TrznxFkrQF7oNPZpuG
         ALyfBv31aB/9uGD3uzKZY6408HXLnff8QT8AcTvITjDbGDNch52QlmTgBL6SX8ot4bQM
         NtYvtzxqWpSl7S3mYLdxvP5W8Jr/NVJKwA3M/Z91L+A8+yT+q5s3OHzhrylWCF/qvcTA
         Rxaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1cGC0gkaVd18/Lxr4eoS+A1o44ByCYajfvvOspb3trU=;
        fh=q2drECZzJLv/q9jbgZaufvq4ZYoZx/cc0KKelHiydVU=;
        b=GjDOFhJ3bcWCRCbW+fSI3P+NU7mqSgTEop3CiRhxxMJShCB5P6kl8s4okY7E8T+1cs
         IpF+EY5nIrWo1GlN4DWLeNNwfbRaBCkJgOHN2KuvZg5Hfs4IMryRXhRY6mhcL2P2/eoJ
         gBgYpixR35HFwmSOvqqruY07mtN+uf/2+AmK+fBxOLCfAJvKUvZpUW9iLwhqUnY4yIyU
         YTOyjeF/R+EdIEUERvREqCBbTlDuWgto0KohClz/KlIwuaAbOiIjD8iSOS418lNSv39/
         LGWJuhBAUN4a97qq4fMAO2CcQI2b6yrnnPyHPwvtCrNGFaRjsTShsUEv/A2vvVJ2Le20
         XUhg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="LMBG/BRU";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77246129c24si641321b3a.5.2025.09.09.22.26.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:26:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-7741991159bso5973471b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:26:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUQujRhRUjn9q1IrJqGKwdWfY58qslad76P7Tka0nwtFTN72ugHluYEJf7n4SoC8IpI4veulzw0hnA=@googlegroups.com
X-Gm-Gg: ASbGncvwmheyoJ4aYPCvYVt6ZIf21y9iZ0p1EEL+yw5q+sjB7n8pEcEaORXf3OBoyDo
	T16RXuqLhvhoSl8cP8VhAXr5+FKsE0KyZ1aQ7I5wXuN8+rJB1WxwPXdu5lzUUKIDsLWmG4mtNU4
	RAwpzo9JsFVktSoywoN4jQBJmV4i60+JMGl6Ex7ZqP8g8DY80MQ7zrtJOfWmZYjwISmcT2zbZvk
	47IAEgNM2/JZeRDEVJXrhngAcbPTD9cyHN/oa6G26w/h75nj77PZS95Rcj3364u+7LWV8hYS7Kp
	h14psxn9VcjdoZ9PU57WyzDGZzq9WxyLJwXzesFi/djqzG9EwHpdBL9m5DeGDF83J1c2YPaLFtt
	zVDYYEwkv5cvYypAxqIaisEXLEKy4BhciNieqZbdraUi2
X-Received: by 2002:a17:902:fc46:b0:24c:d717:719d with SMTP id d9443c01a7336-251761615a7mr159790755ad.60.1757481964506;
        Tue, 09 Sep 2025 22:26:04 -0700 (PDT)
Received: from localhost.localdomain ([2403:2c80:17::10:4007])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25a27422ebcsm14815125ad.29.2025.09.09.22.25.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:26:04 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	"Naveen N . Rao" <naveen@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v3 08/19] mm/ksw: support CPU hotplug
Date: Wed, 10 Sep 2025 13:23:17 +0800
Message-ID: <20250910052335.1151048-9-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910052335.1151048-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="LMBG/BRU";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Register CPU online/offline callbacks via cpuhp_setup_state_nocalls()
so stack watches are installed/removed dynamically as CPUs come online
or go offline.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/watch.c | 36 ++++++++++++++++++++++++++++++++++++
 1 file changed, 36 insertions(+)

diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index e02ffc3231ad..d95efefdffe9 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -1,6 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
+#include <linux/cpuhotplug.h>
 #include <linux/hw_breakpoint.h>
 #include <linux/perf_event.h>
 #include <linux/preempt.h>
@@ -67,6 +68,32 @@ static void ksw_watch_on_local_cpu(void *data)
 	}
 }
 
+static int ksw_cpu_online(unsigned int cpu)
+{
+	struct perf_event *bp;
+
+	bp = perf_event_create_kernel_counter(&watch_attr, cpu, NULL,
+					      ksw_watch_handler, NULL);
+	if (IS_ERR(bp)) {
+		pr_err("Failed to create watch on CPU %d: %ld\n", cpu,
+		       PTR_ERR(bp));
+		return PTR_ERR(bp);
+	}
+
+	per_cpu(*watch_events, cpu) = bp;
+	per_cpu(watch_csd, cpu) = CSD_INIT(ksw_watch_on_local_cpu, NULL);
+	return 0;
+}
+
+static int ksw_cpu_offline(unsigned int cpu)
+{
+	struct perf_event *bp = per_cpu(*watch_events, cpu);
+
+	if (bp)
+		unregister_hw_breakpoint(bp);
+	return 0;
+}
+
 int ksw_watch_on(u64 watch_addr, u64 watch_len)
 {
 	unsigned long flags;
@@ -141,6 +168,15 @@ int ksw_watch_init(void)
 		return ret;
 	}
 
+	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
+					"kstackwatch:online", ksw_cpu_online,
+					ksw_cpu_offline);
+	if (ret < 0) {
+		unregister_wide_hw_breakpoint(watch_events);
+		pr_err("Failed to register CPU hotplug notifier\n");
+		return ret;
+	}
+
 	return 0;
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910052335.1151048-9-wangjinchao600%40gmail.com.
