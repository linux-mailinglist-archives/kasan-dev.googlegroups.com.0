Return-Path: <kasan-dev+bncBD53XBUFWQDBBYUXQTDAMGQEH72ZSIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1315EB50D27
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:25:56 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-725d32eaa99sf203144506d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:25:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757481955; cv=pass;
        d=google.com; s=arc-20240605;
        b=U9O8o3UC3XnpRbijOe3BQ9gIYfeXJlHwSkozMveC7FO/Sj0Vrm+SAHVVUCBsfnOt9X
         o8yEwC/l2m6qXM0mPQIu4LtjVDvGPS6jOgSOQPi4iqIBh0lY4W6bVr79T3k8JKhIgnZh
         AnDavyjPeK/y4fn7zax6SZM+U6g+UgIILCd4yMPsrMvauYiwJS1H1+bIPSuQozkbv4Lw
         hR1a0is5O+457Ti0aME9JvgIO5RgrvyDX6IPdgyajF75v39D/TAx4Sv2xfB2Qnz/aofd
         SHdKeHPaQhaNx6HzBXAu44n9ra7A9K8BsX6+xxhtGN0GmpUyyI+i3/W/MAsWOLWPS/uo
         ZL7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=DX7azLeX0XIVyiFlHMvRhZ5ncQKT7Sg2KcyAW5Zhx2Y=;
        fh=pX0Inb4JtOjEQpex7An2uTTD0tU703hJps1lfBGKU7M=;
        b=jwMfjDW7X/qLAoHjAhHXTyCuqM4fpC/RrATR5kWXdWIKWXFlNxvVjuaYl6Sz+CKNvY
         /hLk0UOIy0/Pt4su7Av0EJieMl+dJv4gWPJXfn26mhMQ6xBcw3wn1DoX+IXGiDKwLvzP
         zl4AMMJIttl9DqS62Ah1HkXIqWPidEDHy4EkC3w1KujJeR3nnrZ0v1t7Y6PSA92yVefT
         ccpfktfgxDEy9v2LJv+aWsip1xgEfDRO4pgoSKaWac2SCZMlByGpDkBk3TPSDu+S/Vmj
         M4osuji0Nsn74NXAW1C8QrIdUkRauqW/PHb7EPTvZSsuEVyeg9am9uYw5cFFARvHJWct
         CiYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hepgyWPt;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757481955; x=1758086755; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DX7azLeX0XIVyiFlHMvRhZ5ncQKT7Sg2KcyAW5Zhx2Y=;
        b=kNYB2AbJzbBo0ZcbRuMy+9n0743k/1MIFt5fJvkWYSqtVl+bbIDzGK7zCdKbOel2d3
         H09SU5NzbFCLd5i2WpZyIJNvBllZw6hUmPD6+qWn3xqIaUy6PrzlWyHyW4KdvGzxY6wE
         S/Z3/lEqvFiGcMRzEh8ls8+4Kb2hxGgjPJVNY8cU9iHvVNNjOx4YR7nu+VePw2/R6fhr
         gvQ5TWX5ncikUbh5TzWtwufGFwoRrkO/H7m6p3rGdzotVUaaD5fPa5L1h/wCWXZUeLhe
         aYKTM54fzEZslRd72/uuDEiH5h+L/HwSUOkYHLFGxaccplIOjMYtWC0oBjHDTDZ4DO+l
         6xzw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757481955; x=1758086755; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=DX7azLeX0XIVyiFlHMvRhZ5ncQKT7Sg2KcyAW5Zhx2Y=;
        b=RA9a3N9SDxyvNrDyimoW/GAltTl1v5qP3InQMu8kln0Vft53gn/yxaOWJePWneZJ3H
         WhO8V7S/5NJwUrIfu14cRCFLwvj6VIVqexlXwUHQ3FmU4arZq6yeyz0I7M02x27OCAss
         pNFk1TWhrB19Y6MBWjOTQ0K/Hj2lQjYTdAFKYIGA223xlQt5/uVEnPDFIX2XOdojFTVB
         aOECDVtjouQLac1qKSg3t8odol+puPkl6P43IlqzcmnAqhe+4BCUJync2wuke6Fnr4u7
         wxCjpm9YwL5ZypeTHNDDzL9oQi7e2uJn3KhlUbgnv2WJsVHO41qskJdkBplusfE7z+wd
         xoKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757481955; x=1758086755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DX7azLeX0XIVyiFlHMvRhZ5ncQKT7Sg2KcyAW5Zhx2Y=;
        b=RTRafuk0rPeYGjSWCGD8+guxzImWhgS/yyeO7Q2s1ROrcv/9Wa9SZrceyr7NaYL2yg
         eXGd4Ap4/4HSQB8HLI0lwNf+HobnpCikHRzEDk2sAxmAujbdjEPaBOOBygxTmg+IfJND
         2qdM1g9EzBdKbzc9qYqau1mCzJWjnLANQ2H/2m+avBBlpqd3J2hWpNZ4IkGuXiwdELLX
         6exb52E6xKpEpAjhFVGvCollCy+I5Cqfji0+3ttDM5skIwbZEv0zY5vQBqJtdhjbF7fI
         QUEJyhYfw1oP7VWFlowaCmVONIlPWv6s6t0qjHTjwq+xeaBMHPxnv07jDoS6X411Qace
         dc1w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXOxcZ0yPj3rAoUbSb12KTSHslLmo75KsZFA96XrwPF7aCeZuO+0I7HIhw2nCbzDCQ+t+P4Jg==@lfdr.de
X-Gm-Message-State: AOJu0YyDvxUngAhxyM2n+yA/d5lFl+ZQ+Nvd8M1xdgVPU4rHAgssibtj
	3mQ/Gi1K7ltKPG6uYDQk5MphLGXIYfn/ZgZxWLIynUkv4bh+zFzp5TJX
X-Google-Smtp-Source: AGHT+IH/4G9G5VlWYIGX7AyRmCn//GEI2gRIE3uXR0UzUfKXXReYPiQjTIYyNziJCX6TcT8WG0Brbg==
X-Received: by 2002:a05:6214:2387:b0:70d:81ce:ec1f with SMTP id 6a1803df08f44-7391f9b36a5mr160549336d6.12.1757481954848;
        Tue, 09 Sep 2025 22:25:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4x7gZK3UIJ0FEJ3k9U4V5/fekjZIfrZShJ4gpSkUWIbw==
Received: by 2002:ad4:5c63:0:b0:70f:abdc:ed0c with SMTP id 6a1803df08f44-72d1b02b2dals87884536d6.0.-pod-prod-06-us;
 Tue, 09 Sep 2025 22:25:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWgOW0QdwMR+uJdmWc7SPG7Q75i7rhLz20RrItiwxopBgJ+bxTUYf5qmCI4TNHxb90y/hYoFchOQN8=@googlegroups.com
X-Received: by 2002:a05:6122:220d:b0:544:cb0f:a659 with SMTP id 71dfb90a1353d-5473aabfa41mr3656665e0c.6.1757481953670;
        Tue, 09 Sep 2025 22:25:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757481953; cv=none;
        d=google.com; s=arc-20240605;
        b=iWj3bN8+3kujppRYORXBHKiL7o6IsfSddcBhZBHh+6qw6NiZ1bswJ9uw8r+gXWnwqI
         H9ohjHx0gb0vkKNTx69Yy2ywz7zJfZD7rww4/AZ/8l41eUG20hmDXXw9hfiY81Aywr49
         2zAPhMHFUl4Ejtl9cO0CgFVVSlnfJncmzLHvNwKAwKzmE9TYFWor4wKsoooqj6nXq28W
         MC/E5LF/v5lups5ahEGP4DIgTSjXyqNIkIc1s3WDINjJxBqDfWC2cjEbeL8FxzAPAVzE
         r7RGu9K06xs5Bk2w/nvfKawZW4CAVt3DjmJ6wQadlxWq52NBg/9IOVXCBEjrOOdO4Uh5
         Dl4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mOx6p8YhFEr+hG/yZ9Zg64+RQ0caUuIY8LjmjDVRe3w=;
        fh=rfbeEoSrQHbI/CFi+gvowG9ntzXXcerDAc9w8bYnvAQ=;
        b=eVD3iGIFtyglCRXL+1zFQddWrtTkqzJZ8dJ8y2/GEUzfwfC5z3IIoMXHRplfRl2zav
         4Rboeb7qLddjw61T5HjLDa3NQE9rFTk+SgnJp5K+yqzhykmcTu1uXImaLM6SowCLTgRy
         bsshDx4eMFb31xJUo2opA1RN2e7CbHYlA9hus/SYuFfCWAzpU5VkqY5uWjsRQPNxOewr
         OItBdBXcC7fw/eC72k+RASgP/J0QdQCx4xZ+rT7F7pwZ5CaTUpjDnmhSnae8EHnbqGH5
         MFP60P1C+/3O/HudliFgV7ACadsuz5yLgXw+zcsFwNxrO7FhkzOF5pRl7K5Y7uUU2EKt
         eP4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hepgyWPt;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-544914fe552si1302138e0c.5.2025.09.09.22.25.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:25:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-24af8cd99ddso81722095ad.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:25:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWIrSYyR5D9EyDwx7Yle3bBmdsCWDPvRwxV36doY43zPDV0kXWQKE+K5g8rmQ90JrZTqtRT3yIHHaM=@googlegroups.com
X-Gm-Gg: ASbGncteYNqejZjJOj6q9D2trJ6/Q96PdjN/DqbTKyRBB+n7/3WH9TRh1o50DWTOeK7
	3g1scJyAh+DfSB6lM+3e0AjRt613veyKvNnVJvxDEzvxL5WLch4KPwA6YGTAvIO8wGla6Vk7D1x
	RfI26acvVXt3edGVYfkSEIApVCauMS8GnW6JvnSzDON1IkPn0Ptxb2IrWqBET7hT9mGSC/RC535
	tlVe5MpxkJSyELw8vE9KJTgslEzFUEHp5cKq23lGIbgkyLffOMtoBSt8AKr3ya2S9x2tBOzFF/E
	Ack8MUNmfjtfWexLfT7ux6whbzL7iKGMGYV/u6l1CzhoncOHUEK055xtOoIRKmRc//dMj+MPB5Y
	RYQEDaeGrc2X6xBxrtyEOSOgDl9sZbUflYw==
X-Received: by 2002:a17:902:ebc6:b0:246:255a:1913 with SMTP id d9443c01a7336-25171cbfd65mr173971245ad.39.1757481952659;
        Tue, 09 Sep 2025 22:25:52 -0700 (PDT)
Received: from localhost.localdomain ([2403:2c80:17::10:4007])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25a27422ebcsm14815125ad.29.2025.09.09.22.25.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:25:52 -0700 (PDT)
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
Subject: [PATCH v3 07/19] mm/ksw: add atomic watch on/off operations
Date: Wed, 10 Sep 2025 13:23:16 +0800
Message-ID: <20250910052335.1151048-8-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910052335.1151048-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hepgyWPt;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add support to atomically turn the hardware watch on and off without
allocation overhead.

The watch is pre-allocated and later retargeted.
The current CPU is updated directly, while other CPUs are updated
asynchronously via smp_call_function_single_async().

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kstackwatch.h |  2 +
 mm/kstackwatch/watch.c       | 95 ++++++++++++++++++++++++++++++++++++
 2 files changed, 97 insertions(+)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 3ea191370970..2fa377843f17 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -41,5 +41,7 @@ const struct ksw_config *ksw_get_config(void);
 /* watch management */
 int ksw_watch_init(void);
 void ksw_watch_exit(void);
+int ksw_watch_on(u64 watch_addr, u64 watch_len);
+void ksw_watch_off(void);
 
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index d3399ac840b2..e02ffc3231ad 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -3,16 +3,23 @@
 
 #include <linux/hw_breakpoint.h>
 #include <linux/perf_event.h>
+#include <linux/preempt.h>
 #include <linux/printk.h>
 
 #include "kstackwatch.h"
 
 static struct perf_event *__percpu *watch_events;
+static DEFINE_SPINLOCK(watch_lock);
 
 static unsigned long watch_holder;
 
 static struct perf_event_attr watch_attr;
 
+static void ksw_watch_on_local_cpu(void *info);
+
+static DEFINE_PER_CPU(call_single_data_t,
+		      watch_csd) = CSD_INIT(ksw_watch_on_local_cpu, NULL);
+
 bool panic_on_catch;
 module_param(panic_on_catch, bool, 0644);
 MODULE_PARM_DESC(panic_on_catch, "panic immediately on corruption catch");
@@ -29,6 +36,94 @@ static void ksw_watch_handler(struct perf_event *bp,
 		panic("Stack corruption detected");
 }
 
+static void ksw_watch_on_local_cpu(void *data)
+{
+	struct perf_event *bp;
+	int cpu;
+	int ret;
+
+	preempt_disable();
+	cpu = raw_smp_processor_id();
+	bp = *per_cpu_ptr(watch_events, cpu);
+	if (!bp) {
+		preempt_enable();
+		return;
+	}
+
+	ret = modify_wide_hw_breakpoint_local(bp, &watch_attr);
+	preempt_enable();
+
+	if (ret) {
+		pr_err("failed to reinstall HWBP on CPU %d ret %d\n", cpu,
+		       ret);
+		return;
+	}
+
+	if (watch_attr.bp_addr == (unsigned long)&watch_holder) {
+		pr_debug("watch off CPU %d\n", cpu);
+	} else {
+		pr_debug("watch on CPU %d at 0x%llx (len %llu)\n", cpu,
+			 watch_attr.bp_addr, watch_attr.bp_len);
+	}
+}
+
+int ksw_watch_on(u64 watch_addr, u64 watch_len)
+{
+	unsigned long flags;
+	int cpu;
+	call_single_data_t *csd;
+
+	if (!watch_addr) {
+		pr_err("watch with invalid address\n");
+		return -EINVAL;
+	}
+
+	spin_lock_irqsave(&watch_lock, flags);
+
+	/*
+	 * enforce singleton watch:
+	 *   - if a watch is already active (bp_addr != &watch_holder),
+	 *   - and not asking to reset it   (watch_addr != &watch_holder)
+	 * then reject with -EBUSY.
+	 */
+	if (watch_attr.bp_addr != (unsigned long)&watch_holder &&
+	    watch_addr != (unsigned long)&watch_holder) {
+		spin_unlock_irqrestore(&watch_lock, flags);
+		return -EBUSY;
+	}
+
+	watch_attr.bp_addr = watch_addr;
+	watch_attr.bp_len = watch_len;
+
+	/* ensure watchpoint update is visible to other CPUs before IPI */
+	smp_wmb();
+
+	spin_unlock_irqrestore(&watch_lock, flags);
+
+	if (watch_addr == (unsigned long)&watch_holder)
+		pr_debug("watch off starting\n");
+	else
+		pr_debug("watch on starting\n");
+
+	cpus_read_lock();
+	for_each_online_cpu(cpu) {
+		if (cpu == raw_smp_processor_id()) {
+			ksw_watch_on_local_cpu(NULL);
+		} else {
+			csd = &per_cpu(watch_csd, cpu);
+			smp_call_function_single_async(cpu, csd);
+		}
+	}
+	cpus_read_unlock();
+
+	return 0;
+}
+
+void ksw_watch_off(void)
+{
+	ksw_watch_on((unsigned long)&watch_holder, sizeof(watch_holder));
+}
+
 int ksw_watch_init(void)
 {
 	int ret;
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910052335.1151048-8-wangjinchao600%40gmail.com.
