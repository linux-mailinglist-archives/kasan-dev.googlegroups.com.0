Return-Path: <kasan-dev+bncBD53XBUFWQDBBIMXQTDAMGQEEHUGQCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id B34F6B50D1F
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:25:04 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-718cb6230afsf136788086d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:25:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757481890; cv=pass;
        d=google.com; s=arc-20240605;
        b=fdfkVlFZ3uWlGLu9tyHwDpv3hjtVxewC7aLcZ6qqbPXTZrE2Q7JGZgs+EXeMCLBnZ/
         M6fQU82M0z6m3YVFpHlwcHLH2gR0uMErEGrz6P1ur2BxXAf/7m4qXjx1vXmWPvvgLT/Z
         7LqJ3V9M9ANtq9wplSEiHHWkKN4M0kJh5Y1u6itu44mFVFPzGw6LFHAkw+SpWDw1ZJvm
         OLVdc+cSNXkzP+vXzbPbDLKGLTeZLeJ82gsfdIBU7HqEgYxG6jIRQWqJysTq7q6sRkmw
         IufTxAdECYwQA7u3KsPwEJvJmEfmFXuYMqv2owAC9bHm4D8LKVZJueOkhuIdOGWyJXu8
         gJcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=iH++5p4r4/UjfS1B8oznQcpZsNyMGgj0jp/Iiv18nyM=;
        fh=YGbHAaSLDHE9e78KHmjk9GaoUmln3tpA4iksNNXtH9A=;
        b=WpSL5idrEmkIbRaTipeA+qH+rok/xfnBT0vEyNg5wCV2dvBZ4yZPZOS7qzCgx/TQS3
         URFpdR70kpB0BpnvPhdeRNBTnHyios25lkapvEwTntteLL2iAnNyweC2xHnmDaX+C3n+
         EyU7e0l+Vt5eiPB/bUQPD/ojYa1lLVZ5ZiRK2Ou6hwnpFKpA/znfGTk0xG4S/UQ4MjnW
         /qqQh9OVyFInpbdFupyjRn2QmBzqGpNF3DYiz8WpFy3Rtb0DYwymY170w39e9WG+v88A
         jXi+doMvFRPuZGTdL6evYD35Iu/3vp8rmAFdyz34UWaZulbPJRtDLGN8sA2zmvYPNFiq
         F2mQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IO9lKn3K;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757481890; x=1758086690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iH++5p4r4/UjfS1B8oznQcpZsNyMGgj0jp/Iiv18nyM=;
        b=pc8GDoab0jqRV+qIDkPI6D7d//a0B1mDpn1tVCd0ZLzFQEHQQTJIpGlJwc2PymDrgk
         igDrSWqHqxqAaRHCDBsakiQqsuqArLUQUqn2hvgNldXYZUnW/Z2b1ch8K18qVXtpuWcJ
         nps26oMFi89M382mfK4OF03tyEC3aG2ZqDibCgff9K8Edo7kjrvdmBfnr1vdlYhwvHQP
         i94BFIhr+wQkkpThFfG4hELfktRhasqyyrYhvfCv068cELcPpeg20KNp4yN7cLbA5Ehn
         UXvc9ESvO6jqy5JqcI2Xl21sDT9vtuV7Qdz2OaTKfTsUYydeL3XTwbNZECvXa39Y3DqY
         coOg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757481890; x=1758086690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=iH++5p4r4/UjfS1B8oznQcpZsNyMGgj0jp/Iiv18nyM=;
        b=g3k+iK7AdEo1F6SJ2UcaXx+60Tg+K9pN5W445STqxMERYLaeo7pvHzm7+fql7jwCwO
         iInGnc0Qru+K6UGVf2o7+utWSKXlWdt1KPx1W1uWjT/XrG4iNL6GYnruicnox6IvROVV
         54Kih2jBKiSyqwqJyaXUyDx8N1fu3WqBQO3Td8Ck0R0L+/EYHfv0Mf3zK85F53ye9py6
         Q8xieTox6yvQumeWnrHXs1e4yFm8cfUv82vmSV+m87AqKIbLa3JydTaMarlCY0zYlb2U
         iYSRjHg0HtD6O6pDa/n11pMZKaUPhOyZPj3y89AduvekueEC52nFKYsJ5eJT99x0FKDz
         ARqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757481890; x=1758086690;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iH++5p4r4/UjfS1B8oznQcpZsNyMGgj0jp/Iiv18nyM=;
        b=a/O+6JxXcTHxn1dZZge0ZPRVEJ4PlshmsGdjaBiVmBCDEZ3U1qcZBYuc1nZPqwWqTZ
         jxUblM3PdvEi7b1+jpwDScQHJQuSgAKiEGWcLBnTxJEpQRrfH5J5SdbaBCuF+DeKernL
         my5f4rNAe6fRqzZaSFlTGpoIzckrUWK41QyW7rvG79WFiFb0Npp3bu+DvPlLYuvewv8+
         2ej9krewD+1m3oUwYkK8SQfb5HXp2oUArfDZCip9fmvFy0hRN/E3d8yJckyDUhFiAEUI
         PjEdoj3WxVkmc5xVUwi2cgUxw8c9+OW7hzTpP7E+qZ2o1drQPqJ7Cx72gtHWMqpdf157
         cVlw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWPrUfasDl4QjYyLS9Wawncwa1KPKX0aoY8PT7AnHbprNiVpk+5Z5xiQF2WNVzg74rSFrZ//A==@lfdr.de
X-Gm-Message-State: AOJu0YzQ7J5ORMbkqeTMOkl6RivJ0z1BvR6HuYZ3CwGYf90Xa63W6wgB
	2nKA5DfUqdLnbtpwHR85JtPmmspj+HY1TwzGki9aLcJ+1lop4X6AXgY8
X-Google-Smtp-Source: AGHT+IElPKw/g2XRExPm3Xe4jFy/TNsIVDQtHTPA4xoLhWx12RqRjfbWWWGx9DhZckkEidrI7XT0TA==
X-Received: by 2002:a05:6214:5193:b0:70d:fe0e:68ec with SMTP id 6a1803df08f44-73941de39cdmr174316136d6.54.1757481890287;
        Tue, 09 Sep 2025 22:24:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5yh1mE0E/5YYFYQ9aS1Ju4/EFRIalD30nCtltOQLGsYg==
Received: by 2002:a05:6214:c4b:b0:725:7cef:3097 with SMTP id
 6a1803df08f44-72d1a69be1els70261336d6.0.-pod-prod-03-us; Tue, 09 Sep 2025
 22:24:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVxuKeHlu6DpdeaxMGK7Rcxx9+RENfBKXUemgQMBNnRUZdKia5+WD1na+7kmvqsoZWrgqaSaPL/wQM=@googlegroups.com
X-Received: by 2002:a05:6102:1608:b0:524:2917:61a9 with SMTP id ada2fe7eead31-53d16b671d1mr3921326137.34.1757481889170;
        Tue, 09 Sep 2025 22:24:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757481889; cv=none;
        d=google.com; s=arc-20240605;
        b=chsYra2KCDJd1iTMdeQpjAyYPztmt83gKStbmZhOBi0yMl4GkH4qAma7M0PO6CRecz
         UVtkjon6lvqexO9Wuz4hWr0almNZy1Wnsbz+/Lkg2b5e8nuc5hP3Gm+v5V3uFe9H2YiI
         +oJCag7T+cG+/clyZYVjpxCFNfV8n/LTiUmg/cBaErdRHisSRWAUQ5chpYndfpM/uW48
         SLcEdn5PT4zVBtqvJyLX7sO+jIBkcVeRyoV0GPJCOGsbae9Waz3TTPPa+Hxhgih7C4HS
         S+c4L2BAgqwDPqxAzWkiaZX8NuU4rV+R5CSd254SDcrw9EnLOew0NTf/6vdvBNquaY75
         XlQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MAwazreHf5k9GgDRW54pld4eDw+UAZx9M09yt/sAPVs=;
        fh=Zn8R3ghAxb6M0cSF0meRbiDrFsBWQjLqT5xKeb14VM8=;
        b=L+CpSg31N9ZyzQqlTGZ2NDZaNQ9GkkcpBH3T96b22olv1s525p8HzHNjJ96FoPhipD
         XaXnHuGa+mYVYS2M0yIGSCxAhYchsFbNSuvj+1f8JBVnXN2FeOTLQsZuPdBHIJsjrg9i
         yPBOeciMmz2y7MPWdoQMXpeo2W5k0+oC8CZpd0GmZgaCKK8f0jOhiimjoVQ+Edznn75N
         z1BNRfH+CjU5R2ENzHw8Zs8i0qCc1KI7CBFS9FTwW6pHixijVzi1UiyhVEaNc7Pu16wF
         JdUSRu0slvX2b/mV52IS1qu/M8DMkcT7v4V5LS5JMq2uhxtDvnribtfpRNlO7y96+dtE
         bXPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IO9lKn3K;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-544910f5312si1335256e0c.0.2025.09.09.22.24.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:24:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-24c786130feso55562055ad.2
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:24:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXP6FnhkaEGCfCXrGvlr2+xjpzDDWlZ7cbjh5L4ylnrNTbYpI1ZUXemw26HQu6wAMAPB8dQvs0C9Ck=@googlegroups.com
X-Gm-Gg: ASbGnctspD9jc1hwfPl5+5roAeWU/geo9HY1nL4Ly92+eP2YpAFovUNRA8PLrVvyi0F
	O0BAFAh4Mr8Necvgy1xDcgp/5oZ42RievjA+v+J0wZSib8MI0CD1PhcKUTbkvTprvmJpK4XA744
	+mMOsPew+NAPJlGCSnNAytV/88g7WKkLWbAkqDJ62ux7EA2kTHcz6LKF9SdBgfaN5Iinh3gR6zi
	duevyzl26OhHtCBmVtHfqnlNKc6wCSJyhdZzGkEcqVUs/YHV8Vi50dw+njOZFj2F0qRtENl9lAy
	YWSXRiqDsC5N7aXkEG2YnD7gp+dRlKJYJbMc3YuTtvkX9DBInoveAqUtTdGSAG/8QCB9Nrigtrt
	8X/fjFtO8jzxROtkVEJyz1V6Gmgq6cF72a+UXrxg3Yo5N
X-Received: by 2002:a17:902:ef0c:b0:24a:f79e:e5eb with SMTP id d9443c01a7336-25173118f06mr198312495ad.49.1757481888337;
        Tue, 09 Sep 2025 22:24:48 -0700 (PDT)
Received: from localhost.localdomain ([2403:2c80:17::10:4007])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25a27422ebcsm14815125ad.29.2025.09.09.22.24.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:24:47 -0700 (PDT)
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
Subject: [PATCH v3 02/19] HWBP: Add modify_wide_hw_breakpoint_local() API
Date: Wed, 10 Sep 2025 13:23:11 +0800
Message-ID: <20250910052335.1151048-3-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910052335.1151048-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=IO9lKn3K;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

From: "Masami Hiramatsu (Google)" <mhiramat@kernel.org>

Add modify_wide_hw_breakpoint_local() arch-wide interface which allows
hwbp users to update watch address on-line. This is available if the
arch supports CONFIG_HAVE_REINSTALL_HW_BREAKPOINT.
Note that this allows to change the type only for compatible types,
because it does not release and reserve the hwbp slot based on type.
For instance, you can not change HW_BREAKPOINT_W to HW_BREAKPOINT_X.

Signed-off-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>
---
 arch/Kconfig                  | 10 ++++++++++
 arch/x86/Kconfig              |  1 +
 include/linux/hw_breakpoint.h |  6 ++++++
 kernel/events/hw_breakpoint.c | 36 +++++++++++++++++++++++++++++++++++
 4 files changed, 53 insertions(+)

diff --git a/arch/Kconfig b/arch/Kconfig
index d1b4ffd6e085..e4787fc814df 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -418,6 +418,16 @@ config HAVE_MIXED_BREAKPOINTS_REGS
 	  Select this option if your arch implements breakpoints under the
 	  latter fashion.
 
+config HAVE_REINSTALL_HW_BREAKPOINT
+	bool
+	depends on HAVE_HW_BREAKPOINT
+	help
+	  Depending on the arch implementation of hardware breakpoints,
+	  some of them are able to update the breakpoint configuration
+	  without release and reserve the hardware breakpoint register.
+	  What configuration is able to update depends on hardware and
+	  software implementation.
+
 config HAVE_USER_RETURN_NOTIFIER
 	bool
 
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 58d890fe2100..49d4ce2af94c 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -247,6 +247,7 @@ config X86
 	select HAVE_FUNCTION_TRACER
 	select HAVE_GCC_PLUGINS
 	select HAVE_HW_BREAKPOINT
+	select HAVE_REINSTALL_HW_BREAKPOINT
 	select HAVE_IOREMAP_PROT
 	select HAVE_IRQ_EXIT_ON_IRQ_STACK	if X86_64
 	select HAVE_IRQ_TIME_ACCOUNTING
diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
index db199d653dd1..ea373f2587f8 100644
--- a/include/linux/hw_breakpoint.h
+++ b/include/linux/hw_breakpoint.h
@@ -81,6 +81,9 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
 			    perf_overflow_handler_t triggered,
 			    void *context);
 
+extern int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+					   struct perf_event_attr *attr);
+
 extern int register_perf_hw_breakpoint(struct perf_event *bp);
 extern void unregister_hw_breakpoint(struct perf_event *bp);
 extern void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events);
@@ -124,6 +127,9 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
 			    perf_overflow_handler_t triggered,
 			    void *context)		{ return NULL; }
 static inline int
+modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				struct perf_event_attr *attr) { return -ENOSYS; }
+static inline int
 register_perf_hw_breakpoint(struct perf_event *bp)	{ return -ENOSYS; }
 static inline void unregister_hw_breakpoint(struct perf_event *bp)	{ }
 static inline void
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 8ec2cb688903..ef9bab968b2c 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -887,6 +887,42 @@ void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)
 }
 EXPORT_SYMBOL_GPL(unregister_wide_hw_breakpoint);
 
+/**
+ * modify_wide_hw_breakpoint_local - update breakpoint config for local cpu
+ * @bp: the hwbp perf event for this cpu
+ * @attr: the new attribute for @bp
+ *
+ * This does not release and reserve the slot of HWBP, just reuse the current
+ * slot on local CPU. So the users must update the other CPUs by themselves.
+ * Also, since this does not release/reserve the slot, this can not change the
+ * type to incompatible type of the HWBP.
+ * Return err if attr is invalid or the cpu fails to update debug register
+ * for new @attr.
+ */
+#ifdef CONFIG_HAVE_REINSTALL_HW_BREAKPOINT
+int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				    struct perf_event_attr *attr)
+{
+	int ret;
+
+	if (find_slot_idx(bp->attr.bp_type) != find_slot_idx(attr->bp_type))
+		return -EINVAL;
+
+	ret = hw_breakpoint_arch_parse(bp, attr, counter_arch_bp(bp));
+	if (ret)
+		return ret;
+
+	return arch_reinstall_hw_breakpoint(bp);
+}
+#else
+int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				    struct perf_event_attr *attr)
+{
+	return -EOPNOTSUPP;
+}
+#endif
+EXPORT_SYMBOL_GPL(modify_wide_hw_breakpoint_local);
+
 /**
  * hw_breakpoint_is_used - check if breakpoints are currently used
  *
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910052335.1151048-3-wangjinchao600%40gmail.com.
