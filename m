Return-Path: <kasan-dev+bncBD53XBUFWQDBBLEXQTDAMGQEYL4RXMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 504B8B50D21
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:25:05 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-329b1e1d908sf2621026fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:25:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757481901; cv=pass;
        d=google.com; s=arc-20240605;
        b=XpHUdTa5L4XCHmE1uDx5LcqXzOo4me7bDcrtl3oSb8pbGnesNqtFK84wBB1NWTyvaH
         A8tDkJj6WWEpOqLbRhItoDLIuAA3c01RbtGszyUxeZQ7l8j7yG3Mj03GuMAuHu6M387k
         gX3sTwLtG4YsgRsoRsrrY92uVKoAFRVys2FLd8MCVMrfhCvS7Uer35ABp9AzUl01FfcK
         O7e4e7RQ/lNx9AzpaLL/Omc3qaNpGPGPJACSpbHTU7rbo06Q66xXR7bl2kBzlWukRXHT
         8fnTi+yHTJvrRy9G5nwJ31DyeveJ1dvdOpbAtgkXYRfDjKzSuOpBAHxzhuKysgnomvX1
         A7SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=oRxVExxBC3id0tNxxVBC4bFVpWD4UpnJ7aAiIUo35mk=;
        fh=tOQDwVWKWOMhZGP0RubCl3B7ZBqjOi07r/BQQhMYnGQ=;
        b=RgHpZclRBYLMBN+kdl8kYtrT1Su+CMxIHEDfENcu+9zdFJPg4j6pasbuAx94YdwKLZ
         H/tFtfYAou/B1Vc2sHXooNbgopeKYMaPQPnXtYbrshGJnFX7qKaUEeaGNSgQ09YwmZgh
         Fip3Ie6dsvQGupArCSnoSstaONhx4SKxKldYuvfEWzncgdQoeR3yPw0jkVQVZmMq8r09
         YceYTUC0oDSi8BkTVbuHWLyE+PRN6bgrpcebSoV3lI1tdgicx0naiRFUVk9zx83pW/KF
         l2TDciy7cpMBeWDF+5n+Ay1PGAIHEYBG/gKtjH/ajnqkZtC+kIook7wl40yCjNXq+C/g
         pgOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S8PoEzUd;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757481901; x=1758086701; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oRxVExxBC3id0tNxxVBC4bFVpWD4UpnJ7aAiIUo35mk=;
        b=Un42Q4esU8XHCXXcJI7yqLU+6dF8oc0ZEixCpXxAJdPJB6pNP7xzfZOiurTAJ8FXsO
         V1VLxwKiPNBnDtugF2xf073vI5GcZiS8gwPhKTWw3XNJnB8J4TcDiYIxHzVhHfQjNjPq
         b7FC63rv6c6jvsS0AOVHjXUSZiEi+kiFCjbhz/ZBkJasXnesmxtFxlDHqVfgWPzI/UW8
         IcwsmuCq1RMU33x3BR4Hsd/tsZH9IO0UaqXrIGrd5TncBI9aeIkMN9JycThQvI869Jzn
         BqZlIFMQhb4EduiiL7BzTnqhekQvidDIAkbfUEBwJ6LE6B3dfzBOXcyYoc4kgN0NT51X
         mlhA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757481901; x=1758086701; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=oRxVExxBC3id0tNxxVBC4bFVpWD4UpnJ7aAiIUo35mk=;
        b=ZjDCROxrrTsgUMULgOArcEMV4WI5QNmvup1yROaZ+T9LsuRnyD26DHCWa+wwn4S8oc
         7J58TuTfmnKZxj/QYVb2cHz0xoqgGvj+xbQFP0kc+bFu98+9ofTYj98MXrXxu9ELjS0y
         acpiLY84QjbvfJbJAazEZmi6sT+5kOIHlrUxwOw2nUCg40VSdAfxj1+Pe6LHbTsrVPNn
         N2K5COnyRsRACoSfjjyswNSNGxvHCP4yIjppxfVcN7xSzAv2pO2RDvqSf5Nja43hJoSF
         uJxh2GzvF4gKCIBrl+Q8fX81D6UHLY4Nv1a7qEZ8AZlYEXT+cch94mzIgWeSzDuTJ90i
         BdFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757481901; x=1758086701;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oRxVExxBC3id0tNxxVBC4bFVpWD4UpnJ7aAiIUo35mk=;
        b=lmm/RKSxTN65ftOPrjVgf7QKM42FqwBveFFZrwdkOfoJkxwYrg3XF4Hkrbfsgb4cwm
         YGjE7fMl+jBkpu/R9rrOjB4l9J8LqJqkDYUQY8lf1QtcdNqy/uKf15j09XwWH1VT9UFt
         /Aw1jmBfr8vyhttlqqRsQekJNdw83P0iQEIec7lpNaxfkyDMqLJqh532vmew/f53rjbV
         uLmvm13sm8N+Jv9BYF5CDxUISNwhbqiRVq/QjOxLrDbK9pq2AypFfyzkn63Dmj5+vd10
         GEdwoQAtksHV6Syoh+gCoKUEN1IgesJBV1YKlrjf+tQ+jbgmlTJXlhOYHqhm2mn3wfeu
         lctA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXQ2HDe6aDI/zWWR+wAHYMNloIfWkJIDx+wpCovP12x1IRa08qCdv8vWmqWwRDIzIvwWrmlUg==@lfdr.de
X-Gm-Message-State: AOJu0Yybth6WLY1jCOLtZluNqGB4rF+KxwmOGLsQ2GmO2KhP2YboXtqN
	tqEds1N4Zoa1Ku3u44rEV3Rcv2smwj2qZEgPWu/JmfRKwcuj3ptZJgp0
X-Google-Smtp-Source: AGHT+IGQUiZTwNui6TJ0OJzMURgDqk+ZBE4xor7AX/azeA20bxoqLg2Mt0Cq5fESvFJzMA4VOB+40A==
X-Received: by 2002:a05:6871:3143:b0:30c:92a1:64e6 with SMTP id 586e51a60fabf-322652368b0mr5972520fac.42.1757481900882;
        Tue, 09 Sep 2025 22:25:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6jnYBg0A9vdNbS5T47kGbMd4dwn6uWwLOpjKa7IGMNWQ==
Received: by 2002:a05:6871:c711:b0:319:c528:28df with SMTP id
 586e51a60fabf-321271cc521ls2867335fac.1.-pod-prod-08-us; Tue, 09 Sep 2025
 22:25:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVdrYEnPp7rBJzSp7opjLYDCgm+0VKiy3h4YB45Q/u5+SCVCZFpk81V6ZVtykmK07L8dAAzS3LPsgI=@googlegroups.com
X-Received: by 2002:a05:6871:3143:b0:30c:92a1:64e6 with SMTP id 586e51a60fabf-322652368b0mr5972511fac.42.1757481900009;
        Tue, 09 Sep 2025 22:25:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757481899; cv=none;
        d=google.com; s=arc-20240605;
        b=ZW59VBmo7FNA+qvhcid+CRaQJRmWh1YsOGZbGYNf8rsR11Gdw+SmTsKOvHOhxAcTBj
         JIW5bakqZMWbRBg+a/VRbOBpEIOhE5cUR9bj58AUMaGhKhSD3DO65F0dBDdEnHIrdhGU
         CVQxblSEy0Y0Lk0w1RIZZF0Xf4ohVF68P8HbHvwOSPpsKceU2xy46r3XSQWA+OJkkOs/
         VTodOeKLgg3FZXv4DhB61PscmxPL2nUZy/fSe1TXgDeKNnELO1FeSe5DGFE7GwF7wylR
         KZRNQgz9Z3Oy4V1cBjdXqv5TYzeL3kcIQmempS/xXsVvJYO/0J84udGnPJQKHT63n8lT
         mTUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AHbowSqCEXMKo5URxnvlReujWCnQ6OEftSHn5bkAAuU=;
        fh=rdYC7Tr0pkBHbYb+vZIe5ErLTRoSSFH6j3SyePr2qC4=;
        b=JuVxc9xwlBkBFXxowOsiY0SUV2chtxxv1tFVpCasjDe2vWPzG3faPLixLp1tQGfA5c
         e9+rfJsPv4q/bIaLEFNy7nWDWmD3Wnkb49f5zBoenlFnQN7Llezlu3Y0XpUUBuGQgR49
         OjADmH5MeT4plHxnuhKKX/Jg9zd3gC8kmm6NRqNASGwKUxRaIVu1K+enPNQqXH3Zewx4
         KVuMp5cy0dxHNfb8vfLsmevZNWV5Lzu4UPkjOwtnehr8HWzB73pnELJ1oSyyAJbTDdMc
         kJ5GKI6nHto9Wf8n96BUzXPzk2IZu06YPwULWOy0e78wZYzhu799xMpxVRERUfxW4VmD
         gssQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S8PoEzUd;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-31d895ec2c8si641581fac.4.2025.09.09.22.24.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:24:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id 41be03b00d2f7-b4c72885c8bso5309422a12.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:24:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWxwm2sRzZCRoZ9pKx9ICSRgigLyHNm0PBuWQiyKwemC/5VmXqBdvZkfKBxoi28m5oM784mCQfh028=@googlegroups.com
X-Gm-Gg: ASbGncsQqEbRUl2wKWQ8WLy6s8vhVAX95L2svL/zkej3a10gDxujXpNNjhWKNytZZEK
	syJhzd+GUtTZyMip9uGP5cVKNw9XP6mj0PrM/BPASlZtyB/kib5slFveTOGYGMKLu/fVuaUwTYF
	MK8gmo8jkrxBAI0WbrWxMWrzHhuEXxq1IJdhSOjMj2MneFQbDr+6ZLw2g00bq1xi5PzqYuBnBIS
	FerwVxnbuP+4TW3Y86x+FFVRU3PcMwTSrXzpT2QvwjD74ALNP8wgXu4Uol4uVnnntDqfJPWHUNG
	VT15D6xgaOQmNV2lPqstKIQ8LLQdBsY8GKLu5irKTQVjwHqzJDWshWh54mZqOIDDXX0pHnOEmrn
	9Q0JQdmp6/HqeQZX/kq4A/P7KayiyPEzKSQ==
X-Received: by 2002:a17:903:22d1:b0:252:fa17:bc95 with SMTP id d9443c01a7336-252fa17c03cmr200824935ad.48.1757481899190;
        Tue, 09 Sep 2025 22:24:59 -0700 (PDT)
Received: from localhost.localdomain ([2403:2c80:17::10:4007])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25a27422ebcsm14815125ad.29.2025.09.09.22.24.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:24:58 -0700 (PDT)
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
Subject: [PATCH v3 03/19] mm/ksw: add build system support
Date: Wed, 10 Sep 2025 13:23:12 +0800
Message-ID: <20250910052335.1151048-4-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910052335.1151048-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=S8PoEzUd;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add Kconfig and Makefile infrastructure.

The implementation is located under `mm/kstackwatch/`.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/Kconfig.debug             | 11 +++++++++++
 mm/Makefile                  |  1 +
 mm/kstackwatch/Makefile      |  2 ++
 mm/kstackwatch/kernel.c      | 22 ++++++++++++++++++++++
 mm/kstackwatch/kstackwatch.h |  5 +++++
 mm/kstackwatch/stack.c       |  1 +
 mm/kstackwatch/watch.c       |  1 +
 7 files changed, 43 insertions(+)
 create mode 100644 mm/kstackwatch/Makefile
 create mode 100644 mm/kstackwatch/kernel.c
 create mode 100644 mm/kstackwatch/kstackwatch.h
 create mode 100644 mm/kstackwatch/stack.c
 create mode 100644 mm/kstackwatch/watch.c

diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index 32b65073d0cc..fdfc6e6d0dec 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -309,3 +309,14 @@ config PER_VMA_LOCK_STATS
 	  overhead in the page fault path.
 
 	  If in doubt, say N.
+
+config KSTACK_WATCH
+	tristate "Kernel Stack Watch"
+	depends on HAVE_HW_BREAKPOINT && KPROBES && FPROBE
+	select HAVE_REINSTALL_HW_BREAKPOINT
+	help
+	  A lightweight real-time debugging tool to detect stack corruption.
+	  It can watch either the canary or local variable and tracks
+	  the recursive depth of the monitored function.
+
+	  If unsure, say N.
diff --git a/mm/Makefile b/mm/Makefile
index ef54aa615d9d..665c9f2bf987 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -92,6 +92,7 @@ obj-$(CONFIG_PAGE_POISONING) += page_poison.o
 obj-$(CONFIG_KASAN)	+= kasan/
 obj-$(CONFIG_KFENCE) += kfence/
 obj-$(CONFIG_KMSAN)	+= kmsan/
+obj-$(CONFIG_KSTACK_WATCH)	+= kstackwatch/
 obj-$(CONFIG_FAILSLAB) += failslab.o
 obj-$(CONFIG_FAIL_PAGE_ALLOC) += fail_page_alloc.o
 obj-$(CONFIG_MEMTEST)		+= memtest.o
diff --git a/mm/kstackwatch/Makefile b/mm/kstackwatch/Makefile
new file mode 100644
index 000000000000..84a46cb9a766
--- /dev/null
+++ b/mm/kstackwatch/Makefile
@@ -0,0 +1,2 @@
+obj-$(CONFIG_KSTACK_WATCH)	+= kstackwatch.o
+kstackwatch-y := kernel.o stack.o watch.o
diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
new file mode 100644
index 000000000000..40aa7e9ff513
--- /dev/null
+++ b/mm/kstackwatch/kernel.c
@@ -0,0 +1,22 @@
+// SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/module.h>
+
+MODULE_AUTHOR("Jinchao Wang");
+MODULE_DESCRIPTION("Kernel Stack Watch");
+MODULE_LICENSE("GPL");
+
+static int __init kstackwatch_init(void)
+{
+	pr_info("module loaded\n");
+	return 0;
+}
+
+static void __exit kstackwatch_exit(void)
+{
+	pr_info("module unloaded\n");
+}
+
+module_init(kstackwatch_init);
+module_exit(kstackwatch_exit);
diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
new file mode 100644
index 000000000000..0273ef478a26
--- /dev/null
+++ b/mm/kstackwatch/kstackwatch.h
@@ -0,0 +1,5 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _KSTACKWATCH_H
+#define _KSTACKWATCH_H
+
+#endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
new file mode 100644
index 000000000000..cec594032515
--- /dev/null
+++ b/mm/kstackwatch/stack.c
@@ -0,0 +1 @@
+// SPDX-License-Identifier: GPL-2.0
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
new file mode 100644
index 000000000000..cec594032515
--- /dev/null
+++ b/mm/kstackwatch/watch.c
@@ -0,0 +1 @@
+// SPDX-License-Identifier: GPL-2.0
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910052335.1151048-4-wangjinchao600%40gmail.com.
