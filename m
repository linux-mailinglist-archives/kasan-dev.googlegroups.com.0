Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH5OW3XAKGQEKUXLBPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 752CDFCC8C
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:04:16 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id q1sf5930174ile.4
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:04:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573754655; cv=pass;
        d=google.com; s=arc-20160816;
        b=fifPvRsNo+GFoBxrPuuvCymM4/ex0C/KFz2rAjCXdR44PPyQKw6XmU2c35c4FDw1+6
         4anIIB9BwpdF2G59ezZ6zVxgrNUpPgC3Nl2NQTXQoRdNOnZkRZXUMXHvlOHHE+qM6Xls
         Fs7YWLW2SdmBgVDoTnXbLo66k/TYlkMS4Y8ykPoQAukIKdmH8ZdDDT3N/YrUBMOKy4qc
         CIEUXCgR/0hPl4BEjhO+4uOM91VHtSFwpgCTZ3uDrIN/Rk+++faYGa3tsyfy3fDEVNvu
         YyiGdDL87kODS6kxubcqX1CkJgCpDQWFm82uuWbzMeStbO8MfV74YgZTeUqpDDC8o7Ba
         XXqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=DWiZZv9V+QLIYbIWzYCcH4V2V6EP5PQ4z38ZY6rsT9Q=;
        b=csw39NyieOTgnSgVGuxiHP4cvGj7rXZKyTtHQQD6e6PK97osPvobHuHtwvHAWTsEV0
         bRiBAzp80yaSSkjQUhx6k5YlaeX+524V2CDP+h8r2tGKPeZB81Sf5Zv2XreHJ24lnwH3
         sZeqcjGwQ1EDuexRp1QsCApqOuuEjioU++nTCtFDcpzhIjLiBDavV93bscC5fPaHZdmb
         kjXvwUpnCluuZvUUHiJBzQ2S2DqwKKOe88/eeyiC4zyppWGOvBXETMxMKTViR242VNOl
         +UvkbO/zqVafCVVDbvF7XHTFTLTLJ6URLNuiRCZPTERCK3BTj1u0S78dm9Oh61seUPvS
         KjLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="IcRlS/dV";
       spf=pass (google.com: domain of 3hzfnxqukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3HZfNXQUKCXYYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DWiZZv9V+QLIYbIWzYCcH4V2V6EP5PQ4z38ZY6rsT9Q=;
        b=bi4Bfu2l0aZfWQohSR5t+1kJqH7G5gEpkfy2NNfE5rHiU1fotzWT7sR2oXBpZdF9lw
         ogGtDoHq+441OEOR4jyCqoW+CyYvrH1r1sMwCyH2qAhhcpWs/gADbHNc+Ws/7R5L7XaJ
         rfxI5DyS5lXLGN62WKPSC+Ilo40tFLgoGnlzaKnMo4uwWBGeN7U21ve5gsVRAFUD9/hp
         oqj3Rj9wqd0nm9kBZlOc3y14bs1ppVhOZoKZwpR1wrWVMG8JJmvv82uQMY8e/wwYoEtH
         ofKOiegw09pz7Wu4YT+lq0gUdEZjLHM5J4HX50cwMMrthlr9O15axERVK3IisO30VGbi
         Ubdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DWiZZv9V+QLIYbIWzYCcH4V2V6EP5PQ4z38ZY6rsT9Q=;
        b=sfK+jBa5kTkf2ADCZmqEARVBjtxMIf8Fx72ZIDBEI46dbRGzg2WLvkbKtdiq30Qfpk
         q9wOxgG3e01OxHyST7+Y5B4YXCmBnlK8T9/T5AdcZaMJyov1c1Flspk/wavU5VNTyDpC
         8dYPODD9kA+1plSRgXxxdgLw1zzi4uomIPW2+38dYDowHpL+0D5FPY3uea2jswZhEq9K
         4H3hzIbS2N/pUqFe6+3abRagYfq8hBfwty1v7N23JPI3b29wcB3KFn4QUeFMb09fSTD9
         7BJ0fezc3tACYWNJiR+Agc3Sl63R4wIQVtfFVt1hb1dDLVyTn89R7mNzE2Q0p8tKrnKU
         s8rw==
X-Gm-Message-State: APjAAAWCBebbJ9yJCd/F7nXLtcvzDB+jgk1+kvQRb02XXFZlM25RBnYn
	qFafPhOFCBoyrvl2BPbxkwg=
X-Google-Smtp-Source: APXvYqyEazUMDH8KB2WRiTPnJtwDRLfOZ0rgFnIzgtwnFCwiax/3nh/s3ES1cmEVZbZFiSlFT/sYUg==
X-Received: by 2002:a92:700f:: with SMTP id l15mr11408311ilc.121.1573754655130;
        Thu, 14 Nov 2019 10:04:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:4a07:: with SMTP id m7ls1289229ilf.16.gmail; Thu, 14 Nov
 2019 10:04:14 -0800 (PST)
X-Received: by 2002:a92:85:: with SMTP id 127mr11933892ila.118.1573754654725;
        Thu, 14 Nov 2019 10:04:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573754654; cv=none;
        d=google.com; s=arc-20160816;
        b=om5/FQQfMH7mJnMFQaanX36oQ6UmcKc7n2iiLSmS7DfryMldZGSaify7fQhBIEhiWN
         tLpeEm2zBAqgwjMSaQb8vj2uluO5N5yKqb7L4b4/FH+ihmkS7uy/Kadybed9GJmAB69B
         lDgWuKERdqSWdwbLZtO6qiPrXpaUtLloY2tSL6CAu3Guodd1HeOenAzCGEu4WaJqnoo4
         TRhvWPb4YQMmWmw5Zbtev5cw+9yCpF88USCsPlHIQRoqjbH6B7TELJcCj+8a/ZMTU4Tf
         G3ZcZC6GW6jB8tASnIXIsN1RhBKcR6S/35RCf6DEWzkEuNhtu/Zixe2OvXu5zVT6bJrG
         +YLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=96xEs+lJYo0V1womdbdeC7cnwgPWDGKGu93eR6OWopc=;
        b=oEqeA2/8P2qaMvjuiGlA6fAEW4fyp3GClLIiv5TGHcv4Gms6uHTvXrCaOKKJ4ErYMj
         iYfE5jABVDY6YZVgSbmeLUA099O1uvFcvtexfQSvoDVYclTQ/jOlUH9r+OXPXHi8ygV7
         M98vrd89ge/ESewxewlc0idl8MxXEBt3d+2c9poPdIJ2DnJ5S2Yk2JJxEPy8evFtPqAM
         CDEvDcNyEz75gtX+0XjQb+z5mvu/wpXC4c47A4dw3LLbO1SaMOI6TfJP4ShttQc+mYkP
         9nOf5XTYGd0SCz8ndGa/8UXHpYhMhYPpVYb5kTAXbmn83Ahp0TNf21kGun1oZ5pm5YVu
         g0qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="IcRlS/dV";
       spf=pass (google.com: domain of 3hzfnxqukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3HZfNXQUKCXYYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id z78si401812ilj.5.2019.11.14.10.04.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:04:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hzfnxqukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id b15so4651219qvw.6
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 10:04:14 -0800 (PST)
X-Received: by 2002:aed:2cc5:: with SMTP id g63mr9497984qtd.205.1573754653698;
 Thu, 14 Nov 2019 10:04:13 -0800 (PST)
Date: Thu, 14 Nov 2019 19:02:58 +0100
In-Reply-To: <20191114180303.66955-1-elver@google.com>
Message-Id: <20191114180303.66955-6-elver@google.com>
Mime-Version: 1.0
References: <20191114180303.66955-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v4 05/10] build, kcsan: Add KCSAN build exceptions
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, edumazet@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-efi@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="IcRlS/dV";       spf=pass
 (google.com: domain of 3hzfnxqukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3HZfNXQUKCXYYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This blacklists several compilation units from KCSAN. See the respective
inline comments for the reasoning.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Paul E. McKenney <paulmck@kernel.org>
---
v3:
* Moved EFI stub build exception hunk from x86-specific patch, since
  it's not x86-specific.
* Spelling "data-race" -> "data race".
---
 drivers/firmware/efi/libstub/Makefile | 2 ++
 kernel/Makefile                       | 5 +++++
 kernel/sched/Makefile                 | 6 ++++++
 mm/Makefile                           | 8 ++++++++
 4 files changed, 21 insertions(+)

diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index ee0661ddb25b..5d0a645c0de8 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -31,7 +31,9 @@ KBUILD_CFLAGS			:= $(cflags-y) -DDISABLE_BRANCH_PROFILING \
 				   -D__DISABLE_EXPORTS
 
 GCOV_PROFILE			:= n
+# Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 UBSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
diff --git a/kernel/Makefile b/kernel/Makefile
index 74ab46e2ebd1..cc53f7c25446 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -23,6 +23,9 @@ endif
 # Prevents flicker of uninteresting __do_softirq()/__local_bh_disable_ip()
 # in coverage traces.
 KCOV_INSTRUMENT_softirq.o := n
+# Avoid KCSAN instrumentation in softirq ("No shared variables, all the data
+# are CPU local" => assume no data races), to reduce overhead in interrupts.
+KCSAN_SANITIZE_softirq.o = n
 # These are called from save_stack_trace() on slub debug path,
 # and produce insane amounts of uninteresting coverage.
 KCOV_INSTRUMENT_module.o := n
@@ -30,6 +33,7 @@ KCOV_INSTRUMENT_extable.o := n
 # Don't self-instrument.
 KCOV_INSTRUMENT_kcov.o := n
 KASAN_SANITIZE_kcov.o := n
+KCSAN_SANITIZE_kcov.o := n
 CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 
 # cond_syscall is currently not LTO compatible
@@ -118,6 +122,7 @@ obj-$(CONFIG_RSEQ) += rseq.o
 
 obj-$(CONFIG_GCC_PLUGIN_STACKLEAK) += stackleak.o
 KASAN_SANITIZE_stackleak.o := n
+KCSAN_SANITIZE_stackleak.o := n
 KCOV_INSTRUMENT_stackleak.o := n
 
 $(obj)/configs.o: $(obj)/config_data.gz
diff --git a/kernel/sched/Makefile b/kernel/sched/Makefile
index 21fb5a5662b5..e9307a9c54e7 100644
--- a/kernel/sched/Makefile
+++ b/kernel/sched/Makefile
@@ -7,6 +7,12 @@ endif
 # that is not a function of syscall inputs. E.g. involuntary context switches.
 KCOV_INSTRUMENT := n
 
+# There are numerous races here, however, most of them due to plain accesses.
+# This would make it even harder for syzbot to find reproducers, because these
+# bugs trigger without specific input. Disable by default, but should re-enable
+# eventually.
+KCSAN_SANITIZE := n
+
 ifneq ($(CONFIG_SCHED_OMIT_FRAME_POINTER),y)
 # According to Alan Modra <alan@linuxcare.com.au>, the -fno-omit-frame-pointer is
 # needed for x86 only.  Why this used to be enabled for all architectures is beyond
diff --git a/mm/Makefile b/mm/Makefile
index d996846697ef..56c1964bb3a1 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -7,6 +7,14 @@ KASAN_SANITIZE_slab_common.o := n
 KASAN_SANITIZE_slab.o := n
 KASAN_SANITIZE_slub.o := n
 
+# These produce frequent data race reports: most of them are due to races on
+# the same word but accesses to different bits of that word. Re-enable KCSAN
+# for these when we have more consensus on what to do about them.
+KCSAN_SANITIZE_slab_common.o := n
+KCSAN_SANITIZE_slab.o := n
+KCSAN_SANITIZE_slub.o := n
+KCSAN_SANITIZE_page_alloc.o := n
+
 # These files are disabled because they produce non-interesting and/or
 # flaky coverage that is not a function of syscall inputs. E.g. slab is out of
 # free pages, or a task is migrated between nodes.
-- 
2.24.0.rc1.363.gb1bccd3e3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114180303.66955-6-elver%40google.com.
