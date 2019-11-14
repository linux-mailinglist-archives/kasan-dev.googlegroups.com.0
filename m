Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG5OW3XAKGQEEOXRXHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 71E9FFCC84
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:04:12 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id l12sf853497ljg.21
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:04:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573754652; cv=pass;
        d=google.com; s=arc-20160816;
        b=1IIR4ItRINV6fTrhgm1kUybgUfKgSKePpNSBdtbOvFkYjyYQ1tAsui5pO0WWkQTLKB
         6NEkTiAYPeF3E5kp5Q9H8P0H7R0FuSG9Hv2b82P/PZ/94gSZqqAw5C1ffEuOpn2tgxN8
         r1rH65yWM5twP5CM1FFqXRqeoLIOHptcoYZCRSvS9ua/IGtDi3Q40uYItiikMfN8cMSW
         BVfKOMBMkREVKTunWe6ifrYOZn/8XwcP/aLK3sD0iac84ZFbmpRzJUOArd8fZWyvpWKm
         F3dpXvKAft2OBCp1wOzDAcSylpNXmPBaePcvJg4scR7eMUBoINJz9QiHxtxdOPLoJqkR
         eNfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ywG//Eew4BtKyITdjSxwZCaJFuJ8pivL+RbYQlBxzRs=;
        b=0NvosAvLnd98cG1v4/7L1HHiXWUNpZ0pvtzvd1aPXm1ReefaKQIYBSxHhjQiFys8Pn
         ZBdqoBO91h9Dnb7ZYBt7GhPOZ0ZXlu6JJMOEzJzpLD9n8pvAx50VZrsHXyX4A7EtQOrH
         VQztCsdhyPlJ/HSRIh0RgydFj/eJgqlJeRWF4ZhtynoXjRfQsOAu2XzSVdPrK8ydsjB2
         MLC2Uc1tcL+K3biIspMKivWk4Od6oiVW478Chmfe+SHqeJqCrXcWFJhV7UJR0TDlsf5b
         W6Psa9qUICn36435xCpVdof1CvNj1hXvJZfF9ty15DABMWcKLQCEobx6rg5Nd1EsYoJx
         iemw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VRI7kx/k";
       spf=pass (google.com: domain of 3gpfnxqukcxmvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3GpfNXQUKCXMVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ywG//Eew4BtKyITdjSxwZCaJFuJ8pivL+RbYQlBxzRs=;
        b=V4Ef8ds7MXMgR9BWbSmDo2V/8Vc/mJIm0y3FoT2q9XOLgBjthVs0uMKcP6zpDP+qIp
         WoaR4aRe7ZQuSSpp0WI7ajc5y/ykDl7OTsIJhcZjTJZ+sRq5qdvN4Z2BIBxPDFNooEyb
         RbEELDHgI8+hMlYvb6Z4VJQK1YRsQlC4PpEhcmQjixU0/CPQ8Kkr1N2fcd/y2PjSNiPl
         B8W39uYnGGiFMx2V0mBOQBhGGdb8w/ltb0KUb0ATNcDjTcTmAfCcWKw++OpCtpwBWrBC
         /dJOm3xlNzoL69ZFGYh+VamCXZ66T6XUvD7BFMuthUGXLv32IMN6qUiwk9x/oZUpwEX8
         VAww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ywG//Eew4BtKyITdjSxwZCaJFuJ8pivL+RbYQlBxzRs=;
        b=EM0Oqk3DpQzU/IvKyTG6jnfcMr1Dm5fBs2daGkIIprNTjRu2qQjwZqETlQmxjN8HW9
         CGGRG47pNzoZjHsyVLbUOLd147mjUBbaD2s5zaBcrOAlZ5K7QHPLnr74h/3hzHuAQZaq
         UAWFe59dPsPuDe8koQF/URlH0S0zKSqplckh/6Bhz8k/HrLIf3l5ecp6VZXTv3n5i63C
         vvvyrh2uj5xD/H5pn9pFDKZPyXM2AuQIXRCYTCsqPXO5V5XIcofzILowQ0huz8wo86xr
         2JZiQ9MqVuBesz0EBbTbIlzVw/ym55c9I8egcfOqozKzb8SB0kjom9y0+4woMl2+8SiB
         ZWQA==
X-Gm-Message-State: APjAAAXXyQ7WJXvv2Q+ASZR4rGONdN7+7QJzIIA05FwuhO1oB0s/99nZ
	DGj5ixSR2TPPYNGb+Dk/HMI=
X-Google-Smtp-Source: APXvYqySvUEv7Bt1XgSai1Urp+mvEqRm/Wq+QMBbVQgivR9bJdDDaQpXyq5TOyOhVyeyP0G0erYBsw==
X-Received: by 2002:ac2:5a11:: with SMTP id q17mr7866923lfn.41.1573754651993;
        Thu, 14 Nov 2019 10:04:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a1e:: with SMTP id q30ls1044236lfn.4.gmail; Thu, 14 Nov
 2019 10:04:11 -0800 (PST)
X-Received: by 2002:ac2:5637:: with SMTP id b23mr7652076lff.73.1573754651289;
        Thu, 14 Nov 2019 10:04:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573754651; cv=none;
        d=google.com; s=arc-20160816;
        b=SdB0oZ9di7wn2dIuZf03LqJYddwORNd7cnWRoiBDFlehm0+aKqclpphCiajpahKqXg
         5MbrvNHgO5T/p1z4FIvjtUWsXE0BXQRLnxMc7vjd6T8wnBDDIyEY1svqL4vTBtW56N3v
         O2C9gReAZvejRLBMM3eu6CribjuJOw1DPz2R1OrNbfMRiUnQjNcmHmh9xx8CzQH7wP4q
         qQ7Mr0ac2o8oRz5G06hdByu9B3SYAkTd0tlMB3L7wWAfl9LQ5s+pJDS0Ju5FL++jMo+0
         yQ2MCyT0N/kkKLwzGZTdY1pQEPUxmX1n4INgJocbDx7Pa9bTZlYc10pvey8YSs7xIjoV
         4zDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=yMaGIqlKjXUqwbUrtjSqf1Asst/iuXZBTZYaUH3mnUk=;
        b=Tv8GZ8QZMtCyOkB7/xtUTZN0UoWc3gGCDXdlEomqpd3mrCggh/M9saR27NXEVkJToJ
         Dxpfsij7QP3Y4gac/bK81DzUfEvX3fJjrDBTxvsB/QLPrnNVG8IY6g5SyXa5VH1MKooL
         oK6GyMnvt+O1M/5Fr79eMR0bdBuIAPld+mf4etriYHuiJ2W2N8oiR1aCGzbl8BNHD0Zf
         71bA7T/2S1IvqT7zy6Og5nwJouEYTmZ4LlJ8/NpX33wf5w7MacDF2EGSBmMobkk0oXJo
         3f7s7I4JKwjU7qA3WoFmXZnn41KOCYoFnWW9RV5ITEPd3UPf+dN380i+Ot3Sj0PxzR7T
         24Lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VRI7kx/k";
       spf=pass (google.com: domain of 3gpfnxqukcxmvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3GpfNXQUKCXMVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id b13si211932ljk.4.2019.11.14.10.04.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:04:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gpfnxqukcxmvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id 4so4899794wrf.19
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 10:04:11 -0800 (PST)
X-Received: by 2002:adf:db92:: with SMTP id u18mr9202786wri.1.1573754650237;
 Thu, 14 Nov 2019 10:04:10 -0800 (PST)
Date: Thu, 14 Nov 2019 19:02:57 +0100
In-Reply-To: <20191114180303.66955-1-elver@google.com>
Message-Id: <20191114180303.66955-5-elver@google.com>
Mime-Version: 1.0
References: <20191114180303.66955-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v4 04/10] objtool, kcsan: Add KCSAN runtime functions to whitelist
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
 header.i=@google.com header.s=20161025 header.b="VRI7kx/k";       spf=pass
 (google.com: domain of 3gpfnxqukcxmvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3GpfNXQUKCXMVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
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

This patch adds KCSAN runtime functions to the objtool whitelist.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Paul E. McKenney <paulmck@kernel.org>
---
v3:
* Add missing instrumentation functions.
* Use new function names of refactored core runtime.
---
 tools/objtool/check.c | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 044c9a3cb247..e022a9a00ca1 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -466,6 +466,24 @@ static const char *uaccess_safe_builtin[] = {
 	"__asan_report_store4_noabort",
 	"__asan_report_store8_noabort",
 	"__asan_report_store16_noabort",
+	/* KCSAN */
+	"kcsan_found_watchpoint",
+	"kcsan_setup_watchpoint",
+	/* KCSAN/TSAN */
+	"__tsan_func_entry",
+	"__tsan_func_exit",
+	"__tsan_read_range",
+	"__tsan_write_range",
+	"__tsan_read1",
+	"__tsan_read2",
+	"__tsan_read4",
+	"__tsan_read8",
+	"__tsan_read16",
+	"__tsan_write1",
+	"__tsan_write2",
+	"__tsan_write4",
+	"__tsan_write8",
+	"__tsan_write16",
 	/* KCOV */
 	"write_comp_data",
 	"__sanitizer_cov_trace_pc",
-- 
2.24.0.rc1.363.gb1bccd3e3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114180303.66955-5-elver%40google.com.
