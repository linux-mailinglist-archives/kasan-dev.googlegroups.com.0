Return-Path: <kasan-dev+bncBCF5XGNWYQBRBJEO3ONQMGQE4ZZFGSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C34C62E9BC
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 00:43:34 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id mr7-20020a056214348700b004c6806b646dsf3086984qvb.14
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 15:43:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668728613; cv=pass;
        d=google.com; s=arc-20160816;
        b=FQTi/41AYH9pyzmqJrybRtFlU0dyEC500wfgQmU4JFaK8EWQZK+EFgIIwO8NjBHPy+
         +6Cfr0YBxZC2JXwqanCLMro+hsfhp6gsb9K8t5lrjY+SPJwxxsmtVByjZwMUKOiUNRPj
         TCLrUgLO21zSLOnkdGPXqGpIUxdQ9FTdxzowULDBBcTTodtDJpogsUnFe9Kuz0f93QGI
         c0aPgsSxQki36AHhlZmrPQKp3qzyygJxESaOfPwPQeh+zm04zzu3pKMQdrO22oxZxDnM
         N+BAjneJ2zymFdFyihO7PR9qBDOreYDeZvs72TW4hG+QXSp0pBDbrxTnl7Fn1Ghzt5T/
         EWqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EdnOqR44TunrfZZkfFbnSMkriVs6OMm3L341+GaT+ng=;
        b=Vn0+UK3Lpv2mHCxXi8sVFtJRwFhBvrbSRf/uc3QzXDUT12PfcDxBmo7F6VSxcM/E4t
         eZ1ibxTNKCnGDfDIOHJrAY4K/joCC7Mhtxl73GFJHm8VXuOg4TGOS0kZUuCcCyesG9OO
         nDaOoVxRekM0vvw+RYOprCADVsNAj3goPwAJXInlmTT8SK+9GW7U4NR5bZ4LFxqX3xjz
         LjOHcrUg41NsDHZdFVgtAlb4EsNt9/pnWBT04pgc3/cXSIV4rhYNJHNtSc5F/YKa3XcI
         un0jjvacqfQd2jYCBbok7H+TGG2CuEenht0ft5dUyfQ5YomisZI6emz9ebhMSEHojlyp
         h+dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EIZNUa8F;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EdnOqR44TunrfZZkfFbnSMkriVs6OMm3L341+GaT+ng=;
        b=iWlgYLD3gS0OHueYA6r1vpTfJky8cBBMwxRYRgV9JuBWoQjYMfr5z05ftxO6YBSBY6
         VJLlfsZ07Cn8Gg4fyZ2jmJcWfBmvtc9muWLfFe3XglyDvsRsEVNHD1cPG/cAXPc0mcgW
         gkWUNBTihhFVGsZvoMBAtK/4ijPMa8uWIGQh8ZTXt7Pzt7bSPffn5ElaOGjyBTBC3i90
         SFl41HLjN1NtUg7JwHR8nBPXtn/2SYp9Y8itQXfdMVv9/bGDmFstgmCDG2TXPLrgfVZ8
         hmGQmOvCvLn++yXg+d2495Fo8CM8lPi9PlwP3apPS17U8+satbFcFLlnPWP6lwcUgcB/
         q2Tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EdnOqR44TunrfZZkfFbnSMkriVs6OMm3L341+GaT+ng=;
        b=0FZZWW67a/Pn7LSZcwmeFQlYd6Qi1rSrhpev2EJ1LuTdH2+PXB2uTFJ8r/cIuEGu+c
         hcDrMpM0JwtrZ5a6bxE0u6E5r+JtURbuTjkRzsV7JwLRYXzMFU80aA+tIdCxWD5gPEml
         iX2ANf/nNFv0dU8erHlInmsnq6hbwGS7Ysajp4hn8k4ugLmgExo/gK8nAS0/76L+FD8u
         sTIrfCZY677Yj04Kj0YiJfYX82VbapzI+3Y63x24Lqw72HaCImlN4eyeD10lcXtjKSvw
         U90OQiQDYjqaXqhkXm4Vo9gFHrJiAhH5EVjpzA54dBstDBJekFxbhO4avgOlAo8jt/0g
         HWFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plsghsi9tD2/2v1phHeVu/ZPqtQ9kLIzQs1QbmXcKv83unfZcfj
	qRjC5VQslgT+zrK8msy+ePI=
X-Google-Smtp-Source: AA0mqf4NOJFbB5/lSWhg8PIMx+z1VyNeYSrdE9mqeZyoufHUaHqph/zIxGnJY79L1WJjp1fBtrsP/g==
X-Received: by 2002:a05:620a:22aa:b0:6fa:3874:4435 with SMTP id p10-20020a05620a22aa00b006fa38744435mr3857770qkh.731.1668728612913;
        Thu, 17 Nov 2022 15:43:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:123c:b0:6ee:8313:6182 with SMTP id
 v28-20020a05620a123c00b006ee83136182ls2298609qkj.4.-pod-prod-gmail; Thu, 17
 Nov 2022 15:43:32 -0800 (PST)
X-Received: by 2002:a05:620a:370b:b0:6fa:1da0:2e7b with SMTP id de11-20020a05620a370b00b006fa1da02e7bmr3468548qkb.162.1668728612352;
        Thu, 17 Nov 2022 15:43:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668728612; cv=none;
        d=google.com; s=arc-20160816;
        b=P3XJf3G7DzM4bQr9DBow+QQJLW4IYwHdufNg9vm/ESU/OTmiIuvs0vHSPCCpBcW6+W
         rzYzK10XghpQ2CkDhBVoqg3fFbvrupODZ6hMM7CGBUlztexWbMiBb4HLpJisNAegGBAp
         874PT7UpmRsfaYkWUePm7TEVbT2OBjH0jR1yRtHuqo4sNaK/IGcH/RENegLJRBa+nUoF
         +MRYX02YmoOOQqQgkEtQa/cikF0bjsD3/NivQN4gmCdn4+xt6Tfsg6REp71y9IAda/W8
         /Bdc4582NYyV5sZbIv0y1T2B12l9HTKL0TLztRmWggLyZTQ4tqAQPw0/w2hunCCmclVJ
         dSuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xfJil3q4xneaphG+dBltmhf3iJIzvXDIW+JWkiHPnUY=;
        b=IPPAu93sdOM49OZOXbleO3dlkCOEg5YtkO7bXka8FTEYtG9Tqyqw5c59RfO0RwIvSy
         dOK/wvC6X11VMtJ5E1NBc8flTt1zPKXKex+4zHnYszrYZ0NCImegL/fH5AvH0ztMkTjZ
         WvkAXJxbPOYnNZWY0aF4JLQbej8BKYKmy+vm1/4fzjK6dWkNRddJ4NW3T66u3Nz3iz6H
         BvlY1fsCUqM7ioAkP9wpQdZqt6DO744Agb3EHVFaEjv3oyj7RP/P9WhuM6aOsCDCYfPC
         ImwFpVC53i2kVRGpQE/z2uRvscC+dhqORhkebpaYXEDWSIg5BH0DSp2aCAEEvErHylH3
         GdCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EIZNUa8F;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id b11-20020a05620a0f8b00b006eea4b5abb0si78341qkn.0.2022.11.17.15.43.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 15:43:32 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id b29so3268230pfp.13
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 15:43:32 -0800 (PST)
X-Received: by 2002:a63:114b:0:b0:46a:e00b:ada0 with SMTP id 11-20020a63114b000000b0046ae00bada0mr4211444pgr.409.1668728611983;
        Thu, 17 Nov 2022 15:43:31 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id h72-20020a62834b000000b0056bd1bf4243sm1738916pfe.53.2022.11.17.15.43.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Nov 2022 15:43:31 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Eric Biggers <ebiggers@google.com>,
	Huang Ying <ying.huang@intel.com>,
	Petr Mladek <pmladek@suse.com>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	linux-doc@vger.kernel.org,
	Luis Chamberlain <mcgrof@kernel.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Andy Lutomirski <luto@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	David Gow <davidgow@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH v3 5/6] panic: Introduce warn_limit
Date: Thu, 17 Nov 2022 15:43:25 -0800
Message-Id: <20221117234328.594699-5-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221117233838.give.484-kees@kernel.org>
References: <20221117233838.give.484-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2740; h=from:subject; bh=UAp3/gSn5HSib4EzfW5wRRKF+FGTDjoMEFBYjvCvDcw=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjdscd1GA/3PLtD3N4H7SsA34PTW3nka1IngIvEXYO EYIpEOyJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY3bHHQAKCRCJcvTf3G3AJvptEA CdGFz8DSNbF4RMjKrrJk88mEDkxWYDqPKgqX4mCBz5IHyHLYf59wVt93MA2s9+Y5dISuBzWnk9orB4 qfArFrJPEPZY2IBBUlcPeCEho6xpwbHRntreRWX2Sn3lBbclKlgm+lVQ4FTgRavIV0cJjI0qMAutZF FAOyJnKFEYiRADA34tk5jIW4ubWsNHHNSG3AjwA0jb9PVui0Wy9LqrbJj0EJD9bkuR/7WGPavbMUEg ntUcsuYQDfvqUgW6Ywm+NK7jv4NozevnPZ7AVR7JCAdexGnbZsuZSeeal58/st/wu+XrpcUVhLcQ5q 8dapczcaRwqnG01Y1bbClamjnwPLMwL60GNMluInTigO4LEXvrEh9pUIjhTIXeIq9QAqDRxjifFRMu bCTr8sX6wOsDtkOizBKxqRBSgCsNFG4CFJbDcxGi5ZJNmOeFwyaJxfQbAWOUq+JZUKZ5FA51HfTDoN 4WjzLeqQ1jqeVDmfPJ0NgZD1rNVWBPpEPRaOmkukaDQyyOeA5Fbh7vfLGUGFMgs3m3NngBdna8YG19 Bv6YBosdV/NmTETybYC0gITxiJPHbKV1dx0B+ZNAbQ9wm1FfG+41bCdpnicHfdZwQGkISK1KSkk6cP 1VQADkQ9vKmG7cMXRQDydqjmg7PmKftmrXjELJoAwbLHqmZ85HDIfmjxDQKg==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=EIZNUa8F;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Like oops_limit, add warn_limit for limiting the number of warnings when
panic_on_warn is not set.

Cc: Jonathan Corbet <corbet@lwn.net>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Baolin Wang <baolin.wang@linux.alibaba.com>
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: Eric Biggers <ebiggers@google.com>
Cc: Huang Ying <ying.huang@intel.com>
Cc: Petr Mladek <pmladek@suse.com>
Cc: tangmeng <tangmeng@uniontech.com>
Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: linux-doc@vger.kernel.org
Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 Documentation/admin-guide/sysctl/kernel.rst |  9 +++++++++
 kernel/panic.c                              | 14 ++++++++++++++
 2 files changed, 23 insertions(+)

diff --git a/Documentation/admin-guide/sysctl/kernel.rst b/Documentation/admin-guide/sysctl/kernel.rst
index 09f3fb2f8585..c385d5319cdf 100644
--- a/Documentation/admin-guide/sysctl/kernel.rst
+++ b/Documentation/admin-guide/sysctl/kernel.rst
@@ -1508,6 +1508,15 @@ entry will default to 2 instead of 0.
 2 Unprivileged calls to ``bpf()`` are disabled
 = =============================================================
 
+
+warn_limit
+==========
+
+Number of kernel warnings after which the kernel should panic when
+``panic_on_warn`` is not set. Setting this to 0 or 1 has the same effect
+as setting ``panic_on_warn=1``.
+
+
 watchdog
 ========
 
diff --git a/kernel/panic.c b/kernel/panic.c
index cfa354322d5f..e5aab27496d7 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -58,6 +58,7 @@ bool crash_kexec_post_notifiers;
 int panic_on_warn __read_mostly;
 unsigned long panic_on_taint;
 bool panic_on_taint_nousertaint = false;
+static unsigned int warn_limit __read_mostly = 10000;
 
 int panic_timeout = CONFIG_PANIC_TIMEOUT;
 EXPORT_SYMBOL_GPL(panic_timeout);
@@ -88,6 +89,13 @@ static struct ctl_table kern_panic_table[] = {
 		.extra2         = SYSCTL_ONE,
 	},
 #endif
+	{
+		.procname       = "warn_limit",
+		.data           = &warn_limit,
+		.maxlen         = sizeof(warn_limit),
+		.mode           = 0644,
+		.proc_handler   = proc_douintvec,
+	},
 	{ }
 };
 
@@ -203,8 +211,14 @@ static void panic_print_sys_info(bool console_flush)
 
 void check_panic_on_warn(const char *origin)
 {
+	static atomic_t warn_count = ATOMIC_INIT(0);
+
 	if (panic_on_warn)
 		panic("%s: panic_on_warn set ...\n", origin);
+
+	if (atomic_inc_return(&warn_count) >= READ_ONCE(warn_limit))
+		panic("%s: system warned too often (kernel.warn_limit is %d)",
+		      warn_limit);
 }
 
 /**
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221117234328.594699-5-keescook%40chromium.org.
