Return-Path: <kasan-dev+bncBD53XBUFWQDBBL7ER7DAMGQEZDBBD5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5352EB548F4
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:13:11 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-30cce517292sf725350fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:13:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671984; cv=pass;
        d=google.com; s=arc-20240605;
        b=eTHypjlDLiEP+lI8hKrb3srsIYLeKCqwGAHLkaC8wvHQaCSkAqHw3H8Tnh/QgxZZoq
         IGSZcS5QL4MYw9P8pxS8rFnRouXgc1JcyE/uhAG/OStiHfCLNZBXWuKQD2S1ITy4pqYB
         AVN0Qy1JRz2/6cl6kcSC1ZrvB1vfaPF5jGtOfd2CD7FTJ2A5nPTposrW7FBkhpyUarMA
         8taGye/w43lBN3rUgEE6m0A+LzocZ9Oqe8IOV4eSsOo1CzlyNPeO0eeogO9BeTx1lqtw
         HjkDJLX6kSBbsxvkaExIZBElqpsu9p3vd0WAOO5EPaaGGcCyfjML6GsNO0O/QyYPA/i6
         T8Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=LybmqYNBY4F2ftwsdWxbE9fbNxlZPoQNaTTidLfmvso=;
        fh=oKGoeLxyEjh+tzugiiwAI9KTB3nvK+6Ci4RXylRzZtI=;
        b=BpxB1HjDkck1jDJrFESc5mY66g45kJOyHth2H9HN5/tWR2ooZqByFI+0YDbWjEpz1L
         tlzuOdBmw/1v1JmufkENTWX9VPl1sEYcTc9a+TqfKmrCoOpwTxUZKKfsNxdtSmEkM3iP
         jCuB5jOufA1tDjYgrSjgGKFV62xgULtf/1rYjuWaWgaTMU2Sph9HXirj3tGWPdRAabxR
         tsxmmzWGurcYKaoijXxSjjCX41Y5kvOfTFSB9AVrlQufLC0t0AdYgZ2oVQQylQMtGsY1
         xPGH3ORiVB4vp/eDb5PTJhrg94GchFJnOIFDD8TwQrqhORNW6EokWy+ewuIgCbIzjrBf
         LxvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="f7/CtEHF";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671984; x=1758276784; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LybmqYNBY4F2ftwsdWxbE9fbNxlZPoQNaTTidLfmvso=;
        b=AgMOG8eQoQAK8VrzSE7om6JfKGxRPOJuai/z/kfXmDOJYcvXgrcU1HV9+GBbdWu9O4
         LQrS5Sx38yD1nKyRlSwHpoT3II/NxzmS69BxSu1Rvrrz+86ILV2T0PJ855GgbmcnVBZL
         t5DXGbX9Z21rMvuuTu9zxILcp4kthIil5W+gGrkhOosm98UkAXMGuovX3/mfWLFGeAp2
         lfS8TUIrWOZnGMZrZ3EnKsdplr6Eu4F3GaGwzTevBNRjI4MQzaljNgx0vct/YGofwqR4
         43GHEiAizd9ODu2BbpxUk6kbSlcw+5/Xia/1eNOIsBVmE2w0jQopr/0RSSKMqD36I/zM
         hZag==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671984; x=1758276784; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=LybmqYNBY4F2ftwsdWxbE9fbNxlZPoQNaTTidLfmvso=;
        b=FLjD/sL6p12OBw2WH50+FoY6s3h0Xv7mp4JZF1NMF6jZ0Y4AN5VpkZ+6aPUY52OZd4
         UNpAprzoer31RTZ4FnbUgSkXAZ3vTltx1bo1L0JIwbuUQqQU0aMEjQ7RS8X9RlRK7key
         hCiNlJIXJpH1GxzImzhm9eA/5GMEivElDm40iMxXicB8Xqffoardhdnp6nNoBsMhtWT9
         Rzw+yghQ6FWuPqt5y7byi2BrVcgzk6MN5ejdmISrftqLsS2LSToCTw3hCFDDSB2dZrFk
         xHip99dbkIPqYP45l0s2AKsoFZgSnLrOGRPKUJx5Y5+Yt3iZgWQD4VfUZbB1UIj7Pa2Y
         FjHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671984; x=1758276784;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LybmqYNBY4F2ftwsdWxbE9fbNxlZPoQNaTTidLfmvso=;
        b=oBQZh9NXY2B09zvdcfWfecUsVUwkEvLyvDTaxFbveqW+2nLSAQQmDwkreG5ClLJlQr
         6hh7xgSOABD+NUcSaebHZRavXv9bYhP9NGqFZa5nAYIRNqlPanM5WIzvmLuatIKqOhj5
         uG5jP9MGstOLz6+oonKNRA29y8xoJdObCLcKmMNGUhw8HY9QpK8gHrAYfkAz0rncB4ej
         cGkehj7lu8To36cM05gUxTfbBsCTL217V6MJsHUPu5y51flk3Ea5HBr6lBp5rua9V0jZ
         5LkstD6Zd6UD30Wn0QqOODfecruwmApdeRXch5/asmjNyn1pPNujaK3pMyN2B3xJack3
         VnxA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX0RLQKRhoTbY/5Dbt54lx2UlJxCOnTLIfGSJ1VmyBD5PJbKgNJnvtXlS0+eYwIry3iVNMI8w==@lfdr.de
X-Gm-Message-State: AOJu0YwUjj4Gtr26HAbJUEQFjeS7JMjQiFtgSwz68PT2UcScLAV1+z/I
	LGBXva2bRPYoUDDsCMV5IHUWw0XshEYItWjINN5/Hzcu2a2XnJ1xTmPl
X-Google-Smtp-Source: AGHT+IGKlKQ7M64LM1Sgi5+9iBjVurRb6a8LbuM5DczJCE44YcilMKq0+Wtlp7Pg9vLOCcXIi/N+iA==
X-Received: by 2002:a05:6871:cf06:b0:32e:f0ff:3ddf with SMTP id 586e51a60fabf-32ef0ff4da1mr465248fac.4.1757671984357;
        Fri, 12 Sep 2025 03:13:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeRKpzuInEoA98rP1ut55vGuWiq/nGrSPZAOMbBjsEV9w==
Received: by 2002:a05:6871:bb8a:b0:315:531e:fdba with SMTP id
 586e51a60fabf-32d04186b09ls612487fac.1.-pod-prod-02-us; Fri, 12 Sep 2025
 03:13:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVsn+qGevwbhJQyPGIiC7HvvgRp9cO/ZEyaGAmfhmWIso9uvQQwuVGlX99SU8TDIDobMgBpyJ0zaTg=@googlegroups.com
X-Received: by 2002:a05:6871:739a:b0:31d:6467:3dd5 with SMTP id 586e51a60fabf-32e54d89c64mr1077255fac.2.1757671983333;
        Fri, 12 Sep 2025 03:13:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671983; cv=none;
        d=google.com; s=arc-20240605;
        b=gqop7Dcw99TuDOcrZ+PGkF8dIvMTasSa5oMf/GNlrjvu0gfKfG2gDyw4VwKHTS9MGi
         Rh7qTGdq62fBOmhoqxIzEJcXPMAPqoDYNCILcC8CIOnROvjTpXoZ3m1Mianh8RxMoNNl
         yI9lS8St8jdvrkOQLwP6tQdEgvDHhr5jONR6wYOuVItk5mDNKp49QVznfkiIbOC6s1c/
         24QCSP2xU5iFmXJc3yuPi6ZkrY8Zycq41wX83IoUEl2m5neNAvU7UzzDE0/dceewEJHt
         FO4tUF4+3pQhYQExdY3R+aCUZ4kk6V4MPzhDgGKEIrVBQybqk/3lHJ6YHoJvYz9sw+eq
         POyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2Mx/ZUXbIMqKSHkTbty4rSJVQCBlfpfdQjz++MJLD94=;
        fh=phD5eAfBXDQKapiJXKhTN1BmXw3qMyC8kiiOCmtV+dI=;
        b=O48zhiHhOXvlya8zNv8TslJwJpLo+NMEi2LURUI4X4g7ZbykVQlkL3ARfsGvypAQVI
         sAvfa/jFfSMiHQxXO5qaXuf2ovMLLnSjsVLSCmytqyExqkdxAgTclh2GerY2m3wmzZwi
         aVtkYW+OjjuUddKtt0eBBKPhEd5s08vBCbFPVUcgdptEstkdMhfyPgXr1oA7frg1U/Xo
         h9gS6ZM0r6LrNm8ZGHg6ubE0rpSayhNbJaUrkEvcXLGYDZxsIgUTg012U68fnmaFmBmq
         dHyna+/vkUhqpauuV/H7TM4cjQYAPim3/6laWQgVGAV0sGdloYJCRXr6HOh8AHKDTyek
         BACQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="f7/CtEHF";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-32d2f52aa36si188451fac.0.2025.09.12.03.13.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:13:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id 41be03b00d2f7-b5229007f31so1089756a12.2
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:13:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVbnwK3qblgj0D3r37NR1X5nbpuEp3tWhtNcILCnlZbXbZpj7d93Tp0tkF+HbnhNmGS1WhKFXBFLzU=@googlegroups.com
X-Gm-Gg: ASbGncsASg0wEXI2hIXJ7Gdgf4mePCrNnFwwIn1R6TL28zV598ph8Mm8GsPvRgI/ugj
	hU++uKC3hB0otZnWn+mPVgaj+gDINZD04kty9pDzS1T09++DxwrGy2XcgDERH4IWoGxni2+uOWf
	5PQ/91g1MeMFKHnpvrx6z46EZuoVZQVfXBPUlaMFddkaiRu2Ul0fR2fbf1HfJN2vrcrneFOIXOc
	UN2/xeyfHF6u1EYYn2gQznMa3k5/dIbJFVzJ+pwvRu/hnoTqGcFFOOuin877wZu7mqO33QwNj2k
	zt7VeVhKQHJgVhphMXkQzk7HW3V2dksLqlqxA5tBM0MUZRXcI69OEhYHVsXSGB+BkTMHc5viGDh
	SFIxG5QWzTBGOfwYcFSZOSTlA/l1KeAxrH5iAglc7R3rtPglMvg==
X-Received: by 2002:a17:902:cecf:b0:251:493c:43e9 with SMTP id d9443c01a7336-25d243e79cdmr29426295ad.3.1757671982485;
        Fri, 12 Sep 2025 03:13:02 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25c37295f9dsm44540355ad.55.2025.09.12.03.13.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:13:01 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Kees Cook <kees@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Rong Xu <xur@google.com>,
	Naveen N Rao <naveen@kernel.org>,
	David Kaplan <david.kaplan@amd.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Nam Cao <namcao@linutronix.de>,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-trace-kernel@vger.kernel.org
Cc: Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v4 13/21] mm/ksw: manage probe and HWBP lifecycle via procfs
Date: Fri, 12 Sep 2025 18:11:23 +0800
Message-ID: <20250912101145.465708-14-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="f7/CtEHF";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Allow dynamic enabling/disabling of kstackwatch through user input of proc.
With this patch, the entire system becomes functional.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kernel.c | 55 ++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 54 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 8e1dca45003e..9ef969f28e29 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -17,6 +17,43 @@ MODULE_LICENSE("GPL");
 static struct ksw_config *ksw_config;
 static atomic_t config_file_busy = ATOMIC_INIT(0);
 
+static bool watching_active;
+
+static int ksw_start_watching(void)
+{
+	int ret;
+
+	/*
+	 * Watch init will preallocate the HWBP,
+	 * so it must happen before stack init
+	 */
+	ret = ksw_watch_init();
+	if (ret) {
+		pr_err("ksw_watch_init ret: %d\n", ret);
+		return ret;
+	}
+
+	ret = ksw_stack_init();
+	if (ret) {
+		pr_err("ksw_stack_init ret: %d\n", ret);
+		ksw_watch_exit();
+		return ret;
+	}
+	watching_active = true;
+
+	pr_info("start watching: %s\n", ksw_config->config_str);
+	return 0;
+}
+
+static void ksw_stop_watching(void)
+{
+	ksw_stack_exit();
+	ksw_watch_exit();
+	watching_active = false;
+
+	pr_info("stop watching: %s\n", ksw_config->config_str);
+}
+
 /*
  * Format of the configuration string:
  *    function+ip_offset[+depth] [local_var_offset:local_var_len]
@@ -109,6 +146,9 @@ static ssize_t kstackwatch_proc_write(struct file *file,
 	if (copy_from_user(input, buffer, count))
 		return -EFAULT;
 
+	if (watching_active)
+		ksw_stop_watching();
+
 	input[count] = '\0';
 	strim(input);
 
@@ -123,12 +163,22 @@ static ssize_t kstackwatch_proc_write(struct file *file,
 		return ret;
 	}
 
+	ret = ksw_start_watching();
+	if (ret) {
+		pr_err("Failed to start watching with %d\n", ret);
+		return ret;
+	}
+
 	return count;
 }
 
 static int kstackwatch_proc_show(struct seq_file *m, void *v)
 {
-	seq_printf(m, "%s\n", ksw_config->config_str);
+	if (watching_active)
+		seq_printf(m, "%s\n", ksw_config->config_str);
+	else
+		seq_puts(m, "not watching\n");
+
 	return 0;
 }
 
@@ -176,6 +226,9 @@ static int __init kstackwatch_init(void)
 
 static void __exit kstackwatch_exit(void)
 {
+	if (watching_active)
+		ksw_stop_watching();
+
 	remove_proc_entry("kstackwatch", NULL);
 	kfree(ksw_config);
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-14-wangjinchao600%40gmail.com.
