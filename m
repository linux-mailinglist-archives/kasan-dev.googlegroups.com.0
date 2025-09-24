Return-Path: <kasan-dev+bncBD53XBUFWQDBB2NWZ7DAMGQEOZ3BY6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DAB2B99AA3
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:52:11 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-319c4251788sf7260478fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:52:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714729; cv=pass;
        d=google.com; s=arc-20240605;
        b=SDl5Dhjbj+6/dkL54Q9HzZmrOan378RGi5wXERpguXddsSGhldoWUpNz9D/IowjI8I
         zcA9W+Wo9Kfe6y9DmX80Wbj0Ywxn1Ehv5lZGerlgqvOpQ/rsMa10A4mU9Kpc8canQooY
         jbYEp+TKRZ+wTU2/+igSP/92PE04CaAM52QB0dpelRfuw58kESi98+NOJ5qxhqIjwPoB
         6pChvbMHg7v46BzvaniQ5AtYTW7n12S49JjmQ8gfrUoWipttXqQ6eP52gwcFqFZ7/SZ5
         V1+kmtxkwqB6T7UI/2qLWDI81QRkF7zhqGWl8+uah8KyoAC0qd30pCR954Bi8M9GS3Jq
         wStQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=pNVbvqX8hL2aXp3pFYHlIn7mTKPgoahIWb4m1Gsr4kc=;
        fh=kTZE1pM1cifuJQMmaaTZyrjggfzeMuK6LA2zZBsHsT8=;
        b=Bv/+DsiEOt7yXkHCskYjjfi3e9MKW0OiV/S16Rl2gEDnOZpsncyTDk4Z2T9oIdA8jq
         V+zHUaqOqxjBBDAj1I2VsOttgCHZFieRcCs6XrBSw2advur3LmHX6NSKKSmUAhikyT1v
         /n42pHWqXpB1l4hiA4E3ColR98MLMAH+jF3/RlpO0PD9Bpt9uhocPNdZF4Gc6VtJUnuU
         WI02M3Ncwe0QDQ9jcR7INkc5mSPPJk57bz8Rz4nUa4JTMX4zQyOD3H/JwBWXY3vcF9T+
         4i84ejzwJYhru8hFGlXVHH+yii9d6IWnL9Y6dVX+kqS7XxvE/xUg5sp10rVIwLePulmb
         RRag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mdymWrNW;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714729; x=1759319529; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pNVbvqX8hL2aXp3pFYHlIn7mTKPgoahIWb4m1Gsr4kc=;
        b=WsDv3XWbgtLH8mlyyNspJ6mNwK22PAFrhC3YP0ruR5chAzfvqyXVZSx3g8V6Ee714M
         FHlXfb1TggyTCxs8UYZCF/dgjKQFojBxMsamelgcxAYtQeRJY3993zg/s67Cf7mHz364
         XpWvLLoXzeihUE1WZ/5WugwK2ty9hpg15Kx4kMm+xVjEk3fwJolVx3BDBpupqAKMNVGQ
         0jzIowVbVAtcEteGY3p6cNHrpOd+q35rBUOMVSaJj7fWOuJ0Oa9xvRlAcBDFmqSac5yl
         vNUopaQ7SaT67W4JSfqqaj9rRtdNRx/lRJ7/lmQt2gFUjLhVSja5tkLZSunYn2/JcmM8
         kLRg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714729; x=1759319529; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=pNVbvqX8hL2aXp3pFYHlIn7mTKPgoahIWb4m1Gsr4kc=;
        b=OAhuKZVOogvx3QNIPBdExDOakMWoEpotm6V+bF+TGifHvDsDb368Cit5l5gXYJLQRP
         NIMETRc6IyjCSTnw+Ka963QH0wp9kSOUzKvC7wp5cQF0kV5iEV78SepcQ4MkXRnS9+cn
         002yOQfEkc9WMk69ioS20eh8yeeAl6x1n8YHRnP2iyKLz7tthk/g9L27dhs2SeCQkLJO
         o7tUW6AJqoYeJWq3xdEldotAjqqY/zpO/MmwvNJc1ZRAOEZOKE74hKhqLTVsf+pV09Zn
         L63qQa93Y6u9U1zPYgEGUy479NsKIc4Ebfxbcip5AD/BQMC/UzXFYjlJc9ZBI5M/Hpx1
         Lr6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714729; x=1759319529;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pNVbvqX8hL2aXp3pFYHlIn7mTKPgoahIWb4m1Gsr4kc=;
        b=GrvlLOTlZVJrU5RwkjoOoTSAl8RZkCIRLk4iF+sno6EHsHRBmHxyPp8z4GOmnH0XLh
         ix9BCXe4Ny2xGHnKC8QgSCOQNaWHOKF+H/oP5yoTnie/Iwao4+PjNm7xhJTJpKj1jo3H
         8RSbzj8k65rm3j5YldUG5KJXj8knQF44Ml4P5yBCbCeMrYhJmpBQznwrb4cHu8P5/MUD
         bUCsNLmq5iCrBT6VBNS5HdQUF6CJvPzPOeHFQsyAvgxF7SCPQV7zlckLBtqNsbFLjSib
         aB109YmlckWksj/In5uJz9SEWBZOkrY2x3lBLWkET1qamwOnVSrWpS2ZCk+Ol2l08oXD
         qdgQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWBYAQ1zvAHT+lBRdzkQjoSaYrMf2xB3bGIDoW7/8GYdn8wM460FHloeJ9cYzAKSbroExswvA==@lfdr.de
X-Gm-Message-State: AOJu0Yx0ipgxkzinNb1l5ITWRlfVU9Le3Nc7GDUTV3Cx6fcahMAQ+Cpk
	275mUxaepfHzEn0RJmM4iPnSB5QxkSAlQ8brz2A1wRAMQs6/+lmcOIsf
X-Google-Smtp-Source: AGHT+IGGP9Ve6hu8ji6Wi91DeUDGcoBzoZ7i1LCUhbHiQAi0SRV5kyFAJJHBcuX5ioHy5B/KsUKyIg==
X-Received: by 2002:a05:6870:a908:b0:31d:707d:3c7c with SMTP id 586e51a60fabf-34c7811797bmr3582016fac.22.1758714729521;
        Wed, 24 Sep 2025 04:52:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4T1crkaxL9oCSB/I+ozJFxtLR97fQ5NwsN2pzX3Qqmng==
Received: by 2002:a05:6871:e01b:b0:336:1449:b8ad with SMTP id
 586e51a60fabf-33701353fdfls4032672fac.1.-pod-prod-03-us; Wed, 24 Sep 2025
 04:52:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/VfjPcLkWq1kR5dLnPfmtRv+y0p7zT1iQZ94u4BQhyaVMC87V2HHrBM009t63HU1OUKa5aeWZ5+o=@googlegroups.com
X-Received: by 2002:a05:6871:808:b0:348:6276:f92e with SMTP id 586e51a60fabf-34c75a68e57mr3260918fac.11.1758714728743;
        Wed, 24 Sep 2025 04:52:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714728; cv=none;
        d=google.com; s=arc-20240605;
        b=gJj5eNqacwofkN4cFmfab8yqsY/T1JkrZNNmnCeREbUZNmHgk/xiyUjZo42zzz4u10
         JCPqiO0ZO37AeNuGte7Z2Whq7WSou9Jb+D/3hoEaF6kaKAdWCkTobjrskJvBjf+pJIJ6
         b02sR4yEwIQl7Rn6VWxVikzOW34A/S2pye2JeG3Spa5z1dKS2gYWGjTj9++DanemNy/v
         nvm2yKffsyLyRyXXQUWQCrtHaf2O6d4Bqv5kmNBoY4PuCNYz18X/YUqomKoPJN1FNEcA
         agbrTGSPtgsBDGX/fe30nmpp3cnXMqiU4ZbyGj1Lpt6snUhCYXDhHZFROWT5X55iCM9v
         xSmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8p2Xfne7CGpLjN/MkaU3Ee28S3aCNgQ2oxnJpFebIbs=;
        fh=PkysF1kCvi2tSxYvZCJyk0cDPBzbNWUl2wTFrUnCcaE=;
        b=cpnKPsQhOhKf1mld5Zpgqqa11IGBQf87VP1vG8PhwodgC6Vb1ojJ9o19ZTqNYajxiy
         fY6+9Qs2AvSxFxBNdzzTNiBkQeQ3cBWrDNDza2Muag6utLzDdTMf5LI8nOE5jLLKdwNd
         2QszlpxgnvQHHY6OnVwHYoBViY/wPcTUaQAj4chQbekY/Psc9gbx3tmAtGgTHsVf1kQ8
         xBOvj4380ZJTt/faMn6QWdREMxaVfo6eoirdfRfotgWgS378GvNAUeU9VNfRA8MJZtsr
         KSmUwNBKNALJxBWE7BVya3V6vjVY222rvLypWHh74MbSXaNDcnZFKKpqvZS52YmSXVuj
         Zcnw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mdymWrNW;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-33f9553b08csi390759fac.2.2025.09.24.04.52.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:52:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-77f1f29a551so4642292b3a.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:52:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXmu0oe8dP9EqosdB+YwgHhgBKnz3C1S9oZ8gmrtkRgcq7VpZxm9xB+anU06DfQtyKqF+8bnGED/Us=@googlegroups.com
X-Gm-Gg: ASbGncsBZxUsFiawZCik/fyKn9zzGQbjdnPEsadS2ugBQIYNjREDguaPOmFzbIjtRNr
	/pQ4Ue8gEGmJ7ocrrYej+/lVYGZZM0Rj641d/FL4hRqFL9UX9QB8VJc8JUIxjzEoWw7OjVFnOIH
	uacYg53n0FrOAREXoUdTkb2/MldWIwZyXspWCtFw4F4fFr1IGBIKT1O4upu9PETT8s3d0zkCv5q
	Ok7cNHaGdseXzWdmJbdEMPe1RmV+fkRloDPPFBEWShgWipqKB60ZeKtclSevkr6Uty5/+eMOOyq
	jyVCjXZNkRmgADHqc15tjaDQgVKtJg03nHoNAXO5VJrxjXYPHPGl6zjTQ8s5yn1C0DpZzI8v3kh
	4lV1pUzzAYtN9JbS2i+sdjZKOmg==
X-Received: by 2002:a05:6a21:99a7:b0:2b5:9c2:c596 with SMTP id adf61e73a8af0-2d0009e2f3bmr8556644637.6.1758714727810;
        Wed, 24 Sep 2025 04:52:07 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-77cfbb7aad7sm18582634b3a.12.2025.09.24.04.52.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:52:07 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
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
Subject: [PATCH v5 09/23] mm/ksw: ignore false positives from exit trampolines
Date: Wed, 24 Sep 2025 19:50:52 +0800
Message-ID: <20250924115124.194940-10-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mdymWrNW;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Because trampolines run after the watched function returns but before the
exit_handler is called, and in the original stack frame, so the trampoline
code may overwrite the watched stack address.

These false positives should be ignored. is_ftrace_trampoline() does
not cover all trampolines, so add a local check to handle the remaining
cases.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/watch.c | 38 ++++++++++++++++++++++++++++++++++++++
 1 file changed, 38 insertions(+)

diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index 887cc13292dc..722ffd9fda7c 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -2,6 +2,7 @@
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
 #include <linux/cpuhotplug.h>
+#include <linux/ftrace.h>
 #include <linux/hw_breakpoint.h>
 #include <linux/irqflags.h>
 #include <linux/mutex.h>
@@ -18,10 +19,46 @@ bool panic_on_catch;
 module_param(panic_on_catch, bool, 0644);
 MODULE_PARM_DESC(panic_on_catch, "panic immediately on corruption catch");
 
+#define TRAMPOLINE_NAME "return_to_handler"
+#define TRAMPOLINE_DEPTH 16
+
+/* Resolved once, then reused */
+static unsigned long tramp_start, tramp_end;
+
+static void ksw_watch_resolve_trampoline(void)
+{
+	unsigned long sz, off;
+
+	if (likely(tramp_start && tramp_end))
+		return;
+
+	tramp_start = kallsyms_lookup_name(TRAMPOLINE_NAME);
+	if (tramp_start && kallsyms_lookup_size_offset(tramp_start, &sz, &off))
+		tramp_end = tramp_start + sz;
+}
+
+static bool ksw_watch_in_trampoline(unsigned long ip)
+{
+	if (tramp_start && tramp_end && ip >= tramp_start && ip < tramp_end)
+		return true;
+	return false;
+}
 static void ksw_watch_handler(struct perf_event *bp,
 			      struct perf_sample_data *data,
 			      struct pt_regs *regs)
 {
+	unsigned long entries[TRAMPOLINE_DEPTH];
+	int i, nr = 0;
+
+	nr = stack_trace_save_regs(regs, entries, TRAMPOLINE_DEPTH, 0);
+	for (i = 0; i < nr; i++) {
+		//ignore trampoline
+		if (is_ftrace_trampoline(entries[i]))
+			return;
+		if (ksw_watch_in_trampoline(entries[i]))
+			return;
+	}
+
 	pr_err("========== KStackWatch: Caught stack corruption =======\n");
 	pr_err("config %s\n", ksw_get_config()->user_input);
 	dump_stack();
@@ -168,6 +205,7 @@ int ksw_watch_init(void)
 {
 	int ret;
 
+	ksw_watch_resolve_trampoline();
 	ret = ksw_watch_alloc();
 	if (ret <= 0)
 		return -EBUSY;
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-10-wangjinchao600%40gmail.com.
