Return-Path: <kasan-dev+bncBD53XBUFWQDBBKFKT3DQMGQERBBCGZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb137.google.com (mail-yx1-xb137.google.com [IPv6:2607:f8b0:4864:20::b137])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A28CBC8A05
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:57:46 +0200 (CEST)
Received: by mail-yx1-xb137.google.com with SMTP id 956f58d0204a3-6365645caf2sf1943967d50.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:57:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007465; cv=pass;
        d=google.com; s=arc-20240605;
        b=UN4hDy/3on7X/O25G1zhsNktqMIABpcmbtkHGT3fvgGf8z4lJRWSMg7uM+/Oqh5vh+
         7FmoebajlAOUqfT9KBxHoIB1/PUuyvctCrt/pym9HpatA/oMx7oNx1EqH6BzRsPIIrPI
         KIZnikeehR0dwbzGXmPsZ4RvkJ5FaB4PfX998DsHlIixrnrJQQ1vgK+5Xv0NbyBK5P0B
         pj7zeF/R5fIEv089iilXh013VIrm+qsCA0UOjucUJLkodM13mM9qVx75FrVJbkqRQGEt
         UbCci1kZ326gbsoLNvAefyyra2sE6qI8Y36uB/zqXxJZN7D39YLq2U0+NNg80bomqWJY
         5Kcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=PzCgp8wluRF5XdeRJDFqjzS/gY022aZEpUNrY8eM8Uk=;
        fh=3ONxsQ7304ekrAWL76OzqVZBRw67nP3Iq0tE3CbD5YA=;
        b=Gsgvqvoyw0EjmjNkI2DvgNH3pGQkDRJvHhnuLJKXb8a+xJuUG4iv+lQy7F0En+CYJU
         aSr26lQjuMFAB6mQ4NQ5AYx0Kt+WUyxvCMQuCfnXq3CYbRRBxOagNmMHlmE8G9st47B8
         0o0SakbkZbdPgUpxRadkwIlE8f0T+LryaVo29HvScryX0YlSONrlrHSqJy8V5wktvXB/
         JOmcQbZekFv1uJfjLhv5Ux/8RGzoxvsXaTp4awws5JfrrmYGkKkckkaJu3KmZlW1vvrE
         WrqaHABjNQu6f1T1LdyG2i6T0+p7kiI00seROYfXeL/CL9AU3ICEAqAuMDpG4pfF9Xd+
         5q0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LjipN5lg;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007465; x=1760612265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PzCgp8wluRF5XdeRJDFqjzS/gY022aZEpUNrY8eM8Uk=;
        b=HWCurg736SiQfKPwzDJH0E8ZB8lKacnzEeMPv7Kau3+NjMkDDOh/ldUmGDs4hzntuh
         kUkkyMzpKIlgX10qN96YWOFoljv8OvKJxCfWomx+2wrQZqUAg66U4l0V8oU2aan5uiwl
         LjEqBgXITKuyyzGweSDoZycukX3PNfYOXse+8YalK2c4qCbdOht1cMTzaSETZK2YYLmR
         GcHbdpLqy5t4XdZhU6JYWQJejDytvS2LaBdtGcKrIqsNKdbmztLl/mDXA95BKtFiBCxY
         kOwTlQioWzt+KJ9AjNxS42vDu+UrigVzZLlPgCF+0TGYfN9Tqv+WP5PDBEdjfHFMi6t3
         fCzQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007465; x=1760612265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=PzCgp8wluRF5XdeRJDFqjzS/gY022aZEpUNrY8eM8Uk=;
        b=Rg/wx19Y3/JgNdJEyRND/olIMkIo0wLR/Fo3kMRn/4+9e4PPsV/NZ66P05aVRPcZOK
         SdkxMZJ7tTb8haFntDPQee4ZXgsvAw24L8Au9/X1E/hrgwqlxlzl+CgPLon4rUwiitS+
         rgfoMzbTXF5EhUjLwnzHdB+nGsxnS1+mPeLEvPiiRrnMfdnK3Jn7KlhXpMwDMS2iOA29
         uOY+8oVjhyurDXV/rPY9NydBXqlM8aMf2NcqKEuxJiaAV1aFGruy+uy7zCuzUXTwaIYe
         06jEmdA0xng9D1I1YMbwcYMoohtqz3vtIfftY9VXZjc3+Z5jm833kxxa16xZRsLghedu
         4Xlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007465; x=1760612265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PzCgp8wluRF5XdeRJDFqjzS/gY022aZEpUNrY8eM8Uk=;
        b=gd+2HUV/h4gC9mwQqV1R/l+r8fEnKyw8Nd7ShU/snVBfMBDFOJCnb5QmOQ1mRtDMEw
         mptc+ruizPGUC0+swXN+h9gBoCXx4Xq4SOwLXwyp0d9dVnr8EvCY6z+D8gOhBlMVaFar
         33Gupgwx48YUenUr6E0iIdf/1QOs/zWb31frwJr5HkJA2+dEKkhQlGzR16Dl32Er83uV
         +8YTrBFZ5rCPlrthXpQo4D23CQjT5u9dPF+MUToZd621fczBdoLMCrvjP2Bg4behHygJ
         fAEPWgh0lfSpRXJqD/v5e6EyLf/xgXS3IcuZW0w47UqL+XWrdzsujqItpkYBL5vsrmsj
         l7GQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWHWzGFaq45qsFSVZ5EdculQAFt3Fd4wh/PkOzu/n5xjCONbyUUIPnOjfU3hMWaHkcDJVq5Og==@lfdr.de
X-Gm-Message-State: AOJu0YxeJaCQiQwCg1R52IWBSMYgD7LFEHHGx8J/j43dz/DzD3brc+aW
	+TPB5kssJSAqh+on0CTRDxcKXSnLL+GVaSPE74qNnnlSt/VBs5oj0wJp
X-Google-Smtp-Source: AGHT+IFVa2j1rTCdnyGp4gmDH2k1RB6WKMJGxzBQrkZ92mWQJpHjwJ2sujQ5T6KksZIaOYl+I+cW0g==
X-Received: by 2002:a53:a081:0:b0:636:d364:4eb0 with SMTP id 956f58d0204a3-63cbe149709mr7570100d50.25.1760007465225;
        Thu, 09 Oct 2025 03:57:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7p5tf4FWZq8W8/G0g4Ipfzosb4Hs4fJ6kluoY6R8Jf+Q=="
Received: by 2002:a05:690e:1642:b0:636:1a72:4650 with SMTP id
 956f58d0204a3-63cd9885a03ls400332d50.1.-pod-prod-00-us; Thu, 09 Oct 2025
 03:57:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUOQY1SwQRuyCMwKj9avSp9hOwkTC/2sNzYkVZD0Uqrc+xZAhDt6fZDAKqNQq02NeX2LUe+j46b0Ck=@googlegroups.com
X-Received: by 2002:a05:690e:4250:b0:636:1f5d:b60a with SMTP id 956f58d0204a3-63cbe087551mr9198545d50.7.1760007464202;
        Thu, 09 Oct 2025 03:57:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007464; cv=none;
        d=google.com; s=arc-20240605;
        b=AOnE8KOncLwAJD2YAp3HKTAiip2z6mIgbRvLd+V63vdqmHlEakVNQcvpsN2G8dJmP1
         1keICFu1QzvoukejiN9MKlQ941hxodw15VrYHT60A0ISYmRL1/Ykv+M1q2rb/lD6KCjU
         t1PYN2cy1vijGpAOzhgehXXvl9B5ZCzz30MiTAI/zDEC7Weg1LWT2LnV5vrI4+hhMYUp
         OPYE8uo3UFqtmCWaMyPnHud/JgGwCVRtZUqFeLQU1/DPjGEUbtaNOCXd4coqn6mk69wn
         vNhRdQg+Rbk5ma7bvXz+GpeqdzbF8ChvKnIIzym6oigjUjsWX5ounMUQEtPFx112vzZm
         qI1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8p2Xfne7CGpLjN/MkaU3Ee28S3aCNgQ2oxnJpFebIbs=;
        fh=HFqRaK7+CQ/D/C5ctyomoIMqa6QjONwnwJ6OeKbYuGQ=;
        b=k7ctVAiRbYY1yZfdDB+DJgro47yE9wzbJ84xJ4n+HA8lkmzet8+RBqHqmBc35Kwmoq
         WkKzAG1B57NGBSmCncfCqmPwwlFg2CoJM6zZkijRrpGABTL+Cxij/uMLrVsQ8EUBNNuk
         CDwWzwP4TGCcsmB1GYmnoMW4Yhy8uDCZyCHP1Oe3qyjFzrUN/Mu6N0XPmAbcWndusIqV
         ySsOPTvMX99Raxkbf0hkCVtI69VHZP33QMsBQIoquNPz8MvXndVN5KwxhXvvwT+4XJRa
         E4tAvgNSrzimJuobmyhuwMzH6W/sEa8M0/4FkoNvNgBfiUsk+TNhAgSu+7RIW3y5dfc5
         zyNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LjipN5lg;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-780f624c72fsi751407b3.0.2025.10.09.03.57.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:57:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id 98e67ed59e1d1-3381f041d7fso2157516a91.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXLd4V1eD/ZyL5555OTxw83W4CopldlNTRSyLHBkiJrPXTh1mFKQ4M8cr0++tjlRQ0BPDUyji9JuZE=@googlegroups.com
X-Gm-Gg: ASbGncvCQzFKRxvVvlypOMC0pDjdwdUga0ogrFcJVOxKOf63b97rJG7hnNVFPM6ATt3
	KyvLPjzeAkPUTIVmaookhyl6qFzTcrihVEPL1K3zvj36b0Y23Qh+ozksKhpuey/fg/aY0VgAxyr
	LhnoeOocnDGGsWWY5ics43B8edcPZZszD2l+xBPKafBO0Ac4bD3ma8BaHHbDNsqE5SPcWKM4ffQ
	P+8mNS+WIYFtJYn/MVRNTp2QfyLL4RWGUp3RO8mjO4yATaVH/7R0ikTSdNes6NiRQ43i3MuVvdB
	KCPeMZLlX9YChOBj6ebV42lbLGgxNsfepmAid3CEmsgBIrYgVxq4FFc4TEfpaXXkuo0owV0/Nr9
	4nkonf+ZKckwdzR+6X27atumayC9B4jcLUdr9YBouBhkHNvcuMBf+/qBGXdRS
X-Received: by 2002:a17:90b:3e83:b0:32e:23c9:6f41 with SMTP id 98e67ed59e1d1-33b51676ef2mr8250254a91.5.1760007463200;
        Thu, 09 Oct 2025 03:57:43 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-33b52a4f8bfsm2196325a91.10.2025.10.09.03.57.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:42 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
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
Subject: [PATCH v7 09/23] mm/ksw: ignore false positives from exit trampolines
Date: Thu,  9 Oct 2025 18:55:45 +0800
Message-ID: <20251009105650.168917-10-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LjipN5lg;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-10-wangjinchao600%40gmail.com.
