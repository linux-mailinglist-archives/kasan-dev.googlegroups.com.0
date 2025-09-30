Return-Path: <kasan-dev+bncBD53XBUFWQDBBMUI5XDAMGQE7A3D74I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 61647BAB0C6
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:45:09 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-b4c72281674sf3313010a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:45:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200307; cv=pass;
        d=google.com; s=arc-20240605;
        b=dEoGFAH8vOiyfJzNJ0FOYH8OOdnnlVNZw8gcTjWHFsxjiez83m6Eo0cAABzOtas7wY
         35HmZwO8vz6C2j0I6Qi3B5PpjrAKUJYYMzmgCvXMr1f1+YKEZXTeF9jhWgjfaRPwce2Z
         XfM4R445UWz/59lxewfW3MKrk3auAw6Htuyss1b/claus+j63Us3PMRnhLGeRHoThUzP
         RchKgTtFSjNBcOhshPIitWIx0zg1pD/xw/94UDB/QOsFIXFwgw4TsgXi5gLf10qxZUVx
         fjmVdOIJh46ZYAVYyZkp8hBvPwjwhUs8l8YXrjBMQaEilwvUrea5a2Cuzwk16WCotM0e
         iV4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=86Bm+zg7iTjiIpnDNATLLBuuJyBfsHyQ5TpvAxUcZNo=;
        fh=Jb2ydAPsWy6TXM7X3R39pX8lScMPZJMqf4JCubQUq1U=;
        b=FjmKCC/ob3O0Ht8JOEHXX1RP38XMPMNWNFkFygDaMmm4aqJJBTMWf19C4CTMYVbOms
         3esw+P/Qv/uHLq5myWYoT0ZvFYrJ5hp6TQFHNe9xvNKHT1MhlIxqbUcOvQOCiWEwuaWM
         kF18dQbhbIFH8/Ri0niQSLZEY7eUqzzuwEbcV+7cfniOfHZIFEhK3UvkIkgfE0pdiHum
         kw2qw0NO7wILxkKKIoE+6aryEykYUNOiLyr3G7qcuX8H3ainJm384qn1MNyNDwKhdYpd
         7lfB+85MreC61vWSJLAQLv+HNDfWdvB8FLrwUjt9AjUuF6NMKgI7CncLKHvWz+J1vhzu
         r2WQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UKPVlwab;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200307; x=1759805107; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=86Bm+zg7iTjiIpnDNATLLBuuJyBfsHyQ5TpvAxUcZNo=;
        b=Ecqdco73vW6+7CjNXZd6peGLw/zy8K5FhIHdfNJ9Bsnkx/g9aKsPojuFAiS0MZd/w9
         m5zW0gYi+FvGjrh6X4wt+PTGuX1MIY9qfDloJ5XksTJy4MicMvTxNa6YjkKvnAzuRnEM
         CbuskYw05Ij8FM7NhbEG2+hWzd74RigSH/PHp51a+JlaDPulCWkz4LK5PIzsrbX3uYgD
         tsCVlMapIxbBy1wRfWeSLe4OsZBtIrzfrwvlqSJUmzOZKygAsWaobT+cUim+nNhauuke
         r0nTftNTKznGJ7Dh+6hWUH0lkF6x1KNbhV/RNV4ZeQeg2DPKZqts60GMA2UkrmaQ7qYy
         OwlA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200307; x=1759805107; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=86Bm+zg7iTjiIpnDNATLLBuuJyBfsHyQ5TpvAxUcZNo=;
        b=dXIHudGqi2ltHGbzzxsDw0BCjI1vI+zKpCQ+COn/EQ3kJrHPOZCNZIXaUpFPCCoyho
         rdLE1rBWdDSW8dvIFcRYXjCR/ZoYLD6Ihe6LIvVJOMgMOSSXj5DG/Da4JO5JKW8S7Jf3
         GxIpYhs9+8dTLyoHEegpwIjMMlGmVlLrdrU9oluW3KyFnhtupzwb9w3KLmAkKh0rxme/
         5aSy62PWHA5K0XlYK7exr/pVVBmLGzVvAEhikw/57m7t1EYx72+NSYOdU79kl4/NDdlK
         3mF2VTec4ndY6mrWy7d/qySbQ0tfTVfu0bRbVoI77bxeKIwWCe9q7dh8b3oHHlKtkQBh
         um1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200307; x=1759805107;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=86Bm+zg7iTjiIpnDNATLLBuuJyBfsHyQ5TpvAxUcZNo=;
        b=H3v3C8/+/s6Igwna8Rcs6gbq2T8y1pteepTMDxiuGtsCn80Ww5aVzzFFZUGZP7sOPw
         gY3OGtMXIgVMaiT88orEtBMiXj7Rt708jdOLAHUac6Lq9ZRCJj+2hCc2NvlDmxhhqdTg
         xpelprgVCj7/EUVTqePT66C+0R3E6DkuA6G1xXgtZfYlS8Mf+2ank+8E0J3sVZyo1yhY
         aUAh3JgIyv0PmH3w5YuqNlp/HxsJix+sUx14XyBqPEXsbTOmvx3gK+CpqGg+MubWQW5v
         khumDk2098KfwiV2xM/8yf+tlNbKnpS3qK5W8qOTuRkmcJj1qHpfM+FEXBWfh8ezAR7T
         YLcw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWJ2BI4MY0HcFqrzpmn1skX/7uBloF2zDDb/gRQlZYHsdd27P8Uv+jElkQR+FeE+5N2GJiXFQ==@lfdr.de
X-Gm-Message-State: AOJu0YzJ+2wiPt+pdw8oPQ/XnSQdCsOV4Dlu5FTHEn0GPquWUxt89y2Y
	oF9ru+72kp9amWHPxbAjyhLe9k9qyNC8HBZw2lj3FaxxN91O95toXQAy
X-Google-Smtp-Source: AGHT+IGED1PRb7YQnx23WPL/YcB5j+XljRm/hL4LOSI09EicOPKgJ6u3RJPMcdgFfNX1vXaaP1ymUQ==
X-Received: by 2002:a05:6a20:a109:b0:2ba:103:aa3b with SMTP id adf61e73a8af0-2e7d37f2d69mr21827723637.53.1759200307241;
        Mon, 29 Sep 2025 19:45:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd79SZHx6UghWY+vSmwUG+K2E+2k80IxPBNDGDykk80PYg=="
Received: by 2002:a05:6a00:2b88:b0:772:6b0d:37ce with SMTP id
 d2e1a72fcca58-780fee11f8als5786438b3a.1.-pod-prod-02-us; Mon, 29 Sep 2025
 19:45:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUGNyHxLXALgICcx27M/LgEjbB4kla4lqzkuC+VxCg8ogNeHAfomA6Mbfel1GXv/NbP59XxFMsW6wM=@googlegroups.com
X-Received: by 2002:a05:6a00:138d:b0:781:15b0:bed9 with SMTP id d2e1a72fcca58-78115b0c301mr17492067b3a.17.1759200305849;
        Mon, 29 Sep 2025 19:45:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200305; cv=none;
        d=google.com; s=arc-20240605;
        b=CTOfmj0x4piqWUmRpht8gidSowVBmLD16lK+7C5ogURaDFgrYRim8Ja/gB06KNKK9R
         ZMyO0J1FZkrg0QzOVl+cCA019zXwCnLF7hHUOdlLelIvWG+GaKrdp308/gTmhceqJhbc
         5NU/Jz0IKkdHZn2bpNVfYSwws4XiHwCt0o3+AXThB25l0s2kD0Z9HTHcYVkaoT55YU4X
         zpA0Fi99bq18S30B6R5m2SkmELtXzjE2mstxUYKybt8stJSuKn7FMV8nqIP6cj5DNiqs
         kCZX5Vxg0+tTN4fB/bees/TLYFA4rH7P7TqaclAp15eTIzJIEuqKMfeHC3SYmOfY3foI
         HQsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8p2Xfne7CGpLjN/MkaU3Ee28S3aCNgQ2oxnJpFebIbs=;
        fh=8ActSLDvrOKXuE9lRJ3OuNojfVlmyEAAa3G5CTGmjvo=;
        b=MI+FPDOuwqNzzD5wIlvJIHuj83Msi7eQYNfnoCytmmmONoYbOx+RghdpDtYpb64Vgh
         0UXqAuH3JsPHM72JGdqP0UJ41HERt8kR/E2v3FLrwy3pllt99o6+yjbCjfDjRFbAFD9N
         ItPrGc7r2sKNgssgABCw4fXwmvepIdUBwyH7x7jbCJQz1xDxKhoH05NRaUGyo7XIwdE2
         1CjTb9WnXofijhwJVsX3cex/K1xyAyuvf+gYXRvoBKBdhQ9QXbbF2Ui+QDIHe7SWrktR
         ugdjHAO6VTqY9qhaRDFfOyPNd3iQbkIIX0ahwpeJC3qSdjxh4tQIwqVJjgSTPSYurY59
         qEGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UKPVlwab;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-78102b59212si535668b3a.4.2025.09.29.19.45.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:45:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-7841da939deso1841380b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:45:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU9hotJ4wHAmP+dVGgVmq652jh4+YOpaxk9s8yf/3yeTwP7PLRxX3pFupIdB/6Az98zK/D/6cKlxco=@googlegroups.com
X-Gm-Gg: ASbGncs9jxI0BuVybAkYy3/XlezvR/jSx/yPmZuB4EWLR+6gJROyPDg1e56rL9/GR4h
	rWCqcn63Dm6hJfRiEmIJbzHJIBSCWmBFAp2sycD3Xtt1eKO8NIYOKPr6QWMI0RnmjeCtxKevsS7
	UE9dhMLR8kp2n03h6Mx6LCwS0qchRsGaY58FhCqP1MOZ0bYNkOuu6hhWJZq0uVA6pCcOPhAro/o
	/kTUb3kMwRgQYqMCenDDGYPZ2HBvV4CBuHOh9uQ2jIhpMVvn2URq5qZLAFEc/pBk9AP8rCly1fY
	kCXib51c+dAhum9pnl9mQIKS3EDO8Qdn5HjM1VGS+6LJ6CYZ4RLbAPj9QrcE3Wz7EFQacwi3TJ2
	EHhfe1w6sse3lVASGUr3GALitlQZ/Ya2m9e6Wd77wOrSVeMPlZRp+h7PBxmG15hb5XQ==
X-Received: by 2002:a05:6a00:1404:b0:782:d4b6:f5e5 with SMTP id d2e1a72fcca58-782d4b6f88amr8934209b3a.13.1759200305238;
        Mon, 29 Sep 2025 19:45:05 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7822f628080sm6431314b3a.89.2025.09.29.19.45.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:45:04 -0700 (PDT)
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
Subject: [PATCH v6 09/23] mm/ksw: ignore false positives from exit trampolines
Date: Tue, 30 Sep 2025 10:43:30 +0800
Message-ID: <20250930024402.1043776-10-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UKPVlwab;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-10-wangjinchao600%40gmail.com.
