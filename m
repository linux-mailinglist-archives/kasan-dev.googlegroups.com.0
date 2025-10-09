Return-Path: <kasan-dev+bncBD53XBUFWQDBBPFKT3DQMGQETP332AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A57ABC8A1D
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:58:06 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-86df46fa013sf311100185a.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:58:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007485; cv=pass;
        d=google.com; s=arc-20240605;
        b=a1Bt0cctwp0V8SBTyg+GKlrFMfeiK+dChqQk8hqsU0qhsuFna4ltc/u35quswpSA5J
         PI4seOAH27PoCqBAQCcFsQYy5UsBtYqCS1WZivobPLE6V+bjJzU5n+p3QEyJQN1Aq5Fg
         5FVSOlvZmMGrbkni2qLcyCdq9XO4g31H/hzWaFtekFTh0vlMcxM8X3Yk8J6gzuybQzZE
         qLVHbKTIjq0t/z6ZohhIzzjy+So7aYTqd/v+5yD9aKNZqBtRD6lhGuuyn1NxaVIE7wT4
         4QPkmYfz3P8IT3JNJBVFjdlIxiSRaV1RKDwdwFGGIwvoDGOmrXOXnTLyz6rJh5Tbmmdm
         fAUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=g6svQQt8EFcY6doFUFeCe6UDilr3dPDLefsEwcT/BOA=;
        fh=3qSragcTkBQ24nPqah7jxVn8SVsqs0fFBo8/WJp47Xg=;
        b=kBmMVhgrcuFLOqpl3HL3AyHb6UYk4iEEQrJJxCnWM3MGv3hSb1WfAWsWcF+o+rnJ9A
         eptYsj3KUptLvexpqAqvL1eeb1rtNXEuRByaB0rPfQKJtSaICHzJye9axUCno/3EFa4A
         mEcsQcNKLu4OpvsWzjWP3zAFPDxQE61wa0fuTOy1j7rpHciBB5BzhCFGIgS0YdGYaCdV
         K1dixAp/Y0/NlUWSTbMETbZQmILjvg1SUIj3fmjtFhZjm9vopm1OO5cMOdnwzl522H1p
         IU+qqWmlBcJuyvIHmdYYalLXzhXrMdCIN8qeuqNEOV2ihYuDf3YEc2kmMB0vk8NSPgLX
         5m9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iTYJELCt;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007485; x=1760612285; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g6svQQt8EFcY6doFUFeCe6UDilr3dPDLefsEwcT/BOA=;
        b=LXdE4NF6AsxbTh2r/QJ9492vcMtF9I8ib3RtQtz23xHv/eO7hsEmoFb4z3puEn4wnM
         /Y2ARyv5gR2dTkULY59O+/Og1yljAQt/sXSTSjTuJowyXKdAro8/cHUZ2BJ4H1DCgidk
         GVmIWS6YzBgsWY+0MlL+7H2iadkM7UUOVH4rCCD/tXCyPkoov4wk8MrmXF5lquMbgbEo
         WC5bCqNZiLyz8GPrd9p/81bjxKPVWGE3kcJdCCCREFa88Y6QGxAW+tBRVlD3TByoNf1J
         LOCblVG++O4NUe4UhT3T3ZCJvpoR06wWPKpMt1EpzQXBmrN6DNR8qnJ04rc0YdxN2y5T
         hfUg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007485; x=1760612285; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=g6svQQt8EFcY6doFUFeCe6UDilr3dPDLefsEwcT/BOA=;
        b=gkV4WXJ3pUPArdJ8Bwq8yUduWMRtdfjO833vln446tZDkdZzfNznDwsu9rxNFE2OH9
         GGp1rzi0K9JFdF/jT2Cq5otXOvkG0rvyYgILgbPJX2QkCIzjdIAt6lHug/5soZS7cin1
         LTqgKYMiTzgOL54Kum8y4aaOuqodxcQRH7eauxMOaayomqeH92vX2TV/XRlRipbkmCul
         5uD/cC2a76nButC2AcFyB8fDW8r8UR9XIRetxFv3jNw8vQpLxso53ojZRd4ZhJsD//Cc
         PQRoo+covWxdECAso21EOYqhTQj3MoXi7IeVdIMiHnjS2LN3CN6pCsTh/nIY31XgbDF9
         LOMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007485; x=1760612285;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g6svQQt8EFcY6doFUFeCe6UDilr3dPDLefsEwcT/BOA=;
        b=vPD+Icz80sUNTeV0QkXpHhSzN6fnzoC0hFC724r2zzvkWAOnXOQOss8V3N5X7Ww6pH
         8KjIdyJuKOMlYFtdJun6KrNJnsaqK8Z1au4WVJOlecRaSuztJxtbe4mmCPnvqVPFV9Fu
         ix1zOaBjxZk7N1cBN+r9d4qCbeZ02AF5SwmdBQ4BmpjGWs6rXXxudJ8o5PdfCPjCjkBE
         VyOWrJXH/fcBNbQKAHocZHrbngB8b8juKdgnCkQzHN5fpXpeKFR0kpDZMJ3M73YSeDBv
         jXm0jCqsWipwvSIvD0jEN0EZlGQmaqAWBaElC1QPmuACXgss6BSI5JE6lkAAB1AW87RD
         9xaA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX+3crd8CDsq93gCEI1qPc20HTE5WCDd6h9eJLskMwVyGIP39HsmR3tYYQVq4tz0Iuh73lWPw==@lfdr.de
X-Gm-Message-State: AOJu0YyG3/n24Mp3oTNT0YG6JuCsa3jO/Sfu4Ba3JseeWriPw9XyZWFv
	s23KdDh8i06smyB6XuO5aFHrsPOPmjfPY2LxA8PhNKs9ZeWMFa5gzj57
X-Google-Smtp-Source: AGHT+IGRiQVOCu4NEHRPSDpLGL34oz2m7p8xDUghssjSkJW8aYSBWSUv01Scq/atPUEqpsVaRFpqSA==
X-Received: by 2002:a05:6214:76d:b0:81c:6455:ec77 with SMTP id 6a1803df08f44-87b2efb9b08mr81774726d6.40.1760007484791;
        Thu, 09 Oct 2025 03:58:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5DllLCt9TSZKPb2Oxsiy67NB5esOVCoDLEcEWPI1bWbw=="
Received: by 2002:a0c:f085:0:20b0:70d:b7e6:85e with SMTP id
 6a1803df08f44-87bb50a810bls11454826d6.2.-pod-prod-01-us; Thu, 09 Oct 2025
 03:58:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUOXyUMtMAPyOW5xRTWErQSqBBgZBeRBF1d7AOejk1qBTG7e3hiFj2Um+ciraC5f5blfQMZsoEJhjk=@googlegroups.com
X-Received: by 2002:a05:6102:dc9:b0:51f:d683:fd97 with SMTP id ada2fe7eead31-5d5e21fbc8bmr2732644137.5.1760007483898;
        Thu, 09 Oct 2025 03:58:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007483; cv=none;
        d=google.com; s=arc-20240605;
        b=aCv5U5VcJXSdW2CjA8Ola2vJ0WfDBPvVkTeJkoiKYegdWqa/rierMkS/mC8UBoYi6q
         FZ5eydLxve44kAPHhkMVmwwUWCcoZybSP9tvQTIZWxI64YLN6Ge1BPloSTLrrmjau/XM
         1bj8KLd1yFc77UXEH9OKfJOB0Hsts797MVS53SK8AA/HV6VNngXCs+6DbUyFpRHXAQHm
         z7zdp1XXKsLksdinQgGkGiD8ZKhBiqyebNjMcevJHLwVYlzuInlrEZ2EWbBQW2oNdvrj
         Bp8eU4dsH7/9t8g5DDCGbgGZB1aObQMl0x1wqoYN6JhqyVzjoveQ0eyYD3G2wUm36Om9
         q8Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1RtyZdLa/V9peD4vyIt7vF3g+yVd+tHG9wNYuCcZNH8=;
        fh=L3Z84mdMQH5g9lB3XQHEdI5VmfM7n5z9cZMOJ0kxJ+g=;
        b=NRosRQxODA8F0uD6axqQ6v5gY76EqqLJfSz/o23csFdqtpRA412xR8yrLwVl3K9eR8
         ezgmJI83GLH4sC2KJxJhuEfgetbZ04zy8RNRmIj/zKNyFycAUoYc8Q0CHDuqKxAjK8YO
         UQg1OeIguY2eZGeA//7XeD81mwhRmV8q1wmmKDjwBaSzkKxn6HCnyGYG8I1xQXLxEvfQ
         yvGbmhiF385RNY3+JtDKxccH/mGsM1rRVrtB2rSmuP9STcfmLoa9DiibvdsL4rNzTNFL
         +7iuzyy0AHVR7uVLsO/tC9x25qkCHxf8uOQYXKD3dT0CzTf+o5150IsRHhDh0S0FUOrz
         3NYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iTYJELCt;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5d5d38cb631si80161137.2.2025.10.09.03.58.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:58:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-78115430134so563788b3a.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:58:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXM9/UPZYb4GNdl5xz3pXd7OlrlOLpkBtakDGcQDN1nqMNUnh0o+a11YTKqUJBKs4BKVm9UE0L1Tds=@googlegroups.com
X-Gm-Gg: ASbGnctCKm+zQOcPjZZe0Vp4ye5WbWqokKnPcUKxQ2zzmHS2+VF81cL3lY26UZ8pH34
	v8DcVGMjfGmdLnmLkf4R+li/j4R7+iBfIj0dJfCCuDXWQCnhOWidhGnQzjuve4Ejg+6uMkaAl03
	uDJ02s5IA8Aw3j1z78NtrcrxkOKIW0YU6BqQ6VPt6Z9IT/ZiihNCVkVgGJSN9LBmPE1Hf07sCud
	oB5dO4MKG7iVsglOKUedljqfMboH6wd8hcmVz3b6UFr2QcKNQzrA5hRAKrLQmw1MESzVqcQk/Bn
	vGzJcyc+ucS/weYCRW4AMJYwofOZcK7wI5prxJfbYdH56Fr6ngRSjRGsMPCc3viAorKROirh8lw
	itkF5NsQRyNZ3mLlIkwsF86Dd/UiAAaFXfcHYo9S++6ljZDtduudIgLV1A5zEnLtXtESA0SA=
X-Received: by 2002:a05:6a20:12cd:b0:2f8:4558:ad9e with SMTP id adf61e73a8af0-32da839ee26mr9375118637.33.1760007482826;
        Thu, 09 Oct 2025 03:58:02 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b6099f3b041sm20711876a12.24.2025.10.09.03.58.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:58:02 -0700 (PDT)
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
Subject: [PATCH v7 14/23] mm/ksw: resolve stack watch addr and len
Date: Thu,  9 Oct 2025 18:55:50 +0800
Message-ID: <20251009105650.168917-15-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=iTYJELCt;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add helpers to find the stack canary or a local variable addr and len
for the probed function based on ksw_get_config(). For canary search,
limits search to a fixed number of steps to avoid scanning the entire
stack. Validates that the computed address and length are within the
kernel stack.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/stack.c | 77 ++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 74 insertions(+), 3 deletions(-)

diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index e596ef97222d..3c4cb6d5b58a 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -9,6 +9,7 @@
 
 #include "kstackwatch.h"
 
+#define MAX_CANARY_SEARCH_STEPS 128
 static struct kprobe entry_probe;
 static struct fprobe exit_probe;
 
@@ -59,13 +60,83 @@ static bool ksw_stack_check_ctx(bool entry)
 		return false;
 }
 
+static unsigned long ksw_find_stack_canary_addr(struct pt_regs *regs)
+{
+	unsigned long *stack_ptr, *stack_end, *stack_base;
+	unsigned long expected_canary;
+	unsigned int i;
+
+	stack_ptr = (unsigned long *)kernel_stack_pointer(regs);
+
+	stack_base = (unsigned long *)(current->stack);
+
+	// TODO: limit it to the current frame
+	stack_end = (unsigned long *)((char *)current->stack + THREAD_SIZE);
+
+	expected_canary = current->stack_canary;
+
+	if (stack_ptr < stack_base || stack_ptr >= stack_end) {
+		pr_err("Stack pointer 0x%lx out of bounds [0x%lx, 0x%lx)\n",
+		       (unsigned long)stack_ptr, (unsigned long)stack_base,
+		       (unsigned long)stack_end);
+		return 0;
+	}
+
+	for (i = 0; i < MAX_CANARY_SEARCH_STEPS; i++) {
+		if (&stack_ptr[i] >= stack_end)
+			break;
+
+		if (stack_ptr[i] == expected_canary) {
+			pr_debug("canary found i:%d 0x%lx\n", i,
+				 (unsigned long)&stack_ptr[i]);
+			return (unsigned long)&stack_ptr[i];
+		}
+	}
+
+	pr_debug("canary not found in first %d steps\n",
+		 MAX_CANARY_SEARCH_STEPS);
+	return 0;
+}
+
+static int ksw_stack_validate_addr(unsigned long addr, size_t size)
+{
+	unsigned long stack_start, stack_end;
+
+	if (!addr || !size)
+		return -EINVAL;
+
+	stack_start = (unsigned long)current->stack;
+	stack_end = stack_start + THREAD_SIZE;
+
+	if (addr < stack_start || (addr + size) > stack_end)
+		return -ERANGE;
+
+	return 0;
+}
+
 static int ksw_stack_prepare_watch(struct pt_regs *regs,
 				   const struct ksw_config *config,
 				   ulong *watch_addr, u16 *watch_len)
 {
-	/* implement logic will be added in following patches */
-	*watch_addr = 0;
-	*watch_len = 0;
+	ulong addr;
+	u16 len;
+
+	// default is to watch the canary
+	if (!ksw_get_config()->watch_len) {
+		addr = ksw_find_stack_canary_addr(regs);
+		len = sizeof(ulong);
+	} else {
+		addr = kernel_stack_pointer(regs) + ksw_get_config()->sp_offset;
+		len = ksw_get_config()->watch_len;
+	}
+
+	if (ksw_stack_validate_addr(addr, len)) {
+		pr_err("invalid stack addr:0x%lx len :%u\n", addr, len);
+		return -EINVAL;
+	}
+
+	*watch_addr = addr;
+	*watch_len = len;
 	return 0;
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-15-wangjinchao600%40gmail.com.
