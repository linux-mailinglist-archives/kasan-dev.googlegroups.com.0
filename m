Return-Path: <kasan-dev+bncBD53XBUFWQDBBTUI5XDAMGQEQO345QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id A5084BAB0E1
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:45:36 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id af79cd13be357-85dd8633b1bsf1219608585a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:45:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200335; cv=pass;
        d=google.com; s=arc-20240605;
        b=NHAtQFHGwFmiRYBFKYLIzKtS1Q//oFCnDw++s6Jb65BLYe4TXdqXA30cWQjzWv2Bhk
         2SFGlAycZxuSFty8S4RKyyzXWBY2zzZnx4eLnrvVSxUhbhK4Ez+mMQRj/MfSITk3STlL
         miNPpUGzP2yZNaKgQ8XByd1++S+kf/z5Ss+7PcisZfhtAt1NNlPx9B9RMzQXwLIWXP9z
         w5WKk2vTktybcneoJaLodhT9Oqwwkn4fC42OqMz6UIWrgvqUUEtvaEC+/1unML3PPcsI
         eNtd/3sM/t7RI+tFJWULW5wbT8+oH21gufEGM0TJ889THjWjYV7m+CFbereyPpZLhLIw
         KRbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=foFEc6vPNzUDEZvrfjdOvpEC17JKUckVFyZBEhPTe+g=;
        fh=I5AuVk79lUdkoPIk4Dv0uUw04VDue2r5OP8wjn9r6h0=;
        b=kPxxLXXay0vuMmOAe1Lsx13RwjsJCrIiTvyUzSXtoLHNKh9mkmAHCiiw+qSn0fVo7l
         iIe1XkWTrqHn+7+aS1PQV2H0+XypvFBUUn3gaK+QmDS9Si8eYu5an0wiANkGcBw+tk+y
         hNUZ0B+JbS8J+SLGIa8fkdk4Sxv3lRT3z/FYsDzbu92qpA7f8avOjwI+P0Vy8Vc+yscL
         VRr5XY1qvKDxVeAO0vjlCp/RS0n8z6B3h+ZwtYLYm8ezUBz1tOo0oqjKMaxbSE7KNmyS
         ocX96uTLpCKWmkxvYWZwDrToKcJTMqGTrgsKIwFiwbQbF+JNCjGP2ud3oQRsTxZ9DPdk
         dCmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KT7wwL8c;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200335; x=1759805135; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=foFEc6vPNzUDEZvrfjdOvpEC17JKUckVFyZBEhPTe+g=;
        b=RVwx/aJWL2f/82H7v9s8G7Nof0m7nLvwqGYlZF+GSulgjLCZtgLx9yDEoFE/hU1kUl
         n9yXr+bg9UNXklS/1ns+10NbqYd0VY4dVmPTMd2ougXYkWPO3W5cwCcyHzuuq+/ESDNF
         SoAWxyCK+ftDrjtuBl5cKuzCWaZgG4fUb7JCUE3Q2Ux41wvIYUq75ezSJfNoqbve0Klh
         r9g7zvlxQggQnKh7uiuxldOIkxCWd0pjMWAQGxYBm9KRltSll1A/KPE0Igx4I81K6TP1
         cl1MC6TfCTy6u0VdWMafL8xmpPRQmgNyrE+BzM+PQ6PuZ6uJrEy/evdxxQj2loJv89uw
         Gsfg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200335; x=1759805135; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=foFEc6vPNzUDEZvrfjdOvpEC17JKUckVFyZBEhPTe+g=;
        b=dxvcG6ZLDvX44+ezltcbOn1M1PwBxAH4nsjXkgOQyALjo3c17rGvyJDUOwpVk6HNol
         mqCJKw/IcudQxXEwbWTTdvlY/p3ETYtOW19Pt0YCRUBbiD2uwezng6+5qzcvwKkwhEn+
         4WulwaScErAoWUupzvd4e6dScTaaDDD6xKICbeA/Po2U6SPYMBKrHpN1+EtuVrQst6VE
         BvO4OdIoWaYq+/UPSvMKHkaa4SrQyCIN++XmWVWfZ3Y1zx7tsf2SEzcClxOCnC5J00xx
         bHZRd3FVwVufc3CWdop3idz+D0ShuRtObg+z5iKYV/585tlrQedyILTEj2kzI8leVPXs
         X/TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200335; x=1759805135;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=foFEc6vPNzUDEZvrfjdOvpEC17JKUckVFyZBEhPTe+g=;
        b=XmeXijbwxbs73JNEkxDxKfJo+HTvrq1rNIKg9USHItVg0k9xnI/pGu7tFZQ94BFKNC
         2GClV8w3rlsEAvjq3pmJRcTaFj/FROORbAH6f5ZgShwM/QLDAUcFK3KS1y7JkP74qk5h
         Gtso8x8yRZuFc5aecbQg+XowCkHN290wEzzCIxwaQchXYXEp+xB/SYd+gzkb0aCCD8AC
         n1ZfwnFDYWALf/15lBc0g6Oq4ia7MNKMUfnTC/HQ6IcfD80S4U+TyHx1c3Sb8BHQBGva
         5biv2+7FJws2b5vBSO1tU5eEFnrWreU8RxhQFmidtaNcRJQTKc0dic/FKIYNYdaFlMTm
         qDXQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU+F7/IypsOuj1STaeZxuGOQ7DOxZVY0II8JL7o/nXExIHg/YaIFrdCZovvuZjBkVzUSxWmJA==@lfdr.de
X-Gm-Message-State: AOJu0YzXa+zPSPqlV2FCyv7i9wFAnam+A7TsOQu/rut64irPcPXBAhnE
	dGtKiNPGhV1Wo6RvMjyKegncxnBSr5bK4KN9HaMcdQBwKbSN3Q8tplCa
X-Google-Smtp-Source: AGHT+IHtlI8QdcXvVF46uKNaYxYA+2bDI8PhtyWB1R8DUdc3LLTulsgmlT0t2iGPZTJiLv0hB3Hxhw==
X-Received: by 2002:a05:6214:2625:b0:78e:5985:92f1 with SMTP id 6a1803df08f44-869973a156fmr42523886d6.11.1759200335075;
        Mon, 29 Sep 2025 19:45:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd47OZZuogm6GpEpY9ZAoZSaS/qQ457aT4jkc0M2c3tgmw=="
Received: by 2002:ad4:56ee:0:b0:7ca:aa1f:8e39 with SMTP id 6a1803df08f44-7efe9e670fbls39095326d6.0.-pod-prod-00-us-canary;
 Mon, 29 Sep 2025 19:45:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXsHoNl5lRlPf2iB2L/z/IfIkAq/hQsg3reFXWOpPrhBO3LuZjpeU6f3USs8006vCtuTJ8j/c+mdzo=@googlegroups.com
X-Received: by 2002:a05:6102:3751:b0:4e7:be09:df07 with SMTP id ada2fe7eead31-5ced31efc0fmr1428999137.12.1759200334366;
        Mon, 29 Sep 2025 19:45:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200334; cv=none;
        d=google.com; s=arc-20240605;
        b=K5IjPnFACRrG/m+bGzbQ3EFeId988I5Yhuw7FkpJ7pd+2kc5MR4WZXOJJI0UuKcJHi
         Uv8fmBX8tQ5DroxZhM3K0u8XvIG21LCgzyRPMoTeGWuNa1CPl2DGg7KetXCq175Epeuu
         c2BtoMdLkgTkUVr3dy5llMC2sPwwOnte3n0CgCpCEKeUOzyFVlL0QJgz1xvmC8lNS+5x
         AmONSQlnQqYgvCFRQnxb1hs3sJNyrkam76bjVR5SVGlxLnob3UcGiGC49F7ee6npyUXm
         gu7Pdw4d5IieJkiRr5WQGAPI8vbqHQYTpZ88mKc6n9de3/xGZf5PEInTbgu6zY+GtKtI
         txdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1RtyZdLa/V9peD4vyIt7vF3g+yVd+tHG9wNYuCcZNH8=;
        fh=3PtdRsIwz0H0vV7OT66TT472QewYZczyPodaHZiEKwg=;
        b=GxFjaMqfKSb1i/rWgQ0OqJ9BNFrXCE7iMPShQhNh4bf2QNNw2U+bIqjr5Kfo/TXk2q
         4UAYo2tEnLQiv4xLRhv+hrwcDJ/TVb5eqU9tfji1XC8HkY5qiW6uugfnQkS62bocGI1z
         F6cu5WYpDlqCWOrZiD3pubCFoiy79lmn6IYc82/fMyYclpZOZeCivfaP8zFTmtXTmGin
         3JyDTo/rVZN0/jLBef7+5fou6BDtjbjNeUAn6gum4rgf5EFRXeh9uOdpKx3tp1wOEWJi
         NoPkqrmQR+phgRsvOQ7RZhBjso7Q84qHfb+PXUBAElCCmEXYWWfyE/2HxjgK2DdAPB37
         f5EA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KT7wwL8c;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5ae3333204dsi602980137.2.2025.09.29.19.45.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:45:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-78118e163e5so2786945b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:45:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVU1wRMLKkoySeD8x3ZA9NZ4F7JQ22c8RQUaqKJDtzm/84qSboKM+BYTBZ99tIyciAI4+DHPflIjIU=@googlegroups.com
X-Gm-Gg: ASbGnctmc0vGbo7ItQjnT7z6/C3OsaODK/5DjzH5ouJdYbMrTyuKMyydwVm1/KdQo1f
	oMHmx7chIEsZN8szyTpTaLUXet2WGc+I5Ra6KXFhcEua9fXcw9ZAPtBG5bjV0JKYyADBLMowgr9
	EnBIpGbnnMSz0cnRkli1Yv1GkEPhCQczpxa5yKRKND6hoiHNmnBQgS6C9gMO+ju2XTRUn92/7EB
	mgch60w3btQqNy0cjYFskEV0WbgW2oRD7UdGJLQJrA99wq5rcccsylfIWTi1NsdV8J6wvZI7Qh5
	vM/Jwi/wV9mHV1ebYroSQcazptT0jdXCIJrkF3uQvXSlUamXJeJZdLg0jHdkaDbO4EvZDtuCIO1
	6QVrRUoHCQKQYnBrYTlVxyfmsK2L19oT8zV+9OsAEpxB6wDbQ6o6hA+s5bJ14z6/F8W7V1j6/j5
	qX
X-Received: by 2002:a05:6a20:9c8c:b0:248:ef8:66df with SMTP id adf61e73a8af0-317732b6b3cmr3072325637.30.1759200333340;
        Mon, 29 Sep 2025 19:45:33 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b57c53bb255sm12683002a12.5.2025.09.29.19.45.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:45:32 -0700 (PDT)
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
Subject: [PATCH v6 14/23] mm/ksw: resolve stack watch addr and len
Date: Tue, 30 Sep 2025 10:43:35 +0800
Message-ID: <20250930024402.1043776-15-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=KT7wwL8c;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-15-wangjinchao600%40gmail.com.
