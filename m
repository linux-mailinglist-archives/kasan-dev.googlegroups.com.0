Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWVN72NAMGQEWDNWN4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D929E6132D4
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Oct 2022 10:35:23 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-13bca69ac96sf5070912fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Oct 2022 02:35:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667208922; cv=pass;
        d=google.com; s=arc-20160816;
        b=b0WLsfr07Rar8vUtohDXZr0AHqk10N+lC67xo2neFPumN1vSj+SpYa7SNdwvYyod4A
         T6J6GAfnw767TWUiM95oHn0V2TWBOdNE08zCC2b9KF3K4pAMciaVsU3NH1YFhsVfjYsU
         Xif/e08q0lwEBy2OHTsfifqo63k6GTFF5wU48sTqi2Hkpz12m5UQZCn2anSgJFLbxYUu
         SKXkqoCVP0q501AevRQTw6TXbS2BxUkctvX5JfxQvxINQXV4Tkc3PgUy0jyqZFVKdy3e
         w0PbrMKo5z1lptiwz1gxC+fs0YwfHjlGZaMhJalGO6NGHFzalNacEZNgdCUXQ3MVrTPJ
         rZug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=y0bJzRnKGyErdn1ZtLsCkeHXkbHL5cWZz9yBD6iCg/Y=;
        b=nvDoo9RO1zt/LUEQRkZBdSZrtYNdBIYQ+IdgvR5Vb2i7PP1A0qiU4W5I1V4dpSKJWo
         YCpifrIxujII7L7nXhpBW+D2oE+leIebJ+YQwICu86jqA9QHxhbdKIg9qsHn0Fc2a2Dy
         SlYd/tPTTIgHoH0xaTyfMlWkBShIDRH/U7ZSgJT6hP4Z/P2RtO13PWDiV8/qYjSV8Y2F
         x3dldGbL4FGofKXga6nuZUfAR/O5VaJn+42eCdU+GIQ+HvXQzC+cbSv9fvir3U1MHjpl
         Fye+93pSjkNDS4VM+XgFaeTOTBzenQM3X74LCBR+CuagrTzzvdAhtiNEOt528Yaw5OKe
         dWmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GEZadzE3;
       spf=pass (google.com: domain of 32zzfywukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=32ZZfYwUKCaYKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=y0bJzRnKGyErdn1ZtLsCkeHXkbHL5cWZz9yBD6iCg/Y=;
        b=XjXMDe0yqz6npmGN6ioLSUucbndItHsrgDUkbyjpJj775bgXL1ZsWpi62lC+KkL4mm
         fK3JQDX0zdYLQIJLibO+C3P4+8NjpJZ1kHs0Dqegu41ABzLK5TXjEOPmdCj+x0SVtWqC
         iFHwLyiSRMloEk417Owznq3VruZbH3aIKo/0UJ8kgf3F8iG8mAgPPi5FAclK7WQ4nDof
         2mQVg1jfW0X3I0ci4sCaUxweA2jtRkAvxMFWqvOCKBNQmyLghTWk5kQ7oMi3xq5J1w8Y
         ZQBoi//lUhZAtIInq544sJeaMv/vOHN0sYCeaEuNHtRv+keAbFPBC4l03O3HvvRC0zsD
         XVzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=y0bJzRnKGyErdn1ZtLsCkeHXkbHL5cWZz9yBD6iCg/Y=;
        b=WxZTjGKeYE0hgAP8yneIGfm2tEB32n4VR5SHPS6Cdwkxd5+kKxHsQHaPh9q2YUxjEU
         r5mn1iabE9qDDeAVADUfzl6rKNRkLKxdBMq6MbItvkd7ixizJgvW5LozOBDjDdCIRZx9
         NtqoP5ZDInfUFgMc4RVus4ZckHcpzti6CHjX9I2NvrltJhfpHMdpWQJpszHcV2BekV6H
         3o4zUHZYJfAUAzVX205Yx2Ut4lQqKiQqcOswbwDwrNlUbOj2LYvm7dtlmn+rXLHsqFG3
         hLetJEPqjnIHxS1B7D1Zf5/hC+oj2p9ZzJOm/MHAzvrABsQV1dOLpTrzyNUS8N6v7Okh
         Bx7A==
X-Gm-Message-State: ACrzQf1MfLhtxYgKgIQ5YyUfQXtXyGSRytHxBc4j8YHQWAzlydPrKY0W
	H0zaWUDCDDKkg0ILwctNU5k=
X-Google-Smtp-Source: AMsMyM7oUBczDJBTVA6I28JVP43mpWhvumvrC1mOC8v7WOGR37HHZv23g5tlS0zWhnhbt+2sPMNWzQ==
X-Received: by 2002:a05:6871:7a8:b0:13b:8822:bf92 with SMTP id o40-20020a05687107a800b0013b8822bf92mr16257639oap.222.1667208922502;
        Mon, 31 Oct 2022 02:35:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4796:0:b0:661:f369:1f4b with SMTP id b22-20020a9d4796000000b00661f3691f4bls1530813otf.4.-pod-prod-gmail;
 Mon, 31 Oct 2022 02:35:22 -0700 (PDT)
X-Received: by 2002:a9d:5e84:0:b0:661:a58a:305f with SMTP id f4-20020a9d5e84000000b00661a58a305fmr5790590otl.137.1667208921931;
        Mon, 31 Oct 2022 02:35:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667208921; cv=none;
        d=google.com; s=arc-20160816;
        b=B9VfoWI5cT0RFCyvNvtPAR2nuEwNL4RYBnNvGm+xhfkhr78vaY6AhUrqQqOsUlVfoq
         DWvxdwvjuwMC6wZTamkdO7hyeb2mIpSaArroe7tJXTloGS7qnGAHt4Iop/O+soyhVRGA
         yLcWlJRfFLmqPXUpZzuz+jXwqeXnho9n7xf0p/OtqsJgr/R+9jl/T9fr2dm8ph1ycK3f
         0E9TkWsmSl5siF33S89aLh7JVKeuW1c+CokMrnMeur1Im5rbzxLyyPHrxn34GMlp2UF0
         69LAE9SPvunTAqu9q2s1zsOBMP3RcUDLInxFQlnlgfW6yt8xNKUrUvQVE8B8Zgj1NWUP
         SACQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=7abLUKvfL513QAFSaGq2FlNA+/gNLlKgxsoNfFkz71Q=;
        b=R13KmsS/pC9tf2M1Im28uiZWR5vrgbFwjxzHXpPEr7UlCSe/EPEQfsOXjcQf9SixxP
         YETFgoSCcXwSZGYznQauy3Bv9qMV9NWGddpj5R7sNzSFMTqvbecfr6gNCpcEGHZuUy/f
         TIuwFvfTCu5UyNh1P/cKVNztINuRmBmHnR6qx6Glc/2I45Tvo/jNGJbpJwiB7j816/LI
         rElU41WSWPO68QDeNJo5DGTj7xzYkIDr6GtdCOMtEJQsh+EkicOsqdptvmY+WasCBPYi
         lnQZWFE8J/HPlpYFUyFsBVaWB0MqpGoFEyV6bbwsd0KSFKYju0/IQBOBOLdgcHM/c5oR
         4rVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GEZadzE3;
       spf=pass (google.com: domain of 32zzfywukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=32ZZfYwUKCaYKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id p84-20020acaf157000000b00353e4e7f335si194413oih.4.2022.10.31.02.35.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Oct 2022 02:35:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32zzfywukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id p66-20020a257445000000b006ca0ba7608fso9882172ybc.7
        for <kasan-dev@googlegroups.com>; Mon, 31 Oct 2022 02:35:21 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3b03:2ab7:7f10:fc94])
 (user=elver job=sendgmr) by 2002:a81:5003:0:b0:368:40be:6e47 with SMTP id
 e3-20020a815003000000b0036840be6e47mr12022330ywb.477.1667208921550; Mon, 31
 Oct 2022 02:35:21 -0700 (PDT)
Date: Mon, 31 Oct 2022 10:35:13 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.38.1.273.g43a17bfeac-goog
Message-ID: <20221031093513.3032814-1-elver@google.com>
Subject: [PATCH] perf: Improve missing SIGTRAP checking
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, 
	syzbot+b8ded3e2e2c6adde4990@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GEZadzE3;       spf=pass
 (google.com: domain of 32zzfywukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=32ZZfYwUKCaYKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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

To catch missing SIGTRAP we employ a WARN in __perf_event_overflow(),
which fires if pending_sigtrap was already set: returning to user space
without consuming pending_sigtrap, and then having the event fire again
would re-enter the kernel and trigger the WARN.

This, however, seemed to miss the case where some events not associated
with progress in the user space task can fire and the interrupt handler
runs before the IRQ work meant to consume pending_sigtrap (and generate
the SIGTRAP).

syzbot gifted us this stack trace:

 | WARNING: CPU: 0 PID: 3607 at kernel/events/core.c:9313 __perf_event_overflow
 | Modules linked in:
 | CPU: 0 PID: 3607 Comm: syz-executor100 Not tainted 6.1.0-rc2-syzkaller-00073-g88619e77b33d #0
 | Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 10/11/2022
 | RIP: 0010:__perf_event_overflow+0x498/0x540 kernel/events/core.c:9313
 | <...>
 | Call Trace:
 |  <TASK>
 |  perf_swevent_hrtimer+0x34f/0x3c0 kernel/events/core.c:10729
 |  __run_hrtimer kernel/time/hrtimer.c:1685 [inline]
 |  __hrtimer_run_queues+0x1c6/0xfb0 kernel/time/hrtimer.c:1749
 |  hrtimer_interrupt+0x31c/0x790 kernel/time/hrtimer.c:1811
 |  local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1096 [inline]
 |  __sysvec_apic_timer_interrupt+0x17c/0x640 arch/x86/kernel/apic/apic.c:1113
 |  sysvec_apic_timer_interrupt+0x40/0xc0 arch/x86/kernel/apic/apic.c:1107
 |  asm_sysvec_apic_timer_interrupt+0x16/0x20 arch/x86/include/asm/idtentry.h:649
 | <...>
 |  </TASK>

In this case, syzbot produced a program with event type
PERF_TYPE_SOFTWARE and config PERF_COUNT_SW_CPU_CLOCK. The hrtimer
manages to fire again before the IRQ work got a chance to run, all while
never having returned to user space.

Improve the WARN to check for real progress in user space: approximate
this by storing a 32-bit hash of the current IP into pending_sigtrap,
and if an event fires while pending_sigtrap still matches the previous
IP, we assume no progress (false negatives are possible given we could
return to user space and trigger again on the same IP).

Fixes: ca6c21327c6a ("perf: Fix missing SIGTRAPs")
Reported-by: syzbot+b8ded3e2e2c6adde4990@syzkaller.appspotmail.com
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/events/core.c | 25 +++++++++++++++++++------
 1 file changed, 19 insertions(+), 6 deletions(-)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index 068412fe8dff..f87030487d9b 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -9312,14 +9312,27 @@ static int __perf_event_overflow(struct perf_event *event,
 	}
 
 	if (event->attr.sigtrap) {
-		/*
-		 * Should not be able to return to user space without processing
-		 * pending_sigtrap (kernel events can overflow multiple times).
-		 */
-		WARN_ON_ONCE(event->pending_sigtrap && event->attr.exclude_kernel);
+		unsigned int pending_id = 1;
+
+		if (regs)
+			pending_id = hash32_ptr((void *)instruction_pointer(regs)) ?: 1;
 		if (!event->pending_sigtrap) {
-			event->pending_sigtrap = 1;
+			event->pending_sigtrap = pending_id;
 			local_inc(&event->ctx->nr_pending);
+		} else if (event->attr.exclude_kernel) {
+			/*
+			 * Should not be able to return to user space without
+			 * consuming pending_sigtrap; with exceptions:
+			 *
+			 *  1. Where !exclude_kernel, events can overflow again
+			 *     in the kernel without returning to user space.
+			 *
+			 *  2. Events that can overflow again before the IRQ-
+			 *     work without user space progress (e.g. hrtimer).
+			 *     To approximate progress (with false negatives),
+			 *     check 32-bit hash of the current IP.
+			 */
+			WARN_ON_ONCE(event->pending_sigtrap != pending_id);
 		}
 		event->pending_addr = data->addr;
 		irq_work_queue(&event->pending_irq);
-- 
2.38.1.273.g43a17bfeac-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221031093513.3032814-1-elver%40google.com.
