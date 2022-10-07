Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5PAQCNAMGQETULBAGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 05FB55F794F
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 15:58:15 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id e1-20020a2e9841000000b002602ebb584fsf1955905ljj.14
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 06:58:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665151094; cv=pass;
        d=google.com; s=arc-20160816;
        b=W97pj/OzwgpyMN6OU0UPrOwSSMbSw2ms9f+wF1iL6PkbEFHKYAnc+mxjKyWwWhJExM
         KaMTjzDoA3LlS9GewG4VScWNCNNB5TuOBgIu3Hsf4W8tp14ZkSdeluaONKRTltiwV7Rk
         sdHzigcVzrykhv7L51+foNBM+OaTBXkxi7y7wMV88pYhPxCq74tZAFzM3UtXUm2xlDu1
         ljZNl0FQQvFB7jCvomhc+TP7KUvQ0QbJEJPohwQwSRCjEWA1d8F9NIcXAGSURxy2VAxL
         D1qPZha1QH1xJAyrW3vSJNPpvAtXooW7kVwTTrZfTaYBW3mAGbnAK++GJc+pXI72+9jc
         FHbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=SkInSbzO5EWPWOm1t6RfOaSivA6WcTHm7ecQTU5baqo=;
        b=gDHTKIRhyHyn771NOrawHlaF/JXPYutGbRd9ZHYpzkUViKce04FZH+HbvMK20pXJAp
         aKP8tjvkX3UIcFk/6X69LnfOkjAM958G6Y+W9sLJVSm6zmYy1JwFaRI1i19RrU1xmqP0
         LTiOKqo1qL8AH04WWPQgOyhVG4RBzkRI+vkaQvS+nl/xpOKX7c7KlCQzoUjr+zX5Qngj
         G+GLdJtSG6CraYFifFlwSIk8XTP4aDXmdF7dCLvWXdTRuqJiXODiFcH5sc0b6ybbSS8N
         qoHN+ZU6Q7TUxm1yzdcjlwPgUOXefC5Fan3sZvepDsVrOl9ELDfpHt7B9WP+3PfaMxrm
         j8yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cOU+Ngw7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=SkInSbzO5EWPWOm1t6RfOaSivA6WcTHm7ecQTU5baqo=;
        b=ewxHAOFRGR1YMWHfJZIpKBhfv9pzIsJJkSz8cPhMDm7TUROZsz3aUX4x8DQ2XF7d1F
         ny2V6Ti6Plpbxa90Vt0Mcg0E09FwzoT8pJfFD/NQ18rFykb0/CzvLA6YuWRCvf+Oau7/
         JfiFCmY9tA/UBBcGIxAurh1qp0QdTnt6FLQYxOqF93T2m2zhDLtNArOBmLAJJuk9gYTQ
         8Lmrhjnz/ASYRWpKsSKUBIRt4KVHOrN1IrcGocqK0MqUkXyxwyXeALhsATKHiXpXrklj
         WkRnoeoE6yGsZL6kePFzfbrXaF1B/ht7EBGfeDpCpi5/ZKtaMMfNEfL9i16bbqFPKDf7
         MXaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SkInSbzO5EWPWOm1t6RfOaSivA6WcTHm7ecQTU5baqo=;
        b=MHNGfQ/YWyQzgIc2grQA//pxLP9VO3q29iEeco3DRcZ6NeM8cyUEhtK2WIUbXQy5x7
         XoTyvV7i7hZBImQ8fEIWg06bWRjWlLgUIe720DQRbai6DlR3FnWk0JkBc9HeBcO+JZYq
         TStk7HUdUnGR9WiVXXtqBS5c/eAq4lNwY9LcID8ZMPKLth+20l+/8wRN+DhKxTG/97H4
         wgiNcx9x3j74mrxyfPRISteStKOY6LM2X6zKvtaebuiuvNadBB6dw6p4sgvakaevJ3V1
         YBTbO+U9LF0TX6KsmAbYRzGl3ImVEK35t1aqm8DiNM9zQVPK4J4W0bEPbaeqOWVMMO8u
         gWGw==
X-Gm-Message-State: ACrzQf2PbzD1v+5Lf0TVCLcRZtHKHJF5ndTxEY3rIqELfhnA3Hzpy8on
	ApDoBQR/B7Qtxw1QyFWbOcQ=
X-Google-Smtp-Source: AMsMyM4AluL91aFAdBhF9Gl13JoxgU/6rdF39wKRRvsfuBox5umx9pvTxymWQ4LBycfPys6a0UiAZA==
X-Received: by 2002:a05:651c:4cf:b0:26c:6cba:c57a with SMTP id e15-20020a05651c04cf00b0026c6cbac57amr1749163lji.288.1665151094061;
        Fri, 07 Oct 2022 06:58:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3607:b0:48b:2227:7787 with SMTP id
 f7-20020a056512360700b0048b22277787ls1368632lfs.3.-pod-prod-gmail; Fri, 07
 Oct 2022 06:58:12 -0700 (PDT)
X-Received: by 2002:a05:6512:1052:b0:4a2:7f09:4f1f with SMTP id c18-20020a056512105200b004a27f094f1fmr1908712lfb.59.1665151092374;
        Fri, 07 Oct 2022 06:58:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665151092; cv=none;
        d=google.com; s=arc-20160816;
        b=VWiGk22j9I19dzWB0GrRcLvhU1Az9KEnLaE+EpeUPalgihslxY1+KP+wBXLHVo5WVZ
         wDlrrYhQJ6lTJrXQRscNPFBKzb6V9OfSq+uUwH+XtMcZFWEbBMZdtB3qEBxaIwcCidK3
         sw04sFOAYaEmeG441NtSF4EFGCflgAtU3C4cioisfuX/bAFDAWUeRjCAzKxxSnGop2WQ
         5M/AsxDnrFx/7nQjyw7Vfghe2YRenY4sea4RydzgZFaidc7mo0caEmmhZ3j6HaCXdeVD
         hzaXpbSODk7SCBjtegkXRa3JL1Ca9IQzU3NCSyEDINnfE7/eajjJ1+QjBG1I+5TtO/rD
         34Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=AP/oJRI89Z7SdscCK80uHrEIj3Uy4MR+Wink1jXvZa4=;
        b=yOj2cVtAdk3HLMqNdJKWNHEWTOGG/QEfwKqLReQm9jRxBcRrUv3+ZghCCYB+oHsjgD
         JvjEq58AWgycHhvaARhclLt9Gg0IzK9hsvztk91e+FGnOKsRZJnzzIM8KmCcqnPt4sGx
         6WlM3bGbuoUEzYhaCYCzPMR65yZcaHMhNdrqZG8nf/5njjtP/6mkF/dZwHsb15/FMoFd
         hjHH6Qjqd3RtGbz34Z/EP+HjHmr9tx7Qqx3u+yZJjDhk4220pPtlBMAVLbK4nJPu4L1L
         L0/JL7RkjWFy0w9/OfKukVSCof3/8gBhsDGaNW8ntbmMUdHiT5/ZGZmoi9xQZvL1c7JL
         6dlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cOU+Ngw7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x630.google.com (mail-ej1-x630.google.com. [2a00:1450:4864:20::630])
        by gmr-mx.google.com with ESMTPS id o10-20020ac25e2a000000b0049ade2c22e5si93136lfg.9.2022.10.07.06.58.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Oct 2022 06:58:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::630 as permitted sender) client-ip=2a00:1450:4864:20::630;
Received: by mail-ej1-x630.google.com with SMTP id bj12so11418869ejb.13
        for <kasan-dev@googlegroups.com>; Fri, 07 Oct 2022 06:58:12 -0700 (PDT)
X-Received: by 2002:a17:907:2cd8:b0:776:64a8:1adf with SMTP id hg24-20020a1709072cd800b0077664a81adfmr4204610ejc.151.1665151091895;
        Fri, 07 Oct 2022 06:58:11 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:4e4:454c:b135:33f2])
        by smtp.gmail.com with ESMTPSA id o6-20020a170906768600b00773c60c2129sm1266134ejm.141.2022.10.07.06.58.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Oct 2022 06:58:11 -0700 (PDT)
Date: Fri, 7 Oct 2022 15:58:03 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs
Message-ID: <Y0AwaxcJNOWhMKXP@elver.google.com>
References: <20220927121322.1236730-1-elver@google.com>
 <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
 <Yz7fWw8duIOezSW1@elver.google.com>
 <Yz78MMMJ74tBw0gu@hirez.programming.kicks-ass.net>
 <Yz/zXpF1yLshrJm/@elver.google.com>
 <Y0Ak/D05KhJeKaed@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y0Ak/D05KhJeKaed@hirez.programming.kicks-ass.net>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cOU+Ngw7;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::630 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Oct 07, 2022 at 03:09PM +0200, Peter Zijlstra wrote:
> On Fri, Oct 07, 2022 at 11:37:34AM +0200, Marco Elver wrote:
> 
> > That worked. In addition I had to disable the ctx->task != current check
> > if we're in task_work, because presumably the event might have already
> > been disabled/moved??
> 
> Uhmmm... uhhh... damn. (wall-time was significantly longer)
> 
> Does this help?

No unfortunately - still see:

[   82.300827] ------------[ cut here ]------------
[   82.301680] WARNING: CPU: 0 PID: 976 at kernel/events/core.c:6466 perf_sigtrap+0x60/0x70
[   82.303069] Modules linked in:
[   82.303524] CPU: 0 PID: 976 Comm: missed_breakpoi Not tainted 6.0.0-rc3-00017-g1472d7e42f41-dirty #68
[   82.304825] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-4 04/01/2014
[   82.306204] RIP: 0010:perf_sigtrap+0x60/0x70
[   82.306858] Code: e6 59 fa ff 48 8b 93 50 01 00 00 8b b3 d8 00 00 00 48 8b bb 30 04 00 00 e8 dd cf e8 ff 5b 5d e9 c6 59 fa ff e8 c1 59 fa ff 90 <0f> 0b 90 5b 5d e9 b6 59 fa ff 66 0f 1f 44 00 00 e8 ab 59 fa ff bf
[   82.309515] RSP: 0000:ffffa52041cbbee0 EFLAGS: 00010293
[   82.310295] RAX: 0000000000000000 RBX: ffff902fc966a228 RCX: ffffffffa761a53f
[   82.311336] RDX: ffff902fca39c340 RSI: 0000000000000000 RDI: ffff902fc966a228
[   82.312376] RBP: ffff902fca39c340 R08: 0000000000000001 R09: 0000000000000001
[   82.313412] R10: 00000000ffffffff R11: 00000000ffffffff R12: ffff902fca39cbf0
[   82.314456] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   82.315561] FS:  00007fbae0636700(0000) GS:ffff9032efc00000(0000) knlGS:0000000000000000
[   82.316815] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   82.317708] CR2: 000000001082d318 CR3: 0000000109430002 CR4: 0000000000770ef0
[   82.318839] DR0: 00000000008aca98 DR1: 00000000008acb38 DR2: 00000000008acae8
[   82.319955] DR3: 0000000000000000 DR6: 00000000ffff0ff0 DR7: 0000000000000600
[   82.321068] PKRU: 55555554
[   82.321505] Call Trace:
[   82.321913]  <TASK>
[   82.322267]  perf_pending_task+0x7d/0xa0
[   82.322900]  task_work_run+0x73/0xc0
[   82.323476]  exit_to_user_mode_prepare+0x19d/0x1a0
[   82.324209]  irqentry_exit_to_user_mode+0x6/0x30
[   82.324887]  asm_sysvec_call_function_single+0x16/0x20
[   82.325623] RIP: 0033:0x27d10b
[   82.326092] Code: 43 08 48 8d 04 80 48 c1 e0 04 48 8d 0d 5e f9 62 00 48 01 c8 48 83 c0 08 b9 01 00 00 00 66 90 48 8b 10 48 39 ca 75 f8 88 48 41 <f0> 48 ff 40 08 48 8b 50 10 48 39 ca 75 f7 88 48 43 f0 48 ff 40 18
[   82.328696] RSP: 002b:00007fbae0635a60 EFLAGS: 00000246
[   82.329470] RAX: 00000000008acaa8 RBX: 000024073fc007d0 RCX: 0000000000001add
[   82.330521] RDX: 0000000000001add RSI: 0000000000000070 RDI: 0000000000000007
[   82.331557] RBP: 00007fbae0635a70 R08: 00007fbae0636700 R09: 00007fbae0636700
[   82.332593] R10: 00007fbae06369d0 R11: 0000000000000202 R12: 00007fbae06369d0
[   82.333630] R13: 00007ffe8139de16 R14: 00007fbae0636d1c R15: 00007fbae0635a80
[   82.334713]  </TASK>
[   82.335093] irq event stamp: 546455
[   82.335657] hardirqs last  enabled at (546465): [<ffffffffa7513ef6>] __up_console_sem+0x66/0x70
[   82.337032] hardirqs last disabled at (546476): [<ffffffffa7513edb>] __up_console_sem+0x4b/0x70
[   82.338414] softirqs last  enabled at (546084): [<ffffffffa8c0034f>] __do_softirq+0x34f/0x4d5
[   82.339769] softirqs last disabled at (546079): [<ffffffffa7493821>] __irq_exit_rcu+0xb1/0x120
[   82.341128] ---[ end trace 0000000000000000 ]---

I now have this on top:

diff --git a/kernel/events/core.c b/kernel/events/core.c
index 9319af6013f1..7de83c42d312 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -2285,9 +2285,10 @@ event_sched_out(struct perf_event *event,
 			 */
 			local_dec(&event->ctx->nr_pending);
 		} else {
-			WARN_ON_ONCE(event->pending_work);
-			event->pending_work = 1;
-			task_work_add(current, &event->pending_task, TWA_RESUME);
+			if (!event->pending_work) {
+				event->pending_work = 1;
+				task_work_add(current, &event->pending_task, TWA_RESUME);
+			}
 		}
 	}
 
@@ -6466,7 +6467,8 @@ static void perf_sigtrap(struct perf_event *event)
 		return;
 
 	/*
-	 * perf_pending_irq() can race with the task exiting.
+	 * Both perf_pending_task() and perf_pending_irq() can race with the
+	 * task exiting.
 	 */
 	if (current->flags & PF_EXITING)
 		return;
@@ -6495,8 +6497,8 @@ static void __perf_pending_irq(struct perf_event *event)
 	if (cpu == smp_processor_id()) {
 		if (event->pending_sigtrap) {
 			event->pending_sigtrap = 0;
-			local_dec(&event->ctx->nr_pending);
 			perf_sigtrap(event);
+			local_dec(&event->ctx->nr_pending);
 		}
 		if (event->pending_disable) {
 			event->pending_disable = 0;
@@ -6563,16 +6565,18 @@ static void perf_pending_task(struct callback_head *head)
 	 * If we 'fail' here, that's OK, it means recursion is already disabled
 	 * and we won't recurse 'further'.
 	 */
+	preempt_disable_notrace();
 	rctx = perf_swevent_get_recursion_context();
 
 	if (event->pending_work) {
 		event->pending_work = 0;
-		local_dec(&event->ctx->nr_pending);
 		perf_sigtrap(event);
+		local_dec(&event->ctx->nr_pending);
 	}
 
 	if (rctx >= 0)
 		perf_swevent_put_recursion_context(rctx);
+	preempt_enable_notrace();
 }
 
 #ifdef CONFIG_GUEST_PERF_EVENTS

I'm throwing more WARN_ON()s at it to see what's going on...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0AwaxcJNOWhMKXP%40elver.google.com.
