Return-Path: <kasan-dev+bncBCSJ7B6JQALRBCXI5OAAMGQEUO6VYHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DECD30E308
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 20:05:48 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id p6sf313502pgj.11
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 11:05:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612379147; cv=pass;
        d=google.com; s=arc-20160816;
        b=AsfJVbtvls7pxjz2/tSVpa239jHw1v/vxg7qlgvLPLacZGsfMsIlP03MwVwgEY7SK+
         7onTKnbAHOPiJHmmvTg5bvJ9AGYgEyRerRvyZyFqb14+tBpxPY1Ohrz/LVz78rMIp+TX
         QFj+bkKxEdznG8uxdcsANN4z5RY0+NSpVfkl/tQ/fBUYaLIw35MXXTdu8IjSU+I0uOCZ
         V8YcAjl1sLVDtQkkLRf+Xky63UfaRDkLCSXoxfTWI6mKuvevakWU2N109iIDY7dnYT/s
         RGtCdYKq6WmUIbXluZLanKBqQZKFvA3ZxsR0i9DsIJqXG+VOAquCrtTp4cGUqZGlbvik
         tfOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=P2RuirHAgXcPCjBpiYuw3pcydYVZFOpY/goE4pcoRy4=;
        b=F9pAqDtcLyMeRQC6xOfMIJIfDoeASjHRRAWisKVmEBesal43iSDtglL5wQb+0Qusif
         kBuG4n6f33dS6Ud0bKNkktyBbFH9qEAcxQzkTHBDM6e8DhbCMpzczrJIEA32ORxswLg4
         qoxE27yj2/U33xugv40Oz2VJrEbJ7fmn519kQqK4UX01XcVY6FFnYC4qrzATRtSXy/03
         4ySfkekkWv3cSkFs8gFVohFATO78vMGKkR6YICMrQddx6LNqsMirAEnRr0yph7pC+M5L
         RxEx5mPvSY0xzbAhibbDIvv7/yzmPQ5TY5fTvKtqvmUkFURVf+INgarnV4YAYmnt1mhw
         H+Bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ix0LqXjj;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=P2RuirHAgXcPCjBpiYuw3pcydYVZFOpY/goE4pcoRy4=;
        b=WmSCLsxoLorwN2P6BVAPV06rEhOSSPkuqnioC3aHRY29IbmMjNLDtH6pP0WeQMgNp8
         cnXQocWlNqpMtP1JDOsIe/iRnlX5t3DBzpVJLBXLBR6DKdPBeP9E0Kk0+SjxVtup5rmu
         za16aZr/C1MbVlH8HxJqBv4M5+U0TazYe+U78/LQfFUCNM+5LD4prLLztTVBUVA46bLa
         7FfNfruCdv/vDbaeOBt6e8YdtyLOOakdaVB0qq87LIcRbwk3sGJOqykCkU7AFGGsDA98
         YQw9r1PdoZ4T1NUMNQkDm+26WGQlkbn8kxLUPXklT6ddYoVJdH1KfYMlVV/rUZhQTTVC
         JAHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=P2RuirHAgXcPCjBpiYuw3pcydYVZFOpY/goE4pcoRy4=;
        b=Dt/CUNw7unaCAzwW/FrZ/OL/soZZBp8/of/gOerqY74GRpMobj7jXCS5bA/m+80H3Z
         4Lvco712GSugV3MC3oaC1LCXL2vg2HOrZ2wkx4w5bPufV4RhZPmjy6DoIWDgdjN9vkgw
         jaJt3ucSThd+mbwbAiOQsYd5L06GM+RE20coJkxzKfeikYmjA/KUsaPWo7DIh2V0WZ9M
         IMKQsCU2vVtIZ571ADwBRaqmDiaXwU92nhhigT46myQkAsweFoDmbFiizJDL450rSWnu
         cJxcvQz2v1zAGFONm6dozrU1kNumcKM2FOkX+o1gZKpGFtt68hLzzqaNTbqigtKfvLtY
         wE1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532vxBQ1FRZVUo+/HwLAQqMSlJ/I+I5aK/x5b68xW7UsSTfkanKX
	/lLB0je6C/n3vtrC1OITVaM=
X-Google-Smtp-Source: ABdhPJxNbb1QLezoVBuWhuZvcK7LqT1UIW6kc65kCamqPpv72Nd09QlIzNHm4TpGuY7MoguFrfVLAQ==
X-Received: by 2002:a62:27c2:0:b029:1bd:f51:33d with SMTP id n185-20020a6227c20000b02901bd0f51033dmr4419024pfn.45.1612379147010;
        Wed, 03 Feb 2021 11:05:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:19d8:: with SMTP id 207ls1246406pfz.5.gmail; Wed, 03 Feb
 2021 11:05:46 -0800 (PST)
X-Received: by 2002:a63:5351:: with SMTP id t17mr5008116pgl.176.1612379146390;
        Wed, 03 Feb 2021 11:05:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612379146; cv=none;
        d=google.com; s=arc-20160816;
        b=ET5TIr0wV7o8cst6XBBLKITnLHaqXFxRBNnoYvdSfLqso80+ysa6sQfPeOz+9wvdbz
         M4l8PDb31sUFA0a4TbTKoo7MJs9aZshDz0U4L5kcbOMCnBDP013Kjz6Y87ukkylgSBoB
         L4aoEob+H3IN/BiyhrdZukjHUG4Q6hReDWJDCjuknKiTRIe3sC3xjL3y/1DxhKHlckWp
         QyshRicIBiT+CehtM8t+C6W4jlFrw/fSoUlG7ZzVwYEHQY34wq7eu1bzwbjUwO1dXFn2
         7ttN5hI1mKHO/Z4tfIulRJUPgbek+MUQ/TN6bYgXHXKfFeERm//zJvIsFM32m1ejBjhe
         e2OA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=lFt/2RFOzQN6thk0J4a0+YNcEpiz/J/7UyVDz3HjZfM=;
        b=JkrmyoVWZQBdtfpz7F2n/2aSFo4F6nnlrw1N+Wf0ENM5lCriaURlMNsXZiGe9POoh2
         ep23HTzFKNpSN4jb+0toiGPS9Vu+jm7iYrCnzlKMZRE8Rediky+hIroq2zf6Z/V7GgTs
         uTZjvlZhbfXPd73IhxB+p+RhbqZXiCIQCD7PTm1n7LhoKT4Q8AiGU8GJ2cJJHs0CaB69
         I4GEoLaRGc1UbP9WMv9cYUFLX3GTlVoFIHur5p70OgXYcXEZj5VUZ7r9kE4y0LUfcwTq
         qM22BWBFIR66UQF/57rAQeSYDmd1id5OcKZHTQC1fzEw7pqU6oPSaUTTvtojv9hfolul
         UgHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ix0LqXjj;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [63.128.21.124])
        by gmr-mx.google.com with ESMTPS id r142si146229pfr.0.2021.02.03.11.05.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Feb 2021 11:05:46 -0800 (PST)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) client-ip=63.128.21.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-66-sTIcB_hWN7CUN9FEBbW0aA-1; Wed, 03 Feb 2021 14:05:41 -0500
X-MC-Unique: sTIcB_hWN7CUN9FEBbW0aA-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.phx2.redhat.com [10.5.11.13])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 127AA1083E90;
	Wed,  3 Feb 2021 19:05:36 +0000 (UTC)
Received: from treble (ovpn-120-118.rdu2.redhat.com [10.10.120.118])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 61D86709A9;
	Wed,  3 Feb 2021 19:05:21 +0000 (UTC)
Date: Wed, 3 Feb 2021 13:05:18 -0600
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Ivan Babrou <ivan@cloudflare.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	kernel-team <kernel-team@cloudflare.com>,
	Ignat Korchagin <ignat@cloudflare.com>,
	Hailong liu <liu.hailong6@zte.com.cn>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
	Miroslav Benes <mbenes@suse.cz>,
	Julien Thierry <jthierry@redhat.com>,
	Jiri Slaby <jirislaby@kernel.org>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel <linux-kernel@vger.kernel.org>,
	Alasdair Kergon <agk@redhat.com>, Mike Snitzer <snitzer@redhat.com>,
	dm-devel@redhat.com,
	"Steven Rostedt (VMware)" <rostedt@goodmis.org>,
	Alexei Starovoitov <ast@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Martin KaFai Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>,
	Yonghong Song <yhs@fb.com>, Andrii Nakryiko <andriin@fb.com>,
	John Fastabend <john.fastabend@gmail.com>,
	KP Singh <kpsingh@chromium.org>, Robert Richter <rric@kernel.org>,
	"Joel Fernandes (Google)" <joel@joelfernandes.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Linux Kernel Network Developers <netdev@vger.kernel.org>,
	bpf@vger.kernel.org, Alexey Kardashevskiy <aik@ozlabs.ru>
Subject: Re: BUG: KASAN: stack-out-of-bounds in
 unwind_next_frame+0x1df5/0x2650
Message-ID: <20210203190518.nlwghesq75enas6n@treble>
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
 <YBrTaVVfWu2R0Hgw@hirez.programming.kicks-ass.net>
 <CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82+jBLZ6KD3Ba6zdQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82+jBLZ6KD3Ba6zdQ@mail.gmail.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.13
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ix0LqXjj;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Wed, Feb 03, 2021 at 09:46:55AM -0800, Ivan Babrou wrote:
> > Can you pretty please not line-wrap console output? It's unreadable.
> 
> GMail doesn't make it easy, I'll send a link to a pastebin next time.
> Let me know if you'd like me to regenerate the decoded stack.
> 
> > > edfd9b7838ba5e47f19ad8466d0565aba5c59bf0 is the first bad commit
> > > commit edfd9b7838ba5e47f19ad8466d0565aba5c59bf0
> >
> > Not sure what tree you're on, but that's not the upstream commit.
> 
> I mentioned that it's a rebased core-static_call-2020-10-12 tag and
> added a link to the upstream hash right below.
> 
> > > Author: Steven Rostedt (VMware) <rostedt@goodmis.org>
> > > Date:   Tue Aug 18 15:57:52 2020 +0200
> > >
> > >     tracepoint: Optimize using static_call()
> > >
> >
> > There's a known issue with that patch, can you try:
> >
> >   http://lkml.kernel.org/r/20210202220121.435051654@goodmis.org
> 
> I've tried it on top of core-static_call-2020-10-12 tag rebased on top
> of v5.9 (to make it reproducible), and the patch did not help. Do I
> need to apply the whole series or something else?

Can you recreate with this patch, and add "unwind_debug" to the cmdline?
It will spit out a bunch of stack data.


From: Josh Poimboeuf <jpoimboe@redhat.com>
Subject: [PATCH] Subject: [PATCH] x86/unwind: Add 'unwind_debug' cmdline
 option

Sometimes the one-line ORC unwinder warnings aren't very helpful.  Take
the existing frame pointer unwind_dump() and make it useful for all
unwinders.

I don't want to be too aggressive about enabling the dumps, so for now
they're only enabled with the use of a new 'unwind_debug' cmdline
option.  When enabled, it will dump the full contents of the stack when
an error condition is encountered, or when dump_stack() is called.

Signed-off-by: Josh Poimboeuf <jpoimboe@redhat.com>
---
 .../admin-guide/kernel-parameters.txt         |  6 +++
 arch/x86/include/asm/unwind.h                 |  3 ++
 arch/x86/kernel/dumpstack.c                   | 39 ++++++++++++++
 arch/x86/kernel/unwind_frame.c                | 51 +++----------------
 arch/x86/kernel/unwind_orc.c                  |  5 +-
 5 files changed, 58 insertions(+), 46 deletions(-)

diff --git a/Documentation/admin-guide/kernel-parameters.txt b/Documentation/admin-guide/kernel-parameters.txt
index 3d6604a949f8..d29689aa62a2 100644
--- a/Documentation/admin-guide/kernel-parameters.txt
+++ b/Documentation/admin-guide/kernel-parameters.txt
@@ -5521,6 +5521,12 @@
 	unknown_nmi_panic
 			[X86] Cause panic on unknown NMI.
 
+	unwind_debug	[X86-64]
+			Enable unwinder debug output.  This can be
+			useful for debugging certain unwinder error
+			conditions, including corrupt stacks and
+			bad/missing unwinder metadata.
+
 	usbcore.authorized_default=
 			[USB] Default USB device authorization:
 			(default -1 = authorized except for wireless USB,
diff --git a/arch/x86/include/asm/unwind.h b/arch/x86/include/asm/unwind.h
index 70fc159ebe69..5101d7ef7912 100644
--- a/arch/x86/include/asm/unwind.h
+++ b/arch/x86/include/asm/unwind.h
@@ -123,4 +123,7 @@ static inline bool task_on_another_cpu(struct task_struct *task)
 #endif
 }
 
+extern bool unwind_debug __ro_after_init;
+void unwind_dump(struct unwind_state *state);
+
 #endif /* _ASM_X86_UNWIND_H */
diff --git a/arch/x86/kernel/dumpstack.c b/arch/x86/kernel/dumpstack.c
index 299c20f0a38b..febfd5b7f62a 100644
--- a/arch/x86/kernel/dumpstack.c
+++ b/arch/x86/kernel/dumpstack.c
@@ -29,6 +29,42 @@ static int die_counter;
 
 static struct pt_regs exec_summary_regs;
 
+bool unwind_debug __ro_after_init;
+static int __init unwind_debug_cmdline(char *str)
+{
+	unwind_debug = true;
+	return 0;
+}
+early_param("unwind_debug", unwind_debug_cmdline);
+
+void unwind_dump(struct unwind_state *state)
+{
+	unsigned long word, *sp;
+	struct stack_info stack_info = {0};
+	unsigned long visit_mask = 0;
+
+	printk_deferred("unwinder dump: stack type:%d next_sp:%p mask:0x%lx graph_idx:%d\n",
+			state->stack_info.type, state->stack_info.next_sp,
+			state->stack_mask, state->graph_idx);
+
+	sp = state->task == current ? __builtin_frame_address(0)
+				    : (void *)state->task->thread.sp;
+
+	for (; sp; sp = PTR_ALIGN(stack_info.next_sp, sizeof(long))) {
+		if (get_stack_info(sp, state->task, &stack_info, &visit_mask))
+			break;
+
+		for (; sp < stack_info.end; sp++) {
+
+			word = READ_ONCE_NOCHECK(*sp);
+
+			printk_deferred("%0*lx: %0*lx (%pB)\n", BITS_PER_LONG/4,
+					(unsigned long)sp, BITS_PER_LONG/4,
+					word, (void *)word);
+		}
+	}
+}
+
 bool noinstr in_task_stack(unsigned long *stack, struct task_struct *task,
 			   struct stack_info *info)
 {
@@ -301,6 +337,9 @@ static void show_trace_log_lvl(struct task_struct *task, struct pt_regs *regs,
 		if (stack_name)
 			printk("%s </%s>\n", log_lvl, stack_name);
 	}
+
+	if (unwind_debug)
+		unwind_dump(&state);
 }
 
 void show_stack(struct task_struct *task, unsigned long *sp,
diff --git a/arch/x86/kernel/unwind_frame.c b/arch/x86/kernel/unwind_frame.c
index d7c44b257f7f..6bcdf6ecad65 100644
--- a/arch/x86/kernel/unwind_frame.c
+++ b/arch/x86/kernel/unwind_frame.c
@@ -28,48 +28,6 @@ unsigned long *unwind_get_return_address_ptr(struct unwind_state *state)
 	return state->regs ? &state->regs->ip : state->bp + 1;
 }
 
-static void unwind_dump(struct unwind_state *state)
-{
-	static bool dumped_before = false;
-	bool prev_zero, zero = false;
-	unsigned long word, *sp;
-	struct stack_info stack_info = {0};
-	unsigned long visit_mask = 0;
-
-	if (dumped_before)
-		return;
-
-	dumped_before = true;
-
-	printk_deferred("unwind stack type:%d next_sp:%p mask:0x%lx graph_idx:%d\n",
-			state->stack_info.type, state->stack_info.next_sp,
-			state->stack_mask, state->graph_idx);
-
-	for (sp = PTR_ALIGN(state->orig_sp, sizeof(long)); sp;
-	     sp = PTR_ALIGN(stack_info.next_sp, sizeof(long))) {
-		if (get_stack_info(sp, state->task, &stack_info, &visit_mask))
-			break;
-
-		for (; sp < stack_info.end; sp++) {
-
-			word = READ_ONCE_NOCHECK(*sp);
-
-			prev_zero = zero;
-			zero = word == 0;
-
-			if (zero) {
-				if (!prev_zero)
-					printk_deferred("%p: %0*x ...\n",
-							sp, BITS_PER_LONG/4, 0);
-				continue;
-			}
-
-			printk_deferred("%p: %0*lx (%pB)\n",
-					sp, BITS_PER_LONG/4, word, (void *)word);
-		}
-	}
-}
-
 static bool in_entry_code(unsigned long ip)
 {
 	char *addr = (char *)ip;
@@ -244,7 +202,6 @@ static bool update_stack_state(struct unwind_state *state,
 						  addr, addr_p);
 	}
 
-	/* Save the original stack pointer for unwind_dump(): */
 	if (!state->orig_sp)
 		state->orig_sp = frame;
 
@@ -346,13 +303,17 @@ bool unwind_next_frame(struct unwind_state *state)
 			"WARNING: kernel stack regs at %p in %s:%d has bad 'bp' value %p\n",
 			state->regs, state->task->comm,
 			state->task->pid, next_bp);
-		unwind_dump(state);
+
+		if (unwind_debug)
+			unwind_dump(state);
 	} else {
 		printk_deferred_once(KERN_WARNING
 			"WARNING: kernel stack frame pointer at %p in %s:%d has bad value %p\n",
 			state->bp, state->task->comm,
 			state->task->pid, next_bp);
-		unwind_dump(state);
+
+		if (unwind_debug)
+			unwind_dump(state);
 	}
 the_end:
 	state->stack_info.type = STACK_TYPE_UNKNOWN;
diff --git a/arch/x86/kernel/unwind_orc.c b/arch/x86/kernel/unwind_orc.c
index 73f800100066..38265eac41dd 100644
--- a/arch/x86/kernel/unwind_orc.c
+++ b/arch/x86/kernel/unwind_orc.c
@@ -13,8 +13,11 @@
 
 #define orc_warn_current(args...)					\
 ({									\
-	if (state->task == current)					\
+	if (state->task == current) {					\
 		orc_warn(args);						\
+		if (unwind_debug)					\
+			unwind_dump(state);				\
+	}								\
 })
 
 extern int __start_orc_unwind_ip[];
-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210203190518.nlwghesq75enas6n%40treble.
