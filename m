Return-Path: <kasan-dev+bncBCSJ7B6JQALRBEWL5WAAMGQEWCR7QTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EB1230EAAD
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 04:10:11 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id n2sf1164427pgj.12
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 19:10:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612408210; cv=pass;
        d=google.com; s=arc-20160816;
        b=0dDYNZzzbM+WwB8VdhCpDR9gDhkYkkFXQ4ChAkqjPXppN4f3P1xvNhI3PlejYGtGa2
         Ekg74OFiRBLmkNptfeCFxj7IBILL8vr0DBLTZkqLk38W6lAgYp/egtUSBIcmsGuC9qlp
         eE6zOjMd0RS7RRg/bgG38ZfvFT5ilWzNqJVQ4leF8C2swO8mU9EP+il9pvyDFBEipSyf
         DFyrT9ArtAbVRIhhhSp6uq3EAKRobPNKa4wGBasfKQdgAO0xJM+PkIeEvgsJW0yU25jZ
         TT571+XtPfb032Mqb3KEemIZSv5xXrVPdbse3jQipzwUEqvKGy9heKUyosUO23/8h63C
         WQxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VCABQ9XPVaGkKcl7B7svrXEr4ALi0thF3PBMTCAwi/s=;
        b=XJOjWBntqvWYcPqU2cL+M0ZkKUOISIRPWFZgx6GRNSxU9EBiZ90Iwrm6x0NCljSMNE
         aYXkDU5jduGczIhw68sHiBeCZDIggMi436hhlrIKFd3GwGCzh/15qZcBV/YbhDHsxnhZ
         i+IYzSg+3CElYErQuElPX9aOEeaD3KEeTfjBUH9Ss1AwlIYUDTZPR+hrV9IRtvFyJU3G
         fPvmgTKnkJ3vhCNt7YaSfQTyrjxYBANuNUFygfeJ/uMaK1Mh6cAk766mr6yD57UYJ//d
         Fikk/4MUs+RVvYrFIAzZY7YFVyZUX2aJJYcS9Hd7o8jmSDykxXnDM65ZnLNSojiX49Lt
         o4IQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JibjivYQ;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VCABQ9XPVaGkKcl7B7svrXEr4ALi0thF3PBMTCAwi/s=;
        b=ZLVbNFezAFd3sVSFaugzWiAFDkG8czapef9Y7/XKl8U3PKd4WXVkRJmmWku+GD7mmH
         7Mg9nCEYUijBvZfU2KgTcUHIwE5ZGjsXmzQwef1WJhsWS5zearUYBkVZZcDZgSZc1P69
         qgx6kpHydIRXgNA2sxR9l86raKZkfVT2wx8nsD6bN9RLhf+GFoJE89zdx/oSM116MuWV
         7UdCzLPOXOdxvpyzVRfy1K7prZqLzg6k371p3gCnwm8kHOw+AIFMhFeSPtrjsWhejmJm
         /j/c//swBVtF4qpwnqAlsHHT9OooeZx1OB5elvrLwXYKOW2ofvsgz7+TbJykD5mEIt/9
         5iXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VCABQ9XPVaGkKcl7B7svrXEr4ALi0thF3PBMTCAwi/s=;
        b=EBVo3+Byte931852aZTCPVb+4gDp1MnHAqDVD3yzcl8fJKkWWkbaES9HTALAPx2fDD
         jqkkuj1METGRFV8lRPApa++ZUDFbOIOuJn8K3j38VZ5meN2NxtvGuOyD5Njxr6rCcX2G
         joo+jPDFT4G0x/r+RBawfCya7ioGXjXUKECbjAYzTCjvDiixhtfRx7j2GmY2LNM9bGsN
         f7F/VhtQC+bY1vYf2PQKiQSLZ775KEAUQrm61jgoOaYHFsnynkX6ZuCYe4AHIL6y/qmn
         u2o2pCPGrMIDctB/y8umQjN/f1umujunadrucH82TwUzskqDWghVCdYriCHiV8X4KANF
         6Vgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531e0qKr4TeiT7SH+3/6fzX7I9sSXEsiiAynsHIDghWnFQip8aay
	Y/adEA51ppl/Ralt2eQByDk=
X-Google-Smtp-Source: ABdhPJwBDAaiSicJqto88FoW2gOEuszZCHNygoPnyPT2EVHXHoFzOB6UlhgVp5YKf7Vf9MPMWOb1oQ==
X-Received: by 2002:a17:90b:4004:: with SMTP id ie4mr5985857pjb.114.1612408210262;
        Wed, 03 Feb 2021 19:10:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a707:: with SMTP id w7ls1972742plq.9.gmail; Wed, 03
 Feb 2021 19:10:09 -0800 (PST)
X-Received: by 2002:a17:90a:7c08:: with SMTP id v8mr6043006pjf.135.1612408209625;
        Wed, 03 Feb 2021 19:10:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612408209; cv=none;
        d=google.com; s=arc-20160816;
        b=UVXT8Szpp7zdLYHfq9h0k4IgACWgUZ9cSaPf0S1FXFeeot5eBW48hU22TfehdcV/tH
         Bj52eJyMbdBQxx+me00NX30yG7gFdYD0sZEXjCBhLzcBWBR5aUth2jFcYHJeZjYyl0c+
         hvLennE9k4uakW+tAxKb0QvF8GqAR7cZ44uB62JXQTW5fLEZsrOJYJk8C3/utJyQCv0v
         WNd+cl9shCulRXGI/nXVaa7ekMm0sukzTcUB5loOjQlo6oDg+29uAyHwayrWVgdFZeLu
         2B5ifFKa0dUyaeXHWm0H4r/lLFfP4AMKTXLXpdLO+ChhgQqTBJqV8pLsn/QiK7ghiXoa
         quuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WDe1YdsK6j3zvzS2L+ASbGFdSYX+IgK0d+X+vIareuk=;
        b=dqZc05z5OKva1vWEoaYAxVZYp99YhwQ7kVaNjiZ2C/ZIpcg9o2lG1sbRVjTGBjYnBQ
         i/hocWr1HAsKrNRJ8CtedDcR48nnP/rAhpAZeyiJhEqWt4CXL64SVZJCwhHRvTf/FqQ+
         499XmZPoIvN+VJpAGkTZwHeFI5Qbo5SsLucMprKWXmi8YYq68ESI3e5zNKIok30ZC3sQ
         gw71S0ap7XJX1bFgS6a26zMjb3JxROgJVW8QFrttJV8tG5nHEwDIIvWBaa0smVi4Vds0
         dBzmQFh3sd4HAdNwCrK0lJSqPwB3+Y2m5jqX9HhEY5GvBQyzv6P1fwg7sWlWWZ7oygEr
         9IyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JibjivYQ;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [63.128.21.124])
        by gmr-mx.google.com with ESMTPS id c17si188870pjo.0.2021.02.03.19.10.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Feb 2021 19:10:09 -0800 (PST)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) client-ip=63.128.21.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-572-NjSn-vCKMfOiTb3L3kvbDg-1; Wed, 03 Feb 2021 22:10:05 -0500
X-MC-Unique: NjSn-vCKMfOiTb3L3kvbDg-1
Received: from smtp.corp.redhat.com (int-mx04.intmail.prod.int.phx2.redhat.com [10.5.11.14])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 1C8F3801963;
	Thu,  4 Feb 2021 03:10:01 +0000 (UTC)
Received: from treble (ovpn-113-81.rdu2.redhat.com [10.10.113.81])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id D31EF5D9C0;
	Thu,  4 Feb 2021 03:09:50 +0000 (UTC)
Date: Wed, 3 Feb 2021 21:09:48 -0600
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Ivan Babrou <ivan@cloudflare.com>,
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
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Julien Thierry <jthierry@redhat.com>,
	Jiri Slaby <jirislaby@kernel.org>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel <linux-kernel@vger.kernel.org>,
	Alasdair Kergon <agk@redhat.com>, Mike Snitzer <snitzer@redhat.com>,
	dm-devel@redhat.com, Alexei Starovoitov <ast@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Martin KaFai Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>,
	Yonghong Song <yhs@fb.com>, Andrii Nakryiko <andriin@fb.com>,
	John Fastabend <john.fastabend@gmail.com>,
	KP Singh <kpsingh@chromium.org>, Robert Richter <rric@kernel.org>,
	"Joel Fernandes (Google)" <joel@joelfernandes.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Linux Kernel Network Developers <netdev@vger.kernel.org>,
	bpf@vger.kernel.org
Subject: Re: BUG: KASAN: stack-out-of-bounds in
 unwind_next_frame+0x1df5/0x2650
Message-ID: <20210204030948.dmsmwyw6fu5kzgey@treble>
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
 <20210203214448.2703930e@oasis.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210203214448.2703930e@oasis.local.home>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.14
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=JibjivYQ;
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

On Wed, Feb 03, 2021 at 09:44:48PM -0500, Steven Rostedt wrote:
> > > [  128.441287][    C0] RIP: 0010:skcipher_walk_next
> > > (crypto/skcipher.c:322 crypto/skcipher.c:384)
> 
> Why do we have an RIP in skcipher_walk_next, if its the unwinder that
> had a bug? Or are they related?
> 
> Or did skcipher_walk_next trigger something in KASAN which did a stack
> walk via the unwinder, and that caused another issue?

It was interrupted by an IRQ, which then called kfree(), which then
called kasan_save_stack(), which then called the unwinder, which then
read "out-of-bounds" between stack frames.

In this case it was because of some crypto code missing ORC annotations.

> Looking at the unwinder code in question, we have:
> 
> static bool deref_stack_regs(struct unwind_state *state, unsigned long addr,
>                              unsigned long *ip, unsigned long *sp)
> {
>         struct pt_regs *regs = (struct pt_regs *)addr;
> 
>         /* x86-32 support will be more complicated due to the &regs->sp hack */
>         BUILD_BUG_ON(IS_ENABLED(CONFIG_X86_32));
> 
>         if (!stack_access_ok(state, addr, sizeof(struct pt_regs)))
>                 return false;
> 
>         *ip = regs->ip;
>         *sp = regs->sp; <- pointer to here
>         return true;
> }
> 
> and the caller of the above static function:
> 
>         case UNWIND_HINT_TYPE_REGS:
>                 if (!deref_stack_regs(state, sp, &state->ip, &state->sp)) {
>                         orc_warn_current("can't access registers at %pB\n",
>                                          (void *)orig_ip);
>                         goto err;
>                 }
> 
> 
> Could it possibly be that there's some magic canary on the stack that
> causes KASAN to trigger if you read it?

Right, the unwinder isn't allowed to read between stack frames.

In fact, you read my mind, I was looking at the other warning in network
code:

  [160676.598929][    C4]  asm_common_interrupt+0x1e/0x40
  [160676.608966][    C4] RIP: 0010:0xffffffffc17d814c
  [160676.618812][    C4] Code: 8b 4c 24 40 4c 8b 44 24 48 48 8b 7c 24 70 48 8b 74 24 68 48 8b 54 24 60 48 8b 4c 24 58 48 8b 44 24 50 48 81 c4 a8 00 00 00 9d <c3> 20 27 af 8f ff ff ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00
  [160676.649371][    C4] RSP: 0018:ffff8893dfd4f620 EFLAGS: 00000282
  [160676.661073][    C4] RAX: 0000000000000000 RBX: ffff8881be9c9c80 RCX: 0000000000000000
  [160676.674788][    C4] RDX: dffffc0000000000 RSI: 000000000000000b RDI: ffff8881be9c9c80
  [160676.688508][    C4] RBP: ffff8881be9c9ce0 R08: 0000000000000000 R09: ffff8881908c4c97
  [160676.702249][    C4] R10: ffffed1032118992 R11: ffff88818a4ce68c R12: ffff8881be9c9eea
  [160676.716000][    C4] R13: ffff8881be9c9c92 R14: ffff8880063ba5ac R15: ffff8880063ba5a8
  [160676.729895][    C4]  ? tcp_set_state+0x5/0x620
  [160676.740426][    C4]  ? tcp_fin+0xeb/0x5a0
  [160676.750287][    C4]  ? tcp_data_queue+0x1e78/0x4ce0
  [160676.761089][    C4]  ? tcp_urg+0x76/0xc50

This line gives a big clue:

  [160676.608966][    C4] RIP: 0010:0xffffffffc17d814c

That address, without a function name, most likely means that it was
running in some generated code (mostly likely BPF) when it got
interrupted.

Right now, the ORC unwinder tries to fall back to frame pointers when it
encounters generated code:

	orc = orc_find(state->signal ? state->ip : state->ip - 1);
	if (!orc)
		/*
		 * As a fallback, try to assume this code uses a frame pointer.
		 * This is useful for generated code, like BPF, which ORC
		 * doesn't know about.  This is just a guess, so the rest of
		 * the unwind is no longer considered reliable.
		 */
		orc = &orc_fp_entry;
		state->error = true;
	}

Because the ORC unwinder is guessing from that point onward, it's
possible for it to read the KASAN stack redzone, if the generated code
hasn't set up frame pointers.  So the best fix may be for the unwinder
to just always bypass KASAN when reading the stack.

The unwinder has a mechanism for detecting and warning about
out-of-bounds, and KASAN is short-circuiting that.

This should hopefully get rid of *all* the KASAN unwinder warnings, both
crypto and networking.

diff --git a/arch/x86/kernel/unwind_orc.c b/arch/x86/kernel/unwind_orc.c
index 040194d079b6..1f69a23a4715 100644
--- a/arch/x86/kernel/unwind_orc.c
+++ b/arch/x86/kernel/unwind_orc.c
@@ -376,8 +376,8 @@ static bool deref_stack_regs(struct unwind_state *state, unsigned long addr,
 	if (!stack_access_ok(state, addr, sizeof(struct pt_regs)))
 		return false;
 
-	*ip = regs->ip;
-	*sp = regs->sp;
+	*ip = READ_ONCE_NOCHECK(regs->ip);
+	*sp = READ_ONCE_NOCHECK(regs->sp);
 	return true;
 }
 
@@ -389,8 +389,8 @@ static bool deref_stack_iret_regs(struct unwind_state *state, unsigned long addr
 	if (!stack_access_ok(state, addr, IRET_FRAME_SIZE))
 		return false;
 
-	*ip = regs->ip;
-	*sp = regs->sp;
+	*ip = READ_ONCE_NOCHECK(regs->ip);
+	*sp = READ_ONCE_NOCHECK(regs->sp);
 	return true;
 }
 
@@ -411,12 +411,12 @@ static bool get_reg(struct unwind_state *state, unsigned int reg_off,
 		return false;
 
 	if (state->full_regs) {
-		*val = ((unsigned long *)state->regs)[reg];
+		*val = READ_ONCE_NOCHECK(((unsigned long *)state->regs)[reg]);
 		return true;
 	}
 
 	if (state->prev_regs) {
-		*val = ((unsigned long *)state->prev_regs)[reg];
+		*val = READ_ONCE_NOCHECK(((unsigned long *)state->prev_regs)[reg]);
 		return true;
 	}
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204030948.dmsmwyw6fu5kzgey%40treble.
