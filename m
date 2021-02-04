Return-Path: <kasan-dev+bncBCU73AEHRQBBBKF75WAAMGQEN4RIDBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 876F030EA5E
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 03:44:58 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id f15sf881711oto.9
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 18:44:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612406697; cv=pass;
        d=google.com; s=arc-20160816;
        b=uhYebJCIJbZkO+NcJ3JMZQo5A5sXKtc05u2Ddb4nH20DqlYyRUwhvl0kf5STSpUCgE
         0UsnRk0lWBVpJjtxhTB8UGrLR9ism+HOSfVRkpzWt+Hrkl81B38+bdAy8gLzMRGjt1UF
         R5XYZrB6F42t4N01KZoUJrR/y2twkQRPRw+xcXckRBuvs2bcRBNF9Ae/IW5uABeCkk4Q
         AgNZTxxjw76d+Ij1GkJKmqLITvIVBaH+wImV9WWCBL2Vq7VSP1O6hEMYp9+6kPqt02b2
         Hu352yZBJUiOtnS3uotiUAMC0XogdNo2uOQZuZUFFYbideLkSkoXCqRBnkgUVcanlK7i
         Nn1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=3WZYcpvks9kB99JbOiT6zX7HGzihWAgVfObZWRIfmfk=;
        b=0aY5HiajlhX881vnWVb/8Y2kC1LtymAeSzNG8I4z/ByachQ0ybdhe4R2tYXVDknDhj
         BqGY5/oi597i0LSq3DlryIA74/fi0kMLw7d1twzZAreKNkGcShIzdV+Y6S+mucAIFVNY
         k/Ft0JAPWcq+hBd4ZY4+7OwtWPF0bGDIsXaFtW/nH2jTvFFdC8SDcUP4rZe3WYo8xNUC
         2PCcSG7nYjNw3iEQzYvn5BmBr+E4AoRl+kfaO0HNzomasZwetg43ROtg+NJo3GPvSyqw
         vsfOVllTnvlFE8P1i9Ry38E98z3CIRfmF31JLnS5efT16igLzg4gkZAPijFKowVtVh5r
         UaFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ei9q=hg=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ei9q=HG=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3WZYcpvks9kB99JbOiT6zX7HGzihWAgVfObZWRIfmfk=;
        b=eZc7GQeqAFnizk2rfg0iGh2STs5y4KqfKddSlHwwUY0EokgHUkZyC+X0lkPcYjjrQn
         DAnrjvlc16JtXPjYadRMfB4BsoDzBWIxWjBvfRSi8QvPhriA0AKpp8nFH0+hAxCWdBCv
         545yBtU0EDFO1zbdZkxBjogOy9UwQjdUk+YoWt7MMoifBJCfQgj0n+bf6FJSKr/mkMx4
         91RkFsp68V5b7wnZU/ffhHdj16TmmynvpBGgTp2DKKUxqBo/5e7ui45juVVbVfwXzyNA
         3iKFrxvUxLoKWPOhb7kXDREl5sfUb6J/cKA0pGTVpsddFLxMwibW0aouD6h8X2wZ9Yxs
         DKTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3WZYcpvks9kB99JbOiT6zX7HGzihWAgVfObZWRIfmfk=;
        b=fcxEZVh4ofBnq3Ng2q+4bqD0Dq4tjvznN760h28BjDe2i6uxh2X05MQ+3MzNy2fIqU
         2EDkOJk0qGXC1McZJDIcuCcl/xfTnc++MW350D0Z6BxOGoJ7UwAqTM58QkeGKdvct3YI
         Ncnumi6+SynueLoqqxIEe9o+nyMDFmbF8e1manzSMyaaH7IhS9i4hJ5YSYqV/Il867a9
         JjdUV1vgvwKZ1PMysVcGLwvTebp+i4oVY7gdixbVJkjpLX0+j6r+cPOH1zLbJe8r9KAM
         vPUoA9Ybr2HGXVjNflmTXvxroaoL3SVEgOKHe/r3aTOiq6NY44XwEQunpw1XxPd55FMJ
         2m/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532jDGv3nC+veh5qHQUXOve+p+0kzaYLL6M7jYjBIJtfWhJt5oJp
	8FQsxdzztrpFLrT3d6g7saM=
X-Google-Smtp-Source: ABdhPJzerEDPbU+BczLgTCRWbnF0/NYZkSiCvpzOp9CrTtShRNIznhPIJH4b6SRN3EUyCrOp0rIjrQ==
X-Received: by 2002:a05:6830:1c2b:: with SMTP id f11mr4174059ote.74.1612406697161;
        Wed, 03 Feb 2021 18:44:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cd8e:: with SMTP id d136ls1010787oig.6.gmail; Wed, 03
 Feb 2021 18:44:56 -0800 (PST)
X-Received: by 2002:aca:fc07:: with SMTP id a7mr3900644oii.89.1612406696631;
        Wed, 03 Feb 2021 18:44:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612406696; cv=none;
        d=google.com; s=arc-20160816;
        b=x6OvS+7/iIxoyzkK6Vjz6R6ZQA6+XiiUqV4b8jwtAu3CzI+MbVi+tUM56wt8WYIAoV
         sqozHmow/f4YcHqGe04ieQxDkb2VD7B6pMtjoGpmtFJB851H3a6ulhKSwFpGdhW134U1
         6LCbR4FJPBAh50tJyA1yjgJohjSP3xbDF1Mr7juJhZ9HFDY22ubb3Ws61RpaWYnv8pZT
         QWr1DrOZ+lnzA/J+0T3jIzhPxUpVCBEH+utqHWP++2ON6tuxi1hzxi8AyUibd1EZ2c2d
         ijVls7tS6gCO7nMxRP7c8bddpvc9FL6RstZRn+f/CjxVc2iGQhdNTCSauDmxN2I6qbvq
         pl7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=S9c95Zn8q0OLwuanJ+Qz7i0VRH5vfRMhfgOI7EfHplY=;
        b=PQCaGmyipli6Fyl431fqZ0ecswhQYjip5GMhO8GcCAqnvLG5vHbr1gHnj20ewD4JaS
         5jb3Kdv4QBzj7vEiCxOOt1vrtVb5JhK20LG4ok8iX0PWxpgLjLW+33wVOzwoRJ//hClo
         3RImYjlDbwtZPQ306jAGrSfveqpuuJJXLMBHEAIfrtiYQbx0FYZQy04lvCY9NtiJ91sz
         IUd06JH/MJuBCILC53ZMgdBh79d5BRVz/adZ37YCZ6Y5xXD4NbOCxKQkdOuBngnXRN2T
         brjGCt0bRtHGQrZkNLVTT4I4fh63G4NBrv4c4xsbzg8BmrODOQ0ALwBgPJZWUWAom75S
         W3kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ei9q=hg=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ei9q=HG=goodmis.org=rostedt@kernel.org"
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r13si231891otd.3.2021.02.03.18.44.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Feb 2021 18:44:56 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ei9q=hg=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from oasis.local.home (cpe-66-24-58-225.stny.res.rr.com [66.24.58.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9B0CA64F4A;
	Thu,  4 Feb 2021 02:44:50 +0000 (UTC)
Date: Wed, 3 Feb 2021 21:44:48 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Ivan Babrou <ivan@cloudflare.com>
Cc: kernel-team <kernel-team@cloudflare.com>, Ignat Korchagin
 <ignat@cloudflare.com>, Hailong liu <liu.hailong6@zte.com.cn>, Andrey
 Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, Thomas Gleixner <tglx@linutronix.de>, Ingo
 Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org,
 "H. Peter Anvin" <hpa@zytor.com>, Josh Poimboeuf <jpoimboe@redhat.com>,
 Miroslav Benes <mbenes@suse.cz>, "Peter Zijlstra (Intel)"
 <peterz@infradead.org>, Julien Thierry <jthierry@redhat.com>, Jiri Slaby
 <jirislaby@kernel.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel <linux-kernel@vger.kernel.org>, Alasdair Kergon
 <agk@redhat.com>, Mike Snitzer <snitzer@redhat.com>, dm-devel@redhat.com,
 Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann
 <daniel@iogearbox.net>, Martin KaFai Lau <kafai@fb.com>, Song Liu
 <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, Andrii Nakryiko
 <andriin@fb.com>, John Fastabend <john.fastabend@gmail.com>, KP Singh
 <kpsingh@chromium.org>, Robert Richter <rric@kernel.org>, "Joel Fernandes
 (Google)" <joel@joelfernandes.org>, Mathieu Desnoyers
 <mathieu.desnoyers@efficios.com>, Linux Kernel Network Developers
 <netdev@vger.kernel.org>, bpf@vger.kernel.org
Subject: Re: BUG: KASAN: stack-out-of-bounds in
 unwind_next_frame+0x1df5/0x2650
Message-ID: <20210203214448.2703930e@oasis.local.home>
In-Reply-To: <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
	<CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
X-Mailer: Claws Mail 3.17.3 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ei9q=hg=goodmis.org=rostedt@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ei9q=HG=goodmis.org=rostedt@kernel.org"
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

On Tue, 2 Feb 2021 19:09:44 -0800
Ivan Babrou <ivan@cloudflare.com> wrote:

> On Thu, Jan 28, 2021 at 7:35 PM Ivan Babrou <ivan@cloudflare.com> wrote:
> >
> > Hello,
> >
> > We've noticed the following regression in Linux 5.10 branch:
> >
> > [  128.367231][    C0]
> > ==================================================================
> > [  128.368523][    C0] BUG: KASAN: stack-out-of-bounds in
> > unwind_next_frame (arch/x86/kernel/unwind_orc.c:371

The bug is a stack-out-of-bounds error in unwind_orc.c, right?

> > arch/x86/kernel/unwind_orc.c:544)
> > [  128.369744][    C0] Read of size 8 at addr ffff88802fceede0 by task
> > kworker/u2:2/591
> > [  128.370916][    C0]
> > [  128.371269][    C0] CPU: 0 PID: 591 Comm: kworker/u2:2 Not tainted
> > 5.10.11-cloudflare-kasan-2021.1.15 #1
> > [  128.372626][    C0] Hardware name: QEMU Standard PC (i440FX + PIIX,
> > 1996), BIOS rel-1.12.1-0-ga5cab58e9a3f-prebuilt.qemu.org 04/01/2014
> > [  128.374346][    C0] Workqueue: writeback wb_workfn (flush-254:0)
> > [  128.375275][    C0] Call Trace:
> > [  128.375763][    C0]  <IRQ>
> > [  128.376221][    C0]  dump_stack+0x7d/0xa3
> > [  128.376843][    C0]  print_address_description.constprop.0+0x1c/0x210
[ snip ? results ]
> > (arch/x86/kernel/unwind_orc.c:371 arch/x86/kernel/unwind_orc.c:544)
[ snip ]
> > [  128.381736][    C0]  kasan_report.cold+0x1f/0x37
[ snip ]
> > [  128.383192][    C0]  unwind_next_frame+0x1df5/0x2650
[ snip ]
> > [  128.391550][    C0]  arch_stack_walk+0x8d/0xf0
[ snip ]
> > [  128.392807][    C0]  stack_trace_save+0x96/0xd0
[ snip ]
> > arch/x86/include/asm/irq_stack.h:77 arch/x86/kernel/irq_64.c:77)
[ snip ]
> > [  128.399759][    C0]  kasan_save_stack+0x20/0x50
[ snip ]
> > [  128.427691][    C0]  kasan_set_track+0x1c/0x30
> > [  128.428366][    C0]  kasan_set_free_info+0x1b/0x30
> > [  128.429113][    C0]  __kasan_slab_free+0x110/0x150
> > [  128.429838][    C0]  slab_free_freelist_hook+0x66/0x120
> > [  128.430628][    C0]  kfree+0xbf/0x4d0

[ snip the rest ]

> > [  128.441287][    C0] RIP: 0010:skcipher_walk_next
> > (crypto/skcipher.c:322 crypto/skcipher.c:384)

Why do we have an RIP in skcipher_walk_next, if its the unwinder that
had a bug? Or are they related?

Or did skcipher_walk_next trigger something in KASAN which did a stack
walk via the unwinder, and that caused another issue?

Looking at the unwinder code in question, we have:

static bool deref_stack_regs(struct unwind_state *state, unsigned long addr,
                             unsigned long *ip, unsigned long *sp)
{
        struct pt_regs *regs = (struct pt_regs *)addr;

        /* x86-32 support will be more complicated due to the &regs->sp hack */
        BUILD_BUG_ON(IS_ENABLED(CONFIG_X86_32));

        if (!stack_access_ok(state, addr, sizeof(struct pt_regs)))
                return false;

        *ip = regs->ip;
        *sp = regs->sp; <- pointer to here
        return true;
}

and the caller of the above static function:

        case UNWIND_HINT_TYPE_REGS:
                if (!deref_stack_regs(state, sp, &state->ip, &state->sp)) {
                        orc_warn_current("can't access registers at %pB\n",
                                         (void *)orig_ip);
                        goto err;
                }


Could it possibly be that there's some magic canary on the stack that
causes KASAN to trigger if you read it? For example, there's this in
the stack tracer:

kernel/trace/trace_stack.c: check_stack()

        while (i < stack_trace_nr_entries) {
                int found = 0;

                stack_trace_index[x] = this_size;
                p = start;

                for (; p < top && i < stack_trace_nr_entries; p++) {
                        /*
                         * The READ_ONCE_NOCHECK is used to let KASAN know that
                         * this is not a stack-out-of-bounds error.
                         */
                        if ((READ_ONCE_NOCHECK(*p)) == stack_dump_trace[i]) {
                                stack_dump_trace[x] = stack_dump_trace[i++];
                                this_size = stack_trace_index[x++] =
                                        (top - p) * sizeof(unsigned long);
                                found = 1;


That is because I read the entire stack frame looking for values, and I
know where the top of the stack is, and will not go past it. But it too
triggered a stack-out-of-bounds error, which required the above
READ_ONCE_NOCHECK() to quiet KASAN. Not to mention there's already some
READ_ONCE_NOCHECK() calls in the unwinder. Maybe this too is required?

Would this work?

diff --git a/arch/x86/kernel/unwind_orc.c b/arch/x86/kernel/unwind_orc.c
index 73f800100066..22eaf3683c2a 100644
--- a/arch/x86/kernel/unwind_orc.c
+++ b/arch/x86/kernel/unwind_orc.c
@@ -367,8 +367,8 @@ static bool deref_stack_regs(struct unwind_state *state, unsigned long addr,
 	if (!stack_access_ok(state, addr, sizeof(struct pt_regs)))
 		return false;
 
-	*ip = regs->ip;
-	*sp = regs->sp;
+	*ip = READ_ONCE_NOCHECK(regs->ip);
+	*sp = READ_ONCE_NOCHECK(regs->sp);
 	return true;
 }
 
-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210203214448.2703930e%40oasis.local.home.
