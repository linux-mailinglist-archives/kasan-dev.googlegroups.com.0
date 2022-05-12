Return-Path: <kasan-dev+bncBDAMN6NI5EERB2HU6SJQMGQE5IJFUSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id AF9E75252F9
	for <lists+kasan-dev@lfdr.de>; Thu, 12 May 2022 18:48:40 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id g3-20020a7bc4c3000000b0039409519611sf1850517wmk.9
        for <lists+kasan-dev@lfdr.de>; Thu, 12 May 2022 09:48:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652374120; cv=pass;
        d=google.com; s=arc-20160816;
        b=PPrY0GZK2i1iW9dtMkiufUk7F8xX9nKsT0Ual8waAtwYRFU0aFjbcm4J87o+T9m4RQ
         PFHXHXPkO3TLQjY26hIIzD8RVKKAT1abD0eawk3FcXFKLLSxQ70CfVWwdD1jDSJY7HeD
         wvr6rNle9roDr+Ub9Y9pZik7k/tIJ7L9fLSAhk5ueRWUNKMnkGjfm2JkFoIDoPfNS+XF
         2tmfuSDgHn4iWHVvZwKCvs+deBaULdnFt7kurRO306YHJhbXQKHCxkJyNgGtgorHNBPm
         HTk9iNNswal3J0BKpSssSDwSmJzGisCtnITr5D0tGZU5N1DXtM55b4h/BcasQeQVgINV
         ZEQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=PKwuNnT3zu1C68sIcTc8s4V2x1Fj4RuEn8wMwaVSl/Q=;
        b=CebAdT2FEqDcp/OkFKEHl0VRNKkk63aMaPUWApv5VyBUZY2RNc9vMafvhZ4ygkU7mj
         0j8HjMMdLn6nv8u+Y/Tsle9dkL4tZ05glHKsNgwLoy79bgI4EcgRaXHYyIGUzMimpZo6
         /0LGsjwBcW4wJQVUIgdWrwOA3ZqwknCJThZlNY+Pf1drhZwSObHKTnH4SErQ8x8lHclL
         WkSKNyeZj47lGFCsuNzXhkRxqhAhku0HH/8EW+MPHgkSA2EE+kCAXJf19hMCOy2WlcZv
         3NxQqP2TmJWA4ngSRf9k6bFHS/o4erSqg12Z9ROVOyBMokmti2mw1LfGuKNFOErW3k7M
         zAsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=dNG6zwNh;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PKwuNnT3zu1C68sIcTc8s4V2x1Fj4RuEn8wMwaVSl/Q=;
        b=SS+ZtJCWs6SNV0Fr4vob41ZzQRtyUyGzXZKyCuxHQUXHhp9kzK779c8dAZKNewKwLy
         rDo31iK1Ke6NHZD5Nmtp5evHNV5B6dK+T4O9ae+AIj0OBkJ0rMtPYcxMKzH+1nvTfL5/
         O98gFhqWYcVIZlS0vxx3qWJ7NLCDo8obPTLsoSLcI4SPIZGZLVPTu/ks7siz9ZR0F63x
         a73IOaQFicEbOt86COYUH932zIhEWpfF8qI0XBY/ocnsTbPynk9ZKJ3+xXbKY4nznbmy
         uKp/mwL1d2IJhiNBai/E2Wa8V5ndGshYKeR+XLMLM0eprmQBM0KGOnZS7AWd3UCJcRfW
         6PWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PKwuNnT3zu1C68sIcTc8s4V2x1Fj4RuEn8wMwaVSl/Q=;
        b=26D49/qbNsLJpcjpGwz/2IkmE47T+HpGlBzmCgHmemp3KVgNISYB9HCKyySpxrjF2T
         mPTFZVA9gZK5De/TXw+BbCHTjrpq8YXqRQ59AZdST/awAoANufwejrPdFerYQaeWQa+T
         /eaV9oq4X8BmdPXaA8sdv9j9IDXKrRkF3JtfUTOHghMj5pKF4MO29aIhEeexhRJyuwuo
         sCVLQ5ONhSI6+Fk2wN2SwEIvtFOgITVn614Ueo+9EcBWnoMEvmls9pjT3EnQifLZFZTD
         /t8EkcveRf8IjVdv33dDwICyXiXrAwUJmIVqKIH3BFo4ss9YiJ0Syf2waNPNbtAuIMkt
         0Jlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531S0Fm29NDQ6psxk8+VYbQfFfus9z0PEV6WpofK3vrBjnod705i
	JhbD/AFHCbVtHmOmpTpP8rA=
X-Google-Smtp-Source: ABdhPJzrLCe9B7qdixfhwM9bc/q79rAGR5XJrXEles13Yt07+4vn4oMh50vlDKILg4PmIYBEAFt0uQ==
X-Received: by 2002:a05:600c:4f90:b0:394:970a:71bd with SMTP id n16-20020a05600c4f9000b00394970a71bdmr707082wmq.158.1652374120216;
        Thu, 12 May 2022 09:48:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1f11:b0:394:7a2e:a847 with SMTP id
 bd17-20020a05600c1f1100b003947a2ea847ls2995837wmb.0.gmail; Thu, 12 May 2022
 09:48:39 -0700 (PDT)
X-Received: by 2002:a7b:c24d:0:b0:393:fac9:3015 with SMTP id b13-20020a7bc24d000000b00393fac93015mr683917wmj.186.1652374119225;
        Thu, 12 May 2022 09:48:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652374119; cv=none;
        d=google.com; s=arc-20160816;
        b=Wvs6u7BOvQs50UsIl3rzrD0SWijCJQN+5VWp8dFdC7G1MdoTD+rGOpB3eW/0127TAu
         CGdyb3QkHBlUzehSyDNyt1bUmnepu6RJec+yELLcN6np160M7AsJXa6iYcNXQPJ3K0bc
         WkqoRFiJbHPUX2CjtdTNdahpdyQBVl0cFA5EEMueTrs0JNGIiT8c6nEJMIqSmlOUDDgO
         qw5R6/4U0G1+yd8M6IyFRvUhhbfGBNVPsCLEjLSB5voaYbRR9zb4nf5Moik/X67QOmjK
         WOLVl8Enirk5jiXpT+Q80dQ0ZkocX9f6MVxPvxzEWNFI3B7SnZcWjzEy4RGBDgWX3BZV
         jnMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=hSX9OFf5tzvIcNgVCMLyCC6NV4cYH+8sLce95997SMQ=;
        b=pGWDvF0ErR3oO2BYrAf2ExSsfVF13xz4B5lwZUYT98z1q5LDutyQMy+ZJDu9Fm0Lue
         auLDM65MVZWElRTtgHUhSxLcR2uyIJ7l9Kro0REl+dy+NIZJJ3tC6x54RNRj4kWrD364
         vj98Kr9dVNobrH3jFx5Yjqt93T5FXKRNaI1+qB+a7XP5RFmuJ3rk28pDPDZzyXrkk2mg
         sfJZVZBP1bIIG6rTc6kwaxxXIx1FcXcunyB8duqScxiyF94ZzF1JoltILV1UZPmwcSQf
         P5DdfmcoiAF42u63wutcD9+Nhtd5hI+bssRRYyw81ltRgttefjF5F76Aqbg4Fo/G8d8r
         Q7zA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=dNG6zwNh;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id p26-20020a05600c1d9a00b003943e39b255si276122wms.0.2022.05.12.09.48.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 May 2022 09:48:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton
 <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>,
 Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav
 Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter
 <cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu
 <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, Ingo
 Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, Marco Elver
 <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox
 <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg
 <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Petr Mladek
 <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik
 <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil
 Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, Linux
 Memory Management List <linux-mm@kvack.org>, Linux-Arch
 <linux-arch@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v3 28/46] kmsan: entry: handle register passing from
 uninstrumented code
In-Reply-To: <87h75uvi7s.ffs@tglx>
References: <20220426164315.625149-1-glider@google.com>
 <20220426164315.625149-29-glider@google.com> <87a6c6y7mg.ffs@tglx>
 <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
 <87y1zjlhmj.ffs@tglx>
 <CAG_fn=XxAhBEBP2KJvahinbaxLAd1xvqTfRJdAu1Tk5r8=01jw@mail.gmail.com>
 <878rrfiqyr.ffs@tglx>
 <CAG_fn=XVchXCcOhFt+rP=vinRhkyrXJSP46cyvcZeHJWaDquGg@mail.gmail.com>
 <87k0ayhc43.ffs@tglx>
 <CAG_fn=UpcXMqJiZvho6_G3rjvjQA-3Ax6X8ONVO0D+4Pttc9dA@mail.gmail.com>
 <87h762h5c2.ffs@tglx>
 <CAG_fn=UroTgp0jt77X_E-b1DPJ+32Cye6dRL4DOZ8MRf+XSokg@mail.gmail.com>
 <871qx2r09k.ffs@tglx>
 <CAG_fn=VtQw1gL_UVONHi=OJakOuMa3wKfkzP0jWcuvGQEmV9Vw@mail.gmail.com>
 <87h75uvi7s.ffs@tglx>
Date: Thu, 12 May 2022 18:48:38 +0200
Message-ID: <87ee0yvgrd.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=dNG6zwNh;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Thu, May 12 2022 at 18:17, Thomas Gleixner wrote:
> On Thu, May 12 2022 at 14:24, Alexander Potapenko wrote:
>> We could try to figure out the places in idtentry code where normal
>> kmsan_unpoison_memory() can be called in IRQ context, but as far as I
>> can see it will depend on the type of the entry point.
>
> NMI is covered as it increments before it invokes the unpoison().
>
> Let me figure out why we increment the preempt count late for
> interrupts. IIRC it's for symmetry reasons related to softirq processing
> on return, but let me double check.

It's even documented:

 https://www.kernel.org/doc/html/latest/core-api/entry.html#interrupts-and-regular-exceptions

But who reads documentation? :)

So, I think the simplest and least intrusive solution is to have special
purpose unpoison functions. See the patch below for illustration.

The reasons why I used specific ones:

  1) User entry

     Whether that's a syscall or interrupt/exception does not
     matter. It's always on the task stack and your machinery cannot be
     running at that point because it came from user space.

  2) Interrupt/exception/NMI entry kernel
  
     Those can nest into an already active context, so you really want
     to unpoison @regs.

     Also while regular interrupts cannot nest because of interrupts
     staying disabled, exceptions triggered in the interrupt handler and
     NMIs can nest.

     -> device interrupt()
           irqentry_enter(regs)

        -> NMI()
           irqentry_nmi_enter(regs)

           -> fault()
              irqentry_enter(regs)
          
              --> debug_exception()
                  irqentry_nmi_enter(regs)

     Soft interrupt processing on return from interrupt makes it more
     interesting:

     interrupt()
       handler()
       do_softirq()
         local_irq_enable()
            interrupt()
              NMI
                ....

     And everytime you get a new @regs pointer to deal with.

Wonderful, isn't it?

Thanks,

        tglx

---
--- a/kernel/entry/common.c
+++ b/kernel/entry/common.c
@@ -24,6 +24,7 @@ static __always_inline void __enter_from
 	user_exit_irqoff();
 
 	instrumentation_begin();
+	unpoison_user(regs);
 	trace_hardirqs_off_finish();
 	instrumentation_end();
 }
@@ -352,6 +353,7 @@ noinstr irqentry_state_t irqentry_enter(
 		lockdep_hardirqs_off(CALLER_ADDR0);
 		rcu_irq_enter();
 		instrumentation_begin();
+		unpoison_irq(regs);
 		trace_hardirqs_off_finish();
 		instrumentation_end();
 
@@ -367,6 +369,7 @@ noinstr irqentry_state_t irqentry_enter(
 	 */
 	lockdep_hardirqs_off(CALLER_ADDR0);
 	instrumentation_begin();
+	unpoison_irq(regs);
 	rcu_irq_enter_check_tick();
 	trace_hardirqs_off_finish();
 	instrumentation_end();
@@ -452,6 +455,7 @@ irqentry_state_t noinstr irqentry_nmi_en
 	rcu_nmi_enter();
 
 	instrumentation_begin();
+	unpoison_irq(regs);
 	trace_hardirqs_off_finish();
 	ftrace_nmi_enter();
 	instrumentation_end();

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87ee0yvgrd.ffs%40tglx.
