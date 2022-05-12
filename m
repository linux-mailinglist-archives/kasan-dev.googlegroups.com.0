Return-Path: <kasan-dev+bncBDAMN6NI5EERBCPG6SJQMGQEDZH7I6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id C705C52524D
	for <lists+kasan-dev@lfdr.de>; Thu, 12 May 2022 18:17:14 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id a9-20020a2e88c9000000b0024f37c179d3sf1750036ljk.19
        for <lists+kasan-dev@lfdr.de>; Thu, 12 May 2022 09:17:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652372234; cv=pass;
        d=google.com; s=arc-20160816;
        b=MIPE9dWAgeO3ovB4gg7IiWo5puMPwgXFIAIvPPTXreIQhnNiNSRXfQQXbZgNrm0uMe
         AY5KF8pTvmuECj6X40oIu7+vn1qzUCJZ0Azol+1q/lIn3C/S0fUIazvrJaFHjmMNomgF
         47u0v9CMfuzgxjGGHc7g1cvKKs0R3S9G8DQtCazjYwkDQ+QCF/w/+VkKxxanf0ahKUjH
         3t6yWbQzWr9q+h5nmxqOKn4SEPEW1ewu+rbd1YHsXX0zbDHyem13JBjcMucZv2oQY/Y2
         yu+Qb07BFFF+t05xrCWwGPcK1EqailheCPBD705nmVv1osnyL9IsW++KZzirWG6FKISZ
         iqTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=4IwABLV75gvl42zdTiX5UfvFd9N4N4OnTGGLcmeZPGM=;
        b=Y8IXyrXf1WVnLdQCCitlh6hCGl5DrYjLa/4Vqc23oV3UeBOSYUAqBQuDHYhPJcxpeu
         TPCuNzIfOebFyJxw3TSFjDFuUIQYM1j3KKyiG1HPxufzTugodDB9ReDP6fAsaTxunApz
         qLhkMA9wEQYSB1KFp6ABrlJv0aMDdBJ5NcIZAMCIihxhDV1LsngcLwrZorIH7hMXgWsq
         2kRdKgdYzeY3jwUu4XzIHvUFpWwd+5svrSt4OV60TxC0EZSBSFtgUUaXJaO1ntvYPt4N
         dVxgbpZxiGh1cT6/LRihOtyd9dBDX/wySdGmF5HImBHC3jV5PUhZQ2r088LGAGMAcA3X
         rNRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=M2SNi8xR;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=W90ZtdXl;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4IwABLV75gvl42zdTiX5UfvFd9N4N4OnTGGLcmeZPGM=;
        b=B6xbsPqeugdPrboqULV1hg3blBdZoONXNobvpm6F0XCDhWbvWzz16e2INkBgsc9fDt
         QnmX4OO0tYrhkFP1i2lkdZd1HVkhJLk0Wl+EcznZSbuhOkqw+jQ+coIe6M+tTIWGdxR9
         aqKh0628qD05rtapNFhsvhPo/8vSGM8i9xLKmTW/grNPpt2tkdcJi0x4IIvc+JxK9V4o
         2zK8ozheqD4A4p6pSHxpBFtwQGjQ+nkz12lRLcdK5Bt4rFxmkXT4Fc0HrkOjo/Z5cm9E
         aMq3PUTAFBvupqdqynCcblq9lH/rN9Jqh+q4cJ8hEI4OyBsropQr0p9a16hxNel65wiJ
         Sngw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4IwABLV75gvl42zdTiX5UfvFd9N4N4OnTGGLcmeZPGM=;
        b=0BaTLWvWPUDlC0RGSiM721ZpcG/j4KXEdArzIm1BHShVWxvljlO5AeW6XsE8QKN4j5
         a6VElV+M4CqtfSRLIwvx6fZBJAQITBkxNtmNfAYQdEZwWgyw5p7E3n8VSBhjyOZKMJcQ
         f1Y6e56tPirBpqmWV3SLd2ba3Y0BQjTL0DfSOzHAWc6q7fsJAdjQ+gy4nt5G17qBDwHf
         e4P1yZay9eFg6Q9QQyqYtXdA+LIzRU6bVGd/IeJdA2Fw3Nkn++JGvhGPhYIPA1Zo2UMj
         sCmsd4/RObhV/Sjt/zyiRtCb8tRFSlWiaSIGKSMBDWdwwi+71RV7iu4FO7Z8bvHhr78n
         ZX0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53335qXBm77xJp9ZFJEjvkY9q4SlYrNWseLB/d0ZwBA3kJcvly9x
	H+HkP8mMxomNUq3tcicmPtY=
X-Google-Smtp-Source: ABdhPJzD1bC0itlxBI9xMYolH0kR/MpTS7aixZkmdjvEkuDPZDZ+YeQx3g02NGyyw4sWuLlwOD5uTg==
X-Received: by 2002:a05:6512:280e:b0:473:a0c9:5bdf with SMTP id cf14-20020a056512280e00b00473a0c95bdfmr355156lfb.337.1652372234008;
        Thu, 12 May 2022 09:17:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:210e:b0:250:5bd1:6dab with SMTP id
 a14-20020a05651c210e00b002505bd16dabls1068898ljq.6.gmail; Thu, 12 May 2022
 09:17:12 -0700 (PDT)
X-Received: by 2002:a2e:8759:0:b0:250:6afa:78e9 with SMTP id q25-20020a2e8759000000b002506afa78e9mr444678ljj.225.1652372232759;
        Thu, 12 May 2022 09:17:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652372232; cv=none;
        d=google.com; s=arc-20160816;
        b=rVDno0dcjz1OyDoeB6gX94o6yxs6qOnZeBEi6ot9pn2ugHxIClKQGspaf38ceT+hBd
         IfHvlcuzG0jNgMagu8Sx3Mo6DATH5XTQBY+2OGutYmWqp4gptM6HE52j5V2Ay5u49Gnu
         TmELRseFUNU45ePUNePy4JzwYWOBmmrEZjp8kzyQyvMg31WdVe7gNKS+UuSnXUx0wGEd
         7IY2HDab+J7mZvQ0FgqvsAkA5ICju10UQHStoed/UYnKtXYk27R+vUNxtAN5Trgt1s2g
         x2G12ppU4CRFk49zQ1MTAMGpQ9v/eD+mDfNjaohgha2XlG0q+0HhR0qN4m5kPDnm/GNd
         Cq0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=P3WA7a2LKBsvGjpHAfwHZrsdX5lPf+mXnzFb/W6CTG4=;
        b=h+BBFPzWJBNmxtrQnVEhMGwqtgsG2X3wPvyirXH2H/bPLYZHPLeYt4gG3X5CLjjxBv
         YQA3yPI3pz+G7+PQIDuTuLI7foGbYBJ60iKKY62BIoX9AGL5vYrIuK9Lnz4QO5rn4AXw
         ELFZHfxttqp6cgV+VMBz2ynxceBjbXvQ+X9GLCrD2FdGelbkAoWec+2f+vXKwFMxj6oP
         /VylumJ3eM6sD9brL2ZbzYH2P721zNYKfVJJChBRejqDqU3WcbFVA4KNKSMh5qIgF3Ah
         lb5bbxeK0bDUjiPmXgobNtzdgvA8bbmvZZ27ghDOdztPo0k8VOPnJ6i8YQnYLSoBsX7o
         Em2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=M2SNi8xR;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=W90ZtdXl;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id o20-20020ac24e94000000b00473b906027fsi1325lfr.4.2022.05.12.09.17.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 May 2022 09:17:12 -0700 (PDT)
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
In-Reply-To: <CAG_fn=VtQw1gL_UVONHi=OJakOuMa3wKfkzP0jWcuvGQEmV9Vw@mail.gmail.com>
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
Date: Thu, 12 May 2022 18:17:11 +0200
Message-ID: <87h75uvi7s.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=M2SNi8xR;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=W90ZtdXl;
       spf=pass (google.com: domain of tglx@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Thu, May 12 2022 at 14:24, Alexander Potapenko wrote:
> On Mon, May 9, 2022 at 9:09 PM Thomas Gleixner <tglx@linutronix.de> wrote:
>> > So in the case when `hardirq_count()>>HARDIRQ_SHIFT` is greater than
>> > 1, kmsan_in_runtime() becomes a no-op, which leads to false positives.
>>
>> But, that'd only > 1 when there is a nested interrupt, which is not the
>> case. Interrupt handlers keep interrupts disabled. The last exception from
>> that rule was some legacy IDE driver which is gone by now.
>
> That's good to know, then we probably don't need this hardirq_count()
> check anymore.
>
>> So no, not a good explanation either.
>
> After looking deeper I see that unpoisoning was indeed skipped because
> kmsan_in_runtime() returned true, but I was wrong about the root
> cause.
> The problem was not caused by a nested hardirq, but rather by the fact
> that the KMSAN hook in irqentry_enter() was called with in_task()==1.

Argh, the preempt counter increment happens _after_ irqentry_enter().

> I think the best that can be done here is (as suggested above) to
> provide some kmsan_unpoison_pt_regs() function that will only be
> called from the entry points and won't be doing reentrancy checks.
> It should be safe, because unpoisoning boils down to calculating
> shadow/origin addresses and calling memset() on them, no instrumented
> code will be involved.

If you keep them where I placed them, then there is no need for a
noinstr function. It's already instrumentable.

> We could try to figure out the places in idtentry code where normal
> kmsan_unpoison_memory() can be called in IRQ context, but as far as I
> can see it will depend on the type of the entry point.

NMI is covered as it increments before it invokes the unpoison().

Let me figure out why we increment the preempt count late for
interrupts. IIRC it's for symmetry reasons related to softirq processing
on return, but let me double check.

> Another way to deal with the problem is to not rely on in_task(), but
> rather use some per-cpu counter in irqentry_enter()/irqentry_exit() to
> figure out whether we are in IRQ code already.

Well, if you have a irqentry() specific unpoison, then you know the
context, right?

> However this is only possible irqentry_enter() itself guarantees that
> the execution cannot be rescheduled to another CPU - is that the case?

Obviously. It runs with interrupts disabled and eventually on a
separate interrupt stack.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87h75uvi7s.ffs%40tglx.
