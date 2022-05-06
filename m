Return-Path: <kasan-dev+bncBDAMN6NI5EERB3US2WJQMGQEKM4OCEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 49E1351DD60
	for <lists+kasan-dev@lfdr.de>; Fri,  6 May 2022 18:14:39 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id n186-20020a1c27c3000000b00392ae974ca1sf3426780wmn.0
        for <lists+kasan-dev@lfdr.de>; Fri, 06 May 2022 09:14:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651853679; cv=pass;
        d=google.com; s=arc-20160816;
        b=yU7jToR5+KCQoZRRixzWc8/POP3VYcXYZirRKyFfRGaqZMPYSYUfgS1QIpuMep7VKg
         fGHLYAIV6dD7I9ca8IbBKraza7rtoM0w6Nzk+H1JX+abVi2Sseuxegf7n0+/QAP6iy5b
         yAOJK1jeYeFtQi99+Xij/xCD8ZRvPYyt++SZeBzMDT2fvee80LRBUlvWoTWjMDr3vU29
         Qsg8ZpgF59+5snZCAXFWlTcCi5VaFwWpTxDPM4eBTRWTN9NN1vwLcm59OsH3piDAbn9N
         UBR8MGeJ9BhqA/PfIowU4rW+9TWTNnzsJS/hsx/m/HP1/APnRqZwzI5/71W65wuaCIbB
         d4HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=jUuGD8labcUwQtTj1KuCa+ZEJMRat4Xm+pfT7gSsVO0=;
        b=VbpH7Q4y98t+nJnp06z4T1UqDz/cxys0G7mdz+vErnBXs+4k8A1v9uzggeYUHt0Pq1
         70ELfwtauqC4JfWV/4hgkDGszpCIn+r0ZU8TsUFxKMaTdFvlhg1AsJGJ4QXxLE1SQ6D8
         i75P39Jwso7g46ujEnjwh78J5heSah0qQensTn2DAsQdyFf5B/dlasIkoT2fdOe/XJ5H
         DRo8hZ3SGV7IOVjuHONJwdNFrWhGtJb2CEJFnBGdLkI30RoIfTlYL8Hg/9oXXLx7NM60
         nr8hZuitFhY2Q4ltvq+uSNpwkX2DbGOxsHrrdSouaxWnkz2OQDW0EJl3s7xoklb/2RWf
         BMWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=BP8TefPh;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jUuGD8labcUwQtTj1KuCa+ZEJMRat4Xm+pfT7gSsVO0=;
        b=pa51IeIFp7gHMGtOM87SlkyYHGv/qA07LrDH/bgsxYIeLd5NMeJDruIDr6yFBPo5ln
         Z95pQLwcEtH2bsyk3Xv9LB4ze6FY3VU5k5SJ4xN2WK+aAqVN9ZClpV0JGLbNa6mrS96I
         KILMw8asDDukfhPZ9kS8rJn0AyzI7KdVp5uO34qdXH9LrLByeKJ1AsOLQTkNq5hv9nZU
         FGXjkz7GtWxZgKVLDC0AXurSNIGGuTD0VXM0DibQJ707CEw8SewgXBefE8Dj75Bp/wGq
         nuUBssSeOaCqpaJs06gFs8D5+ntVAaq/buDgHTiRzXQw/fuVIgPSz2dDDt9JQ38WoAI0
         jgRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jUuGD8labcUwQtTj1KuCa+ZEJMRat4Xm+pfT7gSsVO0=;
        b=sjd8d9IuTjoEart3BikksYuRgbJ5AuT83Boda7Qpka+QaiKsp02WdFR412v7hk3DI9
         3L/qkQtYXMHMaJc1YQ2i9kTRrLA8bd6XAFwB5xzVI0dEm9ttt/XPZZmLy8bLVKLfV2u9
         jneN9iokKrNBizOKC/vm/pPqdI3raVGoa5XAiXPfBIc6LGWJiT9uhJHJFH06AxXgOm6/
         6jFOyLXH2cpW3pV40DZSEehv5RyMjovlvtDtKuh8XZ1Uey/mLJaORcWg000sxaMsqYy+
         GaBWljg6AP4BEDuei0WbzWoO6sozk9iejZ7lUpmfxgMRQcSEPA6n4F9ePKdGQPTH3WzF
         5wjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JM9J7lNbroKLZkwnrJZdNhiW97nlRqhh5ApGIyllYpkXfCIpa
	6qvdXwd8N9PVvJEXNOR1a7Y=
X-Google-Smtp-Source: ABdhPJw4BjWiHw8W+j9Q1oavlI4XxkiuB6oWoN8Yy6O3Ibyylk4hWB6tbLEOnWXJY8vTYS2CLgphjQ==
X-Received: by 2002:a5d:64a3:0:b0:20c:5a27:ef12 with SMTP id m3-20020a5d64a3000000b0020c5a27ef12mr3316052wrp.58.1651853678892;
        Fri, 06 May 2022 09:14:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f950:0:b0:205:dbf5:72d8 with SMTP id q16-20020adff950000000b00205dbf572d8ls518163wrr.0.gmail;
 Fri, 06 May 2022 09:14:37 -0700 (PDT)
X-Received: by 2002:a05:6000:18a2:b0:20c:6d0d:10b0 with SMTP id b2-20020a05600018a200b0020c6d0d10b0mr3357084wri.345.1651853677767;
        Fri, 06 May 2022 09:14:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651853677; cv=none;
        d=google.com; s=arc-20160816;
        b=f1BxOB0zCsbSXX/MHO/Y8Pm77iqsKlfkK2JFV+0r+WcQUx3SpeFKFani93NdlNwDAo
         NFyxyNcU8uDErEMsOeNiQ8Lejnl5goKcu7dqJ4DKrenU5uRMJewfs1Lgg64BB652Kgzd
         EJ8KgatQGV5NQY8/6gtrG++F2laqkVPK7z4iXOaxqP+hrFbCXApiGSKUiuqSr8srUWfO
         QUaxmJHxjPTUAChk9C7B03IYqgLEva3O+KTAlbEAYXPIJLnxUXqo/ZqpMy0KsUnQd245
         +wQXIck7RSeeRC7p609X1KL9zDyID4m9tDcg/l6lFUiOnfmF0hlWVqKk+u2NK/pyMz9u
         /2kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=eGIaI6FR4z9ZKAajKHVzAuOrHeyDOTq0yBE9J83Z0DM=;
        b=StoTBiJESanvqVsYy4BWlEvKc12TMFrXbOtlE10zmZkrLQ2dCJddjhUQpaX5ctIj5V
         qCJqTz3alUbszxIiw3LGdzzVJ/wONwe3HRrLVCgG1MEronSirOIkanIgrkf5QsI7XpCI
         kO8fYd030BZQA2s5sdVH5HhGkMk2kloqs5MWD4dDW+IZtxBLk2JLNlQdYEi94iOwugD/
         JFvwVxfnbSLHxQwDN2ZOGxhybcGMPnLTYahlMDMQRrCE+0YlO3x/78eXle54tpbC1kFb
         Kq9P2sIEM9TdtTZtemBg/nzGxmIcu3Y1fCnt5yANbj87RzbRTu8e5zsvAK+Y6aiyeT0F
         ncOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=BP8TefPh;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id d23-20020a1c7317000000b0038ebc691b17si205365wmb.2.2022.05.06.09.14.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 May 2022 09:14:37 -0700 (PDT)
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
In-Reply-To: <CAG_fn=XVchXCcOhFt+rP=vinRhkyrXJSP46cyvcZeHJWaDquGg@mail.gmail.com>
References: <20220426164315.625149-1-glider@google.com>
 <20220426164315.625149-29-glider@google.com> <87a6c6y7mg.ffs@tglx>
 <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
 <87y1zjlhmj.ffs@tglx>
 <CAG_fn=XxAhBEBP2KJvahinbaxLAd1xvqTfRJdAu1Tk5r8=01jw@mail.gmail.com>
 <878rrfiqyr.ffs@tglx>
 <CAG_fn=XVchXCcOhFt+rP=vinRhkyrXJSP46cyvcZeHJWaDquGg@mail.gmail.com>
Date: Fri, 06 May 2022 18:14:36 +0200
Message-ID: <87k0ayhc43.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=BP8TefPh;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender)
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

On Fri, May 06 2022 at 16:52, Alexander Potapenko wrote:
> On Thu, May 5, 2022 at 11:56 PM Thomas Gleixner <tglx@linutronix.de> wrote:
>> @@ -452,6 +455,7 @@ irqentry_state_t noinstr irqentry_nmi_en
>>         rcu_nmi_enter();
>>
>>         instrumentation_begin();
>> +       unpoison(regs);
>>         trace_hardirqs_off_finish();
>>         ftrace_nmi_enter();
>>         instrumentation_end();
>>
>> As I said: 4 places :)
>
> These four instances still do not look sufficient.
> Right now I am seeing e.g. reports with the following stack trace:
>
> BUG: KMSAN: uninit-value in irqtime_account_process_tick+0x255/0x580
> kernel/sched/cputime.c:382
>  irqtime_account_process_tick+0x255/0x580 kernel/sched/cputime.c:382
>  account_process_tick+0x98/0x450 kernel/sched/cputime.c:476
>  update_process_times+0xe4/0x3e0 kernel/time/timer.c:1786
>  tick_sched_handle kernel/time/tick-sched.c:243
>  tick_sched_timer+0x83e/0x9e0 kernel/time/tick-sched.c:1473
>  __run_hrtimer+0x518/0xe50 kernel/time/hrtimer.c:1685
>  __hrtimer_run_queues kernel/time/hrtimer.c:1749
>  hrtimer_interrupt+0x838/0x15a0 kernel/time/hrtimer.c:1811
>  local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1086
>  __sysvec_apic_timer_interrupt+0x1ae/0x680 arch/x86/kernel/apic/apic.c:1103
>  sysvec_apic_timer_interrupt+0x95/0xc0 arch/x86/kernel/apic/apic.c:1097
> ...
> (uninit creation stack trace is irrelevant here, because it is some
> random value from the stack)
>
> sysvec_apic_timer_interrupt() receives struct pt_regs from
> uninstrumented code, so regs can be partially uninitialized.
> They are not passed down the call stack directly, but are instead
> saved by set_irq_regs() in sysvec_apic_timer_interrupt() and loaded by
> get_irq_regs() in tick_sched_timer().

sysvec_apic_timer_interrupt() invokes irqentry_enter() _before_
set_irq_regs() and irqentry_enter() unpoisons @reg.

Confused...




-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87k0ayhc43.ffs%40tglx.
