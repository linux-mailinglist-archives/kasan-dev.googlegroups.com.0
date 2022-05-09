Return-Path: <kasan-dev+bncBDAMN6NI5EERB2ON4WJQMGQEG4URR5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BFDF5204F3
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 21:09:30 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id t184-20020a1c46c1000000b00394209f54f1sf4602305wma.4
        for <lists+kasan-dev@lfdr.de>; Mon, 09 May 2022 12:09:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652123370; cv=pass;
        d=google.com; s=arc-20160816;
        b=U8tzXce67ygeikK6qSZyeTD+4pA1LfU5idlxyUKc6IyXyLh/zGnvS2irp4PEslpGG1
         FDKQbY6eMjMNype+ho1OEZKTlPDcbt7onkSNg2gdJh4cQ6jpiLBDOOo59BMM41Hv7Bkz
         OJ5Xiu7o9gENCAOg7X19Rk6AuxEGuZAvSO4bee5Zh0Y/tYVy7V9DZQFkl8LSC2oc7vNN
         BIBJuXfxi5sKOe+mPQsqoQtCrr77a5yTUxY78LKH8V0CacB8aZ7bX9GbCjsyu7t6QyBF
         sy3zT83vzpJRmpXKqMwF3H/fv+ssgyzHQN3KPvarAw+6GdSnzjgaFDhBddoPgjfgACQA
         P54A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=Zz/92QsALvCoi4zE0Xcchvi3nGJs9KAP/4kjmkwoMH4=;
        b=zOR1VXbOo2IWT4ek+pR1KqXHuyGh4I2fBpUWlDfxidFKa9O0SZCalcNChTCgtInYsY
         DjSROu5LuS0Hj1Y32JL39w0v9xYVtzSWpDmveQDZOV1wKCed1xb/IXks/s924cEziIyh
         ay7YZIWW4NxpgklNXugAGzQkQdDYssjEpnHlAzU+lc/cUB7nw56/MKanJZTWSTJZluGM
         9ppJMlo6iqM0VOjUDJutIgg2sspL0l3yx/Z7JTtYyYU/B/kcrSl7XIv9WYwkuwIg4Fzc
         2GolwxYpCvzKR9J3QgZSKZ7RzhHs5CZTWOYQCqmQI7MulWet6o49AV5yw2Qy2GiJ7cQY
         yPTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=oVLpbua2;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zz/92QsALvCoi4zE0Xcchvi3nGJs9KAP/4kjmkwoMH4=;
        b=lVzhCs5K5NRd6jaJVjY2oXPtSBoNe/drFPVWiEXgeHsB1R9YNPiKGvR1cje9wDoUZR
         QTNZQdEe4aHVnfLJiDhUHsfC9Hi2TZGJx5p4n/mR0IHnhZhYjyJKcDji6+euf4CUC9Vw
         w/6wmUZdAkQxhxRqwXLqVP44sH1xfT8ifAPLCEQZI5P2N7sfaa4R4UXdx0yu1zuvMdnU
         SBdicITdNDj3J1jqjqZrqbYs3D5YAioe/v3zkRCE7cb+7ZnCy6rCPiwpv97zpaeeUWer
         2Jm2czh3tMyMPFE77UTNvEiALaRZkcEzbMdWZqA17W+uYcP5+8EuVJkFqrS1SWsUBI+Z
         uhaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zz/92QsALvCoi4zE0Xcchvi3nGJs9KAP/4kjmkwoMH4=;
        b=l03BRNDtBgfwOUCe1NCEe6HkzrAd0hpLp9ELsKte+5YQkirjFbnTvacLem3CAIl/sy
         57kzWW1IaI6LXEI0LPlQfVIm3CR0yp9TjktaDRqj043geE26/yaLuphQp1eGbfVF7FtH
         ZXz3xyarJ4jrbOUpxFQEAilKtmcHwEMER9A7PuEyCgRSAt1oIPstRzZpAA+x3MC7P6fU
         9Iey8ikpb50OVx67Z6aSYY1PZ0YPm0mYDqyJpbijcEmMsXZD0Hwucs6jYoto3xOAaIum
         vXLfEEUlqaBoLs+cAhBsqfqoEd+lVcLG8BEqFPKG4d6MDNzLqQEmTuG76Y50hCLH83gG
         Z+IQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531B9MMQuBE+UuW6cS0n7kF+qSWIPYrtVA6XEr43CrISSonknVE4
	Sn62KluzAtbK2PfB5h712UY=
X-Google-Smtp-Source: ABdhPJzyrgBar5VrSLxwn+Fm7EsbU8GTFggckCX3NMONCg2QyOKLwHwQ/JyP4wizWxyDHZC33IA9FA==
X-Received: by 2002:a05:600c:2315:b0:394:1f6:f663 with SMTP id 21-20020a05600c231500b0039401f6f663mr23931811wmo.115.1652123369818;
        Mon, 09 May 2022 12:09:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2747:0:b0:381:80e8:be59 with SMTP id n68-20020a1c2747000000b0038180e8be59ls160560wmn.1.gmail;
 Mon, 09 May 2022 12:09:28 -0700 (PDT)
X-Received: by 2002:a05:600c:190b:b0:394:96d3:5780 with SMTP id j11-20020a05600c190b00b0039496d35780mr4092240wmq.82.1652123368816;
        Mon, 09 May 2022 12:09:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652123368; cv=none;
        d=google.com; s=arc-20160816;
        b=z/RSYHFAD65E6mmTrkYgNVi+Z9CiJNT39NIxM4hQFvAXhpYNzYpDBTXb/uCd/Gsezc
         SSkxG2URqZfMR393jXRAp7VkLZhAdWX1KddM4FWWepHgskEJowSp9cciV/ji2tWovOhD
         Qx8rx2xX6S96TzhD79KMlWlkYsfZPVvYq2TQr4S2dBBxnBsTeAypMKYNIJUNqmKsl5AO
         mh8jZgbLab8PLRnQwoaurtojZ+nqQ5vrwY3yYXKE9TTNAPS5qTN2UhUBAgYccaGPmKx9
         VyeJ9ymPjQFFkYL52e0spxhbrnbMeKYJXBXz7+sSmMv7lcPgg87AvbmtKpkC6rt+9gXi
         P4Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=VawBhkp/iVX6wIchfdV6yUwkO3Wiahi7D6DYX4ALtEQ=;
        b=AdaDckxc5y5xgWx6rYr81xGHCB/bB8CROSfE1n7WjcZ2J9rscr2FMnlAvh26BZDIuw
         irp376FFqfjwQN43xptFdItjTmiAr+Q5sVAEj1KCVvxci94QdvMaNIbZgNSbezKZEBOH
         ddRw7CN5hgucT3GCsEsNa/0nWP16ufbhxOlWnAZXGIiP+JjlOkz4uVNzFEcHi3Flcdbk
         Kza811pvuvZ1y7qX71Y8oguriLWfbEjxNkxLW1Ov20+U+fGjs5jwn5Ao7hynzSGVBrss
         xrW5dC+NRbHrdilQHzulO5geyLp87ciMUsyOX7az1IIwPItYuadNiUgQhL6EEoug+wRr
         HIqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=oVLpbua2;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id c2-20020a05600c0a4200b00393faebeaa1si69390wmq.4.2022.05.09.12.09.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 May 2022 12:09:28 -0700 (PDT)
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
In-Reply-To: <CAG_fn=UroTgp0jt77X_E-b1DPJ+32Cye6dRL4DOZ8MRf+XSokg@mail.gmail.com>
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
Date: Mon, 09 May 2022 21:09:27 +0200
Message-ID: <871qx2r09k.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=oVLpbua2;       dkim=neutral
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

On Mon, May 09 2022 at 18:50, Alexander Potapenko wrote:
> Indeed, calling kmsan_unpoison_memory() in irqentry_enter() was
> supposed to be enough, but we have code in kmsan_unpoison_memory() (as
> well as other runtime functions) that checks for kmsan_in_runtime()
> and bails out to prevent potential recursion if KMSAN code starts
> calling itself.
>
> kmsan_in_runtime() is implemented as follows:
>
> ==============================================
> static __always_inline bool kmsan_in_runtime(void)
> {
>   if ((hardirq_count() >> HARDIRQ_SHIFT) > 1)
>     return true;
>   return kmsan_get_context()->kmsan_in_runtime;
> }
> ==============================================
> (see the code here:
> https://lore.kernel.org/lkml/20220426164315.625149-13-glider@google.com/#Z31mm:kmsan:kmsan.h)
>
> If we are running in the task context (in_task()==true),
> kmsan_get_context() returns a per-task `struct *kmsan_ctx`.
> If `in_task()==false` and `hardirq_count()>>HARDIRQ_SHIFT==1`, it
> returns a per-CPU one.
> Otherwise kmsan_in_runtime() is considered true to avoid dealing with
> nested interrupts.
>
> So in the case when `hardirq_count()>>HARDIRQ_SHIFT` is greater than
> 1, kmsan_in_runtime() becomes a no-op, which leads to false positives.

But, that'd only > 1 when there is a nested interrupt, which is not the
case. Interrupt handlers keep interrupts disabled. The last exception from
that rule was some legacy IDE driver which is gone by now.

So no, not a good explanation either.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/871qx2r09k.ffs%40tglx.
