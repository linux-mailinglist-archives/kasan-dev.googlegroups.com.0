Return-Path: <kasan-dev+bncBDAMN6NI5EERBAFJ4X7AKGQEFWKC35A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 410362DB7C9
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Dec 2020 01:27:45 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id j5sf8740812wro.12
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 16:27:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608078465; cv=pass;
        d=google.com; s=arc-20160816;
        b=LOD7NkKr+00rs6wGRSAohDPcpxQZGpaZ0lIBMd5m/euqpo5l586CnLURBLhT0KHRPZ
         GS2GiV1q7+BbFjlMfvo+Ww/xHZm30xGJPfd8NCCZgGTNESVy5JTPhV4tio/g2S7Ehdcm
         zzDLz1/xk5k8ZfFvmDk5COm3jTB/f40/2yG924bp0w/9vBFpPbTC2tbhG8RknXQpCemW
         sYxq79TJYBDtOlY4vG3Yme6zJBkqt0rrGpxn7W8pWs0OdE27t+UVUdc+HdluB18BXljp
         0z61/27FU/L3m3bHXknecjAV1FFfkh+9jx9JOwkCclOMPoDSZ1kns+WBQiUmLiJmhscp
         W2TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=tk2DlmHvZyvl/9cnFzBSGmeX5KwSPdHQsg2LteOL3n4=;
        b=nO5fe0ireMYGuyLd19XDiao50wfnXwT8WTPmoVX1l0FA1gbwSwn880LmtNtazBVhdO
         Xzf/r+t8CNKCEb98WczvxS6XC1pQDFvc6eD8oMtX+txMq/JL8AfxPhXNhlUWBGM0LhD7
         1r6W7SS+5d/1+4UL2+JjqVbq9KBdXumknceVEg+/pPTRn0EAvGMwk/NP2vfDn8uOQ8bn
         b38srmEFY8fkDdZpDh9H8lp0jS+n7ABzPD3N7dwmblX8a/vEXFrTdGDA3Ff3lfEI8pwQ
         HMluBcnP0VZizBh4+5Q1Ej94LZTXuNXEykjJk0ior79qv8N+HsnEQeFqas+XGBUlIq54
         xhVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=v7rJUlwY;
       dkim=neutral (no key) header.i=@linutronix.de header.b=ccIALfQ0;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tk2DlmHvZyvl/9cnFzBSGmeX5KwSPdHQsg2LteOL3n4=;
        b=aBeo4d2XARmtWwGaxR3Y4QUaHw0p9Z3lYXPHJCfxESCUosO9WmmG2fi0gfy2lmqjzN
         WyOwm5vmYq0Ivd4CbYcYYKZ3lMNBJi8o9SfIAb2HO6Gg5ijiwWgIvHeDmAYfGo+S22M+
         K5QHzsjtUnWsRBqV8xhF6LKXy6tlrO77+K1GNFgq8kMClzSKRAA5BxsYoUltvThSQ7jC
         trEKkAWq1bEs8Ww/1Ab7FIPGkP/7ZwRGugO2b8F2N9xfM51QPgx76kkwfpcRcSF04Zp1
         cv2d95uBlPfoCvHvoQEo2K+SybZPLZ4hrTjPeTbZLZoHRQgTlMVKaw+5XAFqZbprLRj/
         Rj3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tk2DlmHvZyvl/9cnFzBSGmeX5KwSPdHQsg2LteOL3n4=;
        b=nHFWHSKcDerC9WU5WIhVQE5tEhBPrOfE1ywpdubVPt4cnj8asdRtt9wqTmsJd08R9g
         6/0PyXugnC7Gjc8PzBTaS48s7tgmyz+sOUbgnCYrF+ERvcBQb2WG92oH1enU2rQP1sJS
         HjVO6UD2h1yhkvTspV9RVH9GIOE1JMs86ZiUsF8K0P8f31gTEPtsXq+0EGVkUM9V9lWG
         gK2qdDFiQrcuKslIvNOO6HMWjrZPAH3dziTn5f2orXGpRuTPUrtYNZcRl2KncEmI3FW4
         uxNJgYuPWzSgR6x7kT2Ilue7Hpqcn1sVHeFPw3I+rQR3+GNfo1RwUI/bTeiRJ2PgsOnI
         t4iQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Ujmzx1Zo9vPTP83MGJPKMP9WGVZBRxUvSOtLAWK8vYmSqn/ug
	54Z+D50+pWCz12KZXL9XbOc=
X-Google-Smtp-Source: ABdhPJz8fT70NsEOU5Xg9XZbE9yPd+62T5FyHLZZdMRq+WgE+KnO9e4dH1d71bpgu6K6jEPv6Y6dNw==
X-Received: by 2002:a1c:2155:: with SMTP id h82mr890614wmh.132.1608078465010;
        Tue, 15 Dec 2020 16:27:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:b688:: with SMTP id g130ls347012wmf.3.canary-gmail; Tue,
 15 Dec 2020 16:27:44 -0800 (PST)
X-Received: by 2002:a1c:234d:: with SMTP id j74mr925976wmj.18.1608078464119;
        Tue, 15 Dec 2020 16:27:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608078464; cv=none;
        d=google.com; s=arc-20160816;
        b=KWlYE+mW90F82SsjtZjlnx91Megfst9YFqyApQJXzsVJ0I91V52vPudyEvbR8/MVEK
         1BHQZhtisv/ibtG1qt9KI5iWYKbWmJGa9JU0k0EW3yrRz4PG4d6vfImukNuVM2mpAJAF
         bwt+x+65b7qNK88Nw2hj3tPFmKWHrAn+NQSXVzN5P0dfoFIWacOYqahUjAlUnTweublj
         2x1gmFpkGk5MzzJYfVRjIxZaojE6cj1Z2xU67dM060b/MOb0VkFGG7sXQ7e1aOa4V7si
         xJRwqKb/s8fc9Ul2oa6YqfW2heoODiM5On9Ox7iiC9IwXa/q+EuduZ7a5idhYlCnzUfD
         mj9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=9oM6XJd59woVYfiyCB+uESYOvCyhYxaqi5O1krN5wgo=;
        b=R1dJIvnj9S7LGp6grZ5xqAnAm1V21AGWfvS5axIJ3sS1PIdwuT/ZW6pc8SGm6P+EFl
         59b1tDQV+1bsWtBRe4C61AqkObHA/fOAEEz8jO2nNYlkHWwoa1aMDgq/IcQU7HNnyLp6
         okVCgTPv7zfZxy85gDICwFNO9Zvjr/R017fPLHFNekuNgAZr74RGBJJJDyEEoGRm8uI2
         Cg+WZmdnVrhqWs1LY99oqSKrS3DmMOUPS2H+UmuN2AL4Db3Z+tSxfADxAHCkK1cGIiti
         xNlsjfE8THSHuyHzwRsC/hi44zbVcOtUhWRKJNJ0q1a2a3cTZ5G1/EP/FYLEpCvKpE1D
         CNBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=v7rJUlwY;
       dkim=neutral (no key) header.i=@linutronix.de header.b=ccIALfQ0;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id o135si3704wme.3.2020.12.15.16.27.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Dec 2020 16:27:44 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: paulmck@kernel.org, Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Will Deacon <will@kernel.org>, Naresh Kamboju <naresh.kamboju@linaro.org>, syzbot+23a256029191772c2f02@syzkaller.appspotmail.com, syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com, syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
In-Reply-To: <20201208150309.GP2657@paulmck-ThinkPad-P72>
References: <20201206211253.919834182@linutronix.de> <20201206212002.876987748@linutronix.de> <20201207120943.GS3021@hirez.programming.kicks-ass.net> <87y2i94igo.fsf@nanos.tec.linutronix.de> <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com> <20201207194406.GK2657@paulmck-ThinkPad-P72> <20201208081129.GQ2414@hirez.programming.kicks-ass.net> <20201208150309.GP2657@paulmck-ThinkPad-P72>
Date: Wed, 16 Dec 2020 01:27:43 +0100
Message-ID: <873606tx1c.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=v7rJUlwY;       dkim=neutral
 (no key) header.i=@linutronix.de header.b=ccIALfQ0;       spf=pass
 (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1
 as permitted sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Tue, Dec 08 2020 at 07:03, Paul E. McKenney wrote:

> On Tue, Dec 08, 2020 at 09:11:29AM +0100, Peter Zijlstra wrote:
>> On Mon, Dec 07, 2020 at 11:44:06AM -0800, Paul E. McKenney wrote:
>> 
>> > Also, in this particular case, why data_race() rather than READ_ONCE()?
>> > Do we really expect the compiler to be able to optimize this case
>> > significantly without READ_ONCE()?

There is probably not much optimization potential for the compiler if
data_race() is used vs. READ/WRITE_ONCE() in this code.

>> It's about intent and how the code reads. READ_ONCE() is something
>> completely different from data_race(). data_race() is correct here.
>
> Why?

Lemme answer that to the extent why _I_ chose data_race() - aside of my
likely confusion over our IRC conversation.

The code does not really care about the compiler trying to be clever or
not as it is designed to be tolerant of all sorts of concurrency
including competing writes. It does not care about multiple reloads
either.  It neither cares about invented stores as long as these
invented stores are not storing phantasy values.

The only thing it cares about is store/load tearing, but there is no
'clever' way to use that because of the only valid transitions of
'cpunr' which comes from smp_processor_id() to TICK_DO_TIMER_NONE which
is the only constant involved or the other way round (which is
intentionally subject to competing stores).

If the compiler is free to store the 32bit value as 4 seperate bytes or
does invented stores with phantasy values, then there is surely a reason
to switch to READ/WRITE_ONCE(), but that'd be a really daft reason.

So my intent was to document that this code does not care about anything
else than what I'd consider to be plain compiler bugs.

My conclusion might be wrong as usual :)

Thanks,

        tglx




-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/873606tx1c.fsf%40nanos.tec.linutronix.de.
