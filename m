Return-Path: <kasan-dev+bncBDAMN6NI5EERBXEFXOYAMGQEI54FNNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 33F38898AB7
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Apr 2024 17:10:22 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-515adcf2004sf930702e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Apr 2024 08:10:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712243421; cv=pass;
        d=google.com; s=arc-20160816;
        b=HjW8/9vGuT2ikArdTeOZ6zguDCRXDQqY360F+nh5U1CYym8UvNm+ZnIjavKPU+nYdB
         9eO67vRh+w+2RH71k3/zx8+uUpdLUCk1ub3AfqlTNAQSo6BHohBF4/OBy5/C13Qie6sE
         LmEgTBUgOAxiAdoCkir2Oo4LCsZQyey7LmXYN05ydjiKq/c/UuLtu0wrmR47BkKwKbl9
         +YuHvpdAbSifzxbL8RLkWJNGGyCpEX7Mqk6nFhbWgFUczxnaGD3Vu6NG7WdHg9kPiXZH
         eR2NbrPv0LXP9Q+bBEUw0CLkSM8jyrTZcaK18Uw2kfwNTqAdwQhqfVKE+D0e5q5RRY5F
         ixkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=HuRV0w/0Xr7sS1di4yOg7rlYD/4ZjrzbgsoKL4V/Hzc=;
        fh=UcpsUlOHzZ4hweSAljy+eHr6LbY8amMYiRW7hFYLY70=;
        b=AS7UQwkJ8umHUw9FpotbSLTf+DLXiHewY4l5jFUIrhVUSPtUflwWv+cP9ixBoAHHMA
         a3W0ynCdzLoPc1RFKGnYIphVkBPEZSQ2pn5G/pF7w9IAhspGxLdqtJRqx0drPZRcQHFM
         fnoNgL7o9nfgRnUKAwPDOCqr2V537bv+WuMieLmFGy32G6opkaHBw1F/BOULN/CCkKnR
         6zybpaYBQYW8snt6QNJ07KpNW0ayIATUjTZIhNjYrifNjcfbTElA+q5pDhHomtfglasW
         wVcrskTUATaA4b32ZAXbmN2DTGXZnKeYLTgNYazjEsNB2Zm0NILSPazoPpcTalHMcymo
         D9Bw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="yyw/gEou";
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=8WI+dxa9;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712243421; x=1712848221; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HuRV0w/0Xr7sS1di4yOg7rlYD/4ZjrzbgsoKL4V/Hzc=;
        b=SFeWXTlC5xK6uUCctEq+7LW2L9DTyicqcOSGABxsvb6wsSjf0O8eSaDMLH2Lu2HyB3
         RHpMSzMZ9z98suZO/rfOcgdANhDLA13Mo/fleA4k0GU8YVj0xSBx3m4tsDJHcfPISZt9
         QFGAjq/031shJluEVQ+ocd/ac2vNeWpaVocnP98i6QulLzZHz7wHuxmakGPlmDqdgIkX
         H3wrb1BHre2QPrO8EbmOVi0pJxl6ckon71rT8s7GB1vmkYCvncNHWx2WxRRNwhWzROdW
         6o9+OqBZQ8Ln3mhbcJMYHY0JriYwCCqga3r2i4PMFC4PhJUGVgDRQUSwQ0EuzZG+BLZB
         iRmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712243421; x=1712848221;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HuRV0w/0Xr7sS1di4yOg7rlYD/4ZjrzbgsoKL4V/Hzc=;
        b=mK95LuMqocN1rYR0PMWo7vN3zmhiGXb+tNOtr+nJOm8k6hfKtrB/9BBlGzi4dyenom
         z9gzDwNR5g5s6rm2JIdl5GFcOGLA88sPKZxG3NE4hCJ/0Z+w5VuIyV+rLuSWDei1s1YC
         yutzTZ2JzPN64Mnk9yJ961HQsAmM3ncuNj50U+wIVBw6rtfqT/NrrjRD0R2DSMym8vyz
         g4zRmP931PsmVwmUUo9E3jyyxTvY5E8kwDC3Lk6joCTwDfBFvY7wZy41mPbX/fPsdvzS
         JBVjGUhTL6+qFMgqoqFJk7NsTHNf6ScCRsjU3WiekQhAUU8YFzhKx5mRjWpqPFR4ReU+
         /TmQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWygvMyCOJ3Gw6mjWZ+CHlF9fRkIfvsntK0rGONsgv89jZ20jqRlq+NdJu9C4orCMy+eXHRMbE5weYGWyMAXLXNXi21TzSaNQ==
X-Gm-Message-State: AOJu0YzBtcH4INwAMz6YAnK+rlbh5AQNZggfih8zGtiIbUqfIq+/Yny2
	3zAZq8aPQNBprAx699JaxnH8xx5pxQjoX0XDep2+zgLF0txu0MQbo+Q=
X-Google-Smtp-Source: AGHT+IGarzwx3kkljATgn6DFQGTAO7vYWMZe26qffoesy2vhzf+v+zJnceAsHa3wX63YbqDHq8+gCA==
X-Received: by 2002:ac2:4149:0:b0:515:9b1a:6b5f with SMTP id c9-20020ac24149000000b005159b1a6b5fmr2300490lfi.29.1712243421074;
        Thu, 04 Apr 2024 08:10:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:398c:b0:515:dcb5:f12f with SMTP id
 j12-20020a056512398c00b00515dcb5f12fls684205lfu.2.-pod-prod-08-eu; Thu, 04
 Apr 2024 08:10:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCViL56+6VghBmZOF4iJ/CTGwHeYbMSkHDOW5/0N6ZLLEENsf6xE7RWRlt1/Cl8TwEm05MqTx5AIPDCElZox0N3TpGC9emWbS3GsaQ==
X-Received: by 2002:a2e:a455:0:b0:2d4:62b7:4c7b with SMTP id v21-20020a2ea455000000b002d462b74c7bmr2093782ljn.51.1712243418972;
        Thu, 04 Apr 2024 08:10:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712243418; cv=none;
        d=google.com; s=arc-20160816;
        b=VYQTpYZa9WH6gcG/F7UhksPcFzQ/Xgz8ymGsLj9IWywSP1OzEdMkhWHS+zYNkzBbrn
         fjKQGBLz3gQoSn3A7olWWgHNiqHlaO01569ktX7G72Hco8FwgVTpHbl1dyIJbe7Z/nLn
         K7KJrrr66pKczwzEX52ZQF2I2lJaCQdl6AMhYkN76g6odjesF7+E/1M13QbIH24TIr5c
         iILm6zHkgFUPmYt0imhQ+1lvABgfLJddPkACMA05fHiTTiFHhbHQ708VdUNU+A+LpY+0
         rZCPXf7BhGX9XESVmGJIvWd6H4MwatsLWZPtvQ/qKp4QMkqMKlCqy1LzTIY0DSIgdXI9
         QiJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=Z5plkxd242OMtGKpte6blfseLcSdvpYvQ4c9jL8q5L8=;
        fh=4Nv/nEfyFs8DOpffvrTsm+4TdL3Ck8nKKOoUBFJ9uL8=;
        b=DNtcHeZKSuGyX6nNm9aE1kaCnqCzAhVLZyPO39CreKuLt29KawYTedZk+s4wClsMXZ
         hHwh6AayGKs+DNWsjMFHbkT3KHhwAcBzuAPIgDGIMAGMKj1mm+mhZpith2cRArZQC2gg
         SsDmfQS1DphWhXhTBcE8Pl8n2jfeVKSzlboQLuJPuEi5cl4TeYhPyk1I/Rk80LKa+NEw
         8KVso03hGpb733ciMhhh851TTEdU1nQv6sKj6oxMBcRR5PRlzI/eZ/45wdg3bcvFYlUo
         UaZ7nuDTNcHYMYd+9nMFnyfVtuK2otkz8mDorc9TBK8MJ1z9kQ1lgf/iAQobHuWUbFi9
         pCPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="yyw/gEou";
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=8WI+dxa9;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id e5-20020a056000178500b003418013729esi469542wrg.5.2024.04.04.08.10.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Apr 2024 08:10:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Oleg Nesterov <oleg@redhat.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>, Peter
 Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, "Eric W.
 Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, Edward Liaw
 <edliaw@google.com>, Carlos Llamas <cmllamas@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
In-Reply-To: <20240404134357.GA7153@redhat.com>
References: <20230316123028.2890338-1-elver@google.com>
 <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
 <87frw3dd7d.ffs@tglx>
 <CANDhNCqbJHTNcnBj=twHQqtLjXiGNeGJ8tsbPrhGFq4Qz53c5w@mail.gmail.com>
 <874jcid3f6.ffs@tglx> <20240403150343.GC31764@redhat.com>
 <87sf02bgez.ffs@tglx>
 <CACT4Y+a-kdkAjmACJuDzrhmUPmv9uMpYOg6LLVviMQn=+9JRgA@mail.gmail.com>
 <20240404134357.GA7153@redhat.com>
Date: Thu, 04 Apr 2024 17:10:18 +0200
Message-ID: <87v84x9nad.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="yyw/gEou";       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=8WI+dxa9;
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

On Thu, Apr 04 2024 at 15:43, Oleg Nesterov wrote:
> On 04/04, Dmitry Vyukov wrote:
>> they all should get a signal eventually.
>
> Well, yes and no.
>
> No, in a sense that the motivation was not to ensure that all threads
> get a signal, the motivation was to ensure that cpu_timer_fire() paths
> will use the current task as the default target for signal_wake_up/etc.
> This is just optimization.
>
> But yes, all should get a signal eventually. And this will happen with
> or without the commit bcb7ee79029dca ("posix-timers: Prefer delivery of
> signals to the current thread"). Any thread can dequeue a shared signal,
> say, on return from interrupt.
>
> Just without that commit this "eventually" means A_LOT_OF_TIME
> statistically.

bcb7ee79029dca only directs the wakeup to current, but the signal is
still queued in the process wide shared pending list. So the thread
which sees sigpending() first will grab and deliver it to itself.

> But yes, I agree, if thread exits once it get a signal, then A_LOT_OF_TIME
> will be significantly decreased. But again, this is just statistical issue,
> I do not see how can we test the commit bcb7ee79029dca reliably.

We can't.

What we can actually test is the avoidance of waking up the main thread
by doing the following in the main thread:

     start_threads();
     barrier_wait();
     nanosleep(2 seconds);
     done = 1;
     stop_threads();

and in the first thread which is started:

first_thread()
     barrier_wait();
     start_timer();
     loop()
     
On a pre 6.3 kernel nanosleep() will return early because the main
thread is woken up and will eventually win the race to deliver the
signal.

On a 6.3 and later kernel nanosleep() will not return early because the
main thread is not woken up as the wake up is directed at current,
i.e. a worker thread, which is running anyway and will consume the
signal.

> OTOH. If the threads do not exit after they get signal, then _in theory_
> nothing can guarantee that this test-case will ever complete even with
> that commit. It is possible that one of the threads will "never" have a
> chance to run cpu_timer_fire().

Even with the exit I managed to make one out of 100 runs run into the
timeout because the main thread always won the race.

> In short, I leave this to you and Thomas. I have no idea how to write a
> "good" test for that commit.
>
> Well... perhaps the main thread should just sleep in pause(), and
> distribution_handler() should check that gettid() != getpid() ?
> Something like this maybe... We need to ensure that the main thread
> enters pause before timer_settime().

I'm testing a modification which implements something like the above and
the success condition is that the main thread does not return early from
nanosleep() and has no signal accounted. It survived 2000 iterations by
now.

Let me polish it up.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87v84x9nad.ffs%40tglx.
