Return-Path: <kasan-dev+bncBCMIZB7QWENRBZP3XWYAMGQEKJGTEBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 68415899419
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Apr 2024 06:28:23 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id a640c23a62f3a-a51a3459f16sf6167466b.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Apr 2024 21:28:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712291303; cv=pass;
        d=google.com; s=arc-20160816;
        b=EIkfKlU2BliKJF25CnI9vtvSahokxWqV2z+t9zmTmAWN/xvefF+LnPQ/2ep4ujPpYx
         mpQ+BYyuwj8IZRUVOWBGZGL5q7DCfwzTASEJVBEI9oDLCyCK7VdeLemODw80A2UWIR26
         2WkD2gXYfyOoz2i1vWXaF0Usvt+8WNL+JzMKpdpYURX3AcaZp2H2XNQcfJS809aTEL4g
         WrVIxIYcGsfZUxw0LNMkue7DP/SNz3DUP1z5bv/FgW6P1fMnfHQp2V3rwrUtNq+BVJ5s
         SrZ8Qr4NagjZdBVFzStNf4nmUHK7RQvMihEIF3u93FpOJUjjjjo1ljPJ2v8590YXc8QL
         r1Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R6YyakTp4HxyvLGNsYIcfT+nIqlfbwENqoT6tmvoG5A=;
        fh=xfIlx3USfY7NHAPZfS/Z3hvMc4DJBB047DxMsjYFlVQ=;
        b=pfmazpP8FwqijLI5hqZHTYP725Kpl5atMwz0/ufKzm91tA2/TJ0WPSd0Mb6T5dnBNc
         T11wwk3UiRBS4o9J7AaZI+nEWviPrXzY7PghdjeRqTGz6ZLJ+69PBBWuQVWHKzqEEJUc
         6iFZFcu8Foizu7gu34dZyqrc8yo54ijT1NYfUX6LrMzfriINDgC6q5+9QlHcVx9o7Qfl
         +c1lm2L/Qz00RRiKzkyPAcXoxXcxiZ0fzv9Fb+We/dDu9fqwZ7s3jWnYBDClmu3qo8wI
         sKjiN67mQ9jY0TNoEsb9YDgnUDemx2W2WVw7oazDMs0inVJ/OHhRkFbQjmB4dr2pJEm5
         uKjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XJoKP2o1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712291303; x=1712896103; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=R6YyakTp4HxyvLGNsYIcfT+nIqlfbwENqoT6tmvoG5A=;
        b=qxs2OwG/2mbBs09eVbcPht9HCYvwqg2VVsloK2cUOBo6cz0xw19QpyMjaJVW4BUvgo
         LkJ1jJBIg/YlHC6VVJ42QFbbPSxuqCvCPMJzcXH5Efv7AEfBpVnaE3HEeN8TPz/zdJpO
         PoJpixlkbONqbCsDwMyAmpW0m3ooaEVfTCMqFZRkkRgobNIWYQFtZFEZu3zZNvvP68iV
         Tvfi+SFwMURdwus/mOsfvS+drBqhVOoa80f9L0wu1adndaAx2SReG5yfNFgFYP6SdvFf
         0LQANgpsuytHc/Dk+0wla7YRf2ZAfRo2pwzgWhvP/wClFzFwj90ttTxzDcTJUyUe4I97
         1/Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712291303; x=1712896103;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R6YyakTp4HxyvLGNsYIcfT+nIqlfbwENqoT6tmvoG5A=;
        b=N5YwKqaO0q2ej5oMZ9uBZ1PkNQsWWMZ592+w3i6ADKnhzUYzqIZWQxHze/1Ux5ZA8l
         JrJ9QFleF2KHXpZB/B97Ms8zynHOhnacRm+4hd+wCy0p+IBUHwK8A8dVC8m3E7T0DHLC
         9bMSG8FeVBiptdNSWU0n0A77YPrK770z9U9zLinflkAr6IrYiMaPEqg3B69HnvYQYS46
         jspJ/5QhMFQ/ZzKqByI23uqzD0hqUQnBOGn3RJElyvuhjKCqC1JM76g+j6vu1MiGxYPL
         hsNvmca4ki8rms87rgMl9NHX5Zl3xpnEJeCILsRdS6p3IBv1WzGYRhkkXEzNVikPRifP
         SJSA==
X-Forwarded-Encrypted: i=2; AJvYcCUhuQU40cxAh2sO0w/jmjhQAEHz+SZYV4nr1biIpO1Sk6BOkOi9orD2VWyndpXYuPPDQ/lMitPUHeWykodlVxjWTEm3N85nYQ==
X-Gm-Message-State: AOJu0Yyhb1PQCu/iHq6KN0iq0CT0rtwRdJ9lZEPjz+Y+cJHonI9duKXR
	8uhUQm54lIAfUPGx54Wx6syIBVVMgaJyckxieJVp8bN0FVFBjMGj
X-Google-Smtp-Source: AGHT+IFo0GRtXZu6qxZ/FTWE02zYNWa4uu0ZS0wIiB/RTvTApnQCHNtUP1+au4PPISwuVbf7YlP7ew==
X-Received: by 2002:a50:cdd4:0:b0:56e:1010:cd7c with SMTP id h20-20020a50cdd4000000b0056e1010cd7cmr231288edj.12.1712291302019;
        Thu, 04 Apr 2024 21:28:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:f06:b0:56e:1dec:a5d4 with SMTP id
 i6-20020a0564020f0600b0056e1deca5d4ls295731eda.0.-pod-prod-05-eu; Thu, 04 Apr
 2024 21:28:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXXgo0LElVAdMmCFXVFCF9kPfXSYphZNqHODYD5QcdIJCzl2XlTlV5EUDx9D+13O0/UNPIPEvsV9YCxaDZovtt/3YiGsj3WhyUpRw==
X-Received: by 2002:a50:aa92:0:b0:56d:fc89:ecf8 with SMTP id q18-20020a50aa92000000b0056dfc89ecf8mr243544edc.10.1712291300062;
        Thu, 04 Apr 2024 21:28:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712291300; cv=none;
        d=google.com; s=arc-20160816;
        b=cW8ERYSUcylcxkbomy1eHrNDKiz9NKF500BRLDujt7vxD3xIkR9ISNkUUYksNUL22J
         ZhOoWLA2FbnMGZiHYmOoDQXySyRNHtCOuYPsiptskQvbkBpz7XFAoChl34DjoZbCiuNB
         U2sS+e+B9FfeG4uK30FcXaW/tUc9aCpT3x+4JDgs3WmMIBF8+UhrAD0HjXelCR1hYvAG
         qXNOR9N6gYWqWIJCqjDaGwy4d3JLfYyOXGGFM0/rbhlpvO2TIVv4BScNSRp+//c9pv+p
         Bxv7CLlGBstM7HLE6hjp7QQYrZmIf1MMKAiAcZ/zY0feQjKUHHuZJC9JQYQ3A/XKw0Dg
         BRzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n+JLyTEvPZL/Mt8+rCrTxgDV7jqVCeyX64y3OK1/JtU=;
        fh=GtWM3LrWhAJ3COKkuyvsr/YA/a7WEJVsCrPF9GQs84A=;
        b=c6LOWFWVu80GEMkH2xmI5FdVrz7nh0ijXQyfl35ozMYFejzfXuW4or50/uO9xY7QqM
         wvhBzXCQHCZPqeFcF6X3KHPIdFd1NhQK2af3IMMFs93tJMZ+OrVmSY7VyCYDln3t/caG
         7qSGn1199d6X+ZCO9EFrf2mmIcUkX46rRVG3wvrLb0DcQFlnDdTnE7bEaUbNzff+g/Zx
         0M9Sbvd7sDILpC+JzgfKB0NhG/AKucZ9nMOQaTouuwxSFel5Bw0/XYZb9JVBdw1jfnzP
         SKiZrvKoXGBVBKENss128Ef/tGBVeLt3Ox1BYaMoyUrRaLBuOVXGR0XByNFYeprrj6zG
         C7YQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XJoKP2o1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id cq20-20020a056402221400b0056c2ef3a441si17686edb.3.2024.04.04.21.28.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Apr 2024 21:28:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-516c3e0e8d7so1502e87.0
        for <kasan-dev@googlegroups.com>; Thu, 04 Apr 2024 21:28:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWo0HVuCnprVvlOJtdGuWwa1pJ/X/XEbR0uRFZY9Rvm8XKkqb/6j/3P2GdSt0vKkHBdrDab40isnQv7o8DglH0oBD94NihVg5tWGQ==
X-Received: by 2002:a19:9108:0:b0:515:c2ad:6cac with SMTP id
 t8-20020a199108000000b00515c2ad6cacmr156054lfd.7.1712291298951; Thu, 04 Apr
 2024 21:28:18 -0700 (PDT)
MIME-Version: 1.0
References: <20230316123028.2890338-1-elver@google.com> <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
 <87frw3dd7d.ffs@tglx> <CANDhNCqbJHTNcnBj=twHQqtLjXiGNeGJ8tsbPrhGFq4Qz53c5w@mail.gmail.com>
 <874jcid3f6.ffs@tglx> <20240403150343.GC31764@redhat.com> <87sf02bgez.ffs@tglx>
 <CACT4Y+a-kdkAjmACJuDzrhmUPmv9uMpYOg6LLVviMQn=+9JRgA@mail.gmail.com> <20240404134357.GA7153@redhat.com>
In-Reply-To: <20240404134357.GA7153@redhat.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Apr 2024 06:28:02 +0200
Message-ID: <CACT4Y+a1RRx-NK1H-iyuqwEs1kHfUsQBHRU7OsK7zHPmjVHSzw@mail.gmail.com>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
To: Oleg Nesterov <oleg@redhat.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, John Stultz <jstultz@google.com>, 
	Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, 
	Edward Liaw <edliaw@google.com>, Carlos Llamas <cmllamas@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=XJoKP2o1;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, 4 Apr 2024 at 15:45, Oleg Nesterov <oleg@redhat.com> wrote:
>
> Perhaps I am totally confused, but.
>
> On 04/04, Dmitry Vyukov wrote:
> >
> > On Wed, 3 Apr 2024 at 17:43, Thomas Gleixner <tglx@linutronix.de> wrote:
> > >
> > > > Why distribution_thread() can't simply exit if got_signal != 0 ?
> > > >
> > > > See https://lore.kernel.org/all/20230128195641.GA14906@redhat.com/
> > >
> > > Indeed. It's too obvious :)
> >
> > This test models the intended use-case that was the motivation for the change:
> > We want to sample execution of a running multi-threaded program, it
> > has multiple active threads (that don't exit), since all threads are
> > running and consuming CPU,
>
> Yes,
>
> > they all should get a signal eventually.
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
> Just without that commit this "eventually" means A_LOT_OF_TIME statistically.

I agree that any thread can pick the signal, but this A_LOT_OF_TIME
makes it impossible for the test to reliably repeatedly pass w/o the
change in any reasonable testing system.
With the change the test was finishing/passing for me immediately all the time.

Again, if the test causes practical problems (flaky), then I don't
mind relaxing it (flaky tests suck). I was just against giving up on
testing proactively just in case.



> > If threads will exit once they get a signal,
>
> just in case, the main thread should not exit ...
>
> > then the test will pass
> > even if signal delivery is biased towards a single running thread all
> > the time (the previous kernel impl).
>
> See above.
>
> But yes, I agree, if thread exits once it get a signal, then A_LOT_OF_TIME
> will be significantly decreased. But again, this is just statistical issue,
> I do not see how can we test the commit bcb7ee79029dca reliably.
>
> OTOH. If the threads do not exit after they get signal, then _in theory_
> nothing can guarantee that this test-case will ever complete even with
> that commit. It is possible that one of the threads will "never" have a
> chance to run cpu_timer_fire().
>
> In short, I leave this to you and Thomas. I have no idea how to write a
> "good" test for that commit.
>
> Well... perhaps the main thread should just sleep in pause(), and
> distribution_handler() should check that gettid() != getpid() ?
> Something like this maybe... We need to ensure that the main thread
> enters pause before timer_settime().
>
> Oleg.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba1RRx-NK1H-iyuqwEs1kHfUsQBHRU7OsK7zHPmjVHSzw%40mail.gmail.com.
