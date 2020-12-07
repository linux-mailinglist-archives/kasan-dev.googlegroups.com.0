Return-Path: <kasan-dev+bncBDAMN6NI5EERBWXBXL7AKGQEPZFIQVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id AEB512D1DA3
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 23:46:50 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id q1sf125156wmq.2
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 14:46:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607381210; cv=pass;
        d=google.com; s=arc-20160816;
        b=GByXJ4mOVOUEvHForNdfDQ4rBOrMJWKwhpnwrVx59+xscwfi35yeuB/t6KXynKn2ze
         ZpKSdXZ+7SDCcaEoKEZKGJiA5cwNC8X36xNbpi7CMudVB8eCqTMT4ifhxdML+a7nxB5b
         qFL0BBsXgkQbUuT0KS1+yUBzwgOaGxVldEhEdy1VcFD5dH0TqbsiGFAHtI+XJGbzAq98
         D3fI4q3gRQ47ZduzV8v0FgDS19+GX/OwclPstOjfqiWSp31w0q9vxcbpcBM6p5e9r2n2
         QHEyeoN3w9ADUNPsin/61DLfKJinowoHU6HLCQkMj/+xS56mr/ZCrImSCP99utyczUeq
         po2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=GZ9BuxWv5lYinW2Uvgjf1O1lWgvam43vKSYB4aDEx7M=;
        b=sw3WL5ApCdf9p9CrO4uJeUgjteNfTayIgAQGeXSsVj7u2lJ4oBwHMUa/mXbk52U++q
         D7KrNPeRX7wmOVjQG+pzfE8RRQl1OAttK/oPfWuipsXiipmcNMhO9v1JoE4Tvdk5gMuQ
         yrZyyhzMt9rm41crHd6SS3wk9ZkqfGW56eo+abSaDBieNpw6H61VQKyK+sqmiQLmACsH
         k5uGuSXxiaObGqUABucdRoIlfqJGyspitNwqC3PsLZHnfA7qSr6Lz+SbBD2uyVK2e9b3
         WuQL8b0Abc58UsKdkzx4+A+Ql8CCtZ+KaXb/oBJD2KenktgZVMUtOSWYTQB953G53N8F
         v57Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=z6h2Skd6;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GZ9BuxWv5lYinW2Uvgjf1O1lWgvam43vKSYB4aDEx7M=;
        b=g36U1/7Ulomkjn1D1Nr4fxSsv+9HO71ZDGaTTNTKhw7iQ8U7rBFln8TcmIqBzary5l
         Vrni03BUjTYIj1e9DzwNak+FnKzzNt7r3oYKrgIM4/YyDQmsOA4umRREbj1Mfxu5lu3E
         cym9YjkGUs84kc4z+0kPa2Og2XpUTasNZRp3HglXMFrIHWjiN/dbf9WlRT1/VUQ202ti
         H3mcZKrtVSXqv6l8xqyCZtnQlXafPQmEx3XrpU1gkxhkOsmF3ALrjwlmloggK5n2pcUj
         nNYVkKdb9xF5ZuvO+4zbvLwonjFTlq58EKhreiBCCTOEbhambhHJjgRewbYHOUUxkvrx
         P0eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GZ9BuxWv5lYinW2Uvgjf1O1lWgvam43vKSYB4aDEx7M=;
        b=X6ogX3S/4FY6reIXPGZ/mRri2jCBWf7EhCDwcF5EFuHecQXHeSaLetYIw2b0DH96GA
         H8U3+Gc+v3bqEsuJmfyGwTILyVQQfS005clFD8l+MtJ3fJ+V/Pk+TTtPXVGsjNzXHDrN
         5bCUCOloh15ra3cvu+Z42M599RvJglp3N5006M5fZImKHV3zbbOZDzTRtz9INbGYkeil
         S8PngCe/MYHOop8X3wc++HP4uYUQ6GxOqkDyuZqcxrFJSyhjzi3go8CQ8QNmOKC5gdHf
         iCZH/dqirOSTdxX3nmOePSLsr9kCH80sgACXeA8ZRd7rVUvpDcG3KwjPUW9VXcSCsxj4
         oZqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531E5NcolRxWW6LqnT6u2JpZ69TuX96kqKrjjYoZ9slvz1n0vvrY
	z8qK5AKsEq/AYquZCI3k4tU=
X-Google-Smtp-Source: ABdhPJyO8DcvYJPU1mPqCKn0j4eu3YF1XPyTD6lI6W2fI+Ey4SjVwgiqDx5MOCsDzmuyxg//QwG9IQ==
X-Received: by 2002:a1c:e142:: with SMTP id y63mr1077150wmg.28.1607381210471;
        Mon, 07 Dec 2020 14:46:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2e50:: with SMTP id u77ls116117wmu.2.canary-gmail; Mon,
 07 Dec 2020 14:46:49 -0800 (PST)
X-Received: by 2002:a1c:dc87:: with SMTP id t129mr1034179wmg.52.1607381209701;
        Mon, 07 Dec 2020 14:46:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607381209; cv=none;
        d=google.com; s=arc-20160816;
        b=grxtQb/1lK6Dlqc+ERFNFXq96PGiTdbYujkyV69uWlLha5+UP6svmuGJNSwQo3zJ8u
         SwYrC7XFzdafTIga0OYrvHlB8Nk7SLR1y0a93ux/Aa7Ssc44zcGyvbIpJL7fu1O2lz38
         2Lbzu+C+6r9nADqYkAH7oYAFDfI0HoahDrqu98Je+yJeUPE3/7i0+ly3bSRlGTipcVFj
         kK94mWFYTUQSaNr1jSPpOCO5DLnWUceWNaCI+xvyMgcTyYLd6y2mNEKlot5HrXgFfvn5
         mVqiNyM0KRlc5el48lIoI68f+1v7eG4EkwMruRDdqiJG5Esp+en5Ai2uKJMrfZ1P07x6
         e6mA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=DF7s5pk4Zw7F4Z2nppe0ZuFvyidXGsr6pkOHRZYg040=;
        b=ggOdRvDmFQKWm0VALO5eunHmYsI11pwBaHtXK3hfz2l0Giy6C27o4RQd2y/GGIzKj3
         zAKAIqXLQW9fEzjduHqfzZ7bt9Jvf6yBvvtF7/yNPjyH++Djtu47ReiTH/sqwWaqXj8p
         WSLsiE4GHwd0WlckiND80txxAX4RiP5w6oAW+ZwehsXhuqhMaaqcO1Pu8XRDKzpS0xYJ
         xCx1zvTmtikmEIxAPvJ/t2Fotpl4VRF7kf8HAtLCuk41Wwjd+lx11cGoCg4+k0Z+IioN
         upFnk4Pz5gsyiJXcaciGlhHj5U9CIyKv3+KL8Iy0iJC2sLcUpGXuPufdvLoyJCW71SUr
         NECw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=z6h2Skd6;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 18si30567wmg.2.2020.12.07.14.46.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 14:46:49 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: paulmck@kernel.org
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Will Deacon <will@kernel.org>, Naresh Kamboju <naresh.kamboju@linaro.org>, syzbot+23a256029191772c2f02@syzkaller.appspotmail.com, syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com, syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
In-Reply-To: <20201207223853.GL2657@paulmck-ThinkPad-P72>
References: <20201206211253.919834182@linutronix.de> <20201206212002.876987748@linutronix.de> <20201207120943.GS3021@hirez.programming.kicks-ass.net> <87y2i94igo.fsf@nanos.tec.linutronix.de> <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com> <20201207194406.GK2657@paulmck-ThinkPad-P72> <87blf547d2.fsf@nanos.tec.linutronix.de> <20201207223853.GL2657@paulmck-ThinkPad-P72>
Date: Mon, 07 Dec 2020 23:46:48 +0100
Message-ID: <878sa944kn.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=z6h2Skd6;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
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

On Mon, Dec 07 2020 at 14:38, Paul E. McKenney wrote:

> On Mon, Dec 07, 2020 at 10:46:33PM +0100, Thomas Gleixner wrote:
>> On Mon, Dec 07 2020 at 11:44, Paul E. McKenney wrote:
>> > On Mon, Dec 07, 2020 at 07:19:51PM +0100, Marco Elver wrote:
>> >> On Mon, 7 Dec 2020 at 18:46, Thomas Gleixner <tglx@linutronix.de> wrote:
>> >> I currently don't know what the rule for Peter's preferred variant
>> >> would be, without running the risk of some accidentally data_race()'d
>> >> accesses.
>> >> 
>> >> Thoughts?
>> >
>> > I am also concerned about inadvertently covering code with data_race().
>> >
>> > Also, in this particular case, why data_race() rather than READ_ONCE()?
>> > Do we really expect the compiler to be able to optimize this case
>> > significantly without READ_ONCE()?
>> 
>> That was your suggestion a week or so ago :)
>
> You expected my suggestion to change?  ;-)

Your suggestion was data_race() IIRC but I might have lost track in that
conversation.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/878sa944kn.fsf%40nanos.tec.linutronix.de.
