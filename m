Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU7EXH7AKGQEASQQMXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 48F742D1865
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 19:20:05 +0100 (CET)
Received: by mail-ua1-x93c.google.com with SMTP id r17sf3452871uah.7
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 10:20:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607365204; cv=pass;
        d=google.com; s=arc-20160816;
        b=kVo0V6g9ged+tkjmXaaB2gkkbsLmiHsF4oOI3XPEvsYdvd5Z84uH+9F2x9gHHICLUS
         5yG/5bpWaQ4rqw7Y/jDylZuZtVg2W6LnDv/eAzcmxkXHuhAbtTbjNsvv/4k6YEQBsSOZ
         viHk+ovmsNRKXoSIYJfoOVPnPxS1EhexlH05ayOlDZQI+ppZC6XHhEICA9qixNMTAcnZ
         Cn62TNLjWimJRopd9OGmQW5zTaaE7sVIlW+7IlDRvFhUs8oM4GqKkL2pSMHDWqc/O2qN
         Ipm7NsETzerVKaqJQ+AjgXWMwbsRwvtNHtRxaG4/vGE46enAu2uk4+rtBVOb7S+ze0eO
         lzyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=36rCpxrUNQANDDOMRXJMiUF3zGCMKxwTkakhHkC9s/8=;
        b=0WZGdrLrF9f4eM53cXLfAjxPqb6Ivz8JnWusvaqLP0L+JfLme8mr4TknX+fnFYoj97
         4hwaFTgbdmH+OXasWOrOjnELR7ZbsYSdzDW+LIGTC38z34vGkCKlvkpqPlUQ0yCvvlRg
         qKrS1QLTiIZIPo8UZRWPBth6dC1KvF+D+dsykA+KJ9IgwQd2d1e+qtewtzpoSeRDmSgJ
         vDXPgwjJNnTBIx5UE9TJIeOndUSJaRHqkuXIqBiMsxUjYA+XZDIdsUU5hjINCAEZatbh
         mgAI2NXR0j6c/MqQSRjlFSnxdsbgN1qdNAM0HZS97n2x9YlXhhdQLGio/TWIhMJE7gvn
         07bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AL3RDltq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=36rCpxrUNQANDDOMRXJMiUF3zGCMKxwTkakhHkC9s/8=;
        b=lYIpedoP5unAn9MnpLXS/wZ2XH2MeOiblF8h6ITWKAfPG8fBMPT27xQ/5YtI2xYDzo
         Hra8a4JtNoOgLJnn3JnOYOvteIofTltg6dPxz+GU8wahgRaEAUqQeyW7SVkmnKj/KP5P
         57OA6/7BtshJVplAAbuYCVFWREhfMSdH1t7lKpCxOOh/3F1hL4WrmoC0t+mJC07Fh5lC
         RXjGMR5TB00IZjL2ecdW3dGIS21vby92NdrVBtI3Z46NHQoPhewK74yjS0yVW7jJtUy7
         MjUimDXqUCF44EjxnG6UnqOsreAw+l+eGssl52boTqTk8mf98KlyJRlB+rzPFpe7AUgi
         pQHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=36rCpxrUNQANDDOMRXJMiUF3zGCMKxwTkakhHkC9s/8=;
        b=E+utxBgYpK33xDir1GZKQiKGM9g6A5qNrJ+FKILFK2DiV8vmVd8klhe8FeiokkSO+F
         /frAX2EoCoptqOGKQJapWxzTntjzn+JWv26XC5KfISVVTQNXKKepZ3+UwHHozW3rvnUU
         uHIsa1OpwjGqQfygLor25TuXC2l19BZtILPU01RfEkcS88eo2Iriy/4vYtlh9c5lZAAU
         XiFg6fZ1j+zrfJnP9NX434aQveYqKKUUpdEnGVDApWoDLVUA+ke766SsnCMQ7LT06Onv
         +HIELdy3PG0RSU5GEfkwRlRHeeJVPyZCkz9l6JOS0dtHXY0lwr9vCCgsCZeF/dntdTE3
         FAug==
X-Gm-Message-State: AOAM530UAOhl2vBf4l728Z6yFMAHxqOBhmppJT1PZswnEBP8nLA+QSVp
	kWDrzOCVvvyRWL7GT6kq5kA=
X-Google-Smtp-Source: ABdhPJwxXGp0vpT0wilYpwWosXhDhMY82iVCu7rxIdMguPlQHTxz11EbWGPFxZFrFS7tddBkMm6NEw==
X-Received: by 2002:a67:fe85:: with SMTP id b5mr10707501vsr.19.1607365204079;
        Mon, 07 Dec 2020 10:20:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e287:: with SMTP id g7ls2302204vsf.5.gmail; Mon, 07 Dec
 2020 10:20:03 -0800 (PST)
X-Received: by 2002:a67:db04:: with SMTP id z4mr7129526vsj.50.1607365203525;
        Mon, 07 Dec 2020 10:20:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607365203; cv=none;
        d=google.com; s=arc-20160816;
        b=0m2wG6JwYlCInIrLEnLpIFeBsx9IesX+K0S40GoB7gcWiFTKpEy7gnN1Dvn2O2hoLi
         2p8KxWV8UC0d90XbmplU7DPTiKGH0k6h7A/SEmFeRvLCAGUXX9EbZXf1ycRFCB3uXfiO
         eB8j8gQGgGjlKOkC9wiMfQ9EvCqtuJ2kc5clnmgBun9pwtyDc+LvW1hLT6SCsyBAnkA3
         fMhAV4TrWvGybcNJJyU05Gtdon8Id2dA2DP4AiijB8r7jodzFyEa9SOPjC3cn827OBTP
         P0Owr7qzra664/zYolUxyFhuzx3zI6jl5IZ6WwGl5uihJM8l+e4DVxrnwOYR07wcGmzU
         9s7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/cDWtNYa74vRqhGITCqKQSyTcWEEsS+Eii6uHXqsS8E=;
        b=IaecOjL2jz0RbjiFKSI/vGHmMd0rw6rP8lplY/9nUfRzOKrDk7yjnZV91/O0oFwOmX
         DHyIeXTurez8+uiVcfkdhGUUBLRFx5NSFteK7FFvKzdEC3A7wWZX9lFSIVFEBhpgxmaj
         nlZcHtKD5BT73JcD0sPnOq9XXCFXqYm8QLoe+oWFArlDDbxLXfkvGUEEj3+Wg5BcT/ww
         FJVGnWlDLnIkSWMahZOn2RNCdSobgKh7i6gtOASakpOix/7RpJKln95MmlVm1uTWEa2K
         g0qvzuCiloF5EZ5jAafleMqHi2AJKQLDUj0945TFtRf6EeFAt6tVndz8qs+F4l2Q6TyL
         2xPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AL3RDltq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id q22si712900vsn.2.2020.12.07.10.20.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Dec 2020 10:20:03 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id i6so7283811otr.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Dec 2020 10:20:03 -0800 (PST)
X-Received: by 2002:a9d:7cc8:: with SMTP id r8mr14105256otn.233.1607365203049;
 Mon, 07 Dec 2020 10:20:03 -0800 (PST)
MIME-Version: 1.0
References: <20201206211253.919834182@linutronix.de> <20201206212002.876987748@linutronix.de>
 <20201207120943.GS3021@hirez.programming.kicks-ass.net> <87y2i94igo.fsf@nanos.tec.linutronix.de>
In-Reply-To: <87y2i94igo.fsf@nanos.tec.linutronix.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Dec 2020 19:19:51 +0100
Message-ID: <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Peter Zijlstra <peterz@infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Will Deacon <will@kernel.org>, 
	Naresh Kamboju <naresh.kamboju@linaro.org>, 
	syzbot+23a256029191772c2f02@syzkaller.appspotmail.com, 
	syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com, 
	syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AL3RDltq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 7 Dec 2020 at 18:46, Thomas Gleixner <tglx@linutronix.de> wrote:
> On Mon, Dec 07 2020 at 13:09, Peter Zijlstra wrote:
> > On Sun, Dec 06, 2020 at 10:12:56PM +0100, Thomas Gleixner wrote:
> >> +            if (data_race(tick_do_timer_cpu) == TICK_DO_TIMER_BOOT) {
> >
> > I prefer the form:
> >
> >       if (data_race(tick_do_timer_cpu == TICK_DO_TIMER_BOOT)) {
> >
> > But there doesn't yet seem to be sufficient data_race() usage in the
> > kernel to see which of the forms is preferred. Do we want to bike-shed
> > this now and document the outcome somewhere?
>
> Yes please before we get a gazillion of patches changing half of them
> half a year from now.

That rule should be as simple as possible. The simplest would be:
"Only enclose the smallest required expression in data_race(); keep
the number of required data_race() expressions to a minimum." (=> want
least amount of code inside data_race() with the least number of
data_race()s).

In the case here, that'd be the "if (data_race(tick_do_timer_cpu) ==
..." variant.

Otherwise there's the possibility that we'll end up with accesses
inside data_race() that we hadn't planned for. For example, somebody
refactors some code replacing constants with variables.

I currently don't know what the rule for Peter's preferred variant
would be, without running the risk of some accidentally data_race()'d
accesses.

Thoughts?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNQiTbnkkj%2BZHS5xxQuQfnWN_JGwSnN-_xqfa%3DraVrXHQ%40mail.gmail.com.
