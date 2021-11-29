Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAOOSOGQMGQEDPRZXGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C0E0461A29
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Nov 2021 15:43:16 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id m9-20020a056e021c2900b002a1d679b412sf13667086ilh.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Nov 2021 06:43:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638196995; cv=pass;
        d=google.com; s=arc-20160816;
        b=RnsRItTehwEd4ihgwvGoVh46p9xuLNqEM0xhopLHBudMJlIA91n4NmthjZgiX32BdO
         4PZuayiHr/Bs4JCBIg0crC4xeclSNt4NC6Kdi7VZENDG83ViErrqg8jk/Ebd8h3NgEId
         mMuXneEsksKVUlWl+uj4nkdZHGHlZBuMZT9NplzZfqM3p0jpe6qq5jKBUF2o/jNzSzgd
         NmpBWtcppmh2RkLa2hpaewsPwT/0soKuNE51GLC4FHDQDwzeJFTWt42cvP7GhpLDegLK
         gXD8jHJ6EMK+7ux+rAH3Kj0RBMSn1nYKqjwGalySlFXfAEkvaCSEHw9xB0goI3cmhM6k
         kGAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=q/CtwZpJhTUOJz6n+QCToQW0SpdpVo+Ldv6OaeWUigI=;
        b=Mb+lyv9NcmcCScVYK0MA/YTZIxzAOHGlfbb1wGR/1GvTBUgi84DiCItG2sGXTeW1+6
         tXjaEXOI2ioFWS31p9T39R7tK8gWhNGUcR2sHOcRCifiyR1Pqr4sfB3HmFNkyl2QhZBK
         z9yt6lmsa+vu+G/QIDe+ELfPrjj77g6fG8eWr33Nn21chR30ZQWgQWuPH4hSAXQedRZ1
         TOTKxPQBRjTuIWCRG5Px62jGDgIm1e4Ov7mZJv/Xj896cUNiPlAOXTCMVIa8qBsfN5rz
         VaUBSqGUUvyLtRNgo7o3Mx20sVue9Hsb22wmrnWGBq4dp6Bkug48ko93cMKEc6KIP2Y2
         247A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UYFA5+Kj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q/CtwZpJhTUOJz6n+QCToQW0SpdpVo+Ldv6OaeWUigI=;
        b=PHMgIYNwVRnX4p5Mhm7yD6BSVbNZtGl9K1ZYI4LPgAJZygFUCcwqZ6MdtZ8eN+qNXg
         dK+MfnpmxMaqys5948WSODfjXASgHfe+DzMoENO+uRQI8574oEbJQebSOBmr5HC6BG++
         jCNd4DhOxv5K78V1ZUBBC03NqU7HQm+nWYKvaeoY9THfGYlDXISSR2SfOmEnZ1eo9huD
         CDlv8O/Uyxe1RqY0Jg13qA/40lgG5V3/ufBdsexU+U1OW9ezUQBuv/603rKnhfWggqqs
         OH+WVRvVqAAS8mRvLlLrDruwBssUb9DMvjAO2wo17iuDv5bA7VFhRbAPMHuu6coH0q/P
         70xA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q/CtwZpJhTUOJz6n+QCToQW0SpdpVo+Ldv6OaeWUigI=;
        b=cs5/Nlm9EHlFTZ+MXUnrwti24oUP9+yKE1ACs3DtFSP6aexukjJqtg514+jzXrhIfV
         d/r6UCwEMbd20STn4bvUcIZwcM+QoaAilA6C+K19scgxh1q1w5wrBczgSFbeqHYgmq3j
         EEM5Bhl33evJDjLRN/kAZ4LAOHxZi0cB/tfI8iQ+LMfK4ZqkSQKzWrp0iLJC8uPYsPlO
         sjeU3rwPPQGuGnHWsH5NWc0rSx5YvsuH8ZIGQHZzmGQ9xBSa70cNO2aQAwn0e+2MeUSO
         Lk05wQTXiY37NOMDzCDhqH8h4l2go4OiOfhkAxrHqgC6oYhqh4Iak2dYYSp53TMte631
         Wj8g==
X-Gm-Message-State: AOAM53183BF39L2avidBppKQINUaUq865qUMQK0WNjlvRdNk0tgHJNWb
	OUwnDd06uFIQD0Do1FcYpEg=
X-Google-Smtp-Source: ABdhPJzqpmBALPbncOyOfSs+yaDABsAUaMZMjtkedarvPZaVhYGCfLx0US62Ncee6nbHQZdNIUcT4Q==
X-Received: by 2002:a02:b616:: with SMTP id h22mr66629007jam.127.1638196993696;
        Mon, 29 Nov 2021 06:43:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:cf13:: with SMTP id o19ls1521315ioa.1.gmail; Mon, 29 Nov
 2021 06:43:11 -0800 (PST)
X-Received: by 2002:a6b:f70e:: with SMTP id k14mr54800236iog.173.1638196991840;
        Mon, 29 Nov 2021 06:43:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638196991; cv=none;
        d=google.com; s=arc-20160816;
        b=Z8DUhlhTxWxHHukK6oljN6LiAYLZLKJLNlI6KfMPDLTxT6TaZb90TkLXEZzz17xTf4
         eWzg9mPoCl0/yRvFvpfR4hdlrOIdiqP0++EdMn8KoXY2JAC32ZulWnRBNmXYSMTfBhVq
         Z63YXsHGJlvZAnRBIKILeqdoKoGflKR56D8DSeSiB5LI+nApQ21apONrXyIyZUw0Twyj
         /w8gmLCDAS7nnIddo8/k8SgjR/QroY7K7dEJA+a8AJakv2nN+jfGwW4Ch85WaO+TWLcg
         a4HGQEXqX4IddpZxcQ0mLrYgYXzggvd5GgeSyZzimEHmI6waOEhjzQPeXUmpbGXh1u7p
         fXCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3mz1HPmHbMNrW+p+9eQAxOprfgUAji2Y3fPOhA732u0=;
        b=rEZztsOas5igVa+7d5JZJDqlOJfaJgJFlSB3iqw6EYjwXg6S2DzC7t4AU6j3fPtisj
         dq1OiknJjgc4DtbLhMXVoq/QQU2c/pw5kdXPyLMQw6kYBfQ/RONPyvPsmmlI8z4WTCcr
         yQ9PzxU0794dgSO+3dqLwXHFI55JREU5kYLC4/J8IEi/qGZ61uqiu33nVz3hefNNYJ9w
         7otBBTd3HiJjoohj97uQIxfA3oU0Y3FG0QrKDxxbIBPJE4WwU6COwvm4hqa7b23I/IsY
         sP0uLsK3oSsQb5PLx8ava1rH+gf3vphBhdzc+IFZt4Usg2/LYpgAdkdWy2g6MpNJ3VK1
         vi+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UYFA5+Kj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22a.google.com (mail-oi1-x22a.google.com. [2607:f8b0:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id q3si562464ilu.0.2021.11.29.06.43.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Nov 2021 06:43:11 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) client-ip=2607:f8b0:4864:20::22a;
Received: by mail-oi1-x22a.google.com with SMTP id be32so34963334oib.11
        for <kasan-dev@googlegroups.com>; Mon, 29 Nov 2021 06:43:11 -0800 (PST)
X-Received: by 2002:a05:6808:1903:: with SMTP id bf3mr41684658oib.7.1638196991401;
 Mon, 29 Nov 2021 06:43:11 -0800 (PST)
MIME-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com> <20211118081027.3175699-4-elver@google.com>
 <YaSTn3JbkHsiV5Tm@boqun-archlinux> <YaSyGr4vW3yifWWC@elver.google.com> <YaTjJnl+Wc1qZbG/@boqun-archlinux>
In-Reply-To: <YaTjJnl+Wc1qZbG/@boqun-archlinux>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Nov 2021 15:42:59 +0100
Message-ID: <CANpmjNMY7nhSq6aBLMusvbaMQ3LFJ=beHbDvbudg9B-NoFxEpA@mail.gmail.com>
Subject: Re: [PATCH v2 03/23] kcsan: Avoid checking scoped accesses from
 nested contexts
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=UYFA5+Kj;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as
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

On Mon, 29 Nov 2021 at 15:27, Boqun Feng <boqun.feng@gmail.com> wrote:
[...]
> > This case is also possible:
> >
> >       static int v;
> >       static int x;
> >       int foo(..)
> >       {
> >               ASSERT_EXCLUSIVE_ACCESS_SCOPED(v);
> >               x++; // preempted during watchpoint for 'v' after checking x++
> >       }
> >
> > Here, all we need is for the scoped access to be checked after x++, end
> > up with a watchpoint for it, then enter scheduler code, which then
> > checked 'v', sees the conflicting watchpoint, and reports a nonsensical
> > race again.
> >
>
> Just to be clear, in both examples, the assumption is that 'v' is a
> variable that scheduler code doesn't access, right? Because if scheduler
> code does access 'v', then it's a problem that KCSAN should report. Yes,
> I don't know any variable that scheduler exports, just to make sure
> here.

Right. We might miss such cases where an ASSERT_EXCLUSIVE*_SCOPED()
could have pointed out a legitimate race with a nested context that
share ctx, like in scheduler, where the only time to detect it is if
some state change later in the scope makes a concurrent access
possible from that point in the scope. I'm willing to bet that there's
an extremely small chance we'll ever encounter such a case (famous
last words ;-)), i.e. the initial check_access() in
kcsan_begin_scoped_access() wouldn't detect it nor would the problem
manifest as a regular data race.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMY7nhSq6aBLMusvbaMQ3LFJ%3DbeHbDvbudg9B-NoFxEpA%40mail.gmail.com.
