Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7WC7L2QKGQEBINQQDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id AA8F81D4FE5
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 16:04:48 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id z16sf1895818pgi.5
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 07:04:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589551487; cv=pass;
        d=google.com; s=arc-20160816;
        b=LAUF76ajgTRIR+l4TSiSny+khx67WwXOJFomHeca14tKMKO3BEm4O1wv03s8eYf1Zd
         JZeGewqefjHyWHa+0cv8uGc/0JWGNkUXFuK5KX+xOhUPzq0udGet2SuypGi2PUa/psks
         0Qv7MbS1JnjUaL2EFJsjuhd6PA0TosoxfyTfJjGBfsbnoQzTxeLMiTqRznREk5W4+tym
         N5W5RXyw8t50i6pNMoRK9hJs3MB3SauH7vb0YQyPbFTfmN04tQdxz0WVMb31JkZMGreh
         SCOhxwco4nIipbwbSqDzKthUQWTRFVfAusWwcd5FTVpTvL4Mq/iUbUkxeu6P2L6tNYvV
         E37Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Oj3y3PIeKNobt5BF993YqRaZBTB8ITQNcjUoAPCDnTA=;
        b=dDrRT1aaUAzpTgwS6LVtuTrWpi3MK2znT0r4Nlzww4JAkYY+4tRp4XU3oHgexkW6tg
         ONvFPX5DA87VZVw4s8Ayw7AJ9AvpLluE3L+L7B+zFcIVBhx2WKCmxX8frZJfxRG0mcPo
         bc9S5WbP9zrtLJ5hX1h2TCbXA8DZr/rEoaXiUxWaQKiRXBv6zjcazi1Rg3fKkVDAwyxb
         /uTYcblrZtUtJ5uKekxz9q8WM3tUWZclY+GoJxn2a8KLzpDHWim4y0JeXl3t7VYwUPZw
         CS/G0yeEjsb+OFZK56RB4PjLb5j1Qjdpvy2MZUe8E2EmuufCxxcTRcvxf9nn3qvqqlYg
         4yEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KNORJ8kq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Oj3y3PIeKNobt5BF993YqRaZBTB8ITQNcjUoAPCDnTA=;
        b=jZ5CxTrNKGOVBb1PL1aHdPm9AUFz8zI8EpUIGVHXT7Y2L4h3TAzXzR7C0++H9+aQd8
         cRzqdfGKjnvc9e1bMeQxM8yZ5IAZ425iohfLy3usclotI/pZDhrAzgQ7DQIDRaRYLFLR
         jACvWLJRapnixv2uqG785sAoQ9xpbJpXPdGNJbmXPDJ5kQHcYO80FsHgT2f1ghzzh12q
         SOYzYFuq2UoHHVac5bASObRRlNx1sKYX0n6LoEIj7YeOCGot11CjtZEcDP+0jjHB4ndS
         f15II4vYt79zfGOMO5499NbHK4AdDc17KkhM9ia75+AI6QCjKBS7wjyjHC+q9JmBLvsp
         WoJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Oj3y3PIeKNobt5BF993YqRaZBTB8ITQNcjUoAPCDnTA=;
        b=T9p8axCzJUiuD63gLO6dT+U7sbEa3+jDQS1zP2Yl5jUiRJK/6msAmzE7spFklbNuKf
         VZYGmP+2DoUytSIiZFER6tOwcKZontYvfU9VU22jzFGeBmxw9efPIoBirLv8UskxFu5B
         qaho0FVLnKbKIhCcuMo3NeHUG6YnanCRKR23flTGJV8ULdoL/nrFOuGFZAqyDT4UiN7v
         c891Xj9nZ34Brk8Z5dmXaTXngfpm7gG/jT1BYdjfYSuft3c9J5jxh2xvO8rnmb46kcbJ
         9+w1oJrkFPK6Lq2tqxi1t3JfuqMg9TjAZNm5DhVq2Sg2WJPeV1tOqv9I0s7+pUTuQFTE
         /b8A==
X-Gm-Message-State: AOAM53008pm0cpaAE624gNvGjVG4qIZl/5UhoJ05FNPkww/30062rjLx
	BR7XkS3vFMrdI5JHFFffSp0=
X-Google-Smtp-Source: ABdhPJxfgVvU3ktaV+tSR7ZFeghPvS60fw13Ov2d0KK4Lwi76Qpw9iLfrpul/QOtiw0fCeYTLfl3jQ==
X-Received: by 2002:a65:418b:: with SMTP id a11mr3493508pgq.61.1589551486934;
        Fri, 15 May 2020 07:04:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4b5c:: with SMTP id k28ls788421pgl.0.gmail; Fri, 15 May
 2020 07:04:46 -0700 (PDT)
X-Received: by 2002:aa7:80d9:: with SMTP id a25mr4271714pfn.220.1589551486459;
        Fri, 15 May 2020 07:04:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589551486; cv=none;
        d=google.com; s=arc-20160816;
        b=UA4YlyNWrqdAYy7cycv7zjjC/6kezcHlvHMDjoD09P8dOtE8MKtBDdE+YbLvg7uOGo
         Aeu08sFV3S6pPh95oSQKKxDwr3YGcgMkDJMz7jYIJTuenpqv5Vmg3mUEeJs18i7++kd+
         fApJ6rqc7tDFF98+mZwYRjNN1/M5JuzgVc/zF1E8tBahXOzRL4SQTXF9Gn4lRS/VKZdD
         0vtUPLwgutHkhqksaA9stCs0uJBiTikbNpnrEVrcH9pXjSvMSaIB7zhIbqd1eQssCfPq
         1lbwZswQEIMnB1wSqGNOvkE0dqGZ6I6T7lTAfQA1ZOQBgi4JWJK9Byfpkrl/JG/5nKzd
         Qy3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vhaGDwcFvYYQSyxtP5zz3pYpd2ByNv+4SWaajJkndn8=;
        b=JHFdvXwNLcG11O7e6HTVAmps12crjwBRz0vL6UlXhxJs8Lhp4ZzEuHPcw02DHVxIxp
         tp4DlJCouS/1fkuSlpUK8p5PUrX4kY4T1cot9uARhnOqCCh+9pi9nComcwDdMHsewd6p
         on511iPw2nwXPnaYw4AjXhBRE7Nny/Nh4i560h9gqTDjM9XBv3EqN4nmahIv+zavI8+y
         joWo/7UkSwdcQVyg9rctTqv8TqVIioawW0PyrdkHLrpEMQqJV8ppnIXovOS+0g5wjL8n
         sYvTDd0MaLdNq75Au406cH7K0GySeaqOPh9GLA7d8F7lSc3E/By3bgvL/qa1sEG4DJU0
         H4dA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KNORJ8kq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id g6si154524pjl.1.2020.05.15.07.04.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 07:04:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id t3so1975925otp.3
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 07:04:46 -0700 (PDT)
X-Received: by 2002:a9d:7608:: with SMTP id k8mr2547789otl.233.1589551485552;
 Fri, 15 May 2020 07:04:45 -0700 (PDT)
MIME-Version: 1.0
References: <20200513124021.GB20278@willie-the-truck> <CANpmjNM5XW+ufJ6Mw2Tn7aShRCZaUPGcH=u=4Sk5kqLKyf3v5A@mail.gmail.com>
 <20200513165008.GA24836@willie-the-truck> <CANpmjNN=n59ue06s0MfmRFvKX=WB2NgLgbP6kG_MYCGy2R6PHg@mail.gmail.com>
 <20200513174747.GB24836@willie-the-truck> <CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com>
 <20200513212520.GC28594@willie-the-truck> <CANpmjNOAi2K6knC9OFUGjpMo-rvtLDzKMb==J=vTRkmaWctFaQ@mail.gmail.com>
 <20200514110537.GC4280@willie-the-truck> <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
 <20200514142450.GC2978@hirez.programming.kicks-ass.net> <26283b5bccc8402cb8c243c569676dbd@AcuMS.aculab.com>
In-Reply-To: <26283b5bccc8402cb8c243c569676dbd@AcuMS.aculab.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 May 2020 16:04:33 +0200
Message-ID: <CANpmjNNLs+PZfcsb06fdfokzDG0dZSfxDh=b-tvCWt4qoBEZng@mail.gmail.com>
Subject: Re: [PATCH v5 00/18] Rework READ_ONCE() to improve codegen
To: David Laight <David.Laight@aculab.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, "Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KNORJ8kq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Fri, 15 May 2020 at 15:55, David Laight <David.Laight@aculab.com> wrote:
>
> From: Peter Zijlstra
> > Sent: 14 May 2020 15:25
> ..
> > Exact same requirements, KASAN even has the data_race() problem through
> > READ_ONCE_NOCHECK(), UBSAN doesn't and might be simpler because of it.
>
> What happens if you implement READ_ONCE_NOCHECK() with an
> asm() statement containing a memory load?
>
> Is that enough to kill all the instrumentation?

Yes, it is.

However, READ_ONCE_NOCHECK() for KASAN can be fixed if the problem is
randomly uninlined READ_ONCE_NOCHECK() in KASAN_SANITIZE := n
compilation units. KASAN's __no_kasan_or_inline is still conditionally
defined based on CONFIG_KASAN and not __SANITIZE_ADDRESS__. I'm about
to send a patch that does that for KASAN, since for KCSAN we've been
doing it for a while. However, if that was the exact problem Peter
observed I can't tell.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNLs%2BPZfcsb06fdfokzDG0dZSfxDh%3Db-tvCWt4qoBEZng%40mail.gmail.com.
