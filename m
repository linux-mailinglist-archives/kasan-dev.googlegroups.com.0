Return-Path: <kasan-dev+bncBAABB7W5XL7AKGQEQLQF3BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CF1F2D1D6D
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 23:38:56 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id f3sf3602205pgg.9
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 14:38:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607380734; cv=pass;
        d=google.com; s=arc-20160816;
        b=RccgjctTLDrdpOlN0apFiOY4l1q9jeiXA7HtY6nALawKPXWiEra9jjG0Bwrn3Uv1dN
         FlQrLgXX7zKKKTx5Z9vsbG0+3yweCbqhP0/P5DrkOugHXFu1PPhPZX0TSEcmjKV8qYPu
         mUZrIYvdEZuvMqD9kiHPtU87U8HX9KTfsvwPlemxNVfEG36niHPbmScf8zL5o6LnYzVL
         aR9+qjnOTHzfyuXHGLFWLrLWZyMJkwQw0hCreCkVUK4mAKBxr/2P3SEoLL5j4et6/lRS
         9hHFhPJbx2tE6hEH21fT3tXJbLD6bDgWBerOWxoNEdv2nRfOKkzhr6yOO1UIgHVCiQk2
         SdYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=xe+BHnedDNMrFmWJ/3bhcIguMfe2cxzMRILgfjON4s0=;
        b=JzOnBj05SiRzGPkaFNBLj4VWqw6XnDDMV1TsyEQApa2zPaSN1xDfRxH4U6VA2JEG/7
         zWyd95ptQPdOzlpaqOfs+OEYWcChXI+beUtzAHQZ/YCv/zn9MKjG7t8t7iZ2uYdn3TP+
         zouug3hxbcVSrvgjMyh3/nHSJasCQ28+xjaY2o+drh/FeJ+KVfejuWWckZXozga1viYe
         o0/OHYUgEdUcz0778EJkvEL0Td3SgqIDksTWch2atYP4xRjuuDRA0DXbnisnXglqJwmQ
         eE23LDqVUSF7MGM4SSnnmq5usYED9Qx6miZkstFRhQTWZuIufKOmYFj/ZnEzsE1NW2Th
         jLKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HG3baAYg;
       spf=pass (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Y2I0=FL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xe+BHnedDNMrFmWJ/3bhcIguMfe2cxzMRILgfjON4s0=;
        b=GtBowdLRcM2wca/XjjpQMBA3ToZiLQq09VUR/kOcGYxsHcaqRtqUGnSRXdCw0ZmHKz
         JGzz41AM0Qd9HmPn6Ku1xA3jZZsUM8lSm2AQ6K8w/VpaNDvTyZUK6RL21Lvb3gV4qTP5
         0HCuBqHklLwDE3Kwt2VOV4PJgz4sEb5ZTccmcFoxWRezEKCEVjmOmuaBJjpgy99d//2t
         XZ1Dgygn7KG5pYWaC9gwZ8zeL3iijWSnV9CL1eZfulrDD11/YqTKENQHrBJ+tUk5IX32
         WupkKVhpWPDtYE1WjD5VJ973tGCYCRyCJ4afu+YojFeY9cf+yxmPo5AgfrpQ3zCA50in
         CpVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xe+BHnedDNMrFmWJ/3bhcIguMfe2cxzMRILgfjON4s0=;
        b=ErcA/mJtcR1neGEFNvblkowOhTmy4B6lt8YmYBiclrL0QlATY9+PAf/j/9KTK5e8cs
         sepwVs6WNEBviEyKuSg/Wr9dc3+RzicNW3JIvnjR4HgwOjPsBmlUxBImzRW+Zl3xVHBK
         VWwyFgg99a1x9dl5zwYELk3342MdHSviI3x9CFqO6xMedY+2oMjRWVFOo51/6WRRKF9b
         3GKeY9S7SPUne+Trzf7o7BDjvXYMqi1ych0t7eW4Y3HaY+qxUzmms5RXGzwpjPgqCuVt
         R0qOf9Zd2thyypKrNSk0TSZ2A1nqTMX0sugaA+x0KYr8HTbaxtbmTX2MqYwQomDoF3CX
         F/dA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531sCMxttSEm2nq2zM0jU++PtYXc+eJhBNFI8hgQZdcPF+RMMAlY
	3Tttc+nBgmyPRsIjvewCqok=
X-Google-Smtp-Source: ABdhPJxD2W6gjDg/YgJWt/oHb99yXUjCBQ19DonXOFk7YSU1Wz+gspTJWDPb7Sujnaps594I3nye1Q==
X-Received: by 2002:a63:c4c:: with SMTP id 12mr20115241pgm.428.1607380734716;
        Mon, 07 Dec 2020 14:38:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b893:: with SMTP id o19ls282306pjr.2.canary-gmail;
 Mon, 07 Dec 2020 14:38:54 -0800 (PST)
X-Received: by 2002:a17:90a:8586:: with SMTP id m6mr959618pjn.9.1607380734059;
        Mon, 07 Dec 2020 14:38:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607380734; cv=none;
        d=google.com; s=arc-20160816;
        b=0Cs4I6VrCDVca8VZno9DwC+VKhGTdFj0JZI5Yr1oBi+qNDAxStWrxAnDD/iEndEuSi
         V1PN9kW9vM41f9qNuwAbwtxskgE2yhaXhJRYe0NqguzWe5Up8Zc8koSM3aTTKXwGkXSe
         anx5fWJ0uNuec/H/zncmmfd25B7Z+Gmu2BzNt3szcIjzB6cD4A+k4tEpXY1w1dsE840g
         2hpe/YEumJ7UKQMrFgJIkKE+xc6pXs7FhttrlJGpxaZFi4pvCSn+kLmOuN1HyiUU/xoD
         xOxIBnQJM8CWA54fe8XgAhuEdM3ZugQGDf1SnsrqbOyf7Q+8o+eZZbxxEUAw68VgB9Ls
         qwVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:dkim-signature:date;
        bh=d/PFNnH7cOKcF3pr4HoMA4sYrNTV0HPj+9NhuZH4bL0=;
        b=IldBP5U+86nqbzXmoOVOraJ9s5MvE455tqlQrCgGlMfZAQhJ2qczi2EzhWPl3p4PD0
         qEMT3pye1Xc1GgfUo3YA0gN6tHhT33VzK8r2eE7R4C6bvxWtpAvqdNNFNkHnGXe+TQde
         6jBF+5UAiwUzAkxQEXVjp6xnoXTbAmJh86KFwLWtmo9+McRrSkbLJF8M/GDvIS6TLd8h
         8Wfpc4bhBPjtZOTIjFjSXEA1dyHwzeG9D8PkigQy5CWZpEZGRYIKaUuROCimpeOHUBiB
         VhQG2qF9EuOYwtR/vUGrteb466xNeJPn0koHXQeYvOMQb7SO2JkXBaV/P5jy9Bv93kWO
         caVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HG3baAYg;
       spf=pass (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Y2I0=FL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a8si1102316plp.4.2020.12.07.14.38.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Dec 2020 14:38:54 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Mon, 7 Dec 2020 14:38:53 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Will Deacon <will@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	syzbot+23a256029191772c2f02@syzkaller.appspotmail.com,
	syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com,
	syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
Message-ID: <20201207223853.GL2657@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.876987748@linutronix.de>
 <20201207120943.GS3021@hirez.programming.kicks-ass.net>
 <87y2i94igo.fsf@nanos.tec.linutronix.de>
 <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
 <20201207194406.GK2657@paulmck-ThinkPad-P72>
 <87blf547d2.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87blf547d2.fsf@nanos.tec.linutronix.de>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HG3baAYg;       spf=pass
 (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Y2I0=FL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Dec 07, 2020 at 10:46:33PM +0100, Thomas Gleixner wrote:
> On Mon, Dec 07 2020 at 11:44, Paul E. McKenney wrote:
> > On Mon, Dec 07, 2020 at 07:19:51PM +0100, Marco Elver wrote:
> >> On Mon, 7 Dec 2020 at 18:46, Thomas Gleixner <tglx@linutronix.de> wrote:
> >> I currently don't know what the rule for Peter's preferred variant
> >> would be, without running the risk of some accidentally data_race()'d
> >> accesses.
> >> 
> >> Thoughts?
> >
> > I am also concerned about inadvertently covering code with data_race().
> >
> > Also, in this particular case, why data_race() rather than READ_ONCE()?
> > Do we really expect the compiler to be able to optimize this case
> > significantly without READ_ONCE()?
> 
> That was your suggestion a week or so ago :)

You expected my suggestion to change?  ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201207223853.GL2657%40paulmck-ThinkPad-P72.
