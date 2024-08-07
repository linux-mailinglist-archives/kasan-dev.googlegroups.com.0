Return-Path: <kasan-dev+bncBC5OTC6XTQGRBI52ZO2QMGQE7NJ6MZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B819949DC7
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 04:34:13 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1fc60f5f8e3sf2957565ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Aug 2024 19:34:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722998052; cv=pass;
        d=google.com; s=arc-20240605;
        b=bTgvdJCDF8bZvs6aNhuvMkdwtXvSWUobRM8kyM0RnYjFIbbiDy7EvAJl2bjb1LQlDf
         FYu72rTPq7Ak43SRvV2xWXxTaZh/Hj2oVgBHSOsTkVHa+ZVDvIc+PNM/QKlDUqCPiVId
         hdwn2oQCsjy4VqYVlJuV6gh4JRUIM4ctxmsuBs6b1NAX2LKC1IFRxa2aEZUTFJ+36PjZ
         JYlJoIgBtPULfX8/6o9x69C/l2YDJiBo6RlhixBRwvwTgYSrOo+o/XpIY8FS50klq5m+
         b2L6bCzKmUAVgZ/52qK3g6EVZ9E3kBYx/7ar+Cjd9eNlsJT7okjl/D0BNXaSbt4d8tQh
         GWIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=ys6TlAyCKxNLjHqhLOO4GWNzDw50CaKmx0xyzULIK0A=;
        fh=ZjsaXc0fHKoBOc6VlNTNysV1W7D9tIubWkmsl/WhAcE=;
        b=Kd/LsHE1bdhUlluL+AMHYMzDp81RvOMdTdjrJiBO7V2rVEe6cYkE9oIvL7jB8R6Du1
         TPT1QzooYkFIYG3deQQiw8oRtFZ88EB/VPH2VWLRCmhU08bwehhC9FS7KxEdD1upIPib
         fHAeeD1zWn7maqi6xhPkgCR8x0ctAOUrs5t36AK3DnOUxiBPApAM3Ni3f/TR8xDAnCqO
         p8ompP9leNkGsI/3kMAs697eqIIp5QPN6WIc0PnY3pxhhD9G4xLVa09MfCrw/9gikgWm
         +6O9gvi0/lTW5WtNJXk0OD5D91avxKkitRYjvJKL53DWrlghpJDvA0SRKDW06TtbiJUe
         RX8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EeNXxzFW;
       spf=pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722998052; x=1723602852; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ys6TlAyCKxNLjHqhLOO4GWNzDw50CaKmx0xyzULIK0A=;
        b=Sz7IHe9qjb82FVaYXfrx6AH5UYrG9sjAvlIs/dQAsEh/DBAxp1vuorntN6MO4A7lKi
         lj8NaBc1MYRYHW6RwRCSCkjtdHLYuow/IzssTA7Jkdz7PyU8qSpv+n5IGGbmdq2CbXx8
         TnHWEQC0PxVgSJq1bbwsESp6jhBNmyhyD/0xewMyWZ448odV3vOwEUwGD/sqwbxpA11r
         7DP+7h6dd5cYI5kCy5LtkUswjPl7T0PvT8AB5QVo89ozHjLfRIiG4KQQJ1Rg7mXQ5BFb
         /JB0OENbvKbTeq4JNEy0QRpROlSeKuYw0+SF0mF38PYE8wZLIF7XpcEj56yz84HW+rEw
         /oYQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722998052; x=1723602852; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=ys6TlAyCKxNLjHqhLOO4GWNzDw50CaKmx0xyzULIK0A=;
        b=gIIGioVG1qfasUvsj9TPHijoOOeNcjQkqBrLbnyv8enzv3YYOrPH+lyInqXX7SkfcE
         1Ow4nOam/Bg0KMILfvFwx4AMuS54BSdeeOoh0ZjREdK6ibOF967MfKVF/9V/2GlfCy3T
         wSX6IXWBtLeICblYpDdfKoFS5U8jwmllvkmZ9xAsHDa7CHI9K5V8gX2D7CT6qa4vxhlr
         A6tyKkFPWJi1cyQjIkSMGK340h6cH5Phz2U7UHcqHcZtUjXZb4PaUy/7j9LCtmEDkhNX
         5NGbiUyTMH3ocYw4QQRVKoHaJHjk9jTYeuPKGqtHKDal++KG1PE1/Ib76QjK3VVa9pmT
         ofpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722998052; x=1723602852;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ys6TlAyCKxNLjHqhLOO4GWNzDw50CaKmx0xyzULIK0A=;
        b=CJ67C+XCRc/f25EocMzV/6luW8HiqefdGOpflWaco6UiJGQcLoo8FoER1IsLWbLpoj
         M/zklM518Ks7GKw0QxcOhjumVCWRT38CU9wbMYWInqoOktPzXcG4qjVWaR2mvFzgb6GT
         SAWGzzRjwRBDaa3fnN2r2FKSw/RiHYBcdiQz1jSMEJBCCPFfGQdimXBLM8jH/DJkc0yo
         RubbquiqRWAn6/AzuMkQYFq3DiLRe0NVFTg6qEmj+MjzIobSWD4vnC+RrUcymlTK5Afu
         BYQWK+1aMNy/oszofUSfgRasVpM1J7f3SEi3MC7g6KetPMuUM+KGT6EWyDL08xtYk1QI
         5aNA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZ8ewPcTTjTqRRAkLb+aw1wfoiB99kzK+drnmDtHUauTnmYLdSWBK7cg/vX1ou6yfsoIG+mctzYlMQJQ/Qi+ui5lQHUrRZ2A==
X-Gm-Message-State: AOJu0YwB8fGrq+VtJraBkelNalXU6emqk5zL/OOs4p8aW2hi9ad8iW8v
	0tTqO4hwvzZdLev7bvhskwb4k3d8s5nEt2kZgjRm0qR92+qavHlw
X-Google-Smtp-Source: AGHT+IGhcPUzDyQrWuB1LhaA5SKLfrgcQdkqAlDLtHj/SzB6dWMbg2PNTyO8Rrbv/yfTPSmIUF0KOw==
X-Received: by 2002:a17:902:e883:b0:1fb:172a:f3d4 with SMTP id d9443c01a7336-2008368c8aamr1769745ad.8.1722998051435;
        Tue, 06 Aug 2024 19:34:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:140b:b0:70d:301c:fc55 with SMTP id
 d2e1a72fcca58-7107d8916ecls2250832b3a.2.-pod-prod-09-us; Tue, 06 Aug 2024
 19:34:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQlea9LRYmS6mVDN2XYOQbfM0qgPEPIDvrSjjsHowmFfnG82yha3cd7KdbwCOSC/E0cxg2EmzGVrVqLeiHUaN2rbo5xetNc4CBcA==
X-Received: by 2002:a05:6a00:9146:b0:706:58ef:613 with SMTP id d2e1a72fcca58-7106d046c77mr15899510b3a.27.1722998050206;
        Tue, 06 Aug 2024 19:34:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722998050; cv=none;
        d=google.com; s=arc-20160816;
        b=nLb1X9TDbS97RW08xsO3sFwzS3WxRxIUgMALrdmnlD1wrAIExlZ2iEahghs9MWg90e
         l6wPfJIlofUBuZ5iadhxvhPpTr0NVgc6k60DjlJIzjEIPTcsWL6+tt7kaHOGHvEEhWLm
         0Lwf/7V1rAQnfGo4L/NpNfzg4RJviO6dClFI6WWu5S+Eb5xOUjNxHHy6Ud9XcG+pGNmJ
         H+z45zTOwTaDPVcImXL+7h2arnNfvszglIYLGKpVhbbsHH4VNyHrlhEtIXPxDmIKOiXR
         uJk0FKmrXhM9ZCOT9hXHw0KUO5Hq4Q7ejDn3UnCDHOgEgJYVlPD3SV156AZHW8qk8Qb5
         g81A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5X4EYGQ9bpDes6QWo0B6v6ynCxmNh3uLrf5+8l6O1Uo=;
        fh=0Bzgq4LyKU+bYJBZ6RUwPNg6nU6BcY61dFIbIsv0f0Q=;
        b=iUZH/qgm42HDeETsZNUkZ4GpWBTrKb/3FWgA+1pUfkegBw4fuT0JO7sFC4X6qcKIqL
         oNQ3priYOIBPT7cBt8nspc1djmzVoviKzGSDZCavEXCykTdUugtk/SUinImCKeEwhyg1
         +hg27XjPnXDnoyTyGARlSx3aNAs7qTJ/c/vTRnkhgalldCpoF9JvKDXeP/Zo17Bo+6Pb
         1yqlDuKMLGVw566qen15soDx9Bbb7SC6QGOSxsPO0HVoTn2i/QWd6/vz+K0fj3pNI52i
         jwi8ynFxDSCsCGl5Wl+IfQiGJMcpYITvfbRl0pJVPekw+/41yZRmee5UPN4/aW0eYPPs
         3Yhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EeNXxzFW;
       spf=pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102b.google.com (mail-pj1-x102b.google.com. [2607:f8b0:4864:20::102b])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7106e7f3199si522410b3a.0.2024.08.06.19.34.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Aug 2024 19:34:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::102b as permitted sender) client-ip=2607:f8b0:4864:20::102b;
Received: by mail-pj1-x102b.google.com with SMTP id 98e67ed59e1d1-2cb576db1c5so871357a91.1
        for <kasan-dev@googlegroups.com>; Tue, 06 Aug 2024 19:34:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU3+cTWUFwIbERHY8RevUc+7uGAT2I4Ef5wBCrFpClub3IuAO72hvnMtdOofoK6/eemTEDJCrM5QGXTXrOZCfstzoSKlXbDJM3L/g==
X-Received: by 2002:a17:90a:fa0b:b0:2c4:e333:35e5 with SMTP id 98e67ed59e1d1-2cff9553864mr15410645a91.36.1722998049580;
        Tue, 06 Aug 2024 19:34:09 -0700 (PDT)
Received: from localhost ([107.155.12.245])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2d1b36bb3f2sm222306a91.19.2024.08.06.19.34.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Aug 2024 19:34:09 -0700 (PDT)
Date: Wed, 7 Aug 2024 10:34:05 +0800
From: chenqiwu <qiwuchen55@gmail.com>
To: Marco Elver <elver@google.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH] mm: kfence: print the age time for alloacted objectes to
 trace memleak
Message-ID: <20240807023405.GA7014@rlk>
References: <20240803133608.2124-1-chenqiwu@xiaomi.com>
 <CANpmjNNf8n=x+TnsSQ=kDMpDmmFevYdLrB2R0WMtZiirAUX=JA@mail.gmail.com>
 <20240804034607.GA11291@rlk>
 <CANpmjNPN7yeD-x_m+nt_bsL0Cczg4RnoRWGxPKqg-N5GdmBjZA@mail.gmail.com>
 <20240805033534.GA15091@rlk>
 <CANpmjNPEo=9x1FewrZYNG+YEK_XiX5gx8XNKjD9+bw7XWBV9Xw@mail.gmail.com>
 <20240805140601.GA2811@rlk>
 <CANpmjNO94wMDfLpDQqM6XWp7fLjNH=ZSOCqmQ3jQgHQfPaHERg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNO94wMDfLpDQqM6XWp7fLjNH=ZSOCqmQ3jQgHQfPaHERg@mail.gmail.com>
X-Original-Sender: qiwuchen55@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EeNXxzFW;       spf=pass
 (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::102b
 as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Aug 05, 2024 at 04:18:47PM +0200, Marco Elver wrote:
> On Mon, 5 Aug 2024 at 16:06, chenqiwu <qiwuchen55@gmail.com> wrote:
> >
> > On Mon, Aug 05, 2024 at 08:50:57AM +0200, Marco Elver wrote:
> > >
> > > The "allocated/freed" info is superfluous, as freed objects will have
> > > a free stack.
> > >
> > > Consider a slightly better script vs. just using grep.
> > Well, I think using grep is eaiser than a script to find leaks by a
> > large number of alloc tracks.
> 
> Sure. But a slightly more complex script is a better trade-off vs.
> impacting _all_ KFENCE users world-wide with slightly less readable
> error reports.
> 
> > > /sys/kernel/debug/kfence/objects is of secondary concern and was added
> > > primarily as a debugging aid for KFENCE developers. We never thought
> > > it could be used to look for leaks, but good you found another use for
> > > it. ;-)
> > > The priority is to keep regular error reports generated by KFENCE
> > > readable. Adding this "allocated/freed" info just makes the line
> > > longer and is not useful.
> > >
> > How about print meta->state directly to get the object state for its
> > alloc/free track?
> > -       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
> > +       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (%lu.%06lus ago) state %d:\n",
> >                        show_alloc ? "allocated" : "freed", track->pid,
> > -                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000);
> > +                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000,
> > +                      (unsigned long)interval_nsec, rem_interval_nsec / 1000,
> > +                      meta->state);
> > > I'm happy with the "(%lu.%06lus ago)" part alone.
> > If it's still a not good idea, I will follow your suggestion and resend
> > it as v2.
> 
> No, that's just making it more ugly for no reason. It's replicating
> the state info (just like before) for alloc and free stacks and
> generally does not add anything useful.
> 
> See, we are writing code that is deployed on millions of machines, and
> KFENCE error reports do appear in the wild occasionally. We have to
> optimize for the common case.
> 
> Your change might be useful for you, which is a relatively unique
> usecase. The common use case of KFENCE is to detect memory-safety
> errors, and good error reports are a major feature of KFENCE. All
> information is already present in the reports (and
> /sys/kernel/debug/kfence/objects).
> 
> I argue that you are able to write a slightly more complex script that
> simply looks for the free stack right after the allocation stack to
> determine if an object is live or freed. Maybe doing it in bash won't
> work so nicely, but a small Python script can easily do that job. Once
> you have that Python script you might even do further processing, sort
> things by age, size, etc. etc., and then print whole stack traces.
> Just grep can't do that. So if you want something useful, you'd have
> to give up on grep sooner or later.
Well, I will consider a script to realize my request based on your
suggestion. Please help review patch v2 for KFENCE common case which
updates the commit message.
Thanks
Qiwu

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240807023405.GA7014%40rlk.
