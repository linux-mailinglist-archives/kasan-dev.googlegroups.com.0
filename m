Return-Path: <kasan-dev+bncBC7OBJGL2MHBB56KU64QMGQEFQ5IBXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 700BE9BC91E
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 10:29:29 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-460dd04feecsf130056841cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 01:29:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730798968; cv=pass;
        d=google.com; s=arc-20240605;
        b=f6OZaWyzcXfDPKH0bDcnRy+nE5ShJbSjisOeoYn5ZMODKgy9fDJNAL3F1G+dGbatF5
         3wk0DMGPYua6Mz5brobEjeaF+nKK8CrtoinbnLxwL2cawkYOJGZqeQfjSw9svjnqqb/E
         +PUWywjP6LYxHyjJddsaQ+b841Z/C2FzU1zXVc7GphBKz9V5Nr8cZoV3Oka4IvqihwK7
         no/+cGNviY2Iu5O3iBsbBQgs0VF7P4PV4Jp9uHw48YGNsdOphmRVPufPKAMlbKSNdWN6
         UtTArgBEzOgnexyn3I2/rO8p8q32zS6xAdEh5Jew9KLjaJLwy1ms2wAlAcxhesRD1ga8
         vduw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YZCj+A87NRdOFZH+noiIM6zd46XX0lpzWdElnajzXpg=;
        fh=blqAmUebZcAaYLIFbWhqyHvwXJllWJSvFNawCqGjtB0=;
        b=UXh4tSOFmsqsusPvlsBskd60M7Y+vbslxcSCwI+smcYzLOUoA4fR4owU6XgQHkBVB/
         zumw5QMa34ZoAkDR24CGyyQOIfZtfERoHM0sLlrAOmN4bnDOW/fS9TJOP5F5AC5G6bcX
         NNKx3qr2pl5xZss87mByXrRH0UzGGNFkg9uQKi8RNxMIXN0rYTH+8RXzHcc/1WVcZbkX
         gfvwykFsJqzjPO+dJ1bGk17qxRC7D2sQubRh7lMfv2w5BtaMaeF+Ccv/Jktt7nQxS2IM
         o93R0RyRk770M1PhUO83r/ySbPs3d2gkP8cBDQbR/Ipp+VJovuZkEDYQlz8JJpZci2MI
         TPlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uPcjcnMY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730798968; x=1731403768; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YZCj+A87NRdOFZH+noiIM6zd46XX0lpzWdElnajzXpg=;
        b=R4PVpjvLGwpI9CPNoBr1iNMwu8VhYRgQk7RJix91TVtErAmU/fT3XmGvJZ9h0XhFe7
         0MtW86cRePlAziAzimwPcp3tP361E9UB1v7zL+MLEQNCU5D4KIvknPpXkh6KjOUaTUGt
         wjOIFt75kuDAf/7TB1aJlNg4Z7UOz0TbblsLNm0a7gXY3gjQG77CixD6KxOaBmX9TpCI
         hmXIAE8/6JOWfbrf0rnLG68v7w8pn7aSfrcQFodAmv5f1PZKV2O9V5rl2BoYkdSAl6XE
         8mosRUm+uU92Pzvko7sDt13mWtoou4F5IzfkNXhNYsvWLN4btOkprwQqEuMtGhDXf7uN
         Gfpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730798968; x=1731403768;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YZCj+A87NRdOFZH+noiIM6zd46XX0lpzWdElnajzXpg=;
        b=AsedYh4CS1R9+TdJfAr++G2GqXA9gLNw5/kWDnDAMeSY2o7E5yY6sgy1fB4Jffg6aK
         agycjd07HTlOMtopwamlfEsWe/LBEtAPcyzeDGq2z0DRei1BHzPag7C+O/stBf9AG6yt
         mBEBu49RKVw4z5/qHSgnmVBxEmgQFjE9EZ/BXHYYc0D64K/TCnBhlIG2kbUjeqPg5a5B
         KrRgl7WeZ0g+Yr4WqEF/11iH3k4qIXFEoQoZ8ylz/zFrZjCIjUHFhSYV4ejHGE9Zznhr
         2ETqtnorPSrjthVXRpbU57ZL7HROxmK2DM42hoiwXffEyIBEYRfI0g34WRfAA0b9W2/7
         4RQw==
X-Forwarded-Encrypted: i=2; AJvYcCV/l5fx8tT+E/4W+3imDjpZf8xQFo6BNHBtPKrh1OPDKUG32ppt0ZgUAwqGXwTp52VaHaKY1w==@lfdr.de
X-Gm-Message-State: AOJu0YyR1tfI8XIjc6ajGusVdY4SnQZitLGwyN1g4ONiafkNXMJkMhel
	m2BYTJiEBmkRqxD+aVGvX2uwNDZsXIv2DbKseaIo/q1BrGN93vKx
X-Google-Smtp-Source: AGHT+IEZGIux9d1/Fkd5VLfp4Zdhe6oBu19EVy6G1CusyfWoRli19BQIEhYE1nA073G87U8Qt4Wb4w==
X-Received: by 2002:a05:622a:a:b0:461:189:5f35 with SMTP id d75a77b69052e-462ab29bd35mr313984101cf.25.1730798968163;
        Tue, 05 Nov 2024 01:29:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5907:0:b0:461:428c:d46f with SMTP id d75a77b69052e-462aaab7f21ls80860171cf.1.-pod-prod-02-us;
 Tue, 05 Nov 2024 01:29:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV5NtqHJ00EqrYjbpzVOKkBXQuUpeqnN+gYAZfonM5uQAv7fDu3qbBOjwI3Uekj4VfxeX4Q5eizFDI=@googlegroups.com
X-Received: by 2002:a05:620a:46a9:b0:7b1:4b2e:3c0 with SMTP id af79cd13be357-7b2f24db267mr2785088485a.14.1730798967298;
        Tue, 05 Nov 2024 01:29:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730798967; cv=none;
        d=google.com; s=arc-20240605;
        b=NJJ2qxYleccM4XxtCV18/IJgq8DyPSqUPRH+a9g87+SMAXswTcgckua3SRD4GrnTUP
         jifWzxcDgxAzscLgyDQvezdodJTsPP+5d2xUtqzLue6I8IdSx1fH4R4twd0G0VHvXUC4
         keVDoGeq16AnymtwIbxonvS/mjUHoSI1V0ys5LNTj27il/D8meUFF5AlJ8OAAzOKoBDj
         6pcIRQyO+Iv37ecSLQfVIiyrMmDC44yzfSFvK0+oVvYeLDmiCHKTUt8mYRBWOe3hyJoq
         AKcThD8sQAo2r96X5GtprxmvqacsKFzyRIz9DCevRGf1mzslypM91oaLv+RLM0MkyQYe
         gcXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qE5HCyg61ikvJ6X0lEHZILXMMCdxd5npMW3fd1/VuCY=;
        fh=8+CzcuUEdeKczy/JQHSYdSsiJbFu/3wN6A9E/9B+j9g=;
        b=Tre1u2NPgy7TvekTSDIZFwwPiUTT9ZYBq8kauMw4i5PPt1r83mvgDWmUHT1YrpKoAb
         OdjUX/E65zrNYjJ6Aj11tHNvf+VAXRsREY7UOBmW+r7Ki77kKx9wc0P2Acw8d2H6KxBW
         FnTd9VLAbMi2nGyDV2lGJnF9R54xjpKQ5aSVKUW2LAJHujet6oL0e9aa3x7tjfCqU1f/
         0AfXI8Rg638ODKdw/ovdEaJgTzLb+zB4Bv9VNz5wwKsdkFTOG8d5f20ffIBS3FuFWJ4d
         jc9QqH8i/5xPB671PkwgrPmMML/lmi9AklfydaU1TC+PC3P7iOOQlFZrO7z6bz4di/wD
         MdPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uPcjcnMY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b2f3a65bb5si38019285a.4.2024.11.05.01.29.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Nov 2024 01:29:27 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id 98e67ed59e1d1-2e3fca72a41so4279694a91.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Nov 2024 01:29:27 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXZlM3WABO2A6ygZRlSr+++gLxW/k41P4HloppZ/a3UT8n9TGOH0Oek8ahPayNhGWm0xYMGqf2HeAA=@googlegroups.com
X-Received: by 2002:a17:90b:1a8e:b0:2e5:e43a:1413 with SMTP id
 98e67ed59e1d1-2e93c182879mr25488015a91.9.1730798966084; Tue, 05 Nov 2024
 01:29:26 -0800 (PST)
MIME-Version: 1.0
References: <20241104161910.780003-1-elver@google.com> <20241104161910.780003-6-elver@google.com>
 <20241105091342.GA9767@noisy.programming.kicks-ass.net>
In-Reply-To: <20241105091342.GA9767@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Nov 2024 10:28:50 +0100
Message-ID: <CANpmjNPws3_sODe3_KcHp9UFx79xk4Ow0QvVxYHGf_axGdoEag@mail.gmail.com>
Subject: Re: [PATCH v2 5/5] kcsan, seqlock: Fix incorrect assumption in read_seqbegin()
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>, 
	Boqun Feng <boqun.feng@gmail.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Mark Rutland <mark.rutland@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=uPcjcnMY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, 5 Nov 2024 at 10:13, Peter Zijlstra <peterz@infradead.org> wrote:

> >  static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
> >  {
> > -     /*
> > -      * Assume not nested: read_seqretry() may be called multiple times when
> > -      * completing read critical section.
> > -      */
> > -     kcsan_flat_atomic_end();
> > -
> >       return read_seqcount_retry(&sl->seqcount, start);
> >  }
>
> OK, so this takes us back to kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX)
> and kcsan_atomic_next(0).
>
> Which I suppose is safe, except it doesn't nest properly.

Yes correct - we just give up on trying to be special here. It would
be nice to also have readers have a clear critical section, but that
seems a lot harder to enforce with a bunch of them having rather
convoluted control flow. :-/

> Anyway, these all look really nice, let me go queue them up.

Many thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPws3_sODe3_KcHp9UFx79xk4Ow0QvVxYHGf_axGdoEag%40mail.gmail.com.
