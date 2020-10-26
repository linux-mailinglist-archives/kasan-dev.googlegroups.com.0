Return-Path: <kasan-dev+bncBC6ZN4WWW4NBBAWT3T6AKGQEMQSKWMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 66C6E299774
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Oct 2020 20:54:44 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id k15sf8155489ilh.2
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Oct 2020 12:54:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603742083; cv=pass;
        d=google.com; s=arc-20160816;
        b=pJm0SunJF8B3HWhzVY4ZJXH+gt+ErQOPSu1NUrxeRARKhlq2Ek3VRpMhpgtRXNZMAv
         6M/+l6AwGRlR+PvgPWTMDE544+DaBZggNMYvp7DkQrhVkt8W0E4LcJc0+Yddn6Y73+HE
         iwQi0LtRqNVEAAz7MBXbv5emtwgbf+RKyvyWaejcrIcShSWjJ3/mQwj/Tzn9HfAnM0Zi
         OIgwf5CZlyAkEW04sWcmwe50MX+AsU1xJjwd8ny/M6T0zcP7SLSwv/YCvSCBA/KuClHt
         8nnfq3ao1hlFXX3AU5L3GhYofWgfihBDW5ymLM1jlkcQpfb/BBvtfsbRnOos6bb10E2D
         YZww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=qpTxiUTiHs2YDfHqRN1q0SkBHVho2xJEIXU6V2nFETk=;
        b=TWEnH7Z50lOmaInex+CDcJwGSOYWOnIsJ+qZ6b7Oq8YBYdeD66ehp89cDSK9MT42kV
         XqLB4LFaPBHWo6oL5x0CAjAJWw+XUJBoYDjzlpcJ4Uw2/nWWhgc3GfvQfPnTFrwpw6l9
         TRhYI7AdMyv1ZfG20YqX7RxXzIiIs4KN4Q8YY1ygflCIrcW68DVprc/ZsDhmjVJanVBd
         1aE5H7ifsVHqJmaEBxo9ADf3ETqPzjOaJGE62Wmrp+QFzduez0haM9piaY02/JLY5sVl
         zzXW5fMC4vLhb+rkcBMvc2QWMaNLH9dZo1MBiuNxwESDOD9Bml7Ej+8X0G85sarVfZS2
         GXzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gelyVPuU;
       spf=pass (google.com: domain of jidong.xiao@gmail.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=jidong.xiao@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qpTxiUTiHs2YDfHqRN1q0SkBHVho2xJEIXU6V2nFETk=;
        b=Q/LuIVWC5HWpUR0i8QbC0G5q2Pd+lkAVZEhKf699GNAmPv+dYr8q8zhhY3G6BzZDBf
         Jql+Oz73jQNNUJLDMrQgrjd4DW9n0vmlF2kXePVIgAfjq11g3DgCdniMFFUN6tLQKhtE
         wxmDB4miToifzW4fbfqsqFnGS6xvT01AHtfNJOkhRZ2G5ShZzDIwdbI29gDT2aDrqpcF
         D95+VRnaNVbZuDUx0pwN5Kl2ZC0p1LRC+zLTRYbjWtJYZTCPhxAqEQkEVlo6DbIDT4qO
         OvM8AFuW1gtQoZ6WKsorT3VtP0rQ0bYwzZJWIlQmv66GvNlR1xr4VEi5I6CHgIJhlzcu
         DPLg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qpTxiUTiHs2YDfHqRN1q0SkBHVho2xJEIXU6V2nFETk=;
        b=m00redVXEmSujESqEgJhrKe8ibU7Yv7k22RJmsD/ZekP2ZVk/o4yx7tpObk5QCo1D0
         2T/re79nVNTNZTMjfwuc38UX2ksKhSSAXWHh6YNEYvOFcEgkr8WeOeyq3h0LPfQLOKXJ
         onjxYtSmfd5GWmSTYEIHLLPUIIk85IP1+++yt1reDX1H8xvY2sQvDeeduyYlk1rSGNHw
         27rxtRWeE+ERTOYwBuSWDyRbu72OLgDShprkVlXEUIxele9yOabclUSF7APPir7r6dbr
         PKBWXx/9dVzfHoy9iin3bRapc2YJebge05c3sL+1E+l9OoIbQMA3UtcHLrM+orFQf/J4
         fFpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qpTxiUTiHs2YDfHqRN1q0SkBHVho2xJEIXU6V2nFETk=;
        b=t5p7k1X6jKWPC+Ab00jitTOgd30Y0bnmUUmru+vsKxifp9CCv03IMEvpUqzrb2S9IZ
         +Lgm/zVjzgReUGPAny067KFe4w2Y+LUK00NFBe8c2WwLH0ubo/0IyYqIIkgTpqpEaeB0
         /3qG6EhqRexW6QvPz6JrHCate3aqVSjtdOwFDZNUH588xc/VNgWf97TRC2ckwo6e0XgL
         mDi0ih0Ys9Az+M7Fr1yxPHKYsV/eAz5MoZGzlJlo4zL84aa/d/6/LC3UOXrXq/aSpBXL
         1UGWfPCecIcqAImL+h8gFMjbNxh3OWgzK3Vx5JIgiyxh/VYgclAmvzSugioAHoBti/UM
         vUAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KN91pQ5Pjjh+5k9D/qhHYpjusEiedORRIzVGWGoy4BSVrUjjy
	Yd085/UeYdGhivDB9z0fe/8=
X-Google-Smtp-Source: ABdhPJx3y2SLUjK90qoOLNdpG1rlEKddpB18OUEFg4zN6zGzSfcodOn017Z/mnBZ7RCCPA+Uam1fMw==
X-Received: by 2002:a5d:9842:: with SMTP id p2mr12150384ios.113.1603742083055;
        Mon, 26 Oct 2020 12:54:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1308:: with SMTP id r8ls279886jad.7.gmail; Mon, 26
 Oct 2020 12:54:42 -0700 (PDT)
X-Received: by 2002:a02:70c2:: with SMTP id f185mr12290107jac.88.1603742082660;
        Mon, 26 Oct 2020 12:54:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603742082; cv=none;
        d=google.com; s=arc-20160816;
        b=me62fY/RDqtfwJsGDq/SwiDh1UDH/nT9YFwBx+V1HFtNs63va9Ff4FvaiqUl2dEAq3
         NM8tG2tvoj5iT1lwDwpsNvlxejmW5oZN0BgO53hwv9RX9UIKge8Pz5+8u8xGmDCRrrzW
         vwc4qZ7R/jClT2bHOK64D7KjB97SCRBOdYzSXAM8duu0MQp9elQ4+9AEldp/kWTs27Zu
         r5MlHfe2dRF85rYzy/MJ8QTLsTLT7g8skCMCBYy85ausXwKtVn0UtL9RAmrl4eYr6tOL
         d9bhXVUhfjvWFc82Fq6QvKKkFlKg1O9mVJqYw3AX6gQ2DIW9ugbGV3i+srzj7bmM3UU3
         qCVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hfOlu+V9tx7TMyPBDRwXR9H5U4ObzlDt3TojQFxQc4c=;
        b=kbtC57IeTLcEoLXwr5QTr6tMfW6HfR4sWa5LEeow4HT7nLteZ9YhEueZPQKPRpYQ54
         3QncMhFXqHigmvc8rk1N2sDda7LtQClpHLuqacCaH3evr2cL+l7AMgJcpjN9mMuiU39M
         eK5nNy8UUfzTe7mS+6qD/QSEZwaFSxfEjD5LkhTJfja6qIuGlthNJshXihalLXwGyt35
         D2Mzo64eG7fyIdZ+P3jy6Bfh6PgbSaH1xlr5O5VkDMD1DeLX0jyUbPRm5x670Nmb6oRg
         KHcx8dyhUX5su2Xm0+z+x+87/bjnMLZ/1xHd2HLWwx66K6uK6UprUTT2A54IyYPrvbZM
         3e9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gelyVPuU;
       spf=pass (google.com: domain of jidong.xiao@gmail.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=jidong.xiao@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x129.google.com (mail-il1-x129.google.com. [2607:f8b0:4864:20::129])
        by gmr-mx.google.com with ESMTPS id p5si175073ilg.3.2020.10.26.12.54.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Oct 2020 12:54:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of jidong.xiao@gmail.com designates 2607:f8b0:4864:20::129 as permitted sender) client-ip=2607:f8b0:4864:20::129;
Received: by mail-il1-x129.google.com with SMTP id x20so4326424ilj.8
        for <kasan-dev@googlegroups.com>; Mon, 26 Oct 2020 12:54:42 -0700 (PDT)
X-Received: by 2002:a92:845c:: with SMTP id l89mr12920691ild.114.1603742082474;
 Mon, 26 Oct 2020 12:54:42 -0700 (PDT)
MIME-Version: 1.0
References: <fbb6a417-0767-4ca5-8e1e-b6a8cc1ad11fn@googlegroups.com>
 <CACT4Y+aGLpDf_j7LziZZpNi0UVOBJzyhu-WV_hySQiMcCBQXLg@mail.gmail.com>
 <CAG4AFWZvWRMYR-7+zv7RS-Khd25+AEgdyX4O86utTbTZ7QD3yA@mail.gmail.com> <CACT4Y+Ya30AEFs-p-3p=oWePkVxd+GvBAi44u-8ZKCuH+Zz6zQ@mail.gmail.com>
In-Reply-To: <CACT4Y+Ya30AEFs-p-3p=oWePkVxd+GvBAi44u-8ZKCuH+Zz6zQ@mail.gmail.com>
From: Jidong Xiao <jidong.xiao@gmail.com>
Date: Mon, 26 Oct 2020 12:54:31 -0700
Message-ID: <CAG4AFWbYBv2pZ1KfaLicuDJJBG95gTuw6q-Oc1uxVN5pq=DU7g@mail.gmail.com>
Subject: Re: How to change the quarantine size in Kasan?
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jidong.xiao@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=gelyVPuU;       spf=pass
 (google.com: domain of jidong.xiao@gmail.com designates 2607:f8b0:4864:20::129
 as permitted sender) smtp.mailfrom=jidong.xiao@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Oct 26, 2020 at 12:30 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Oct 26, 2020 at 8:26 PM Jidong Xiao <jidong.xiao@gmail.com> wrote:
> >
> > On Mon, Oct 26, 2020 at 12:19 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Mon, Oct 26, 2020 at 5:30 PM Jidong Xiao <jidong.xiao@gmail.com> wrote:
> > > >
> > > > Hi,
> > > >
> > > > In asan, we can use the quarantine_size_mb parameter to change the quarantine size. Like this:
> > > >
> > > > ASAN_OPTIONS=quarantine_size_mb=128 ./a.out
> > > >
> > > > I wonder how to change this quarantine size in KASAN? Do I need to change the kernel code in somewhere (mm/kasan/quarantine.c?) and recompile the kernel?
> > >
> > > Hi Jidong,
> > >
> > > Yes.
> > >
> > > > Like I saw in mm/kasan/quarantine.c,
> > > >
> > > > #define QUARANTINE_PERCPU_SIZE (1 << 20)
> > > >
> > > > Does this mean for each CPU 2^20=1MB is reserved for the quarantine region?
> > >
> > > Yes.
> > >
> > > You may change QUARANTINE_PERCPU_SIZE and/or QUARANTINE_FRACTION:
> > >
> > > #define QUARANTINE_FRACTION 32
> >
> > Hi, Dmitry,
> >
> > Thank you!
> >
> > In ASAN, the quarantine_size_mb doesn't seem to be relevant to
> > specific CPUs, why in kernel, this quarantine size is defined for each
> > CPU?
> >
> > Also, what does QUARANTINE_FRACTION mean? if I want to specify 128MB
> > memory as the quarantine region, suppose I have 4 CPUs, shall I do
> > this:
> >
> > #define QUARANTINE_PERCPU_SIZE (1 << 25) (i.e., 32MB for each CPU).
>
> QUARANTINE_PERCPU_SIZE is just a local cache for performance.
> Generally you just leave it at 1MB.
>
> Re QUARANTINE_FRACTION: see the comment on top. That's what generally
> defines quarantine size.

Hi, Dmitry,

In ASAN, the default quarantine size is 128MB. My understanding is,
the quarantine section helps us capture some tricky user-after-free
bugs. Can you explain why in ASAN the default size is 128MB, yet in
KASAN, only 1MB is needed?

-Jidong

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG4AFWbYBv2pZ1KfaLicuDJJBG95gTuw6q-Oc1uxVN5pq%3DDU7g%40mail.gmail.com.
