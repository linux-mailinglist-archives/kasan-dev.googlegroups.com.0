Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2XTXOCAMGQELK265XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id C7063370EBD
	for <lists+kasan-dev@lfdr.de>; Sun,  2 May 2021 21:13:47 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id l11-20020a67ed0b0000b02901f3823e11e0sf1809261vsp.3
        for <lists+kasan-dev@lfdr.de>; Sun, 02 May 2021 12:13:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619982827; cv=pass;
        d=google.com; s=arc-20160816;
        b=X0EiN/tw1gY37lEABWXvddjOQujQdUyuf/QuoGRnkvL+1RKPnqb2ASm6fOmumQCXq8
         MN0IsM4q4xT2DKiXtiN8XRhmuP/hIvMT9MTYWsyMv2nBVwqbdUfzmS66v1DUMf8sJcmh
         WEBbDbVioUZyJS4eb7oMZ71P00I4gH0Tf8hSOpCs0gxJk1Don3VqSldybz1AcDJFAOFK
         WdAdNqB0bChWLRadCs4ogKCk2f9/g8442Quoh53Amo87KXtmQ7i7vRGylRZYJSdimJJQ
         fnSLOKDsgnQ3lmaVZ6zAgCRzIljUf6JdVZ7DvVti69CeHtIUTMbrAaZ+d3w5JTqX1C8V
         RWig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aEkFKbtGMum7odo/UbvGzAaLiGaN3TNruce844uBZE0=;
        b=B0xP+Z/GYPInY0uoJ4WCEsnr9k2nxUJenLH/x7owK+CxkfjPAsIQnzi6QanG1CvYlr
         T2kBAFLx2MMxwfBqhyYDwTfQZdMtvzxTZ+QAvrkt9yfPkKgR969oxywJBnRf0r1eZUYo
         22XJ1TyJFnNEUQLGe3ErVk3XaFV9+eJwTZxuoAh951uuTtcP9wY2MJPKoU5FPfAp1bAO
         2/xNP4+YaWl6L6yGKtep1TUKg3DILYH81gouCHW3iC3SzAbGOCDwH10BC4cJsCHZL7p8
         pJhXFsJtiY3Bd3Y1AR3ujproSNvVY2f0nR685lSVn1Zbn2rXNoJOClWeO51Eg1N5V7yJ
         x/qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="eRrh8/FT";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aEkFKbtGMum7odo/UbvGzAaLiGaN3TNruce844uBZE0=;
        b=cBN7Kf8Hnx+v/JS8j9P4CxpQNSC97539Wg84rnU1Xp2IHQGQkdO70jtiArR0mjF+2p
         Pe+uRJ91CnunuhCC1Ryi07AzPo5GUgQcMVuWc6pTlQL+hMZECEr0eZw/qiJYbogOEcMq
         PCGvJmbjWiRtq167V/w/XYEIchVVuumw5tj8u4i9Wq5DmzQPnLkYW+/eg1KskEIvjOLq
         Pi9/IiO1VQ0+5PKBFszMiAE4PmLPZ6Ldc0bZteigtuvXLm40ZaeduahZnJYc/vHYaz8M
         ibP+/tgW+/BLRSI1MLwz3zaHiZp8cSSE1RYRCeDtMtMTQDkmHa7TPVqRGnns+FKxrBrH
         W0bQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aEkFKbtGMum7odo/UbvGzAaLiGaN3TNruce844uBZE0=;
        b=SQuDqgQ/9pqsP2VmJnw/R+QxXJIFs9J9SquAHOW99NS8P3SheGKddz97y3RC/OjotY
         IC4A5z5WEK7pkjFcA91xvTJLDqr71LJccE0+fRH+GmYoIIiRaAPC+UeM4mV+HBq5fHgm
         DhzdUxvYe7cfOFhPEH2GX0unaSPIMY0FIWhBKMb+wrILoPIWz34Y3hHSkh1lIEsZci+k
         0QyN/q5jw3YoJoRcBh9Oc9PrwWwWu1k1Ao27U5XK2Na1LsK6JM/OsxnN+rGGkg+aR7qv
         d5ZwLVSDxytq7BkIeGINWnXc+g8Fqio0+3QDZuFwBamylLvsxPPorT7su+6IYB/hTJHn
         Wwsg==
X-Gm-Message-State: AOAM532NoIq3tBH9sLAwe4RCJ7nze5HxOpGaV+2qSk0S2tdSs/L/69Hi
	vfSK/dDLEYz2+duvC0fak+M=
X-Google-Smtp-Source: ABdhPJxhesALzhdH/peHWUccXTV1APluCOcbAIPbEshvAH20ugAq1A8WSPgD0rAaTLvpT9Hz8U7gkA==
X-Received: by 2002:a05:6102:348:: with SMTP id e8mr14291537vsa.10.1619982826910;
        Sun, 02 May 2021 12:13:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:1c14:: with SMTP id c20ls912562vkc.10.gmail; Sun, 02 May
 2021 12:13:46 -0700 (PDT)
X-Received: by 2002:a1f:a388:: with SMTP id m130mr13191793vke.1.1619982826356;
        Sun, 02 May 2021 12:13:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619982826; cv=none;
        d=google.com; s=arc-20160816;
        b=k7xTTOeiyTDCnagV8jkRmBUKxt2gfofGPRNEDXrmR3vZpCfxYmZwu1KHw0OY1zZ8Rf
         j9YjANj1Vl5d3po+av+hIPP1E13cUJb8CjpEFqrznem24jsYFca98Z0e2SydP/K3b/BQ
         0XKOg1GUx55l4Au7RF06YYYO0oU0gAEGs7tKlAYi+2n/vYnY+lhkJYBIstY+Qa977fZt
         lKFl+U1dohz90m4ANBsXriidSKcUO0w2QBfqcMzI1AYyTm8eU41RAahH8lB4gwoEblyz
         Wx8PF9NQBDFrxJyncmWXw7BeINz/uG7QWdbVDIWP0jUG0OXq6ikvSM8ExE+e25wyeHHk
         wNQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=emMfiYi99q3nX4v+CBQmuXsA/kqjvpixR7oLzYPLuiM=;
        b=U/bHMWRJoVfouK/HK2HRTVRWoYSB40n9au4c8Tw5CuFD8MMbpcs/FE7Lm+bmkjjOpR
         SQl4W0TXp8IIm19JvWQ6WkGWpXHb9Tz2R+jxiWS2zUCU5LVrvfkBs680/tomK1piMrQ4
         szmt++ppOWP5Deqv/q67P57e290oU8g35DoLk5gvMIPgUVMyzpoKfav/yxrnbYXF5AIB
         NR7kVUC2Ru8/jKwur0oN0C9h0Q81+79szJqrqAX3y1dFO9nkOGuxm36BECV+Yt5Pod02
         x4r7jlJ0flAoA4rv7toLMGA3gp28sjYZJSCrmEB5Z9oTJsk6UviYlraFRWFmn29hz0kH
         cL7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="eRrh8/FT";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2d.google.com (mail-oo1-xc2d.google.com. [2607:f8b0:4864:20::c2d])
        by gmr-mx.google.com with ESMTPS id a1si141969uaq.0.2021.05.02.12.13.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 02 May 2021 12:13:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) client-ip=2607:f8b0:4864:20::c2d;
Received: by mail-oo1-xc2d.google.com with SMTP id o202-20020a4a2cd30000b02901fcaada0306so615249ooo.7
        for <kasan-dev@googlegroups.com>; Sun, 02 May 2021 12:13:46 -0700 (PDT)
X-Received: by 2002:a4a:e715:: with SMTP id y21mr2293005oou.54.1619982825669;
 Sun, 02 May 2021 12:13:45 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m11rarqqx2.fsf_-_@fess.ebiederm.org>
 <CANpmjNNJ_MnNyD4R2+9i24E=9xPHKnwTh6zwWtBYkuAq1Xo6-w@mail.gmail.com> <m1wnshm14b.fsf@fess.ebiederm.org>
In-Reply-To: <m1wnshm14b.fsf@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 2 May 2021 21:13:34 +0200
Message-ID: <CANpmjNNpsdqCp51_P=NCM=fMREhN6HWQL7aiOdyfqu=aUmkR7A@mail.gmail.com>
Subject: Re: [PATCH 7/3] signal: Deliver all of the perf_data in si_perf
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="eRrh8/FT";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as
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

On Sun, 2 May 2021 at 20:39, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> Marco Elver <elver@google.com> writes:
>
> > On Sat, 1 May 2021 at 01:44, Eric W. Biederman <ebiederm@xmission.com> wrote:
> >>
> >> Don't abuse si_errno and deliver all of the perf data in si_perf.
> >>
> >> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
> >> ---
> >
> > Thank you for the fix, this looks cleaner.
> >
> > Just note that this patch needs to include updates to
> > tools/testing/selftests/perf_events. This should do it:
> >>  sed -i 's/si_perf/si_perf.data/g; s/si_errno/si_perf.type/g' tools/testing/selftests/perf_events/*.c
> >
> > Subject: s/perf_data/perf data/ ?
> >
> > For uapi, need to switch to __u32, see below.
>
> Good point.
>
> The one thing that this doesn't do is give you a 64bit field
> on 32bit architectures.
>
> On 32bit builds the layout is:
>
>         int si_signo;
>         int si_errno;
>         int si_code;
>         void __user *_addr;
>
> So I believe if the first 3 fields were moved into the _sifields union
> si_perf could define a 64bit field as it's first member and it would not
> break anything else.
>
> Given that the data field is 64bit that seems desirable.

Yes, it's quite unfortunate -- it was __u64 at first, but then we
noticed it broke 32-bit architectures like arm:
https://lore.kernel.org/linux-arch/20210422191823.79012-1-elver@google.com/

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNpsdqCp51_P%3DNCM%3DfMREhN6HWQL7aiOdyfqu%3DaUmkR7A%40mail.gmail.com.
