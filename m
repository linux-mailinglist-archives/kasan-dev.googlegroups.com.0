Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3N6WL3QKGQEXK5VY4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 198CF20079F
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Jun 2020 13:20:14 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id b100sf3577416edf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Jun 2020 04:20:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592565613; cv=pass;
        d=google.com; s=arc-20160816;
        b=irt/vH9IA+rsXYYylDpeHz5lmQWYBPg769j1Jta9rSG1dygxky+IEOIKPD1CVu0oaq
         VHool9IhuTtrOzWe7tHxCtfqewVRh5IE8ezmImIZqVpKFcMsiOSbIV3Zu5WnavBD53Pi
         QXMF9XaK2NDEiBfgEEZpkuRo0FUATr3jPU+lFDIMsXcuQbe/hMnW2ik6fQb00tsPouE+
         9VyGgpUz4J7mXDE1vMStp/GxIUJ6/HPgZfHGn4yAPizE3m9BFzXgk9lwvVlDh9N+dKqs
         /BmmARHuL5Y/2dIJXZcdHp9W7tYoHEvucpWanIG+eLbEI9nFunZT3rkW6PHvCbVmrHZh
         gv5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=EihiYglV8QYZ8kn95ifJPoN3t3JcaigzBAONp79vx3Y=;
        b=PwocWE29dt8cjU3H8EVhUpU92oKJCqKeE1p3VhFvOvCABXi9dC7cQsibmCaBE7qfUL
         Z5We023uqNA541uigtzUE8KIKE+a/OrqeS2qHeA+cGfqA+yAbN2kdyJVH34N2WgCTmLF
         KkVSX0PSj4KTvpqXjkVUtzOurdb143LpFRO4Gt6J0wZzMUA0U58elletOVuYvBXuyLec
         eKk+PjFM9UtU7FUJiZdCIXlM5iEctzmpTZrtD6vex8JbBOGreNJQV+FBia1k35hOjZLV
         vundqRLNkHIThTZH4rZNskEesNxEry4sL47bzcpYowm1R7wl4A2g4oYlEAXbJuAQiTGd
         bZhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="U/rK2K4E";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EihiYglV8QYZ8kn95ifJPoN3t3JcaigzBAONp79vx3Y=;
        b=Z31QNmIO91BUvnFi1kuI8Jh4zD9Iosok5USrCNGoH1q8CJAE99s/G82vRZ/St01dk8
         14Fe37La628oyXBkuirr98knGBOiOf8+ItvBk4uwAx1YmuMjOH/LhSFyQW67wQui0Z4O
         DKFTubiuVSKIU8octrRkwDahA45q+m7Sg/nm2ULN6I0TpO0IpoU/QhRqzwVzwVeV7MGt
         iVy46clPSTYD/DWU1LJPG5UiuJCbq5l7bwenFcmc3f0qR4T/R2Kfew0X5ILHIQw93wFa
         PZtVovUKzXsS88wGHOmNIa8YaJlBRJRJoaCkaDWEMp/FXqiKExyzyW7YXeYnJKLyoaRG
         xpgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EihiYglV8QYZ8kn95ifJPoN3t3JcaigzBAONp79vx3Y=;
        b=EbmcdwXl8ElVLLiw+GRCHxJcfQJD1Pd+SHXg/GSbpcCcRnjkoisnMyH9UJzPjsbi2N
         ywF1b/YWgIBHsKRCXP71rjTbInFOV3H2CGfo/gFKI7neZ4lzFOp6D8D9A8Ki6ORfzZ8K
         IlFk7kNNMRox52hNwYpbPru7Qt+iTZI5/opg45j4pqVB0zRcRLs3u/zcuhBxDsTD1q/r
         PI+Ro4l6hR6wlySa3+uzP6DyXxBJlTW/1b6RdNqE2VnWFuomPqybCdK21BubKhlaBrJE
         yCORO549ZbzdUimlF/c7h+t52VKsst7PFma+UqF7kGoNPOfn/HdySxmz8cMlpr2wmcuD
         492A==
X-Gm-Message-State: AOAM532vaFzbmNXdfGAjOH2fUbIZXo0BTZqBgE83OO6z1IlDtaq+ZYzh
	M/HAZdcN5Sn1ErMaJijf4Zs=
X-Google-Smtp-Source: ABdhPJzXXqmMsrzFafhV194+VtQ6pRFWXiwBF8rh8T2ILILRmgpvk7OGraa7LMMwTb2+ET6DSRZvqw==
X-Received: by 2002:a17:906:da02:: with SMTP id fi2mr3313970ejb.41.1592565613793;
        Fri, 19 Jun 2020 04:20:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:24da:: with SMTP id f26ls4202105ejb.4.gmail; Fri, 19
 Jun 2020 04:20:13 -0700 (PDT)
X-Received: by 2002:a17:906:c10f:: with SMTP id do15mr3323093ejc.249.1592565613199;
        Fri, 19 Jun 2020 04:20:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592565613; cv=none;
        d=google.com; s=arc-20160816;
        b=zlzrTWLoINhIgg8BjLuhds1vuQfqi1itcIVhFfN7bPmn57wYHwwfb+jPvi0A4dVXjC
         IitqLwAd09H3XU+pqE0Qw+lbTNVWva8n3aF29kljyd12E4OnNOt+gevKBcatBMDybfOH
         VE1iFHRzKwKRAGWOfx7a7fPwBaKYZR4T5HTUuctUQGu5kTP0SVACraFH0qgGFg+5+/bx
         ZUxsnandz5vcfvRKyKe1AVWU6KsJE2oJyqSeEzUGQkETttGle+kIF4oewTADo9bWHnNW
         80RZuTgFiPyft/lVo4Retyz5/y1EvPNwFHIcV11VAv0a/FR+JdQoNOyCefNO5YXlVbhR
         M+xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Qf1AaPRC8wT8ApWvcCrW7+qVyHAnZzxWN/jMarI/fGQ=;
        b=dxAQnhiyILq6nRJt9o7R/F6b6gTqtxpMZfC06Q0p24UkJsf137N0pEk4qL2lfPYjx1
         Kt7rW4mwVXG6Oh5dxEAvfNYG+1+OTkP+XwSi1sNAH7L3iZ+0vVgUVWe4UIcJ571p0rQz
         sI+MxnpWFT3if14B/Fo6OngnGrxkg/wkOAFkHCGqzNuvHJAFr+4oG1Y/QjTJAGdohLGy
         URZw0BNgWVq4JvmVn9CBxDW2qC9c/yar2fQ9hMgq6PzdKTh931FArKRCCpWN9lI7sUGU
         QK8+6sTtukzYKi2QsdPpmg1bIyrSlCXFTtiT0hKYMqAyUr9P2XHaZbTVkEREFgnFzd6L
         udnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="U/rK2K4E";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id bt20si305400edb.2.2020.06.19.04.20.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Jun 2020 04:20:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id l17so8107014wmj.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Jun 2020 04:20:13 -0700 (PDT)
X-Received: by 2002:a1c:3c89:: with SMTP id j131mr3171402wma.59.1592565612616;
        Fri, 19 Jun 2020 04:20:12 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id x205sm6850861wmx.21.2020.06.19.04.20.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Jun 2020 04:20:11 -0700 (PDT)
Date: Fri, 19 Jun 2020 13:20:06 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christian Brauner <christian.brauner@ubuntu.com>
Cc: Weilong Chen <chenweilong@huawei.com>, akpm@linux-foundation.org,
	mm-commits@vger.kernel.org, tglx@linutronix.de, paulmck@kernel.org,
	oleg@redhat.com, lizefan@huawei.com, cai@lca.pw, will@kernel.org,
	dvyukov@google.com, kasan-dev@googlegroups.com
Subject: Re: + kernel-forkc-annotate-data-races-for-copy_process.patch added
 to -mm tree
Message-ID: <20200619112006.GB222848@elver.google.com>
References: <20200618011657.hCkkO%akpm@linux-foundation.org>
 <20200618081736.4uvvc3lrvaoigt3w@wittgenstein>
 <20200618082632.c2diaradzdo2val2@wittgenstein>
 <263d23f1-fe38-8cb4-71ee-62a6a189b095@huawei.com>
 <9BFEC318-05AE-40E1-8A1F-215A9F78EDC2@ubuntu.com>
 <20200618121545.GA61498@elver.google.com>
 <20200618165035.wpu7n7bud7rwczyt@wittgenstein>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20200618165035.wpu7n7bud7rwczyt@wittgenstein>
User-Agent: Mutt/1.13.2 (2019-12-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="U/rK2K4E";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
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

On Thu, Jun 18, 2020 at 06:50PM +0200, Christian Brauner wrote:
> On Thu, Jun 18, 2020 at 02:15:45PM +0200, Marco Elver wrote:
> > On Thu, Jun 18, 2020 at 01:38PM +0200, Christian Brauner wrote:
[...]
> > >=20
> > > Both mails seem to have been caught by spam at least I don't see them=
 anywhere in my mails.
> > > I'd also need to check what protects nr_threads and I'm confused why =
that data race would exist if it's protected by the lock pointed at in the =
second response but I'm not near a computer until late tonight.
> > >=20
> > > That commit log still isn't anywhere near clear enough for this to be=
 included.
> > >=20
> > > The report also isn't coming from kcsan upstream and apparently based=
 on a local test.
> > > What does that test look like and how can it be reproduced?
> > > Unless we see a proper report from syzbot/kcsan upstream about this I=
 think we can simply ignore this.
> >=20
> > We have this report, back from January:
> > =C2=A0
> > 	https://syzkaller.appspot.com/bug?extid=3D52fced2d288f8ecd2b20
> > 	https://groups.google.com/forum/#!msg/syzkaller-upstream-moderation/th=
vp7AHs5Ew/aPdYLXfYBQAJ
> >=20
> > So if this patch is amended, it'd be useful to also add for syzbot's
> > benefit:
> >=20
> > 	Reported-by: syzbot+52fced2d288f8ecd2b20@syzkaller.appspotmail.com
> >=20
> > The line numbers of that report match what's shown in the patch (they
> > seem to be from 5.7-rc1), but definitely don't match mainline anymore!
> >=20
> > We're in the process of switching the syzbot KCSAN instance to use
> > mainline, because all the reports right now are out-of-date (either the=
y
> > moved or some were fixed, etc.). Once that's done, more reports should
> > be sent to LKML directly again.
>=20
> Hey Marco,
>=20
> Ok, good. What's the overall strategy here? This seems to be a generic
> problem with sysctls and a quite few global variables too. Is the
> strategy to amend these all with data_race() most of the time where we
> don't care? Has there been some discussion around this already and
> should there be some before we start doing this?

For the change here, I would almost say 'data_race(nr_threads)' is
adequate, because it seems to be a best-effort check as suggested by the
comment above it. All other accesses are under the lock, and if they
weren't KCSAN would tell you.

But, for most of the apparently "benign" races like here, it's back to
the question about assumptions we make about the architecture and
compiler.  Although it's nearly impossible to prove that on all
architectures with all compilers, a data race won't break intended
behaviour, a simple question I would ask is:

	If 'data_race(nr_threads)' was replaced with
	'random_if_concurrent_writers(nr_threads)', what will break?

Even if the data race is meant to stay today, IMHO simply marking it
'data_race()' is better than leaving it alone, because at least then we
have a list of accesses we should be suspicious of in case things break
around there.

In an ideal world we end up eliminating all unintentional data races by
marking (whether it be *ONCE, data_race, atomic, etc.) because it makes
the code more readable and the tools then know what the intent is.

Some of what I said above is probably better discussed in
https://lwn.net/Articles/816854/ in the section "Developer/Maintainer
data-race strategies".

Thoughts?

Another thing that would be good to figure out is, if we send individual
reports one-by-one to LKML, or some alternative. One alternative would
be to go check the syzbot dashboard and have a look through reports in
code that is of interest before they're sent to LKML. Although a lot of
the data races are still hidden in some moderation queue, would it be
useful to somehow make this visible?

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200619112006.GB222848%40elver.google.com.
