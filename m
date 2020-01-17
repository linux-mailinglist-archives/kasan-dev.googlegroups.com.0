Return-Path: <kasan-dev+bncBDEKVJM7XAHRBN6PQ3YQKGQEGV66HII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 79E5C1409AE
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 13:25:27 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id k18sf10508802wrw.9
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 04:25:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579263927; cv=pass;
        d=google.com; s=arc-20160816;
        b=aeHOybO03vh8CWBOhvwVjU5BGApfVBVBFt1dzojRbkt4Vo/QgiufLBp9uUMvWyHpoV
         p5+HGITVDK+YPKnZE8351KxbGHBL/n9H4TrdXXWvMZb58cOeW5gkpZInKXZMaqt5SYE4
         xhgkR5GKupk2MTvrkDviphO/AsRbEMb9GI6hYO5VSOIwp4iDzSl4mfwhWI+kDigCRINS
         872BB4zi8BUD12SoT1QMXEdFONhyKGwiD5kkenPKLP7Zry2AidSpTvyBvJ5Vc1jpvLgz
         k84B88WZ00UC1bpZkcVwFWC58r1i6IfCKVhzY6TpRpaUElLlzaben35iRpzgrwzrgAXu
         RLEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=NzFLqCLTXidBJ4P2g9sk82iUwZkqD9oqBfdiWfl05dA=;
        b=euacKhgGB62vOFNdRSIN0xxsWEdHfF+A+PQwDjUPlOAnIynj2mbkxxxEjsgcFmqm5j
         Iuoo7K79O7Uv3li687G8Pzjcc6dn2NQiIGEvmyWmse/cHunO56LAMP+Qs3rzOMo4g/5s
         Oh55AZdhvDtIu2vR6nzlXCfUukOmK4Xwex6mzfmAJwI1CoU5lBWiHZklHYXZK194KRkM
         gQaXWRRjRJXP95zap3WApgaqOY6fEqBGnUBhqVRGmNELrj+1+g7J9Q2NWsT5wxCfOJZp
         5y4YjyiXRMcsiWCL5oql2kyI1KrOyXZFENDwSHZEJ9VBU6JkoCtsnHtwcjB7A5cOVntd
         YWiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.134 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NzFLqCLTXidBJ4P2g9sk82iUwZkqD9oqBfdiWfl05dA=;
        b=QNGsYDWtC+BJAGvLfosMkFgdCyxnQU31JmT0fdEYMRE9maPbVct3oozk5yHoYvDln7
         gh9Dc0FrgYT0zFzm2bIrJVUNRgBf5gddYqQP72evyd935mvZPfmWFCqr83Xo3f8XUWsx
         WhZV/y0MEi3UsBUegIv3bVJ2SgjOFS3bHEgesQmCaS3qCRpU219za398BYukau4itzrA
         Kp5brRWkLhU168h5tlqcqPIIrf4h3/1w7amoZnJ5bUy5oYSZcBuhy8jjtGkBFlPopni5
         KO/Ry44/tLE7C7U521rczBkNNabokR+3fiDORk+WBrhMSLVdqtvZBQJGCVvz/e/8DY2y
         pRGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NzFLqCLTXidBJ4P2g9sk82iUwZkqD9oqBfdiWfl05dA=;
        b=C5cY7C2DSvzp8kWtgUSm2YexneDjuKQ4V6zk2qB2GbRIGFofjKQEn3/2GByJuTXsb/
         gojoMY8+/NQd7E+kBpKEUmaOz4Gr+PXHGDD3VjgWTU7WhY5BXqNoIDaksTJjAvB237jS
         mc3jthAAJ7EwU8MoXeLQ3N+2AVQ3PZUB2srvGjDLzPiQwWvsvMVMWDyWT4hN7iaeAq8/
         VCKaSO1GGnF07lNBMyW13iNoOu/9GiBW+q7aT6kaGFdVvHdP+WIoJYObvvI5r/GhaRQh
         mol10XIuH2LjDNhg+vs8GLrd/7kwt3yRhxOHr1Mp1sCqWmlAObit/Vz+iQb3q7t5XeBx
         oPUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXc2aBOXDG6lvoR/fN4+uDPWFaLe+4zr8T3qb8FszI0Mj24cLbh
	P3REXvq8B9Yv/Le/sWqCvig=
X-Google-Smtp-Source: APXvYqzLTxyB6u/Fpd0fVyuI+f1rjABzbU8tkPGiTESb560LB+FBUIfilHjrEK3zZoGSP0mDtfQD/g==
X-Received: by 2002:a5d:458d:: with SMTP id p13mr2807308wrq.314.1579263927112;
        Fri, 17 Jan 2020 04:25:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6912:: with SMTP id t18ls8880935wru.7.gmail; Fri, 17 Jan
 2020 04:25:26 -0800 (PST)
X-Received: by 2002:adf:ebc1:: with SMTP id v1mr2860326wrn.351.1579263926565;
        Fri, 17 Jan 2020 04:25:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579263926; cv=none;
        d=google.com; s=arc-20160816;
        b=Zn5vNWm5WgKWGsoLYUqyi2PHVP4xAjatzwIAM0lCOegbjQPZ/hYiIEm9KOM0e5U9r2
         ekj/NvqtujR6sHINrD/h5xIteAa9+32UYhGO2lzW05g8xE+bNN2ReK9+3TXB3tsqCFyK
         fj/xQHs7Tl45OmW1K5dxQ5ypPMTV4GXhmtRUIeEaJe7IpkOeE+UFbXnmap1WFIJzeQfT
         jpVCOF6EiA3QFEIts7XCSYWF+Iwc5+WZjrcMPLlaTQuBMhM4wehDL3zlhGGUFFiEthxS
         Y9TeFVrM8rCOuZXC2jiGThBMrvVLDsr9rrV486wRhPdOB5MEobvRblii4Lyq38f9M8n5
         jOQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=ofkFzqAPqr+jBxYWuzv55ROGh3dZrxjFf7k+rVUuhN4=;
        b=zRo0UR+tTHWgijYvqbbbI251pP7mboK3Y4WLK0D+Ns3pd1UjmIc0oYvPyfcm9DHO+A
         ur+pxV2xKPjKMKYFnFEhnD7A5XCSN1DgbxwQZy5rMOWS07SfIwk6mK5WXKtRnBoHTbKL
         v7qhF6Me9ikHPOVlIISsvslD9fxiEVUdEBFF4xacilZ7pi+O1uzUQ4Dd2GgMHpm8V07k
         Hho94Ft/nADPK/LtfhUVC83GYWpZTtTpOeduwv8gR/INz7FAGRwYWdYa1ALmcgzQPHbA
         BJfDXwfs4iqiQ71t66r8RZdU89moYTXbAuPRJ30CrFH4pYyykInVFECAjrgOAPsfGd9t
         96gA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.134 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.134])
        by gmr-mx.google.com with ESMTPS id s139si573531wme.2.2020.01.17.04.25.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Jan 2020 04:25:26 -0800 (PST)
Received-SPF: neutral (google.com: 212.227.126.134 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.134;
Received: from mail-qt1-f169.google.com ([209.85.160.169]) by
 mrelayeu.kundenserver.de (mreue012 [212.227.15.129]) with ESMTPSA (Nemesis)
 id 1N3Xvv-1jaawf06BX-010ZNC for <kasan-dev@googlegroups.com>; Fri, 17 Jan
 2020 13:25:26 +0100
Received: by mail-qt1-f169.google.com with SMTP id e12so21613039qto.2
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 04:25:25 -0800 (PST)
X-Received: by 2002:ac8:47d3:: with SMTP id d19mr7117054qtr.142.1579263924900;
 Fri, 17 Jan 2020 04:25:24 -0800 (PST)
MIME-Version: 1.0
References: <20200115165749.145649-1-elver@google.com> <CAK8P3a3b=SviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-+JiQ@mail.gmail.com>
 <CANpmjNOpTYnF3ssqrE_s+=UA-2MpfzzdrXoyaifb3A55_mc0uA@mail.gmail.com>
 <CAK8P3a3WywSsahH2vtZ_EOYTWE44YdN+Pj6G8nt_zrL3sckdwQ@mail.gmail.com> <CANpmjNMk2HbuvmN1RaZ=8OV+tx9qZwKyRySONDRQar6RCGM1SA@mail.gmail.com>
In-Reply-To: <CANpmjNMk2HbuvmN1RaZ=8OV+tx9qZwKyRySONDRQar6RCGM1SA@mail.gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Fri, 17 Jan 2020 13:25:08 +0100
X-Gmail-Original-Message-ID: <CAK8P3a066Knr-KC2v4M8Dr1phr0Gbb2KeZZLQ7Ana0fkrgPDPg@mail.gmail.com>
Message-ID: <CAK8P3a066Knr-KC2v4M8Dr1phr0Gbb2KeZZLQ7Ana0fkrgPDPg@mail.gmail.com>
Subject: Re: [PATCH -rcu] asm-generic, kcsan: Add KCSAN instrumentation for bitops
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	christophe leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:sQc/Bz39qNexC1DoBBfafBRQpo2eugRj/ZKKpkJXmeB8eMWMNfD
 hqFd7YzqkYpzdKVEy3qkylZwyMIbtqw/4TBS3o7CyshstSI7sLIXiECRBf4BsS3PZrT1mAG
 e9kNBipO1qCpekzcM5aRovyguMyA1rIfxKQVgNU1l+oFTlMSPWXsn8G+wYx6YPDK6hRfqfv
 08zFDydD3mOo15m12G+LA==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:e0x4Thqj4Ak=:zwGqdidOonOZnELeLIWg6U
 kODToNpuglHzWhoUy8f9GdLiyDDpg8aCR3Ehw8zDOqB/4BGB/FQOAxmc95UV6wzeG8D34C5PH
 zbxd0CZMykDnNW0c1wV2GwRMTY+mEVCGEE+vK3waJK4C0u8r+pzRwKrCJIWX2cGj7c7SVNOdZ
 FGPCFUl8xrHjvk+T7PngrpeW6VymAfWosLJQycbh+hpVNlE24pSY+pD1QB9WvpWYpzgWlqcpo
 4sA1giLHjumm55B/lDNE+faxAKe5p2osG4uFXZaoQ7vXyjtuEZRKTxDwDx5l6bC1jISe9f48e
 QhKrGCrLh6do8A/7TLawaQWGny/u2Pv1S+DU3rXaZ3KcpM1+fgBMgQ/e3kJB63zTcEk4ZT8/P
 RHbzo0l6PpYR2zw/FB6gHd+NQaAuWA5Z4B16uoIAEQs6pnFClbqqd3DVdVkjVfjycJ04oV18B
 S8cuLOi8YzxOJmVOhAotQSmys6UU6w34dpl8C7AWluUKKu4wlOgQ7/eARQZHNBeqRQ7BinXU9
 3im03fJySo72erCEBmyn65QPQSm4jBk/wJs8bT4Ccjf3sPiAjSp8WGhhY1viBM+Htksr/vr0z
 N39Q6T+jX3T9WMK6J/ul6IwMj7+SWLWBmWZUr6JnyETT+l88xP5MlUDq9ZYtKWg8pjbkW+VWB
 8ej47aK5z2VAVUHgpPLD3j7t3HlT3L2Cpol37H0f25RCWPHvUfAR93WHwf9nnhyVhdbYo6Q8C
 FMj4qtjtLe+wjVqldb3fIuz2w4FLkeBF5KcegR5On9kgF9sVG1GmpoSdVnWnkz7DlQQyMVzOV
 adTmqaTaG5KqQ0C9kmbAUuCqXyc63YtuXXQ0Sa5dVfS6xJ7P0jJ3UjKdUVOF4QnGHc+9/0rZb
 aQAeQD386lxgua6atBqw==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.134 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Wed, Jan 15, 2020 at 9:50 PM Marco Elver <elver@google.com> wrote:
> On Wed, 15 Jan 2020 at 20:55, Arnd Bergmann <arnd@arndb.de> wrote:
> > On Wed, Jan 15, 2020 at 8:51 PM Marco Elver <elver@google.com> wrote:
> > > On Wed, 15 Jan 2020 at 20:27, Arnd Bergmann <arnd@arndb.de> wrote:
> > Are there any that really just want kasan_check_write() but not one
> > of the kcsan checks?
>
> If I understood correctly, this suggestion would amount to introducing
> a new header, e.g. 'ksan-checks.h', that provides unified generic
> checks. For completeness, we will also need to consider reads. Since
> KCSAN provides 4 check variants ({read,write} x {plain,atomic}), we
> will need 4 generic check variants.

Yes, that was the idea.

> I certainly do not feel comfortable blindly introducing kcsan_checks
> in all places where we have kasan_checks, but it may be worthwhile
> adding this infrastructure and starting with atomic-instrumented and
> bitops-instrumented wrappers. The other locations you list above would
> need to be evaluated on a case-by-case basis to check if we want to
> report data races for those accesses.

I think the main question to answer is whether it is more likely to go
wrong because we are missing checks when one caller accidentally
only has one but not the other, or whether they go wrong because
we accidentally check both when we should only be checking one.

My guess would be that the first one is more likely to happen, but
the second one is more likely to cause problems when it happens.

> As a minor data point, {READ,WRITE}_ONCE in compiler.h currently only
> has kcsan_checks and not kasan_checks.

Right. This is because we want an explicit "atomic" check for kcsan
but we want to have the function inlined for kasan, right?

> My personal preference would be to keep the various checks explicit,
> clearly opting into either KCSAN and/or KASAN. Since I do not think
> it's obvious if we want both for the existing and potentially new
> locations (in future), the potential for error by blindly using a
> generic 'ksan_check' appears worse than potentially adding a dozen
> lines or so.
>
> Let me know if you'd like to proceed with 'ksan-checks.h'.

Could you have a look at the files I listed and see if there are any
other examples that probably a different set of checks between the
two, besides the READ_ONCE() example?

If you can't find any, I would prefer having the simpler interface
with just one set of annotations.

     Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a066Knr-KC2v4M8Dr1phr0Gbb2KeZZLQ7Ana0fkrgPDPg%40mail.gmail.com.
