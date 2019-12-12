Return-Path: <kasan-dev+bncBDV37XP3XYDRB37QZHXQKGQEGE3K6PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id DC7C611D3CC
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 18:27:11 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id z10sf1275297wrt.21
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 09:27:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576171631; cv=pass;
        d=google.com; s=arc-20160816;
        b=W1n2tsb4MknggNEjjfgMHB/fxRfl0yy5jD4MD47ppmbyq3PeTpRXY2K0VOmanfcJ9N
         iYp8iVKNZzAV102/xaBkWbMW7QTdtR8m92k6WU3Nint16U5egThu7Djw7yiXwAfhPUuF
         kdUdq2FhS9wRh6KV+Jj51CzippBh0WlNcatdYPhcPCYvCJ/cPXD0cCZGkN4UD6QncVh9
         5LUhpT1KbUr3EGyt5WzRPDghvP/QC08QGAYRJJQL/JHLro0uJECvX9G+GiQ3otdwf3ZM
         0U963GsamCKVRl2+3rWOo0WKVTwJ46UYKCq+e/eJUCDagxHvPnibmRPWT7MK0JARqSUi
         d3Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=RGLvM4RR7W7kYElySPYGLfi2Q5yJa7kQI8N9xIu16Jc=;
        b=wP5bf0yA/6N07NNlvDmtcKPG7J8lJDaQ6alLbkOA4O7wHttD10YnvX/3JID5+6a+VD
         n/TTYDcFrefWgsS/ISN5HTCLP/eaKi79/lbssT00/vo1UtWOi5mDpH15HHMsiZ8Bya9D
         SYszKTqGFV4IbBzFPvldwyfFBHmu4evN+bwNk1mmMHN+p3hud7W+COt6Zi/btwHrn860
         OVxlHuPB55D6ZliYE7TCbN80/l3Swxcso2aeEMMSIQcuGRtPQb5y0aCMvMgAZWQ1eTOz
         7AFUlTylMwrOLC80IWDAZnRuK3irUqsdPFYDs4JXdodWXwiD43CxzUy0QU4tT14xGC63
         KK8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:content-transfer-encoding
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RGLvM4RR7W7kYElySPYGLfi2Q5yJa7kQI8N9xIu16Jc=;
        b=GlUD1YJT4zRkJwu6/HyX7oBUp4sVmbpht+oRdgAFkkZezzaiThFwerX4t1Cb4ynZXw
         /dYXYjF7MHG7lHgdf6HTefshjzbc19DcoySxkZxguDHel4fWZB8GRPqmc4lGTN5sP0d3
         D5bbdQxWPziKnG4zaVNK/7RnBHlwdWVNsgEZs0rStXa/KXJSVXRYHrkGo/6mNLpNBd3a
         lQVW4I7vCXuRFWlVRYwHlqVxeF6cAIO6dqtEQRnRguhGfdxkS9A8o6TYn3k5O3kVDysZ
         ftLQhg+uvoqEkR2cZQfoPO99YfrAdCgWtDY2cB7hORybiFfeeagi2tAAdZM7mKZgBCMg
         /xXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RGLvM4RR7W7kYElySPYGLfi2Q5yJa7kQI8N9xIu16Jc=;
        b=okH1HhRzAJ7si+gvvOBKBOvMHBR+o6k2CHVmWtATxKKTAsqws9nJkE1xy7xlmDXAF3
         m7+tWpptIBH0pH+1W+D+mONiAT1ngnGbzDuEjRmAevEiKn4HipJKrI7H4RnPX+KbWL1Z
         SBMcM8qIE1dijbnPsdEOXBi6YVMpQ3ds+gsBqpdNrgExSQYrcfstj1u1fNG/EV94ckFP
         k2pdr3ihb//hSFJNuNoYxPq+dCJl+SC4V/Tm4C/SQHE4rpJ0PvHaOa1toUJHRnnFA55O
         ls8Jm4ZZli3wW+JkHdTPGOFuHQaud4YoSy0yvlnm6lOaFOdWl5yZlrQ6PsqA7OIrPOzl
         YlIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUHbCTnxqUcxxHt1J29GIUWIuVQz7M6+CQkSFEGlYlS5vgL+0tR
	+NNqlfR9wZmNe79IwwqqWA8=
X-Google-Smtp-Source: APXvYqzNJFQKXfFYI5KJL7vvxFpthvCXzs8xwjzRTJq5dXLRlYfGMhMMIUf82dAoTSi1r7VlAa8fPw==
X-Received: by 2002:adf:e290:: with SMTP id v16mr7943778wri.16.1576171631530;
        Thu, 12 Dec 2019 09:27:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cf15:: with SMTP id l21ls3011100wmg.0.canary-gmail; Thu,
 12 Dec 2019 09:27:10 -0800 (PST)
X-Received: by 2002:a7b:ce81:: with SMTP id q1mr8096328wmj.47.1576171630919;
        Thu, 12 Dec 2019 09:27:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576171630; cv=none;
        d=google.com; s=arc-20160816;
        b=swBwOre0sYuRxg9chfH3q8kMdBIgllkg0tLpVV4sBGwjg8lzE2xVodLsHZQoRtKMgT
         Q4bTJwgOd2xujeC9bpoNcG+o4zgsJELJkUb+mYzsHMdffHnrpenfcfYJAOCcGSckzsN2
         v/GvHu5IlzY7y9wbkFgM+k6ZY1YjzA+CRct6JUvMcGiqIp1QoRuQ9sMeEZ0HWgONtK2m
         l6oAnNB2+6HzABxx42Brf/rGbPMYU+LwPUx0LV/CtNmz+ucgO+Ee3pOdWLnE10TdRXgJ
         QVPywjzb8cSmF5+Japy8Ir4NWvPUJmk8DoU23flJ/pFKa1Up0djy08HJnxEa1zHtLcrT
         b8ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=yLln+kGSZES5QkL9ahqMCpG4ddNQ0HILbIUzpfYLvcA=;
        b=b7VkmA3j1P3Ql+6lmi2Ugh4qBia9ZVmFIP42HdV+azQONf7SJFZuk5L/DEVqFfjvBU
         aMt4C8j3A4FFo9jU/IcUf1cb6qnvzBUbZpO3ZAqHfsJfdKb2q1+0mIwSjEeXPaY65vy8
         1Wz8NmBe24kwF4wTkP/k+LoUZphDqcKZ6WAhy8K/2b8wlar9ZDRUKH0xkEKgVHk50btL
         EsbhMHc+wlAXLU4GNEFxRipVgSFNQme59qxGjbgdYGkme4P+kRpRpmKXsAM1yFLAvykW
         zCvwcwHkBecSPfLwu1Nju735ExjwwWwX6K3THF5+hRcVvpNTnwHI54ig4pTswpaQ9LIY
         nKgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a138si251577wmd.1.2019.12.12.09.27.10
        for <kasan-dev@googlegroups.com>;
        Thu, 12 Dec 2019 09:27:10 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D97AE30E;
	Thu, 12 Dec 2019 09:27:09 -0800 (PST)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 89DEB3F6CF;
	Thu, 12 Dec 2019 09:27:08 -0800 (PST)
Date: Thu, 12 Dec 2019 17:27:06 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Mukesh Ojha <mojha@codeaurora.org>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	sgrover@codeaurora.org, kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Paul E. McKenney" <paulmck@linux.ibm.com>,
	Will Deacon <willdeacon@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>
Subject: Re: KCSAN Support on ARM64 Kernel
Message-ID: <20191212172705.GI46910@lakrids.cambridge.arm.com>
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org>
 <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
 <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
 <20191014101938.GB41626@lakrids.cambridge.arm.com>
 <0101016efaeb3a3b-81a8c0fa-c656-4f95-9864-c7f4573024fd-000000@us-west-2.amazonses.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0101016efaeb3a3b-81a8c0fa-c656-4f95-9864-c7f4573024fd-000000@us-west-2.amazonses.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
Content-Transfer-Encoding: quoted-printable
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

Hi Mukesh,

In future *please* reply in plaintext rather than HTML.

On Thu, Dec 12, 2019 at 04:22:30PM +0000, Mukesh Ojha wrote:
> On 10/14/2019 3:49 PM, Mark Rutland wrote:
> > Once the core kcsan bits are ready, I'll rebase the arm64 patch atop.
> > I'm expecting some things to change as part of review, so it'd be great
> > to see that posted ASAP.
> >=20
> > For arm64 I'm not expecting major changes (other than those necessary t=
o
> > handle the arm64 atomic rework that went in to v5.4-rc1)
>=20
> Hi Mark,
>=20
> Are the below patches enough for kcsan to be working on arm64 ?

That depends on what branch you're using as a base. My arm64/kcsan
branch worked for me as-is, but as I mentioned that was /very/ noisy.
Both the kcsan code and the arm64 code have moved on since then, and I
have no idea how well that would backport.

I had a quick go at porting my arm64 patch atop the kcsan branch in
Paul's tree, and that doesn't get as far as producing earlycon output,
so more work will be necessary to investigate and debug that.

I hope to look at that, but I don't think I'll have the chance to do so
before the end of next week.

> I am not sure about the one you are mentioning about "atomic rework patch=
es
> which went in 5.4 rc1" .

There were a number of patches from Andrew Murray reworking the arm64
atomic implementation. See:

$ git log v5.3..v5.4-rc1 --author=3D'Andrew Murray' -- arch/arm64

With those patches applied, my change to arch/arm64/lib/Makefile is
unnecessary and can be dropped.

Thanks,
Mark.

> 2019-10-03 	arm64, kcsan: enable KCSAN for arm64 <https://git.kernel.org/=
pub/scm/linux/kernel/git/mark/linux.git/commit/?h=3Darm64/kcsan&id=3Dae1d08=
9527027ce710e464105a73eb0db27d7875>arm64/kcsan <https://git.kernel.org/pub/=
scm/linux/kernel/git/mark/linux.git/log/?h=3Darm64/kcsan>
> 	Mark Rutland 	5 	-1/+5
>=20
> =09
> =09
> =09
> =09
> 2019-09-24 	locking/atomics, kcsan: Add KCSAN instrumentation <https://gi=
t.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=3Darm64/kcsa=
n&id=3D8b3b76ec443b9af7e55994a163bb6f4aee016f09>
> 	Marco Elver 	2 	-2/+199
> 2019-09-24 	asm-generic, kcsan: Add KCSAN instrumentation for bitops <htt=
ps://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=3Darm=
64/kcsan&id=3D50c23ad00c040927e71c8943d4eb7d52e9f77762>
> 	Marco Elver 	1 	-0/+18
> 2019-09-24 	seqlock, kcsan: Add annotations for KCSAN <https://git.kernel=
.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=3Darm64/kcsan&id=3De=
2b32e1a3b397bffcb6afbe86f6fe55e2040a34a>
> 	Marco Elver 	1 	-5/+42
> 2019-09-24 	build, kcsan: Add KCSAN build exceptions <https://git.kernel.=
org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=3Darm64/kcsan&id=3D35=
a907033244099a71f17d28e9ffaca92f714463>
> 	Marco Elver 	3 	-0/+17
> 2019-09-24 	objtool, kcsan: Add KCSAN runtime functions to whitelist <htt=
ps://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=3Darm=
64/kcsan&id=3D3afc592ca7ebd9c13c939c98b995763345e85e08>
> 	Marco Elver 	1 	-0/+17
> 2019-09-24 	kcsan: Add Kernel Concurrency Sanitizer infrastructure <https=
://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=3Darm64=
/kcsan&id=3D73d893b441dc3e5c1645884a19b46a1bfd4fd692>
> 	Marco Elver
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20191212172705.GI46910%40lakrids.cambridge.arm.com.
