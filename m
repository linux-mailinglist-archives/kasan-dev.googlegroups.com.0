Return-Path: <kasan-dev+bncBDV37XP3XYDRB3576DXAKGQEAIRCI3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id B643610939F
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Nov 2019 19:39:43 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id g11sf4261922edu.10
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Nov 2019 10:39:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574707183; cv=pass;
        d=google.com; s=arc-20160816;
        b=bvvoMDMLuZFhI+PdLrt1NqQkzbW5XtRJ2JB8NGMkuoUm3P3XMzkEQfX+PBiGzZmodW
         ez+U4UcVXyCNmuFIDzVttl+AwvzGftkTm5Avx2sPxebUX7qP1sCgDZeNEQpPoJOg1kjF
         FZJHqg0TyhEdRJZ0UxwxS3dJShue9zhuX8lIuZ0px5eoP8eA8qyj7ixNtQbn0pU1HNV4
         riZ5AbBf5fgV+xT/S2MkKUtJnvNEY6BNCv1/F5QUUCvhJvcsuR92893JW86gQpiVNsE/
         KPR3VHgfdgM8d1MnERSZe2mEZL+mvibAqO4p63UZkrNmWniefHAG3GTXerwQHzBeg/Hm
         1rGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=KpjM9EleDdoFRdZAH9+hf7szL+557kcvSjZbgq46Fmg=;
        b=y1MtNE5ONiIZ8T8k1nrZkV2qeBa5ZMELGGtIg5hwh+64w/sC6C8fFijCMzAGf7dqsz
         BZhrdzOWUhZh5mA4F32fn62gKrfyQuBjQmgJEEtBZ3hr9iiSTPyDg323HttyiYYNL4H+
         DDvqe3lScAjPUNtYXqWn6bSNKSQtnD0F+StdEOr98IhNw7Nzw2WksNDZRI41bUnTulaF
         2mcf6htDdvm9fbhc9BnCvMndROLVPASuC+wukjXS8W6LBegO/t8gogR18gsXJ8wlffUm
         jKfy4t9eebOrK0znT3EXCDXZ8StBzztLdKuW9bLkyytfPUjzdMnisfq52J4sBPMDtBoP
         zkyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KpjM9EleDdoFRdZAH9+hf7szL+557kcvSjZbgq46Fmg=;
        b=Z/WVDgd8MFJ5BpHL/o694OUvzonJFK3porQZOC4/nCZwg4ETRCTpGNWA2Np0PPH2mZ
         yI6ZjnmL6hEW2YtXkUvMmvNyVIhKBaiYo4682bT1Cg2yqHKXxsW11Fdqy06CGPYkJ5jW
         mLYWoYL1oriHA6vZBb0GOBpBscferv+UuLv8fS9lsDarT+tavQwx1Axj9tXo1P7jTqdv
         hize7QRKci/+/nlJniEP5V42qWnyr5yT6InfrlsBoR/5NDZYpttT4jIbNG8fckrNvWXC
         ITtTXWgTCQ5XqrEKGkVSuNlegwXs63KNzwNM91UhXmdu5aUgqRFshCy4wQ1oT8QNDFcQ
         iAqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KpjM9EleDdoFRdZAH9+hf7szL+557kcvSjZbgq46Fmg=;
        b=rVrQEm+h98Tdb8S8jFhkKwSthNqWOK2notfXHwnLx4qBdrSQ0aZTB+lmQ0g6izINhb
         iFHZd0E/wjD1uLx5n0fESiGR8f19ArNWKg6rK0hEpHDPNIoLaEhB1oByHXFgjLkaHJ8V
         qSOZyR0akuexlVWAofRgUicLUiOpaFzNOHHfi5K75KCWudfLxv7znaEHodfGwgYlxUW0
         Q7ILtzrA1uzU32wE+z1JC6iiILdE3uzMgbj47Fq04PT/oy7ZfmyqikHQNnPgLyTG5GQc
         QYts+bVnYcEXlyZslExLEUN9/03QNNlblJ7LFzxh2ct3mXYwqitayrAxrS8SPv/nyLU1
         sAEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUKygBWLfbMdVya668MkJmsUqHtjK8V7nLdlRa9EkzX/UHCwzOg
	pTSZ+BMYNYmkidnP2yAcE64=
X-Google-Smtp-Source: APXvYqwt1g4tZv3UAiqewvTd3WFVYW9jHlfMd0ouSEHyzhyuz3tpHF20W9nkjzkjQojQ0W3JlqAw0w==
X-Received: by 2002:a05:6402:14d3:: with SMTP id f19mr20431552edx.252.1574707183393;
        Mon, 25 Nov 2019 10:39:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:db0b:: with SMTP id t11ls2315197eds.1.gmail; Mon, 25 Nov
 2019 10:39:42 -0800 (PST)
X-Received: by 2002:a50:eb8b:: with SMTP id y11mr20730791edr.242.1574707182689;
        Mon, 25 Nov 2019 10:39:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574707182; cv=none;
        d=google.com; s=arc-20160816;
        b=wU4q8Mt8kRNPKxlpfpIeCnrog5nUlh8IXqf02htRl0m7T4Z9GCXjZV8Dg397iPPhN9
         tF4nHYMhSbml600VcjZsis/unKA99JCGVJLHfG3plB+lSaWWtaXq5XXW6gB4Ppuv0XUu
         EF+3NXiDl7RQbAV2eM2FAUgSAyBBlfqq1l/Q9J08uWMzPHH54YjcnoXV3K7tXM/UIj5D
         d9uaIo5+JE8pAR1Z5G9lCq57602LMNax3KSTWB7pK5DvCrHuAUJnWBrYjx1KkRoqlITP
         Y579xiLhSLVA7TweZ+HNtKYEKDx69/zxilRaVuUI0Fmikm5CIQx/OLj8kosbdH7vMy6n
         uBjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=tHbfH0zHQ/iHrVop/lQ6dHIbGmrgJn72JpMiRgVYAfY=;
        b=a2c1WeoceVevArm6pgQ8NVInPMjH+6dH/eXUiuC+7yFUrIXcUzQjJOoRN397YP6aKv
         RKOPsiufOXV2TnrZKyFCyd/PYR3koxMG7g62qka+2+QXfTVlgZ75vALpIJgmUzk43+Vt
         3rcc1ogODbSOf9ckKu0J/D7J5gfOBx+/K8byctf4KkWVZm4C2iFjW6UxxBYV2/NmI9aD
         9lfsjE2lq/66U0ek8jWuhBOyYfo9Oc9MlmonwOpoVNdJiI1fJ6cKCBS7Ct8JSJjGVO1z
         Fzs5gnTQvNfTf3+kkqjOLrUy1OBsjtY/Gn2/++BUGSDnzYR3CWZZdi23faBIixbN63wG
         M65w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id n21si369359eja.0.2019.11.25.10.39.42
        for <kasan-dev@googlegroups.com>;
        Mon, 25 Nov 2019 10:39:42 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CFDBE31B;
	Mon, 25 Nov 2019 10:39:41 -0800 (PST)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 652BA3F68E;
	Mon, 25 Nov 2019 10:39:40 -0800 (PST)
Date: Mon, 25 Nov 2019 18:39:38 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Randy Dunlap <rdunlap@infradead.org>
Subject: Re: [PATCH 1/2] asm-generic/atomic: Prefer __always_inline for
 wrappers
Message-ID: <20191125183936.GG32635@lakrids.cambridge.arm.com>
References: <20191122154221.247680-1-elver@google.com>
 <20191125173756.GF32635@lakrids.cambridge.arm.com>
 <CANpmjNMLEYdW0kaLAiO9fQN1uC7bW6K08zZRG=GG7vq4fBn+WA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMLEYdW0kaLAiO9fQN1uC7bW6K08zZRG=GG7vq4fBn+WA@mail.gmail.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Mon, Nov 25, 2019 at 07:22:33PM +0100, Marco Elver wrote:
> On Mon, 25 Nov 2019 at 18:38, Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > On Fri, Nov 22, 2019 at 04:42:20PM +0100, Marco Elver wrote:
> > > Prefer __always_inline for atomic wrappers. When building for size
> > > (CC_OPTIMIZE_FOR_SIZE), some compilers appear to be less inclined to
> > > inline even relatively small static inline functions that are assumed to
> > > be inlinable such as atomic ops. This can cause problems, for example in
> > > UACCESS regions.
> >
> > From looking at the link below, the problem is tat objtool isn't happy
> > about non-whiteliested calls within UACCESS regions.
> >
> > Is that a problem here? are the kasan/kcsan calls whitelisted?
> 
> We whitelisted all the relevant functions.
> 
> The problem it that small static inline functions private to the
> compilation unit do not get inlined when CC_OPTIMIZE_FOR_SIZE=y (they
> do get inlined when CC_OPTIMIZE_FOR_PERFORMANCE=y).
> 
> For the runtime this is easy to fix, by just making these small
> functions __always_inline (also avoiding these function call overheads
> in the runtime when CC_OPTIMIZE_FOR_SIZE).
> 
> I stumbled upon the issue for the atomic ops, because the runtime uses
> atomic_long_try_cmpxchg outside a user_access_save() region (and it
> should not be moved inside). Essentially I fixed up the runtime, but
> then objtool still complained about the access to
> atomic64_try_cmpxchg. Hence this patch.
> 
> I believe it is the right thing to do, because the final inlining
> decision should *not* be made by wrappers. I would think this patch is
> the right thing to do irrespective of KCSAN or not.

Given the wrappers are trivial, and for !KASAN && !KCSAN, this would
make them equivalent to the things they wrap, that sounds fine to me.

> > > By using __always_inline, we let the real implementation and not the
> > > wrapper determine the final inlining preference.
> >
> > That sounds reasonable to me, assuming that doesn't end up significantly
> > bloating the kernel text. What impact does this have on code size?
> 
> It actually seems to make it smaller.
> 
> x86 tinyconfig:
> - vmlinux baseline: 1316204
> - vmlinux with patches: 1315988 (-216 bytes)

Great! Fancy putting that in the commit message?

> > > This came up when addressing UACCESS warnings with CC_OPTIMIZE_FOR_SIZE
> > > in the KCSAN runtime:
> > > http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
> > >
> > > Reported-by: Randy Dunlap <rdunlap@infradead.org>
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > >  include/asm-generic/atomic-instrumented.h | 334 +++++++++++-----------
> > >  include/asm-generic/atomic-long.h         | 330 ++++++++++-----------
> > >  scripts/atomic/gen-atomic-instrumented.sh |   6 +-
> > >  scripts/atomic/gen-atomic-long.sh         |   2 +-
> > >  4 files changed, 336 insertions(+), 336 deletions(-)
> >
> > Do we need to do similar for gen-atomic-fallback.sh and the fallbacks
> > defined in scripts/atomic/fallbacks/ ?
> 
> I think they should be, but I think that's debatable. Some of them do
> a little more than just wrap things. If we want to make this
> __always_inline, I would do it in a separate patch independent from
> this series to not stall the fixes here.

I would expect that they would suffer the same problem if used in a
UACCESS region, so if that's what we're trying to fix here, I think that
we need to do likewise there.

The majority are trivial wrappers (shuffling arguments or adding trivial
barriers), so those seem fine. The rest call things that we're inlining
here.

Would you be able to give that a go?

> > > diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
> > > index 8b8b2a6f8d68..68532d4f36ca 100755
> > > --- a/scripts/atomic/gen-atomic-instrumented.sh
> > > +++ b/scripts/atomic/gen-atomic-instrumented.sh
> > > @@ -84,7 +84,7 @@ gen_proto_order_variant()
> > >       [ ! -z "${guard}" ] && printf "#if ${guard}\n"
> > >
> > >  cat <<EOF
> > > -static inline ${ret}
> > > +static __always_inline ${ret}
> >
> > We should add an include of <linux/compiler.h> to the preamble if we're
> > explicitly using __always_inline.
> 
> Will add in v2.
> 
> > > diff --git a/scripts/atomic/gen-atomic-long.sh b/scripts/atomic/gen-atomic-long.sh
> > > index c240a7231b2e..4036d2dd22e9 100755
> > > --- a/scripts/atomic/gen-atomic-long.sh
> > > +++ b/scripts/atomic/gen-atomic-long.sh
> > > @@ -46,7 +46,7 @@ gen_proto_order_variant()
> > >       local retstmt="$(gen_ret_stmt "${meta}")"
> > >
> > >  cat <<EOF
> > > -static inline ${ret}
> > > +static __always_inline ${ret}
> >
> > Likewise here
> 
> Will add in v2.

Great; thanks!

Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191125183936.GG32635%40lakrids.cambridge.arm.com.
