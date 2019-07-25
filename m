Return-Path: <kasan-dev+bncBDV37XP3XYDRBKEC43UQKGQE6IDNPYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id F165D74B4F
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 12:15:04 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id m25sf11338021wml.6
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 03:15:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564049704; cv=pass;
        d=google.com; s=arc-20160816;
        b=U29amacL6FaxAtcGeRxWnhG7v5oBEGDIb0nzeEBgdHK5qiM7oooOtjNM1WXBifGGd0
         jW0sX3Z4B156FTADnaSPeWi2gK5V6Mkmr57Z6qbfxtT67I++Nw2y3/xWtYN1U8IOU2Ws
         oTB/Yu+M5pSf5Xkc1sMun+W91lX9PWnffrb5QLk3eBFkkFVIk2WotaUq0ZGK1Uned28n
         HlK2BrkeqnGWE/8eRElkGC+SwS/7OlLXCGzaopV0UsRxvX9FnUBjKA2HIETONFukRoPp
         d2+7juKPP3uAOZnBVaPWwyFmyzRup1ZMjF0tWq73CwtUVUxbsRscrpHNVq97uONWfq2R
         xGHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=gKoOaJTaAKyGnAaIFsj/TQ5mx34oj/jj3PG01M1k6Zs=;
        b=STj3PUvVUjEyVEDd451QQBNRW9qUluFIIraVC548OSIzh2NpP2liL0Iv+HVXgXU/a0
         qIe5Qvbk4I5L+ivYvHpwxYeqC/5cIQAr2QZMW/1Gn+7oNWjrSrektxXHAEAcrGbh5A1U
         D9zmAV9Z/FxLIQb5FZa5eLmDV7Y3SAf3LmyFWZnJZuDV4wDhfbzpYVpZJajFG/r1r8pb
         /J4NazlKJYAxUHoY6626s/lOFLB08m2u6b0zjUi02poikxSQqP5lGCLLTSCz8oMxhh5h
         pbMxQStLfhkvbfN2qbyfEr74M2dyuX//+NVqGiuBu2sj7ystY9MMSl1Z8jVTCKDWw1YF
         c9ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gKoOaJTaAKyGnAaIFsj/TQ5mx34oj/jj3PG01M1k6Zs=;
        b=SBf5Fxqvqgbgcsb6W09G1lODW+DsxQIntKgtxTslOU1oIKsYaJ8+EhPtF5b2GyM8mv
         BTOngyKVtOeRg46kijxamF9CT0lwTdbUY21q/33YNWSnWGXAEv55y4Xfl7Xlv7kMyjpo
         bp54mbafiMSblthj/vv/vVGVq/GR3BTret6mwAEgKvq1pVyrp/7gycFYimEVyM2SwYRA
         E4qAbrBq5z6n1B6pvmzFrmXbuokpc++PsAx74e0W092MsjfsQ19NBqiSGLxZMppybAap
         rNulOHVejcKDw0kydTo1j+wYtEKa0J9UPB5Py4be+2Ltq2S8TVEVZFFh33lCcG9zgWFG
         b4kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gKoOaJTaAKyGnAaIFsj/TQ5mx34oj/jj3PG01M1k6Zs=;
        b=m2uZxdR1vBaxnRKEvX+jvwj0lhkluzBjWpUW4CievrZD1MKSTaSHPmYuj4hvUUXZMk
         rLdd+8jVSyjvoW9ACVj6RI/PujyFbjeviwwlSokkZaEunwa+qSWTPLfwJJafI9FNsT4D
         2OAiC7evzXCxWbkC48/45wfN7d/nUf4XNMHG3BP7RbUzexi5rwCmZNdTKfSaFhvv+Qgc
         QhQIyS/BUF+OVsJ3B9xT9On8JeZJ2CyE0qKaVTvy8TzA4/FXq/AZKyvJfvtRkrJtYUOD
         57/BfGg5cDHFGiQ3LYZOyGtil2jjbuPiTMQFyxnuQUilHCcFCgS6FgoSktKZ1PNefrtR
         k9qA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVJwBDaywlWIkI1k2W48ZR3lJWCX6yQyEX1PFpm7WmnMG3vzC1G
	xys6cVoau2+jNwdSFkum4HQ=
X-Google-Smtp-Source: APXvYqwCyUIZiyW9eaHH0PZk34YJw2T8SIGHfdpdaggnPfqrhxc2mxiFEx8zYqvvfP0aBmd+p89srw==
X-Received: by 2002:adf:e2cb:: with SMTP id d11mr65306338wrj.66.1564049704686;
        Thu, 25 Jul 2019 03:15:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c05a:: with SMTP id u26ls17512666wmc.4.canary-gmail;
 Thu, 25 Jul 2019 03:15:03 -0700 (PDT)
X-Received: by 2002:a1c:7f08:: with SMTP id a8mr29101172wmd.1.1564049703885;
        Thu, 25 Jul 2019 03:15:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564049703; cv=none;
        d=google.com; s=arc-20160816;
        b=ELC/286hWWNmMO9Uy2jBOMJQSnhsvgqoNuAs3qhgxfVw+w0ffUch4SSRRFpOrux7Ud
         ARLfTCb0fw/xkNkJs1xlgSzGknJxk6hfwRz96yJXNxmZQkeOJ3SM+L4D3OArlSgPlf7N
         0hs5Ni+5/qWkz4jaUlQi3MkEXY8IrFvfmxKi5CAQ9Q7K/8eL2cGukdOqYfoptmOY5H4/
         8ghkUGhxotS+/GVN/EmEK4rBMt73IZCfdyAi21L8tJAET0OALhYuNSskqCZ11lwQdHHb
         smwRzf6U/Rg+FYcjSPh5wtbsK0RW4CzTKgXxafeGp1Pvh7P47JTfX5jCKTj9qqCLCARw
         U67Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=A5fpHhkBLopjEAVRdvHy+BaH175D9mtLGLFtLihQLSk=;
        b=epB5qZtb+ZM9HP2K11mkOaaHVcNt51Er2BuGVbkfQgna1PsQuQNiKBV/J4sglXbSay
         Z6gp19kcSd9bVWJcjcdamKcjQjkhokZup0p7+jzs/Y6iHQekjTkYrF0sMcBFYswEJmYx
         vnrXiWtUURnEBGWnqttKIQVvGywhha4HlTezXyHURnlw8LF0d64zHdGm5IeJbscydsL4
         IyNSOl+rTPlYGbYhBbFp7fXz96S74/RNOVY/2juGGGBw8PAt17Xakta2WeqgRwcxK5Xk
         J4HeVEf+9UpqjKgVgPkymZAPpitV6vkJn2GGXZ3WR12tBpPaGtFualWfTYAgteMg+TC/
         sRQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p15si1775832wmb.0.2019.07.25.03.15.03
        for <kasan-dev@googlegroups.com>;
        Thu, 25 Jul 2019 03:15:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9A82F28;
	Thu, 25 Jul 2019 03:15:02 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CD3273F694;
	Thu, 25 Jul 2019 03:15:00 -0700 (PDT)
Date: Thu, 25 Jul 2019 11:14:58 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Daniel Axtens <dja@axtens.net>
Subject: Re: [PATCH 1/2] kernel/fork: Add support for stack-end guard page
Message-ID: <20190725101458.GC14347@lakrids.cambridge.arm.com>
References: <20190719132818.40258-1-elver@google.com>
 <20190723164115.GB56959@lakrids.cambridge.arm.com>
 <CACT4Y+Y47_030eX-JiE1hFCyP5RiuTCSLZNKpTjuHwA5jQJ3+w@mail.gmail.com>
 <20190724112101.GB2624@lakrids.cambridge.arm.com>
 <CACT4Y+Zai+4VwNXS_a417M2m0DbtNhjTVdYga178ZDkvNnP4CQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Zai+4VwNXS_a417M2m0DbtNhjTVdYga178ZDkvNnP4CQ@mail.gmail.com>
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

On Thu, Jul 25, 2019 at 09:53:08AM +0200, Dmitry Vyukov wrote:
> On Wed, Jul 24, 2019 at 1:21 PM Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > On Wed, Jul 24, 2019 at 11:11:49AM +0200, Dmitry Vyukov wrote:
> > > On Tue, Jul 23, 2019 at 6:41 PM Mark Rutland <mark.rutland@arm.com> wrote:
> > > >
> > > > On Fri, Jul 19, 2019 at 03:28:17PM +0200, Marco Elver wrote:
> > > > > Enabling STACK_GUARD_PAGE helps catching kernel stack overflows immediately
> > > > > rather than causing difficult-to-diagnose corruption. Note that, unlike
> > > > > virtually-mapped kernel stacks, this will effectively waste an entire page of
> > > > > memory; however, this feature may provide extra protection in cases that cannot
> > > > > use virtually-mapped kernel stacks, at the cost of a page.
> > > > >
> > > > > The motivation for this patch is that KASAN cannot use virtually-mapped kernel
> > > > > stacks to detect stack overflows. An alternative would be implementing support
> > > > > for vmapped stacks in KASAN, but would add significant extra complexity.
> > > >
> > > > Do we have an idea as to how much additional complexity?
> > >
> > > We would need to map/unmap shadow for vmalloc region on stack
> > > allocation/deallocation. We may need to track shadow pages that cover
> > > both stack and an unused memory, or 2 different stacks, which are
> > > mapped/unmapped at different times. This may have some concurrency
> > > concerns.  Not sure what about page tables for other CPU, I've seen
> > > some code that updates pages tables for vmalloc region lazily on page
> > > faults. Not sure what about TLBs. Probably also some problems that I
> > > can't thought about now.
> >
> > Ok. So this looks big, we this hasn't been prototyped, so we don't have
> > a concrete idea. I agree that concurrency is likely to be painful. :)

> FTR, Daniel just mailed:
> 
> [PATCH 0/3] kasan: support backing vmalloc space with real shadow memory
> https://groups.google.com/forum/#!topic/kasan-dev/YuwLGJYPB4I
> Which presumably will supersede this.

Neat!

I'll try to follow that, (and thanks for the Cc there), but I'm not on
any of the lists it went to. IMO it would be nice if subsequent versions
would be Cc'd to LKML, if that's possible. :)

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190725101458.GC14347%40lakrids.cambridge.arm.com.
