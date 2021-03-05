Return-Path: <kasan-dev+bncBDV37XP3XYDRBCF5RCBAMGQE7BU7YPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FC2B32E79E
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 13:05:30 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id u5sf1514073qkj.10
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 04:05:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614945929; cv=pass;
        d=google.com; s=arc-20160816;
        b=U7/rqqHkbg2xTwPO8TmuM3vDdQTIEVAjn0EydgxKAf6mEIV2qODNniT+tnBTYX0wdk
         acaHnoKdVWkWbKyx0+XmNhChgq5VzqZzG1nWzHh97nRPuB7vV741Wl02fSiisAG8jSV8
         KAc5xK7TNyB4Ga+DsZ11XGaIXrMj/i6dzmA8P4Qj8vPPefLo3c69Ptwg90soOBOitUyU
         3JGqlaTRv53icobnm3zG3xIumOv6FIFPqxtkzt4N4iSgAbgldtmUj8cOHoeQbSbn/Q7C
         YcMtI5Q/uIGMAfG4Uqk+HIUtU/ikCa+RtEYXYvsUahRGuveNGHvPPN4VXiWozY4RGGts
         5WdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FV5LogSmUAVdugb+FffaiDgUyL4n2j6EkhCec6gOWe0=;
        b=Q3HueWCIkX/QbyVkVT3zgd+nTGQq5fL6MP7Aplv9Y16IP4DHqUL1DYJh4L3XLwqCed
         kglaff18rIKODqikbVtYVXNLl9Yd/76hbdQPWzOsOdHURRfaikZZvM73AvDX07k3Q5AW
         P5QqyZx0lYmnzTRm4vaS8azD/zFDM5nOcOpTWXRd0biGOnOZw9SCkRrlP+ybRwV4VYOV
         QQOSCiYkFtuFD+lTfxGjsUMZ9TN2HTSeVkuNNNEoJ/YYYqmjHQpDppHrPlzpblUp5Fjw
         QpBPfCngpPKY+ZBB2hXuh5a71QWnqmrk6lxQDgUFKyATzkfib+GsfavNv00O2D1eadG9
         XmVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FV5LogSmUAVdugb+FffaiDgUyL4n2j6EkhCec6gOWe0=;
        b=mBXk4MB8Dlz7Qz5ZdLamKioxOE4/amLG401ICofeSLf/tiCh+QD8pN4bXSYZRBysgO
         aYdpkUl3s+Spk31Yf3lGEoTg1xnF7SIyDTGtHuKzbL/DRvnq80JSm+B8bi/dRT8gguzI
         AGb7TLzOkQBYhGJPf+DLStMDdY5fY+xPaiFPlUACmqe7kfuvTmlZmHD/vOLdQDxPiD/y
         RSqmgg6zTYtmj7wv1ZQTrcIPw4brcoYZpf2Ki7ZOBDHn/nacFQ1M8ILsU0RKST16X7kh
         Id22NFkJbw2fGdzWEFKKZwQTFDd6Bn/1RUJ1AixgV5pWcbV5is38IigwJKeruALBkoRr
         H5Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FV5LogSmUAVdugb+FffaiDgUyL4n2j6EkhCec6gOWe0=;
        b=iiq/1G6UNpuOMZ/SQhqf0q9Xnc+PfUbG1LCpo2OrMjeVhVRBW1C22ubOuK85PYuIhs
         PUbJN9A10txkIFbrVRyzycqu+sZMqgwGe0+ARykyoYetDTgh9QMLTesJADkaToetqxMl
         HKUI/ghZ/nlhpoyNH2feAw+5c7ySUnwO5WQJCFMJh0NK7Osbw55gHecOpf1QiuYPbWTU
         tAogHQf/Qs/+kF8EBBndgFWULUYetsTzaM2aKJ6RTBX08WNOJskiH1CsfWAs1g1DD5tc
         uXkIb4RZahF67sbyr9Z7Fx9sPvd1IRdEIxfLz23vX3D13H+tHhjUMirvN/TJmZGt8r41
         3jCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532eVNHsukZvHrTOwihtmU11jfVuq0fPDSjjSWa+7QDmI8E5vD7A
	0ow0/CiGb1lPJD9mY2EaChM=
X-Google-Smtp-Source: ABdhPJz9S0e0OsiCLZBM+cvH3kHfwDNe2Weh/j9qPLtf1IFYIgeleLx6BsweNoX/+9eD3BRxG9Ncbg==
X-Received: by 2002:a0c:aa10:: with SMTP id d16mr8345975qvb.42.1614945928874;
        Fri, 05 Mar 2021 04:05:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a050:: with SMTP id j77ls4824588qke.10.gmail; Fri, 05
 Mar 2021 04:05:28 -0800 (PST)
X-Received: by 2002:a37:4986:: with SMTP id w128mr8358799qka.313.1614945928360;
        Fri, 05 Mar 2021 04:05:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614945928; cv=none;
        d=google.com; s=arc-20160816;
        b=suEfoTtDvyIURyZcZUmWHTGkEIYhMZ6Rvm2ysbZbBRtUdAvVkJ5zUWuX1TKuNt9gPj
         eSOPSAy51m/kPJSEc+1a/5tuYweakI01lUcGkPlhES6cElHG33ktcfR2qoA9HfohW1e3
         uMA8smgV9hA33OOe7NJU2FuTSVXSo3HKkmf4fmE6DGVDxNkKEoQoV9GpEFS+n4CAVxur
         t7JoMNJSPoa3b4M8ThcMP+KKk0ImukxxO7C91ga/uXE0fBVXoAODsUIlLo+ndc6Dytw4
         t8JRtuSTZ7ZKWjfHO6nO/xA0wizuCX1+fJf/QsrmXIICC53rf8U9hP+OiuiRadOqqjmA
         Dpig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=SLCCn59yF2lHkFGeGMH+08+03NCTJUCMcNIxKKCI3fs=;
        b=Aj4n6Oh9o7KshHkFK7dscDn88DId1JbVS7NpDdeulXdgvjWeDE/BCw6fTD5NSwpJnM
         3srdeNl4aNkpMhmcY/gp0q68nzcfZSnDrJHF8zThdHX33gTeAEMi1JlHWoJqjGzxZ2fA
         mpUSv9jJV4/iQBJBFxJ+Ocjf0vEPXpf5NC6b0JqaYBps0V7cSc3UhF9OrmiANNy4z4DY
         okm1AhAzsWDt3G57h3qECsCYs+5qXEaCwExA3htFBKnA6x6MckO2FZIdwedsVMtSRBLa
         K4y48W5+VA3nmF+/BuK9iP9+VGKmJNqQ103o7pMZZ/3JKhYHdiNuu1OEElWSUQaKipg3
         rO0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i17si12104qko.4.2021.03.05.04.05.28
        for <kasan-dev@googlegroups.com>;
        Fri, 05 Mar 2021 04:05:28 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6F22531B;
	Fri,  5 Mar 2021 04:05:27 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.47.91])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B046D3F766;
	Fri,  5 Mar 2021 04:05:24 -0800 (PST)
Date: Fri, 5 Mar 2021 12:04:53 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	LKML <linux-kernel@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	broonie@kernel.org, linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
Message-ID: <20210305120453.GA74705@C02TD0UTHF1T.local>
References: <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu>
 <YD+o5QkCZN97mH8/@elver.google.com>
 <20210304145730.GC54534@C02TD0UTHF1T.local>
 <CANpmjNOSpFbbDaH9hNucXrpzG=HpsoQpk5w-24x8sU_G-6cz0Q@mail.gmail.com>
 <20210304165923.GA60457@C02TD0UTHF1T.local>
 <YEEYDSJeLPvqRAHZ@elver.google.com>
 <20210304180154.GD60457@C02TD0UTHF1T.local>
 <CANpmjNOZWuhqXATDjH3F=DMbpg2xOy0XppVJ+Wv2XjFh_crJJg@mail.gmail.com>
 <20210304185148.GE60457@C02TD0UTHF1T.local>
 <CANpmjNMQNWBtWS7O_aaCfbMWvQUnzWTPXoxgD8DzqNzKfL_2Dg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMQNWBtWS7O_aaCfbMWvQUnzWTPXoxgD8DzqNzKfL_2Dg@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Mar 04, 2021 at 08:01:29PM +0100, Marco Elver wrote:
> On Thu, 4 Mar 2021 at 19:51, Mark Rutland <mark.rutland@arm.com> wrote:
> > On Thu, Mar 04, 2021 at 07:22:53PM +0100, Marco Elver wrote:

> > > I was having this problem with KCSAN, where the compiler would
> > > tail-call-optimize __tsan_X instrumentation.
> >
> > Those are compiler-generated calls, right? When those are generated the
> > compilation unit (and whatever it has included) might not have provided
> > a prototype anyway, and the compiler has special knowledge of the
> > functions, so it feels like the compiler would need to inhibit TCO here
> > for this to be robust. For their intended usage subjecting them to TCO
> > doesn't seem to make sense AFAICT.
> >
> > I suspect that compilers have some way of handling that; otherwise I'd
> > expect to have heard stories of mcount/fentry calls getting TCO'd and
> > causing problems. So maybe there's an easy fix there?
> 
> I agree, the compiler builtins should be handled by the compiler
> directly, perhaps that was a bad example. But we also have "explicit
> instrumentation", e.g. everything that's in <linux/instrumented.h>.

True -- I agree for those we want similar, and can see a case for a
no-tco-calls-to-me attribute on functions as with noreturn.

Maybe for now it's worth adding prevent_tail_call_optimization() to the
instrument_*() call wrappers in <linux/instrumented.h>? As those are
__always_inline, that should keep the function they get inlined in
around. Though we probably want to see if we can replace the mb() in
prevent_tail_call_optimization() with something that doesn't require a
real CPU barrier.

[...]

> > I reckon for basically any instrumentation we don't want calls to be
> > TCO'd, though I'm not immediately sure of cases beyond sanitizers and
> > mcount/fentry.
> 
> Thinking about this more, I think it's all debugging tools. E.g.
> lockdep, if you lock/unlock at the end of a function, you might tail
> call into lockdep. If the compiler applies TCO, and lockdep determines
> there's a bug and then shows a trace, you'll have no idea where the
> actual bug is. The kernel has lots of debugging facilities that add
> instrumentation in this way. So perhaps it's a general debugging-tool
> problem (rather than just sanitizers).

This makes sense to me.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210305120453.GA74705%40C02TD0UTHF1T.local.
