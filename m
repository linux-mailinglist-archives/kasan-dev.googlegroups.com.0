Return-Path: <kasan-dev+bncBDV37XP3XYDRBLH74DUQKGQEMHQY5WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id B09E472D5B
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2019 13:23:24 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id y127sf10632468wmd.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2019 04:23:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563967404; cv=pass;
        d=google.com; s=arc-20160816;
        b=G62weo1zI7wIvr+lKxNMpljzTnNyWCH4ws1qnvMIt6Ud8pUWOVRBGY0XyW7eOv5tSZ
         /pRJ6avcu3gkeqSNEgNFZLK3QRBZqoaDYxo1IhtJIEeG8FVnrIeLUGdXNVzBpbHU4ZVK
         znN54VgQvPKgyZr0OWJRDPrtemJeBx3n0B6ufTuMIc0D5jasMnvTM4iddCtSgQbzn3pM
         Yox5qkGMJyUem0toLCcuHkviiIyZ6+s4zTVwuXoTITRBhZMOAIbCYL1YMndQpHORHptP
         E5LXk7V9crI6gZqZhzRmUt7zDNLI2EAxtTeRADWKFWY1fvyYQNmyJxEOCwQkarjOFThY
         DmAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=nA2L1HMmIhjPDRTiB34E0n43qfjS5cWw21aGCx3Exno=;
        b=ZIvhrz4fFBkfcWQd3vH19HU517lLqKoOpVjVwjXMt5tTvVBOHC28RtEXMo17xb96Go
         Q/LEwpiBd33WUcyfoCEmGH95nDRip09lKAsJ/RKggeYwdjEyJAppOt5qEeqDYEoBCGtd
         B/YA2/ulwD3SNoV7O8W6OROukMWwC90KlgLgemBzX8E5bd3eQB46KO/8+jfA54LGiNYh
         7Y18lZO0BqJDbMoXoWJF8fIEFwHVSjIj2qU65zcxm8T73baT9XSi9Eo3Jn/LE4pRgv4R
         E2JaxEqBiU368HmyHIOXHVg+mo3BUSXqJlJSKXEwO9bkLOd1tYnm/6kw9Owl+OvmROQP
         mBZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nA2L1HMmIhjPDRTiB34E0n43qfjS5cWw21aGCx3Exno=;
        b=D7lw2y5w4KsG3pnJGtKzpWRimjP6BZ958ef2vM2XCqGarZIVxr2+NgLlbzH9aK+yfS
         QQMi9pq06l64WdS49HUC+1+ep66g0DceE6PZx+d9GTjw/FZ6TV2g/WYOQ7hcbRfcS3e4
         H/AyAzRh3LSsoeNDWyUWZ1fPq0x4rzLeMVzbA62ozXvbC2Kk/1EE46olghrvzisrV1vI
         RYe66EEAZd/1yp2jymx79MNy2XhUcB3YMqLfg1SnX/d3+8NbdbCS05JZQFxdzTpJRYwY
         MsvzBEnmCUXNNOUJn7ZTa/FokWM3wSURyXeBXZErN/XTNGso69YehXRJod61W1Cqb0fE
         OjdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nA2L1HMmIhjPDRTiB34E0n43qfjS5cWw21aGCx3Exno=;
        b=KHdNOGG4WZTEferhYtzwiNao1oc4cycQqsUbmvuSJ4Tf/eolRgTHEXveRS+oMyxC0n
         Lda4jECul4DSLajiN2Bts38XBEfKA6zTSGAVzgg9jVjccqsrhrU2fwdicLW5CTWcVojO
         1yuT6DILKP7tqPZIpa38LoogfgNt8YZiUTqhoC6veKuybG+BzQvpf3Icj3vnWzQiFOmM
         k0ELxHlXU6P9lLTVVELzznS+fiIxePXJDwAH0ZaX/PrWYo7ZSVBUizy04rC0jkTOTzs2
         77XjPy+4n12f3ulG7PnEQOWsfUbe4ETEGCzIhwvDzvtC5o5OHURvIWxXOKj1ersvnCV+
         KOMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXIINqIoPodLvE9AFENdWrAmdhPF7XT/CBwNgc8KmGbn3OOjf/h
	rtTM4oeSmq0f8bIOh/mddbU=
X-Google-Smtp-Source: APXvYqy5Xq9j3kB/DivoPE1AIpf2X7lFn7H+ohmoCyYDj/N+WvSb/o/DS/dTDgSIavVx7wdpXd5RnA==
X-Received: by 2002:a05:600c:2056:: with SMTP id p22mr2031106wmg.155.1563967404433;
        Wed, 24 Jul 2019 04:23:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a2cd:: with SMTP id t13ls13745262wra.8.gmail; Wed, 24
 Jul 2019 04:23:23 -0700 (PDT)
X-Received: by 2002:adf:e6c5:: with SMTP id y5mr91454036wrm.235.1563967403902;
        Wed, 24 Jul 2019 04:23:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563967403; cv=none;
        d=google.com; s=arc-20160816;
        b=QVMlxxS0wvb9czmjhoUpYrjjh7hxqzRIgxwWhxQX2hEn9dgDeTplxuIYTrffoEqj95
         qkliTOsR+mXru2L0SWqpG+uSFWw6s3yQHVZ7lmpr/bjpxx3sdx4D0gGlLuf6IUu5SeS1
         C9S5+W1iNCrK+LL3JvAuOJCBayC4Zm7rvVen7tbEve52QxCNU25aEDdovjm3D9MvHrFs
         jF7paNCs723FbNYpXQ9DzrXxkxlYK+8wdjf3VgCf0tmfGkWYO0LTKN+Jg4pC20WqWd9a
         PWSfcX4bneFQ7SHqFrJnMPw0vGiS7DxkwSfYn6mCh33uW75B04ztsQoh0sTaoRKM8oI2
         lRCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=pA/QbGG5emYrgtlKOSirjwbDA4VTCh+pBSNZ0yF96nQ=;
        b=A+HLIlByt7YhCiPjR0aEkK5P84CxTVXs5kgpOeu6370wM9UknkMCRJkoxCNl5Xn/iA
         /lDqgMPYaNWM/vYN0df/TUrTMx4KwC41XWbXS+lTR+fpKR7hqMBe17ZGhvoiyBDLGfSn
         FRJyjsdTf7n3/InSnOZvh3Um3l2Ffgc9z/KOAGwNC9+U/hMRPeLwrQSGe5oGYIGD0/W3
         NS2rIeCIAehnlac31QvKCOeUeQ1NA4ga6RpQBN/QZ8N4GS7Tknw5wT9mCWTDDL48AaGX
         DG8l7C4fo+DB3fCXaA9IC9iTtJinlR8oPaAOrwLkhfq+4CHlFXMUAa2KxgfBoOKb0gd4
         mDEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f13si2528651wmc.3.2019.07.24.04.23.23
        for <kasan-dev@googlegroups.com>;
        Wed, 24 Jul 2019 04:23:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 286A0337;
	Wed, 24 Jul 2019 04:23:23 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 72B4C3F71A;
	Wed, 24 Jul 2019 04:23:21 -0700 (PDT)
Date: Wed, 24 Jul 2019 12:23:19 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 2/2] lib/test_kasan: Add stack overflow test
Message-ID: <20190724112318.GC2624@lakrids.cambridge.arm.com>
References: <20190719132818.40258-1-elver@google.com>
 <20190719132818.40258-2-elver@google.com>
 <20190723162403.GA56959@lakrids.cambridge.arm.com>
 <CANpmjNPBNUQXoPUNw46=iieH3SS1Pk8PxNvQ1FPdNCoU4g8F2w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPBNUQXoPUNw46=iieH3SS1Pk8PxNvQ1FPdNCoU4g8F2w@mail.gmail.com>
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

On Tue, Jul 23, 2019 at 06:49:03PM +0200, Marco Elver wrote:
> On Tue, 23 Jul 2019 at 18:24, Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > On Fri, Jul 19, 2019 at 03:28:18PM +0200, Marco Elver wrote:
> > > Adds a simple stack overflow test, to check the error being reported on
> > > an overflow. Without CONFIG_STACK_GUARD_PAGE, the result is typically
> > > some seemingly unrelated KASAN error message due to accessing random
> > > other memory.
> >
> > Can't we use the LKDTM_EXHAUST_STACK case to check this?
> >
> > I was also under the impression that the other KASAN self-tests weren't
> > fatal, and IIUC this will kill the kernel.
> >
> > Given that, and given this is testing non-KASAN functionality, I'm not
> > sure it makes sense to bundle this with the KASAN tests.
> 
> Thanks for pointing out LKDTM_EXHAUST_STACK.
> 
> This patch can be dropped!

Cool; it's always nice to find the work has already been done! :)

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190724112318.GC2624%40lakrids.cambridge.arm.com.
