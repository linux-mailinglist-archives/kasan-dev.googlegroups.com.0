Return-Path: <kasan-dev+bncBDQ27FVWWUFRBWEO47UQKGQEPGKJFLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D26475245
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 17:14:34 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id x22sf13494672vsj.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 08:14:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564067673; cv=pass;
        d=google.com; s=arc-20160816;
        b=pp6tyK+4vHVSvzJVTmuRcyMlTxEeRAtb8ny5J8s2Gb9ajaKqyGlc0Yavd7tsL725KS
         /sF/Ab8DWAYcGp4iF0SkXmxEnkefdAJqKHO3Q/1pCAVXqcyZz2rLiU7d5JFhKUfnCaHz
         6g8QA8B89qYpL4c45Clbr5+/gcKnNzc2T8XG7AwBOIsObCzSU+9pFWw76MtsfgIxMM9R
         9LMfekr/AwewwkWQroNj1yerQEkGR8jKuBTMITidp4atggCt8wx0bCjMg+15e+F6Czq5
         39WzCU8hDFrnNw/DrUswSw9tyY3zDWEoAJ8Fx089DxvggN/p/OpZlt6myM7mE4YSlahd
         5ePw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=Z1kUu2wgzyRZ4x+6C+u62wGA1L6q59VtMhIdq2GP4Qs=;
        b=YpxNpzSjAn9cWtSsaIaE0sKPoG6lSxXr+uGwyy7qtEw/AXOa6+7YONv5ybdJvKB2vY
         j7alkWgCB+GzMmwhpywAShUF5XjjV3e33ynLMVtXpJeXWBxLrsYMps21rIrFqpul+ld2
         0ZKFeFMwxsbpxJgKqrQoYKs1crdhNN1pGasrCE714tPl8rKpjNJdDvf6td1opuGX3rFb
         pHp9gnSR22Exu7chgXAgRWjKJZ9japt55B4etl7da/BQo033mYa7rX3UkCQtrVkHs7up
         3R/b3e66i/T+vj9T5tac1/jMQCFwJQy3TiULJ2cIb3n4AHEycS4SbazKvr3JhtXydW9A
         yCwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=mj5vl9gl;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z1kUu2wgzyRZ4x+6C+u62wGA1L6q59VtMhIdq2GP4Qs=;
        b=ontC81FBN2/pK65Li+8WrbuFDgfx1Y2yzqgawhsYk7yfnJMRlwUhU0qfxm9yBb9rFS
         uBK0tpTyGuljwHpAjmHdyLTLuU9oBy0eoIlQtv0PRCLYiJfHWV3nrLbk1brXdji6y1OU
         lkmBeneKf/2GudkikPk4ORGV9cM2ys+DlYteIc6B8o8Q/jR6tj9RTd8IeBRYYxvza3rR
         slbp0JoDjx1wezuMbSNZDdN3OtSXvlUwAnSZIkHhopJNvNi802T/M3kZFd+p8Mk3gwh3
         ll0YMsP+Th8Jr90ovc96T9kikjpDwF+Mg0vQjhF/0cUNgHyrBGb3tPpHF8bmzA9g/cgx
         A31g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z1kUu2wgzyRZ4x+6C+u62wGA1L6q59VtMhIdq2GP4Qs=;
        b=HEdrGeYmCaKb6+QA6h+RyuUxqSQ+q5ehVZS9ZNY3BNX4rvqxnTJ4OkshN0HIeL/FPQ
         7naN9C3Mr/vGMxDjuHKC57UG6o0nWzmg0M8BYCofb1BqX/JnSJK6DzeL3gs4Rv9Th2Y9
         2MbZXZugy7RatWU0iZwr3Agda7olcN5EyxqjS60icI5/9FqSbBQ0cJsldjAO5yjmdPym
         v0WW0vCYHCj1SLAzD099O5x7iXfsCIEuu8vVSMubI0y26gHmiS2ZpB67qnW40pd6MBe3
         cBmD2bKiO0KOLTG2CDHdNsb62/bRo8WyBtOsdT8oRScV6C6pmVGTtZHVIYFxjypkYyRT
         B0Jw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVedMzzdKYOqpybRL9g78UQ562Hdee461PbnOpBIVxLsFGLW4Lt
	CR5PZQUx7/qwBn0ATQX8aHU=
X-Google-Smtp-Source: APXvYqzq9UzEUCOt6sLldW0U+kj9c3IMnnOHmKYG0Q50ATs7A++Ugm0rhftHCeLzvUwC50TrQLjO3g==
X-Received: by 2002:a67:89c7:: with SMTP id l190mr56416474vsd.13.1564067672969;
        Thu, 25 Jul 2019 08:14:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7282:: with SMTP id w2ls3779869uao.9.gmail; Thu, 25 Jul
 2019 08:14:32 -0700 (PDT)
X-Received: by 2002:a9f:3f4d:: with SMTP id i13mr10488920uaj.54.1564067672733;
        Thu, 25 Jul 2019 08:14:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564067672; cv=none;
        d=google.com; s=arc-20160816;
        b=VdrRKnXHE1lzSsBbxj6iZaSeujQt5VJcfpox6n/yJnFnYDVz2FsD/puGDqUFLPXhQN
         HjcO17GDuGewLPscVUK3Rkly6r2dOO7HxEpz3xVcXaOSxOESdBssQdcXVNUirYzBuSMI
         OBxlqWDzgZuKVXXpKveWCFx7dwr0tILK44ROVNonBuvi9aBfdi+r2zvTtUd/Hsp12Qmy
         pNOt/C630R4s1gzNUMfuKsSI5Byh1tv43zg2t6CrKO9ZFaxLUJfkmwCz9Rdrc0K39Q9D
         XFSvJc8XORm7rHQdKHjnA5wHrI8vjIfaE/7f/q/fjiY1Zy4knLVRz4yvJorxH1GTIsX8
         hzCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=ukHOzhV4OjQKdS86FY0h+hNCicHoI0651/0C0J3cWEA=;
        b=0SY/5ZjpQ4eQboO7nP+slah6Gy0GlYMkC9OZ7vaUBuzlr6EQhmaXctHLZ0CPbmwRuH
         ECMIrV+eJLPbo650W1e0zQfNhQvsi8T7eT9bEswLfDKGpGhBSfTj0ORFR0kE4/TipIDX
         DIkLEo5LYOYBNgg6CdvyJEF7RNn2R/6N0krW1WoYzn/HhMdkpjzz2B3vvgS6zl5T7NP7
         LgROTTnKBnC4Z8UqyIOhiyOnNTkt2lc0NEAu/uP9nvSgx7V28j6Z6D8iIq5noDRYw+LE
         aeSuS6DNU2D+YviNUitE+w68eRtR7AlIB6FCuix5XIV9MceS4w/Wh3UsqXH3WoPL9T29
         uQaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=mj5vl9gl;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id b15si1832462uap.1.2019.07.25.08.14.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Jul 2019 08:14:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id r7so22922163pfl.3
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2019 08:14:32 -0700 (PDT)
X-Received: by 2002:a62:ab18:: with SMTP id p24mr17273516pff.113.1564067672245;
        Thu, 25 Jul 2019 08:14:32 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id 195sm87695944pfu.75.2019.07.25.08.14.30
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Thu, 25 Jul 2019 08:14:31 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, Peter Zijlstra <peterz@infradead.org>, the arch/x86 maintainers <x86@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 1/2] kernel/fork: Add support for stack-end guard page
In-Reply-To: <20190725101458.GC14347@lakrids.cambridge.arm.com>
References: <20190719132818.40258-1-elver@google.com> <20190723164115.GB56959@lakrids.cambridge.arm.com> <CACT4Y+Y47_030eX-JiE1hFCyP5RiuTCSLZNKpTjuHwA5jQJ3+w@mail.gmail.com> <20190724112101.GB2624@lakrids.cambridge.arm.com> <CACT4Y+Zai+4VwNXS_a417M2m0DbtNhjTVdYga178ZDkvNnP4CQ@mail.gmail.com> <20190725101458.GC14347@lakrids.cambridge.arm.com>
Date: Fri, 26 Jul 2019 01:14:26 +1000
Message-ID: <87r26egn8t.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=mj5vl9gl;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Mark Rutland <mark.rutland@arm.com> writes:

> On Thu, Jul 25, 2019 at 09:53:08AM +0200, Dmitry Vyukov wrote:
>> On Wed, Jul 24, 2019 at 1:21 PM Mark Rutland <mark.rutland@arm.com> wrote:
>> >
>> > On Wed, Jul 24, 2019 at 11:11:49AM +0200, Dmitry Vyukov wrote:
>> > > On Tue, Jul 23, 2019 at 6:41 PM Mark Rutland <mark.rutland@arm.com> wrote:
>> > > >
>> > > > On Fri, Jul 19, 2019 at 03:28:17PM +0200, Marco Elver wrote:
>> > > > > Enabling STACK_GUARD_PAGE helps catching kernel stack overflows immediately
>> > > > > rather than causing difficult-to-diagnose corruption. Note that, unlike
>> > > > > virtually-mapped kernel stacks, this will effectively waste an entire page of
>> > > > > memory; however, this feature may provide extra protection in cases that cannot
>> > > > > use virtually-mapped kernel stacks, at the cost of a page.
>> > > > >
>> > > > > The motivation for this patch is that KASAN cannot use virtually-mapped kernel
>> > > > > stacks to detect stack overflows. An alternative would be implementing support
>> > > > > for vmapped stacks in KASAN, but would add significant extra complexity.
>> > > >
>> > > > Do we have an idea as to how much additional complexity?
>> > >
>> > > We would need to map/unmap shadow for vmalloc region on stack
>> > > allocation/deallocation. We may need to track shadow pages that cover
>> > > both stack and an unused memory, or 2 different stacks, which are
>> > > mapped/unmapped at different times. This may have some concurrency
>> > > concerns.  Not sure what about page tables for other CPU, I've seen
>> > > some code that updates pages tables for vmalloc region lazily on page
>> > > faults. Not sure what about TLBs. Probably also some problems that I
>> > > can't thought about now.
>> >
>> > Ok. So this looks big, we this hasn't been prototyped, so we don't have
>> > a concrete idea. I agree that concurrency is likely to be painful. :)
>
>> FTR, Daniel just mailed:
>> 
>> [PATCH 0/3] kasan: support backing vmalloc space with real shadow memory
>> https://groups.google.com/forum/#!topic/kasan-dev/YuwLGJYPB4I
>> Which presumably will supersede this.
>
> Neat!
>
> I'll try to follow that, (and thanks for the Cc there), but I'm not on
> any of the lists it went to. IMO it would be nice if subsequent versions
> would be Cc'd to LKML, if that's possible. :)

Will do - apologies for the oversight.

Regards,
Daniel

> Thanks,
> Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87r26egn8t.fsf%40dja-thinkpad.axtens.net.
