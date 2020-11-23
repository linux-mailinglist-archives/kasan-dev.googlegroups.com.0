Return-Path: <kasan-dev+bncBDV37XP3XYDRBY446D6QKGQE66DPJLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5920D2C1480
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 20:32:52 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id w12sf3808152oth.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 11:32:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606159971; cv=pass;
        d=google.com; s=arc-20160816;
        b=hVxB47+wDP8uuVOeBs73DXaC9KzfjiLODdbwBXelJgwKHumgTGy2BHV3W1nB44CFBt
         eQ0J3veui6KEYRGwLqxb2JhZPJWZ9NovCNgMZ22KuwNt2caXfvAS8MU1wEbHDEReOcHj
         KsKzCRy6hkfS7Pgcyxw4rrdqi0Iq0Ylhfb1yjgF2R+1s2+h7KIKGMPG7Z7gCn20YI9dj
         y/v/R89BWYQJvBFipAdTeYdID0693kDdeKK10NyrYpfoPmgTfjzyE43Tf1f3SfxBhGJI
         cggHQwz/dC7YMSXdEvZSIOePQCPgtqq1O/1sjJ3xJimVRZY42ZIIYHnRenboXU1wVdzR
         L+IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=E+H2tAKGO/R7qKVjcoFtaDN/1ZHX0jRGCNp5JPY9mCw=;
        b=kyhzum/FP1oj1J4qhn12fmm+sYw99KKa/JzbcfAy1j2hn3ivUAqPzDWGqO698Qdmfw
         +EcK1okdOO54N9PsX/TOj9mo2yCRx1S3nluqAFJeGpXwK/FMeexKU4A0LmyMWGNjWdvf
         TWhfGF60LkSJnck2YgK/3bbjePpObkOhfh5uJkeP8SUdqrYJFPLuLOOyfqKoFGzPJ/Wv
         GrPWW4MVaUvw1mmQiatd0PDfSmZ5gNN0i7BEuZkTQUwMnIu2Xs/G21WI2gXadcySUpPr
         JR+2sOhHxYWWHgUQEW+MpVEE31zrakoYbyErHx14dP/bq0hEDf07BUcy2YQjV7w3RvSp
         8xIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=E+H2tAKGO/R7qKVjcoFtaDN/1ZHX0jRGCNp5JPY9mCw=;
        b=n4Tos0IM5uDeniqF8jj/PIQ+is535BPxbEmm0ermFeGp/dSGy/B0luE/r/p4ntRy/w
         1nrJDMMI7poVqDk6cJ8lBI3zny8rrsWQy3EwZVLRDdHaNJ80zRM1IL0oZ2dgIl70lv+L
         UxXnCro00yx848F8GyptG7RDdbjozKmWNQIpcogk+wSyOdT938u9lJuN5CeSdT80n8qq
         yEeeC/L8G6aQMrcNHSTWhdctgNqSzMDRwkkio7yhejxfpZWkaFNEBpUyn0K4qZzEPhV4
         vkWZja8VcUV5999GfCW4aayDO6/o4/bzhOlJYZNTPubJx4wS8XhO8+jdLyHO27sDwdoo
         +s8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=E+H2tAKGO/R7qKVjcoFtaDN/1ZHX0jRGCNp5JPY9mCw=;
        b=P3BhVxTX/CO5lL5wXk8dIrce9Z6un5xhBMcZkUdjfgPPlbl9AtVve9ctpZIQVp1liu
         eadtm8hQeelGYFUVtmW6F57r+G1hGafegyHq80V7qT5TzpQzauxWuzhUBGDglWwOW7Aj
         08v1QgvKjLBKMVWMZAAwnYDVSbHv/VbirIjeNDm9+FyxSnLyb8Yv+wmOmk8JTqCiyx0W
         HaRm3EaqizxDXEX0Jbk+FOmuoAzA1dLOIbgQCapOVzKT/DdRrDkjDYz0rDe0j7J4d8Lq
         9s/s6btYdoUuOUd7JRaDCr65sJ6iPGr5aH5wteurxEuAUbEL5kNNQgUHnf7n5Dlg2aUX
         V/vQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531NgyBnD79n4CjNITbzL7+P9lDj/59qfQUo4AO4aayWeBlKyrME
	Nz0NdmvlAYxS5VIlFBpVmy0=
X-Google-Smtp-Source: ABdhPJwapsr80uKpMfCkVUBZ0x/8HoOY+W2KOS/++9xeUB5U6I9uBcnfx7JZx0clYrZTQqcnTnQQFQ==
X-Received: by 2002:a9d:2ac3:: with SMTP id e61mr640945otb.252.1606159971225;
        Mon, 23 Nov 2020 11:32:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:39c9:: with SMTP id y67ls1015825otb.7.gmail; Mon, 23 Nov
 2020 11:32:50 -0800 (PST)
X-Received: by 2002:a9d:851:: with SMTP id 75mr755931oty.102.1606159970877;
        Mon, 23 Nov 2020 11:32:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606159970; cv=none;
        d=google.com; s=arc-20160816;
        b=XgC5pFTIuyY2gniEqlEaMpt6l+1FrTbHxlSXWK7gHuULw2azwdZPE1gGzRI7oJ1wqM
         oLqAl8dnAIWjU9qXC9KoAEN+W/ropG9ZK0CG/c3tApEqMB/nB5g2abOCSzZId2nnK7hw
         7vw67dF63zbK4lTazIbeDMYQ6ptTBcBSWhuQfoFa/AbvfczT4Ffx98VuNiS2AoI+BwSh
         L8XzhaVTJqviE0lcaeSnCvXbQjmyTAbRCE9KwTqUSwX0DCzwM52rETdLMDcqpuPKSJHc
         LSQaBRV+wnoVlWSfWsvkmz9Km0HHbprVPZ3eikyNrZtD3G8ZO8u8cBYlW4f5lef6RPIC
         5kXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=/oxcQlFvwWpMO7fHpsQkvXcJ00SFmanYy3+AbiRDOhQ=;
        b=rcXFFsO9+7dx4lUY5tij/SpiEK1saUnusJiPUI64FnQ86cy4hWj9PL+ofFDnw1dJ1g
         BkxXnjbCtZb1XGD4doTM/IyV0DbkTJ73bhPckCRLDfAVfup+pcVYVMlrUCjXOsnCQw28
         NwlpMU+w3mhDNE1ihhA6Srjsd1o/gvXpOCkWMR3HA+k4vBXl8ZFOaQ5SDiRHETzOlmTA
         92h78dkzLwdexFON/VFlPFg5LGMQgJJtRNXks8U99s22XMfgKinwXFbk+KLOAmcEd7q3
         fsZdkms4jEIzAUW2I1SuZwrKTD+kkq/YcC63gNUGaoGA2uPU/e1kwRd9/eUeP3+iIirc
         We5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f20si330370oov.1.2020.11.23.11.32.50
        for <kasan-dev@googlegroups.com>;
        Mon, 23 Nov 2020 11:32:50 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 97DE4101E;
	Mon, 23 Nov 2020 11:32:50 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.27.26])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id DDCC93F71F;
	Mon, 23 Nov 2020 11:32:46 -0800 (PST)
Date: Mon, 23 Nov 2020 19:32:41 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	linux-arm-kernel@lists.infradead.org
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201123193241.GA45639@C02TD0UTHF1T.local>
References: <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201119225352.GA5251@willie-the-truck>
 <20201120103031.GB2328@C02TD0UTHF1T.local>
 <20201120140332.GA3120165@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201120140332.GA3120165@elver.google.com>
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

On Fri, Nov 20, 2020 at 03:03:32PM +0100, Marco Elver wrote:
> On Fri, Nov 20, 2020 at 10:30AM +0000, Mark Rutland wrote:
> > On Thu, Nov 19, 2020 at 10:53:53PM +0000, Will Deacon wrote:
> > > FWIW, arm64 is known broken wrt lockdep and irq tracing atm. Mark has been
> > > looking at that and I think he is close to having something workable.
> > > 
> > > Mark -- is there anything Marco and Paul can try out?
> > 
> > I initially traced some issues back to commit:
> > 
> >   044d0d6de9f50192 ("lockdep: Only trace IRQ edges")
> > 
> > ... and that change of semantic could cause us to miss edges in some
> > cases, but IIUC mostly where we haven't done the right thing in
> > exception entry/return.
> > 
> > I don't think my patches address this case yet, but my WIP (currently
> > just fixing user<->kernel transitions) is at:
> > 
> > https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/log/?h=arm64/irq-fixes
> > 
> > I'm looking into the kernel<->kernel transitions now, and I know that we
> > mess up RCU management for a small window around arch_cpu_idle, but it's
> > not immediately clear to me if either of those cases could cause this
> > report.
> 
> Thank you -- I tried your irq-fixes, however that didn't seem to fix the
> problem (still get warnings and then a panic). :-/

I've just updated that branch with a new version which I hope covers
kernel<->kernel transitions too. If you get a chance, would you mind
giving that a spin?

The HEAD commit should be:

  a51334f033f8ee88 ("HACK: check IRQ tracing has RCU watching")

Otherwise, I intend to clean that up and post it tomorrow (without the
additional debug hacks). I've thrown my local Syzkaller instance at it
in the mean time (and if I get the chance tomrrow I'll try to get
rcutorture setup), and the only report I'm seeing so far looks genuine:

| BUG: sleeping function called from invalid context in sta_info_move_state

... as that was reported on x86 too, per:

https://syzkaller.appspot.com/bug?id=6c7899acf008be2ddcddb46a2567c2153193632a

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201123193241.GA45639%40C02TD0UTHF1T.local.
