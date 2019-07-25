Return-Path: <kasan-dev+bncBDV37XP3XYDRBSEA43UQKGQEYKSKDQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F14C74B3B
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 12:11:20 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id h8sf23725645wrb.11
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 03:11:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564049480; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zbm2c6M715r/bynPJ8ENijs3odxGY+Yu/yn1m0v9m8C7ysjPPznhWMfS+LB/C6mHCx
         Le5s1ilj5zGQwZIYoeuOnYLXDwqlGSGv2+Z7oELyKG9F9kQVg904xwG7s+9/LBxzJTLs
         awcafkAwSzL8wYE/rdWCZAJeB7/dUYjI/bO/Txt4J3YQWi7mI4foYPnTlmXo40DZBJ32
         jehyDvXA6/MkmWWMajWv3BxTNZw0IBU8rxTkjTr3cnGCOyR6IwbhE61q38NhtFSddRs5
         7CDALaAQa3u3GNAj56jSXDSTZ65z4Nvrz/BxLk5PiPp7yPhqaMeaTabYVlBVL0LWoge8
         4Kgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=zjRPSjxMwsvYe2mscNPlKKKQoX7synke8nH704Mh2+4=;
        b=wjldkp+RmxEW1YHAp/Ntw7RycxTe51YbBNjc44R0pf8FixCMV3F3va2EAZCThSFVzF
         Y6Lq0uF9t42oZz5D6oCX+SlgrOVa+SXo13CwfSY+icmxNLAVdzEeRdMlNZmEKIzq3FiL
         8B2Z2IplicJlsS7F5iPw9rwo5yKlCTGjoYKPoJQzDdMgaLRm7KhkAB4zvcqKNeDz6Udu
         My7yRc64+t6vniYBbecvQsKN7DvZYvJUb7bjvmh8B03W4492qnm+FrwZTe6xaTlNtZsT
         NPgNmrcfqiDSkbb5dRLg28HFYMEtVO8v8/Y/kC4HRJJqcQPOaK4MUg3OQZeOHYzYt9ZW
         81tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zjRPSjxMwsvYe2mscNPlKKKQoX7synke8nH704Mh2+4=;
        b=ohBsJRa5muRiq5neN178UnEt6YJE27FXJ65lUirs+JDVhlSkQHflwdjEGoS1R5RIfc
         XEpXITl3kqDD+DlERsxPqIXHD1HgFZ3p6rgHmc9PlB9NxCeltBZBIE+M7wMYfSWr86gf
         2m6j2tIphEFeLOYBv/GLR+ktbsCf/ZPRp3iNWhRY0bzbwmFZ6cYW04v/jQzIj9p6/NKi
         V3Qk+YpcjXYSDubscfhRNh9sZr3Pd9izeSWLVwYjPfreiuq+8zS5ftyZFppBPW8LCw8m
         xjZcDMWIySpVuUPmjXtccx9Rbcvg9opxN6ICluQZRJNUGfmfJrlhQp5WLu+0goe9dwa3
         im9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zjRPSjxMwsvYe2mscNPlKKKQoX7synke8nH704Mh2+4=;
        b=mU86QUkxXqvP+YCIa1p5Ctiqd9gusWiWgwTc12RtLvxGmD3R5oRtelyJH5pY8NR3u2
         wJbcWmR0Uegy7eiPF8vauhQmXIp2abyKRVq7PjoVuYA9kwxsrkNMMRMJEfQiMJJN1cBl
         dzzjHm8yHlbXuiY9qKBcEPVInVz2W4t3WiZZ8b4nWpJWZREikQO7gBGxBJVKyy8WrQZ8
         ObbzHRDh6R5zwBRrybbVBxq2zEtSpIkQhptLIPeXflMQDgXMhFSKdQT+9i+3sD0kzO/A
         Co8U9RXu0aQP5i1QpzeZP+G8+xO0Eh9EqnBxjG1Y7yNA0LTMsldU1vxZDPOW3+1Y/cpu
         c3XA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVV83ghRG2K98axD+IAouBHPNsjMpC6qHPfiHc1Y9KnASI04vWI
	aScoG1asjPEQYLgqas0Xntc=
X-Google-Smtp-Source: APXvYqzbfqfVEf2IhLmsB1TQuB1CDB+dIQjZPr83PvejQAf96r1lrBCij5xdeWlNr+6bhFpfVeXehA==
X-Received: by 2002:adf:fdcc:: with SMTP id i12mr13909337wrs.88.1564049480344;
        Thu, 25 Jul 2019 03:11:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:5411:: with SMTP id i17ls17521449wmb.2.canary-gmail;
 Thu, 25 Jul 2019 03:11:19 -0700 (PDT)
X-Received: by 2002:a1c:480a:: with SMTP id v10mr78458127wma.120.1564049479308;
        Thu, 25 Jul 2019 03:11:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564049479; cv=none;
        d=google.com; s=arc-20160816;
        b=SCBo+tR8cWen7XTfAkF/ke/SP1+4fS6XwTRevY0xHHO0eJVzz9fQWQHBxjUk5ewJH4
         Dftg/4oPuaSjie67fwzReAUhjuzsPQcf7F1Ir5kpxaVDTWQoSi0b3kfEWHIQp6RFDDS9
         AfFWUBQaF4a5cY0jkGaiWlJPN4zFI2nnC4XzV/Cae5lO1vnQUTLg9cpmTj+qUUj3nr9l
         ZOhqpwka7mVyyFIb59Lk9lZtPsFh60Ig/VFGnI+3Ma8peASi58ty6GAUzQVUnBR7IssR
         U9IUOkUY2Dyr37YurIAObAzWbhOFe0SSBfBl9xj1jWPZqq06wfPDmNdfdg1Pay4p+BkF
         1GcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=u7tKf+2NnKOmU/uZV2Hb861aUCGvvOIpkxVrUNbnFHc=;
        b=swK8U+TP9MNlfm0yif52ypn36FXHjUEVnB2qHjQ3xxFS2QezroInk/uvos0B3hf9rW
         FU86K8aPI4zFoCM3xtNvGvgiiysfR0zvQg5LMaSaqXi7VqX+LGYA1tW0Dcq4f02dovEk
         YJOahWEOEdh2AwUz7Ozq9snaBy+jMnQnsIdaazRLdAAWI/hM4IrNWjj4O1OICjVItx06
         69Jrs7n9AJRoRN41Gmr3yaXINKecB8sL6HU0eaKjT5YvTrwNGQdiZo7ejVXHwW1WaMJr
         77AIzNckmWmFpLzaBHfKds+Mygrr6TdC0hN3eunZupkmJdd8VxChegsi0eiQc0TgGR1E
         TFRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id u18si2616582wri.5.2019.07.25.03.11.19
        for <kasan-dev@googlegroups.com>;
        Thu, 25 Jul 2019 03:11:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 49C53344;
	Thu, 25 Jul 2019 03:11:18 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0A9883F694;
	Thu, 25 Jul 2019 03:11:16 -0700 (PDT)
Date: Thu, 25 Jul 2019 11:11:14 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Daniel Axtens <dja@axtens.net>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Andy Lutomirski <luto@kernel.org>
Subject: Re: [PATCH 1/3] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20190725101114.GB14347@lakrids.cambridge.arm.com>
References: <20190725055503.19507-1-dja@axtens.net>
 <20190725055503.19507-2-dja@axtens.net>
 <CACT4Y+Yw74otyk9gASfUyAW_bbOr8H5Cjk__F7iptrxRWmS9=A@mail.gmail.com>
 <CACT4Y+Z3HNLBh_FtevDvf2fe_BYPTckC19csomR6nK42_w8c1Q@mail.gmail.com>
 <CANpmjNNhwcYo-3tMkYPGrvSew633FQW7fCUiTgYUp7iKYY7fpw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNhwcYo-3tMkYPGrvSew633FQW7fCUiTgYUp7iKYY7fpw@mail.gmail.com>
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

On Thu, Jul 25, 2019 at 12:06:46PM +0200, Marco Elver wrote:
> On Thu, 25 Jul 2019 at 09:51, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, Jul 25, 2019 at 9:35 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > ,On Thu, Jul 25, 2019 at 7:55 AM Daniel Axtens <dja@axtens.net> wrote:
> > > >
> > > > Hook into vmalloc and vmap, and dynamically allocate real shadow
> > > > memory to back the mappings.
> > > >
> > > > Most mappings in vmalloc space are small, requiring less than a full
> > > > page of shadow space. Allocating a full shadow page per mapping would
> > > > therefore be wasteful. Furthermore, to ensure that different mappings
> > > > use different shadow pages, mappings would have to be aligned to
> > > > KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
> > > >
> > > > Instead, share backing space across multiple mappings. Allocate
> > > > a backing page the first time a mapping in vmalloc space uses a
> > > > particular page of the shadow region. Keep this page around
> > > > regardless of whether the mapping is later freed - in the mean time
> > > > the page could have become shared by another vmalloc mapping.
> > > >
> > > > This can in theory lead to unbounded memory growth, but the vmalloc
> > > > allocator is pretty good at reusing addresses, so the practical memory
> > > > usage grows at first but then stays fairly stable.
> > > >
> > > > This requires architecture support to actually use: arches must stop
> > > > mapping the read-only zero page over portion of the shadow region that
> > > > covers the vmalloc space and instead leave it unmapped.
> > > >
> > > > This allows KASAN with VMAP_STACK, and will be needed for architectures
> > > > that do not have a separate module space (e.g. powerpc64, which I am
> > > > currently working on).
> > > >
> > > > Link: https://bugzilla.kernel.org/show_bug.cgi?id=202009
> > > > Signed-off-by: Daniel Axtens <dja@axtens.net>
> > >
> > > Hi Daniel,
> > >
> > > This is awesome! Thanks so much for taking over this!
> > > I agree with memory/simplicity tradeoffs. Provided that virtual
> > > addresses are reused, this should be fine (I hope). If we will ever
> > > need to optimize memory consumption, I would even consider something
> > > like aligning all vmalloc allocations to PAGE_SIZE*KASAN_SHADOW_SCALE
> > > to make things simpler.
> > >
> > > Some comments below.
> >
> > Marco, please test this with your stack overflow test and with
> > syzkaller (to estimate the amount of new OOBs :)). Also are there any
> > concerns with performance/memory consumption for us?
> 
> It appears that stack overflows are *not* detected when KASAN_VMALLOC
> and VMAP_STACK are enabled.
> 
> Tested with:
> insmod drivers/misc/lkdtm/lkdtm.ko cpoint_name=DIRECT cpoint_type=EXHAUST_STACK

Could you elaborate on what exactly happens?

i.e. does the test fail entirely, or is it detected as a fault (but not
reported as a stack overflow)?

If you could post a log, that would be ideal!

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190725101114.GB14347%40lakrids.cambridge.arm.com.
