Return-Path: <kasan-dev+bncBCC4R4GWXQHBBNOX6D5QKGQES2GQXGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id B56DB2848A6
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Oct 2020 10:32:54 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id g14sf2632281oov.19
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Oct 2020 01:32:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601973173; cv=pass;
        d=google.com; s=arc-20160816;
        b=L39fdlAfQMJybdSiSSa6ccXCh9O4xm3kmw18MnQk47rViisHX3uSktTSZcs7O31XM0
         uJng4dCq89iZt7KIRoJ/T/dTdEm++0e0tg9QvmVCcssG4f0Zyw4drjvqcu4kp7dIzASd
         ptCgGjVbqYiWBugbL4WUL+ftRVJk8q6/YHhPzLFAlcrTVM1Um3sIdGTmZDvigdO1sVrd
         6VFRfc+ulYZ8XCnRWJob+/xNJlho4o33dfJfTHlDt0ArZGzEpP1Z73n9Hxj9Kp6pkOHj
         uTLdOSm9bxN+opQ4Qa3Dax/NcaYswpuDeqwebzOa6To9L7+Q7Kl2PF6wPFiDbSnm/uA6
         V+Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=kC3T3g7KiKnEl74i8dKwR+L9qU52X8H0ie4bdorc1ZQ=;
        b=Tqb8OTms9WtRwNBwtTpOXsJYg2KGob8nlD3d+eakxZldS+Show9X42W3YkZN6Yjzpt
         b+f6QNFVBV1I7IrrCMDhmTqfxs2OtXzwxcI2mSKSSuNxZm+aG8r3PBsxjM5PTPiRQJtv
         xdPso9hYgQ3P9Y6QgP5lUjab0aAz4/mUb/kOwDTc/bAwHHlTy+LJCbT//en8c4b83Td4
         HY/oaOoScnFg8+2uGV5+HM1GRB2JjoUF5/oRkIB2PUM2blwT/nxjuUra9ODPwW2LC+MF
         jOglciRKQaRqNHxvpegAoooWTfTldrEAehksvWu0VDhc83tP0H8KVtyL9+ZFGIW0xnrx
         F9rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning cl@linux.com does not designate 3.19.106.255 as permitted sender) smtp.mailfrom=cl@linux.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kC3T3g7KiKnEl74i8dKwR+L9qU52X8H0ie4bdorc1ZQ=;
        b=nY2fdbMCA764tadcWJFFiSYK55NCxzkawAHn1NA0qkmtK4BAF4Lps+zbQaC6YO2jww
         7UV0f+jqN16ahlPuSdNwRK1LCo9cYs4MPDEsXIC4qg5S5fDOh2vZXLqRc7FYHSRs5keH
         AZ7hGWqmY0O6kofZWvdFfsMWD2u7LG6DQilj9dEukOVVs5lu/ifGpccl6FHmr96IPbLy
         tP429oRqOKXjiBQR06rOHf3EfhPWTuh8fk9r5ZN16LGt4LnpFf3RFKSNo6SIqwit7Scp
         u8PeKkj0fbQUXENq+tTVJtjwvmbKMJlN5uLqZiZuQT7Z+dcZnVD3+1z9ujYFqU0ZLIdF
         fQoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kC3T3g7KiKnEl74i8dKwR+L9qU52X8H0ie4bdorc1ZQ=;
        b=smPgGdfgVQzvKbyYzkfChOHbfUmTzsiB3zOCcv45l2Zg6NlsXrr10JvhQmnBwPHOhW
         OJSTYzPD0dE95d5WhmLEo3NT+G1c3rGhcjsSEePdz5GKQEg+yfDE/CB30n2Vry9D2wDV
         EfBQMYo24Zf1/QP00j8MbKF4yVxDsAVebcxZbmLwsVtvtxv/RG9/exL88P4fO7ZdSCG0
         Kv1AoAOjLd/ki8K4iib48LLbUZlAKnlg85wk6fWwx4CSW0hhbCjB4Ecl9aYB3ofY6L4o
         DI862hVOu/Q0FI+eBObSgY40dlGNYYmCf4scm1yXQHQfkrdLojctAf0Y0SLdHhP9A0U6
         3wbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qbM4sPItBP4MNCJUDMJW5hTnm5Zg8MOsLqcVxuBdm+X25iWI/
	+4HOLHybDOWOfYo4NLg5TpY=
X-Google-Smtp-Source: ABdhPJzqev8AIosqNzR2a7e+IYE2X6o7LAGdD3uCJgOQ8wIHPlYOmwX09kE/qM/zRUDFlUB3g8Wruw==
X-Received: by 2002:a05:6830:310f:: with SMTP id b15mr2249013ots.208.1601973173330;
        Tue, 06 Oct 2020 01:32:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:dd0b:: with SMTP id u11ls2786592oig.6.gmail; Tue, 06 Oct
 2020 01:32:53 -0700 (PDT)
X-Received: by 2002:aca:3f09:: with SMTP id m9mr2159924oia.1.1601973172990;
        Tue, 06 Oct 2020 01:32:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601973172; cv=none;
        d=google.com; s=arc-20160816;
        b=pnr6Ltooo96lgnvM6ylBuXj8UZLqJcOj0abQe2+QzV4o8/3Cw4hhR3cL5C2J4qPebI
         Hp61S/eWEI6E+Ps8Y4YhuTfIbrcuyUcqeDcujBVmk6ZSQnL1Qdu02vQnSXmbcDL3Ifrn
         LVINCUMmtWda0Tn+gw3lfgLDo/QmRXhFuk7WprA2CasaF84b+i96hVmnVhjxK5A6uT8W
         BaoPg3/HXju6MDtJBDAzy0aB8Mr01Tz+/FJ/GV5JWxcfvvrV8iclztqqk0sGY4+qlYPm
         Zfah37GTDIxniwCIJOrpYu5xuWCRYjV8p6qLUy/OjyVVfUVDieKnyJ1YGdsR6mzYARDi
         B3gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date;
        bh=h2fGi82oNeDwbuAxdUUFtC85weVXxwx+kW762dleTbQ=;
        b=A1ta7gRuOzoNFS3cglK3iRC9H80alyTwDnGNr5o8enQ23aZKkyCSys+EvH4UktCFqx
         9t1c3y0dg45IfjO877CMNPLoK1BCt2ClTUQ4vv5qi6DPHQuArOdkSY3Qk5X/zZbKfNYM
         jIqBBu+mCkYsimg4gkqOgzKQbc/EhuLaDnxWzNL62oKMDEEBNIZ1edKoXs0ZgGM7n7OW
         38mSth29aiVakwhjYRLnYkjdJ6fLPYv/r/cemUejYmQG0gaDCgyPw6EVi/8+RyMTKqzY
         hWQIdWjzOUqQapxcvyxmkdMUIuEPzbtAelOqCQQ15glLM7d14YRCQXbQU+OO5zLpWlz3
         YkdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning cl@linux.com does not designate 3.19.106.255 as permitted sender) smtp.mailfrom=cl@linux.com
Received: from gentwo.org (gentwo.org. [3.19.106.255])
        by gmr-mx.google.com with ESMTPS id l15si365282otb.0.2020.10.06.01.32.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Oct 2020 01:32:52 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning cl@linux.com does not designate 3.19.106.255 as permitted sender) client-ip=3.19.106.255;
Received: by gentwo.org (Postfix, from userid 1002)
	id 2990640ABD; Tue,  6 Oct 2020 08:32:52 +0000 (UTC)
Received: from localhost (localhost [127.0.0.1])
	by gentwo.org (Postfix) with ESMTP id 26F2140ABC;
	Tue,  6 Oct 2020 08:32:52 +0000 (UTC)
Date: Tue, 6 Oct 2020 08:32:52 +0000 (UTC)
From: Christopher Lameter <cl@linux.com>
X-X-Sender: cl@www.lameter.com
To: Matthew Wilcox <willy@infradead.org>
cc: Jann Horn <jannh@google.com>, Alexander Popov <alex.popov@linux.com>, 
    Kees Cook <keescook@chromium.org>, Will Deacon <will@kernel.org>, 
    Andrey Ryabinin <aryabinin@virtuozzo.com>, 
    Alexander Potapenko <glider@google.com>, 
    Dmitry Vyukov <dvyukov@google.com>, Pekka Enberg <penberg@kernel.org>, 
    David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Masahiro Yamada <masahiroy@kernel.org>, 
    Masami Hiramatsu <mhiramat@kernel.org>, 
    Steven Rostedt <rostedt@goodmis.org>, 
    Peter Zijlstra <peterz@infradead.org>, 
    Krzysztof Kozlowski <krzk@kernel.org>, 
    Patrick Bellasi <patrick.bellasi@arm.com>, 
    David Howells <dhowells@redhat.com>, 
    Eric Biederman <ebiederm@xmission.com>, 
    Johannes Weiner <hannes@cmpxchg.org>, Laura Abbott <labbott@redhat.com>, 
    Arnd Bergmann <arnd@arndb.de>, 
    Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
    Daniel Micay <danielmicay@gmail.com>, 
    Andrey Konovalov <andreyknvl@google.com>, Pavel Machek <pavel@denx.de>, 
    Valentin Schneider <valentin.schneider@arm.com>, 
    kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
    Kernel Hardening <kernel-hardening@lists.openwall.com>, 
    kernel list <linux-kernel@vger.kernel.org>, notify@kernel.org
Subject: Re: [PATCH RFC v2 0/6] Break heap spraying needed for exploiting
 use-after-free
In-Reply-To: <20201006004414.GP20115@casper.infradead.org>
Message-ID: <alpine.DEB.2.22.394.2010060831300.99155@www.lameter.com>
References: <20200929183513.380760-1-alex.popov@linux.com> <91d564a6-9000-b4c5-15fd-8774b06f5ab0@linux.com> <CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK=iyBkA@mail.gmail.com> <20201006004414.GP20115@casper.infradead.org>
User-Agent: Alpine 2.22 (DEB 394 2020-01-19)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cl@linux.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=softfail
 (google.com: domain of transitioning cl@linux.com does not designate
 3.19.106.255 as permitted sender) smtp.mailfrom=cl@linux.com
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



On Tue, 6 Oct 2020, Matthew Wilcox wrote:

> On Tue, Oct 06, 2020 at 12:56:33AM +0200, Jann Horn wrote:
> > It seems to me like, if you want to make UAF exploitation harder at
> > the heap allocator layer, you could do somewhat more effective things
> > with a probably much smaller performance budget. Things like
> > preventing the reallocation of virtual kernel addresses with different
> > types, such that an attacker can only replace a UAF object with
> > another object of the same type. (That is not an idea I like very much
> > either, but I would like it more than this proposal.) (E.g. some
> > browsers implement things along those lines, I believe.)
>
> The slab allocator already has that functionality.  We call it
> TYPESAFE_BY_RCU, but if forcing that on by default would enhance security
> by a measurable amount, it wouldn't be a terribly hard sell ...

TYPESAFE functionality switches a lot of debugging off because that also
allows speculative accesses to the object after it was freed (requires
for RCU safeness because the object may be freed in an RCU period where
it is still accessed). I do not think you would like that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.22.394.2010060831300.99155%40www.lameter.com.
