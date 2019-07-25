Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUFJ43UQKGQENZJYWSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3869374D44
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 13:38:57 +0200 (CEST)
Received: by mail-yw1-xc3e.google.com with SMTP id l141sf36586303ywc.11
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 04:38:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564054736; cv=pass;
        d=google.com; s=arc-20160816;
        b=V4G1MU7s5Blz9XodRLXBF/A29up0ltW0GaEY1IoaMLgcJI855mfPzmPWVDCDS3fIId
         CCuxDXwV+GBudE5CyXOCfeUUl5FlbrB3tJlGwYH9feaiHIVGJ0GM1fOc1pt2Wo3bhh3A
         iuCRpsVeQRpJqSWhdwACam40pdvy4j9KIa6Py2u3JMbr3Q++e8Qa8s/sqZR6mLt5Ym1T
         VZEzImh3p/XTndcfL5pQYNhiOuaotu6XPyuaRKiI0D67OzVZ0AFiMG88Rr9UYdrc0CUX
         otpcetpmhRjBBwF/+E8SCkglLimbbXrm+ZrQazwu3ej/3mlpHBkF69zBB9W/1TNfs3LH
         BTOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R0T/j3Sbbx3747ZzyHo9LVwH7TRSz3f689v5+9nA5YI=;
        b=H1V0IKY/P65g0w3JeRBhKd23LyoqTFiOJWd+OBL2kx7Ck+CZ9vIWL8/56ESDRwKLFm
         arkYPKGuZvK/ywt6fUizKox8nX2xxixQL7UD/nrveK6AXimo3QMFNtXuBFiuCURqggj+
         amwXsZ8hMwKrNdWgEt+UXovmN6urGNNtXD6hETVLKiXPccwpnnDUJVw9NQkreBJUcbuj
         s2LolOcH9JpxZslyhoO1z8HLSjKuk36lqm+q8FB43Cec0h9ce8iNp9C4qg8Gxj9UZmcA
         dpRyRhG5246ZluVuFunQAwON+ySH0tG9zl9KyTF90G1V+nmVzgFyx8NDQ0K19xd6ysTT
         MS0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="nyY+obe/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0T/j3Sbbx3747ZzyHo9LVwH7TRSz3f689v5+9nA5YI=;
        b=pbrbmFpABx9VH/wfNc7WNTUTsnrAWcz1S/gpVmssq1Zjs6IXST19DZMGbBIz0yi4/4
         xgH7ErAjFm5NIP9sYiTDgXGn0JgzrU1WZFaf9TNXwNulkeCXM4PmLdcnCXyD7wCwfcsJ
         iOVtVEXMNxOnSMGdMoxOLaeWEs0kPQiOKNfsoE8tKEY5crVksaH4WD86Hw76OdqKQ/lE
         QLnVu19RJnuXz4l+Ui8t2vWqTkGlCbpnLfsEMWpGhPpIwrhsQH+097iRJDRnlBKFjrbL
         T9Aiz+GHvoBvybkaslj6pc2cK2SCKm7K5p/+UZDyLH8d1v6s40WYVHkdtEi2IE1elMFc
         uq1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0T/j3Sbbx3747ZzyHo9LVwH7TRSz3f689v5+9nA5YI=;
        b=V3NqHGZcUvzKcXt+5ryvxww2cDqKbyH8xMpiC8xKDvLDAhVOPbQ/QGpu/Y6q84YGh4
         xssOoKyNjTRKbO/PlMQSZulfOxr9lYPL8JkNHuNqWtUPUJ4M0umEcwG6FWVFS7+pqPjl
         qBtcoOrpbDj1ETkXv/xB/XGQdlV+zfe6FGq1mm+EHmFELj4tg/AL5vzsrgJcVcEYTNEQ
         IXQIDIttkDdaCgeK5q35jLpJlk0KmGVS3j5O+Vv19pTrCTDfEfnpSRc3UJFDcKYE+Ppv
         Aq+LI1ODdRk2i5tUlNuaUg0HQ8N39nMpMQPuWHfYKpYRApuA72B3+NJAm+NCx4rZREUq
         CjhA==
X-Gm-Message-State: APjAAAUif2/gBkascpjM2XYnTGjD3mS28Nxxpevu3S29LdfN5E7M74/4
	aHXmgLI5YU0fLsIbq5Ou+gs=
X-Google-Smtp-Source: APXvYqxTYt5lQr/uyFQ7xZI6fR04Z/ZcerNJsQ8uRPZjTAL0iSjyM+wsNcTvX28NUtDzMd5Z/z1D6g==
X-Received: by 2002:a5b:84a:: with SMTP id v10mr39724049ybq.111.1564054736278;
        Thu, 25 Jul 2019 04:38:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:48d3:: with SMTP id v202ls6193747ywa.9.gmail; Thu, 25
 Jul 2019 04:38:56 -0700 (PDT)
X-Received: by 2002:a81:a682:: with SMTP id d124mr55457514ywh.302.1564054735954;
        Thu, 25 Jul 2019 04:38:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564054735; cv=none;
        d=google.com; s=arc-20160816;
        b=DC5L26gO6uPPDc9BOTgYAm/e085IVuLg8WFKYat3p+yuZJo096KKor58wksb8qVQhg
         By+SxflEr+6akiOQ3FQ2EEI7OhyBxc8RXFTlFREIyUobJUyxB5Sx8dufcQp8/dkWHZL6
         Avj42zbIR6AYr/SNpOtFpAGJ81U+AOHKAKWv3jHkXpoWkerSSQDrrj8yfEYUX3JRXkx4
         9THIvw0AedIr3WE1vWh23Yk+2SkfZeXU1lhJy92/XkSOxW89mZ1whOSPtbOmQlsL4JSJ
         O1FzikP6O6sWcXb4tJkmrKKMiWYS+238BuHTkTZ2D8f113eTAB2liaJyaiOSJ6QYPUwq
         AUbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G6MpZgr7i8B1FkEDPScz8e/wH7xnLSjpvv/jUeXDToM=;
        b=pFQwmqAuD7kbU9ojx3necCq/BQLYuWnp5OyeMyq++YukvpKD18o36dWTqG22L7fXvD
         QKo+5CyTq7Ore6SDnyltXNxblguDUZWJ1lDZY+QHh4lJ9WxS1AqKnaFQRRd+jr9pZugo
         gEogChDrYcTUmf9CWHJ0kxvoTyPYCd8f51TtSm0JCzqtGKFPZ7BuR9oFaLBIR1oTUfWy
         ohV09+sUL6wBkTGr6LZ4mgyjlr+3UB41h07MdCdFfzrQaMm5zn8B38jfFhaUWUw1zuwJ
         HAC8Qx/AWb8R/bBU9qw6wDPVKG9ygV2gEY9WwaLdBm1ios3eAhZqapY7PMXgQVrnINRG
         5JuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="nyY+obe/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id x5si820670ybn.2.2019.07.25.04.38.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Jul 2019 04:38:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id o101so51269750ota.8
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2019 04:38:55 -0700 (PDT)
X-Received: by 2002:a05:6830:1688:: with SMTP id k8mr24913637otr.233.1564054735077;
 Thu, 25 Jul 2019 04:38:55 -0700 (PDT)
MIME-Version: 1.0
References: <20190725055503.19507-1-dja@axtens.net> <20190725055503.19507-2-dja@axtens.net>
 <CACT4Y+Yw74otyk9gASfUyAW_bbOr8H5Cjk__F7iptrxRWmS9=A@mail.gmail.com>
 <CACT4Y+Z3HNLBh_FtevDvf2fe_BYPTckC19csomR6nK42_w8c1Q@mail.gmail.com>
 <CANpmjNNhwcYo-3tMkYPGrvSew633FQW7fCUiTgYUp7iKYY7fpw@mail.gmail.com> <20190725101114.GB14347@lakrids.cambridge.arm.com>
In-Reply-To: <20190725101114.GB14347@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Jul 2019 13:38:43 +0200
Message-ID: <CANpmjNOQSqtpEWNbk6Ed+GmZ8ZBY-LBn4ojt8_yrUM+qmdGttw@mail.gmail.com>
Subject: Re: [PATCH 1/3] kasan: support backing vmalloc space with real shadow memory
To: Mark Rutland <mark.rutland@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Daniel Axtens <dja@axtens.net>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="nyY+obe/";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 25 Jul 2019 at 12:11, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Thu, Jul 25, 2019 at 12:06:46PM +0200, Marco Elver wrote:
> > On Thu, 25 Jul 2019 at 09:51, Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Thu, Jul 25, 2019 at 9:35 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > >
> > > > ,On Thu, Jul 25, 2019 at 7:55 AM Daniel Axtens <dja@axtens.net> wrote:
> > > > >
> > > > > Hook into vmalloc and vmap, and dynamically allocate real shadow
> > > > > memory to back the mappings.
> > > > >
> > > > > Most mappings in vmalloc space are small, requiring less than a full
> > > > > page of shadow space. Allocating a full shadow page per mapping would
> > > > > therefore be wasteful. Furthermore, to ensure that different mappings
> > > > > use different shadow pages, mappings would have to be aligned to
> > > > > KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
> > > > >
> > > > > Instead, share backing space across multiple mappings. Allocate
> > > > > a backing page the first time a mapping in vmalloc space uses a
> > > > > particular page of the shadow region. Keep this page around
> > > > > regardless of whether the mapping is later freed - in the mean time
> > > > > the page could have become shared by another vmalloc mapping.
> > > > >
> > > > > This can in theory lead to unbounded memory growth, but the vmalloc
> > > > > allocator is pretty good at reusing addresses, so the practical memory
> > > > > usage grows at first but then stays fairly stable.
> > > > >
> > > > > This requires architecture support to actually use: arches must stop
> > > > > mapping the read-only zero page over portion of the shadow region that
> > > > > covers the vmalloc space and instead leave it unmapped.
> > > > >
> > > > > This allows KASAN with VMAP_STACK, and will be needed for architectures
> > > > > that do not have a separate module space (e.g. powerpc64, which I am
> > > > > currently working on).
> > > > >
> > > > > Link: https://bugzilla.kernel.org/show_bug.cgi?id=202009
> > > > > Signed-off-by: Daniel Axtens <dja@axtens.net>
> > > >
> > > > Hi Daniel,
> > > >
> > > > This is awesome! Thanks so much for taking over this!
> > > > I agree with memory/simplicity tradeoffs. Provided that virtual
> > > > addresses are reused, this should be fine (I hope). If we will ever
> > > > need to optimize memory consumption, I would even consider something
> > > > like aligning all vmalloc allocations to PAGE_SIZE*KASAN_SHADOW_SCALE
> > > > to make things simpler.
> > > >
> > > > Some comments below.
> > >
> > > Marco, please test this with your stack overflow test and with
> > > syzkaller (to estimate the amount of new OOBs :)). Also are there any
> > > concerns with performance/memory consumption for us?
> >
> > It appears that stack overflows are *not* detected when KASAN_VMALLOC
> > and VMAP_STACK are enabled.
> >
> > Tested with:
> > insmod drivers/misc/lkdtm/lkdtm.ko cpoint_name=DIRECT cpoint_type=EXHAUST_STACK
>
> Could you elaborate on what exactly happens?
>
> i.e. does the test fail entirely, or is it detected as a fault (but not
> reported as a stack overflow)?
>
> If you could post a log, that would be ideal!

No fault, system just appears to freeze.

Log:

[   18.408553] lkdtm: Calling function with 1024 frame size to depth 64 ...
[   18.409546] lkdtm: loop 64/64 ...
[   18.410030] lkdtm: loop 63/64 ...
[   18.410497] lkdtm: loop 62/64 ...
[   18.410972] lkdtm: loop 61/64 ...
[   18.411470] lkdtm: loop 60/64 ...
[   18.411946] lkdtm: loop 59/64 ...
[   18.412415] lkdtm: loop 58/64 ...
[   18.412890] lkdtm: loop 57/64 ...
[   18.413356] lkdtm: loop 56/64 ...
[   18.413830] lkdtm: loop 55/64 ...
[   18.414297] lkdtm: loop 54/64 ...
[   18.414801] lkdtm: loop 53/64 ...
[   18.415269] lkdtm: loop 52/64 ...
[   18.415751] lkdtm: loop 51/64 ...
[   18.416219] lkdtm: loop 50/64 ...
[   18.416698] lkdtm: loop 49/64 ...
[   18.417201] lkdtm: loop 48/64 ...
[   18.417712] lkdtm: loop 47/64 ...
[   18.418216] lkdtm: loop 46/64 ...
[   18.418728] lkdtm: loop 45/64 ...
[   18.419232] lkdtm: loop 44/64 ...
[   18.419747] lkdtm: loop 43/64 ...
[   18.420262] lkdtm: loop 42/64 ...
< no further output, system appears unresponsive at this point >

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOQSqtpEWNbk6Ed%2BGmZ8ZBY-LBn4ojt8_yrUM%2BqmdGttw%40mail.gmail.com.
