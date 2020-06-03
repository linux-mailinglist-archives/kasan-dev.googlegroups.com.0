Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFON333AKGQE546FPBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id CCC1D1ED0DD
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 15:33:10 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 203sf1518972oie.19
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 06:33:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591191189; cv=pass;
        d=google.com; s=arc-20160816;
        b=ThKlITpaSfbDBp8i7o31q8bEEuZNu0z79J4rvhaFF0hGErv4MPhRjn2usdIcT4zzEy
         PgspGOoANDh2ABG8Egykp7ze22v2ullyH1cTrHQcWAtQvoif/T6ZPLk91quSSLKQwgzi
         Fr+Afyjfx0P1hRWpiSWj4OzaN0nMuUcUjQATJfIJ8CRx/5FMqqncQT03u0zThaI2ZcOE
         ghbFL/29SQNG9/FM2DJjS2Gn5GmKi39kCkGgqp/2W/EU6uM48Yu/840zp+vjUAPF96lV
         Omq3Ik2d13hTxeVydTzfDgD/tYLXTrlLkvNceEXhJEaQV7SdnB0EJjyMGEeBg58Xz3Nc
         6Skw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c01d7/sHgt/KMcMH7qjrh4HbfmaK3maPGYjkw8NiB3c=;
        b=gXCrbQawyU9fHSGLAeIKAtu0nG78ZHj5koaz2Cma7b6mXq8Cv8cZh8aenqUJ0s7EGl
         DgY3uJoXYTld4BrBMrmfDcbEHqMiZ7vno646/B5rLP9jqzsNRlrFDX5FGxS3g04/chBr
         8zP6sSB57YWWCRchE66i7hdJDFotFSnq5RmR+dC8bwjwSOR5eX4SfiOOl56uhUjtZWEv
         kJxaIddHct38UhIptXqn6cgR7ZjTVMwZj8kX6ZYaYt/uA1fexnQhPuWvnpc39e0lqM0k
         yjUUZSWg1v+nLHe8Bc+5Q9BOnqKCeiVxIYKVC4Y9zZcHZsBnEc4TqPkw/KXdcdDMObcu
         SYpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qQY7fexk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c01d7/sHgt/KMcMH7qjrh4HbfmaK3maPGYjkw8NiB3c=;
        b=Ks05A/TUu+qO1E1coF99cNHLdvsRVpqli96NzFdHmWNKl4HO6FLefA1MO+RMNeqDn9
         oJhe7IdWIEIctY1PclKJH2glyhBmAinO51hnxiBHDWmu7qNWmf0BMuqWLLdxbc+vSSAS
         tetoBu+wq2zh1XnmZa+oLkrtCBzP1vlY/spRQ18SLd2HHpEGttlwnsiap2hdw9DqkKbg
         B1Yes3zloEc3s/1cBRI1hjNrSx90ERH+2bhk2piIfq6N/DB25wMmbLUY6ih8QZQxEx/a
         GM7hJV2gPi6sHJeqK0t49OycT4pWD/SRq9GnBuWJlENeL3B9iZZKnFZL9Mm5lvPLA3Of
         CQcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c01d7/sHgt/KMcMH7qjrh4HbfmaK3maPGYjkw8NiB3c=;
        b=kq/XaANnIVyoUXCX9+2O13ozMez16S83pLDmCo8gTDlLIfIT7owJdj/0MpDksJiFzH
         4N/HZVOy1xwEdH0hfbU4uwb2yhbhPV7c6Hw2g7VYMa0Kzfg5Ro+ad5LPJElfX7XPJ6vN
         3mpqaHbuSoP4ifzKxhUJy7mGrzP/0sEzK0p2q2Av0Z68+GmqdKCVWiuGp/k/V4/b3yye
         2G67WQYo/TVDkVPq1PH5hJ0AKaUqz68y8VXFqc3PuBw920jzwLzOwpwK1xSOswflE1QG
         mzhqhEc/kB8woQwgKZGgXXC9aNue4yV/avI+WFFrbh0DfMtJdMT00MkZA34Y170YrSC7
         s0ww==
X-Gm-Message-State: AOAM532hoXprRmxkHK0lrZIScd+L+sncgiLXzOGLpMaal/Dc9xciCX4h
	ZasVdz81sIRsfuiS9d4hXrU=
X-Google-Smtp-Source: ABdhPJyIPJvYTAp8F3HqIlXzjmAWBl+x2Tk9hRDysbq+C4T8BGq/XW7CAIooan6rU5vajV2Yppt3hg==
X-Received: by 2002:aca:3d09:: with SMTP id k9mr5955093oia.160.1591191189836;
        Wed, 03 Jun 2020 06:33:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:502:: with SMTP id 2ls416821oif.11.gmail; Wed, 03 Jun
 2020 06:33:09 -0700 (PDT)
X-Received: by 2002:aca:accd:: with SMTP id v196mr6231353oie.135.1591191189429;
        Wed, 03 Jun 2020 06:33:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591191189; cv=none;
        d=google.com; s=arc-20160816;
        b=En3uEFy4F4JG/ZleILdy1tdCReLm8CxPqqmrA7WxkOIGOTmqfjtElcc7tKUN2yz37M
         aGUcvRh0X0rMp5SQ+4U/VKopEdsn2GxC0zmrDzKCYwMyVZshpaCX0n3lwsI+yZJLc8Ih
         JSKZr5wtuwEjwoTe9CayjclkFo1DjpzL8p8G/ISPWphMZA33/yPJo5Do3q+HtgMGcZMp
         /4BGMiS/vLTQ0CVA3vseODCc6DFrqxLZZNKUWc+WwnHXFj63DYkaBS+7ukyKkgdIpT5Z
         axunqQD/qDxe6cDIbZh50dmauCrdohLxJ3QUrvuE51/yGiI51VXQNnmMf0ZeJ+6I/0Vb
         ZYQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2Q5Izy2Q3y4sMGHFp3V6FithAv0OmwTAETmoYPgsSps=;
        b=PMEeLTmfdg3Hr9VwqKu2jOFc2ry44RDoQ2w0xNJ4G+ULCzjhN4kQ3XZXldySw5Bx1z
         /zSr3U5J3rnwAym164yDfXzuAHT3mGGMW8j3ZqaWouNffhDWJWw2LWOUQMmSO/woBEOM
         FYUbLv3zzcOPVw1qgSzhjA3XAOUybPMfO7+8TFfHdPTrFEbJEtzEhnxmqMknQKxHUBcS
         OHW4z0csE1IwMZLs4ex9uG/dKYoDVt/1YDvs0HLPmbHMPGo5etASgV7unEKnAiB3d6Ib
         GWTlemzsec8liSF7zf8BdeDmDt409bHSR7MddhQWWB4bIxXGyiI+qtLpzFhWSYCJauca
         TlPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qQY7fexk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id d2si111249oig.4.2020.06.03.06.33.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 06:33:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id d67so1801598oig.6
        for <kasan-dev@googlegroups.com>; Wed, 03 Jun 2020 06:33:09 -0700 (PDT)
X-Received: by 2002:a05:6808:34f:: with SMTP id j15mr6473850oie.121.1591191188821;
 Wed, 03 Jun 2020 06:33:08 -0700 (PDT)
MIME-Version: 1.0
References: <20200603114014.152292216@infradead.org> <20200603120037.GA2570@hirez.programming.kicks-ass.net>
 <20200603120818.GC2627@hirez.programming.kicks-ass.net> <CANpmjNOxLkqh=qpHQjUC_bZ0GCjkoJ4NxF3UuNGKhJSvcjavaA@mail.gmail.com>
 <20200603121815.GC2570@hirez.programming.kicks-ass.net>
In-Reply-To: <20200603121815.GC2570@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Jun 2020 15:32:57 +0200
Message-ID: <CANpmjNPxMo0sNmkbMHmVYn=WJJwtmYR03ZtFDyPhmiMuR1ug=w@mail.gmail.com>
Subject: Re: [PATCH 0/9] x86/entry fixes
To: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qQY7fexk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Wed, 3 Jun 2020 at 14:18, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Jun 03, 2020 at 02:08:57PM +0200, Marco Elver wrote:
>
> > What is the .config you used? I somehow can't reproduce. I've applied
> > the patches on top of -tip/master.
>
> So tip/master, my patches, your patches, this series.
>
> $ make CC=/opt/llvm/bin/clang O=defconfig-build/ -j80 -s bzImage
>
> is what I used, with the below config.
>

Thanks, can reproduce now. So far I haven't found any indication that
there is a missing check in Clang's instrumentation passes somewhere.
I'm a bit suspicious because both Clang and GCC have this behaviour.
I'll continue looking.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPxMo0sNmkbMHmVYn%3DWJJwtmYR03ZtFDyPhmiMuR1ug%3Dw%40mail.gmail.com.
