Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKXQ5TYQKGQESU6CY7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id D71AA153A71
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Feb 2020 22:48:27 +0100 (CET)
Received: by mail-ua1-x93b.google.com with SMTP id h10sf1000555uab.12
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2020 13:48:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580939307; cv=pass;
        d=google.com; s=arc-20160816;
        b=VcZSlQodsNdzDrTHt6N9B2MF6Fi3daM4TnFLmSCd+jIu+iR4eHjpDdtyzfVhO6EIx7
         /lbE3aoqYZpC9ohawbepOIlvjvZvq8EybyQq+aZFK5ro0lBS+sWu89VJKRg90aSU0eL4
         /0mc77YbzLLPyq49kcLBLAEZ6rhkfQWzO7fbV7xr5YI3Y0k0Bu4FH9qBSI3y0Q9E7SlO
         +AzCqQM/MfRIxbiXsgG8XYzx0OobF8So0V74uUEZzn7QBewsE0ilA3G7wu4oBJ1hi6KP
         ANeJiCNhDKlkj/vOqiEDlBKnQ4jM1q0QbuKkhPyJWm7254bLSBKs3LG0IxkPUJ4BXvRT
         NpLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=x3GDaXuoyXh5swugShGS7HOCvLx138XuX/GNSV/D8LI=;
        b=qqY7U1EZP5Ta9MdpupkY49vZ1C8PtvDjnbb4tEMZMEYE1QSIuVvaoeYvqJcx/2XIpM
         a0TrTy+b2oyci4L/8/xEqXu0dJS1cbmCqwhDyW03fnuf2FldTlg4diSZ4FOfik/DwgF5
         ObkXF+Jo5uEtwBOew3JnIq+DbNOO0c4XltwlVn/azFZWGiiOCEsgTesgTD199AFZzf+j
         awj1WCWlzogzryuYoaROR12yI3DvAq3dAqsWmEHbkXSColdwpy0AgQI8X+9W4abTctWu
         wUWeGQ4D6kuhlvuQULoVhrD8jRo4ai3NsUKjkr/xUoEs3G1uv89qioQwtB82WKFhOFhY
         /2ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b6YmUZtq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x3GDaXuoyXh5swugShGS7HOCvLx138XuX/GNSV/D8LI=;
        b=TvYoZCjybtMWv+POo/fqMpRJFC8s9R5HC85WQSoMr3BQJ6UpBy8VdT8OS3lmTk6D6K
         wdgPZ3EmITnNlp+eA3cv6zY5o229HuUl+uzs8/SzsTHxpqnI8QOrjzGrcbLXqBuBNgPT
         dISSe8Jjo+28bWXnlBK/Ai+fxcT5n0rrCnAVy18SDoa7Xfr51rRTFg8SvOWQMPTMmUM7
         WhR+t/soNvg9wyNrq9nZLHvmMHTUvdVheRugCVpi8KhnV/nbdPhHuQj70P9vtHmLUckh
         c/athI0JTwBrrJszoVa+/x/bNVUGS13mFUpeazAy56wPzsGsNCDk8nV2/em29Nr1BWht
         yOrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x3GDaXuoyXh5swugShGS7HOCvLx138XuX/GNSV/D8LI=;
        b=iQjWYkxseY2yGIxcJgdLhlO6RGxN5fn7jZMv0vQ8pjbdwdd/rdwQthuSOvwrv7kF0L
         oLYnl8ufj1d0NzG8QxnUDNNMCRbWpyCml32I0CPdXj+5lbPzQ2rMvtuubwJvXDaR6YhK
         04L/UoDRX6IdMyXOdoDd6nqG/d9uETTG/+X3SyVHnb1xl1cf9ATy8uV618brYOlKpKAx
         eHrKu2zveKFUtEcfBETeVR3MBBl6s3BA3n8G2KJiB1efoxl1t8iDUPQldAWhMrdeASym
         qwyS+r7gDHEi6y+92cpcpaq7QpaDqkIiMpbKmXKVcgfWMb2rWsbYk/qo2PLqWan7sXb1
         PjfA==
X-Gm-Message-State: APjAAAUoksYSdaKkAHioTMRvAqkqJj4Wkq1hCkwCQyNQSt9mLa6MPw96
	2e1kNnviMjE2HFTxC8cV5x8=
X-Google-Smtp-Source: APXvYqzzHNV9iTbIMqebFoPvmkOxpuOu/p9dAI6Qn7NGTd2bqdn4o6TA9OeOJN5h2Ba+372y7TocRw==
X-Received: by 2002:a1f:2287:: with SMTP id i129mr65493vki.2.1580939306926;
        Wed, 05 Feb 2020 13:48:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:27c5:: with SMTP id n188ls489090vsn.8.gmail; Wed, 05 Feb
 2020 13:48:26 -0800 (PST)
X-Received: by 2002:a67:ee59:: with SMTP id g25mr24162040vsp.186.1580939306506;
        Wed, 05 Feb 2020 13:48:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580939306; cv=none;
        d=google.com; s=arc-20160816;
        b=al8XM3macwfjBYnaNGlW5V78yn8In1O6kh5Iy1lju8tMj3mVSmBuWIXa4RPfDta8fV
         aM65Nc+24iGj8fEGgrpUL7/hISgOJko8Llp46PE8qaeuScTfkDYBow2/vDLZnQv8YWTg
         p5tnO/epPqhYyY/XsI5X/ezq/0PybvHAcBBIkA6d+MINSJ9MQWyoTjgc9wvg6lc1gck2
         U8vVz0G6PFd+U5+ya7XiP3ATxVhwngR2/rM2YLDpLKfKt+0qtONNVeaIHZZKStBTC1c/
         /E6FjaKroeGV7I42XU9R3GjW9qSewW94SsB+q5fSSAM4W8471NtbKeh/jXUVKVnYwrGi
         J8Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xXCgFsyUYTQDrzFUzk4xcUNalccwTiUIPoXgx9OJsgQ=;
        b=QCxpbgqVah6GpRVQ54TXPy8GGXY+PXAECEHqXGaUd62Sv1d2ncmMwoZ4CLKPTDo1Y7
         EAOZagtHDu6i63FkQPaSolPLpUmqdPAEYpcrJdpKzMnn0Cn2x0M2BDkrVhfgqfprt+Pv
         TOlZLQgtwDYe24cUEN7H7zbtlQgy7t14nfDmPOzlFXPRC7akR01D66u4erbKeuG1PbnC
         AkFMpj9B8RUM32KFrJrJc91RP+caI6DnUAk/WQctoNOIzfdMfMv5cZkpeAxT4OF6ZWdi
         c9HKniABqggKuWrt55k11pVDwdXjo3aJ6d4hbM8C4KvTH611NeXoBz9LE9wvtETEQxQe
         ZHcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b6YmUZtq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id t76si54401vkb.1.2020.02.05.13.48.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Feb 2020 13:48:26 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id h9so3458333otj.11
        for <kasan-dev@googlegroups.com>; Wed, 05 Feb 2020 13:48:26 -0800 (PST)
X-Received: by 2002:a9d:7f12:: with SMTP id j18mr29256452otq.17.1580939305566;
 Wed, 05 Feb 2020 13:48:25 -0800 (PST)
MIME-Version: 1.0
References: <20200205204333.30953-1-elver@google.com> <20200205204333.30953-2-elver@google.com>
 <20200205213302.GA2935@paulmck-ThinkPad-P72>
In-Reply-To: <20200205213302.GA2935@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 Feb 2020 22:48:14 +0100
Message-ID: <CANpmjNN4vyFVnMY-SmRHHf-Nci_0hAXe1HiN96OvxnTfNjKmjg@mail.gmail.com>
Subject: Re: [PATCH 2/3] kcsan: Introduce ASSERT_EXCLUSIVE_* macros
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=b6YmUZtq;       spf=pass
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

On Wed, 5 Feb 2020 at 22:33, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Wed, Feb 05, 2020 at 09:43:32PM +0100, Marco Elver wrote:
> > Introduces ASSERT_EXCLUSIVE_WRITER and ASSERT_EXCLUSIVE_ACCESS, which
> > may be used to assert properties of synchronization logic, where
> > violation cannot be detected as a normal data race.
> >
> > Examples of the reports that may be generated:
> >
> >     ==================================================================
> >     BUG: KCSAN: data-race in test_thread / test_thread
> >
> >     write to 0xffffffffab3d1540 of 8 bytes by task 466 on cpu 2:
> >      test_thread+0x8d/0x111
> >      debugfs_write.cold+0x32/0x44
> >      ...
> >
> >     assert no writes to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> >      test_thread+0xa3/0x111
> >      debugfs_write.cold+0x32/0x44
> >      ...
> >     ==================================================================
> >
> >     ==================================================================
> >     BUG: KCSAN: data-race in test_thread / test_thread
> >
> >     assert no accesses to 0xffffffffab3d1540 of 8 bytes by task 465 on cpu 1:
> >      test_thread+0xb9/0x111
> >      debugfs_write.cold+0x32/0x44
> >      ...
> >
> >     read to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> >      test_thread+0x77/0x111
> >      debugfs_write.cold+0x32/0x44
> >      ...
> >     ==================================================================
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Suggested-by: Paul E. McKenney <paulmck@kernel.org>
> > ---
> >
> > Please let me know if the names make sense, given they do not include a
> > KCSAN_ prefix.
>
> I am OK with this, but there might well be some bikeshedding later on.
> Which should not be a real problem, irritating though it might be.
>
> > The names are unique across the kernel. I wouldn't expect another macro
> > with the same name but different semantics to pop up any time soon. If
> > there is a dual use to these macros (e.g. another tool that could hook
> > into it), we could also move it elsewhere (include/linux/compiler.h?).
> >
> > We can also revisit the original suggestion of WRITE_ONCE_EXCLUSIVE(),
> > if it is something that'd be used very widely. It'd be straightforward
> > to add with the help of these macros, but would need to be added to
> > include/linux/compiler.h.
>
> A more definite use case for ASSERT_EXCLUSIVE_ACCESS() is a
> reference-counting algorithm where exclusive access is expected after
> a successful atomic_dec_and_test().  Any objection to making the
> docbook header use that example?  I believe that a more familiar
> example would help people see the point of all this.  ;-)

Happy to update the example -- I'll send it tomorrow.

> I am queueing these as-is for review and testing, but please feel free
> to send updated versions.  Easy to do the replacement!

Thank you!

> And you knew that this was coming...  It looks to me that I can
> do something like this:
>
>         struct foo {
>                 int a;
>                 char b;
>                 long c;
>                 atomic_t refctr;
>         };
>
>         void do_a_foo(struct foo *fp)
>         {
>                 if (atomic_dec_and_test(&fp->refctr)) {
>                         ASSERT_EXCLUSIVE_ACCESS(*fp);
>                         safely_dispose_of(fp);
>                 }
>         }
>
> Does that work, or is it necessary to assert for each field separately?

That works just fine, and will check for races on the whole struct.

Thanks,
-- Marco

>                                                         Thanx, Paul
>
> > ---
> >  include/linux/kcsan-checks.h | 34 ++++++++++++++++++++++++++++++++++
> >  1 file changed, 34 insertions(+)
> >
> > diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> > index 21b1d1f214ad5..1a7b51e516335 100644
> > --- a/include/linux/kcsan-checks.h
> > +++ b/include/linux/kcsan-checks.h
> > @@ -96,4 +96,38 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
> >       kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC | KCSAN_ACCESS_WRITE)
> >  #endif
> >
> > +/**
> > + * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
> > + *
> > + * Assert that there are no other threads writing @var; other readers are
> > + * allowed. This assertion can be used to specify properties of synchronization
> > + * logic, where violation cannot be detected as a normal data race.
> > + *
> > + * For example, if a per-CPU variable is only meant to be written by a single
> > + * CPU, but may be read from other CPUs; in this case, reads and writes must be
> > + * marked properly, however, if an off-CPU WRITE_ONCE() races with the owning
> > + * CPU's WRITE_ONCE(), would not constitute a data race but could be a harmful
> > + * race condition. Using this macro allows specifying this property in the code
> > + * and catch such bugs.
> > + *
> > + * @var variable to assert on
> > + */
> > +#define ASSERT_EXCLUSIVE_WRITER(var)                                           \
> > +     __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
> > +
> > +/**
> > + * ASSERT_EXCLUSIVE_ACCESS - assert no other threads are accessing @var
> > + *
> > + * Assert that no other thread is accessing @var (no readers nor writers). This
> > + * assertion can be used to specify properties of synchronization logic, where
> > + * violation cannot be detected as a normal data race.
> > + *
> > + * For example, if a variable is not read nor written by the current thread, nor
> > + * should it be touched by any other threads during the current execution phase.
> > + *
> > + * @var variable to assert on
> > + */
> > +#define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
> > +     __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
> > +
> >  #endif /* _LINUX_KCSAN_CHECKS_H */
> > --
> > 2.25.0.341.g760bfbb309-goog
> >
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200205213302.GA2935%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN4vyFVnMY-SmRHHf-Nci_0hAXe1HiN96OvxnTfNjKmjg%40mail.gmail.com.
