Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEGJ7WAQMGQENY5J3NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id BAF9232B68E
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 11:27:29 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id y12sf17097153ilu.14
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 02:27:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614767248; cv=pass;
        d=google.com; s=arc-20160816;
        b=UoQk9MD4gh0Ycp9CKTQChVApDIA7tfA7QaTWYp35lODX45hhK0AAIPBVg74y69v9fJ
         ExvjNPnfmt+jawD4hG3UoyM6XODsQPe84v+Gj2fXUyuOoxlK7sNrOac7etLaeJwBjhdn
         KgZSs4c03qTLrg7h03FVJS6uKFxIUgNdjcti7PvP+O41nLD7VKK7ITIoaNWgqxTJ9ia9
         tYIc1d486fkRw8hsoqN7ntgcim55pcfTeNPreH0Z586zcbZezF8iQ65iMuoO15doAx5P
         hoPvdJiYYyHsnudYbZjokzDezZuo/6PWUar4xLoPQmgkQmejNXrJQ6LpAA3sf9RaT9Yr
         0crA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OGehOH7eKYbqRAZZGu9MdTwCZHZq7lGo1XxiLX8O1vg=;
        b=1DKBy1Wy6F/H1VV1Vjw46BjShdavEq5QtujGH5dwBsipR0cGJBBBXyKsp2dlHCAO1+
         hOxvWNdd5kE0x4vfCqIN/gkfQ4DGTrjWxfGPXDeKEuOGAj0VqwioIr445/XFm5pKP3ew
         veFU17hJQoLZVl6Shre87VXiB7WMlsZEP6NU/RsZZoXqmqmulWYZK/vc4cFx5yl+0D3Q
         fZLgKREVTn1BpeBgLAM/hYl03Ua/iUPey7T71dryr94l0zs0JSgcwucVQ5DrPs49bfMb
         qSe9nXVuS6V/+a1xhLnOtAFqfG7k7ampE9SPGlj+4gPxEruOXlUlY/BnoZJ1WvOhuIjQ
         cuxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TPsmqF4D;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OGehOH7eKYbqRAZZGu9MdTwCZHZq7lGo1XxiLX8O1vg=;
        b=rAczKmwPXVAvItfUaTj7WOMJvFgTCebVR+oYBUD7i9pJNMGcd6vy8a9vyIJlZG9WLC
         LVz9b0J0GZpFgxXyy+t/29iZtyPkX+Tt2fpigkBQB7R/WgTzkP+9byeY6ma1d+CByVxh
         byOlXu3KAp1WnhoIOZEnytjvvhLvlKtmspat5C/wdonts+H3pBBneN3DywNr/nvsrrZh
         4IU2nI3TxfV4YnKJ8rX3JTfgCHQo1pZzG9HIqzjdbN6e8kyBi3GSDEifpcdqtR+QOzSA
         B4P7eoLPqDqL70I8f+nN9duBg7SmFmCh8Z7YVX9GELBKErPz9x+bOeNt+VeiBtg+wuk3
         ENFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OGehOH7eKYbqRAZZGu9MdTwCZHZq7lGo1XxiLX8O1vg=;
        b=hFF97ZtJcKxfkgKUrbBrttMTHjJuytvVraoYP964bQdxGzQMpOHNxvDuKjDA0gg1B1
         qWF3fwFtIbLRDRlXO3bylF262mcZoef84oo0ZAFAUGLbKA/9OYLgDTvmF+66K6ltBj5J
         ZTAqrXhGu/03uwNoyrMYplp8u6dBGOeLLP8OyER3yFqvMJI2w6T1Rrwg8s8kzcnNMQGI
         XO8+fH0rvbuzT4rL4wcQsefuURROvvdp04MV/NJ+3LfSiWKVPuITXAecpSs1ldPwOAR8
         lKCPW1uRdTJNJIooXpjn+DQFGyhBwfYtnvhTf0wsGqnu26Xrs9f7dTuC3scHQUpwGAER
         ILpg==
X-Gm-Message-State: AOAM53304g9ijruXeiPt8YWRkbBIW8LZf4cEZz9Pn2M296y+Hs+6qOih
	HhVuA5NL3f73atvMAv2Dhcs=
X-Google-Smtp-Source: ABdhPJxxu76gCRp25fgqnS7RvQ5sofOk6Ye26x5GI0Y2IXtGMtBQ4NWg3/Y+iW6nceaLN7jYxgdt1w==
X-Received: by 2002:a6b:5112:: with SMTP id f18mr2050036iob.196.1614767248537;
        Wed, 03 Mar 2021 02:27:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3606:: with SMTP id d6ls489201ila.3.gmail; Wed, 03 Mar
 2021 02:27:28 -0800 (PST)
X-Received: by 2002:a05:6e02:194e:: with SMTP id x14mr21975201ilu.218.1614767248231;
        Wed, 03 Mar 2021 02:27:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614767248; cv=none;
        d=google.com; s=arc-20160816;
        b=N8/V2QpFgJxszYbEC21AlZznq5Cal4e7fnCHZrVFDzf0JQavWlts9+HreWORvaMCGV
         di0CzFshZuWnZfE8b4yZru0G5i88kb8bFAw8aA4LwphVhOqSbFeYG9zcmarq5SjbmB2y
         Tc8IbLlK4MbyWuZeKE0g2UqSBvVz42ovzaN0vQwPHKMTvrvcaHaZOoRD/PDSlm2Qejuu
         c43I6REWhLjaSRZbMu8UM/eWgLH/2BK8LmwhlGEDxPL809j52vH0NS1SjxCIwbHX0vSI
         P9/E0fRXH6A2cp+SqhNWOgESXUf8Tg3wmtUDXfPeD82Jxkc8d5Sfi2xAP6J5MgPLgL33
         wQxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=94FU4aImSyveb72Fh42pjQwrSbJ+f3XzeivB4wSoR78=;
        b=dUFbtg3e8UDtNplMi3V29iwDVkC1TLwu3yMzVw+K1p7wPZvcpdqZ3oPSSrQPrj61Km
         cj7oedePN3dvI894IMhd3zxGM7i6jk+px3psgtpeLDRvCcevXDk1brFO/p9Gz2h2OmOw
         xtsUBIQQu4tlEn7Ayc+8kAfnHpQfVemaV7zDKCpmWxM56984Hp9hUdzPMQvUWAAiP9qX
         Wj+5JdWOFiLV+q9n59jLSOR4j5XTirSrnLsrQpWs2ncCk7fBLJOjVGyA+qL+68433FF2
         GugaZjpKgg9WSnQQhnmjKQx7M8PWpYvIavjAfU0ODweA2H81bBGCkG+fWeupb8B2vxTY
         S4Zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TPsmqF4D;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id g10si1805668ioo.0.2021.03.03.02.27.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Mar 2021 02:27:28 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id j1so25412190oiw.3
        for <kasan-dev@googlegroups.com>; Wed, 03 Mar 2021 02:27:28 -0800 (PST)
X-Received: by 2002:aca:5fd4:: with SMTP id t203mr6668726oib.121.1614767247769;
 Wed, 03 Mar 2021 02:27:27 -0800 (PST)
MIME-Version: 1.0
References: <20210303093845.2743309-1-elver@google.com> <YD9dld26cz0RWHg7@kroah.com>
 <CANpmjNMxuj23ryjDCr+ShcNy_oZ=t3MrxFa=pVBXjODBopEAnw@mail.gmail.com> <YD9jujCYGnjwOMoP@kroah.com>
In-Reply-To: <YD9jujCYGnjwOMoP@kroah.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Mar 2021 11:27:16 +0100
Message-ID: <CANpmjNPS7BXepA=G-Fbc_PEjeBhyc8PYEhzEO+TbWApGO7tL-g@mail.gmail.com>
Subject: Re: [PATCH] kcsan, debugfs: Move debugfs file creation out of early init
To: Greg KH <gregkh@linuxfoundation.org>
Cc: rafael@kernel.org, "Paul E. McKenney" <paulmck@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, stable <stable@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TPsmqF4D;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as
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

On Wed, 3 Mar 2021 at 11:24, Greg KH <gregkh@linuxfoundation.org> wrote:
> On Wed, Mar 03, 2021 at 11:18:06AM +0100, Marco Elver wrote:
> > On Wed, 3 Mar 2021 at 10:57, Greg KH <gregkh@linuxfoundation.org> wrote:
> > >
> > > On Wed, Mar 03, 2021 at 10:38:45AM +0100, Marco Elver wrote:
> > > > Commit 56348560d495 ("debugfs: do not attempt to create a new file
> > > > before the filesystem is initalized") forbids creating new debugfs files
> > > > until debugfs is fully initialized. This breaks KCSAN's debugfs file
> > > > creation, which happened at the end of __init().
> > >
> > > How did it "break" it?  The files shouldn't have actually been created,
> > > right?
> >
> > Right, with 56348560d495 the debugfs file isn't created anymore, which
> > is the problem. Before 56348560d495 the file exists (syzbot wants the
> > file to exist.)
> >
> > > > There is no reason to create the debugfs file during early
> > > > initialization. Therefore, move it into a late_initcall() callback.
> > > >
> > > > Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
> > > > Cc: "Rafael J. Wysocki" <rafael@kernel.org>
> > > > Cc: stable <stable@vger.kernel.org>
> > > > Fixes: 56348560d495 ("debugfs: do not attempt to create a new file before the filesystem is initalized")
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > ---
> > > > I've marked this for 'stable', since 56348560d495 is also intended for
> > > > stable, and would subsequently break KCSAN in all stable kernels where
> > > > KCSAN is available (since 5.8).
> > >
> > > No objection from me, just odd that this actually fixes anything :)
> >
> > 56348560d495 causes the file to just not be created if we try to
> > create at the end of __init(). Having it created as late as
> > late_initcall() gets us the file back.
> >
> > When you say "fixes anything", should the file be created even though
> > it's at the end of __init()? Perhaps I misunderstood what 56348560d495
> > changes, but I verified it to be the problem by reverting (upon which
> > the file exists as expected).
>
> All my change did is explicitly not allow you to create a file if
> debugfs had not been initialized.  If you tried to do that before, you
> should have gotten an error from the vfs layer that the file was not
> created, as otherwise how would it have succeeded?
>
> I just moved the check up higher in the "stack" to the debugfs code, and
> not relied on the vfs layer to do a lot of work only to reject things
> later on.
>
> So there "should" not have been any functional change with this patch.
> If there was, then something is really odd as how can the vfs layer
> create a file for a filesystem _before_ that filesystem has been
> registered with the vfs layer?

Ah, I see. I do confirm that the file has been created until
56348560d495, without any errors.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPS7BXepA%3DG-Fbc_PEjeBhyc8PYEhzEO%2BTbWApGO7tL-g%40mail.gmail.com.
