Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBP6H7WAQMGQE7LY7LLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id CE48C32B689
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 11:24:02 +0100 (CET)
Received: by mail-ua1-x93c.google.com with SMTP id p13sf1857359uam.22
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 02:24:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614767042; cv=pass;
        d=google.com; s=arc-20160816;
        b=yLLhmnBVDVn5W7O/ewp3cYyIT5Anu6c4ahPE4YecDyBslLrVd3tdqRkQ9Xn8lg6Etp
         v/yubPXwheicyV8ScXEsHrzP7nUxWUDdhnJM4i1uOJddZGp7s7IoP31OCXv+TGYg0heR
         knYT1BhVrED2kCTUQ+eKAeFlaXBQG5zhaLcoSQmc/Apigzrmt/FYyEJtE414CmAh7TGM
         Q/o6jx2VxqBC/phLST3sUiVr1C8GNUUuZeMAIc4o4uSZ3LfRSvQ8F/WnPzNz3BFOVN04
         uvQdJTj+eMPfBdD+qozJeldAeQ2gGAtdCbwhYniBUqaF/RhVn4gW9bzYatPJqQuuQ7WR
         x/jQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9tknla1NVlRlPhHQIU8NlY8Og9WolJ7ZOgw6SnHqvFs=;
        b=ps5VnSkFF1j8Q4jCxd81Dbx520dFOPiP+8BcMpob1qDlSHj7RohycjtYb4a4WlRoVX
         RSn/AeEsNEmT1HozK046IZYa5kaP+ZtDkOZgnz9XDjBhgo3CfJ2UzSqubKPUUekMUR7Y
         id3i1utGnuFyd0vNjt6+D9GM+C6TvkfdPjk7l5HWlCwc9Ep9KhHvUcZZYOpoHFVhvG+i
         9OMELmny63D178uxBRr9M8tKosGpANhJAulLZ1VCh5umWLfzYA+9fR/xEgwYJmdfnjly
         ixHKLS6UJSVETcslsk3wio8JYC0BrLqOtQu6ZLq/mysT8F+UuiyNwZcX23qdLyrY4O3s
         E3cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=mK8uAQYu;
       spf=pass (google.com: domain of srs0=ywzk=ib=linuxfoundation.org=gregkh@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ywzk=IB=linuxfoundation.org=gregkh@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9tknla1NVlRlPhHQIU8NlY8Og9WolJ7ZOgw6SnHqvFs=;
        b=MWzVyI9eQkl04cvQk7ZrUtZ6hJXKxX42zOGfHLbmclR9YGngt6p9mfQQUUsgAsOpFH
         LIcj70z40vBzhOuTZxYMBGJikhSt2dH7DiUolX7oPjKQ4CClz4Kse5U2MVNixtIVL1T/
         r30zfFi2k6WaJ3pGlgBPyZ3wxYNBJxBAjEe3HSJdBVKXYp4iLhYw0tU+T3LwjdkPsOVm
         JxKXzudVaft3z+g0Rwa7e0NpaZRs+tMCGT+uY+NkL13fm51GEc7yqhjRA4zxfg6z26My
         RqLdpMdeM34dOhZ049Q1B7Q5NmrQV1SX5pmDmsM3uebkd1v8rgiTvCIFK1ogIn+93aZJ
         YroA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9tknla1NVlRlPhHQIU8NlY8Og9WolJ7ZOgw6SnHqvFs=;
        b=niibvdspKDNPsEkU3bQjvelyexBQf3LeQ7DXnf9gKHsUYRTkkwyBbYfLnIsSNgN9iX
         YsnTB6TglJheiGCwX9xBGc8PYagTI+3Rn4/ipcqoI2kXDaFYvfqviB5Xl8cZW5FxiM6y
         Jw/g0Aw7akcZCLXl2wWeBxqVF+aopFrfg8m19MSAmpXoeZbtYi6v9RfsIKbGXD2V+lXL
         gH/n+OlZuzyi9OtAQcviX8Br68LWkvL0qSTvP2RWhPX+NdolsdMz1a5UuunbUmYho63R
         gAj6qJHfl4p2aYg4Dm+XFGzMBvKB0LAiPmKaZ+Cg1OmIvn4tMUb70Mfp3xIojpHqo7kS
         CskQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530cBVn5w+g9jGKhCE4r4JStxf1f6kviLNZHwlNYofns2W7kbh2f
	VCWlX2Aib9Zvp5ZaUYHX6Ys=
X-Google-Smtp-Source: ABdhPJw4YIc1M8xFhFQnOuevTevnKhGGTEzn6znn0NGdugwkiWdzHwwp8r39SQ5vyIIEbuHHF/9Tcg==
X-Received: by 2002:ab0:382:: with SMTP id 2mr4039671uau.46.1614767039861;
        Wed, 03 Mar 2021 02:23:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:319b:: with SMTP id c27ls195399vsh.6.gmail; Wed, 03
 Mar 2021 02:23:59 -0800 (PST)
X-Received: by 2002:a05:6102:89:: with SMTP id t9mr5361119vsp.28.1614767039393;
        Wed, 03 Mar 2021 02:23:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614767039; cv=none;
        d=google.com; s=arc-20160816;
        b=sO98zbCaBgi/D/Ma3LVPQDTNHkeVCkyBjJLUvE7d6HxoN1O9B73I4l1pP8jfKQiKQJ
         ZOgqURsGvuHkiwdpPdXYKcbzCXE6FZXiepB/4WHmRova8ZdEON7PctD5tQw1y5oF1ka0
         Fy8pZwokjkoZrgGt7+6Pk8f8LUqtaqtVTAgBMps5rK4Z/sdfuN7WPdR04ioGwdpPNDvQ
         1CFuXDTcBSq4JFrPtUwLlwYDmBxXdeZQtZ+P1cBBxIxQpQzK+doJ9FOLZrdTrMqfrN69
         4Vq5JJdC6X0rq0Efb2BYr0i3TosgHNqyefOMeATAFNGKLHzApzafWJ4fDpyBfqaUT4G9
         VDQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XJSPnpXOUcQ9Lu7FqcpViyjrzP6H/GvGt1ms5kzy3AQ=;
        b=NwLmSTLWaCdVUtJHQeXDMvn2xmZUY81UcMB8LeSyNmu3ade8fqGD9SCJEIkizLVBGI
         O1bYinQCewvdXXuZfH/9zjKZvyS3EWjjRuz/+G4WculJZtP3t9E43rn/9mHQNRrWM1Fn
         it3BMmki3aWKb7gMxWIiBdsAC4vWpTBpfi/0umw0OmWMqeVzcbF/ErxZu88gZvcVQI1W
         TSinnXoIPfoV9UX9FFrtR+K0gJtMRnKia90jlQCL+K3q7eYNeQToc+ycbMOyp+wuzvRP
         fNvxLXx/19Tfq0ojGPWKfprUxj5W2Bm57f8wrmplOwRNuPzz1ajxftlOPlfdRg9KAWS5
         V3Sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=mK8uAQYu;
       spf=pass (google.com: domain of srs0=ywzk=ib=linuxfoundation.org=gregkh@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ywzk=IB=linuxfoundation.org=gregkh@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i18si11684ual.1.2021.03.03.02.23.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 02:23:59 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ywzk=ib=linuxfoundation.org=gregkh@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 63150601FF;
	Wed,  3 Mar 2021 10:23:57 +0000 (UTC)
Date: Wed, 3 Mar 2021 11:23:54 +0100
From: Greg KH <gregkh@linuxfoundation.org>
To: Marco Elver <elver@google.com>
Cc: rafael@kernel.org, "Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	stable <stable@vger.kernel.org>
Subject: Re: [PATCH] kcsan, debugfs: Move debugfs file creation out of early
 init
Message-ID: <YD9jujCYGnjwOMoP@kroah.com>
References: <20210303093845.2743309-1-elver@google.com>
 <YD9dld26cz0RWHg7@kroah.com>
 <CANpmjNMxuj23ryjDCr+ShcNy_oZ=t3MrxFa=pVBXjODBopEAnw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMxuj23ryjDCr+ShcNy_oZ=t3MrxFa=pVBXjODBopEAnw@mail.gmail.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=mK8uAQYu;       spf=pass
 (google.com: domain of srs0=ywzk=ib=linuxfoundation.org=gregkh@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ywzk=IB=linuxfoundation.org=gregkh@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Wed, Mar 03, 2021 at 11:18:06AM +0100, Marco Elver wrote:
> On Wed, 3 Mar 2021 at 10:57, Greg KH <gregkh@linuxfoundation.org> wrote:
> >
> > On Wed, Mar 03, 2021 at 10:38:45AM +0100, Marco Elver wrote:
> > > Commit 56348560d495 ("debugfs: do not attempt to create a new file
> > > before the filesystem is initalized") forbids creating new debugfs files
> > > until debugfs is fully initialized. This breaks KCSAN's debugfs file
> > > creation, which happened at the end of __init().
> >
> > How did it "break" it?  The files shouldn't have actually been created,
> > right?
> 
> Right, with 56348560d495 the debugfs file isn't created anymore, which
> is the problem. Before 56348560d495 the file exists (syzbot wants the
> file to exist.)
> 
> > > There is no reason to create the debugfs file during early
> > > initialization. Therefore, move it into a late_initcall() callback.
> > >
> > > Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
> > > Cc: "Rafael J. Wysocki" <rafael@kernel.org>
> > > Cc: stable <stable@vger.kernel.org>
> > > Fixes: 56348560d495 ("debugfs: do not attempt to create a new file before the filesystem is initalized")
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > > I've marked this for 'stable', since 56348560d495 is also intended for
> > > stable, and would subsequently break KCSAN in all stable kernels where
> > > KCSAN is available (since 5.8).
> >
> > No objection from me, just odd that this actually fixes anything :)
> 
> 56348560d495 causes the file to just not be created if we try to
> create at the end of __init(). Having it created as late as
> late_initcall() gets us the file back.
> 
> When you say "fixes anything", should the file be created even though
> it's at the end of __init()? Perhaps I misunderstood what 56348560d495
> changes, but I verified it to be the problem by reverting (upon which
> the file exists as expected).

All my change did is explicitly not allow you to create a file if
debugfs had not been initialized.  If you tried to do that before, you
should have gotten an error from the vfs layer that the file was not
created, as otherwise how would it have succeeded?

I just moved the check up higher in the "stack" to the debugfs code, and
not relied on the vfs layer to do a lot of work only to reject things
later on.

So there "should" not have been any functional change with this patch.
If there was, then something is really odd as how can the vfs layer
create a file for a filesystem _before_ that filesystem has been
registered with the vfs layer?

thanks,

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YD9jujCYGnjwOMoP%40kroah.com.
