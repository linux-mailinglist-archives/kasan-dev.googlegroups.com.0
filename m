Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRXU2PXAKGQEBKVGQ3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3d.google.com (mail-yw1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E178D10360C
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 09:33:11 +0100 (CET)
Received: by mail-yw1-xc3d.google.com with SMTP id t19sf17310894ywf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 00:33:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574238790; cv=pass;
        d=google.com; s=arc-20160816;
        b=IElDJIatHKre78n9oeyGkcmF901uMZzP+U6fKgqjK77HvNKgsHD5SIsWORQpV9lo8B
         U2lObTS385BhVi6Qjouqns97QWxFtKIOXbOIyQRlNjvi8hnF+5Vq38bF6/eUVpmFDBaw
         P3t4+ROpPN+owVhOprJhB8b6dJZsRlVa+tN1YkydTfHL9QtrOhsuJlUNFJpBXfpprW8h
         ciPvjuOms5V4lQeY/Rro4zkbUTXt/CKxfBvmOKF3aw2bEpYlD5WHAK5tx2uQKgjpAEpb
         B1jy0dOKNuRjAlkju92ndIqoKkGzihk0XNZWoAs/wUuImSv3qujATq2xf9W/1sPhxisG
         GFwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=76Xwf7eubbnDiwXYBSMW48ohig10k5zSEFZ/sVrbaDQ=;
        b=EYCwfwZ5zf49IQ3g+FgmN9n1N/T0CcOYlRLuyyAXvdpAbx71Mnm3se7l7RAaBRhyWT
         Qne6BB9Fcr1OwR8tvNPe5n1VYUKRm7B2z27HEAphumPFbnJwkbUFs4aMr6p5gPPew1Z9
         1y1TyONVHm6MLdHkpEHLdUZB8R9bxqYMC/KPp1z2zVi1ZSCUfL072VPtW9zYPHmLRO3N
         ec9QqDBI+ofsxzHoy8SRd7ePWHS7wY7ITveVwm5ytsowz45mImyE7AP4rnSvvgh84FfZ
         d6zjgGV/W8RSRbXXDBWxhaiUGJPVuCDHF39SStssRNfsfWKgp8BNKDAvwAyd09Ji8FwP
         9cNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OGrrZDpa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=76Xwf7eubbnDiwXYBSMW48ohig10k5zSEFZ/sVrbaDQ=;
        b=MZPNL+E/AvjG3h6HM0rAOoFYhxowcxveaLk9bPRDHRVWzvbpb0Fe1zk0e2HCIPnD8m
         b6TV6qeW8Pu5loUVUfMWuw5uEMN2cUdMx2jWSLeaKxgjNrQaC7ZhxRb4RR4CqoPjJT1G
         /sHYzlpaamlVIRmT/auV0HfD2ceIsU+s5jaZgUDY0qvzaVuPTB+ZKb5iddJ1zpkjHhVH
         MqmvsYu7EzbVUro0O5XojV3MQtSRa8tEBVWDVkVT/S5FououxxMNGz8uZ+PEDj+Pss2i
         YYi6Jf49p9kDQqf32A9T/e6YKqZwpm9ryDdXoXBVaJ9sPZhL5S81kn5pOIsAPCLIvwVD
         3ckw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=76Xwf7eubbnDiwXYBSMW48ohig10k5zSEFZ/sVrbaDQ=;
        b=CLHr7U5utvSLk4dRV7xumOhVnuPxzGV5eiAXQJtxpxsNzqvkQX7XhBF6gxuwVa8kRu
         dryH4772wilD7Fz6NKYMDSji12NMsFwd2gNNu0hwQSZfxn4FgHJ2EFZh25B9EyNR/DHx
         F2okX8jOcB1ijA5nGBmL5xR3/6jHVYMFJ8TVEeJL2EMjvr003SmLquxWjO5pzSu54Ogk
         haeCEZG1VXBsqtO9KcjbOocI/kEv7Ggsr9988hfYPGsCRgXFxKiqr0oZHzleSg43avdo
         0kjgEUXEDpYs6QK7ApRWtnHRbIGqAPtaDDMXtzl5MWZujSToESYmKJKSGP7xIJ0BpqNl
         57Fw==
X-Gm-Message-State: APjAAAU2iWILy1jn+xNfMqySFfL6P9pFAwwj/Zrxyt1ave7Lyr+kF7Lm
	XQvqsm/syVNTdOeOfkkhvz0=
X-Google-Smtp-Source: APXvYqzBPyqzL46ZdMU7IlVhtKmE3aWaD1mI1aPtFS6CxjCJN9qKpxQiH5EVK8675d12gvsdyh87wQ==
X-Received: by 2002:a25:b57:: with SMTP id 84mr1007987ybl.103.1574238790531;
        Wed, 20 Nov 2019 00:33:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:98c6:: with SMTP id p189ls152067ywg.13.gmail; Wed, 20
 Nov 2019 00:33:10 -0800 (PST)
X-Received: by 2002:a81:a10f:: with SMTP id y15mr847868ywg.96.1574238790109;
        Wed, 20 Nov 2019 00:33:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574238790; cv=none;
        d=google.com; s=arc-20160816;
        b=nNGp8MHMQp5QDCDKodsh5flg1ZPyYqlso8Q9aYbAgradLl0WMeY8f7/fVjJsoK3or2
         ovsW6Yc3mIGrxx6KPSm5pApv0HYPwrrfhCgtEF29fxNv0R+eLmPACFiUUN1Flg5oIArB
         DY9IrDdFMrJGncTyIjaQ3KEfxxPlx3oK5I89fr2/oxakp0I+vSURrFwCAF1pS9TVB5x9
         kb8jZL7AjseOB6Sf1fyZCKreDl93Ndkm1x8pDwuJYUxmA9k1QvWB/0/BVZZ9q+Odi5tP
         is4tbYwGs9EAwRQMw2Ic07nRXaEUClGrP1HgUfzQr39kJkQJHp3uAfAzpklCpyq6ck5J
         Uthw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PED6ZYCgPaRUxZYECcuhZmbEWK8QVrh8hGaeK/4Dmy0=;
        b=YSY7NesaY7WYwtKmD7e8m8+73Hz+HI25yljNk6yelH1N5Q4Alm3gcWDxOTkGya0q0h
         MvKSZCOx7LPa8zDpsyWuJhcevxR7eovK63oHjrqH05Jd5aZawYzZIOQw7VStF7tV1BKn
         cv5hm2joM4vuoeeW43FsAODPoBxjW4N0yABsMNVOypkJpJYgP/6iSZOWYYMr3VycAINU
         CJt6ApWbrqg4zJRMVMxIzR8+DPPC29dltEVjFrKAAIehMeShI4kqfjSuh6ld834Irfjl
         8bNpFuDCgORTpaPwmgQQrMG+5VgA2k4jQ9LYeGD8AAmjQtMqT5UbtNVFsTKTqM3FE2wd
         kA9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OGrrZDpa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id u3si1394994ywf.4.2019.11.20.00.33.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 00:33:10 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id c14so13498541oth.2
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 00:33:10 -0800 (PST)
X-Received: by 2002:a9d:3d76:: with SMTP id a109mr1082964otc.233.1574238786622;
 Wed, 20 Nov 2019 00:33:06 -0800 (PST)
MIME-Version: 1.0
References: <20190820024941.12640-1-dja@axtens.net> <877e6vutiu.fsf@dja-thinkpad.axtens.net>
 <878sp57z44.fsf@dja-thinkpad.axtens.net> <CANpmjNOCxTxTpbB_LwUQS5jzfQ_2zbZVAc4nKf0FRXmrwO-7sA@mail.gmail.com>
 <87a78xgu8o.fsf@dja-thinkpad.axtens.net> <87y2wbf0xx.fsf@dja-thinkpad.axtens.net>
In-Reply-To: <87y2wbf0xx.fsf@dja-thinkpad.axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Nov 2019 09:32:55 +0100
Message-ID: <CANpmjNN-=F6GK_jHPUx8OdpboK7nMV=i=sKKfSsKwKEHnMTG0g@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] kasan: support instrumented bitops combined with
 generic bitops
To: Daniel Axtens <dja@axtens.net>
Cc: christophe.leroy@c-s.fr, linux-s390@vger.kernel.org, 
	linux-arch <linux-arch@vger.kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OGrrZDpa;       spf=pass
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

On Wed, 20 Nov 2019 at 08:42, Daniel Axtens <dja@axtens.net> wrote:
>
> > But the docs do seem to indicate that it's atomic (for whatever that
> > means for a single read operation?), so you are right, it should live in
> > instrumented-atomic.h.
>
> Actually, on further inspection, test_bit has lived in
> bitops/non-atomic.h since it was added in 4117b02132d1 ("[PATCH] bitops:
> generic __{,test_and_}{set,clear,change}_bit() and test_bit()")
>
> So to match that, the wrapper should live in instrumented-non-atomic.h
> too.
>
> If test_bit should move, that would need to be a different patch. But I
> don't really know if it makes too much sense to stress about a read
> operation, as opposed to a read/modify/write...

That's fair enough. I suppose this can stay where it is because it's
not hurting anyone per-se, but the only bad thing about it is that
kernel-api documentation will present test_bit() in non-atomic
operations.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN-%3DF6GK_jHPUx8OdpboK7nMV%3Di%3DsKKfSsKwKEHnMTG0g%40mail.gmail.com.
