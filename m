Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBNFQSODAMGQE5YH4GWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id EDAD43A4F90
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Jun 2021 17:52:21 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id nl8-20020a17090b3848b029016df4a00da9sf8089223pjb.6
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Jun 2021 08:52:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623513140; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Oxreh3ggyhUhbhWuyK2JD9yXkMa7yrVshrrrcXvlsMmcsFRYJNzfqoAXneCURc6SU
         riQ61HwwBQ7aMB1HZ67ZriOaMQVovtEwGlZj/3kAfFuto3gVVwg0wk/RpZi9852r0156
         k95jiEg2lxe6R+rcrsobpC3iOe83Kvlwhbwp2DByfp6fOxO7NEuSgvCFk7YQEqQIeAT6
         4gCW2I4TIEYF45EmIgfXH14XnLSPkmJy4ZUXa6Oi2VTr1UoU9X/sySpaf8NR+0gB6+1Q
         Guc/kg7ihxxWXeZjtUerYD/jnjzzTqcm3jajENlDHPBBHemhf6OyZl5+XI3DBC6UgFE8
         uy5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=EqYlg2e7frFBqeimPc3Kd8Vl/MRbbqkBpC6M1kyOD8U=;
        b=s1lQgui4lGtW7DD5xk3MWdG+N5qoqEyO01Zp57vVDb/do2TL1rDonQRappW8nTeTCZ
         2X6nPi1eFzTGkwr2OXY7xhjQbCIy7GjHQVCruSNJoGzL+/CEraWRQ23Jzjq2uEzv78QC
         d2cMOESYWohN0DOIg4pitPZDvVMQXXrsRlfTpEJcYkAJM8Ylxv0pyCgh/1GMp8guspxY
         0nixozXF+0CAcYLj3tSi2Z6Qlk2rIvETuEhPpmDUgapgopPHP4EvXb2Vrade+yAVz/H3
         P8vycUpPS1ytV84ZQsfFjioDGBfgBz1110j2s7Pp4wJrFvbNisuA08n/98tyGUlBQy+I
         Oc7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=Q1VvwNIy;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EqYlg2e7frFBqeimPc3Kd8Vl/MRbbqkBpC6M1kyOD8U=;
        b=IvFSXAIh9q+7tTLnqvbQjHK6Nwxy2//6Z9jauix1jnKKX2pKEatbTSlGxjVqd0Dj/u
         tUTFYnTIsL6Oamajnkx50saN008NDGwBQz03TqVv9/SyK4yX9qSWd9Ij/kqofPBAt130
         PvdnPpGw3conJk2gR2oQndS56rmQLi470a63iAbneSq7SWOtr6epB/8ryvrHnHlYw2iS
         zVOkEmVf8mbLr7kx8B5NgMWHIF7HHOaghD3X5c242Cl3+FXLwAk/G2ZXFkmeZSCNv+hC
         w19hIL0L13TZzhbYGiYNtrCUl9UNeJTvROKJyqNCRVDNEVQ4PECMtRj9tb5lhHrsrB8S
         kBvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EqYlg2e7frFBqeimPc3Kd8Vl/MRbbqkBpC6M1kyOD8U=;
        b=lhZMEO7K1ZA7MxJ6t/7UJh/5WJ/9m9sR8pBcNGZ2x5u+Z+rtGqjNE0xjlMLI2pt6Z9
         TFJomJzK3nDse0aLqfZ+PmaFEeFXnN9rPFgFG2jnyWtISXIGwFl8gKgCVOPjatmJo0qm
         Y/Eig5/DuKGUUDLmdxXIbbdfBImfWrJgJcoMtGe+qFD3Q4IVSMLSwgA1cd1fmCkht3R8
         E4Y95+qkO83NOJyLlHM3bN/OMcVoDIVsUyVnSmi9Oy3Axj68sQILs1iBY5/d+FSQuFDO
         raI5Xg7E1lhcpbNDHdUrDyrShdunytuxuyJzR6L+TG+aN7mMZ1EL2gph9noKMBM3yRn2
         eHyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ftEHx/dBgDOlijGtZcpnG++XLRHz5QbyIZPyPQnPGsszWWxu6
	8VhIBWDz8yydJy1oFmnUQYA=
X-Google-Smtp-Source: ABdhPJwPYWSVNjnxF/TXrNgJz1Cujvj4FSwHzvnB1dL2BY/Gg6KlbcofahniMOTHkK8DDgBLT9ip/g==
X-Received: by 2002:a62:8c0d:0:b029:2e9:e1f4:c433 with SMTP id m13-20020a628c0d0000b02902e9e1f4c433mr13484538pfd.24.1623513140487;
        Sat, 12 Jun 2021 08:52:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:17a4:: with SMTP id s36ls4882767pfg.9.gmail; Sat,
 12 Jun 2021 08:52:20 -0700 (PDT)
X-Received: by 2002:a63:368f:: with SMTP id d137mr9145219pga.93.1623513139953;
        Sat, 12 Jun 2021 08:52:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623513139; cv=none;
        d=google.com; s=arc-20160816;
        b=TvMTpF+9CRcEqoDGzHiB/TwtWN3WEdrviFd+UW3I65K5aIO3xp7L0h7cbxxTQOGT5N
         FHlDudpCBFUxIqBhBSx5ixCi77Bj+NnNvE+zmdZQXsMrVlcSpHyRPvMgdlcAPAWfJMO3
         Ol6Sz1UA6UlR1hHN2GJ1S9RE+ACnj3LsPDyuYwXWpskZLhXadS7EnPrmWLXoy0YN4pG4
         3FxzhMvo2XdZ0fK/buKSQqYeiXbOH2mBk37Sfe0MQRJjbCF++Nvb7L6a0z2bx/EUQnGU
         JxyE5uSHKewolsNuAEPEaQgVvdLuVvToitIB8M/Uo7NnjX41TcQyxbDsePnE99ZP2/Lm
         8h5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XCEI819buUZaBFkvABEGT8AVcHevd/tk7Crnu6XSBPQ=;
        b=X22AmSBm/GqL7MZ6py1Z9z+mmwLv17T6XYLvKnUjHkYSepB89aETUTmPKhlNI7Y9b3
         huvc5judXCl7IcGevHmOaubZrL3SxX6I8CAQM/vHGlbeOpGGWeXjzXOco4PIGkWdQ32D
         RbhbBySAT1MwgGsVwAjtpaucXTsdECNZ9xfkGrRka2z9UhNbt6XCST3xrN83smbp6KJD
         peGlqaWubdhZzcuTRJEcf5gFO0mcUKep/reWmFEX9uMJswSbZB0lFzxdBAcx1JcUZUir
         pCPq2yyiJTXMPFjENYoOX4Q7j0wWz1+096umce3/GiDnsCj6cUi8vy06gARkSkUHTH/o
         xEfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=Q1VvwNIy;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id mh11si1147361pjb.3.2021.06.12.08.52.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 12 Jun 2021 08:52:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 16AAD610FC;
	Sat, 12 Jun 2021 15:52:18 +0000 (UTC)
Date: Sat, 12 Jun 2021 17:52:17 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Marco Elver <elver@google.com>
Cc: Kuan-Ying Lee <kylee0686026@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH v2 2/3] kasan: integrate the common part of two KASAN
 tag-based modes
Message-ID: <YMTYMebTk7tJEmXX@kroah.com>
References: <20210612045156.44763-1-kylee0686026@gmail.com>
 <20210612045156.44763-3-kylee0686026@gmail.com>
 <CANpmjNMLzxMO0k_kvGaAvzyGoyKxBTtjx4PH=-MKKgDb1-dQaA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMLzxMO0k_kvGaAvzyGoyKxBTtjx4PH=-MKKgDb1-dQaA@mail.gmail.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=Q1VvwNIy;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Sat, Jun 12, 2021 at 04:42:44PM +0200, Marco Elver wrote:
> On Sat, 12 Jun 2021 at 06:52, Kuan-Ying Lee <kylee0686026@gmail.com> wrote:
> > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > new file mode 100644
> > index 000000000000..9c33c0ebe1d1
> > --- /dev/null
> > +++ b/mm/kasan/tags.c
> > @@ -0,0 +1,58 @@
> > +// SPDX-License-Identifier: GPL-2.0
> > +/*
> > + * This file contains common tag-based KASAN code.
> > + *
> > + * Author: Kuan-Ying Lee <kylee0686026@gmail.com>
> 
> We appreciate your work on this, but this is misleading. Because you
> merely copied/moved the code, have a look what sw_tags.c says -- that
> should either be preserved, or we add nothing here.
> 
> I prefer to add nothing or the bare minimum (e.g. if the company
> requires a Copyright line) for non-substantial additions because this
> stuff becomes out-of-date fast and just isn't useful at all. 'git log'
> is the source of truth.
> 
> Cc'ing Greg for process advice. For moved code, does it have to
> preserve the original Copyright line if there was one?

Yes, it does have to.  Unless you want to talk to a lot of lawyers about
the issues involved here and can defend the removal of the copyright
lines to them.

So please keep them.  Unless you can get your corporate lawyer to sign
off on the patch that does the removal.

thanks,

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YMTYMebTk7tJEmXX%40kroah.com.
