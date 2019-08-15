Return-Path: <kasan-dev+bncBAABBLM32PVAKGQEB4NJ76I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CFC48E30F
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 05:12:47 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id y18sf939729oto.21
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2019 20:12:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565838765; cv=pass;
        d=google.com; s=arc-20160816;
        b=qTdEDBpgcIyhurP4kQSyGb1ei4S678zKvmdJ2Hu6FNekvDB0vmAs9vRW3BUu6Qbx5T
         OxDkd4XzqzUnPOzxE7awCspJrQd5xwwY2jaVjbSOEtMgcFz4iZ6yhScbR0+0f5QLiwkZ
         FFgvVrbrs4PL2RDOARQBHUFNMoCk9OCBLbJbLRAebaPjh6Gfyl4F52WZN1ZW/w/MzpHo
         E9H3MrUsy1hGa0rraH7yweiQLcAxb1klt7SMr0ZiR2v3yuJlWHV13cLGZ+YETnVGImDR
         FITUFybtSk6cRYUtrISgu9HqPypuI5wqIYLFK8D7BtskJzN5aX/1PBYdyTL+sbN1UWLQ
         uRlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=VqJNovtZfyPYHdwDId7Es58q4mXtNATw+9rjnk6HIiU=;
        b=lCR02oYHEVtKgsjq46AhyTOY4Awdlbs+bza9eW0wP/0zyjk0efmWbFKCtQc+G4Fw4G
         TnjBP0M35oHAFncpnD+ODvW06A4F1RlHkVvm5oz4kAReBERKZfFJhZJIJphNSpzbe//g
         xl1WuBkgALdYo4+wQbvrwbrK52ryAbQ+8JBl4hM3A6IvAkcMOilCfRsjynJLPZr41Jz5
         CqcjfmKoCxGtUNlfM8fbEubdqQFjYVyFtpstQHSkfyqs4TkjBlYZ00GEWABlr5VjanY/
         ASFSlEbO7X7Wz91n8Bb66aSAQgaQEPv5bc1VtVHWHqi0fqQW762YNJoUZwUAIxakFhBv
         QCpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VqJNovtZfyPYHdwDId7Es58q4mXtNATw+9rjnk6HIiU=;
        b=qYfRlPovHSaUREiPrmR14by8fwfvt6azJ8j5thT5V6clJj9ScJRbu2cWeITvtnX74q
         mI3ORFNDwawib4JIHhk1kj0RWG/C1I85eMWXBF7qnkDkVBu/O2VkYS3ImlPn6XOfc9RO
         TBUNMvrmffGNm6394f9S++2fpCGhDSmFFibKsueZj9PLAc1DZJfoRqHimQCPNfAhCxNy
         TELIuLp8I3yGb4Nw9DzO+uOhi8cvZdktSq9XnEzMh0z0zYGgkHbCQJ5hrq7v8LAEh2dU
         ZvqGR/Zuv7eGhVXBhEsYq05nfX0zl2Ji6hUkd6B7k7TFRbxMdpoiDw3GIhv6WY20jEVr
         aYcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VqJNovtZfyPYHdwDId7Es58q4mXtNATw+9rjnk6HIiU=;
        b=OUD9p+Gl28Wlh8DRYTwtHZOAuTI91PXDeNOAqzeD3vkLVleDjN3Ya5hqTAkQb2npsG
         GEA8ESuBYIGpKdY/+OmHNNWhp8CtIW0DMP4lPPWCAK15PBS7uPZanHVp/CG9vKn4pbsx
         i6eJJ+cIryH2hIlEbdx0gx10LJN8jkA4qbsY4duPW4ZccRQKCEzK7apJ9fbkk6XvlpO9
         P2kn4MrvvJghcM1g+oTKDfisSeyL/TeqwtrDkmm7GrEH3E1dUvyDQrZ0dRsjKJq4cqc/
         BEYwG+uehNNLeKTFufEZqUceoTuN2qv0vOYL7uzQvXLBL6yYnhdxC7AQZzj/X3/cO80A
         /4xQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWuBvQ6vA31JE59iQmY9BldzqTH5Cb1kvoQQEPwLle6Nj4ihehH
	4QC5yAmWZSB9zXXdKtDCUmI=
X-Google-Smtp-Source: APXvYqzNpSug6okYL8cT7Klxu0+lTAllWbcJoxseYGsa3iYajIj9eITuJTT7EE5+zA+Tp8tX4zJbsA==
X-Received: by 2002:a05:6830:4cb:: with SMTP id s11mr1744375otd.366.1565838765753;
        Wed, 14 Aug 2019 20:12:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2f43:: with SMTP id h61ls792390otb.8.gmail; Wed, 14 Aug
 2019 20:12:45 -0700 (PDT)
X-Received: by 2002:a9d:7399:: with SMTP id j25mr2041883otk.196.1565838765357;
        Wed, 14 Aug 2019 20:12:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565838765; cv=none;
        d=google.com; s=arc-20160816;
        b=pOSTj6QYjemwvkoXXS4GiIjgxHerx3qkLTN+5Jsz/rRXDr9Yk5qOnf/RTXXV9l43Zo
         4mCAsBXBLZtJrDahp7xp63bMKKMrSS47yzFwayhaqB/VDwhFg+3kKVL1YKWPj0/b4M10
         ddKAysoA63OS+/HtNNuZenJpenJlLTwsRe+82cdf+RWaGlK3jrVMOIkDIg8H2cKqASMX
         20i+Fi08EXYgyzA6/zoo83XsYC4aUqf/J49EwNdh6cP3JYA2N+B4QxuUtNGoylRh/tLS
         fW8vYebfBKOgcJdYFKJMOLXo6K4aN3VQkOVqt5i+hllyvLHMw/GDlbiDxEEa4kzZPznm
         s3Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=IwdPDFaVkKZGYv++K0TGtHzcaXQv+wz/L9hg1+/F7aw=;
        b=ON7cTdHiKqGeMz/bKQg9NGcI33jl2lvqYfsTLhfFzOPErnGM0/FlAWXZt5iWeDgPoX
         ZSeNeqBn0T7k0cD2tIq3EOEGQKy7PVKcn3GAgcOIAOjbD4VY125CoDupYqI0sPbphmZZ
         qhADaEGKEJ1vNGcqhSyfe8h+77u7OQaLV4iWuSJxB+z5J5WD8GGhPgCysGInHlxG/nP2
         WMRMosvCWxk9ZTyoAzBTJzh0V9gP5Ube65jrCxk/J4iZ1T7Fnm7asM47EdoAaIz9TM54
         jUa7JiD17bUl5pMLgT9bJz8ySkk8wPujgl5zQoBfbA3pbktsXvMN6M5BIh27S8jOsw+p
         zJ5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id w131si4414oif.2.2019.08.14.20.12.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 14 Aug 2019 20:12:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x7F30l8x044401;
	Thu, 15 Aug 2019 11:00:47 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Thu, 15 Aug 2019
 11:12:24 +0800
Date: Thu, 15 Aug 2019 11:12:25 +0800
From: Nick Hu <nickhu@andestech.com>
To: Paul Walmsley <paul.walmsley@sifive.com>
CC: Palmer Dabbelt <palmer@sifive.com>, Christoph Hellwig <hch@infradead.org>,
        Alan Quey-Liang =?utf-8?B?S2FvKOmrmOmtgeiJryk=?= <alankao@andestech.com>,
        "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
        "green.hu@gmail.com"
	<green.hu@gmail.com>,
        "deanbo422@gmail.com" <deanbo422@gmail.com>,
        "tglx@linutronix.de" <tglx@linutronix.de>,
        "linux-riscv@lists.infradead.org"
	<linux-riscv@lists.infradead.org>,
        "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>,
        "aryabinin@virtuozzo.com"
	<aryabinin@virtuozzo.com>,
        "glider@google.com" <glider@google.com>,
        "dvyukov@google.com" <dvyukov@google.com>,
        Anup Patel <Anup.Patel@wdc.com>, Greg KH <gregkh@linuxfoundation.org>,
        "alexios.zavras@intel.com"
	<alexios.zavras@intel.com>,
        Atish Patra <Atish.Patra@wdc.com>,
        =?utf-8?B?6Zui6IG3Wm9uZyBab25nLVhpYW4gTGko5p2O5a6X5oayKQ==?=
	<zong@andestech.com>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH 1/2] riscv: Add memmove string operation.
Message-ID: <20190815031225.GA5666@andestech.com>
References: <mhng-ba92c635-7087-4783-baa5-2a111e0e2710@palmer-si-x1e>
 <alpine.DEB.2.21.9999.1908131921180.19217@viisi.sifive.com>
 <20190814032732.GA8989@andestech.com>
 <alpine.DEB.2.21.9999.1908141002500.18249@viisi.sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <alpine.DEB.2.21.9999.1908141002500.18249@viisi.sifive.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x7F30l8x044401
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

Hi Paul,

On Wed, Aug 14, 2019 at 10:03:39AM -0700, Paul Walmsley wrote:
> Hi Nick,
> 
> On Wed, 14 Aug 2019, Nick Hu wrote:
> 
> > On Wed, Aug 14, 2019 at 10:22:15AM +0800, Paul Walmsley wrote:
> > > On Tue, 13 Aug 2019, Palmer Dabbelt wrote:
> > > 
> > > > On Mon, 12 Aug 2019 08:04:46 PDT (-0700), Christoph Hellwig wrote:
> > > > > On Wed, Aug 07, 2019 at 03:19:14PM +0800, Nick Hu wrote:
> > > > > > There are some features which need this string operation for compilation,
> > > > > > like KASAN. So the purpose of this porting is for the features like KASAN
> > > > > > which cannot be compiled without it.
> > > > > > 
> > > > > > KASAN's string operations would replace the original string operations and
> > > > > > call for the architecture defined string operations. Since we don't have
> > > > > > this in current kernel, this patch provides the implementation.
> > > > > > 
> > > > > > This porting refers to the 'arch/nds32/lib/memmove.S'.
> > > > > 
> > > > > This looks sensible to me, although my stringop asm is rather rusty,
> > > > > so just an ack and not a real review-by:
> > > > 
> > > > FWIW, we just write this in C everywhere else and rely on the compiler to
> > > > unroll the loops.  I always prefer C to assembly when possible, so I'd prefer
> > > > if we just adopt the string code from newlib.  We have a RISC-V-specific
> > > > memcpy in there, but just use the generic memmove.
> > > > 
> > > > Maybe the best bet here would be to adopt the newlib memcpy/memmove as generic
> > > > Linux functions?  They're both in C so they should be fine, and they both look
> > > > faster than what's in lib/string.c.  Then everyone would benefit and we don't
> > > > need this tricky RISC-V assembly.  Also, from the look of it the newlib code
> > > > is faster because the inner loop is unrolled.
> > > 
> > > There's a generic memmove implementation in the kernel already:
> > > 
> > > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/string.h#n362
> > > 
> > > Nick, could you tell us more about why the generic memmove() isn't 
> > > suitable?
> > 
> > KASAN has its own string operations(memcpy/memmove/memset) because it needs to
> > hook some code to check memory region. It would undefined the original string
> > operations and called the string operations with the prefix '__'. But the
> > generic string operations didn't declare with the prefix. Other archs with
> > KASAN support like arm64 and xtensa all have their own string operations and
> > defined with the prefix.
> 
> Thanks for the explanation.  What do you think about Palmer's idea to 
> define a generic C set of KASAN string operations, derived from the newlib 
> code?
> 
> 
> - Paul

That sounds good to me. But it should be another topic. We need to investigate
it further about replacing something generic and fundamental in lib/string.c
with newlib C functions.  Some blind spots may exist.  So I suggest, let's
consider KASAN for now.

Nick

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190815031225.GA5666%40andestech.com.
