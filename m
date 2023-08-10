Return-Path: <kasan-dev+bncBDZKHAFW3AGBBGNZ2KTAMGQELE7WVOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D1ED777295
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Aug 2023 10:15:22 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-3175b757bbfsf424068f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Aug 2023 01:15:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691655322; cv=pass;
        d=google.com; s=arc-20160816;
        b=yf3xVciFKW0JAiTpOwcQJBHOsA5PDN4C75A+n55x0uHW9GigWP/3RN0FoBw8ktBN0O
         zmEc6LrUDTiAdc/eylRDmw+fjnR39AXpNtex4e4sDzWMElS3JdCey/1kecZltsmHx+3V
         64RHrqiNYeIrchPB98MrktbTeGRZjR8VebdtG7wjc5kNEa9oFI04J8+zWV8Q5ipRI5ZV
         80+q9cJYyW2fqaSzMC9gec31dSzX7GU0i+1U8AVOTa32glz7Ch953/vw+4cJoJtRcLjD
         YTIFjZ0a5l1+eXhR3essi8/D1jmAblBdCsUisB23+W5PHxSM+a4E9UvuFyLxSCnyVqpv
         NEpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8d/Nvrzf/CZRL4RB7mebNT+9/KjURf/oj0H9sprxhH8=;
        fh=GyiYDglD9h29HXXbD45R+obMNrZsHNJsyw6W2UMF2tI=;
        b=nScAr0Bo7kX1AZ294PK+LXieW+CHqzm3Y59pjeCqPA7hgweLNr0R6gevYh9LjpxcBY
         dMW6BEjYHD5euGpsecllHca3RsvqUSa1uPRIJ5Z9m14XouFk/8YCz84iAb0StQsD2p3a
         /1f74npq4BQHtORNpL0OgCh0a9ayuVohi69mIUG/rvwjBILIweGT87PogISG5Xm54dZq
         DD50RCPaaGmLG3Sc4Se8Guq9jGNg/HHzlokCYZRfNjplcpoGLPsJGmhxEjiihPzTdtQp
         aRWmitwaabnPF/hw8As6Kg+h79SB8LVKapDI1/jTD+NXNMkT85vn9hOIy8ydQ5SE7Xur
         BnfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=fApRWQR+;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691655322; x=1692260122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8d/Nvrzf/CZRL4RB7mebNT+9/KjURf/oj0H9sprxhH8=;
        b=bR/s61WZcn0n1Ww3+ckcvvJ5nfKSeP2KOei7ao46KlTjAdgw8fo5TlODZLDjQe8ge1
         MzBbzbpDNH3ujIjDEOKNu6E8MIf59rHsUPLchNyKNdNb0mJV2T4vz0YCb/qe8YXRGvfB
         O0Mf0KAF2Oyqgi4SabU8drOmSvqk6sEvKJCXeG+sjiFeeoAhm+hRpi/4i5yx8ia6UMGA
         pZDu94Bi7ONjk984QiNe0ba5MCtJ2zqirpb0zh2Aa6XKakHOhGYiVIyZSqhLTefB4j9p
         h4oD+A2O9rRV657iLu0wJOi4SomzHTy6CZB3TK/lkznOT6yBabf04FEGVRMQ10JbJgqI
         nCag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691655322; x=1692260122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8d/Nvrzf/CZRL4RB7mebNT+9/KjURf/oj0H9sprxhH8=;
        b=CFOpE3fHi5ZND3nH98XeUIcAkJaSCqe8xYZnuOmAV3IphghNfQxoHjYvtbdGTkIP2E
         FM5UZfNN+OH8O9VqQwDojoE0LbIL+wKyfGiFaOFuQhApoTMVjj+39EBvz/lJhRfIWwcp
         7DCtLJFY66KBEf8uTWaVXggxTOxV6JcmMJwZ6+ui7Ot2T8QBa4w8ZfBFwcaWUdw1AtEK
         NzPs/OyC/VUiDHbMqLBZjWvXhhFHWrPyjONHyRdGd2eNaffQeTfzZLyEXlh4siWT3/df
         LGhgGuKwk7UbDpV8gddPJZUgqwCWEH6q4SAa1bpAL4STpnbI2OVttqJr5zzKhFqz2g/0
         hl3Q==
X-Gm-Message-State: AOJu0Yw2HiZ8Ocjz3LAGKRPllClYVhOqJw5lHdiZimX5WstSxsYlN6Aw
	N0naibR4MCsyboV4ZPyclY8=
X-Google-Smtp-Source: AGHT+IFgpdGgrTZz3GuZggvStvgeFUtvVdBknAkpSpEmga21iolWTD7mSZyQ+uoidXLGkDgxmUj4yA==
X-Received: by 2002:adf:f74c:0:b0:313:f5e9:13ec with SMTP id z12-20020adff74c000000b00313f5e913ecmr1394768wrp.68.1691655321673;
        Thu, 10 Aug 2023 01:15:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1cf:b0:318:8bf:804f with SMTP id
 t15-20020a05600001cf00b0031808bf804fls157723wrx.2.-pod-prod-05-eu; Thu, 10
 Aug 2023 01:15:20 -0700 (PDT)
X-Received: by 2002:adf:fe11:0:b0:315:ac1b:91e with SMTP id n17-20020adffe11000000b00315ac1b091emr1656406wrr.53.1691655320000;
        Thu, 10 Aug 2023 01:15:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691655319; cv=none;
        d=google.com; s=arc-20160816;
        b=w1wqEWofIX4BAj95ERT/LlAwkRw4+2eyd+p9gqPrGhFiU9JWBfetRFn2GO/zsIyJ/X
         FC9LpylgaFySLFTLtkHEHJX1929bHWycPxLOd8mXKyxn71OeXIrPhI94ifWU0SD6x2eg
         tz5fYDdjr7xXkhybC4+PNPsv+RoHrqWqsLIqwEa2x7PHbIiSu+mvIIpVNbuuSWnpdWz1
         hG1NWelu6PThMqsPdR23tolc50mWSG9D5u98CGvjsA5oaU0OCBQ0p46PzrokwQVsScdL
         vh3iQnNtGRiYIVdDzsVJUK7/kLviALotu/LLKbXAiIRjc8KfGNDH4skNhQUPOQMZsg22
         r+aA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ElbU9RvDenPkT7xhen9VyORMPFOizJvDYj/Km+R918Y=;
        fh=vmUQn/KoiKBz0TN4QXh4zrTyMSy/18taF2m5XcOxj7k=;
        b=MFx/5D0LEkpGtJJsMBDAHkSOuWjvfkBvajbPuNW7/Q7cr0Ua3ENIRUJHIf8jQ2qrEd
         bl3/tkw5Z5gFZrU7uL+uIgVBb7sXtGdnTXpbPOjAoJqytMAx3/iFoMATo19bV+o3GXLw
         muNODcVQ4BYT/vjxyTHPByp4iPDkBxmxUKPMzc0leD2ccPoBd8CGCytGPkYu62ogWp/u
         EVQPzDeMCFneIcJvzTnxKvZvfXdN+QKbXOVv9HBpbm8HkOTC9H7fMkBkUEFhNQBmsAWu
         gK6M1dKRulU5ZvUsUNEoWZirV+7aDFKYxNffBmkaur08yzzhlwC++FPhbmbNqmmasrZg
         0x2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=fApRWQR+;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id b9-20020a05600003c900b003177f06b59fsi72229wrg.1.2023.08.10.01.15.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Aug 2023 01:15:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id A553A1F38D;
	Thu, 10 Aug 2023 08:15:19 +0000 (UTC)
Received: from suse.cz (dhcp108.suse.cz [10.100.51.108])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id 3041B2C142;
	Thu, 10 Aug 2023 08:15:18 +0000 (UTC)
Date: Thu, 10 Aug 2023 10:15:17 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Message-ID: <ZNScla_5FXc28k32@alley>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley>
 <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com>
 <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
 <ZNHjrW8y_FXfA7N_@alley>
 <ZNI5f+5Akd0nwssv@smile.fi.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZNI5f+5Akd0nwssv@smile.fi.intel.com>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=fApRWQR+;       spf=pass
 (google.com: domain of pmladek@suse.com designates 195.135.220.29 as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Tue 2023-08-08 15:47:59, Andy Shevchenko wrote:
> On Tue, Aug 08, 2023 at 08:41:49AM +0200, Petr Mladek wrote:
> > On Mon 2023-08-07 18:13:57, Andy Shevchenko wrote:
> > > On Mon, Aug 07, 2023 at 06:11:24PM +0300, Andy Shevchenko wrote:
> > > > On Mon, Aug 07, 2023 at 06:09:54PM +0300, Andy Shevchenko wrote:
> > > > > On Mon, Aug 07, 2023 at 05:03:19PM +0200, Petr Mladek wrote:
> > > > > > On Sat 2023-08-05 20:50:26, Andy Shevchenko wrote:
> 
> ...
> 
> > > > > > How does this sound, please?
> > > > > 
> > > > > Not every user (especially _header_) wants to have printk.h included just for
> > > > > sprintf.h that may have nothing to do with real output. So, same reasoning
> > > > > from me as keeping that in kernel.h, i.e. printk.h no better.
> > > > 
> > > > (haven't check these, just to show how many _headers_ uses sprintf() call)
> > > > 
> > > > $ git grep -lw s.*printf -- include/linux/
> > > > include/linux/acpi.h
> > > > include/linux/audit.h
> > > > include/linux/btf.h
> > > > include/linux/dev_printk.h
> > > > include/linux/device-mapper.h
> > > > include/linux/efi.h
> > > > include/linux/fortify-string.h
> > > > include/linux/fs.h
> > > > include/linux/gameport.h
> > > > include/linux/kdb.h
> > > > include/linux/kdev_t.h
> > > > include/linux/kernel.h
> > > > include/linux/mmiotrace.h
> > > > include/linux/netlink.h
> > > > include/linux/pci-p2pdma.h
> > > > include/linux/perf_event.h
> > > > include/linux/printk.h
> > > > include/linux/seq_buf.h
> > > > include/linux/seq_file.h
> > > > include/linux/shrinker.h
> > > > include/linux/string.h
> > > > include/linux/sunrpc/svc_xprt.h
> > > > include/linux/tnum.h
> > > > include/linux/trace_seq.h
> > > > include/linux/usb.h
> > > > include/linux/usb/gadget_configfs.h
> > > 
> > > Okay, revised as my regexp was too lazy
> > > 
> > > $ git grep -lw s[^[:space:]_]*printf -- include/linux/
> > > include/linux/btf.h
> > > include/linux/device-mapper.h
> > > include/linux/efi.h
> > > include/linux/fortify-string.h
> > > include/linux/kdev_t.h
> > > include/linux/kernel.h
> > > include/linux/netlink.h
> > > include/linux/pci-p2pdma.h
> > > include/linux/perf_event.h
> > > include/linux/sunrpc/svc_xprt.h
> > > include/linux/tnum.h
> > > include/linux/usb.h
> > > include/linux/usb/gadget_configfs.h
> > 
> > This is only a tiny part of the picture.
> > 
> > $> git grep sc*n*printf | cut -d : -f1 | uniq | grep "\.c$" | wc -l
> > 5254
> > $> find . -name  "*.c" | wc -l
> > 32319
> > 
> > It means that the vsprintf() family is used in 1/6 of all kernel
> > source files. They would need to include one extra header.
> 
> No, not only one. more, but the outcome of this is not using what is not used
> and unwinding the header dependency hell.
> 
> But hey, I am not talking about C files right now, it's secondary, however
> in IIO we want to get rid of kernel.h in the C files as well.

This sounds scary. Headers and C files are closely related. IMHO, it
does not makes sense to split header files without looking how
the functions are used.

Everyone agrees that kernel.h should be removed. But there are always
more possibilities where to move the definitions. For this, the use
in C files must be considered. Otherwise, it is just a try&hope approach.

> Also, please, go through all of them and tell, how many of them are using
> stuff from kernel.h besides sprintf.h and ARRAY_SIZE() (which I plan
> for a long time to split from kernel.h)?

I am all for removing vsprintf declarations from linux.h.

I provided the above numbers to support the idea of moving them
into printk.h.

The numbers show that the vsprintf function famility is used
quite frequently. IMHO, creating an extra tiny include file
will create more harm then good. By the harm I mean:

    + churn when updating 1/6 of source files

    + prolonging the list of #include lines in .c file. It will
      not help with maintainability which was one of the motivation
      in this patchset.

    + an extra work for people using vsprintf function family in
      new .c files. People are used to get them for free,
      together with printk().

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNScla_5FXc28k32%40alley.
