Return-Path: <kasan-dev+bncBCLI747UVAFRBG7PQ6NAMGQEJYEWGQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D6625F882F
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Oct 2022 00:20:13 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id h186-20020a636cc3000000b0045a1966a975sf4502227pgc.5
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 15:20:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665267612; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cr9uuOm7bsDlGBjwfe9U4e27CbNHLkWA/UkABIunrzej69sSsDfNK3dii8wpu1Pkaf
         3ArKTt0se4RXIKDMn4oR98wyxqeEVmOttPlMdPxecWn4TmnsAgggOA2o8Bv1zQYa4mhM
         aFpQREc9xmYk7Ldv5mGMWsdVRzKK/JvUFJcjDTFHXQqIFi8p7L5N5bWgexcjBEvs+W7O
         SDWIY40tUwa08quV55am2EzhuDbKfuwUac5n7G1dBSMP+bReITvLlVeu5Wfey+jkLT48
         VeSQlEjAOYLiqdwIRjzuRTcls8hXnGFWAD9rhVBfVXTTHltwuzW1VwfdtIGtvnOxCX+5
         fQ9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=KjKr3Yp7eNMjIJQKqoa74mZn+9q9wtka+sKwgBRQ08Q=;
        b=MyZMtjJmJrw2BTGz7JANxZKqcxsETZNKAb4/xl5fBsUOr1hGH4v+LUWcdHHiEs9uej
         XGmC6BdNw3EL8UERmZ8dQ5tWDvlw9ctoR03h/CWo8t5UkxoIBiGVhG8DznPzLGDjyjBO
         jvgSOLyEEM1J7ev+VH7cOAps7VxDaYiHzfqfFAsOS6+wXOdMphYYxQjhZ2OAEntDxTUr
         p+q47vYLiQ6pT1T3Eh1jgMvm7ZVfO7l4joUhvoGixPvCi/SkPLiGct1RQDOTTT5AHp4i
         /tyUsHZJhinumAWCSZK/1hSuhLEziFfq/5cig+j1OTtDaap5GIJKGq/jk/vyvgdlFVb/
         W3fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=QmEOahoB;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=KjKr3Yp7eNMjIJQKqoa74mZn+9q9wtka+sKwgBRQ08Q=;
        b=T2pTm64ry7X/9zh/2ekSGPif8f/u+q/tnx250uyMRGh2AN1z/WR+sjTMVwwkCnWldW
         Rp6INGX7eZF5BF3nvopUxj7rPlDcvMtvjk9K88ZgMfRI5KMpTEyoNJqfgFF4hfmR4mpg
         SC1tsyZIXxSoxNaWkuFaOCJnYvOY/eP7xb7R9vOLNEQdpJGjOZDGL9vZUdOjcM+dCizR
         fSHSwNNnF6sFMwmNDzOh5MqYjmV/4xwd/MSWNOpHJTkroNubrbXXeHTY5hrH9wyoidH+
         Ss6DpRxRqrHFx0b6oMVC9BSMo9yMDWqdvGvyTBTD8446LEgho069/17SP2ZO7APaiWPt
         ozHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KjKr3Yp7eNMjIJQKqoa74mZn+9q9wtka+sKwgBRQ08Q=;
        b=r4JSojv2S9Fbkbb8+XnN40eVZwvkQPXjJwQHFCb0Z+Zl/VjsNP9ne5sSv44wXWqPZP
         SxkfNHmK3klyN7LbYnDinbnkaL0DJsq7TvpJICCzqButwA4dTkX5+/NIChNC4GNmUQsP
         tQ6x4GXBI1NFsmzU6vkmqzE9DSCvu7heL7DobENekFbhiNcfQ1SvnK+iU5VYe795b9yh
         z8lxdy2MwkzdPAta7N+qLOLDpklescU6doPQFZEMu9sHlz5I3JWZLgBT7XEutK8cdRbz
         vMYBc8zQFfFQlbc3E/jhuFLONhBBXT6EXo5ZtKFnFI8omgHuJM2Cil3At9wD7MrU93Ms
         iWrw==
X-Gm-Message-State: ACrzQf0+FMWiSIscCYCYMjJuFwZx3ZLmH9wuPaEsiC65WNg+aTUSTNTG
	yYBxeqAsK/xsgYZ63bMPDrk=
X-Google-Smtp-Source: AMsMyM5/h6MRomjyFIETFUizvcSQURnMM0oXy8gXznZRS9pdrj7Z9JtX6Vp6ffjwE/q/+g649yk+iQ==
X-Received: by 2002:a62:3306:0:b0:562:5109:aed6 with SMTP id z6-20020a623306000000b005625109aed6mr11935570pfz.34.1665267611771;
        Sat, 08 Oct 2022 15:20:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:38c6:0:b0:557:cfb6:bcec with SMTP id f189-20020a6238c6000000b00557cfb6bcecls3734886pfa.9.-pod-prod-gmail;
 Sat, 08 Oct 2022 15:20:11 -0700 (PDT)
X-Received: by 2002:a05:6a00:234d:b0:561:f0c3:cde1 with SMTP id j13-20020a056a00234d00b00561f0c3cde1mr11809879pfj.34.1665267611037;
        Sat, 08 Oct 2022 15:20:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665267611; cv=none;
        d=google.com; s=arc-20160816;
        b=alOiMxduu0ptpGrK3HqaLjFKY4pq6CeJ0NUGj9SWHCkTZw1M7qV4wQvMl7Zp6NC5gD
         pDPjNZtiHxf+TI4zRL9Tr/7ibRM2mVS3DNwmExHaHughEU6GA0qoAuDsBFkQwVcB4wLd
         awZTwrRLu1gSgXVtpv3XrcabyUtgTnlPfPXHk2A68WO1cH4hh76iU75XA07ACuOWgCFP
         ukveE14+h8AC1iExstwXxivjYNsC9Q4ld0yPHEgvzdmRA48blRYHb0VkkLXEn3BnnVow
         VoqbVPAMw+U+c535Q3saE5aICymqWd1t0jxyRfJ6o1MQH6ZU8SAXpQaHvgvr6+eYL6Lh
         Tmrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=P/cyFerOrVR1hjiF/QX04AV2aA5aZrHQbK/mKyxjv9I=;
        b=Omq660UWoLIoLSgzpqfZVilmW5WN+BiegieLRZDxUZl60SW0RkMtYIJQn50iK2JGvh
         r03pZFRqOq/6BrfUsNEnN8ICblHDD4hNovmToE0UqELp/PZPsYkThNNZ3W85Qci7lgta
         gJy5oZlr1KjbsV6A7hVtAs1KmH6tF9LrQNTqR6L3t4mDYqqidjzxtBIiOzT9wGAknkpC
         hFPMuxGFXAhXAt0kcvKUZsOvQiYhNCd2Q8wYlfubaIh8XDXUGLq3sCjP8geslKsMdSo4
         iICA38LhY8/9v6uNVvh4w/npkCkzFWZYUStIRowj0a/ttYM4FuA/5gKsr8X8WnkfWGE7
         U6xA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=QmEOahoB;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ne1-20020a17090b374100b0020a605eff06si420877pjb.2.2022.10.08.15.20.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 08 Oct 2022 15:20:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4A9B460B02;
	Sat,  8 Oct 2022 22:20:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 70236C433C1;
	Sat,  8 Oct 2022 22:20:03 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 6a6d913c (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Sat, 8 Oct 2022 22:20:01 +0000 (UTC)
Date: Sun, 9 Oct 2022 00:19:59 +0200
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Laight <David.Laight@ACULAB.COM>
Cc: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"patches@lists.linux.dev" <patches@lists.linux.dev>,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph =?utf-8?Q?B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Heiko Carstens <hca@linux.ibm.com>, Helge Deller <deller@gmx.de>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Huacai Chen <chenhuacai@kernel.org>,
	Hugh Dickins <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	Jan Kara <jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Berg <johannes@sipsolutions.net>,
	Jonathan Corbet <corbet@lwn.net>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	KP Singh <kpsingh@kernel.org>, Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Pablo Neira Ayuso <pablo@netfilter.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Richard Weinberger <richard@nod.at>,
	Russell King <linux@armlinux.org.uk>, Theodore Ts'o <tytso@mit.edu>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	WANG Xuerui <kernel@xen0n.name>, Will Deacon <will@kernel.org>,
	Yury Norov <yury.norov@gmail.com>,
	"dri-devel@lists.freedesktop.org" <dri-devel@lists.freedesktop.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"kernel-janitors@vger.kernel.org" <kernel-janitors@vger.kernel.org>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"linux-block@vger.kernel.org" <linux-block@vger.kernel.org>,
	"linux-crypto@vger.kernel.org" <linux-crypto@vger.kernel.org>,
	"linux-doc@vger.kernel.org" <linux-doc@vger.kernel.org>,
	"linux-fsdevel@vger.kernel.org" <linux-fsdevel@vger.kernel.org>,
	"linux-media@vger.kernel.org" <linux-media@vger.kernel.org>,
	"linux-mips@vger.kernel.org" <linux-mips@vger.kernel.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-mmc@vger.kernel.org" <linux-mmc@vger.kernel.org>,
	"linux-mtd@lists.infradead.org" <linux-mtd@lists.infradead.org>,
	"linux-nvme@lists.infradead.org" <linux-nvme@lists.infradead.org>,
	"linux-parisc@vger.kernel.org" <linux-parisc@vger.kernel.org>,
	"linux-rdma@vger.kernel.org" <linux-rdma@vger.kernel.org>,
	"linux-s390@vger.kernel.org" <linux-s390@vger.kernel.org>,
	"linux-um@lists.infradead.org" <linux-um@lists.infradead.org>,
	"linux-usb@vger.kernel.org" <linux-usb@vger.kernel.org>,
	"linux-wireless@vger.kernel.org" <linux-wireless@vger.kernel.org>,
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
	"loongarch@lists.linux.dev" <loongarch@lists.linux.dev>,
	"netdev@vger.kernel.org" <netdev@vger.kernel.org>,
	"sparclinux@vger.kernel.org" <sparclinux@vger.kernel.org>,
	"x86@kernel.org" <x86@kernel.org>, Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v4 2/6] treewide: use prandom_u32_max() when possible
Message-ID: <Y0H3jzGE1oiwEYa5@zx2c4.com>
References: <20221007180107.216067-1-Jason@zx2c4.com>
 <20221007180107.216067-3-Jason@zx2c4.com>
 <01fafe0e56554b1c9c934c458b93473a@AcuMS.aculab.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <01fafe0e56554b1c9c934c458b93473a@AcuMS.aculab.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=QmEOahoB;       spf=pass
 (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Sat, Oct 08, 2022 at 10:08:03PM +0000, David Laight wrote:
> From: Jason A. Donenfeld
> > Sent: 07 October 2022 19:01
> > 
> > Rather than incurring a division or requesting too many random bytes for
> > the given range, use the prandom_u32_max() function, which only takes
> > the minimum required bytes from the RNG and avoids divisions.
> > 
> ...
> > --- a/lib/cmdline_kunit.c
> > +++ b/lib/cmdline_kunit.c
> > @@ -76,7 +76,7 @@ static void cmdline_test_lead_int(struct kunit *test)
> >  		int rc = cmdline_test_values[i];
> >  		int offset;
> > 
> > -		sprintf(in, "%u%s", prandom_u32_max(256), str);
> > +		sprintf(in, "%u%s", get_random_int() % 256, str);
> >  		/* Only first '-' after the number will advance the pointer */
> >  		offset = strlen(in) - strlen(str) + !!(rc == 2);
> >  		cmdline_do_one_test(test, in, rc, offset);
> > @@ -94,7 +94,7 @@ static void cmdline_test_tail_int(struct kunit *test)
> >  		int rc = strcmp(str, "") ? (strcmp(str, "-") ? 0 : 1) : 1;
> >  		int offset;
> > 
> > -		sprintf(in, "%s%u", str, prandom_u32_max(256));
> > +		sprintf(in, "%s%u", str, get_random_int() % 256);
> >  		/*
> >  		 * Only first and leading '-' not followed by integer
> >  		 * will advance the pointer.
> 
> Something has gone backwards here....
> And get_random_u8() looks a better fit.

Wrong patch version.

> 
> 	David
> 
> -
> Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
> Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0H3jzGE1oiwEYa5%40zx2c4.com.
