Return-Path: <kasan-dev+bncBCLI747UVAFRBN7XQ6NAMGQEG7DKSKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A49A15F8849
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Oct 2022 00:37:44 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id dh7-20020ad458c7000000b004b1c8f7205esf4673763qvb.5
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 15:37:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665268663; cv=pass;
        d=google.com; s=arc-20160816;
        b=VG31FXnSPryxkAkBEJ2Hnmm6EaDzgvTo+2YQ12DHEVh8lbYFFgivpWNeQwjYYADfbQ
         hrXtKUDbXsSzvtx8Mp77gG/qgQ6IGVgZlI6YsZB1ymCC1LMURkJBm4h39/Y2o9jpVDPZ
         SgnW+tprnZWGL21Pbohb74CVRQq8j+6UCAyscarA9GQfPx18q8nlaZwEMkG52gOzMS1l
         O9JJ0EB9icEmsZAuuPXs0MXe/+uxPyJFYF/hWXXZfGFSipAEexpvhEB7CADu23bPPmnt
         pBn2HWjqN70uEim2dzZW7kmzA506xcNismWL1Iy5ZfG7rXbbPaqosdF0bS+44+7oMD8s
         IKfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=aUmF27LRN6HcRf9TLrKpLhu/3sFYTx32JEJuiRlV/G8=;
        b=spwc90RxLAJo6i4SrI7VlVkfcGJiCYpeMXzesefz9376mYHkziWAsWK5MsMh78M59I
         WMpXLf4VNzVh4RJ3DtmuvQuZg1RFdzNDCiBvQHqRl8QkG35fDlWi1rE3fPa3zkePDB8S
         z4RWQfCJEqyG2wvjg60aE2mnd2hauuCK1FLbbZwi9zObFkQSIgiaP8dEjDjesg8S3TTO
         GDM6/Lp/+MY316/zp5N+rn/8ZUcZCDwjmo/aqY5wi1kPqXbNVMFdOrYsbPdNwZpjwhp8
         Z7WIiFoHEqrDZKnejXnOkvgTKyWHT5Mqbe6U4N9f0KTfpArQU0CqstaAdio3MaCOwmU4
         IQ+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=XGhFZP09;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=aUmF27LRN6HcRf9TLrKpLhu/3sFYTx32JEJuiRlV/G8=;
        b=t9/fo0Ylk5mIu4m7QUZNYe06yugZcJWrDpVtg/hKJgYMiIEfPuWOM2xabcJEVrlTU2
         Nc56FxacyJJ0sE6VLIg4UfL7u2pdShKtDEy5/kBfYFhMWFjVpWBvZlKP6ZgQPGJ9rfhy
         eb9p8mXA+5Ot5hIvV4TP9W9Ay6wtKul8pHK4zY1hS8XECvydk3ophBPv9U7uYKjsgNDc
         tJPVzI+GBiXvAjlSKi8K+aKhPsJy+mq4KHvMwoD9jq+IygbGi3ZCEKBcjDlM0ihIzv8E
         gHftUZrCpTFY4A443S9WM6QEHjFYKZjVMjb++Gi9texKmRhZfE+F6Z6yYeRZZHFd2Hnc
         zcag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aUmF27LRN6HcRf9TLrKpLhu/3sFYTx32JEJuiRlV/G8=;
        b=IHUoOKQzgAhFxOJo+GtcoiY2MKSJOkwj4YLXyHSfBSW0rp1gCG55oexvdjmhQyHJsv
         5iNuDU1mRIuJ3eVdbWyNrLTZscsNHxlEnf/tW07tQgSUte/QrlLlOV4Dm53WP4kJAWuJ
         HLyIwmz6psEngbIUYSRVsCwwXBeBsVr3/GR7LZEqPBHKFUDllUq3YdIuQ35mqm04KvYt
         AD1qcnBS+8LhOlGcJ+Wr7scvRtFSsawhHSclKWMq0/osMDjwB8jkCf9VaayDTGzR18OA
         xMY0yjswIYpn7AAtLu5W8m4IQU2SHwsNfm5MRsuLQ/sbba5+CjiqdJNvThe5+Jh74WDU
         cbVA==
X-Gm-Message-State: ACrzQf0GLroLJq/FGn/GMw6lVUxSYSQC3WzajObQ8qu1V+15/tI7i6B/
	GOkAo8+9X65EEhYP9E/+CFM=
X-Google-Smtp-Source: AMsMyM6eGvTE5XqV7ZiZttT8f4f4x/7tEu89ajC6KVU25ywRDeZks2U2flKz7WOXBfvAwrohqquq7g==
X-Received: by 2002:a05:622a:196:b0:35d:442b:ab45 with SMTP id s22-20020a05622a019600b0035d442bab45mr9761966qtw.565.1665268663551;
        Sat, 08 Oct 2022 15:37:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1883:b0:31f:22fc:d794 with SMTP id
 v3-20020a05622a188300b0031f22fcd794ls5074432qtc.7.-pod-prod-gmail; Sat, 08
 Oct 2022 15:37:43 -0700 (PDT)
X-Received: by 2002:a05:622a:1002:b0:35b:baaf:24bb with SMTP id d2-20020a05622a100200b0035bbaaf24bbmr9761615qte.85.1665268663097;
        Sat, 08 Oct 2022 15:37:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665268663; cv=none;
        d=google.com; s=arc-20160816;
        b=qhfX+/ymvb6Wlx/b1FCBz0AIIwO2pe2R+F24RhxaIsanNEwRoizupenJv/RDUjLw9q
         s8Em8FnP4T8YIVfTPk578tODDMHhYQcJyqBBiKQ3bMofURSDyqbS+7oSx0cxgbjU5ns+
         xjtE9ChMLW6mrnX6ZmU1SkXzU6huPXbJkzb5D4vH6bxW/Y1QQQjIDRS33EdpZxzU33JJ
         splJyo22tXBGp+lvWPsIuFxXhNAn89NHP7z9qNpKOOpYdBgEGgR6qxgLI51YYfKUn6oK
         yhjYszHNSd3wjJ2e6WNY11ZeGdOhcEHFnMmjXWR/bru+AV90S2kbd1S/DPTx6oQ7PXE1
         9EEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KIVWIkgHNJFfTR3APACYr63A/xqCM59y71KVcO4sCaY=;
        b=Ue9yjKy6dUkk4R1pqC3On+TzLC9erwiTD4EFTR6oLTcntr76J8LvH0sZplHQMDSM2f
         y/8iQKCm10Mu7Be9nDeX2rkbv20kMBW9Qi2zzpM8ucC9xlBktqfjSsmRIN62qh7wZyUK
         ILKYbRZSjMEIyjpWlHPbvkiQPKru8ZHi0lne4j7duWa6ZvyYWyzusUhCPyEnX5iDs/i/
         JKcCFAuCCNYg3mhOP+G0Xxw0BcLSwlqqsda0VD8/WYjKwe934gJiS5UPXXE7r8hv3fw3
         SE4neomGGNvrRWv6zEgmD8cR9qaj7qkSbnSF9koUvsNLpfsoqHJGoYxeJ/ZhvCXOLp27
         NvGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=XGhFZP09;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id y6-20020ae9f406000000b006ce4c1110bfsi183861qkl.0.2022.10.08.15.37.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 08 Oct 2022 15:37:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 69DE260B14;
	Sat,  8 Oct 2022 22:37:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6DFC7C433C1;
	Sat,  8 Oct 2022 22:37:35 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id c941732b (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Sat, 8 Oct 2022 22:37:33 +0000 (UTC)
Date: Sun, 9 Oct 2022 00:37:33 +0200
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
	"x86@kernel.org" <x86@kernel.org>,
	Toke =?utf-8?Q?H=C3=B8iland-J=C3=B8rgensen?= <toke@toke.dk>,
	Chuck Lever <chuck.lever@oracle.com>, Jan Kara <jack@suse.cz>,
	Mika Westerberg <mika.westerberg@linux.intel.com>
Subject: Re: [PATCH v4 4/6] treewide: use get_random_u32() when possible
Message-ID: <Y0H7rcJ3/JOyDYU8@zx2c4.com>
References: <20221007180107.216067-1-Jason@zx2c4.com>
 <20221007180107.216067-5-Jason@zx2c4.com>
 <f1ca1b53bc104065a83da60161a4c7b6@AcuMS.aculab.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f1ca1b53bc104065a83da60161a4c7b6@AcuMS.aculab.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=XGhFZP09;       spf=pass
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

On Sat, Oct 08, 2022 at 10:18:45PM +0000, David Laight wrote:
> From: Jason A. Donenfeld
> > Sent: 07 October 2022 19:01
> > 
> > The prandom_u32() function has been a deprecated inline wrapper around
> > get_random_u32() for several releases now, and compiles down to the
> > exact same code. Replace the deprecated wrapper with a direct call to
> > the real function. The same also applies to get_random_int(), which is
> > just a wrapper around get_random_u32().
> > 
> ...
> > diff --git a/net/802/garp.c b/net/802/garp.c
> > index f6012f8e59f0..c1bb67e25430 100644
> > --- a/net/802/garp.c
> > +++ b/net/802/garp.c
> > @@ -407,7 +407,7 @@ static void garp_join_timer_arm(struct garp_applicant *app)
> >  {
> >  	unsigned long delay;
> > 
> > -	delay = (u64)msecs_to_jiffies(garp_join_time) * prandom_u32() >> 32;
> > +	delay = (u64)msecs_to_jiffies(garp_join_time) * get_random_u32() >> 32;
> >  	mod_timer(&app->join_timer, jiffies + delay);
> >  }
> > 
> > diff --git a/net/802/mrp.c b/net/802/mrp.c
> > index 35e04cc5390c..3e9fe9f5d9bf 100644
> > --- a/net/802/mrp.c
> > +++ b/net/802/mrp.c
> > @@ -592,7 +592,7 @@ static void mrp_join_timer_arm(struct mrp_applicant *app)
> >  {
> >  	unsigned long delay;
> > 
> > -	delay = (u64)msecs_to_jiffies(mrp_join_time) * prandom_u32() >> 32;
> > +	delay = (u64)msecs_to_jiffies(mrp_join_time) * get_random_u32() >> 32;
> >  	mod_timer(&app->join_timer, jiffies + delay);
> >  }
> > 
> 
> Aren't those:
> 	delay = prandom_u32_max(msecs_to_jiffies(xxx_join_time));

Probably, but too involved and peculiar for this cleanup.

Feel free to send a particular patch to that maintainer.

> 
> 	David
> 
> -
> Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
> Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0H7rcJ3/JOyDYU8%40zx2c4.com.
