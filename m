Return-Path: <kasan-dev+bncBCLI747UVAFRBSNYSONAMGQEVLBWI5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 189005FAAE6
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 05:00:27 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id a12-20020a1ffc0c000000b003ab942d8f38sf838521vki.7
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 20:00:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665457226; cv=pass;
        d=google.com; s=arc-20160816;
        b=UJLJIkj7y6IMHH3lUGRGapElTIr9f+ITZImB+piTcwzW4RyFH0fBfFA1cVOucYFmgU
         +uNpxsto9Qu+Ck39uYiAmrW4ACeSN3w+cedcUSCKteEgRtU4svS8vvSe5aEcAy/kzHVw
         HQ2x02J8C41Zpcs6dSmNfQ2Bxsq8oXbfcx2V7mD0UBI358RwOQYfdaHMfJqKnQkFWTY9
         1LCc22Ny0Kn/Zmn7JYhHKaz5sByYNL2LlnJsgqAMGELFL19sbXq+c6tF+qAU5IOqByBK
         fDafLEyF7LUou0DEgt7RWRHvOAyyYfVK+zma8TR/ohGdFoVC5MdWiOfUGYDw0c6cM00C
         v2FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=TNZO5AsouJ6q4tChH09TbNamExsDm4FkG/15rbEYpf0=;
        b=DSPavq/mmiM2TGo8gE/RhjX12xkhY8AEHn+h0857RJXNf+uPBuA2TBhGDZjgSkhg2A
         buu8Wl+fqxBjUuS+j7orgPZkNRGEy+Ii9jPiT/J7ocdAvx1bD9isEjr8cRg/JWhLVFlY
         Ho8P3fgFqkM2UP3Nx95U0xAJuDUroOdNjWA/i+FTkwJ7MIMpkOz0GtCByHqqGy4MQ/KY
         s3L4Nnpars3SrYC6bTY6kOzeF3Pt5TdRMTsrmuDhlu9D1eocRqldGnIp/SZaU+97asfx
         gD62uPr6936h20UbIjUmtS01jZuy9F0sFPGd3yOp6RbRon+O6IMTkFd11mVlgsi7GmEp
         ejOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=HINC5krz;
       spf=pass (google.com: domain of srs0=ame8=2m=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=aME8=2M=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=TNZO5AsouJ6q4tChH09TbNamExsDm4FkG/15rbEYpf0=;
        b=clunUQ2inicOHHce6b1DIbRG2ARZIsNwepnirqypSdwkE6oYen2uiAyBnb15N3Sa8l
         6N+xzt5zPhXZFBVC0gpwE4iWhD8d3GniGZ3ykNsgAcWKFjGOMiFWN3iYXzgNm8xkVXN0
         4QcA+3lUiZHp4N5AttCv4rE0YkZ3gtKeWGJgnWGVzFfAVMCVUau05GV4pz/7IRQlER1B
         /6RWRmn+6FOdPqR0beJCyPwHKn6b1fkCcjnIKhvZv1b2b7f2gwQlBqCKRJ03q2y63uWP
         ohsQ5o4RUv5mo0phVPiUX/OdyTiTZv0DuMtLDmpRm9vuH6KlrAdeO5BwXaAv/spVylYZ
         MbjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TNZO5AsouJ6q4tChH09TbNamExsDm4FkG/15rbEYpf0=;
        b=Z4HhdBUoPzf7zCukqWavb4/pjZ8cPcIf6+Ag8LzDOV5WqbCpZVuvX1if/0hC8vQlZI
         FZKJRflIPMb03pzlSmjeWeQRYE/XI51CTQ0GTeEsopwRdCpOqBgwUW3fj6/XGLHu0MAt
         3oIglnxeET9mxXBwn+mgEuHrw3BNMXJYEaS3w9Sw3Txeh1oSEKAKgSphuhziaXOODw7/
         G2bXMys+GH4zZ2k1MbpKDM9Xa3t7iPRsmMXpat0XoYD1I3Z+UMXOBX3W8bIBqRPLRps3
         2gkzVp9ZWUCMrV5VdoDPn3pelzhEpjN/uZbEkrHB0h9snlWHDSyoPFBiZNQfferIHffo
         HAng==
X-Gm-Message-State: ACrzQf0LwR15U1q6Q7sRQUEYc6GVR6VEmlqXrVk28SYX3OBEkImPKQgL
	WcKoSsdNI7dFO6r0QByk6TQ=
X-Google-Smtp-Source: AMsMyM734mcNOqaQyVw5VGgxbHLjcyWWerZp55lf7Va/IrNJctT3v1+ZCypOyN9zsDrVH5u0l8xF+g==
X-Received: by 2002:a67:e0da:0:b0:3a7:99d5:e1d6 with SMTP id m26-20020a67e0da000000b003a799d5e1d6mr2342708vsl.68.1665457225863;
        Mon, 10 Oct 2022 20:00:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:df95:0:b0:3a6:3be8:f923 with SMTP id x21-20020a67df95000000b003a63be8f923ls2584502vsk.11.-pod-prod-gmail;
 Mon, 10 Oct 2022 20:00:25 -0700 (PDT)
X-Received: by 2002:a67:f59a:0:b0:3a6:fbe0:b8d4 with SMTP id i26-20020a67f59a000000b003a6fbe0b8d4mr9543109vso.5.1665457225305;
        Mon, 10 Oct 2022 20:00:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665457225; cv=none;
        d=google.com; s=arc-20160816;
        b=Wn96bsPwYb2ybP0K4dpJHrhR7SedN98WYHz3+wUGbIFtDQ4y/0wHtAxphE4cmfoQgb
         H70Pgtw9/0UnKtGb4YTAXXvg8tpdli3Xi5ah6URRMm55sSeJyqJ83e6m0frqSJ4VWECw
         wTjWqFCmenQNUkNImIQeDT8jrcizq01S5yoqhns+9/ZeCoDjzt/bO7+gO7R7256zoxf+
         GgA0DRQYUlMPgbIVZu9cVfx+C7o/jGamcJ5Sn4HxAlfqNy3qK98rmSsztOr8o73I2nxc
         hszpDNktwSV5Q2ANFxaSNlGSy4/vNSX5uDq6h6QikOeqeSIp2vKq16aUJT5aDcOiL2y0
         ol7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Qirw48xc/tsq9oJ9bN2wDgpC7gkOILHLI1FFvZKjy0g=;
        b=G2TrGisrRFLb+rixTlgosyQIEpIBEXI/tRGspLXn4ULL3AkwxOrPX2sNBjkktFbZD1
         8/coDoAm+iaFPF+KU3vJjcKpXqLOt3TbDgvgwF4cwXtMTdL+4Dj0IUKgLIidp095Yk3P
         kbVDSRiw41JXs+lQX+ZPrEy4+LsTdW1nXh5tVTersTOx8LaxIUWzuvAya1Escn2Ga8p4
         Mps88z0P+OtB6rGOF8amlm8ljjMD8ihR1A5AP6TNd2ZkaUiACuEYht1/kQI+orw3x7q5
         nFh0rIixnOXbWIkjvUOYOOvmdPtdAn/5evFUVFsv5vhwVE5rRHCsBDo1TCZSzVheE+Rh
         xGJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=HINC5krz;
       spf=pass (google.com: domain of srs0=ame8=2m=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=aME8=2M=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id r11-20020ab06f0b000000b003d919da0471si2068878uah.1.2022.10.10.20.00.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Oct 2022 20:00:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ame8=2m=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id BD5A76106D;
	Tue, 11 Oct 2022 03:00:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 207E1C433D6;
	Tue, 11 Oct 2022 03:00:18 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 0a7ccddd (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Tue, 11 Oct 2022 03:00:16 +0000 (UTC)
Date: Mon, 10 Oct 2022 21:00:08 -0600
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Elliott, Robert (Servers)" <elliott@hpe.com>
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
	Toke =?utf-8?Q?H=C3=B8iland-J=C3=B8rgensen?= <toke@toke.dk>
Subject: Re: [PATCH v6 3/7] treewide: use get_random_{u8,u16}() when
 possible, part 1
Message-ID: <Y0TcOH/BDfg5c1gj@zx2c4.com>
References: <20221010230613.1076905-1-Jason@zx2c4.com>
 <20221010230613.1076905-4-Jason@zx2c4.com>
 <MW5PR84MB18421AC962BE140DDEB58A8BAB239@MW5PR84MB1842.NAMPRD84.PROD.OUTLOOK.COM>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <MW5PR84MB18421AC962BE140DDEB58A8BAB239@MW5PR84MB1842.NAMPRD84.PROD.OUTLOOK.COM>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=HINC5krz;       spf=pass
 (google.com: domain of srs0=ame8=2m=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=aME8=2M=zx2c4.com=Jason@kernel.org";
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

On Tue, Oct 11, 2022 at 01:18:40AM +0000, Elliott, Robert (Servers) wrote:
> 
> > diff --git a/crypto/testmgr.c b/crypto/testmgr.c
> ...
> > @@ -944,7 +944,7 @@ static void generate_random_bytes(u8 *buf, size_t count)
> >  	default:
> >  		/* Fully random bytes */
> >  		for (i = 0; i < count; i++)
> > -			buf[i] = (u8)prandom_u32();
> > +			buf[i] = get_random_u8();
> 
> Should that whole for loop be replaced with this?
>     get_random_bytes(buf, count);

Wow, that's kind of grotesque. Yea, it certainly should. But that's
beyond the scope of this patchset. I'll send a follow-up patch just for
this case to Herbert after this cleanup lands, though.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0TcOH/BDfg5c1gj%40zx2c4.com.
