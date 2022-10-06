Return-Path: <kasan-dev+bncBCLI747UVAFRBXM67SMQMGQEBVCPGRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B7605F6CD6
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 19:24:47 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id m21-20020a17090a7f9500b0020a88338009sf1384379pjl.4
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 10:24:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665077085; cv=pass;
        d=google.com; s=arc-20160816;
        b=BKjqCimzdZoEMibjeXZfpGuz0ioHb1IBNgH2QdnyRF7COovf+tpYqb0+SLdo9ZtzAJ
         c1mrDJmeUJQvXROI6FwoSRpJBtRtVEYjZhjLuAsd3hgFg+RGO6LiTRJYyuw2OGo9c1yk
         WXz8E1TRC1q9rCP56wDUjtYtpgN9gTzoSpGibV7NN8X2sLhx/tis4fyf2gXcQWHPTTmP
         0RyTKgUpeF77o7uQ5YUv5aVxxQX4X6W2MbGe1ZcixMwtfAdl0KdpR8U4DcyD+knjbsPU
         jgHiRO8AQan7nsVO/T35ft3/U6LjGkRh/jMxkuT+Sv7P8aCukDgoGGlhX17Un8q2bJUn
         EFUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wS7xtzrMPOu5jQraSq+TnZO5QwFh44WmaqNwjmwTYLM=;
        b=qocfhE+wtYcJV+PV2tEER9+u0pQ5eXb0NGNIF3j0bMC6pmCg/8lerHWNN6RQZbMNSL
         ggLQJ1HtRbjMZc7Qhf5+0N41hwAhXAN+UzdUn9VWfWV+og+PbZr42FfAGx0NbgJX7TXk
         uEoel/7j74AMlvfTXP3Eos07HlBiUHi+d75LxVV0GF+GSSOwVu9jiMA1Vd8HrBlSkW8K
         CzPtEKBLTEaelCX/8GMeXw8zsiLi9IedprXFB6Xn5iBdXeT1pTNAAGkagKpmQnQ+yz4p
         udCrx1BVAZ0KVivJBsnKr1g8qoLt2uYOtb30IstWINMp6DcJbPyaHc3nJ0QzTBJjSg2v
         IpiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=So1DAGzC;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wS7xtzrMPOu5jQraSq+TnZO5QwFh44WmaqNwjmwTYLM=;
        b=DqT1Uzzh/hXWJ70vDRro6YQjOvGElnhARIw5DNNY+UwkFcYnca4hBRiOt6kyOl73SP
         YwJvqS0E52SrAvrc5IwpQMzLtelA+mDxeGbci8df6DLnYM9ZQXN2RNFahTv/K/FMWGTj
         z4gv58MjMPIMI5k43Oi/tS2UFGJirSH28TRaCX3lgriE6+n2u7+/8o8Rwub3a/6JaaUV
         /wgFvv8e78mZCv4Z5xS3GzWhzMC+Q6y3OnNP2tTaTz6E4WUq7Elz67VVH0CDIwEYUUWs
         tWAF3gQu+HH4E9KyYJMX7CrURvI8V9aEZZrrMO9L5gFpvzkGE66v+Ag+hn5/Gc7MWdIB
         3jzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wS7xtzrMPOu5jQraSq+TnZO5QwFh44WmaqNwjmwTYLM=;
        b=lcrvU0Q2tDClq+0g2CTEKnrnQNJiUUd540y8bRw2coqxFwKtco5DGaqzvMqcH2eCDP
         ZvY406VVpVcLVVbcjvCrABZQZYBbW8Jg1INtf/nUcylTf8276rciaAkhR/lTYjxf66NY
         FQzhFTT8iFpyD5HJR/4YleyTlj+E8zmiyOoQeKJnLpCn+dCRiFRQ1c7w7S0iSpQH3EVs
         dbRIWa6bl3zeNpdpQvCNxQYmR3sg4qONXKjrALENQOSGexPRAIMPACaP7Z1MYl2TTHHL
         7JQt0+yAQcqzIPrZA6G5Dv5p4WTZ+91pXbX5Ih8PZwTK0iF0KrrCJn57Kzia6pt+FrQl
         8jbA==
X-Gm-Message-State: ACrzQf3f5jUp+mMpyGcZHSWqgH+WCPImtssok2lrnzTDwFIjOiLfsJOk
	PsL1eLDJ5bOcT4382okBwrQ=
X-Google-Smtp-Source: AMsMyM61H3qZFP8DTS36kycF1VyZuuV0l8zGwf4pGea3peEgxGa+BiqRiw2dvIe3YusaCStjQjvLzw==
X-Received: by 2002:a17:902:e74f:b0:179:fdfd:2c84 with SMTP id p15-20020a170902e74f00b00179fdfd2c84mr544272plf.41.1665077085814;
        Thu, 06 Oct 2022 10:24:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:be04:b0:172:8d81:7e5b with SMTP id
 r4-20020a170902be0400b001728d817e5bls2014856pls.6.-pod-prod-gmail; Thu, 06
 Oct 2022 10:24:45 -0700 (PDT)
X-Received: by 2002:a17:902:e84c:b0:178:2a08:501c with SMTP id t12-20020a170902e84c00b001782a08501cmr909080plg.110.1665077085098;
        Thu, 06 Oct 2022 10:24:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665077085; cv=none;
        d=google.com; s=arc-20160816;
        b=J8qNDqCXuuhWjM7qn1nSfnzzzjiH8dmDJZH7PrvZalNJnLdhAgYnG5HFFSkwXNgyqG
         NwKiHmyPU/uvSU0gFw0jWxCkO79kCNL2c4ggAoRYk7sjSCjIShhbYeiLiDRXjYBkZ5sQ
         stgIv0ljnacdfBoGQwroQeZQ3F45kzt5qs8Q7cNPcAsVF5UTqJwfjBUUOXHIArLs9IDy
         CPjnf4TVxbuSXSRbBvQpHTxKKyDFPak8yvbcCDeZ8fMyiY4Cn7mLswcG2sIyQIr6hJsH
         s4a7fAf5o/OawQqFhiDPp2aeF8tIVyLZWJa/4MPb+kbgHat3F8sL71nVQlA29oprWlG4
         IOxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hw+hnIMvKUNp0lwyCAgNJh72KYkKEhg87FRQTBs88Es=;
        b=cXtFRwILw6IO43gsQeXQLikAG5PzuvqYd0a/Do8lsiENFWFLWPGUbDxBJmvTc135jz
         +JxgYJkfQngNj1NW7k0ZwexwD6koItFFgpPQjONoMDtWiCkcCOk1sofaiyYkUi3+hcAG
         KtY7WthN7Dbow/dc4WMcbLwsUnMsklOO4lQWhwdF8tmwJoAD1/eZxujzb8r3r+lwIEZh
         EDFzViVVyta5QN5cEW/bw1laA2bYuTCtdkLyKZR1Tgma5cNMJ/sjJhkHZnpwsZY1jg1h
         nI6/JejKyWkk9jvfHwYbMJU6oZSOxexlwvnyEx74FEKDUaqHGDx82KolaQBENlYwcLiH
         dhgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=So1DAGzC;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d125-20020a621d83000000b0051c55b05eaesi599950pfd.5.2022.10.06.10.24.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 10:24:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 94FC0619DD
	for <kasan-dev@googlegroups.com>; Thu,  6 Oct 2022 17:24:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CD0CFC433D6
	for <kasan-dev@googlegroups.com>; Thu,  6 Oct 2022 17:24:43 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 90892c8c (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Thu, 6 Oct 2022 17:24:38 +0000 (UTC)
Received: by mail-yb1-f169.google.com with SMTP id e20so3024292ybh.2
        for <kasan-dev@googlegroups.com>; Thu, 06 Oct 2022 10:24:37 -0700 (PDT)
X-Received: by 2002:ab0:6cb0:0:b0:3d7:1184:847f with SMTP id
 j16-20020ab06cb0000000b003d71184847fmr777504uaa.49.1665077067240; Thu, 06 Oct
 2022 10:24:27 -0700 (PDT)
MIME-Version: 1.0
References: <20221006165346.73159-1-Jason@zx2c4.com> <20221006165346.73159-4-Jason@zx2c4.com>
 <848ed24c-13ef-6c38-fd13-639b33809194@csgroup.eu>
In-Reply-To: <848ed24c-13ef-6c38-fd13-639b33809194@csgroup.eu>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Oct 2022 11:24:16 -0600
X-Gmail-Original-Message-ID: <CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg@mail.gmail.com>
Message-ID: <CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg@mail.gmail.com>
Subject: Re: [PATCH v3 3/5] treewide: use get_random_u32() when possible
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"patches@lists.linux.dev" <patches@lists.linux.dev>, Andreas Noever <andreas.noever@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, 
	=?UTF-8?Q?Christoph_B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>, 
	Christoph Hellwig <hch@lst.de>, Daniel Borkmann <daniel@iogearbox.net>, Dave Airlie <airlied@redhat.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, "David S . Miller" <davem@davemloft.net>, 
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, "H . Peter Anvin" <hpa@zytor.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Helge Deller <deller@gmx.de>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Huacai Chen <chenhuacai@kernel.org>, 
	Hugh Dickins <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>, 
	"James E . J . Bottomley" <jejb@linux.ibm.com>, Jan Kara <jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
	Jens Axboe <axboe@kernel.dk>, Johannes Berg <johannes@sipsolutions.net>, 
	Jonathan Corbet <corbet@lwn.net>, Jozsef Kadlecsik <kadlec@netfilter.org>, KP Singh <kpsingh@kernel.org>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mauro Carvalho Chehab <mchehab@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Pablo Neira Ayuso <pablo@netfilter.org>, Paolo Abeni <pabeni@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Richard Weinberger <richard@nod.at>, 
	Russell King <linux@armlinux.org.uk>, "Theodore Ts'o" <tytso@mit.edu>, 
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Ulf Hansson <ulf.hansson@linaro.org>, 
	Vignesh Raghavendra <vigneshr@ti.com>, WANG Xuerui <kernel@xen0n.name>, Will Deacon <will@kernel.org>, 
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
	"linux-mips@vger.kernel.org" <linux-mips@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
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
	"sparclinux@vger.kernel.org" <sparclinux@vger.kernel.org>, "x86@kernel.org" <x86@kernel.org>, 
	=?UTF-8?B?VG9rZSBIw7hpbGFuZC1Kw7hyZ2Vuc2Vu?= <toke@toke.dk>, 
	Chuck Lever <chuck.lever@oracle.com>, Jan Kara <jack@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=So1DAGzC;       spf=pass
 (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
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

Hi Christophe,

On Thu, Oct 6, 2022 at 11:21 AM Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
> Le 06/10/2022 =C3=A0 18:53, Jason A. Donenfeld a =C3=A9crit :
> > The prandom_u32() function has been a deprecated inline wrapper around
> > get_random_u32() for several releases now, and compiles down to the
> > exact same code. Replace the deprecated wrapper with a direct call to
> > the real function. The same also applies to get_random_int(), which is
> > just a wrapper around get_random_u32().
> >
> > Reviewed-by: Kees Cook <keescook@chromium.org>
> > Acked-by: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk> # for sch_cak=
e
> > Acked-by: Chuck Lever <chuck.lever@oracle.com> # for nfsd
> > Reviewed-by: Jan Kara <jack@suse.cz> # for ext4
> > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> > ---
>
> > diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/proces=
s.c
> > index 0fbda89cd1bb..9c4c15afbbe8 100644
> > --- a/arch/powerpc/kernel/process.c
> > +++ b/arch/powerpc/kernel/process.c
> > @@ -2308,6 +2308,6 @@ void notrace __ppc64_runlatch_off(void)
> >   unsigned long arch_align_stack(unsigned long sp)
> >   {
> >       if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_s=
pace)
> > -             sp -=3D get_random_int() & ~PAGE_MASK;
> > +             sp -=3D get_random_u32() & ~PAGE_MASK;
> >       return sp & ~0xf;
>
> Isn't that a candidate for prandom_u32_max() ?
>
> Note that sp is deemed to be 16 bytes aligned at all time.

Yes, probably. It seemed non-trivial to think about, so I didn't. But
let's see here... maybe it's not too bad:

If PAGE_MASK is always ~(PAGE_SIZE-1), then ~PAGE_MASK is
(PAGE_SIZE-1), so prandom_u32_max(PAGE_SIZE) should yield the same
thing? Is that accurate? And holds across platforms (this comes up a
few places)? If so, I'll do that for a v4.

Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg%40mail.gmail.=
com.
