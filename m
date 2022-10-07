Return-Path: <kasan-dev+bncBCF5XGNWYQBRBDN4QGNAMGQERHP2I6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 79AA45F7C03
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 19:12:47 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-130cf89e654sf2915258fac.20
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 10:12:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665162766; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZKaN1dgDqRdoUNK5FIxA4N4cmThQz4eQf3Nd29H0IBTbj4FRE3rWdD2ZVQMTfUTvKM
         tZU6OX5oLSOdr3LvYDVhwIAtqpcuGYhbunDoFBxW/S6lKc4cCusM7sljS4f9HGD/gtr+
         1f2UGnja+ex6RhWYRAY9LV3OUVOmRRt5p8Zys5Q0Yl/9KvPiQvuEkhhFEQIz0dfY6PfP
         DeuJfTyBOsuLgHQD22D209h2RXEptRQKOaH7Tx0Ko+H+8/T+QnuhR/PvFxeHJ3BeVfzr
         pJ+YCi27eB++vuGAwa32RXZ1xtRR2Oebc9QwkC0ECAwKS3+wVx7gip90G/IZV6S4BzQS
         WDHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=8YOaZnb/tjK2y3Zu0JbiIxOAEjSFXx1WGuUjW4vYF/U=;
        b=AuAB/jPkWnEv7e9avrBfU9aq3Yg2scQZgv2APSOug+6volrPUeugchs8mNrGZHBrJe
         sn8SmXB/6CQDhTjK3TiOeEVWTOdBp8FIbYuyD0WjuYUgjSa0EMhfDSs8KNvHWICavRri
         iE4JycUcFk6XSo1ezTYgmFaPav1lznn9MQXP7D7si7XVpmf328NixRW6XzEp9o6SSCSi
         2wJZFST9qFegDbUjmC25CfVl55fJ5t0LNS6j3rpLG4gEyLfpmcF8Q3u838EsllehPCq9
         ofyInYyos2+kOpj3bz56+UvjBYW3E91HlnyGhDbRU/oEKP3dHynj6xrawtKVy7c1TEt1
         wwdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lnyLGuYm;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8YOaZnb/tjK2y3Zu0JbiIxOAEjSFXx1WGuUjW4vYF/U=;
        b=juPyLVj2bWahaBtzyKXGK7IVlDyZ1Bd+OmVptaNvmCI2XdpSKrVMqXbncwWcPUynuV
         XQMdaDTiXPIfSuu0kZo8QAv/4Jms6I+cZGtsXdtGtF8Na5sxBhmrE/Hma8gVzLaCFn3A
         ZcDVHy3RcbKU5fPzIYsZmIQxvOxUxagvlRaVB3gocxg04bKezAU9bbA2TJT72DAd1/93
         pJwww5D+fS881Lap5WBtKgh6B38+Id2RmzFE8Qo12xeaxASeDtAIey0aeN4JqKXUlsxZ
         aobG/uvaDC2zbhZHxj/QoTJMO/XPLhYuKw5RslyOcjK1tEkXhDGmYETXssc5ErZECTtJ
         w1ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8YOaZnb/tjK2y3Zu0JbiIxOAEjSFXx1WGuUjW4vYF/U=;
        b=KlgX0b3ewOWrppI0xnEmmJenVOS/CwrpUgApHihSABZcPBGQuELw7FNAfde5dRNofa
         HnbFpw3v8UrCRhLYxmvi1KMbLA+tEntTp6iJvfGCEhzER7cqC2jWjFqAryM82f7t/QSi
         iPAvUJGexcVWAyLREeh1d0JT8vLQhPVRvkQrcoy9o9EOCsQR9N5HA3TGabj8fu2GPoGW
         tHggg5B31qiOb7IFdw76JX5AFySgue+zP5R+LWJVOF//ynSyYH9huA7qOV0lVOtUyQMG
         c8VGNyAvf8WeX2tPiLBkUz6BqAMF2PhYcvIYVQjSQHYNy7UBaGyptEZP0VhI65UQUvrH
         no0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3be9l3qtq9SqoVZjwYfiQmMiz1Gixw3Xk8ma725rCoL16NGyne
	+0sGPLgSNyt+Y7YAEEU52Ek=
X-Google-Smtp-Source: AMsMyM7KCOi0Mi8xNCA5P2xg6/Yyk4mNseDzxzM4uzVd8aOl02d/kV3JtrbACc35aqfHcCAfsXayDw==
X-Received: by 2002:a05:6870:8890:b0:12c:dd21:304f with SMTP id m16-20020a056870889000b0012cdd21304fmr8787147oam.237.1665162765871;
        Fri, 07 Oct 2022 10:12:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:dbc5:0:b0:351:10b5:2e7b with SMTP id s188-20020acadbc5000000b0035110b52e7bls1667155oig.11.-pod-prod-gmail;
 Fri, 07 Oct 2022 10:12:45 -0700 (PDT)
X-Received: by 2002:a05:6808:17a7:b0:350:d0af:21a9 with SMTP id bg39-20020a05680817a700b00350d0af21a9mr8265401oib.248.1665162765276;
        Fri, 07 Oct 2022 10:12:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665162765; cv=none;
        d=google.com; s=arc-20160816;
        b=mRx8pYluxv3yc7M1Fv0vcZ8BmPz1oE2ezVTXZrk8eZEY/VIaGafPf1lees/8PYDJHO
         wh6g+O/4/WhJ/3IKvLMHuuW2uwNNHLQyrVAXxy9U6TrFM+3mfR6JtjDG4ck8MrZ0BQmH
         TkQy0ZKB/1MdnxdNiOHeV6CkMNSLXAWrnfTIOYeLgJhZI25pbAwURlB7IlW0LVoS3R5o
         5VE+oLT0+KjAHe+YRendKJSaNG+0GUqID7Dwc5pM5RMtciauOYlfOdkbt6hpnKu+44uc
         u2g3mkcsyhlbnAH3Zn+J2gJsN/FKGSE9T018XzJn/qKTsUjg1/AfOpEcAGiSwo6zWibA
         Fyvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=r+ar3rF5Nifj4ZH0w5BLPJvorwhCPz9FpYPvkQg1fFY=;
        b=nVQzdLZib/vSKIaaq45JgWQHHl0gBBsLYCoTbNfMW/FeOsN0F0WGWOJGbp8a4dFOm4
         aXPQcFcJcqlsOEm+ML8efQP5YZnVfSJst8D6YykSzRI2nHQZ98b33RIpXKy0PbF0mLAt
         OSWIfgHwrOveZIL8Oeq4j4lFMpNprAriLHZX3xpKfPJX/xp0nN/6KonW/fvct08ydYUX
         WoxMrJkDXsQSG+HXrQNhoXDrM5zOIKN0YnjEh3kPLDlIpkvrPB+MDu8a8ix0gnLR247N
         h0rocsIqHrz9/wqmeBTPR0k+mA+k9tDs8vDwbZrZZk/s39Sa6vlUNAk5xxDFNT9OQTPY
         HQyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lnyLGuYm;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id v22-20020a056870709600b0013191afecb8si176530oae.2.2022.10.07.10.12.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Oct 2022 10:12:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id 2so5196629pgl.7
        for <kasan-dev@googlegroups.com>; Fri, 07 Oct 2022 10:12:45 -0700 (PDT)
X-Received: by 2002:a63:8149:0:b0:459:4e80:56bc with SMTP id t70-20020a638149000000b004594e8056bcmr5537842pgd.538.1665162764512;
        Fri, 07 Oct 2022 10:12:44 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id o68-20020a62cd47000000b00540a8074c9dsm1849097pfg.166.2022.10.07.10.12.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Oct 2022 10:12:43 -0700 (PDT)
Date: Fri, 7 Oct 2022 10:12:42 -0700
From: Kees Cook <keescook@chromium.org>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"patches@lists.linux.dev" <patches@lists.linux.dev>,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph =?iso-8859-1?Q?B=F6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
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
	KP Singh <kpsingh@kernel.org>, Marco Elver <elver@google.com>,
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
	Toke =?iso-8859-1?Q?H=F8iland-J=F8rgensen?= <toke@toke.dk>,
	Chuck Lever <chuck.lever@oracle.com>, Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v3 3/5] treewide: use get_random_u32() when possible
Message-ID: <202210071010.52C672FA9@keescook>
References: <20221006165346.73159-1-Jason@zx2c4.com>
 <20221006165346.73159-4-Jason@zx2c4.com>
 <848ed24c-13ef-6c38-fd13-639b33809194@csgroup.eu>
 <CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg@mail.gmail.com>
 <f10fcfbf-2da6-cf2d-6027-fbf8b52803e9@csgroup.eu>
 <6396875c-146a-acf5-dd9e-7f93ba1b4bc3@csgroup.eu>
 <CAHmME9pE4saqnwxhsAwt-xegYGjsavPOGnHCbZhUXD7kaJ+GAA@mail.gmail.com>
 <501b0fc3-6c67-657f-781e-25ee0283bc2e@csgroup.eu>
 <Y0Ayvov/KQmrIwTS@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <Y0Ayvov/KQmrIwTS@zx2c4.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=lnyLGuYm;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::531
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Fri, Oct 07, 2022 at 08:07:58AM -0600, Jason A. Donenfeld wrote:
> On Fri, Oct 07, 2022 at 04:57:24AM +0000, Christophe Leroy wrote:
> >=20
> >=20
> > Le 07/10/2022 =C3=A0 01:36, Jason A. Donenfeld a =C3=A9crit=C2=A0:
> > > On 10/6/22, Christophe Leroy <christophe.leroy@csgroup.eu> wrote:
> > >>
> > >>
> > >> Le 06/10/2022 =C3=A0 19:31, Christophe Leroy a =C3=A9crit :
> > >>>
> > >>>
> > >>> Le 06/10/2022 =C3=A0 19:24, Jason A. Donenfeld a =C3=A9crit :
> > >>>> Hi Christophe,
> > >>>>
> > >>>> On Thu, Oct 6, 2022 at 11:21 AM Christophe Leroy
> > >>>> <christophe.leroy@csgroup.eu> wrote:
> > >>>>> Le 06/10/2022 =C3=A0 18:53, Jason A. Donenfeld a =C3=A9crit :
> > >>>>>> The prandom_u32() function has been a deprecated inline wrapper =
around
> > >>>>>> get_random_u32() for several releases now, and compiles down to =
the
> > >>>>>> exact same code. Replace the deprecated wrapper with a direct ca=
ll to
> > >>>>>> the real function. The same also applies to get_random_int(), wh=
ich is
> > >>>>>> just a wrapper around get_random_u32().
> > >>>>>>
> > >>>>>> Reviewed-by: Kees Cook <keescook@chromium.org>
> > >>>>>> Acked-by: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk> # for =
sch_cake
> > >>>>>> Acked-by: Chuck Lever <chuck.lever@oracle.com> # for nfsd
> > >>>>>> Reviewed-by: Jan Kara <jack@suse.cz> # for ext4
> > >>>>>> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> > >>>>>> ---
> > >>>>>
> > >>>>>> diff --git a/arch/powerpc/kernel/process.c
> > >>>>>> b/arch/powerpc/kernel/process.c
> > >>>>>> index 0fbda89cd1bb..9c4c15afbbe8 100644
> > >>>>>> --- a/arch/powerpc/kernel/process.c
> > >>>>>> +++ b/arch/powerpc/kernel/process.c
> > >>>>>> @@ -2308,6 +2308,6 @@ void notrace __ppc64_runlatch_off(void)
> > >>>>>>     unsigned long arch_align_stack(unsigned long sp)
> > >>>>>>     {
> > >>>>>>         if (!(current->personality & ADDR_NO_RANDOMIZE) &&
> > >>>>>> randomize_va_space)
> > >>>>>> -             sp -=3D get_random_int() & ~PAGE_MASK;
> > >>>>>> +             sp -=3D get_random_u32() & ~PAGE_MASK;
> > >>>>>>         return sp & ~0xf;
> > >>>>>
> > >>>>> Isn't that a candidate for prandom_u32_max() ?
> > >>>>>
> > >>>>> Note that sp is deemed to be 16 bytes aligned at all time.
> > >>>>
> > >>>> Yes, probably. It seemed non-trivial to think about, so I didn't. =
But
> > >>>> let's see here... maybe it's not too bad:
> > >>>>
> > >>>> If PAGE_MASK is always ~(PAGE_SIZE-1), then ~PAGE_MASK is
> > >>>> (PAGE_SIZE-1), so prandom_u32_max(PAGE_SIZE) should yield the same
> > >>>> thing? Is that accurate? And holds across platforms (this comes up=
 a
> > >>>> few places)? If so, I'll do that for a v4.
> > >>>>
> > >>>
> > >>> On powerpc it is always (from arch/powerpc/include/asm/page.h) :
> > >>>
> > >>> /*
> > >>>    * Subtle: (1 << PAGE_SHIFT) is an int, not an unsigned long. So =
if we
> > >>>    * assign PAGE_MASK to a larger type it gets extended the way we =
want
> > >>>    * (i.e. with 1s in the high bits)
> > >>>    */
> > >>> #define PAGE_MASK      (~((1 << PAGE_SHIFT) - 1))
> > >>>
> > >>> #define PAGE_SIZE        (1UL << PAGE_SHIFT)
> > >>>
> > >>>
> > >>> So it would work I guess.
> > >>
> > >> But taking into account that sp must remain 16 bytes aligned, would =
it
> > >> be better to do something like ?
> > >>
> > >> 	sp -=3D prandom_u32_max(PAGE_SIZE >> 4) << 4;
> > >>
> > >> 	return sp;
> > >=20
> > > Does this assume that sp is already aligned at the beginning of the
> > > function? I'd assume from the function's name that this isn't the
> > > case?
> >=20
> > Ah you are right, I overlooked it.
>=20
> So I think to stay on the safe side, I'm going to go with
> `prandom_u32_max(PAGE_SIZE)`. Sound good?

Given these kinds of less mechanical changes, it may make sense to split
these from the "trivial" conversions in a treewide patch. The chance of
needing a revert from the simple 1:1 conversions is much lower than the
need to revert by-hand changes.

The Cocci script I suggested in my v1 review gets 80% of the first
patch, for example.

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/202210071010.52C672FA9%40keescook.
