Return-Path: <kasan-dev+bncBCLI747UVAFRBU7FQCNAMGQEBLWFZ7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 363ED5F797C
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 16:08:21 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id i4-20020a056e02152400b002fa876e95b3sf3885018ilu.17
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 07:08:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665151700; cv=pass;
        d=google.com; s=arc-20160816;
        b=BegTNnUq4JCsWOnYU7l0RBuR4cdWZ/CINdjEQPUDPnOPBNMAZfXtSLxupuPgxH0W9r
         Is15YYZdz7ZTAfFZoijSnh2fRayN6xDakdjT8pgPzK12s2Cwm3lYoOLkd9qdrtEz+vbe
         YOVVs5wR88hprP3l3CWvnfpzIf/5uramf/MXBslN9IocUyITVr3FHgc/w9JvZatFs4R0
         c01LsElKCf8aKH0lMfE0cf15kbgVRzP5EV+xpGE3O6yccXwM4EvIjC7wgFPje40W8Rdy
         858DsXFiGwqmPfJ0WBXKzqJvMe0RykGUAdkDCm41uFMdNMY9hmCiGMGLyd9chMiHAgl6
         14yQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=XbwIcC49WMYZpxX9T0i2RND9IxGcxexAOnkoVyERzdY=;
        b=lJEUU/7V87Z97lyVl7O9vIxiEhz5iWXaHUi2e3/bq28i7s20u5SB2DcC93qQOvSssD
         DCJM5xfDk5CdSoBC+e0ukOAQdwUDsKbmYQyZeDV70W/GZgfDNdIM1MBU63jgnV2W5DF1
         jKIeIFOJoJ6TvmMRR+MQjF9dUjFQ6SbCr+bRdpzWU9x5FkGue6ecbHbNqmhKwkhb2QJB
         6Pm7Z3/Clin2HgJ1a41ltVj+hOjR6jHoWpvIAy+c5Hp4EVvelkDanjH6Yrq0YqcxqG6u
         6XagOOkXiNW82lvq2hVrd51Fno5p2q55sKxx6t3jlN2dbuLoWD9qsfQNRIIkIPELFwL0
         RMHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=nfYgePI9;
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=XbwIcC49WMYZpxX9T0i2RND9IxGcxexAOnkoVyERzdY=;
        b=pQFjW1D7Z7Kb+q5rlC3UntMXftVUGEAmPmGARMavmY7y7B0Ye84XH+pYMy1hmj2MOM
         QbHtf02YGDcx7a4SKCV0SFbO+KVr7BJdDWCrmGaf2oy5fxfs9Azvi5oweLtwqE87FX/Q
         TgM/ea21/YVqVGLQglLnI2h9hitRxY7sTxEcohEBd8MHDlrYGkiSlo++bKFKGpdYO/sF
         r2mdBQ4GPiXI0YCrBmVJlH7WXWHBiavqLkFaSyngo4IOixBHcbkEZxuw+Kw2oaoS6wu4
         XbczzXsdGF1h7nHNuR9qgqqdlRbCEixFLJApww9QMAetTemmPqy2hDX6XM1NOk6uXHQy
         wQnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XbwIcC49WMYZpxX9T0i2RND9IxGcxexAOnkoVyERzdY=;
        b=FFgMyX5Ok0E6q7sn6Ny5NmGpbcHb3ke1GcDKz395pQDf2oqVwwnGeD19Xs29A3ADrV
         cd0nPDN4ekvJFppCi+xokIA5q5Swym1m8sX7JAv78sZH9DNivl58pVF1PcYF/GlncY7w
         3WWlCQDDgd4OrM29F5/pSGfkTdRnFKGXuazr8CDbHW57DwzHqKZbfz406EipuCYcrRQZ
         3ArRPuLkUhD8UJA721j4LkH0VudqThuaQBF5jyhMbak0w8xW4d5wfborKiTye2vGPZeA
         kR/QLjKxLfTotqX70H93zei1k6XcwCiMf8TfVotAMXrnbxmkfRrb2MyuGypWMuMxdfPy
         wxNQ==
X-Gm-Message-State: ACrzQf1NR9WAcLK5hm/7wB82AcSWBLt9y5abpQAb3ZqoWfWDMn8Uz6cL
	u+m+fUxcAb6LJcRwMnB8a3U=
X-Google-Smtp-Source: AMsMyM4bmzUpPVZENxcjCPrhXPjiDoaClNQvFKK4BH0xZb3LXuuYyWbGFEcSlkBU+OnnLYIZxiGknA==
X-Received: by 2002:a02:8807:0:b0:363:937f:6 with SMTP id r7-20020a028807000000b00363937f0006mr1187224jai.136.1665151699741;
        Fri, 07 Oct 2022 07:08:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1114:b0:2fa:722a:fe05 with SMTP id
 u20-20020a056e02111400b002fa722afe05ls1061771ilk.5.-pod-prod-gmail; Fri, 07
 Oct 2022 07:08:19 -0700 (PDT)
X-Received: by 2002:a92:c548:0:b0:2f9:fe3f:f4c2 with SMTP id a8-20020a92c548000000b002f9fe3ff4c2mr2479173ilj.180.1665151699309;
        Fri, 07 Oct 2022 07:08:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665151699; cv=none;
        d=google.com; s=arc-20160816;
        b=wfFPQJXuueuaJjds2lFEsbWFlgM9FH63Ut1tn00tbkQAG30OuCQJCAXnzSkYy3llZC
         KCcOhDGb0uBqx1xS27duzaS3phUUhFEchxM6+T2YyN8xl5uTf0tGginUFveg0wCqHKmT
         hEgaPXYWeWirQJfS1zP7H8PLOHyuPVVm00NHr+arQPlPSEVpPNfj23j2qqIAFh3avutP
         QY1fZPoUC9D+BHfBUVpSc8bXM/MYeOdr2qbQwTxdbtOVIwR1vbPavEe4dc1EfID6E3Nd
         ZFwrLpmrFQnftZzPr56p1813jwI2TAJTJEJq6G/zXTyZB7/O3h6YWt/CuQHZxhYMw5hX
         jdKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=GwMExxyHWRhjupCjy80ATuiTjwid+3186g/nbW9UcWo=;
        b=b7EJaXOLpQePL0EdKnmxOEESgolo5mzHNETxilbrlBMBlhGt19dpSKlMHdcNhLe21Y
         U5QG7gg2R7ahvc3tID8dfWVZMboPBfId/QTPQMS3P+gaFdP6GjnZQ1pqkphfrp3+Cowg
         7Jv6rWo8iSxa9aZaRhuTYkctWHE8TtmGXtA+sjKdzuImcOWOfpq6x4Qik4AMm8Hw0Vio
         ayeDON8nyYSuZ1iu5IBWrormhnCr4TSixIrL+zflxBeyQjJ4KI+52d4WCKztsAPl6RYu
         enpFF4m1t2s8h6QbZ5D4sW7MZQX0y//DlnqcqDMdOvOtRO6ss/bHK0itRploKY4C09Cq
         reig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=nfYgePI9;
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id l9-20020a02cce9000000b00349dba16b8dsi77630jaq.6.2022.10.07.07.08.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 07:08:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D63CA61D26;
	Fri,  7 Oct 2022 14:08:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 070E7C433C1;
	Fri,  7 Oct 2022 14:08:11 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 7db71c1d (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Fri, 7 Oct 2022 14:08:08 +0000 (UTC)
Date: Fri, 7 Oct 2022 08:07:58 -0600
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"patches@lists.linux.dev" <patches@lists.linux.dev>,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph =?utf-8?Q?B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
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
	Chuck Lever <chuck.lever@oracle.com>, Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v3 3/5] treewide: use get_random_u32() when possible
Message-ID: <Y0Ayvov/KQmrIwTS@zx2c4.com>
References: <20221006165346.73159-1-Jason@zx2c4.com>
 <20221006165346.73159-4-Jason@zx2c4.com>
 <848ed24c-13ef-6c38-fd13-639b33809194@csgroup.eu>
 <CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg@mail.gmail.com>
 <f10fcfbf-2da6-cf2d-6027-fbf8b52803e9@csgroup.eu>
 <6396875c-146a-acf5-dd9e-7f93ba1b4bc3@csgroup.eu>
 <CAHmME9pE4saqnwxhsAwt-xegYGjsavPOGnHCbZhUXD7kaJ+GAA@mail.gmail.com>
 <501b0fc3-6c67-657f-781e-25ee0283bc2e@csgroup.eu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <501b0fc3-6c67-657f-781e-25ee0283bc2e@csgroup.eu>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=nfYgePI9;       spf=pass
 (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
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

On Fri, Oct 07, 2022 at 04:57:24AM +0000, Christophe Leroy wrote:
>=20
>=20
> Le 07/10/2022 =C3=A0 01:36, Jason A. Donenfeld a =C3=A9crit=C2=A0:
> > On 10/6/22, Christophe Leroy <christophe.leroy@csgroup.eu> wrote:
> >>
> >>
> >> Le 06/10/2022 =C3=A0 19:31, Christophe Leroy a =C3=A9crit :
> >>>
> >>>
> >>> Le 06/10/2022 =C3=A0 19:24, Jason A. Donenfeld a =C3=A9crit :
> >>>> Hi Christophe,
> >>>>
> >>>> On Thu, Oct 6, 2022 at 11:21 AM Christophe Leroy
> >>>> <christophe.leroy@csgroup.eu> wrote:
> >>>>> Le 06/10/2022 =C3=A0 18:53, Jason A. Donenfeld a =C3=A9crit :
> >>>>>> The prandom_u32() function has been a deprecated inline wrapper ar=
ound
> >>>>>> get_random_u32() for several releases now, and compiles down to th=
e
> >>>>>> exact same code. Replace the deprecated wrapper with a direct call=
 to
> >>>>>> the real function. The same also applies to get_random_int(), whic=
h is
> >>>>>> just a wrapper around get_random_u32().
> >>>>>>
> >>>>>> Reviewed-by: Kees Cook <keescook@chromium.org>
> >>>>>> Acked-by: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk> # for sc=
h_cake
> >>>>>> Acked-by: Chuck Lever <chuck.lever@oracle.com> # for nfsd
> >>>>>> Reviewed-by: Jan Kara <jack@suse.cz> # for ext4
> >>>>>> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> >>>>>> ---
> >>>>>
> >>>>>> diff --git a/arch/powerpc/kernel/process.c
> >>>>>> b/arch/powerpc/kernel/process.c
> >>>>>> index 0fbda89cd1bb..9c4c15afbbe8 100644
> >>>>>> --- a/arch/powerpc/kernel/process.c
> >>>>>> +++ b/arch/powerpc/kernel/process.c
> >>>>>> @@ -2308,6 +2308,6 @@ void notrace __ppc64_runlatch_off(void)
> >>>>>>     unsigned long arch_align_stack(unsigned long sp)
> >>>>>>     {
> >>>>>>         if (!(current->personality & ADDR_NO_RANDOMIZE) &&
> >>>>>> randomize_va_space)
> >>>>>> -             sp -=3D get_random_int() & ~PAGE_MASK;
> >>>>>> +             sp -=3D get_random_u32() & ~PAGE_MASK;
> >>>>>>         return sp & ~0xf;
> >>>>>
> >>>>> Isn't that a candidate for prandom_u32_max() ?
> >>>>>
> >>>>> Note that sp is deemed to be 16 bytes aligned at all time.
> >>>>
> >>>> Yes, probably. It seemed non-trivial to think about, so I didn't. Bu=
t
> >>>> let's see here... maybe it's not too bad:
> >>>>
> >>>> If PAGE_MASK is always ~(PAGE_SIZE-1), then ~PAGE_MASK is
> >>>> (PAGE_SIZE-1), so prandom_u32_max(PAGE_SIZE) should yield the same
> >>>> thing? Is that accurate? And holds across platforms (this comes up a
> >>>> few places)? If so, I'll do that for a v4.
> >>>>
> >>>
> >>> On powerpc it is always (from arch/powerpc/include/asm/page.h) :
> >>>
> >>> /*
> >>>    * Subtle: (1 << PAGE_SHIFT) is an int, not an unsigned long. So if=
 we
> >>>    * assign PAGE_MASK to a larger type it gets extended the way we wa=
nt
> >>>    * (i.e. with 1s in the high bits)
> >>>    */
> >>> #define PAGE_MASK      (~((1 << PAGE_SHIFT) - 1))
> >>>
> >>> #define PAGE_SIZE        (1UL << PAGE_SHIFT)
> >>>
> >>>
> >>> So it would work I guess.
> >>
> >> But taking into account that sp must remain 16 bytes aligned, would it
> >> be better to do something like ?
> >>
> >> 	sp -=3D prandom_u32_max(PAGE_SIZE >> 4) << 4;
> >>
> >> 	return sp;
> >=20
> > Does this assume that sp is already aligned at the beginning of the
> > function? I'd assume from the function's name that this isn't the
> > case?
>=20
> Ah you are right, I overlooked it.

So I think to stay on the safe side, I'm going to go with
`prandom_u32_max(PAGE_SIZE)`. Sound good?

Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y0Ayvov/KQmrIwTS%40zx2c4.com.
