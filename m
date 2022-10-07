Return-Path: <kasan-dev+bncBCLI747UVAFRBWWQQGNAMGQEOSYI5WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id A359F5F7C86
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 19:56:43 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id n32-20020a05600c3ba000b003b5054c71fasf4685045wms.9
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 10:56:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665165403; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Kcq1L/WD0x13HTtAuVaBDU4vexc5kopms+RpmAEEHNkJXBBApDn0QZyrB4ZG7iFSk
         Nqkz8bxaE0VoxDogxVs0+tyTnj5Uvr6OyYW9L8KzH+byCcdlfwcTHQRs3UMO82WTQWDR
         T7Wpa3d16LsZOgtK5pE3yg4t9/jMhIs1oStzc77kK/N/PMRdmlvlG1PPAe2JnN85O/Wq
         SNz7bmbEVLe5EW1MqL5qfQJ97cek2Mv+kIYnZZ7jjufAkQyB60N0S3zCqOlCatxy3og9
         Nfzt2I1xzzXC2opyNqKN9/jtRlJ0SsvYWv3tvr+ui2wpFm3LeDGNEAgUW6DZwlywl/ok
         UtBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=TsXQP6hUvNiIhyHXiMMaANWE/JIVuV+dJQ5zRo5eh50=;
        b=SbrxXgt76fyVPq69mL8ylOGVyhAHw4kTwbbsk1f3S5T362/T+IFeegjXeeK0pX2FBN
         f1nrKlb+UlsiUjh1sFAhxOYuGzxuwknsT38yOW9TY9T67n5m7AJf6L18mDCsrtT+IHOF
         SUtu9s2iGoVeAVA0rdq9mi3fwEAMnFp3O6dRamgbFHgxBlCgAiM06A41qn6Cdj7AacGl
         R7qUBZnKnXc83GG+fnD4e23Z01n4sPqrtvIFTW8xkKeGmWqjV/zUUJxF2Ou2Z1hkda1x
         ykjopC+fF9VomMIlOd2UcahnsP01BZtyIfTs1/7RgWWyTXa76P1NEnN9sd9aOGs/YaW1
         bUdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=f8gITOWu;
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=TsXQP6hUvNiIhyHXiMMaANWE/JIVuV+dJQ5zRo5eh50=;
        b=YjpSbJsiUaRPuWi5KRR6xRQh/GPWO2CgrLWpNP/SewzqE0MOlmgnLCHX2UiE/QnLL4
         CFtOmtsSAL/r/0jCCyEazRg6yWKoUh/pPSf9OYLJ365/gJeQk6QybGGlkllpoDdXmkbG
         DrbolN4yK/KxKmdDunRACcAHrMDog862yHesBuCPXDNSD2Tu8hUaxNCG2uxHBzLuGNDv
         o84AAtf6rtQ5dJ5VB8oFLazbecmZMHsMtmhGVHUwlM7sFd+KVmpD17OOcfLSxvExQY20
         lvyjdHjkCjpIGBzjABUlwcbfURCcAIO8OcPRgvIohnVVorGdSa57vFQD8dDEvrS8n46h
         Viiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TsXQP6hUvNiIhyHXiMMaANWE/JIVuV+dJQ5zRo5eh50=;
        b=dkNTFQt/avOo6fdxttKEZHPk9Tc16FuqVsK9fbcUc/7DLDjf/9SdIsvM79f7wlkZAH
         V+79WqLyLgrS6xCFlW9cVL8WkJhfnzyhNvDCQFyXmuJ81FLGM3tHcE4EY4uIlX5x2jpM
         ZU7skajoPmvrSWzP7p1DZjWt3S0TQ1kI0DUq+vl5FakrWM0EpzniKsUYMvHGBZaLgsy9
         nf0f9Y90JUC5DapF1a9h2OEdiAKUZ1O49BCM2ChUFwVDBEuJ08ZGTcgb/CDipBmjtWO4
         cAQHlO6u6ezb5Wv1rOhcPYKpfrrz0/OC5SDKq4u2kZp6zFeTulQyCaXPKKEuZb+soet4
         kxpQ==
X-Gm-Message-State: ACrzQf3nKa6og5q1q4+VblpyTiTh+fnLbQ0zbWShGAFB04yqgaOAc1wt
	FOx/ygvD9R8JKIPgRo/iH1E=
X-Google-Smtp-Source: AMsMyM7QbwjhRfwdZZTdjNp/yYZUJE3EArK4WFakTIL6kxxY5yD0CaOGLAgSaBGNubYbC6MwTPHHXg==
X-Received: by 2002:a05:6000:547:b0:218:5f6a:f5db with SMTP id b7-20020a056000054700b002185f6af5dbmr4121123wrf.480.1665165403011;
        Fri, 07 Oct 2022 10:56:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5020:b0:3bf:beec:7a9e with SMTP id
 n32-20020a05600c502000b003bfbeec7a9els3921158wmr.3.-pod-canary-gmail; Fri, 07
 Oct 2022 10:56:42 -0700 (PDT)
X-Received: by 2002:a05:600c:5254:b0:3b5:99c:9be1 with SMTP id fc20-20020a05600c525400b003b5099c9be1mr4293933wmb.172.1665165401935;
        Fri, 07 Oct 2022 10:56:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665165401; cv=none;
        d=google.com; s=arc-20160816;
        b=yVijAzCEsZfxVpvWq++l95Wuuo0bWxv1m1zk1dMqZUwWqfT2z6kaZX8Ay8XVWIKMW2
         2blsEkTl6IGEmT0tENYrodj3F67gn3393QoqWPReirPVES55DTLYtID8FmXmLyHGOCqa
         Yn4yonMXWpUmeZLX7wsVQChwiF0+QsMgzeFukY3i+ysHFf76b+ViLhDie1MN6YAlz/hD
         Lm4kJMOZcERbDdjtbVmrLqGDJjTNK2bxtHGilSkEB/IDaDUQ5F5mkerVqhE+2NDbTNLO
         l1h2D1qAuzuigrWouGH7dSKTj2Nch5QaU/X2TXYPHcRELbeyzNpMyyj3gET8FZxRAJhh
         vDEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=nK/H0hVDBIBg7GodmLmaWI9qS4fvsGkmZJoRHEB4Sqs=;
        b=HYPKM7hc4/s8tH38Mlm+4kwuyrEnOJNV2TP30b2VpT86YkAvhFMiiU/PLpxZwwl8+5
         6yx+4VKPY1TnI1M8K+btygY025nUm/2uDMlic+fvxrg0iwmc94Kb0PmKylIDrrL5RiaT
         EmFasAtP7BP1R7hZxE9cS/OEUm29Be7GDiWqQ40vu6XbmYLNs0jDJGV22jSjFrIXXMDu
         NxtG/QpsyIQe4sD0C5cm0t0ClEcssNuUsubP6kfVAmnCRsaF59Ocs0oRE26nGsrY4m8K
         IgTyThj72Zjpe28i0a+a12N3bhFPCUDki87V+JkvbduMEQhNVpH3zSu2TmhW5MptuReM
         tOIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=f8gITOWu;
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id bj8-20020a0560001e0800b0022e04ae3a44si111100wrb.6.2022.10.07.10.56.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 10:56:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 5F174B818F6;
	Fri,  7 Oct 2022 17:56:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B63F0C433D7;
	Fri,  7 Oct 2022 17:56:33 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 1a87e0a2 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Fri, 7 Oct 2022 17:56:31 +0000 (UTC)
Date: Fri, 7 Oct 2022 11:56:18 -0600
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <keescook@chromium.org>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
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
	Toke =?utf-8?Q?H=C3=B8iland-J=C3=B8rgensen?= <toke@toke.dk>,
	Chuck Lever <chuck.lever@oracle.com>, Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v3 3/5] treewide: use get_random_u32() when possible
Message-ID: <Y0BoQmVauPLC2uW5@zx2c4.com>
References: <20221006165346.73159-1-Jason@zx2c4.com>
 <20221006165346.73159-4-Jason@zx2c4.com>
 <848ed24c-13ef-6c38-fd13-639b33809194@csgroup.eu>
 <CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg@mail.gmail.com>
 <f10fcfbf-2da6-cf2d-6027-fbf8b52803e9@csgroup.eu>
 <6396875c-146a-acf5-dd9e-7f93ba1b4bc3@csgroup.eu>
 <CAHmME9pE4saqnwxhsAwt-xegYGjsavPOGnHCbZhUXD7kaJ+GAA@mail.gmail.com>
 <501b0fc3-6c67-657f-781e-25ee0283bc2e@csgroup.eu>
 <Y0Ayvov/KQmrIwTS@zx2c4.com>
 <202210071010.52C672FA9@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <202210071010.52C672FA9@keescook>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=f8gITOWu;       spf=pass
 (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
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

On Fri, Oct 07, 2022 at 10:12:42AM -0700, Kees Cook wrote:
> On Fri, Oct 07, 2022 at 08:07:58AM -0600, Jason A. Donenfeld wrote:
> > On Fri, Oct 07, 2022 at 04:57:24AM +0000, Christophe Leroy wrote:
> > >=20
> > >=20
> > > Le 07/10/2022 =C3=A0 01:36, Jason A. Donenfeld a =C3=A9crit=C2=A0:
> > > > On 10/6/22, Christophe Leroy <christophe.leroy@csgroup.eu> wrote:
> > > >>
> > > >>
> > > >> Le 06/10/2022 =C3=A0 19:31, Christophe Leroy a =C3=A9crit :
> > > >>>
> > > >>>
> > > >>> Le 06/10/2022 =C3=A0 19:24, Jason A. Donenfeld a =C3=A9crit :
> > > >>>> Hi Christophe,
> > > >>>>
> > > >>>> On Thu, Oct 6, 2022 at 11:21 AM Christophe Leroy
> > > >>>> <christophe.leroy@csgroup.eu> wrote:
> > > >>>>> Le 06/10/2022 =C3=A0 18:53, Jason A. Donenfeld a =C3=A9crit :
> > > >>>>>> The prandom_u32() function has been a deprecated inline wrappe=
r around
> > > >>>>>> get_random_u32() for several releases now, and compiles down t=
o the
> > > >>>>>> exact same code. Replace the deprecated wrapper with a direct =
call to
> > > >>>>>> the real function. The same also applies to get_random_int(), =
which is
> > > >>>>>> just a wrapper around get_random_u32().
> > > >>>>>>
> > > >>>>>> Reviewed-by: Kees Cook <keescook@chromium.org>
> > > >>>>>> Acked-by: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk> # fo=
r sch_cake
> > > >>>>>> Acked-by: Chuck Lever <chuck.lever@oracle.com> # for nfsd
> > > >>>>>> Reviewed-by: Jan Kara <jack@suse.cz> # for ext4
> > > >>>>>> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> > > >>>>>> ---
> > > >>>>>
> > > >>>>>> diff --git a/arch/powerpc/kernel/process.c
> > > >>>>>> b/arch/powerpc/kernel/process.c
> > > >>>>>> index 0fbda89cd1bb..9c4c15afbbe8 100644
> > > >>>>>> --- a/arch/powerpc/kernel/process.c
> > > >>>>>> +++ b/arch/powerpc/kernel/process.c
> > > >>>>>> @@ -2308,6 +2308,6 @@ void notrace __ppc64_runlatch_off(void)
> > > >>>>>>     unsigned long arch_align_stack(unsigned long sp)
> > > >>>>>>     {
> > > >>>>>>         if (!(current->personality & ADDR_NO_RANDOMIZE) &&
> > > >>>>>> randomize_va_space)
> > > >>>>>> -             sp -=3D get_random_int() & ~PAGE_MASK;
> > > >>>>>> +             sp -=3D get_random_u32() & ~PAGE_MASK;
> > > >>>>>>         return sp & ~0xf;
> > > >>>>>
> > > >>>>> Isn't that a candidate for prandom_u32_max() ?
> > > >>>>>
> > > >>>>> Note that sp is deemed to be 16 bytes aligned at all time.
> > > >>>>
> > > >>>> Yes, probably. It seemed non-trivial to think about, so I didn't=
. But
> > > >>>> let's see here... maybe it's not too bad:
> > > >>>>
> > > >>>> If PAGE_MASK is always ~(PAGE_SIZE-1), then ~PAGE_MASK is
> > > >>>> (PAGE_SIZE-1), so prandom_u32_max(PAGE_SIZE) should yield the sa=
me
> > > >>>> thing? Is that accurate? And holds across platforms (this comes =
up a
> > > >>>> few places)? If so, I'll do that for a v4.
> > > >>>>
> > > >>>
> > > >>> On powerpc it is always (from arch/powerpc/include/asm/page.h) :
> > > >>>
> > > >>> /*
> > > >>>    * Subtle: (1 << PAGE_SHIFT) is an int, not an unsigned long. S=
o if we
> > > >>>    * assign PAGE_MASK to a larger type it gets extended the way w=
e want
> > > >>>    * (i.e. with 1s in the high bits)
> > > >>>    */
> > > >>> #define PAGE_MASK      (~((1 << PAGE_SHIFT) - 1))
> > > >>>
> > > >>> #define PAGE_SIZE        (1UL << PAGE_SHIFT)
> > > >>>
> > > >>>
> > > >>> So it would work I guess.
> > > >>
> > > >> But taking into account that sp must remain 16 bytes aligned, woul=
d it
> > > >> be better to do something like ?
> > > >>
> > > >> 	sp -=3D prandom_u32_max(PAGE_SIZE >> 4) << 4;
> > > >>
> > > >> 	return sp;
> > > >=20
> > > > Does this assume that sp is already aligned at the beginning of the
> > > > function? I'd assume from the function's name that this isn't the
> > > > case?
> > >=20
> > > Ah you are right, I overlooked it.
> >=20
> > So I think to stay on the safe side, I'm going to go with
> > `prandom_u32_max(PAGE_SIZE)`. Sound good?
>=20
> Given these kinds of less mechanical changes, it may make sense to split
> these from the "trivial" conversions in a treewide patch. The chance of
> needing a revert from the simple 1:1 conversions is much lower than the
> need to revert by-hand changes.
>=20
> The Cocci script I suggested in my v1 review gets 80% of the first
> patch, for example.

I'll split things up into a mechanical step and a non-mechanical step.
Good idea.

Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y0BoQmVauPLC2uW5%40zx2c4.com.
