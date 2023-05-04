Return-Path: <kasan-dev+bncBCKMR55PYIGBBWGQZWRAMGQE5ZLIWCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 47CDF6F66D9
	for <lists+kasan-dev@lfdr.de>; Thu,  4 May 2023 10:10:02 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2a8b03ec360sf1021051fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 May 2023 01:10:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683187801; cv=pass;
        d=google.com; s=arc-20160816;
        b=IkkVKMCjbfpcuPh3ix4+NRKKpqinYsmCdHZdv8ZGQkS/T1lRqXrAOXOy9AbOdxT5XC
         /IicknedDQjvn+IjsJZwE5twrTqlErTzQEpvcl9wClV2MbW0RksnE4OwQ+el295YNSlb
         vs89NQmt+ha8zbxO+6DheHfKWIv9ZtxH6fWBKPy+LBFooXT9G9+8+BfTjR0CLOCcv9w0
         xAhJKJRn0Zb+c7cwv+zHwhzD/NUa+BieuWvqKIKe3ddjN0sov+9q4jmDp0I+a0eBFs06
         C60WhT4wmAK7INJ7eD5r3+i2LNLRucr5Uf+V6gFeFfFOWcAU/VZrh1YuUzQe4mFlmYCH
         VBgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=iUreXWw/6RuU0XX5zl1SE64gsLXJVr40+t/L+Dfib+w=;
        b=NWqfpuIIHM7Qc49E/kjkizLTmHFdLVWJfUDDsqHvN4zdZsC/7LR6oFm8/9MXqWyJvZ
         30yR8M1ixpcBTHMnpCXaPDjOTn/VqVJyXQxIRAHh1L2EIsNQO/0aogIDfg/tAMPsmP5s
         hUFY25Kyyjz8tR2qiuJX5P1/sjP4R/MclOG3JP8G1jiJT+2BsAleIWbUNftd5X9aSXrA
         2xU0aiODaOakLXIqxoGhATo4gzFw8D3e8ZgbPwD004Y/74brywALxFbriZUxA/AH0arj
         ZaknwDzDND25jN1PyRfPbns4d/p+KAZm+9+yBz8Uy0Sfis03CgItMqDdqdq2RtL2ze/b
         Ou0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=pWdGUIdH;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683187801; x=1685779801;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=iUreXWw/6RuU0XX5zl1SE64gsLXJVr40+t/L+Dfib+w=;
        b=rd73ZTsho6u+868ZACeEXMbkLT6GQeP54y0sR1t3uteIpPTHpsK+6JoyabtWa1M0jn
         wPCZ+cJFrsUd74JR5Rn03vTlHcWSsAgbWRzTJ2i2g2QgLxw5h/dGtPNkg6LWX5YkLviw
         yGZFuMwmv2bnvQUpavx0aopus4WWAE26jNK36ZXrwvExBaoylYy/EiM+aGDGFdeFUJ4V
         tDpct57vGrt73IPzoExmWjr4H9Ry2uY8637sK7+RJAQj32WpjDy5gSmyVdJ5Z80AVfkI
         N/DaPYZSqB5oxmQnKRjiWc6NBfETsLCquy8Z/1ATeOsaj8z6A2W8zz2OAo5qSTwm40RM
         JWTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683187801; x=1685779801;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=iUreXWw/6RuU0XX5zl1SE64gsLXJVr40+t/L+Dfib+w=;
        b=JPnxXfJwlV+8iyTsmEb5X4POT1JDM5MouDlgY8XJUv0jEK4+Zth3NxQ4RCt3hLaxDh
         stg1D0pz/ZP7aKHL6iNID2THlVZKd0vCUFQQmozTvtPNj3nX1xTYz0TLveWyNqOESdo2
         pD5VewLWtkUzUMhxQkYmzaQV7RKKDVGQwnG+/cV8CRvcWjOfuIbnlKwgYZSR8ofTNkfL
         76n0DhPNs7tbqfxbxgMYA+NJQ0znjTU1l9GPmIARoxcu40cYwNsJIQhoTWKKvKjtpqCg
         yYKJHG/xLQwIvBm9Bk4CP24OHg+s4dPxkMBHYJM2JbZfUfvDgs2ACock7L0TaI++7JwB
         iocw==
X-Gm-Message-State: AC+VfDxq9SL2Eg2ZXGyAumu4zrsFl4lomVEZoF/fZCw8cSauiyajVcMz
	9S4ezV+rInT1bp7y3HR8ECc=
X-Google-Smtp-Source: ACHHUZ5v57BxZhwaM5G2EN8+j7a3XTtjOKY+32lyWmJoYHiLTKUM53kOknP3QgdyRNvE6tstclfb9g==
X-Received: by 2002:a2e:9b44:0:b0:2ac:73bb:50cd with SMTP id o4-20020a2e9b44000000b002ac73bb50cdmr649672ljj.8.1683187801251;
        Thu, 04 May 2023 01:10:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158d:b0:4ec:6fe6:9f26 with SMTP id
 bp13-20020a056512158d00b004ec6fe69f26ls2688986lfb.0.-pod-prod-gmail; Thu, 04
 May 2023 01:09:59 -0700 (PDT)
X-Received: by 2002:ac2:5583:0:b0:4db:456a:9a1 with SMTP id v3-20020ac25583000000b004db456a09a1mr1455009lfg.66.1683187799509;
        Thu, 04 May 2023 01:09:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683187799; cv=none;
        d=google.com; s=arc-20160816;
        b=oGWiS6JWcUCtOAJPqe9ovCGkp0Kvh4eTvlPd8qJ7oVCXBXR/mGf+Z2CIV+SBdmFqNG
         e3k9SBCVGPzG1yvkPP/HZLYgQ5nOg5R800ihmlgCIN4WdFSGgvmQriEQQawWBhS/GIOv
         OHDibkpXs45xxebqlTNroZJLLgCkc5cS8xnIMBnGjJqkiaPR4OPKnxuC7h1TKloQGPgC
         IJ0Z4ps/dAEuToymw+XV6wwTr9snf2RxBNQDSJc3y8pDFD4bt3Fh0hoTv4EA5nEXM48+
         /W5XYPtqDbsWTw1J5i705KTKTsuLDtrqiCmXddOvykLmjJZ6OKUTlIz6NKTb+LX3q/25
         jt8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=H0f9aUoTiM+sJjdWNgkunI1DxI6aESt6W4qyqw6LAGM=;
        b=PSJ/D5ZDhRoVtv/++V5o5bcdUdWB4CkNsUHzcmGUV7R0vuiGTv+l9IKIzLKfChCrEw
         GXk5LEjaQ4JvKLoY+4J1rnRGz5SWymJZfxsx2ZTc8QLicKq5H3y2/Dl5nKxM7l+cbWGj
         WkmiFUD2fJuY7JINQfHYF3YIWG2k08Jqi4KXwoIRrE23bDnCV7BAwa0Q3qbasgVhZpki
         7pMaFEmznEAi7jBgE0mErtYCn4K8CBghkShQ7BSDgMDSLeNDbauzCyaJjxB2QylPByoW
         LiYvgJ5KPHgzX0bAwGP2xNg+oJXmeCTEJ7/WdfjAFhSr1MYaFO3ytjGeQpSe6vvFzT1P
         WJVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=pWdGUIdH;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id h28-20020a0565123c9c00b004f13b703015si255174lfv.6.2023.05.04.01.09.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 May 2023 01:09:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id D0CCA2096E;
	Thu,  4 May 2023 08:09:58 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id A6BA4133F7;
	Thu,  4 May 2023 08:09:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id BMewJ1ZoU2QKLAAAMHmgww
	(envelope-from <mhocko@suse.com>); Thu, 04 May 2023 08:09:58 +0000
Date: Thu, 4 May 2023 10:09:57 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 35/40] lib: implement context capture support for tagged
 allocations
Message-ID: <ZFNoVfb+1W4NAh74@dhcp22.suse.cz>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-36-surenb@google.com>
 <ZFIPmnrSIdJ5yusM@dhcp22.suse.cz>
 <CAJuCfpGsvWupMbasqvwcMYsOOPxTQqi1ed5+=vyu-yoPQwwybg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpGsvWupMbasqvwcMYsOOPxTQqi1ed5+=vyu-yoPQwwybg@mail.gmail.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=pWdGUIdH;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted
 sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Wed 03-05-23 08:24:19, Suren Baghdasaryan wrote:
> On Wed, May 3, 2023 at 12:39=E2=80=AFAM Michal Hocko <mhocko@suse.com> wr=
ote:
> >
> > On Mon 01-05-23 09:54:45, Suren Baghdasaryan wrote:
> > [...]
> > > +struct codetag_ctx *alloc_tag_create_ctx(struct alloc_tag *tag, size=
_t size)
> > > +{
> > > +     struct alloc_call_ctx *ac_ctx;
> > > +
> > > +     /* TODO: use a dedicated kmem_cache */
> > > +     ac_ctx =3D kmalloc(sizeof(struct alloc_call_ctx), GFP_KERNEL);
> >
> > You cannot really use GFP_KERNEL here. This is post_alloc_hook path and
> > that has its own gfp context.
>=20
> I missed that. Would it be appropriate to use the gfp_flags parameter
> of post_alloc_hook() here?

No. the original allocation could have been GFP_USER based and you do
not want these allocations to pullute other zones potentially. You want
GFP_KERNEL compatible subset of that mask.

But even then I really detest an additional allocation from this context
for every single allocation request. There GFP_NOWAIT allocation for
steckdepot but that is at least cached and generally not allocating.
This will allocate for every single allocation. There must be a better
way.
--=20
Michal Hocko
SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFNoVfb%2B1W4NAh74%40dhcp22.suse.cz.
