Return-Path: <kasan-dev+bncBCS2NBWRUIFBBKXKXGXAMGQEUU3MJGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A8F5C856E9A
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 21:33:47 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-511490b3d50sf1267682e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 12:33:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708029227; cv=pass;
        d=google.com; s=arc-20160816;
        b=hahhVa2rPK0/epzoRKzuCglkNuwU8xxqW2r627Bbs56Uvf9s7DvKaE0jJVgUZWF7dT
         8DIu0aNxAY/NAUHTbO9Z41dYYEg/zFewBvGhml1gX9uwVL51czjyHoflDIP5vSTm7iHz
         pw7s5mj+qbCEefvs65ElWQmOhjioV9c1CAhggnIdxhYzw0P0D2QdcawG0m9w3968Roqt
         XX6IH/RExOq+VovoQjJ56ZJlceqRdZB3HBL5qCyzeZ9GYd5ANHlD5cttNxEyvbT+MqdS
         0xVxJWC2OMACFppH2uCEpsI0O3GGu9k1k1TKMTaHgXZo3RlJFOZbkCFSNwILjcBu+Q3W
         EouA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=oCPoLeZNoHKi1lYLkxa8tNDH/JS9mcBJkFacY02wzhU=;
        fh=KsDU6zm3hRDvv9/8BMfiZE39R2uz+ZHZq3FsMcYhXpw=;
        b=ZPpIf7iwGW/C8h0mmlqD+POPrfYo53kl1iIydZs9vSTTrPNgqA+MBSVY2kZuZEwOvh
         hA7Hky8GBIlmsa9x9mmbdh+cK1stADZymCj6pguhKvDRmazEaXOzfWeYpnLC3PDR2Fpg
         qTI7UeXPnHgZlwADIBSe5odUSPV92D2r+STithpq6MLGNn186bpMOUZv0MuclUVFTfud
         EJpZQuD6Ylb4qW0qVur1y3pG/ut9Ggd8lzybbL5SEgZICZGScBNIyK49wp4J9L1uKOue
         tsW1UidBAE3mq8SJ0BH/MBa16yv3jzc0o2jIIrVzy2Veq0N50uNyCeAdXEeY5xR+wOnj
         s3vw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=uKMqNbYR;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.184 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708029227; x=1708634027; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oCPoLeZNoHKi1lYLkxa8tNDH/JS9mcBJkFacY02wzhU=;
        b=C/dOUL39sUG2Z0r9qN77HNLolpH/lRapJZ/SdkZMlr7QZD+dgTpk7TavTZLPDB/mnc
         SteDVw5f/bF4d4XpMMTiYDbkfNg94ERslaQ1modZu2e9mK80sr5bjbb2xavNyM2umwpV
         0U/H8e0IvOZrNraNdxKmX+gM6OTTrgvjLqrdCOvrFiF3phcnn1Dt9EmwQIQqcHvIljnI
         ogJC1VLTInzHw337EYErm79XBohTA1P6RjSBBkatVmWIeZReZluNIc4FG6DXOnGEf/gr
         ROCVkwKqqxT7bQOdy3ioy3j2urAVAwpa2CPSP/rZw8QSUY8N/QytYZ1yH4tGBme7k7j4
         yP4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708029227; x=1708634027;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oCPoLeZNoHKi1lYLkxa8tNDH/JS9mcBJkFacY02wzhU=;
        b=EvFOESAUvPtlK37b0GLb7lqqVXQELowfcnznOUkRRVKMnAWHch8sAM8S5KUTMK3Bkh
         2/pp0Fk9xM4op3d4MTSIryCXDov72HAt6+m20IFdN8rebRXtw6cMV1p1Eck3+ziH5CTB
         xlfzoPvnQUx3q0hGormnB4Hyjj/qicCg/26jUmgHsB+z9QxCuwrcQMqn6TavotPprehE
         P8zOrecnC4rg0K8ddMIQWObKVpQeJ755+9d5CGunl6LKf/E2xQIRqj1ECDsp2z75w6Wx
         IuayV6kXynvP58+oH4cw15LP24w03on69mtn52bu8iJIWHlLR6qGCU94yxBykR3e8B28
         88OA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRopBonpxDcVLAio9k5lwLBOq1RC9CVQux3hvi7AInQgt4CQzLg/k6oiP1VfLF0Y7RsT8fmrD5K/h39hk+UTIpylagGjUnrw==
X-Gm-Message-State: AOJu0YyClaVXohctHjpHp4Tq6mQmkTG5gWN1eqCP0yBFKlWODLvszXsE
	97aDRRUjNoZp07NSNlbDv5G/nJduHyKW3mqX4w0ugp+VaxKruY1c
X-Google-Smtp-Source: AGHT+IGTHoiTFok8/L+NOFmD0zR1qWWFLbd6s8Ie9iDvoPOtHLKwgb4AlRQ89Z8ybQiYniVf5RPHpA==
X-Received: by 2002:a19:6452:0:b0:511:69bf:d1a6 with SMTP id b18-20020a196452000000b0051169bfd1a6mr1761388lfj.40.1708029226591;
        Thu, 15 Feb 2024 12:33:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b86:b0:511:4a70:6ac4 with SMTP id
 b6-20020a0565120b8600b005114a706ac4ls84597lfv.0.-pod-prod-05-eu; Thu, 15 Feb
 2024 12:33:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWCDM5R7h7JKp6eOzQm29PwArPQQmt1JEKc8HtB+quNJAxt7fzhxXhqgPqkRSoXky0fGyRlIkId3aXRezlWnm4jm1L/Fy7RNTibSQ==
X-Received: by 2002:a19:5f5a:0:b0:511:565c:601f with SMTP id a26-20020a195f5a000000b00511565c601fmr1970998lfj.54.1708029224735;
        Thu, 15 Feb 2024 12:33:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708029224; cv=none;
        d=google.com; s=arc-20160816;
        b=ocwuXNC/FpySLlLRsB3IMWW/71sWiLcYfNOMtpHOrOPw9v/UYL7mMtXVLjvELqOwJU
         J5ZTWNDHvydiePC4EADyHhR8EzP3Be9BccKu7yb8u//33/hfC0WhsxeKPoGo8HEuaSJF
         u0SMWl0zJaE69LDrHGXQAy/cM+JvMirpoEn1DTlwlx29AKJ4Nkp5eSN7L8+ovOyFB1Wm
         U0xS67Nfe74zlGddZ3c1UphAnsj995qMDdcD6TCsqYgyVKacX7yaBIEVDhygkDTPTQ8z
         p/QrNGqZ5OJYt/tw4tqlcv71gGeLPI6GZCIPZtA4mzCuAQXjvLRju7WfVgcGaYtVCKZz
         vRTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=1h3mKBhbYx2gO9e1zxP9AUVbRxFOpkSn+Z2PNxlzZgw=;
        fh=Z1oiWE6w/L54M/flN/Si8YFXMT4vwuce+Gv47tQRNAk=;
        b=SWTJX4cdRd6OJXmRdIgi6GTutZDnonpSddD4ujNw7z6HywMHorWi/eVfG4cCFPctXw
         95vv1CCpU8EnDk6NLn19udVVAVRPnh765KpSDQz9dCYyIV4bJduxStUOZliFNFWPA/NT
         ZRzNfL2TlTdGvNEikL3fJdij2L1PjFyce0PrNmSAMdN6JY6ELoo4AisHOTF/ScIeOVBP
         V8obNdGlERBDeCRL/DBLNottdgKKfi/qhvvhuX0OtyaHF6sd5jwHuQ17MYqJykcipK1q
         4TGk5L0dHalT5ub7Qd90+7wAKwhodKz7/TYN6ML/tnAy+xch1jtfkCRCgVeysMgM4n+6
         ufzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=uKMqNbYR;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.184 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-184.mta1.migadu.com (out-184.mta1.migadu.com. [95.215.58.184])
        by gmr-mx.google.com with ESMTPS id be7-20020a056512250700b00511ab55723fsi83487lfb.0.2024.02.15.12.33.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 12:33:44 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.184 as permitted sender) client-ip=95.215.58.184;
Date: Thu, 15 Feb 2024 15:33:30 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, 
	akpm@linux-foundation.org, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-32-surenb@google.com>
 <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=uKMqNbYR;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.184 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Feb 15, 2024 at 09:22:07PM +0100, Vlastimil Babka wrote:
> On 2/15/24 19:29, Kent Overstreet wrote:
> > On Thu, Feb 15, 2024 at 08:47:59AM -0800, Suren Baghdasaryan wrote:
> >> On Thu, Feb 15, 2024 at 8:45=E2=80=AFAM Michal Hocko <mhocko@suse.com>=
 wrote:
> >> >
> >> > On Thu 15-02-24 06:58:42, Suren Baghdasaryan wrote:
> >> > > On Thu, Feb 15, 2024 at 1:22=E2=80=AFAM Michal Hocko <mhocko@suse.=
com> wrote:
> >> > > >
> >> > > > On Mon 12-02-24 13:39:17, Suren Baghdasaryan wrote:
> >> > > > [...]
> >> > > > > @@ -423,4 +424,18 @@ void __show_mem(unsigned int filter, node=
mask_t *nodemask, int max_zone_idx)
> >> > > > >  #ifdef CONFIG_MEMORY_FAILURE
> >> > > > >       printk("%lu pages hwpoisoned\n", atomic_long_read(&num_p=
oisoned_pages));
> >> > > > >  #endif
> >> > > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> >> > > > > +     {
> >> > > > > +             struct seq_buf s;
> >> > > > > +             char *buf =3D kmalloc(4096, GFP_ATOMIC);
> >> > > > > +
> >> > > > > +             if (buf) {
> >> > > > > +                     printk("Memory allocations:\n");
> >> > > > > +                     seq_buf_init(&s, buf, 4096);
> >> > > > > +                     alloc_tags_show_mem_report(&s);
> >> > > > > +                     printk("%s", buf);
> >> > > > > +                     kfree(buf);
> >> > > > > +             }
> >> > > > > +     }
> >> > > > > +#endif
> >> > > >
> >> > > > I am pretty sure I have already objected to this. Memory allocat=
ions in
> >> > > > the oom path are simply no go unless there is absolutely no othe=
r way
> >> > > > around that. In this case the buffer could be preallocated.
> >> > >
> >> > > Good point. We will change this to a smaller buffer allocated on t=
he
> >> > > stack and will print records one-by-one. Thanks!
> >> >
> >> > __show_mem could be called with a very deep call chains. A single
> >> > pre-allocated buffer should just do ok.
> >>=20
> >> Ack. Will do.
> >=20
> > No, we're not going to permanently burn 4k here.
> >=20
> > It's completely fine if the allocation fails, there's nothing "unsafe"
> > about doing a GFP_ATOMIC allocation here.
>=20
> Well, I think without __GFP_NOWARN it will cause a warning and thus
> recursion into __show_mem(), potentially infinite? Which is of course
> trivial to fix, but I'd myself rather sacrifice a bit of memory to get th=
is
> potentially very useful output, if I enabled the profiling. The necessary
> memory overhead of page_ext and slabobj_ext makes the printing buffer
> overhead negligible in comparison?

__GFP_NOWARN is a good point, we should have that.

But - and correct me if I'm wrong here - doesn't an OOM kick in well
before GFP_ATOMIC 4k allocations are failing? I'd expect the system to
be well and truly hosed at that point.

If we want this report to be 100% reliable, then yes the preallocated
buffer makes sense - but I don't think 100% makes sense here; I think we
can accept ~99% and give back that 4k.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3%40n27pl5j5zahj=
.
