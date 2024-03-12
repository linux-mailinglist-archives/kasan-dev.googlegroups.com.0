Return-Path: <kasan-dev+bncBC7OD3FKWUERBFPHYKXQMGQE2VCOV3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E260879C74
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Mar 2024 20:57:12 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1dd62ea9be4sf13115ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Mar 2024 12:57:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710273430; cv=pass;
        d=google.com; s=arc-20160816;
        b=z9gk/UEC0+7LOkg0zUGlfDwqBpfOx2Iqv33yTARmdjGMGlfaaYDmBKZx2JQEDT69ZW
         UTYxo3+rwZR8U1+2oFsZZPHrF3PIaINw17EwfdDgTP7ef6ze2fN2D4yHzgxbHEMdcsSW
         Fz2n4K1uErrqhy1WajGbmflr+pUUNUokp+jvR/tI4aU5RBDfhHG7PbYHNCGBWmsnxZyo
         8Hg9xf1u60z06uxw10Al+GV4O3CcRojLmM5MrHnW7zyxDct3eVeP1WjbeBvRN+hVMwTt
         XH1uhys92Lt8DK/qH6WL+k7JauCRAq7iOmCyguEXOGgctSWTEw1tlWaSLWWBQ4twnFyo
         PrQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=N5IV4c/sSKAMF4TAuVhIdzbjIFNY69Wqi+FYrv3bHUg=;
        fh=bJy3NvnQ0wp23uuyM60uy1Ez74OloDLLS87nCqOgtE4=;
        b=mJHzLczGqa1+KHh7Wtdn8dicM15oL3Xz/Z6427z3YJuMnrnSSvgRlkY3Xfo+hOAEuS
         0+7ErR666o27gOd0I95v7PuoQ4aw7GCK+DW+urQlVbZztqD+gWhVwbwHu+nJB0E6KC/F
         qI4ZpaoNXAwnTBzQ+1cm/RV8SWqd0JcpKbqmtGVFDUAYUryR8Ps6e4KfImehYSmCAaFc
         /YqIF3DoYdhvdcaxSMxHRTK3bNEaMnGM9vEcFQ1fUM2ToKA45Aon9bPxArsEg9cvEau1
         GsgS1MSH9JanwG8gQp2oJyPU8L1Lc3xMO8cvjx2AXOJpy6k4SBlRo6HkrENWwm6DQwWX
         yqsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hm4lr2jK;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710273430; x=1710878230; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N5IV4c/sSKAMF4TAuVhIdzbjIFNY69Wqi+FYrv3bHUg=;
        b=hdI4zthr8b6qHgejXmn7Z+e/RIydfluEQ623T5S2eBvMuP9Ogoo+zNnmVEBpwANCcN
         P0/4FWjkg8J5ORNssohYsPqqJgiXWMSj77qR2NBUWX2toOZ+4typL9p5owSt1yqiE7Oc
         wKK9FwALLCFC2auzN9wQBYxn9ck58S0ralLUGrXHB8m02NHa3fNHOkLY/st2wAzampLG
         jDb0ADi3CStf2E8TT0dPun8xj3NR2GQbubug+LJYIonwPgfOMfZbrNBbiwvt+XjO5+Fk
         6HsFZgiGFlueJvU1dn9HtH/bEhWAfoYfuoBDNU8nb9f+5AU3umPMJdC86yg7kUOnhdB+
         DH4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710273430; x=1710878230;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=N5IV4c/sSKAMF4TAuVhIdzbjIFNY69Wqi+FYrv3bHUg=;
        b=OeO2fwXZ2pd7qxl2nHvv8EnPJFtvl5vPtR+b3SZjeYpkxnWg+ti+Y3RPIwnx38j5T/
         3wMX0yZA6xevIGcJ9OnP3SWv4sDwELNuIy0n1RvK0P+DddHbSQM0/OYcfvqrRPz94/Bu
         67n8psReP9R5SY9kd1sRxdY//FS1KNLKat/cdJkYAvs/nQHZfB2my4xVtGmnRoJA7uPU
         cSjBaasy1JoB1AEZ4tFCfwTYowPrQl8uN+DcN3U3uxtLcXvpT0VMmY+vfAmAc9r3DJyS
         eriyvSFJ/Dm2pg31iyTxsV+MCtdvuXrMliC6w6k7XWmlhwXm0U5uaX6WzbELzgAnpdzN
         eLLA==
X-Forwarded-Encrypted: i=2; AJvYcCUSbGJlnAGy4bAdGmU29czdwzCj6e6bAL/suKPEUpnDzekmPUDn3qZHZPrJ2qkb+dZ5H+9mWp824A0cH40zuA3iauV6D4rBlQ==
X-Gm-Message-State: AOJu0Yxcy5nCRUKjK1cm9bag/cOJiPMiD+nfzsBDtvrfCYzWw6B3PZGu
	LRAP9RclUFbRRFVSwEKdIyZadWVG6iVJauw/NkjC2h8dqzfKDuON
X-Google-Smtp-Source: AGHT+IGBCAz+xB+FFmotqHMc5JGOwo23kUQs/h5VSK1lF+jOgM2RNpgXmPqDJl914GWGGTOxQ8iBKQ==
X-Received: by 2002:a17:902:d50b:b0:1dd:6795:3bce with SMTP id b11-20020a170902d50b00b001dd67953bcemr54plg.15.1710273430061;
        Tue, 12 Mar 2024 12:57:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:a1c:b0:6e6:b3d8:2def with SMTP id
 p28-20020a056a000a1c00b006e6b3d82defls348557pfh.0.-pod-prod-02-us; Tue, 12
 Mar 2024 12:57:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW/0dLRIhd8p08M8BabPbeiW/gytIMMyMmqCLIAes7/IPXyElOYtxkRHJbO2gqEA/WG2Ut2UtNieqQAnBW+ldbpo7fI5a4hCxdVEQ==
X-Received: by 2002:a05:6a20:734b:b0:1a1:2064:9e3a with SMTP id v11-20020a056a20734b00b001a120649e3amr1718108pzc.47.1710273428928;
        Tue, 12 Mar 2024 12:57:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710273428; cv=none;
        d=google.com; s=arc-20160816;
        b=esEGyoYnZ78YYrFrjaEZ46B0NzjIdEpkQCLhWtHK5ETqijOMPZ2WA/P5qqmRmtjDSk
         kR23rQjQ6X9ECS3cQNS0zA1OgAV3t2F3OzjrhAcXT0NSj3ZEscJZR+M8pgPVu/ucS+go
         PxUbm4BOtD2JTOCNlLJQfcNTNXJVQDuo0JFUWM7YK7icrHuDjZB4zxpzMWfx3RB/Fh2l
         mrd7AuM0AJA9wI9YH8SIzSLQAcVYGTxk4RFKYu1uIDkSWyR2Bv1GwlVI5hgmIsICMe9t
         vQhalwf4shlkOo/yX8Jpd1WvNB4xQl+0aALajNeRGnY3f0KJU2DqpIL8Day4+kIZcJm2
         F0XA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wT+2mjCDEB2wrTUTyTKLuab+xNoniRJZtNtidsDDPI8=;
        fh=NrqJfP9tpz3jtaSlBx7cykGlgtno3LHmxS9GlqrKS7c=;
        b=EJddZ8GpQNCtmclB/I/dNBJb5op5VH0N4j2LYpJZTBft1AisIG+hFJO2YywqqIGnB5
         LrHJD322YgDDAn1D/1rE+x8TTq4MfPWvGYWdHX0nb+pEMz8hWGTYtissQwHfWUteopbr
         edBjgZVau95KSNsAAW82LHWuIOUb/1lWLatcExNOw9KYWTIb2CMI3yQFJnVXyj+xMN1M
         57hUdQrDeXdWUQNBfh6uw800Vet2AxkQIW+Zn4SrnDE5uKEH1BQ76JwnbwE8ZahyVZwV
         Oq9uEqpmkxm555xeBA8ub7y7AJvww8NRyuTioBrNpfnSaQA7H8SpQAhp6BI7KKaCK62Y
         YBUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hm4lr2jK;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id p24-20020a056a000a1800b006e6a8a85ee9si156994pfh.6.2024.03.12.12.57.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Mar 2024 12:57:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-6098b9ed2a3so3178507b3.0
        for <kasan-dev@googlegroups.com>; Tue, 12 Mar 2024 12:57:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUlnTbuIsLWlaEum2EBwReKPMsUC/Tfg3JLJqd7vPLrk0G6eYzJ7IUQCE2EqdF/c0AsGDzJu8kLFU8rLArVJdyBdw+ObYF7WDd+/w==
X-Received: by 2002:a0d:e885:0:b0:60a:67fb:146 with SMTP id
 r127-20020a0de885000000b0060a67fb0146mr551414ywe.17.1710273427660; Tue, 12
 Mar 2024 12:57:07 -0700 (PDT)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-14-surenb@google.com>
 <a9ebb623-298d-4acf-bdd5-0025ccb70148@suse.cz> <ZfCdsbPgiARPHUkw@bombadil.infradead.org>
In-Reply-To: <ZfCdsbPgiARPHUkw@bombadil.infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Mar 2024 12:56:54 -0700
Message-ID: <CAJuCfpErSnRK3TH-+keVF+2Vq-e1cSXrOcg8UAFke3btt2Y9+w@mail.gmail.com>
Subject: Re: [PATCH v4 13/36] lib: prevent module unloading if memory is not freed
To: Luis Chamberlain <mcgrof@kernel.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org, kent.overstreet@linux.dev, 
	mhocko@suse.com, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=hm4lr2jK;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Tue, Mar 12, 2024 at 11:23=E2=80=AFAM Luis Chamberlain <mcgrof@kernel.or=
g> wrote:
>
> On Mon, Feb 26, 2024 at 05:58:40PM +0100, Vlastimil Babka wrote:
> > On 2/21/24 20:40, Suren Baghdasaryan wrote:
> > > Skip freeing module's data section if there are non-zero allocation t=
ags
> > > because otherwise, once these allocations are freed, the access to th=
eir
> > > code tag would cause UAF.
> > >
> > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> >
> > I know that module unloading was never considered really supported etc.
>
> If its not supported then we should not have it on modules. Module
> loading and unloading should just work, otherwise then this should not
> work with modules and leave them in a zombie state.

I replied on the v5 thread here:
https://lore.kernel.org/all/20240306182440.2003814-13-surenb@google.com/
. Let's continue the discussion in that thread. Thanks!

>
>   Luis

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpErSnRK3TH-%2BkeVF%2B2Vq-e1cSXrOcg8UAFke3btt2Y9%2Bw%40mail.=
gmail.com.
