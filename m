Return-Path: <kasan-dev+bncBCS2NBWRUIFBBD4HWCXAMGQEGW47PKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 901D48540A3
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 01:04:33 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-511a4a286f2sf257804e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 16:04:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707869073; cv=pass;
        d=google.com; s=arc-20160816;
        b=cjC77gyoaVRhsdjNcyHYSlYLnZxPvdNRp9VONn158bqOtW+f8BEf9wC7Tqe9rT4dFx
         OWGwWBw0GYTjYI09PDdHTndTaHovnBKchQHtHNUQHlc3zyzTH2BJ5Ewx3w6oBW1yxqyk
         XTe0KPrLjrLlpUTgm8GPElIgWHjPLsUMvQloVqz7D7KftVqjmHCEbc1UeqNsSNzKbZ+9
         PBuP6/KRiiycEhosLbCE6c/T3+qdZINkyN4A6KSyEHTJOIq3oLhANOsoE8S/KTfn7QaM
         yMfMpUhrRYoxdme1VsOg7ppPneD1ObCAVVnuv1CXLx7ohyuQl68Q3shDPArqWUXKQ690
         XcbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=cr3t0O5FM44Zmrs1WVLcAbNd/s7bRjxs2ejq9yqfzis=;
        fh=5lj4xYQqTBEULTVfzwwYkKzh6CTyCdmF2M6Ngs4BxEc=;
        b=VJ88XYNJzOjYdb3Ba9GBPQUVOzJkPvT8Hv0ssgj2sxXceZCwb7hN58EKdPfwMKuhUp
         TiYpnRtPaTL2fhX6cv6Lv97p+Byy5RKNW3lfgmew5qVErSCfRBzcWurAzRpfw1yqXkOf
         dTp0EutG6xLIYPUXxaywfpQlCyxmXHwt7toNl8Cw2Ld6AlXQuwjWpTisHhUiiwZ7zjMw
         +gJ/UF9NZ4gV1468hEGXXlyaJQCFjCdWgPszAWJWdyG/aucArYSbHcq8EJqnnR4xT8+R
         kX1vjdkGs8H860rl4Q/gOs6SUbGy7poHo1Hf6DLLEX0HQMchGuZqrveLJUCpUZX4h1Ph
         mSLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=k67cy+ui;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.182 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707869073; x=1708473873; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cr3t0O5FM44Zmrs1WVLcAbNd/s7bRjxs2ejq9yqfzis=;
        b=nyS8ViEuBydjC2wJ8bp3XNOkx3/X6W66CPFYapQcV7a/jfGnhTbL9Aj+1KhUsOQVw8
         NnCV0T2q6H2p+2swZvtPl9neMfpdGCDbB//JusoyDlEh/E6nyPMZt4cEynbP4V5+nsr0
         NpDmVGwMYHt2x76sGFtsm6GYSIqk3R0Tv6CEkPXFJ4+QTVSGIg9e6Cgm7jTKoSmulpKS
         17m6QVQDdQ0jv0SoS3EQHDAdNVfAFzF/jLth/NlR89RSOWGkBr01Z2nOIXbi6hAMUaDn
         l8SHrPXqUuK28MZXYS6uy4jaKDVDTI39BEigPOGYDpq+XugCW/L7+qlFxISivTA6pekd
         LIbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707869073; x=1708473873;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cr3t0O5FM44Zmrs1WVLcAbNd/s7bRjxs2ejq9yqfzis=;
        b=N6uk5mdw8sJt0/I0jTwhd1DKZkUqlJSrNBWU5XhXq8ZHvxaDSJ7364hxXdwygOQvub
         N5mecFuY2ppy05FsGP0+h92VFoVJf1vwYRtAlwgTmhKHua/9GyCjAJuG+j15rq9TNytO
         DhXmwutuloybi+mHmVJgeJDjzSZsXnAMDk8Kiia2j8nNeWlTIBfXLn6TuG2MV5Sbnocw
         yXNkL0oos0+I1c5LHQbXKmwxgDCn+PTHVBbimuPYyavvcHUbKNgTBrr+iOV5zbzu7Lti
         4rprC6n2CqfpCkSFBew/QFAkq36pwI3knY7W8pHeiLQS4+ZMQOLLGAKfnFcgQ2UWR5BC
         0XBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXK83DL4faRmCM1Wu0g8QFXwPhY3x1UNIcWQ9FkHZu3eDcF0E3OULdFgmS00nlgAvcH0rP4h9BD5i3ORI9wSZlwg8Ni7USF2Q==
X-Gm-Message-State: AOJu0Yzsf6WHQHpnucAHxd/BL4hWeRIRhvPbA1L71Yvz1RyllT0LUgqt
	YX2l6Am26dwHh9ExwyjCVEc+g14+83JD3TNkjXBpw4i58A0jjdlp
X-Google-Smtp-Source: AGHT+IFvREkbNazfu/VGwME1jIaVwLQVUxqDBUozuTEMDfdbJDdpYi0Jh9ujuEfBMG5s5azCX9NVAA==
X-Received: by 2002:a05:6512:2002:b0:511:a587:dc27 with SMTP id a2-20020a056512200200b00511a587dc27mr210228lfb.43.1707869072170;
        Tue, 13 Feb 2024 16:04:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:a8c:b0:511:7a78:7ea9 with SMTP id
 m12-20020a0565120a8c00b005117a787ea9ls997755lfu.2.-pod-prod-09-eu; Tue, 13
 Feb 2024 16:04:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXXpXs0Q/vibr/sPFLXq8xKDqGr6JrTR7wqAcpVlGP1iqka1Bzg5WuUSrDRwQ2CVdnWQKjfXHJYwiJzNkw9uEe3mIB2qIzXJ5nCSg==
X-Received: by 2002:a05:6512:1c6:b0:511:627e:3840 with SMTP id f6-20020a05651201c600b00511627e3840mr692263lfp.27.1707869070224;
        Tue, 13 Feb 2024 16:04:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707869070; cv=none;
        d=google.com; s=arc-20160816;
        b=UJ11yM2IIQvBJBU4tzx9HHPGR3vBMguOnixOycHWpLi2m8rRm6IpEcUloXZUC49Qpd
         HZNMFo5PUVVMzd+rEuSGdsFGSMINLaqXzHlWCZmQOKLwmP3JB9k0e3P9dke3gZcYtlAh
         qliHP8V9JQF/NDyII3lFrGBG75i3vlBvKq2sHOy9wZpekG5Jjlw5gXeO7ebZno8PtQqD
         NoygkOfpY8M/o1N3Qn+c2yXWkBM7yLAcP+nzjYMgH1ED8JRcT8DpXn9LmjHmgBmiG1uO
         G4Y89wgKrrboLtGnPY6wuhpCu8mom7jgjvd6eQr1BzC+GR3ybzrrpzijV8H30oYioEp9
         ZCZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=lwr8Vkf8N+L/tCuYvXon7N+M0Ve52ARdPVwI9sTaz1k=;
        fh=1k6LNUcHTVkqaAiE49xCXYKb4GdgPVhvgzHv2TTUEeE=;
        b=h26BMkV8ChEAqlk5F3Nn4YtsYkejfYrtLGJrJmG/B3fSXRb4t4GOGJhcUBAwmOpLa2
         ulxqng04HqhzeAaraenJzVHsYmf52w+BSWFnUrO+jmyZRBUlJOUbEHtqapGLidvvrjzs
         zZbUNW49FVKQAh8JQRIMo7tUszcw5YvyBcjjGeftduORugXyZ/0CfvdikNOTuPrksGyD
         zobmsO1Fe2MoWGy/9MLAWJQo2wFxZJ0me4MJmhJ0oj75ZLS/eGBMHRw6+gkDPG9yj8ga
         EnxM6kkhoUfOHOLXtJ+n62rHeJfwECHwP5P0MOcliNKKzqgbfyKABs719ctREhSS5n/x
         Zn4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=k67cy+ui;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.182 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCWBPdqlRTWt9IAMeY+11vav3QygFLJ58qb+i1CtAl+CWXSRYFDTRYs84nWQD2zWu8QNdzmHiEgTeNlaAVv1QD4JEros/IoPyqH/yA==
Received: from out-182.mta1.migadu.com (out-182.mta1.migadu.com. [95.215.58.182])
        by gmr-mx.google.com with ESMTPS id o16-20020ac24bd0000000b00511a71805a8si1416lfq.8.2024.02.13.16.04.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 16:04:30 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.182 as permitted sender) client-ip=95.215.58.182;
Date: Tue, 13 Feb 2024 19:04:06 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Pasha Tatashin <pasha.tatashin@soleen.com>
Cc: Suren Baghdasaryan <surenb@google.com>, 
	David Hildenbrand <david@redhat.com>, Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <76imoy5prhf2rhtuajlx3whdowfs3swdmufmosqvqrlljj4bye@dofqsd4674ek>
References: <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
 <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
 <a9b0440b-844e-4e45-a546-315d53322aad@redhat.com>
 <xbehqbtjp5wi4z2ppzrbmlj6vfazd2w5flz3tgjbo37tlisexa@caq633gciggt>
 <c842347d-5794-4925-9b95-e9966795b7e1@redhat.com>
 <CAJuCfpFB-WimQoC1s-ZoiAx+t31KRu1Hd9HgH3JTMssnskdvNw@mail.gmail.com>
 <CA+CK2bCvaoSRUjBZXFbyZi-1mPedNL3sZmUA9fHwcBB00eDygw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+CK2bCvaoSRUjBZXFbyZi-1mPedNL3sZmUA9fHwcBB00eDygw@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=k67cy+ui;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.182 as
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

On Tue, Feb 13, 2024 at 06:54:09PM -0500, Pasha Tatashin wrote:
> > > I tried to be helpful, finding ways *not having to* bypass the MM
> > > community to get MM stuff merged.
> > >
> > > The reply I got is mostly negative energy.
> > >
> > > So you don't need my help here, understood.
> > >
> > > But I will fight against any attempts to bypass the MM community.
> >
> > Well, I'm definitely not trying to bypass the MM community, that's why
> > this patchset is posted. Not sure why people can't voice their opinion
> > on the benefit/cost balance of the patchset over the email... But if a
> > meeting would be more productive I'm happy to set it up.
> 
> Discussing these concerns during the next available MM Alignment
> session makes sense. At a minimum, Suren and Kent can present their
> reasons for believing the current approach is superior to the
> previously proposed alternatives.

Hang on though: I believe we did so adequately within this thread. Both
in the cover letter, and I further outlined exactly what the hooks
need to do, and cited the exact code.

Nobody seems to be complaining about the specifics, so I'm not sure what
would be on the agenda?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/76imoy5prhf2rhtuajlx3whdowfs3swdmufmosqvqrlljj4bye%40dofqsd4674ek.
