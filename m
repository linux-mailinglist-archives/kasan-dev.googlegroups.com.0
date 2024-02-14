Return-Path: <kasan-dev+bncBC7OD3FKWUERBBPKWOXAMGQEXUDS2FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EC9C854F9E
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 18:14:47 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-42c6fb437b9sf816661cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 09:14:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707930886; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vj+JGjAQJjpUKS1E4fA+IggrOhFLwtDFEzr3fB/XMjKCFGevDGqN6ZQtcvxiSdHy70
         AUhos0j5Wt1zPfuZIpLwZc/lhlFywbAP5tLtaEyPMFu2sR36JkcHfV9lnyswGMYuf1dN
         JIxpcHDrHcRri/GzI0GTlpRWwoTvkkta+VMyrRm7abtVi1lmEj6IkHav3vB14ZdCe+N+
         ytiWi7bzXGw1FnWcUl2gDEHerY0myf+uLmj/J6N6VIU1bAavI9zAaYAAJ/XrlexlfDEQ
         pchYRi3mZzYdY0YExQDNYtGl40B2f4q0PKEJMHVupONlZAL8AT3bUGNBxaKwxwctBDmY
         IgMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y2BAYmWtcFOwx8E/qV0EyRaoIyExPIZdyQpQb22biZM=;
        fh=0Lzl4Qpar1xo6jjHxd5xXf6grbVK9xzfQxZWyU9ABuI=;
        b=gHj3PetNcXsauTJvyeD8LXqFZzc13NvZxd+g28HuZ+8mQUj1pvcxgbKA0RrTQ/CKG8
         /FzmNFuu3Vhcww8syvhjNsLUczN10eo0oZvx927Yk6N9vIxHeLZkBz04fembtd3f5sMb
         B/MOhae6/OzSwzmOYZaKcZRAT5+Fw5QXHRr8dh862LxBo3JjbaAsTnPVvKub1QhnCQtY
         vyHwJhwLYAzm0brOjMfKvi/mR05M4r1ruMJgiFC44CWWfk/xGgJes+0nLV1Hc5xeqfIz
         F/DaAGKaFiIgJrkBWHhp8BxJvmFBNBy4Q/1xuF46MDphCCxhnwj9KTJHCpex3rWylEl/
         s5TA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oPUuUgtP;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707930886; x=1708535686; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Y2BAYmWtcFOwx8E/qV0EyRaoIyExPIZdyQpQb22biZM=;
        b=MOWRbX5mtnvSNKVWzKkBBsWrxKVybZDZqW8oCzKSdVzNEz7FJGS9a5tYdMSsjCgVC3
         d4EnC9SKRRNgat7SflMnwls273ZYS1QpGZfDH54p13nt7QnrC8bFS/1CXdgbhvv6a2zh
         C9JZtLzRhDpBov6+jauF/j07HwIVFcEU1oEqqC8SMMbpfEEJ2vQpq4SJF6wmbelm9gKE
         9KDa2h1ipJk3sTXv8A1DHIE1ZkG925Jjj2zvY5sNlDQcG8OXyjDbi2jhb6doJTtuDP/2
         Tc1dmI/gyx7E0y/cqi3vgPJUtPTiOV/X8/kagJK+yURCnh/6RaneiHEf6hEghiGcwQ2B
         s93Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707930886; x=1708535686;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Y2BAYmWtcFOwx8E/qV0EyRaoIyExPIZdyQpQb22biZM=;
        b=g25ggYBTnwMmQoI3lLdaT/FpMK79GbmS40viblf/Mowdxwtz9sM6wTysSx9sq0ucyx
         r65CNTvrDqHTPr1zhdw5ZK+r26jFLHyLems3GrEZoUYw0TuOVIJfGFTRY6cCGNp0EXjX
         isb0RR2TQqNRuKTvbiuMvSUL/TuAhMdievBAEf1PcXaEYNZIJrJTYE3W1wqEvKKYqQwB
         T7cGrtzMx0oDlkxcB7547H3EiALQl3DxNn2Htw4VTA5AtoCW2IZKC1RuWrlS7/Bof67s
         IOYXrJeoK2W6bE33AcFWNe8wJVGUEgL9qSoLj8FYuod17/AdioNzRLjQIWzjUkTUNUeW
         RNxg==
X-Forwarded-Encrypted: i=2; AJvYcCXAZ4fdgTFIzRO16wWDQ7h78My3/PibHx769J53gXPgM++gUcFOfmShQzF7mFzY9G2R7Xuk3Mfd6Ydbvzxq0WlQseDbGuqigg==
X-Gm-Message-State: AOJu0Yw1Cf5rOOIywKiZovGBUFlS5HrvEV604YxS1pvWqXmcIb4b51sq
	ARb3xxTlU4vvYjFIAIn+5vIJosCHfeOX3f3pr8zR0l469EBc2B7G
X-Google-Smtp-Source: AGHT+IF7GBfEzhcopkXfFMLRG8c+meK5gY34Oo9ZJVtxaw+wzOnkDXrW5YiHKcIQjK8jjV0LD9STIA==
X-Received: by 2002:ac8:5c56:0:b0:42c:757b:9409 with SMTP id j22-20020ac85c56000000b0042c757b9409mr320101qtj.16.1707930885808;
        Wed, 14 Feb 2024 09:14:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:246e:b0:68c:bc0c:6bb with SMTP id
 im14-20020a056214246e00b0068cbc0c06bbls1565390qvb.1.-pod-prod-00-us; Wed, 14
 Feb 2024 09:14:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVe708Ybhb1eeDm3VDAo5l9XsTPbc3PUJAOl9odWFzmb1sWZjd5um7uABQKx7TdJcJQp0N4MmzA5VPHYc0FvXSeMrfMmvv5hDWyqg==
X-Received: by 2002:a05:6122:d16:b0:4b8:4e76:a5e6 with SMTP id az22-20020a0561220d1600b004b84e76a5e6mr2681684vkb.2.1707930885141;
        Wed, 14 Feb 2024 09:14:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707930885; cv=none;
        d=google.com; s=arc-20160816;
        b=lGNN9sPHx3FOJjEM3rX4Mk1vsC6IbdZS/pWWKniT/mv9zjC5c1lO7uZUXKCCAzQKC6
         h06rlaUAsqGJl16BIqGhw43L20lbwo/td08/VYggLo/Evn/jFmF0GRVkoNDu7/XZ1dN/
         AfIOqzg0qpdwvswiE7XfCOzGHMQ0S6NbGoDgWPAymbqlp8f8GCL3nlLRmBdEjV2QCQtI
         PiVRo5qW5JNaVZcCjjvyfF8LQHJ9gRoKKLuls1YuZwSUFUP3nSjEp9FyS2tyaq/B0/oI
         lp8KSxPAwC/qLZQjaMJWO1K4XIncSEDQehagE/LaMj8XpTqYRhnJMlAp4UOzKIVQ4Fy3
         tEAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8ou5WjqaFbf0d6dlT4/+7co77L0bUTMJQFMyMq7YuMo=;
        fh=f4PMYpyZwuDTJGd2IUEaJMtufEWGu3CIhWgD9te1wmQ=;
        b=DxrDP5I7J19LEJDT3pFn0v+O4L8EE8wTjV37kcNMmyxfs8ESrQfmiRRRESDsG8tbhS
         6kfM2vF4hT0VoJrwBPZfkRMEX2bFfELbt5mvQlkNdzDI5gpv8QR0yeEcrs2/x297D3cN
         WCXtL31CiviFec5r9+f9dPAZ8UE6AZrLMfTu+Nwl6eslLkjEC+0LkWOC2wyT2CkxG9Qa
         3coMx9WhgoVxAv730S9+2hRFmXrKuV5uj6m3RD6vvHdOPCxLh/E7bC7VXjjDcw/VZtKa
         Ybs/6tba5fpySwNLeAgFkmFmojfaXzX4cnHgR56Cx5OyMtHvt9NIqAuFm4cHTgejc/UN
         NqUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oPUuUgtP;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCVPmIDDmQYdQ8giyMNUpSVDt+3GLIFnz2ZfAf3VP46VELbs6NPm+wbYUvJUg24HRNYRvitDzYs8u2B7Ah+rsC1PNT9GoqLWCvh4Kw==
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id v6-20020a67ff86000000b0046d3986403esi860081vsq.0.2024.02.14.09.14.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Feb 2024 09:14:45 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id 3f1490d57ef6-dbed179f0faso777673276.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Feb 2024 09:14:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUs4lGNlB90SkOiM4j7O75n0xmhpV02z1Ks4KUX0nU3rxboYFwCH0kRviLZs+N7zg8FFATRnTZaJf+lFnMQxua8uulIKl0m6VwPLg==
X-Received: by 2002:a25:4b84:0:b0:dbe:d2ec:e31 with SMTP id
 y126-20020a254b84000000b00dbed2ec0e31mr1980533yba.27.1707930884496; Wed, 14
 Feb 2024 09:14:44 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240214062020.GA989328@cmpxchg.org>
 <ZczSSZOWMlqfvDg8@tiehlicka> <ifz44lao4dbvvpzt7zha3ho7xnddcdxgp4fkeacqleu5lo43bn@f3dbrmcuticz>
 <ZczkFH1dxUmx6TM3@tiehlicka> <udgv2gndh4leah734rfp7ydfy5dv65kbqutse6siaewizoooyw@pdd3tcji5yld>
 <Zczq02jdZa9L0VKj@tiehlicka>
In-Reply-To: <Zczq02jdZa9L0VKj@tiehlicka>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Feb 2024 09:14:30 -0800
Message-ID: <CAJuCfpFR85w5_8sX0uLfi4SsVb8Yr6DDu=VTA25PB-3SgC=5UA@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Michal Hocko <mhocko@suse.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Johannes Weiner <hannes@cmpxchg.org>, 
	akpm@linux-foundation.org, vbabka@suse.cz, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
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
 header.i=@google.com header.s=20230601 header.b=oPUuUgtP;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Feb 14, 2024 at 8:31=E2=80=AFAM Michal Hocko <mhocko@suse.com> wrot=
e:
>
> On Wed 14-02-24 11:17:20, Kent Overstreet wrote:
> [...]
> > You gotta stop with this this derailing garbage.
>
> It is always pleasure talking to you Kent, but let me give you advice
> (free of charge of course). Let Suren talk, chances for civilized
> and productive discussion are much higher!

Every time I wake up to a new drama... Sorry I won't follow up on this
one not to feed the fire.


>
> I do not have much more to add to the discussion. My point stays, find a
> support of the MM community if you want to proceed with this work.
> --
> Michal Hocko
> SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFR85w5_8sX0uLfi4SsVb8Yr6DDu%3DVTA25PB-3SgC%3D5UA%40mail.gm=
ail.com.
