Return-Path: <kasan-dev+bncBC7OD3FKWUERBWEBZORAMGQEM7DY6JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id D70556F5FED
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 22:15:21 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-192b4dc7ef1sf217652fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 13:15:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683144920; cv=pass;
        d=google.com; s=arc-20160816;
        b=RP4Ck/llTiSQv18VM/08VqEFSPAQDgAx+3d5eN6PI3tK13NqdwpQe4b0EleQ5nY6a/
         Qb2Fl37ZyNvEZ1ncgjhngQNgQx0HI3WuR5esCFZtRAQgGT0jp6u5SyAgW8fqq4Mw5+wj
         9rMdlMuE/CiLVh0JkK6ymuczsszzlJQfvvGwbcWXX2XA3NE204Ggk5tw7+GW/7Z8bPdO
         VCURidXXxRaWnuIHOri6nzGjC5SKqcJRP1y0MC9I+ONxKFZgQHKFxVhUi3e5Pa+seSmY
         40QPfdZ+jGEk6DA51wzYezoziNsuvbDIv61czTrObNp+xdFWaqE3DkGpOUyyuM4obEGA
         SfLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pmlX8ZVYs6EV5VXN16FOt1/4vph2STmIpgvr1Bc1U04=;
        b=GvcCtPcRkl+e991RSQ9VhXMLUFT1JoyXyOQHpOCLT/yz0mqdQYVqkrfk6s20ZH+SPR
         mX1dAkM0d82EhUibtLdRoL7MvkKHdTDKu4E4XqYrHgDOrbHOM+SoVwTQGAtlwdJ8jY34
         AyE76/5iU8JWcF5dCNSa2iaXr2ScO0dnc+0EhMeFA7S9jN4It9BVeNIs7LOUWitb9+X2
         JzagzZdwI5kkp0LZqMhZyCdbMydBazeOAajrj06ur6qmJa5qvTf5AhdVOZHDicATtBSV
         2d5EXAwTTNMRB/8UWV5qXyPCNkgQCu6aVyAAX3gnrDojtB6Uw7/U3iDE6i3epUQSLtaA
         Y/2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=UCO8xAxP;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683144920; x=1685736920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pmlX8ZVYs6EV5VXN16FOt1/4vph2STmIpgvr1Bc1U04=;
        b=fzxMoCKItG7hsSRAxNDsRiIIUmce6Q3w8YcVLquiUKyxM5Yv2XNscymHeRHUxSEenx
         40w2LZ93OzQxTHFjFDlu8951sPWESCZmVCFx60t48nge64LhG97640E+EvHIkWzbzgpB
         /cnog+BMXCV8C8dRpedoW3CK9fRKFwLVeA/njPjQP0Kf+qM/2M8cw+kEA/kTNrAr7Sks
         L5+NH9sDSbidLDj5SsA/yvSGnfwY20pexa8DJViSYpzGwwNnFPqKp3NRTxSAilBqPYBB
         nlLiBM8M3ZGnCpvsVDcQQK/N1BlIaWEFdgqleZKko9zN3/HpusqVFgWAnl+QdtO3okBW
         apHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683144920; x=1685736920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pmlX8ZVYs6EV5VXN16FOt1/4vph2STmIpgvr1Bc1U04=;
        b=RpOb2kodElTsY37ityqMA7eL5+M0jO3KmCKjseDJBv+OX1Yzh4EoHkpHFgziU+QTT/
         h8EmlTvvlGZ3IUwjtNLL+d8MKywG4kEcvUltg40Ax5rWgN0+v6EUZ4P67qnvVe4KpykU
         kSQexv4H27g1aIz5UcOZMUA7u6Jl3GPPwkBA0OsLFeY9HUronV3DJ0+ZyFAz5E0BMcAC
         t+J8NsR+tvE94o4HzvFCr9ArJD4K7RUVwOrvvovrtnI9eBhy8t3kDL/iHydlLXSQm+WG
         jO26Ce3v9V86oSgFWlpQtadbW17M4/Ktq0b4exYvDbVC3n6Zg/mQP/mpD4vPGvdQwHlH
         wZCg==
X-Gm-Message-State: AC+VfDyOlgMvlbEmv/eMXa2dhp1xfTIfFxLzXGg33Hi6r6DMg7WLjP6i
	0HNzCXsFtjz68fSHnQkm50w=
X-Google-Smtp-Source: ACHHUZ4I7RagBe9FjwImI65qq1sZ8XNRenvz4DbptGJori+IfcICvMQaUDvXVcuGOAmd9pPLUpik0w==
X-Received: by 2002:a05:6870:148d:b0:192:a3bb:3819 with SMTP id k13-20020a056870148d00b00192a3bb3819mr1851723oab.10.1683144920673;
        Wed, 03 May 2023 13:15:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2c8e:b0:192:a0b9:956a with SMTP id
 oh14-20020a0568702c8e00b00192a0b9956als988748oab.8.-pod-prod-gmail; Wed, 03
 May 2023 13:15:20 -0700 (PDT)
X-Received: by 2002:a05:6870:7401:b0:187:8a98:10b3 with SMTP id x1-20020a056870740100b001878a9810b3mr11710903oam.45.1683144920261;
        Wed, 03 May 2023 13:15:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683144920; cv=none;
        d=google.com; s=arc-20160816;
        b=0hwvyGU2I26KzX9Hb1/y+7u5nGXT3gSbs6CYbSoojZJ7vIRcR6oo4HUD7DU4kbNpiG
         MD+gFr1JIOIkAfZ8q7hME6ef8ob6OY01Y7n8SHYtIni7eOkE9/x94XNUfqSLut24NYyq
         SP7SZvKk8e1+eI7G1kDQ4YTZvI2X/cWc/5L6rweFLPatM+Petqcc8F3wYOJd4H1PtZmt
         elqEQkcIdyxYArgn7c4pJuXqclSOjNhJn5sZOEqJeVCjLf6xSFPXxuLEZEleLr35MpCy
         2NyIBtfKC8aCYYrvxJxZ8aMf2esnwCqgyRrAsG9/zwP2Dqmb/FhHrAzxWNSYbURW4j9X
         3VBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fJv5xHBTJjNv/pix2rgh9sMW7sCnrk66nOy29HPAlus=;
        b=gD4ZDuUTIhuNdE6U6vI7HgyVY4ZS5K1N1CkNvJifwv/FNBJSO43RIxuHE5/JIV+ZRv
         r13f51gdf6pfSz+71j7izO4ByDpBCVWeeW2MFHCsYYX/K523DoPEQZlDmCNlkv1mjDcU
         fgAO1lVgq4FwfNaLD8yyfuKoSNlPqwZr7vkZcwXfc4+bUEjCECrDIYrStiSP2z1Kqr6n
         oFIThdCyQbV398qE2xKoZj2eDuVacQa9qNWKqp+gix2frkbCLFlfo74fMhqoLN5eCAwH
         VOsytmVAA5yhRUFo0eZXN4+06dSTokYTcrKDwpuJ4THDrD+3Af8Rkw3VacxwNSpW1sHm
         7Hjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=UCO8xAxP;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id h4-20020a4ad744000000b005472fa9aa03si389810oot.2.2023.05.03.13.15.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 13:15:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-b9ddcf0afb3so6392886276.3
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 13:15:20 -0700 (PDT)
X-Received: by 2002:a25:2b45:0:b0:b8e:db20:eccf with SMTP id
 r66-20020a252b45000000b00b8edb20eccfmr22508398ybr.55.1683144919429; Wed, 03
 May 2023 13:15:19 -0700 (PDT)
MIME-Version: 1.0
References: <ZFIVtB8JyKk0ddA5@moria.home.lan> <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
 <20230503180726.GA196054@cmpxchg.org> <ZFKlrP7nLn93iIRf@slm.duckdns.org>
 <ZFKqh5Dh93UULdse@slm.duckdns.org> <ZFKubD/lq7oB4svV@moria.home.lan>
 <ZFKu6zWA00AzArMF@slm.duckdns.org> <ZFKxcfqkUQ60zBB_@slm.duckdns.org>
 <CAJuCfpEPkCJZO2svT-GfmpJ+V-jSLyFDKM_atnqPVRBKtzgtnQ@mail.gmail.com>
 <ZFK6pwOelIlhV8Bm@slm.duckdns.org> <ZFK9XMSzOBxIFOHm@slm.duckdns.org>
In-Reply-To: <ZFK9XMSzOBxIFOHm@slm.duckdns.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 May 2023 13:14:57 -0700
Message-ID: <CAJuCfpE4YD_BumqFf2-NC8KS9D+kq0s_o4gRyWAH-WK4SgqUbA@mail.gmail.com>
Subject: Re: [PATCH 00/40] Memory allocation profiling
To: Tejun Heo <tj@kernel.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Johannes Weiner <hannes@cmpxchg.org>, 
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, vbabka@suse.cz, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Alexei Starovoitov <ast@kernel.org>, 
	Andrii Nakryiko <andrii@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=UCO8xAxP;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as
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

On Wed, May 3, 2023 at 1:00=E2=80=AFPM Tejun Heo <tj@kernel.org> wrote:
>
> Hello,
>
> On Wed, May 03, 2023 at 09:48:55AM -1000, Tejun Heo wrote:
> > > If so, that's the idea behind the context capture feature so that we
> > > can enable it on specific allocations only after we determine there i=
s
> > > something interesting there. So, with low-cost persistent tracking we
> > > can determine the suspects and then pay some more to investigate thos=
e
> > > suspects in more detail.
> >
> > Yeah, I was wondering whether it'd be useful to have that configurable =
so
> > that it'd be possible for a user to say "I'm okay with the cost, please
> > track more context per allocation". Given that tracking the immediate c=
aller
> > is already a huge improvement and narrowing it down from there using
> > existing tools shouldn't be that difficult, I don't think this is a blo=
cker
> > in any way. It just bothers me a bit that the code is structured so tha=
t
> > source line is the main abstraction.
>
> Another related question. So, the reason for macro'ing stuff is needed is
> because you want to print the line directly from kernel, right?

The main reason is because we want to inject a code tag at the
location of the call. If we have a code tag injected at every
allocation call, then finding the allocation counter (code tag) to
operate takes no time.

> Is that
> really necessary? Values from __builtin_return_address() can easily be
> printed out as function+offset from kernel which already gives most of th=
e
> necessary information for triaging and mapping that back to source line f=
rom
> userspace isn't difficult. Wouldn't using __builtin_return_address() make
> the whole thing a lot simpler?

If we do that we have to associate that address with the allocation
counter at runtime on the first allocation and look it up on all
following allocations. That introduces the overhead which we are
trying to avoid by using macros.

>
> Thanks.
>
> --
> tejun

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpE4YD_BumqFf2-NC8KS9D%2Bkq0s_o4gRyWAH-WK4SgqUbA%40mail.gmai=
l.com.
