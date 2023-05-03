Return-Path: <kasan-dev+bncBC7OD3FKWUERBMPZZGRAMGQENKHNBBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id C865C6F5AEF
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 17:24:34 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1aae6179e68sf25609775ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 08:24:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683127473; cv=pass;
        d=google.com; s=arc-20160816;
        b=vLkrpXV5r9/5bbZYSyTsNAbIvtamcBSSfffnaaDWE1Nln/xVWV7DMKISC/lnlEqt+i
         mruh6TqO+UF6uavhVDG2NlSO2ESCUe7+Ya2j9TZyHy4N6O2vcbrYoNuaOZJw1ezoxNZ4
         PRjQmlDRM1Wt4r9AHoe0FwgZK3MiJ1leItHize542nXaUOsUE3eXPilLHICI+BZ2jH78
         0y7IjnkSMGco5fIykgI144S78UubbRDV49qHp0epzlK2dUlHsSURp8UAwlheAZnuo8zl
         M0Fl7PbvGrkrE3NptK3FwiOPGHI9pjSJUK06rygkWA1QtbsDH1yftJVWO7iniZUhHAkY
         6/kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=of2hUjPAEAUlej825Dm75DXqjQ+22OSWInhiTxDCtiA=;
        b=Q1wsiVUxWRx/t0bpstvs/ObJv20Vza/9ExKegszy4prM2r53/KIYEAdWHUzYhSAdoy
         sFKMIJ9doN4lBHUdODz0bChpablW4/9EzWBFHOvJbBCX5GhNEggdMYnpI+TU5zUK/Z4K
         XRo41CIDFOf1i54sLYrGie9q48296zJaHNlLuCyQz/FrzbBl3r9e5yvNN8Sb+OLt0J3Z
         nBmapy9Dn6Ndy+wEd6vzOmDoUQY6GxQG6ZS/dWLT3+ofWNlLQMlAWCrtz6I/jRuqR0Le
         yRCGsuxjp5qQfhKZepxCeA3LC9gg4y+cr34ETRpnUbq9s6wffmD8qBFb4Oz8YpH9KXkC
         LPmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=unFkvF+6;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683127473; x=1685719473;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=of2hUjPAEAUlej825Dm75DXqjQ+22OSWInhiTxDCtiA=;
        b=XH65ZieRni8J3U86MB5t7StGWthcu0gg8cpylnustE4h4kBGaT/SwOHylUm+eyFaFE
         MM85WYU4Wx4U0elv2EbUXOBcC7NznkSJHMw7lKkZ5iMHd8yiLw5l9/W9vtm3UmvJVd5j
         K50OXwTUHnTPo3USNPPKejPdPe/RMnHD3AVLKhNYSpzM+rzOZ1yzrKHOeXEQxvtqr1DZ
         /lNi/obzzzm9VyaNu36CkskA9ioXD/+KQZrMNcjGwh3SmDj7ZKC8XF+g3hZUTBZrxh1g
         VMT2gEJ3Rd3ggEQK4FZYGbPqmyLqjYL/7dPr363GvcBGqhO/GnWZ/Iw2famM+NTrskdH
         s+2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683127473; x=1685719473;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=of2hUjPAEAUlej825Dm75DXqjQ+22OSWInhiTxDCtiA=;
        b=OuBQsBG6L2J5MDhgMmK8G19j1XluVKumB9SAgYv/y/tTiYt/x5i55ghiu47vPui2en
         piyvEndw6HACNsFECY8neyz2O2w7Z214Vv+lOB36zY0aMjcmZSVAofplFtG48LVzk+CK
         KaazS3eS8gmztLrZIXDxP4lAGYz9wVorh/9c6g/f6jm2t9y8mpxnzPUDePJS/qpHk69I
         wUfqWyaBqrqE+SwNZ0ob7FTTM34mwwPSoD1SanOIjdhE4UFbhc7Pfzd/EqSfiXSuRVbs
         frrY3pb7OJJXq1yGJHEe5TGxr6XP/dgv0GI5Hn3QUVhvAvMRNXvO2Ul91BhNKqOglML0
         kKqw==
X-Gm-Message-State: AC+VfDw1lOZ+f+6rvc4wJO+NSqeuif02loM6mVUt0eTXJIe8KpNT1TEZ
	gPuFNbMmnzXsA7WAUy6jiHs=
X-Google-Smtp-Source: ACHHUZ7DrGk3ObKOjQDtWupOS7RuPaq2cVL7FHct5/Lj1vGGVHh4nmhcm0137n44QdZ2jlMFF4Gnyg==
X-Received: by 2002:a17:902:a98a:b0:1a5:e03:55b with SMTP id bh10-20020a170902a98a00b001a50e03055bmr129546plb.11.1683127473193;
        Wed, 03 May 2023 08:24:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b02:b0:24e:8dd:ef7e with SMTP id
 lx2-20020a17090b4b0200b0024e08ddef7els6765034pjb.0.-pod-canary-gmail; Wed, 03
 May 2023 08:24:32 -0700 (PDT)
X-Received: by 2002:a17:90a:2ec7:b0:247:1997:6a1f with SMTP id h7-20020a17090a2ec700b0024719976a1fmr22602094pjs.12.1683127472384;
        Wed, 03 May 2023 08:24:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683127472; cv=none;
        d=google.com; s=arc-20160816;
        b=ah7mmHAF1vutYWveoH8BsEqvciQKJ2eYYWDEiJP0apT/iGVZcm93MM3k9En6Zd7X10
         UF+0jktz+36LHUtMdjAcMd84pQiC1pFDNPIr7aBZ2wDIXuNhZD6TQbETULlvGlYjTshq
         +dXJY4HlMSUqZ4EMIm3uAIpvC4uAh6woe1ZqCDl2on+V91JMmsi0bP/zG3gB0D/2Pzxg
         lgWRTamM12COqyiaqt8Omi+pdbjd3jZ1sPac3+zBolZgTTNarjY4o52QiZkzao0G7eOh
         oZq8csesRdbCx7LuXxxFEUbifhz96Nq11LmGP/cIIyhphlogVF369YO/hv6jEjw1c9PS
         q6Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3u3xUQKsQtY5MjJU7KWdFVlKdUwGfS6WMFqIdWoJCIo=;
        b=VCMB2XfFO65uQdTzJKSRAy9UYiOGzBberHeryUFUmutOI0NdMiUHlPTGOeAsjXNoJO
         MIGc7/+A2E4RPftxQmqYGYPqfi+cEmP8u6X7WCC2Lb150bEwcnTgGK2oGEemoSDFFUmr
         2aZ26T1SVddeZjiKFn70WRjZ3YEndbi/qi3Jh6W0OzHhPbwsjbecaWC30o8sLRIP4RPE
         kwp5z+uIFuaFqeWI8ZC7VdpsvCejM0ZoFHTSr1LfO3XuBRkYGnaKcvUvd8EBxivPSOys
         mnPFpOdGgP/FuLffIr7c0gUJxqLMPgIZRBWLxriXLZhwUNOoxjK/ximi50pc24j9DWCr
         /JLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=unFkvF+6;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id z4-20020a170902ccc400b001ab0493c81dsi348495ple.13.2023.05.03.08.24.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 08:24:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-55b7630a736so16342427b3.1
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 08:24:32 -0700 (PDT)
X-Received: by 2002:a0d:e296:0:b0:55a:4109:7f5a with SMTP id
 l144-20020a0de296000000b0055a41097f5amr11315408ywe.12.1683127470672; Wed, 03
 May 2023 08:24:30 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-36-surenb@google.com>
 <ZFIPmnrSIdJ5yusM@dhcp22.suse.cz>
In-Reply-To: <ZFIPmnrSIdJ5yusM@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 May 2023 08:24:19 -0700
Message-ID: <CAJuCfpGsvWupMbasqvwcMYsOOPxTQqi1ed5+=vyu-yoPQwwybg@mail.gmail.com>
Subject: Re: [PATCH 35/40] lib: implement context capture support for tagged allocations
To: Michal Hocko <mhocko@suse.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=unFkvF+6;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1129
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

On Wed, May 3, 2023 at 12:39=E2=80=AFAM Michal Hocko <mhocko@suse.com> wrot=
e:
>
> On Mon 01-05-23 09:54:45, Suren Baghdasaryan wrote:
> [...]
> > +struct codetag_ctx *alloc_tag_create_ctx(struct alloc_tag *tag, size_t=
 size)
> > +{
> > +     struct alloc_call_ctx *ac_ctx;
> > +
> > +     /* TODO: use a dedicated kmem_cache */
> > +     ac_ctx =3D kmalloc(sizeof(struct alloc_call_ctx), GFP_KERNEL);
>
> You cannot really use GFP_KERNEL here. This is post_alloc_hook path and
> that has its own gfp context.

I missed that. Would it be appropriate to use the gfp_flags parameter
of post_alloc_hook() here?


> --
> Michal Hocko
> SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGsvWupMbasqvwcMYsOOPxTQqi1ed5%2B%3Dvyu-yoPQwwybg%40mail.gm=
ail.com.
