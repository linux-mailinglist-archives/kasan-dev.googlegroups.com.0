Return-Path: <kasan-dev+bncBC7OD3FKWUERBDPH3LDAMGQEMXCRNWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 7245FBA4726
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Sep 2025 17:38:56 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-32eb2b284e4sf3200170a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Sep 2025 08:38:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758901134; cv=pass;
        d=google.com; s=arc-20240605;
        b=UN56hGg/dGJOEqfnk4qMeYoOfKXxR+9SXgMmt/75A+BLo7GfoLu8a5+XjAZyOOBDww
         29+4KkWoLPbYLZSpDrFQZWYmTwT/VtZaenULAkPhECrg7IwDa2Yl06Dhv2yKhyMRv+KN
         0ZEE+hSOCZFZQym5bJWzIEbat95Ep6fna7rXqzLH/VxsGD3ZPu42bCH+CBGJgxkMmsei
         2w/O1R9UjPECDnARj4liLNHG9jIIc0032CDn9OmFce8k7Gs1gf2XAzDgmzUYMQA2rHWv
         0WwDC/QhElZTbGnp2mTDC0MEUNtkYSxvRlTcdMRMFloGl69pmS+H+bHFWg5Mnm4vZhYC
         JzMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6kVQVBKTRq9nL/3Fyr24JOd2gVk/SqO0AG0a5KzowkA=;
        fh=nr/jqkCSfE2ce8xzXgZNo5KVpD4UnHTaqP3hI6Sui/o=;
        b=jCsqc3/LRBLu/fUOrs9N9RQ55K0ovHorj1QNZQzGnv+nO0h41wZUU5mjmbD7CPBRhz
         vGzf5+Lc9mQfU16tuO4ykoVYIlDMybsGHiSvfB+ajkUAchElfaaf698tjCXIo2sCd7jB
         PkML/yENoVi4f0aTyQ9bafiyluW3INuB0guyhQXAu0W5kfxPufIFyDySwbEKCL2048s6
         fEfM5wGhfpOG/D4bdRY/+8qKe5X+RSCDOgAn9j3ZScPPqeeg6cx1iOhTKohuycWD0BLg
         89LdWBeuq6IZZ5qSfVhocV8HaZV0m5TIRlKQbtCbTmsnEq1FZsaktcdQjEif+icDGH8E
         CBwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OzWzV64N;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758901134; x=1759505934; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6kVQVBKTRq9nL/3Fyr24JOd2gVk/SqO0AG0a5KzowkA=;
        b=PhhWI8ShClgRl2RDu8p6xQZYQvG9Un73Wp6yPKNfP0SHocDaZ9jYFNfAEiHWxiImob
         3W0m4wlE/OQnTpBfCN/ser6iXbDE9Fy6uedD9fdkNtwzOjJOzi59io9pYK4wY9CI4rzv
         H4ZmhmFFHQTlzECNfujWq3Mbln/XZr/SLtA/ndvcYrVl86Z1EN0KCUUGkmsrhyrRYZy5
         lRFfdNx6hqIkKIvbfUDPtPIzwtiWwhiZ1k/qPZtLpnJY+dNjC6deN7nGAqwSJqWTsJt7
         G89UFqoc/kopEjCbmyCSCbkYYeVqur7oPZVNhMcX7kHvX3+ASPZBgSBVdQyMYKaEpONj
         iA+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758901134; x=1759505934;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6kVQVBKTRq9nL/3Fyr24JOd2gVk/SqO0AG0a5KzowkA=;
        b=fStuZIK1GAtM9TGXC6eNrb62/HdkYSG6siNGsoMj1ibepjDCuczSZUnrteCa1J3mu1
         azqPRHmcv4OvqplrHMaIlfEdON/LQ39V6xQLr/upNXsANxfF9JvUtQxkKhKwCvbqxT5s
         mHTNnseobF6NQVdw0v+Y2ykB/v+/uZtmfTak/1JH0asWT/+Y29ujzyxHQTRAg6zcq+xX
         5XNtSPXESOQE7Ld5fg7m5tSMcyMX2X1/ZJWFC05rmkjzNDYcCrCNjg/KAxqN/DYKRZSC
         J5P6tFFvs50oW0ihKbGzEl9iU7aaV9DDRBurbssvPSp0leGXV7fm6juvudSPv4fTsRE3
         0iqQ==
X-Forwarded-Encrypted: i=2; AJvYcCXU/5HG3Hv64lgDa2TAuu2tgiFw7diJhGEmVKUGtF/hdtvJApaS2P1/GV/mm9Uj1xwSaN79ig==@lfdr.de
X-Gm-Message-State: AOJu0Yy3aso30DI3IqJ6gO4e9Tnp9p/wAnIPYs0qXAEigm1yKUl5oH35
	pmm84qULxhcVpVx5Q6oK37HijZ+XcURQuoQ2jkDS4JGgvEYj7nbFfIla
X-Google-Smtp-Source: AGHT+IGEvxyDkgVU80iI88SDz3uBjK0FIbeVMOlKVBBd6+9uSNsndQwLDhcnpoOzkD+WsRqIh/Y/kg==
X-Received: by 2002:a17:90b:4f8b:b0:32e:42bb:dc58 with SMTP id 98e67ed59e1d1-3342a2c28dfmr8601006a91.26.1758901134230;
        Fri, 26 Sep 2025 08:38:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5Wtt1W6CaDtFRy5SKmbn8pONS/XWo38KxsK5xE+nyseA=="
Received: by 2002:a17:90b:3744:b0:329:e0e8:a90f with SMTP id
 98e67ed59e1d1-3342a4d169als1942974a91.0.-pod-prod-03-us; Fri, 26 Sep 2025
 08:38:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXPS2sMWsN+HYEEmYRghY0KfGtxnGN8KdvnCZ7yVt0P+3PY7qYIhs8hSm59sjL9arVJGe+fqT/Sl0s=@googlegroups.com
X-Received: by 2002:a17:90b:384d:b0:32e:64ca:e84a with SMTP id 98e67ed59e1d1-3342a2436b8mr10611048a91.12.1758901132616;
        Fri, 26 Sep 2025 08:38:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758901132; cv=none;
        d=google.com; s=arc-20240605;
        b=P6P/l1g53CUaCc+5m2+peOKDGlkASOIvikWQIdVwWtgt+Koz6KmtIaaVdhSqb++H1t
         EO8JJsqcYaDNoI6A58GvBjJTY4zQHuh3ZRM4xF1xIfmo5+JWapyNspfDTJa0rPAfdtS0
         KTIuvG6XHiSJL/THDEPjmlzuLQQrL1nCLoJYBt7oJEpkcbsTmfvQCiEzHUcVIUN/kBhi
         rAd9FRjevecC9G7f/cqD3Mcnp9+wncaiQP2tTZdEUYjGyMt0a8LOiC01OkwsrNq50dwk
         NF/F1BnlfR28k5/9oJrl8k/lc8/vae/bbBOEevqojjPfvtPFlATnuspKi2W/r8UkoEp7
         BrtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lXzocX6ZDXcHxojnIagSNZA3qKAOhB8e13p864rbCw0=;
        fh=VFe6UK9DA4FGhMKw/tl+6zh9vN67MLV4FnJnLCMSFsU=;
        b=IVzidrvE0UOPur7qVg1L7yuMNAASbwiM4bQwF5McAJn42HwQMo1YusXCTAis6NOn1b
         9U7ppBe7wAHhEuCzoA7WYy92oZ35FXc/voWo3UyXmHcKSgRe3PEMiVWrq4gm9C95fA2s
         EvmQtqlWikyRYuKEhO6t8rIPyYgW4yQK01Rby5PJkxCuZXsAhRApk1LHa4wGlu4N6HA1
         h00wJR02BW74GQvCDegq01VpkpjvQQ5LrOfc6OLi/gOlliCg8I/Jnt25k3Om3oiPXTFx
         0poodhrA3p39t3qYNad0ymclC6jr5EyXjsPPOuGmTqXhDaSxNoPwihT1ve2IC4f2Fvh6
         pL6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OzWzV64N;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82e.google.com (mail-qt1-x82e.google.com. [2607:f8b0:4864:20::82e])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-33470ceb81fsi258117a91.3.2025.09.26.08.38.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Sep 2025 08:38:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82e as permitted sender) client-ip=2607:f8b0:4864:20::82e;
Received: by mail-qt1-x82e.google.com with SMTP id d75a77b69052e-4de60f19a57so255021cf.0
        for <kasan-dev@googlegroups.com>; Fri, 26 Sep 2025 08:38:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXe6jBHBPSeu9xeeQS/eiMmNCXCmp/xSV+3vQZUCatFA5Vo8gMa0gQIR90lKnxZTxEMQyOS4VhFLWM=@googlegroups.com
X-Gm-Gg: ASbGncuos8e7arOg67UxyZ7uA4zNA5KjjB1p0XLK+KfWkSarIT5KP766dgfUdfbIgNG
	0kJ5T36OXbBsN2BpC9BR7zsQrwvmzNZS1UmGOYHID/jbjH7Vdk/Uie/GTyLH4qnPkf3zLibWTxZ
	q/mNe9fsdIX7e5jNWofFCsBSimrhabGoyUdV4MmNAhqJwD6cl591qWb4Z0ozJL6WUjjtO+8woUx
	7gAAC1d9Hqu
X-Received: by 2002:a05:622a:14c:b0:4b7:9b06:ca9f with SMTP id
 d75a77b69052e-4dd1675a20amr6251731cf.2.1758901130945; Fri, 26 Sep 2025
 08:38:50 -0700 (PDT)
MIME-Version: 1.0
References: <202509171214.912d5ac-lkp@intel.com> <b7d4cf85-5c81-41e0-9b22-baa9a7e5a0c4@suse.cz>
 <ead41e07-c476-4769-aeb6-5a9950737b98@suse.cz> <CAADnVQJYn9=GBZifobKzME-bJgrvbn=OtQJLbU+9xoyO69L8OA@mail.gmail.com>
 <ce3be467-4ff3-4165-a024-d6a3ed33ad0e@suse.cz> <CAJuCfpGLhJtO02V-Y+qmvzOqO2tH5+u7EzrCOA1K-57vPXhb+g@mail.gmail.com>
 <CAADnVQLPq=puz04wNCnUeSUeF2s1SwTUoQvzMWsHCVhjFcyBeg@mail.gmail.com>
 <CAJuCfpGA_YKuzHu0TM718LFHr92PyyKdD27yJVbtvfF=ZzNOfQ@mail.gmail.com>
 <CAADnVQKt5YVKiVHmoB7fZsuMuD=1+bMYvCNcO0+P3+5rq9JXVw@mail.gmail.com>
 <7a3406c6-93da-42ee-a215-96ac0213fd4a@suse.cz> <CAADnVQKrLbOxav0+H5LsESa_d_c8yBGfPdRDJzkz6yjeQf9WdA@mail.gmail.com>
In-Reply-To: <CAADnVQKrLbOxav0+H5LsESa_d_c8yBGfPdRDJzkz6yjeQf9WdA@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 26 Sep 2025 08:38:39 -0700
X-Gm-Features: AS18NWDgSteTnQAeHe58pnPN5CXO_C6LUnKFpTmB_8Hvkh2DQsaUFE0c0GhVrg0
Message-ID: <CAJuCfpG7Gf3_P6gKrUa+3iNZgq7SNd7nZa7Uq1P+v3FVHnL4QA@mail.gmail.com>
Subject: Re: [linux-next:master] [slab] db93cdd664: BUG:kernel_NULL_pointer_dereference,address
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, kernel test robot <oliver.sang@intel.com>, 
	Alexei Starovoitov <ast@kernel.org>, Harry Yoo <harry.yoo@oracle.com>, oe-lkp@lists.linux.dev, 
	kbuild test robot <lkp@intel.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:CONTROL GROUP (CGROUP)" <cgroups@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=OzWzV64N;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82e as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Sep 26, 2025 at 8:30=E2=80=AFAM Alexei Starovoitov
<alexei.starovoitov@gmail.com> wrote:
>
> On Fri, Sep 26, 2025 at 1:25=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> =
wrote:
> >
> > On 9/19/25 20:31, Alexei Starovoitov wrote:
> > > On Fri, Sep 19, 2025 at 8:01=E2=80=AFAM Suren Baghdasaryan <surenb@go=
ogle.com> wrote:
> > >>
> > >> >
> > >> > I would not. I think adding 'boot or not' logic to these two
> > >> > will muddy the waters and will make the whole slab/page_alloc/memc=
g
> > >> > logic and dependencies between them much harder to follow.
> > >> > I'd either add a comment to alloc_slab_obj_exts() explaining
> > >> > what may happen or add 'boot or not' check only there.
> > >> > imo this is a niche, rare and special.
> > >>
> > >> Ok, comment it is then.
> > >> Will you be sending a new version or Vlastimil will be including tha=
t
> > >> in his fixup?
> > >
> > > Whichever way. I can, but so far Vlastimil phrasing of comments
> > > were much better than mine :) So I think he can fold what he prefers.
> >
> > I'm adding this. Hopefully we'll be able to make sheaves the only percp=
u
> > caching layer in SLUB in the (near) future, and then requirement for
> > cmpxchg16b for allocations will be gone.
> >
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 9f1054f0b9ca..f9f7f3942074 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -2089,6 +2089,13 @@ int alloc_slab_obj_exts(struct slab *slab, struc=
t kmem_cache *s,
> >         gfp &=3D ~OBJCGS_CLEAR_MASK;
> >         /* Prevent recursive extension vector allocation */
> >         gfp |=3D __GFP_NO_OBJ_EXT;
> > +
> > +       /*
> > +        * Note that allow_spin may be false during early boot and its
> > +        * restricted GFP_BOOT_MASK. Due to kmalloc_nolock() only suppo=
rting
> > +        * architectures with cmpxchg16b, early obj_exts will be missin=
g for
> > +        * very early allocations on those.
> > +        */
>
> lgtm. Maybe add a sentence about future sheaves plan, so it's clear
> that there is a path forward and above won't stay forever.

LGTM as well. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpG7Gf3_P6gKrUa%2B3iNZgq7SNd7nZa7Uq1P%2Bv3FVHnL4QA%40mail.gmail.com.
