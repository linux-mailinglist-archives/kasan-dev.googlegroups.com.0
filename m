Return-Path: <kasan-dev+bncBC7OD3FKWUERBQNOX2XAMGQEK2NOZAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 28E788583A2
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 18:11:31 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-363c06d9845sf21492075ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 09:11:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708103489; cv=pass;
        d=google.com; s=arc-20160816;
        b=yQGZbSrE77PHtkTSQQVeV6lprSPClPJsm9IEiw1KFFcLS4welQF+JY/ev6Xybes8VI
         fkSxnyOwZq1hcuouxsxPD+K+tOmEBxxUhupI7CVjscw642M9dm+k/N/xGWO1bktnexkO
         axgcT+hUh6DR32LiR+NiaAwwIb1noJMgR0o4XK32h7kyS4TIIzLC1//WdneFOkovG7TB
         Ic/mULpM7byCyK7FGka4xxlQgt7e4o12WeWUgb2y2lGntZpA8wWR0TsW62GQdtqCvAgx
         7TXFhIoVQs1Rmu69l06FmDFhfdhJYAOjg2uNHzimfyCG4eeULCqYQLsC8muVqjbP7znQ
         9IOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mz+tjLBsRlFMJrtQLHB/kCQUOOPM2R6sWOb9yOF2Wos=;
        fh=3Q9Ishu666/pzMsFST3iX9d04UHtUWR8lzO5DreZ1wM=;
        b=ikb9XOxsP+yQNvFDmZvDxa2Q5wMww5KfXoyo1KwFSOIpsWUQwc5fzZT9g2on0nn7My
         xtQrn/Wtz1YvLF82pTVXFWPpFIKhexjZZkHtAyqiXx2ll1K8CfqBqbdjWTmvGpgYIwnA
         T2feuPySunpwjykvuHWUjpnlmjZfn/IjcZ/4MuY9ZnMpRZAW7FhdnuUVMNuV/IxVzMJR
         A0X64Afjy5JvrFdx5MyCuzz4L4RqXkm2kLVa0BAKpzWCW6NC7z0Ug56OmI6VobNwH1P0
         d9cOQ/ToswUhGPZlR2RuX4ztOh9WHA2+nEskDwk1g51kmK4NftuU4a0O+GnHr9b9nW32
         P7Qg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Tegbuwkl;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708103489; x=1708708289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mz+tjLBsRlFMJrtQLHB/kCQUOOPM2R6sWOb9yOF2Wos=;
        b=G2w52a59Ft7HaiCvcmZgYCYVg1C9l+zISJMPMdQi3mucRukqYL8smqKLjjQyK/1PgS
         0JHmp3PBAbaYdzP8SABhPNXwz+aNFagTb8+K2ng/u8BD08cfp7nubVBlaRXUN9B5T9UB
         EToeQNNty1SWk7Ha/pqBJJ2h4quHttjznARmqY22C8LFG/e2kGswco3cor1jrN9nBAA+
         HQtHlP/BUsyjjrYTkL77/Em1ZobFsPBIaM70Y2x9Q56Z3RWFBp426dmbMUVBM+l4wzoX
         WtHndKXph2mCmSjRJAcu9+HXPvmNNxXWT/gfZG1Sd4Ov1EjUQtpKB8fEJBCyL480EcqV
         rFGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708103489; x=1708708289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mz+tjLBsRlFMJrtQLHB/kCQUOOPM2R6sWOb9yOF2Wos=;
        b=OYGXbFoAPiybroP100eKPJSXKFeUmnxDKmj0bmOuDKfJbneq1RFToD2SfYedOgdGw5
         BfRe3SjBXlbpQv4bRaLKOL1aMbwRpdTt0Dv2VMcbYb4tXHXjWjjqiyLouOfKgc7Sptmg
         KsBLvlPsxdHUFIqZYmlO708Fmn60wZxlvNPSOmgOJpPdtPCviGT5c3He95wYTDXQoxeN
         6yq+I7OQIYbPljAp0ZowzYFncSeoJazqANY5Q72cOwJ8gT6osNii7aS/UMWSBtUWBlgl
         GtERkVXpaxjLTjqSc2uRjT2eo3LlXVt/nxjnAr1LHYz6zyCjgYD+seCiwlua4abFgyG8
         +qbQ==
X-Forwarded-Encrypted: i=2; AJvYcCWvtM9j86NecjKWPNFe9sIIwWI8p5bD7IYKZKFDb0PuYlilfB6tOvCgJgujve2peWlwcZtikYf+ZZC0cc8EzJYS+RXLsXPqtA==
X-Gm-Message-State: AOJu0YyqC51KLaSL8hz1okuDCzomqiyHS0Dc7153G8Vif37E8AWjnk0B
	Wn74QUykt4Irmx4yfeHmCAG7eoS2sCHRzuKZwK8adJQsJGzkzObx
X-Google-Smtp-Source: AGHT+IEO+EvOHsBYQeao6HIz3BIgH//B0M29SR+JSVJldj4q0Ra9uUZ2qDCY3PdVq14wH8Ey+NPlRA==
X-Received: by 2002:a92:d58f:0:b0:365:1174:6e18 with SMTP id a15-20020a92d58f000000b0036511746e18mr1490881iln.10.1708103489617;
        Fri, 16 Feb 2024 09:11:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:17c8:b0:363:7d3f:13ee with SMTP id
 z8-20020a056e0217c800b003637d3f13eels778346ilu.1.-pod-prod-06-us; Fri, 16 Feb
 2024 09:11:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV2DabV+PP0+xmlgkQFShUwa5IYJFLFFLad7W7NSSsXkz+vAmbG2VCClTwtqyE9SGZ3XGaUW7uNMGrnzoj6VEe6f06rW+euyopyOA==
X-Received: by 2002:a6b:6008:0:b0:7c4:4d50:2c99 with SMTP id r8-20020a6b6008000000b007c44d502c99mr5820113iog.11.1708103488922;
        Fri, 16 Feb 2024 09:11:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708103488; cv=none;
        d=google.com; s=arc-20160816;
        b=D4TaiDm1hoddIZPQpnvHt8mm0om9gPM25RWk/wJzHbOjfw2W6qqvZQLfla+onII/oI
         Y//nnySWwuXFqBEijIDOOH8QJbKoimdse049D/HW5bDco1FbyM+IigvzerMPpeVn2ZG9
         7ztSo0vczWXUpMhSRZflUXT5oQS5OKO8Zfsn2vDLOit9rRbMtsjKnViadIGrlBGWcC8d
         FLd9HoF66zH4vQ0dBwXNO6Lk1WZjKIift6onYpmb2p7WkWxfOc3E7WGt94Y9ct5QVWF6
         JCyLPHQ+dqw1xn0Q3hYL54KFvcwtAU5LuzW6L3D7ExD9NzpHQZl824lSfaT/folsEcpW
         nBoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uuBxuiKdZN3KVCrAhLvxlGbAMwEHkyTmKhPVF6pp06o=;
        fh=n+vqUAJFHwAqQxJEX3hLO3ZhQi7iMBKnrhnClf0Vnk0=;
        b=qgebhR/oDFy7IAbPbq19h1JYJhkXVCccy6vte9ihlMuWC0uDQ4q2ENDFJzzwdyzx11
         uDlXm4qJvWcVR5v6sT3WlDPETJHEVD7epnq+QeEDjr3hSggJALWvg65+h+9udUPLy6cq
         sbvjbuvC4CqB5FVckpAQWAs026NROsy6Rqj5LUB6uOsLrm8zwynvSFff3D6v6cgFkgUu
         C+4MaIeUujd3AQvCiDrg+1xcxSFtnoub9sBrFsn8YeRylP4JNHWVBOfEx74X2zlG7kh3
         coO3Nn836MXqXD/hoPrYx1KfvNPB1FFMoqtaSTdbFPb0Ht702HL9PWBhGGMlcWMgYYZG
         nAgg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Tegbuwkl;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112f.google.com (mail-yw1-x112f.google.com. [2607:f8b0:4864:20::112f])
        by gmr-mx.google.com with ESMTPS id t13-20020a6bc30d000000b007c3f8360af9si21525iof.0.2024.02.16.09.11.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Feb 2024 09:11:28 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112f as permitted sender) client-ip=2607:f8b0:4864:20::112f;
Received: by mail-yw1-x112f.google.com with SMTP id 00721157ae682-607bfa4c913so21752367b3.3
        for <kasan-dev@googlegroups.com>; Fri, 16 Feb 2024 09:11:28 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUSEOtJXCueyKuib7VGBWjvd/21FaUlL5E//bCuxgkdQU2zUahRx5WKxrbcLUKVxpWHvJsJI/NImaAh0KHu2GiE+7kUitPV9e72CA==
X-Received: by 2002:a81:8391:0:b0:607:e1c0:450b with SMTP id
 t139-20020a818391000000b00607e1c0450bmr4624095ywf.0.1708103488010; Fri, 16
 Feb 2024 09:11:28 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-22-surenb@google.com>
 <ec0f9be2-d544-45a6-b6a9-178872b27bd4@suse.cz> <vjtuo55tzxrezoxz54zav5oxp5djngtyftkgrj2mnimf4wqq6a@hedzv4xlrgv7>
In-Reply-To: <vjtuo55tzxrezoxz54zav5oxp5djngtyftkgrj2mnimf4wqq6a@hedzv4xlrgv7>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Feb 2024 09:11:17 -0800
Message-ID: <CAJuCfpEsoC_hkhwOU8dNSe5HCFX-xiKsVivqyXbVmuEE-_F2ow@mail.gmail.com>
Subject: Re: [PATCH v3 21/35] mm/slab: add allocation accounting into slab
 allocation and free paths
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=Tegbuwkl;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112f
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

On Fri, Feb 16, 2024 at 8:39=E2=80=AFAM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Fri, Feb 16, 2024 at 05:31:11PM +0100, Vlastimil Babka wrote:
> > On 2/12/24 22:39, Suren Baghdasaryan wrote:
> > > Account slab allocations using codetag reference embedded into slabob=
j_ext.
> > >
> > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > > ---
> > >  mm/slab.h | 26 ++++++++++++++++++++++++++
> > >  mm/slub.c |  5 +++++
> > >  2 files changed, 31 insertions(+)
> > >
> > > diff --git a/mm/slab.h b/mm/slab.h
> > > index 224a4b2305fb..c4bd0d5348cb 100644
> > > --- a/mm/slab.h
> > > +++ b/mm/slab.h
> > > @@ -629,6 +629,32 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s,=
 gfp_t flags, void *p)
> > >
> > >  #endif /* CONFIG_SLAB_OBJ_EXT */
> > >
> > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > +
> > > +static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s=
, struct slab *slab,
> > > +                                   void **p, int objects)
> > > +{
> > > +   struct slabobj_ext *obj_exts;
> > > +   int i;
> > > +
> > > +   obj_exts =3D slab_obj_exts(slab);
> > > +   if (!obj_exts)
> > > +           return;
> > > +
> > > +   for (i =3D 0; i < objects; i++) {
> > > +           unsigned int off =3D obj_to_index(s, slab, p[i]);
> > > +
> > > +           alloc_tag_sub(&obj_exts[off].ref, s->size);
> > > +   }
> > > +}
> > > +
> > > +#else
> > > +
> > > +static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s=
, struct slab *slab,
> > > +                                   void **p, int objects) {}
> > > +
> > > +#endif /* CONFIG_MEM_ALLOC_PROFILING */
> >
> > You don't actually use the alloc_tagging_slab_free_hook() anywhere? I s=
ee
> > it's in the next patch, but logically should belong to this one.
>
> I don't think it makes any sense to quibble about introducing something
> in one patch that's not used until the next patch; often times, it's
> just easier to review that way.

Yeah, there were several cases where I was debating with myself which
way to split a patch (same was, as you noticed, with
prepare_slab_obj_exts_hook()). Since we already moved
prepare_slab_obj_exts_hook(), alloc_tagging_slab_free_hook() will
probably move into the same patch. I'll go over the results once more
to see if the new split makes more sense, if not will keep it here.
Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEsoC_hkhwOU8dNSe5HCFX-xiKsVivqyXbVmuEE-_F2ow%40mail.gmail.=
com.
