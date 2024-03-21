Return-Path: <kasan-dev+bncBC7OD3FKWUERB5GZ6GXQMGQEFE4Q3EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id A6EA5885F9D
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 18:23:01 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5a4e252a350sf987430eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 10:23:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711041780; cv=pass;
        d=google.com; s=arc-20160816;
        b=UOFQoHa2WG7eGulYk2/e9BS7aXW9wlghCmStc2588Qnx2MRMudT0lqghU+JulSHXqU
         rgiTNZ65O+3kb19b3wVj+d0bHR+EAc1p4dIqkp3b3Rv1J8MP0Ob8Cd9Z15bXRPb6lPW9
         CJak/vSYy1MEsliruXBiOZOPEVi0+TkIRBNfnujP9NRPpn96K8znIV3/g/23OW3MTTxy
         puXmgCuNhUyIYejnYa+k12+zKlULEsdSys3r9lvO5oPMg87l53OPoqHOpl4UoavzO7o5
         pgHzxoMUu4G8hdasUJh9dcC0Y1QpD/QMf5JcbvkRumDcT+ocNvWHgHfz0+go9Zp6GxtK
         C+gQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h+ywfAOu2ywOttPM47rPxMtu/4OZfirTNmEQ2H4F1zc=;
        fh=T8CzQ4otfDq5G4pQujdcSr3jcPFCAay7wi8FhUAa6Tc=;
        b=Or8wI2eEicG1ZRLynX77StifxeZO8vc6wJzPWcm4jmRQq2LGtoR9GYqUUcgbimhvNz
         /XzS6nNf6w8HhT4Joqpcns+Sq3VPB5Mu9BFlC+PFH8KjeDgR43w6L41NghBe74nQs9aZ
         HjVg03yshfyID/fsBp+PAH6NKqA8UiqZLZb9Y1Ur/KPGKnGJrtB9FO2IcGNH4RNad+Fk
         XTuCfBqKx+RkrmwYtXZvnokdX/slt82fjYu9QYFEpFadO8pEaIASZ9BY0QMmSSFLHLNb
         ft59zCnmZMCLfv+14oS4NuW9nSawdrM/Z/7S2kyKquJG3E0uttnTo5fGxUprqpCFVcUz
         T9FA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=N3qgNeoR;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711041780; x=1711646580; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h+ywfAOu2ywOttPM47rPxMtu/4OZfirTNmEQ2H4F1zc=;
        b=Ia6briiwX+cczJvXfFVHX78ht9Js2246pJf4diScstOEA7U1JXlONUS5bAFW0zBnb2
         KfC4hxczpkFBArDTpXo0kU/6Lc5WqnC5KDxB7sR0Nbq7lB48QOIVB7hXtAUijvZ5dGoL
         xVPz9ZRGs6sQYqYHyUvzwJ2mZZktYYw0WELLfNMy+AghuebZn+bIdH7+OXN9lLPkAUYK
         CkQsFT8L1DpbfSBhigEVoDAOfhJ2jy/EjCqh+lQoIjIN+nvjU8U3D/BFLqiciHUPt0+w
         HydXk4sOHX1tBq9UB2kYeypULo9LH5gdUTpH3Kh+R5OROxX1sD5TBjlR9ji/uNx91CL1
         FOYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711041780; x=1711646580;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=h+ywfAOu2ywOttPM47rPxMtu/4OZfirTNmEQ2H4F1zc=;
        b=TuzN71KBNwvxLxr/IjaPQdHhx3FGGarbR/foLsSdLi7Im4Es3TMHiipVSx1C5Gfu4W
         ZzoLdfhvDorvmTlB2EnlY7+qfBanVyPz47YNsIKGBU7zHYEcACcY2iHKBrznU1zcNIyn
         xkV7+hzDfbFDq8rR0QVeO9Gc+zO3wWdn1/nUJAO31sRE5WQKY1xEobpNF5dDGI2WB8W6
         uuG4Jwh8Q+7J89lUMbHM6UgIxVJeOAwYw9AabxIZ28MGSNg1XGIQf0DvTEarPDZK9ske
         72/s/EHjzxqJ0Ve5JU6XeKqou6276MnGTAWXpU2liyqFo+Y0j+WX7Q8o3okNA2xBVdBA
         TDSg==
X-Forwarded-Encrypted: i=2; AJvYcCX4q6LNfiZ4jObG460Na5tOFkFImJcaWIdCUhfSeLQ+OdBWEGsn8UPbiS1lQL5hTrPsPCz4o6cUh4aOzI3JQUBzVtR7oI/isw==
X-Gm-Message-State: AOJu0YwDECNJ+EynCxthLcSSsEr4PG+pcPoRqbdh92ki//qRt4UytPWJ
	rBg6d5ICy6UlywATjmI9kpXX7RR9kiT/L4BITm0gKXN2hAcDnDeS
X-Google-Smtp-Source: AGHT+IEFrRhofK/8rMzcxvcwZDENhaE1BKtKbzkNmwuSXLtLpKISZwzykycArgrFmZDCJzyE5vDxpA==
X-Received: by 2002:a05:6870:8193:b0:221:978d:a676 with SMTP id k19-20020a056870819300b00221978da676mr24301121oae.3.1711041780421;
        Thu, 21 Mar 2024 10:23:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1587:b0:222:5ca1:6a8b with SMTP id
 j7-20020a056870158700b002225ca16a8bls1426632oab.0.-pod-prod-02-us; Thu, 21
 Mar 2024 10:22:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUmP8Awk0ycGSx+ApnicyKF8EnOgnSN1PKpopSY7YeUY8UgK3slUktfcEHHqc75XeJB86XHmYBtIR94+AF1dCKyEqECLAkhqycSxQ==
X-Received: by 2002:a05:6870:5253:b0:220:de16:412b with SMTP id o19-20020a056870525300b00220de16412bmr26612188oai.44.1711041778640;
        Thu, 21 Mar 2024 10:22:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711041778; cv=none;
        d=google.com; s=arc-20160816;
        b=bZ4S10AtUeHAHqSX83mS0TaF0aBHWOAMel7ATccVy81rFgpQsbNcH+4OoeIEou8OD7
         xsZ1g6FRMchVP3mQeynczx06SnYyFvDZg99M/2FSs7ATklYZ10Llt8vvtnDNlUYzDQfF
         MmEK3uN6NBU/SRID/iuAxu46XCvODOsjYF1uFeFpv0q1NwcjtGNZlG7+y4Sdp2KLYA+a
         WwFDRff2D1PAlcfrw6eG9japXLGZQQlzpt3cPFfbpqqvPhW9woUKLA+vhxJ8cQ4+VFi8
         A9qZI8RfZbHlBARPCZYp9y3jpx8q0YM/ppD2Oa8iQv0sL4KCrISLaER0Ado6K89IIrrJ
         58MQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=w4sCto2weX/tSraSWS0s5CjzL8cyi2xaSDvgaVtTzPM=;
        fh=hw5u+ENTSIHa9ql4QYRDdkthDBtqECGbEjDQ9LElYjk=;
        b=DSVVM/aDbORCiRki2QAPuM4cpXRsd+gkspxJvdQEuoIFlhgYAIYQtCznQSEfjV9Jp0
         GfhaOLAClKoebkz2AEzOcJzKmx/GcwF5pqpZ6w/LT/HEZHlg8DGvTK9rK2UHRH37BGMX
         SeQc1SFtE94zhE8b0OUjSpEuYgN9HXneGd+Tl7RRjFidgD31d2ryzpRWnEiqIO0iH/Bi
         N7ofCNYQOFn5BaQTWQMUqzg5LlE4qAoOEQqAetVp7MP7z3ZxZsnuoDpdIdZHVC6AbQSb
         lwqJFpIu0vKFnOK9NwvEPXctiKvfKtKwG5bfEqvF98lvJqbAe/3A/Qh8GFlp8F39tWhq
         UjGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=N3qgNeoR;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id lh22-20020a0568700b1600b00229c91af0easi45930oab.5.2024.03.21.10.22.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 10:22:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-dcc7cdb3a98so1223582276.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 10:22:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU/pWUEego3h/XehaSuOHRyBpzPvJ+TNhXloZubm4U1ZMKbPUoxidlxoHZSk+r7g7UXws5bnyRm2jlCGbnFFFojk5nV+0QEpqtBuA==
X-Received: by 2002:a25:3607:0:b0:dcc:323e:e1a4 with SMTP id
 d7-20020a253607000000b00dcc323ee1a4mr19870609yba.6.1711041777566; Thu, 21 Mar
 2024 10:22:57 -0700 (PDT)
MIME-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com> <20240321163705.3067592-21-surenb@google.com>
 <Zfxk9aFhF7O_-T3c@casper.infradead.org> <ZfxohXDDCx-_cJYa@casper.infradead.org>
 <CAJuCfpHjfKYNyGeALZzwJ1k_AKOm_qcgKkx5zR+X6eyWmsZTLw@mail.gmail.com>
In-Reply-To: <CAJuCfpHjfKYNyGeALZzwJ1k_AKOm_qcgKkx5zR+X6eyWmsZTLw@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Mar 2024 10:22:46 -0700
Message-ID: <CAJuCfpGeep=4CqW+z4K=hXf2A6V3aWZLi_XSeEuEz1v=S7qKnw@mail.gmail.com>
Subject: Re: [PATCH v6 20/37] mm: fix non-compound multi-order memory
 accounting in __free_pages
To: Matthew Wilcox <willy@infradead.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=N3qgNeoR;       spf=pass
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

On Thu, Mar 21, 2024 at 10:19=E2=80=AFAM Suren Baghdasaryan <surenb@google.=
com> wrote:
>
> On Thu, Mar 21, 2024 at 10:04=E2=80=AFAM Matthew Wilcox <willy@infradead.=
org> wrote:
> >
> > On Thu, Mar 21, 2024 at 04:48:53PM +0000, Matthew Wilcox wrote:
> > > On Thu, Mar 21, 2024 at 09:36:42AM -0700, Suren Baghdasaryan wrote:
> > > > +++ b/mm/page_alloc.c
> > > > @@ -4700,12 +4700,15 @@ void __free_pages(struct page *page, unsign=
ed int order)
> > > >  {
> > > >     /* get PageHead before we drop reference */
> > > >     int head =3D PageHead(page);
> > > > +   struct alloc_tag *tag =3D pgalloc_tag_get(page);
> > > >
> > > >     if (put_page_testzero(page))
> > > >             free_the_page(page, order);
> > > > -   else if (!head)
> > > > +   else if (!head) {
> > > > +           pgalloc_tag_sub_pages(tag, (1 << order) - 1);
> > > >             while (order-- > 0)
> > > >                     free_the_page(page + (1 << order), order);
> > > > +   }
> > >
> > > Why do you need these new functions instead of just:
> > >
> > > +     else if (!head) {
> > > +             pgalloc_tag_sub(page, (1 << order) - 1);
> > >               while (order-- > 0)
> > >                       free_the_page(page + (1 << order), order);
> > > +     }
> >
> > Actually, I'm not sure this is safe (I don't fully understand codetags,
> > so it may be safe).  What can happen is that the put_page() can come in
> > before the pgalloc_tag_sub(), and then that page can be allocated again=
.
> > Will that cause confusion?

I indirectly answered your question in the reason #2 but to be clear,
we obtain codetag before we do put_page() here, therefore it's valid.
If another page is allocated and it points to the same codetag, then
it will operate on the same codetag per-cpu counters and that should
not be a problem.

>
> So, there are two reasons I unfortunately can't reuse pgalloc_tag_sub():
>
> 1. We need to subtract `bytes` counter from the codetag but not the
> `calls` counter, otherwise the final accounting will be incorrect.
> This is because we effectively allocated multiple pages with one call
> but freeing them with separate calls here. pgalloc_tag_sub_pages()
> subtracts bytes but keeps calls counter the same. I mentioned this in
> here: https://lore.kernel.org/all/CAJuCfpEgh1OiYNE_uKG-BqW2x97sOL9+AaTX4J=
ct3=3DWHzAv+kg@mail.gmail.com/
> 2. The codetag object itself is stable, it's created at build time.
> The exception is when we unload modules and the codetag section gets
> freed but during module unloading we check that all module codetags
> are not referenced anymore and we prevent unloading this section if
> any of them are still referenced (should not normally happen). That
> said, the reference to the codetag (in this case from the page_ext)
> might change from under us and we have to make sure it's valid. We
> ensure that here by getting the codetag itself with pgalloc_tag_get()
> *before* calling put_page_testzero(), which ensures its stability.
>
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGeep%3D4CqW%2Bz4K%3DhXf2A6V3aWZLi_XSeEuEz1v%3DS7qKnw%40mai=
l.gmail.com.
