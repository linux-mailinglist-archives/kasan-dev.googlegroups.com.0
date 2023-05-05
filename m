Return-Path: <kasan-dev+bncBC7OD3FKWUERBGMN2WRAMGQEJY74IWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id E2B606F8872
	for <lists+kasan-dev@lfdr.de>; Fri,  5 May 2023 20:10:35 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-517bfcfe83fsf906442a12.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 May 2023 11:10:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683310234; cv=pass;
        d=google.com; s=arc-20160816;
        b=uoZFbOYwKZX9nS67UDKvIVkwlwH1+cdf8ajCq+nXjmu9V3P9xukLqSFwPzysrjteCM
         iZTj/Cf8v2uRWnVCBlKlpBwtzDnayhygFX3c6DyrQAJrxB3pP+7MH4l0GiIKHsaeDO+S
         rP8cabr9hyPqMecaUfbh5L0yyjqWc/jVWwI0/z0G+5pOAfFd/SpE0E5XSnFTRaKny4yg
         secMgrRsdRqEFFFbDfL8u0kkjK7Iu3M7w7vwGGp4e/IgCH3NzacYL2vI0HRC8tkZMFQz
         OOeXQQsWactZALc2Rc6DP8ghTlrZjIX9i5e54N9QVncxK5cnbkOORPh19qARRH+SaNKJ
         OcbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=l0impMfI7BmQyhMIoBnZ7ZzMKh1L4vPrYoLJ3EjyXL0=;
        b=S4u2LLQkKCOHtbE6hKXJxGoGgFg2cLtPZru1zqMkBFrdIZFM1zNtZ4XVyNO120tvqh
         Jw/pexY4iOMEQeLhmR2QbAcTFcjE5DvJFCm80POBM5kV9NZXLv+Kg9ia973epmAwKEcK
         vdjW5MJ6pirfoQIsZFm7hev//RuR/RKLr/KS+O6kzJ1CHuieo6W3PW/GjECOCtigkjdJ
         UzRzOsJGu7JLGhulgkNhPT/iPDPXrjnM7fVxXLeBCl4Z6wWCBXnWFAEcyLexLTiLL9dk
         sH7ChIbDrpT1Gz63YPx8V0xexbTqN/rY4iqqKojxxGLXFW3dvvbaGSsjGfDlIaCOA2gL
         KRKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="JuehaV/R";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683310234; x=1685902234;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l0impMfI7BmQyhMIoBnZ7ZzMKh1L4vPrYoLJ3EjyXL0=;
        b=sXwjWmBGUjmN057DBlrOklujz2lPC9Xq8FPJ3rAP+OSlDs+dTsflZ2vqMQycTAj+Fp
         fTDufHCM+N2kYdxxspU0weIJXKTAGvnyZ0+I7XgtEPuil2D59PCPlzgnfikw9Glf7p2W
         HqIUsUSsIK5jEcoxBfazdNptUBpBfMN+PVWk95Acpl+gwnFocYPmpHv8/C38UHLyCoVm
         VP/wtfbF6nugs5KxxudWV37glW2N1irsgU+yTVcYXSTiTLws51EXFlPXV89MYCqzBSwU
         BHU1b9fJCfrQ9EwBxm5XU8UmaSrBV4NL3rkMUXwB/idvPyin8SIlFvOWhbuyGIEHtS7r
         APIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683310234; x=1685902234;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=l0impMfI7BmQyhMIoBnZ7ZzMKh1L4vPrYoLJ3EjyXL0=;
        b=MHRSJqrW0rvw2IlmtObNV93g6AJouou6qBRrQ29EnvXsaygin86kx12ubNF1PRUyAH
         EUN4gD2s5AMGnRZ6s6wvzpvR3tQ7Yp3xBcguSDLKf2qcxdi9RMTMfzlEti6J8dz/2SLh
         SJP7guybuqtdGUmlfGB2aRPUfNMysd6t1etnq4DRH1HEMhD6PjF6l88WUo56E3TMtOui
         X9HWX0Dz44XGXZNaoC3bS/04+C8SdW18zC/+bS2Qv31dVAsKs97uGB6aIjjJMi58u8MW
         AFPmunsH0lS8MP+YHRePMYNmHUeyaxj1oy0Ef+IZAciEOzwokctEBGT/CAOD3nDbRwYB
         Xffw==
X-Gm-Message-State: AC+VfDxUIvwDQrWUVeHjlrx1mRmk1nAImVrODrexuxoSXE7PepZgQ3LP
	a2Oww18CGJ//a6qiNAolQ9E=
X-Google-Smtp-Source: ACHHUZ4OXYUseoXTjaQAofM/ZDQdZsZoGHzI1ViGeyCF0wdEPYx+Q/LmlIl+i+vUe4xpwT08+8X15w==
X-Received: by 2002:a63:6945:0:b0:52c:6489:dc95 with SMTP id e66-20020a636945000000b0052c6489dc95mr526517pgc.12.1683310233893;
        Fri, 05 May 2023 11:10:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d886:b0:1a1:a83b:2ab with SMTP id
 b6-20020a170902d88600b001a1a83b02abls19238832plz.7.-pod-prod-gmail; Fri, 05
 May 2023 11:10:32 -0700 (PDT)
X-Received: by 2002:a17:90b:1997:b0:250:2337:9b96 with SMTP id mv23-20020a17090b199700b0025023379b96mr2360203pjb.9.1683310232862;
        Fri, 05 May 2023 11:10:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683310232; cv=none;
        d=google.com; s=arc-20160816;
        b=pPMB1ns7ecaA2ODs7DrJnG5v0RBPK6Rmp6IfZUqwPde47YDdLUb2eN7D5VdJpCwojC
         7N20qSykL4fjCRTa41+tnJuAq261Y8Ll2qk0RVv7PfP3QrCm2kRlAP5KIHGKeKm2oQu4
         ZREz+W3Z5s542Fe1eA+x85ON3XpK4CV4eggiutkhuWSljlfw7wbZgSrNGPs/yaX/UEOV
         Q3+SUo2TmYqxFx6xTs9GAzqWhopz+obth+BRucR/NhKoOWDqF5nMFN01wP4vAbAodn15
         tyrG6nbIUbDuKeEYLJRtdiJa73E/IKnF9+B1SG1qnVTJgkiqKBjnqrex6vlZjmsjrm4j
         cDCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QVZYG1JecNO86jzNV6C/AMNw6VQt+fJvqwCxq5mp/Nc=;
        b=JqqTHqdNoHem6aAOxBLxvugFWS2zpcHeqkWO/I+IPRegz0bXhT0c6xkJWlCnNXgDoM
         7QmJcJdXBqaSOhCpJtZxQWwTVaFxATLNIP7u6W9kzAkwA/WjJ856o2KVdrI/TZRO0Sun
         IN4VUd62aqbHMXDxhOYzKi4tntkoULeOnnfzVuRTs7qyXT/h5+GgEvcOcb6lcPGtO2O5
         xo2fFJY0KoSOFIlhcWjfVApp9SbLGHv/Al0o/k9KVU+X0dQyYZ8SoYZ5sYx5h7esHoNT
         2TEFYqr+CwSoxmuqhuJz5YQ0hxn7K5L2pEipccc2w68Og658spUC8oHx3TNDdzvh0IIc
         yFlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="JuehaV/R";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id pl10-20020a17090b268a00b00246fa2ea350si354668pjb.1.2023.05.05.11.10.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 May 2023 11:10:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id 3f1490d57ef6-b9ef06cb784so2755440276.0
        for <kasan-dev@googlegroups.com>; Fri, 05 May 2023 11:10:32 -0700 (PDT)
X-Received: by 2002:a25:19d7:0:b0:b97:1e2e:a4e5 with SMTP id
 206-20020a2519d7000000b00b971e2ea4e5mr2351347ybz.40.1683310231779; Fri, 05
 May 2023 11:10:31 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-36-surenb@google.com>
 <ZFIPmnrSIdJ5yusM@dhcp22.suse.cz> <CAJuCfpGsvWupMbasqvwcMYsOOPxTQqi1ed5+=vyu-yoPQwwybg@mail.gmail.com>
 <ZFNoVfb+1W4NAh74@dhcp22.suse.cz> <CAJuCfpGUtw6cbjLsksGJKATZfTV0FEYRXwXT0pZV83XqQydBgg@mail.gmail.com>
 <ZFTA8xVzxWc345Ug@dhcp22.suse.cz>
In-Reply-To: <ZFTA8xVzxWc345Ug@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 May 2023 11:10:20 -0700
Message-ID: <CAJuCfpFOLyZKvtqHuukOZvegxGHVUcAtbh3Egt+01yZ9kcEAew@mail.gmail.com>
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
 header.i=@google.com header.s=20221208 header.b="JuehaV/R";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as
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

On Fri, May 5, 2023 at 1:40=E2=80=AFAM Michal Hocko <mhocko@suse.com> wrote=
:
>
> On Thu 04-05-23 09:22:07, Suren Baghdasaryan wrote:
> [...]
> > > But even then I really detest an additional allocation from this cont=
ext
> > > for every single allocation request. There GFP_NOWAIT allocation for
> > > steckdepot but that is at least cached and generally not allocating.
> > > This will allocate for every single allocation.
> >
> > A small correction here. alloc_tag_create_ctx() is used only for
> > allocations which we requested to capture the context. So, this last
> > sentence is true for allocations we specifically marked to capture the
> > context, not in general.
>
> Ohh, right. I have misunderstood that part. Slightly better, still
> potentially a scalability issue because hard to debug memory leaks
> usually use a generic caches (for kmalloc). So this might be still a lot
> of objects to track.

Yes, generally speaking, if a single code location is allocating very
frequently then enabling context capture for it will generate many
callstack buffers.

Your note about use of generic caches makes me think we still have a
small misunderstanding. We tag at the allocation call site, not based
on which cache is used. Two kmalloc calls from different code
locations will have unique codetags for each, so enabling context
capture for one would not result in context capturing for the other
one.

>
> > > There must be a better way.
> >
> > Yeah, agree, it would be good to avoid allocations in this path. Any
> > specific ideas on how to improve this? Pooling/caching perhaps? I
> > think kmem_cache does some of that already but maybe something else?
>
> The best I can come up with is a preallocated hash table to store
> references to stack depots with some additional data associated. The
> memory overhead could be still quite big but the hash tables could be
> resized lazily.

Ok, that seems like the continuation of you suggestion in another
thread to combine identical callstack traces. That's an excellent
idea! I think it would not be hard to implement. Thanks!

> --
> Michal Hocko
> SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFOLyZKvtqHuukOZvegxGHVUcAtbh3Egt%2B01yZ9kcEAew%40mail.gmai=
l.com.
