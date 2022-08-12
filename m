Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5FS3CLQMGQEVPYTFEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id B1547590DE9
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Aug 2022 11:12:21 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id n13-20020a056e02140d00b002dfa5464967sf201308ilo.19
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Aug 2022 02:12:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660295540; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mdn8jPy+gFtuBzXgvfSTFKM0BcjniHwOxFdWsA6w3xGapZT5ZA77Rv1HOTkd6gBCDU
         djzNdXelhJTM3MlMpLtd2VPd7dbLtyxIfR/aOEal8AyNl3o71tBa+Q+CqnaDHWJFC6hw
         Ajw6lPNG8SPqv8CkcYlM0Nvp1j2vyNReaubzSqzg+K0nAhVCeFkBPIU9J0bM8GgCoUjA
         zGlK6DOimBA+bhQpcXoxzhHwYNswty0eDHG6E7Y7zT6dRikMKf+k04tUxyIScLZUnsj/
         AUgrJpd65MKz7AFwBCLKjikWWJMPxrDQ3ZPO9+PVqWaSceUrP89D2QLdLP9RYIq+ksYf
         Ze+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Y6mTH1Ke0bZZ2SMmLZ1FRqkvbm8GRwmGbfTunvgtRyw=;
        b=KPE/mBGmGdMgmVbdHtcFKXrLI5PX7U5iMjBq9whmsh2uC/EXgv5YZHGhWT5jQz/eIX
         bWrjSuapnuxf8HM90J0gi1/5FaYdMr7enRY0UzoZyFiB4VmLlO2W5RyFo57wPiaz0wOF
         dsbrHI/K6GmPEjzr14Hr0eMy04pkPVEvt88Z3WfPv2jb0Eq4qFQPo0rN4hQfxLqhirZK
         Z96wcys6OGqzxoFppNOlOpYzPEj42xT6nyIyJ+gxFk7zjQ50fYNYOQTM4CBazAkFN0Xl
         BT+oJtiz/W4yWwZEFudNuMvPObQhd+EsLOayds+xY0wAxgjBcDjDPKF94SrYW5B9xGp2
         FgBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DfJqfQf1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=Y6mTH1Ke0bZZ2SMmLZ1FRqkvbm8GRwmGbfTunvgtRyw=;
        b=HHYJSO1Ih0rED7cUAxPza0mhvPvadQTpkZr6C4snRJuhPtTrWFgqkjW6wyilpzdhOt
         ibBr7rabKTL1153SPPjUjQGqxCzTQb5uYbuOXUbX0Uh8MyqfiiX32eY/TNNmdEP5vq3i
         3Cznw8rj8piOr7KUI57cg8CRpqbkaGD6cn6uR9DedQvFMxyUatVFrXgSPxzarO4057Iu
         zlfGP/qOJrSyYKkO7xgJwHK5L1k1J0stjNq6uX3M3SaLs6TjTIMVVmIFjexL0R5aZK96
         go9naBTYnGoy/0fGZN+yVO6o/Oz4TomT4ox/Yisc02orGQtmbYlRBZjNYe8149tCbjJj
         +Z/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=Y6mTH1Ke0bZZ2SMmLZ1FRqkvbm8GRwmGbfTunvgtRyw=;
        b=RIw1oTYz59Ej4IeU6IKvZsvTCsBnuzZu9ZqIgC8gqh7OosM3evDk/Sr81NAv1/MCAg
         sLExwJU4VViTKN5mc+mrYAAE6+Tik8fzR3pa3XVqwghx4JKtCHoEp7n1bTtiEZYLMMOQ
         gMRU0nSVrsaJ7XmuEg/h4zc+dVVyLlapgnQeAcO7oMp5sKK7wHbmuqhEdDPc5DNz0dMG
         AUBQkwNTRtHRcBXWKFz1PQLvxHNETC2Hq2ZbDPZmtluZDaYVWKTP0jv9AKNPrn/riyRb
         SecxYzYFNj/Aylpq+NAbRntG1hEytGwQ+vIesq7X3o9dNPHCV42F9/HYZgq+CaIOoc1P
         Rm0Q==
X-Gm-Message-State: ACgBeo12fBgttdCBc+0f9q3ZP+d9fqnPvblb2OQ+/Qr4uyi2mfglBq9X
	4yNK1UfbraZH5RnROg6HzCk=
X-Google-Smtp-Source: AA6agR4sHmNq7Oa8MxK+VTgHljOjciJ4UihfN9NZr4IHI6f1AuKPsbtLuV5CQ97lNXKwjfatorIb8A==
X-Received: by 2002:a05:6e02:174d:b0:2de:5a82:eaa9 with SMTP id y13-20020a056e02174d00b002de5a82eaa9mr1396921ill.241.1660295540434;
        Fri, 12 Aug 2022 02:12:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:95e9:0:b0:343:44a5:a2d1 with SMTP id b96-20020a0295e9000000b0034344a5a2d1ls995780jai.0.-pod-prod-gmail;
 Fri, 12 Aug 2022 02:12:20 -0700 (PDT)
X-Received: by 2002:a05:6638:2109:b0:343:59d7:3815 with SMTP id n9-20020a056638210900b0034359d73815mr1616174jaj.116.1660295539905;
        Fri, 12 Aug 2022 02:12:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660295539; cv=none;
        d=google.com; s=arc-20160816;
        b=G+1lKsG/nCn8zGiD3d0cvATnL0DnNVWu+WuXvk61jVMBK7XYmD0OML0bHVZwyRO4vj
         6JFlDAN0Gx67e+FcGVME/F16/cvazQdgV1yQwKnPKFfFLU5yHapDTzHm0myiTQI+CeOr
         VtPGwtWY8NfmfTkkyZk10EKi/rSn3oh2Y/Do6aa4AYvkszWDFHHskcXM5F0l2XnGzsqe
         FF9kObNjH/S5i8sURJiNBfQ1zqg4YJLF1PmECz0lxhOn/vgH/9hJgCpY2C3HsFUyT/y5
         t/+ah15VlRVPSwBIeDMmAb6q4GfCv2F3TqKTug0cFv+NfHUp52GCMntaQE8gFk7qTBJv
         MLhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=45DlX2m161o/Gwf6jjpL+rTtdDNcNUjOyYHwEltA6sE=;
        b=gPSXM136LEEU4+vgVXo+RL6FA+XomWScDj0k+4V0/UxDc88xQlsod4EgYMmeJPpm/C
         /ok71bigW9jILW9PbjiBG8cNMYHk0/MxE5jS3UMShKcUzDQwhtysrd1uMgfEw8MeYN9X
         uE80YohNJl0HPfJw9cvRADiDXGDqAPIMBJbReGlkI1hll4PRm6hJezYafHa6a7QI+12W
         5lwx5BlnRndudApYhC6KeG+Z7Xmr/jgeQLI4Qv/uSyqjxJjzCRbt4nQgqKRyxccQhKe8
         tsC+KLIKmX2WJkZ9EsxIYZKJYQAmnWxxYoLD8TnbIdQ+Xyy8hNVSVrfz2hXQPhqEyfo4
         VYTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DfJqfQf1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id j13-20020a6b780d000000b00684fb05008dsi63143iom.0.2022.08.12.02.12.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Aug 2022 02:12:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 204so587716yba.1
        for <kasan-dev@googlegroups.com>; Fri, 12 Aug 2022 02:12:19 -0700 (PDT)
X-Received: by 2002:a25:ad16:0:b0:671:75d9:6aad with SMTP id
 y22-20020a25ad16000000b0067175d96aadmr2562613ybi.143.1660295539457; Fri, 12
 Aug 2022 02:12:19 -0700 (PDT)
MIME-Version: 1.0
References: <20220811085938.2506536-1-imran.f.khan@oracle.com>
 <d3cd0f34-b30b-9a1d-8715-439ffb818539@suse.cz> <CANpmjNMYwxbkOc+LxLfZ--163yfXpQj69oOfEFkSwq7JZurbdA@mail.gmail.com>
 <6b41bb2c-6305-2bf4-1949-84ba08fdbd72@suse.cz> <CANpmjNNC3F88_Jr24DuFyubvQR2Huz6i3BGXgDgi5o_Gs0Znmg@mail.gmail.com>
 <26acafb0-9528-9b29-0b5d-738890853fca@oracle.com>
In-Reply-To: <26acafb0-9528-9b29-0b5d-738890853fca@oracle.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Aug 2022 11:11:43 +0200
Message-ID: <CANpmjNOCFqHdNUQQJ_zzug06Miwqg6kQpCqM0ckhy6jXzX-bLQ@mail.gmail.com>
Subject: Re: [PATCH v2] Introduce sysfs interface to disable kfence for
 selected slabs.
To: Imran Khan <imran.f.khan@oracle.com>
Cc: vbabka@suse.cz, glider@google.com, dvyukov@google.com, cl@linux.com, 
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com, 
	akpm@linux-foundation.org, roman.gushchin@linux.dev, 42.hyeyoo@gmail.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DfJqfQf1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 11 Aug 2022 at 17:10, Imran Khan <imran.f.khan@oracle.com> wrote:
>
> Hello Marco,
>
> On 11/8/22 11:21 pm, Marco Elver wrote:
> > On Thu, 11 Aug 2022 at 12:07, <vbabka@suse.cz> wrote:
> > [...]
> >>> new flag SLAB_SKIP_KFENCE, it also can serve a dual purpose, where
> >>> someone might want to explicitly opt out by default and pass it to
> >>> kmem_cache_create() (for whatever reason; not that we'd encourage
> >>> that).
> >>
> >> Right, not be able to do that would be a downside (although it should be
> >> possible even with opt-in to add an opt-out cache flag that would just make
> >> sure the opt-in flag is not set even if eligible by global defaults).
> >
> > True, but I'd avoid all this unnecessary complexity if possible.
> >
> >>> I feel that the real use cases for selectively enabling caches for
> >>> KFENCE are very narrow, and a design that introduces lots of
> >>> complexity elsewhere, just to support this feature cannot be justified
> >>> (which is why I suggested the simpler design here back in
> >>> https://urldefense.com/v3/__https://lore.kernel.org/lkml/CANpmjNNmD9z7oRqSaP72m90kWL7jYH*cxNAZEGpJP8oLrDV-vw@mail.gmail.com/__;Kw!!ACWV5N9M2RV99hQ!Oh4PBJ1NoN9mEgqGqdaNcWuKtJiC6TS_rIbALuqZadQoo93jpVJaFFmXUpOTuzRUdCwcRJWE6uJ4pe0$
> >>> )
> >>
> >> I don't mind strongly either way, just a suggestion to consider.
> >
> > While switching the semantics of the flag from opt-out to opt-in is
> > just as valid, I'm more comfortable with the opt-out flag: the rest of
> > the logic can stay the same, and we're aware of the fact that changing
> > cache coverage by KFENCE shouldn't be something that needs to be done
> > manually.
> >
> > My main point is that opting out or in to only a few select caches
> > should be a rarely used feature, and accordingly it should be as
> > simple as possible. Honestly, I still don't quite see the point of it,
> > and my solution would be to just increase the KFENCE pool, increase
> > sample rate, or decrease the "skip covered threshold%". But in the
> > case described by Imran, perhaps a running machine is having trouble
> > and limiting the caches to be analyzed by KFENCE might be worthwhile
> > if a more aggressive configuration doesn't yield anything (and then
> > there's of course KASAN, but I recognize it's not always possible to
> > switch kernel and run the same workload with it).
> >
> > The use case for the proposed change is definitely when an admin or
> > kernel dev is starting to debug a problem. KFENCE wasn't designed for
> > that (vs. deployment at scale, discovery of bugs). As such I'm having
> > a hard time admitting how useful this feature will really be, but
> > given the current implementation is simple, having it might actually
> > help a few people.
> >
> > Imran, just to make sure my assumptions here are right, have you had
> > success debugging an issue in this way? Can you elaborate on what
> > "certain debugging scenarios" you mean (admin debugging something, or
> > a kernel dev, production fleet, or test machine)?
> >
>
> I have not used kfence in this way because as of now we don't have such newer
> kernels in production fleet but I can cite a couple of instances where using
> slub_debug for few selected slabs helped me in locating the issue on a
> production system where KASAN or even full slub_debug were not feasible.
> Apologies in advance if I am elaborating more than you asked for :).

This is very useful to understand the use case.

> In one case a freed struct mutex was being used later on and by that time same
> address had been given to a kmalloc-32 object. The issue was appearing more
> frequently if one would enforce some cgroup memory limitation resulting in fork
> of a task exiting prematurely. From the vmcore we could see that mutex or more
> specifically task_struct.futex_exit_mutex was in bad shape and eventually using
> slub_debug for kmalloc-32 pointed to issue.
>
> Another case involved a mem_cgroup corruption which was causing system crash but
> was giving list corruption warnings beforehand. Since list corruption warnings
> were coming from cgroup subsystem, corresponding objects were in doubt.
> Enabling slub_debug for kmalloc-4k helped in locating the actual corruption.
>
> Admittedly both of the above issues were result of backporting mistakes but
> nonetheless they happened in production systems where very few debugging options
> were available.
>
> By "certain debugging scenarios" I meant such cases where some initial data
> (from production fleet) like vmcore or kernel debug messages can give some
> pointer towards which slab objects could be wrong and then we would use this
> feature (along with further tuning like increasing sampling frequency, pool size
> if needed/possible) to pinpoint the actual issue. The idea is that limiting
> KFENCE to few slabs will increase the probablity of catching the issue even if
> we are not able to tweak pool size.
>
> Please let me know if it sounds reasonable or if I missed something from your
> query.

Thanks for the elaboration on use cases - agreed that in few scenarios
this feature can help increase the probability of debugging an issue.

Reviewed-by: Marco Elver <elver@google.com>

With minor suggestions:

> +SLAB_ATTR(skip_kfence);
> +

^ Unnecessary space between SLAB_ATTR and #endif.

> +#endif
> +

And the patch title should be something like "kfence: add sysfs
interface to disable kfence for selected slabs" (to follow format
"<subsys>: <thing changed>").

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOCFqHdNUQQJ_zzug06Miwqg6kQpCqM0ckhy6jXzX-bLQ%40mail.gmail.com.
