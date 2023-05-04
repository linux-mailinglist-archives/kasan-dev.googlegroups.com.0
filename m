Return-Path: <kasan-dev+bncBCKMR55PYIGBBTPLZWRAMGQE75ZZBFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A1B66F67F1
	for <lists+kasan-dev@lfdr.de>; Thu,  4 May 2023 11:07:26 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-509f56de80fsf207768a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 May 2023 02:07:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683191245; cv=pass;
        d=google.com; s=arc-20160816;
        b=KXr6+bAI3qHuMOi7VuzlmHajrLdPW9l8+5RtFJQ0p7k+VX1hwn7vJ5RSHHIaJqZoEh
         5IKXGVA6CXwXhOFgogovMoDRWHA6TltVEDBKrhK7Hz+pxPsVpXN9Yg7DMurZ9h+8Sbzx
         XmgQHgbS1lAbXYVXOhuvOb50Fwl2S1up8ZHsGowBg6vZMLfqYYTuKE7yuUjddNKgffpy
         q6KgyPHNxqcl5zjbmvoXgXaszntt5yOuEGfXKrf86JhERNr+JOmUfauLZW2dPFT723zK
         EQfti0UAvJX0nPTDLc0dSvdGIZW8MIklUus5lq8th4CDoPyjN9l/FfSnqEFMYr5VoYHp
         dc4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=jVvYszgpwN4h5kz7SJl8cRGeD6Zz/S976EbzWa25ee4=;
        b=iBhPRIHg/jTEJmeB6YiUugd9V85NMZL5pQc5SYPVxD+Zrv45WztuU89ofnLfcuNB/X
         NNxNqz1gwUAEQQxNOEg5MSTnwhIUN5fTg1CTS8OnB7nchur0XlphdLjYCCTV+e9fV5hD
         PNV8Wevnqv07c7rVopMXENBMSCnvqGcE3ZUj0oY1R3MfGuNbbkS3jg9D7yeECiv7levo
         C1+/7uItdQIMzSRI640OEDL+KxGf94VFvJ8SmT36h/Oa0RZW77FgjWQlwCgG5mR2vac/
         sRRPAqf5rIJjgEKFU0f/U4fwcxA/L/H+lu2YXcgOrMO6jliv7l0DJEMUSu/0wbrJP83d
         nUZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=ANDPuuGS;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683191245; x=1685783245;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=jVvYszgpwN4h5kz7SJl8cRGeD6Zz/S976EbzWa25ee4=;
        b=j/Mu/VXlrqTiKRQS0JH1nj3uKgdS8QiM2Zd9M29gMa3krXF+/+TJR49uKK39CgMlWT
         bxLhhUgi+FO47lf/ea9W/7lzqv6TZvmFrLN0JC1DyLn4GsiCPr8KEHRhgCUj1AdY5jqz
         YdT+3Dn67sGaPVj8l/PkT2aBhQXRIBzjIapHn7My6c+q5SrVte/4m5xmsqNi5VIhrO95
         EXIqObHdsb64SY4t3H7EQJVSRFIu8lBlier624NwBvCZ0u9dH6Ug1AT4n1LFAVL+TpAZ
         6G5gMEAtNzi+HXFMdz2wbqd71E+qY7dBNqQxiCRbR0FUv7AF2DtD0ko9BD2GgYBjpmhz
         PoEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683191245; x=1685783245;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=jVvYszgpwN4h5kz7SJl8cRGeD6Zz/S976EbzWa25ee4=;
        b=SrI1JifzKXhVUm62wagnywY2Qs/ysAGKbv7S7oMPOx3d6qTQJ4srhWxOkVPKSy64wB
         iG79IUTaEPBgFTSt9wH0rsMMfIPOn52qvYhUbI5NLecXUcWuNNB2gRRuKGFdkF6d9i4d
         /P4WPwD8QKz4dcaDZbOJWPsEv/eKC2JqroFoF3Q7U6Vs/K4OP/YOYmRmMDA8gdY1Vot+
         lBjpNy5VtdOsRRHiBD3y8A4aGBPEokrOPuOqoJzb7tEN0qx5TD3NPNDnwCY1YIq1Q4EZ
         Kk+cyO1HkIamAVZne1jOPs8P6GEOQihY0gmlhM2PEhZKS++o/MvFLUQK8Qa29cuHCyJ1
         SGhA==
X-Gm-Message-State: AC+VfDyLxBcOl0duNjXDpbiC463GP1wu6QNV+P8YIiuAB9fSXusgK7GK
	G7for+S7jS74uTcbtlI31Js=
X-Google-Smtp-Source: ACHHUZ5Ik7d0GDukRa9AQQb9nxJP1AEAdYxSYxPVVBkVv0MzUWbu6cpeOfDaBXJrUvWVKlsgZlJSHw==
X-Received: by 2002:a50:8d08:0:b0:50b:c733:51a4 with SMTP id s8-20020a508d08000000b0050bc73351a4mr426154eds.7.1683191245560;
        Thu, 04 May 2023 02:07:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:120e:b0:50b:d30b:de2b with SMTP id
 c14-20020a056402120e00b0050bd30bde2bls193789edw.1.-pod-prod-03-eu; Thu, 04
 May 2023 02:07:24 -0700 (PDT)
X-Received: by 2002:a05:6402:1050:b0:504:b511:1a39 with SMTP id e16-20020a056402105000b00504b5111a39mr727543edu.12.1683191244084;
        Thu, 04 May 2023 02:07:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683191244; cv=none;
        d=google.com; s=arc-20160816;
        b=jN+twHug/lPGNKCj0m55/X7L0s8xTLEx3O52bVLfhyB64NnS3bZDpjNNnKq5MiE1EE
         1EX/3L6lCLSdx+3JdnhStbaBHKPVnL6flfGvEfHi/WjZbdbg2vWpicETLO1QakPBA45k
         XkN2ShP++4w7jQFcDSoBcr1CFbZN67fhPEfSV5+cD8mWm4QrOGn4PuYLg6Ni/9NM2IQs
         qipuf/JcwAULlrBnCzFqP0A1PODjnM0xCPeWbZcF72skm3de7k6v96u4g8NjQQPitlGV
         OzcBpFcGj3iIKr00CY9u6YkEUO24oDMjBMiWyo1z1M56s67yNWkOqoXzhe+GDK0vZOFt
         ZFbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=+qJXmRqw+FfGzaNlkZLDu9Le9CEnkyHeMqv8Le5oQts=;
        b=X0VsRlqf3hYPAfIIdsOiV38vgd6kDwmRMsmoqPM9B/N4ltY7MAz9zZr3Z4Dhl4b2wS
         r+vsGPhXL46ZDCqS6yk0KP38QKGUmMbDzsiJvuOekIbd7Y/TTASqIL59RO0TPhNnigZo
         bhDUBFiCTuaLvTgwhRs+G1k2/KavrLEm4Ft13QgL3ZA6t6accaD1QGtEUsIx5/uscgpU
         M21upwBhuhcGS4cLD7Lfo/YpVUeA1foLZXcfVNCOVs4AXQKYjGoK/VL7Kk65tR+Wd3ev
         DA69tUW9e0N3Kvcm/iBdLqYuhDcLHp22Y9Km81LccTFunhIObozBhRCLHWI1ofY0Y1xz
         SsXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=ANDPuuGS;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id g34-20020a056402322200b00506956b72a8si220205eda.2.2023.05.04.02.07.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 May 2023 02:07:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 99D5D33924;
	Thu,  4 May 2023 09:07:23 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 6EB8613444;
	Thu,  4 May 2023 09:07:23 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id zaOgGst1U2SVTAAAMHmgww
	(envelope-from <mhocko@suse.com>); Thu, 04 May 2023 09:07:23 +0000
Date: Thu, 4 May 2023 11:07:22 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=ANDPuuGS;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted
 sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Wed 03-05-23 08:09:28, Suren Baghdasaryan wrote:
> On Wed, May 3, 2023 at 12:25=E2=80=AFAM Michal Hocko <mhocko@suse.com> wr=
ote:
[...]
> Thanks for summarizing!
>=20
> > At least those I find the most important:
> > - This is a big change and it adds a significant maintenance burden
> >   because each allocation entry point needs to be handled specifically.
> >   The cost will grow with the intended coverage especially there when
> >   allocation is hidden in a library code.
>=20
> Do you mean with more allocations in the codebase more codetags will
> be generated? Is that the concern?

No. I am mostly concerned about the _maintenance_ overhead. For the
bare tracking (without profiling and thus stack traces) only those
allocations that are directly inlined into the consumer are really
of any use. That increases the code impact of the tracing because any
relevant allocation location has to go through the micro surgery.=20

e.g. is it really interesting to know that there is a likely memory
leak in seq_file proper doing and allocation? No as it is the specific
implementation using seq_file that is leaking most likely. There are
other examples like that See?

> Or maybe as you commented in
> another patch that context capturing feature does not limit how many
> stacks will be captured?

That is a memory overhead which can be really huge and it would be nice
to be more explicit about that in the cover letter. It is a downside for
sure but not something that has a code maintenance impact and it is an
opt-in so it can be enabled only when necessary.

Quite honestly, though, the more I look into context capturing part it
seems to me that there is much more to be reconsidered there and if you
really want to move forward with the code tagging part then you should
drop that for now. It would make the whole series smaller and easier to
digest.

> > - It has been brought up that this is duplicating functionality already
> >   available via existing tracing infrastructure. You should make it ver=
y
> >   clear why that is not suitable for the job
>=20
> I experimented with using tracing with _RET_IP_ to implement this
> accounting. The major issue is the _RET_IP_ to codetag lookup runtime
> overhead which is orders of magnitude higher than proposed code
> tagging approach. With code tagging proposal, that link is resolved at
> compile time. Since we want this mechanism deployed in production, we
> want to keep the overhead to the absolute minimum.
> You asked me before how much overhead would be tolerable and the
> answer will always be "as small as possible". This is especially true
> for slab allocators which are ridiculously fast and regressing them
> would be very noticable (due to the frequent use).

It would have been more convincing if you had some numbers at hands.
E.g. this is a typical workload we are dealing with. With the compile
time tags we are able to learn this with that much of cost. With a dynamic
tracing we are able to learn this much with that cost. See? As small as
possible is a rather vague term that different people will have a very
different idea about.

> There is another issue, which I think can be solved in a smart way but
> will either affect performance or would require more memory. With the
> tracing approach we don't know beforehand how many individual
> allocation sites exist, so we have to allocate code tags (or similar
> structures for counting) at runtime vs compile time. We can be smart
> about it and allocate in batches or even preallocate more than we need
> beforehand but, as I said, it will require some kind of compromise.

I have tried our usual distribution config (only vmlinux without modules
so the real impact will be larger as we build a lot of stuff into
modules) just to get an idea:
   text    data     bss     dec     hex filename
28755345        17040322        19845124        65640791        3e99957 vml=
inux.before
28867168        17571838        19386372        65825378        3ec6a62 vml=
inux.after

Less than 1% for text 3% for data.  This is not all that terrible
for an initial submission and a more dynamic approach could be added
later. E.g. with a smaller pre-allocated hash table that could be
expanded lazily. Anyway not something I would be losing sleep over. This
can always be improved later on.

> I understand that code tagging creates additional maintenance burdens
> but I hope it also produces enough benefits that people will want
> this. The cost is also hopefully amortized when additional
> applications like the ones we presented in RFC [1] are built using the
> same framework.

TBH I am much more concerned about the maintenance burden on the MM side
than the actual code tagging itslef which is much more self contained. I
haven't seen other potential applications of the same infrastructure and
maybe the code impact would be much smaller than in the MM proper. Our
allocator API is really hairy and convoluted.

> > - We already have page_owner infrastructure that provides allocation
> >   tracking data. Why it cannot be used/extended?
>=20
> 1. The overhead.

Do you have any numbers?

> 2. Covers only page allocators.

Yes this sucks.
>=20
> I didn't think about extending the page_owner approach to slab
> allocators but I suspect it would not be trivial. I don't see
> attaching an owner to every slab object to be a scalable solution. The
> overhead would again be of concern here.

This would have been a nice argument to mention in the changelog so that
we know that you have considered that option at least. Why should I (as
a reviewer) wild guess that?

> I should point out that there was one important technical concern
> about lack of a kill switch for this feature, which was an issue for
> distributions that can't disable the CONFIG flag. In this series we
> addressed that concern.

Thanks, that is certainly appreciated. I haven't looked deeper into that
part but from the cover letter I have understood that CONFIG_MEM_ALLOC_PROF=
ILING
implies unconditional page_ext and therefore the memory overhead
assosiated with that. There seems to be a killswitch nomem_profiling but
from a quick look it doesn't seem to disable page_ext allocations. I
might be missing something there of course. Having a highlevel
describtion for that would be really nice as well.

> [1] https://lore.kernel.org/all/20220830214919.53220-1-surenb@google.com/

--=20
Michal Hocko
SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFN1yswCd9wRgYPR%40dhcp22.suse.cz.
