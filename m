Return-Path: <kasan-dev+bncBC7OD3FKWUERBEFI7CXAMGQEFRF4QBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F1D3869CE6
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 17:55:46 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1d3d9d2d97bsf2479045ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 08:55:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709052945; cv=pass;
        d=google.com; s=arc-20160816;
        b=rkbPG4YXaYR+ICLC7BmiafTg6Dd7tm70lJeTHgU+wvbgWcFXSSjtxx+VRKwiRgcpua
         PpMAIWnBe3jlTqfbz+2SZohwS2oWZqoMbkjHXA9hg7xX5TL3d3RSnLSHs7sbwRAQYemS
         jVBG6xA53pWpx9UKNBJrc82yZL9Q3Ml/QudqTlF+d0W6YK4nOg+jSY5uoeTbA/vreos5
         jfoZ1ZRTIMFxFucUTELL0heV3gWa8sozePLd4Pe7ldA6nAFeAzNvD53hAGwkxv4VbbKc
         W8TWfqlrwgZmq6TOKDv/WS8lu/TWAJCMYYoVuep/Nxv11zCctNoYYT1Vn/YOYzmUZOhc
         oNQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X507xk+kKi5djjLEbnKYzM5B2+PHOaMP5fYFYaklSCw=;
        fh=SiFwSpt1qe+LT5k7UOPmQ18wVFUDQxkK2t+TvtgMd44=;
        b=JGENrQIeb65QTmHD+dmkcrjvKYAmkPlc7tOMl+BORjLbEOmZ62+Az26PQsXG66G2B6
         lqy+oEoDbeT4pzL2N6mmzf+p1q1/QxsdP2oFCfjpfPASvr7O7KFC/Y+XAYqbSPoJiYP5
         7/ehPBKEj1cFuNGeXy6jalmXsP+sj2c4xwyXnuHML1tfESZrsFj5dAq7rOdnpeaCCtc3
         +PNOb+m7SChPjwPfUzTi17IR+sGdxxqo30zzuzvKG4wWnTvshNZCeEcEmh5YrbcAisi8
         v95medhPsI1MvmVblkqp0ie79QulGRQ2adS6O6zOFyuZGVHQMFtjrb+VvHjTSc80s5do
         AoBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CiyCKk21;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709052945; x=1709657745; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=X507xk+kKi5djjLEbnKYzM5B2+PHOaMP5fYFYaklSCw=;
        b=mu9ZoHeV82UHVqF+wwVw85miG/yDJi99TX4Nsv1xgizPHON/Y5IpBuxmvyM2XbDkQl
         odaP3HxzilRDKT9vKetC1WozHwlxcljkiZvP8dRBzD4Jj7mvmkdnfgFYAA9qltcZoc8w
         n9WEI71WtL9tAL5zUwaS2wBeAkOrF+8jd3gZYef7/4sQSXbDsDK8E6TtFqs0jtbUrP5l
         SL8R2d0c+uWU61KCzKXWWFTRHs4kEVpAOdYeCVmuZFipdN4zaWvESh5wE0hZ1Ntd4pf1
         rqyQT2RmtBpNZY8WV0X0tFzV4pgYzAFPjueaMW4KWzAHNZy1XHel7R2X9RVTO3z/z8wq
         e1Fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709052945; x=1709657745;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=X507xk+kKi5djjLEbnKYzM5B2+PHOaMP5fYFYaklSCw=;
        b=xB3hdmmZlXkYeZqVx5sRueDIh6QYHFLS3kwebZ1/ytf6c0QkRJjgaaxH2yQ3F2lfN3
         VJTYYkqrGBC9XT9GEWDcD4yxTsCEHyhRGi9r1mY/iJScByLDxWdoFXvhsaz5FfDfdiGl
         hNSliRUYQl7EnQBXj71rInFz4eoqZe8yD8OVP5ZCSwqW2mJzI4fVDNBKcH5wqZ6XqD/K
         GL/5iTT31BDtbB4S7kXIlZQsvudIBM3oytXH7bCFEjrob75Rqf5C/NCfno7/PGDGs/x6
         kV5E2v7bkOc73yvNy66baD+JbR/4rUO2/1V44bLC5YSTMZ2J/ofwB5LccgIkEveJ0Zw5
         Rp0A==
X-Forwarded-Encrypted: i=2; AJvYcCWsUjZ7ag42D1Zq9UWnjozkmJ4V0O95TWWov0kUMO+AH/ihIli62+ydY9JyGSFWJseQmsKOjzkvBwD1rR0dU2IcNIikKrkcbw==
X-Gm-Message-State: AOJu0Yyfh5xdXH1DgFjfkuEM7mw3bA1O+VTS9v4NJ+3UVoB+GRooEoIt
	StILy/flFbIoB9QRaAqNjF7weRm90kqicLBFPV05E+vbAyG8ivas
X-Google-Smtp-Source: AGHT+IE5zKn+kNOXlWEavsiML5QS8Hgc5XwBBfVClneJ6K+vIkglz1VNXfyjZlN3//kW5ibqbtHzkQ==
X-Received: by 2002:a17:902:f60e:b0:1db:8eaf:7652 with SMTP id n14-20020a170902f60e00b001db8eaf7652mr217206plg.5.1709052944660;
        Tue, 27 Feb 2024 08:55:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:55c1:0:b0:5a0:3850:af20 with SMTP id e184-20020a4a55c1000000b005a03850af20ls1647719oob.2.-pod-prod-03-us;
 Tue, 27 Feb 2024 08:55:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXih0gDnE5b0m4quD+h0Sv962LhPSGe2UaO7qhkHwbpzmEsJzkoh4934tOoJvWTbidu/LAw23/jJpszeM03gdKDJosl2G9uHIRzbw==
X-Received: by 2002:a9d:6f05:0:b0:6e2:ec3d:f141 with SMTP id n5-20020a9d6f05000000b006e2ec3df141mr11246099otq.16.1709052943783;
        Tue, 27 Feb 2024 08:55:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709052943; cv=none;
        d=google.com; s=arc-20160816;
        b=AI9hExj0Ikm0ZJgg+IoXQK3F0TlyFDdH7P1/6wi7w5XfTsXBGI+m7QFqxM7RlzZeB5
         dvlxgPlCsesz+cPHu78GK1LGtRdeR1NtzcaG/Due4t3pCdh/l+CSaaWbC0Su1UOHyOqP
         VT1xUKZBoMkoJFm5r/SAOY+/icMmxD1CYe6VOwWptmRgx6etlujt9goCzZfp72t93yEf
         rP5YF6oXwq/pfTGsJEEfSJybSItlO7lO9BwM6gw64x0ePrEDS1Zd2qlkMr039V51OgU7
         GCmxqQAaWEAZovA/rfQ4r/wT0p/uNom6+/qb7xL519PshHbdo74MpPYhJZt9J1XIJcMp
         WmWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WING8+ifDIdPqWo/GgNARqwiCxM6QeK8N+15oiAYs8U=;
        fh=EM7AjhGXn2nXC1jrJyNJIo/q34EwNS5t8B6Q7C7LpIM=;
        b=sXlt9HSL9geYEkrGvO/OckJDbN7jkdPieboO/I2i1eXQ+Whm2qo2ikXkSbcLt50O09
         0b3IvUr927/qyqDWE9I7WHPhA5Xim9+EeET26gwB5kGufj/Z2uu4s3RtKIvMn7Gv+3F4
         Mc9F634Ux9DOYN3BPt9pHHu2odYMz06G4yD0S9/tQAZtdhn4yClSUY6p08MgU55vSCp1
         3IbDSS8iBm/S4IYETq3x5Popvd4xcAF0iDO0+txhTslYSQq7NpDDw6ZCqQNvg6phF7jd
         +jKz/FmsYtNM3FwhaO2VhVU0r+NhIN6Yl34CRkL5pdYVN5ToSebiCqQT1Hs8I5M/hFCw
         UpDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CiyCKk21;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id h2-20020a9d61c2000000b006e485c6b379si604562otk.5.2024.02.27.08.55.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Feb 2024 08:55:43 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-60925c4235eso9423047b3.3
        for <kasan-dev@googlegroups.com>; Tue, 27 Feb 2024 08:55:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXAoj6uJYm9FT8p6ez7+rz0iD07J4i9sh/5zjPNX/W5A8TlcEq8+WeTA8+uX/LDWU96dQ8AWMKHlFKqqsQtWqY5TrFHLPNVbQ0aXQ==
X-Received: by 2002:a81:e245:0:b0:609:2857:af0 with SMTP id
 z5-20020a81e245000000b0060928570af0mr1933120ywl.25.1709052942967; Tue, 27 Feb
 2024 08:55:42 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-16-surenb@google.com>
 <d6141a99-3409-447b-88ac-16c24b0a892e@suse.cz> <CAJuCfpGZ6W-vjby=hWd5F3BOCLjdeda2iQx_Tz-HcyjCAsmKVg@mail.gmail.com>
 <72cc5f0b-90cc-48a8-a026-412fa1186acd@suse.cz>
In-Reply-To: <72cc5f0b-90cc-48a8-a026-412fa1186acd@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Feb 2024 08:55:32 -0800
Message-ID: <CAJuCfpF=uwxH93BF6905FAcvaihYD0iyT=rJS-REe4u_1Km22w@mail.gmail.com>
Subject: Re: [PATCH v4 15/36] lib: introduce support for page allocation tagging
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
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
 header.i=@google.com header.s=20230601 header.b=CiyCKk21;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a
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

On Tue, Feb 27, 2024 at 1:30=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
>
>
> On 2/26/24 18:11, Suren Baghdasaryan wrote:
> > On Mon, Feb 26, 2024 at 9:07=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> >>
> >> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> >>> Introduce helper functions to easily instrument page allocators by
> >>> storing a pointer to the allocation tag associated with the code that
> >>> allocated the page in a page_ext field.
> >>>
> >>> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> >>> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> >>> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> >>
> >> The static key usage seems fine now. Even if the page_ext overhead is =
still
> >> always paid when compiled in, you mention in the cover letter there's =
a plan
> >> for boot-time toggle later, so
> >
> > Yes, I already have a simple patch for that to be included in the next
> > revision: https://github.com/torvalds/linux/commit/7ca367e80232345f471b=
77b3ea71cf82faf50954
>
> This opt-out logic would require a distro kernel with allocation
> profiling compiled-in to ship together with something that modifies
> kernel command line to disable it by default, so it's not very
> practical. Could the CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT be
> turned into having 3 possible choices, where one of them would
> initialize mem_profiling_enabled to false?

I was thinking about a similar approach of having the early boot
parameter to be a tri-state with "0 | 1 | Never". The default option
would be "Never" if CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=3Dn
and "1" if CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=3Dy. Would that
solve the problem for distributions?

>
> Or, taking a step back, is it going to be a common usecase to pay the
> memory overhead unconditionally, but only enable the profiling later
> during runtime?

I think that would be the option one would use in the early
deployments, to be able to enable the feature on specific devices
without a reboot. Pasha brought up also an option when we disable the
feature initially (via early boot option) but can enable it and reboot
the system that will come up with enabled option.

As Kent mentioned, he has been working on a pointer compression
mechanism to cut the overhead of each codtag reference from one
pointer (8 bytes) to 2 bytes index. I'm yet to check the performance
but if that works and we can fit this index into page flags, that
would completely eliminate dependency on page_ext and this memory
overhead will be gone. This mechanism is not mature enough and I don't
want to include these optimizations into the initial patchset, that's
why it's not included in this patchset.

> Also what happens if someone would enable and disable it
> multiple times during one boot? Would the statistics get all skewed
> because some frees would be not accounted while it's disabled?

Yes and this was discussed during last LSFMM when the runtime control
was brought up for the first time. That loss of accounting while the
feature is disabled seems to be expected and acceptable. One could
snapshot the state before re-enabling the feature and then compare
later results with the initial snapshot to figure out the allocation
growth.

>
> >>
> >> Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
> >
> > Thanks!
> >
> >>
> >>
>
> --
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kernel-team+unsubscribe@android.com.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpF%3DuwxH93BF6905FAcvaihYD0iyT%3DrJS-REe4u_1Km22w%40mail.gm=
ail.com.
