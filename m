Return-Path: <kasan-dev+bncBC7OD3FKWUERBLHWV6XAMGQEN54ZGNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 14FE1854013
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 00:28:46 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-5c5c8ef7d0dsf4816198a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 15:28:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707866924; cv=pass;
        d=google.com; s=arc-20160816;
        b=BPTLi2lv+nVzC65CDxaJ1KFOuWSyWD0NZ6Syslofs5VJzMVmxHCBfWAJ+4qG46n58w
         +eXgdlZY0HoHDNsPMPQTBVvpIbq6fJh8fIXbJobZzbanB3wiaMvsLd3EHrIwu6PuiCXL
         ivd4jnuokjvWhCrrZWrVfuUtNi9oih69xiJTTpI4cx3PNVZ7SQ15tB5oRXjxXM5Qfb8d
         m/PNid41Fn8Eflc4yTNyDpfI7ltHcSZfX0pcY1Ro4B50GqDEHishIOoCdT0z/AU9ugFl
         D84Q/xfJ4/87+rUnMxdp5EUtM/obUc0DmnAQxiUuAJWr4PHA7ckOyIQUxTQbpRPxp3Tw
         RQAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=awelDNH60FGggdBZMlx9VaqYiLO6Uh+tTbWynF877t4=;
        fh=cObJByFAmXWG3GqOSj/gxTJwKDB7ksNr3MF/pNbZt/4=;
        b=LypJ1H5zBD6FuBCPnNFf1Myx4I7Uznh1BTm0HMOz3iwr5274tj4AQItrVRnD/7m3Mi
         b++6iVH1NbA9oQeHOV7/zWzDotu+DhFOGRq4kshIDbq01vF/gKwdl/uzH9qa6uYG/J5h
         +wjdabvsS1pgPKGkuKRubgGt/kaeblP9iY29LwrZBD6RdOUkvJPVrWUVts60E+Q1JUFN
         ZN6Z7uAJROLw2NuU1Xdzsv1yFGERxRs+WSXx9FngzWOO/LxXqMqsMuehUvA8MxzMjx3q
         jzlvLTvzWWXSa8SQYugMC9/mtsPjP0XwIZ5/OBHeRExPpIpM4jbB1EpPIQvsJBUTueTc
         UQZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sjpiX15i;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707866924; x=1708471724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=awelDNH60FGggdBZMlx9VaqYiLO6Uh+tTbWynF877t4=;
        b=r4vxayecARe5AaGdvCnFZnVO/5Pw/KHxcewIgE5QQUa/3kdIYDPTfM8YxHqD1HQs/F
         7qyxez5eJ00xKGPD9wewt7qXTIlSwaVzL9IoeOjfLL8YhzjXvFbcUAVHJDMUUqUrdFgu
         JGp1AzTotAieRS5eC5ZXS0xH6OnE0ymGSqSsHaT06FB4ktSw0uJmr/RKCqNSXFvvCTFJ
         NCbffi6xkoUqKo7LDgYgbkFfZR9sHS/F5VAYB9BqbHwo/ZEzXE4CiSutnGaKItg4LLkO
         5852D8EY5yt6LPNnUenlABrjPWK+JSzgsqXSrrZ6Tu/f8fkCQzRuih1JCiHrhUDcMe1a
         oPLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707866924; x=1708471724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=awelDNH60FGggdBZMlx9VaqYiLO6Uh+tTbWynF877t4=;
        b=N8bowhs0DhzSUpTyJ3phUchiC8nb9wgCRFf9WaTKpfXcogD6eqRzS82LF9vyZBnx6P
         zj4p7/QtzFLieNq70fYhLl1zRVaNo88kJwIqSanguidJvI9zEpd+j88r3vCQWF1t+3gd
         F3JL1rNh/ToZTG2kFx/zgnYfoFBn5zo6EKyZmTOfxh7oYNcsyw9QbQANyGVOrwBuCYuJ
         EcyFbVPamg1MeaWViROe9OEUN27w+Pg9J7IOlBTXwDHdXXV2eXPoDrbecwIx/glKkxmk
         4sPN/iCZvHSNYUh1tOUfisXoWliCKwjGCsS79JgwgSFF7c1L9H1c+gFKOJCfTaWZH5CR
         sZtg==
X-Forwarded-Encrypted: i=2; AJvYcCVg4MKy9nwcXfnEBQkfQIcWjufRWtFAVKM4TljHPBkCrYRTI7inJJTr03hxv1bj3IJEEizxqmERUd/4R5mxkgnhAVZBgVodiw==
X-Gm-Message-State: AOJu0YwzKwiajg5ogwu76KrttD8rmYc/cHimeDKQfGGF3oL7G16k+Bia
	ibPiGlW1UCzPweLzCeVJPOsolkSF4SXofc7IWBICEwRAuqLGWNKO
X-Google-Smtp-Source: AGHT+IG4Q1yRTYE18MI0thMlYtTTxS4Kp6FOhesf3ib9hcM3LUCtW4l+i7UTwl53J5J9OqQX8Eg3UA==
X-Received: by 2002:a17:903:1250:b0:1d9:791b:7dd2 with SMTP id u16-20020a170903125000b001d9791b7dd2mr1184435plh.7.1707866924579;
        Tue, 13 Feb 2024 15:28:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:25c1:b0:1d9:a51c:a833 with SMTP id
 jc1-20020a17090325c100b001d9a51ca833ls390460plb.0.-pod-prod-01-us; Tue, 13
 Feb 2024 15:28:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVO4Xj6/+xxVnE06UY0MEWaU7GRg9tY+I0shoaGEVO/7AkqOxW1n17OOIvyxzRqHWlHAwY7sQEgRt0IrUqlp5d9Fdbd3rVdYSD4Tg==
X-Received: by 2002:a05:6a21:164e:b0:19e:a353:81b0 with SMTP id no14-20020a056a21164e00b0019ea35381b0mr294150pzb.11.1707866923484;
        Tue, 13 Feb 2024 15:28:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707866923; cv=none;
        d=google.com; s=arc-20160816;
        b=chhzQvzhja29/7o/FqeM0frZRB7NbzlUgjxNpopkgIhDtiO+reSGgd8qrKpZ6E3/bM
         GOFkFgZoDSogmDQpcklOwPAEBEUsQM4WhhgNIpL/ApIbJe02OOnKwq1xIeDA8YWMXh4w
         ojjcXoYUCw9h5juGqca4vDt8TlX2pwWHCYPWONahW+E5D2RBr4gKPMKgSz+W9NwIHjXL
         u+5H5aprkBCh5S9sn60aC1aaLLAOeFFKYEWHXl0UepRbVmEIceWoLfKVgxW2asl0VUep
         jbJQ91SVlhMnE9UnUSdk2WKIslj9UZfbqOzSQJkmj9fRihk9tBbs0vYVjOC/Sn2a7LEk
         r9Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Fh7ErxUCpzMchpW5XvBpyJH6+JOUDYjAM9H3p1A49z8=;
        fh=fYU3f2oeMK5hueUJPT1TTE73FBxsQ7GmgWrEvAhzaZk=;
        b=ZIlNE/eSYp3LbD9vAMxPVbPs6E4ghKHaeCgQhjUhX7ScyvWS+GR7fEcp4Z0WVa6/Xc
         diS0c4NLAkx9+hjJbsrbKouWhkKQyKS0nPms2r+LV7UbXCkG5YgcqLVqVb6HOwrgz3rA
         jKdcIRBQs5zmRAm3qTU2FApouKwp/s6iISG5iIb0QKairivn7fwzclyOmh+TOY4w4SCD
         kClRgRwHrlzbepaFNcw6OH9rsp23UztDgEKT/L4Kt0xOKhD3Us8y8mIMaRFAGRIAf8x1
         6S769nz2wUZOXtT7CDiW6HSJ0KXgZf1FPnXvcdNdo2B40z078rqVAuPliax3pvH/cjvd
         D9GQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sjpiX15i;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUX/LnxRszUf3X3jEVptJZ2mSrEII7mNorucYziV0e7Lp6y/4jLw+K+j5lVRqNjd21+D+Sd7V9hQ8w6PAQnC3eMT1ND09/8IxPBpQ==
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id p6-20020a625b06000000b006e06c8a8c7esi1551082pfb.1.2024.02.13.15.28.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 15:28:43 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id 3f1490d57ef6-dc7472aa206so4205663276.2
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 15:28:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVukQ4eHMl/b64tYb+Zrw7641Sc5qFOqFDs8XMislV5s7QyxKI4ocWaMZ7jHuE8GahBGZjdLBQasefRmgp8aRTEN2l+CumlcywW/A==
X-Received: by 2002:a25:84d2:0:b0:dcd:6a02:c111 with SMTP id
 x18-20020a2584d2000000b00dcd6a02c111mr818389ybm.11.1707866922283; Tue, 13 Feb
 2024 15:28:42 -0800 (PST)
MIME-Version: 1.0
References: <Zctfa2DvmlTYSfe8@tiehlicka> <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com> <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com> <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com> <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
 <a9b0440b-844e-4e45-a546-315d53322aad@redhat.com> <xbehqbtjp5wi4z2ppzrbmlj6vfazd2w5flz3tgjbo37tlisexa@caq633gciggt>
 <c842347d-5794-4925-9b95-e9966795b7e1@redhat.com>
In-Reply-To: <c842347d-5794-4925-9b95-e9966795b7e1@redhat.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 13 Feb 2024 15:28:28 -0800
Message-ID: <CAJuCfpFB-WimQoC1s-ZoiAx+t31KRu1Hd9HgH3JTMssnskdvNw@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: David Hildenbrand <david@redhat.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Michal Hocko <mhocko@suse.com>, 
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
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
 header.i=@google.com header.s=20230601 header.b=sjpiX15i;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as
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

On Tue, Feb 13, 2024 at 3:22=E2=80=AFPM David Hildenbrand <david@redhat.com=
> wrote:
>
> On 14.02.24 00:12, Kent Overstreet wrote:
> > On Wed, Feb 14, 2024 at 12:02:30AM +0100, David Hildenbrand wrote:
> >> On 13.02.24 23:59, Suren Baghdasaryan wrote:
> >>> On Tue, Feb 13, 2024 at 2:50=E2=80=AFPM Kent Overstreet
> >>> <kent.overstreet@linux.dev> wrote:
> >>>>
> >>>> On Tue, Feb 13, 2024 at 11:48:41PM +0100, David Hildenbrand wrote:
> >>>>> On 13.02.24 23:30, Suren Baghdasaryan wrote:
> >>>>>> On Tue, Feb 13, 2024 at 2:17=E2=80=AFPM David Hildenbrand <david@r=
edhat.com> wrote:
> >>>>>>>
> >>>>>>> On 13.02.24 23:09, Kent Overstreet wrote:
> >>>>>>>> On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrot=
e:
> >>>>>>>>> On 13.02.24 22:58, Suren Baghdasaryan wrote:
> >>>>>>>>>> On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@s=
use.com> wrote:
> >>>>>>>>>>>
> >>>>>>>>>>> On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
> >>>>>>>>>>> [...]
> >>>>>>>>>>>> We're aiming to get this in the next merge window, for 6.9. =
The feedback
> >>>>>>>>>>>> we've gotten has been that even out of tree this patchset ha=
s already
> >>>>>>>>>>>> been useful, and there's a significant amount of other work =
gated on the
> >>>>>>>>>>>> code tagging functionality included in this patchset [2].
> >>>>>>>>>>>
> >>>>>>>>>>> I suspect it will not come as a surprise that I really dislik=
e the
> >>>>>>>>>>> implementation proposed here. I will not repeat my arguments,=
 I have
> >>>>>>>>>>> done so on several occasions already.
> >>>>>>>>>>>
> >>>>>>>>>>> Anyway, I didn't go as far as to nak it even though I _strong=
ly_ believe
> >>>>>>>>>>> this debugging feature will add a maintenance overhead for a =
very long
> >>>>>>>>>>> time. I can live with all the downsides of the proposed imple=
mentation
> >>>>>>>>>>> _as long as_ there is a wider agreement from the MM community=
 as this is
> >>>>>>>>>>> where the maintenance cost will be payed. So far I have not s=
een (m)any
> >>>>>>>>>>> acks by MM developers so aiming into the next merge window is=
 more than
> >>>>>>>>>>> little rushed.
> >>>>>>>>>>
> >>>>>>>>>> We tried other previously proposed approaches and all have the=
ir
> >>>>>>>>>> downsides without making maintenance much easier. Your positio=
n is
> >>>>>>>>>> understandable and I think it's fair. Let's see if others see =
more
> >>>>>>>>>> benefit than cost here.
> >>>>>>>>>
> >>>>>>>>> Would it make sense to discuss that at LSF/MM once again, espec=
ially
> >>>>>>>>> covering why proposed alternatives did not work out? LSF/MM is =
not "too far"
> >>>>>>>>> away (May).
> >>>>>>>>>
> >>>>>>>>> I recall that the last LSF/MM session on this topic was a bit u=
nfortunate
> >>>>>>>>> (IMHO not as productive as it could have been). Maybe we can fi=
nally reach a
> >>>>>>>>> consensus on this.
> >>>>>>>>
> >>>>>>>> I'd rather not delay for more bikeshedding. Before agreeing to L=
SF I'd
> >>>>>>>> need to see a serious proposl - what we had at the last LSF was =
people
> >>>>>>>> jumping in with half baked alternative proposals that very much =
hadn't
> >>>>>>>> been thought through, and I see no need to repeat that.
> >>>>>>>>
> >>>>>>>> Like I mentioned, there's other work gated on this patchset; if =
people
> >>>>>>>> want to hold this up for more discussion they better be putting =
forth
> >>>>>>>> something to discuss.
> >>>>>>>
> >>>>>>> I'm thinking of ways on how to achieve Michal's request: "as long=
 as
> >>>>>>> there is a wider agreement from the MM community". If we can achi=
eve
> >>>>>>> that without LSF, great! (a bi-weekly MM meeting might also be an=
 option)
> >>>>>>
> >>>>>> There will be a maintenance burden even with the cleanest proposed
> >>>>>> approach.
> >>>>>
> >>>>> Yes.
> >>>>>
> >>>>>> We worked hard to make the patchset as clean as possible and
> >>>>>> if benefits still don't outweigh the maintenance cost then we shou=
ld
> >>>>>> probably stop trying.
> >>>>>
> >>>>> Indeed.
> >>>>>
> >>>>>> At LSF/MM I would rather discuss functonal
> >>>>>> issues/requirements/improvements than alternative approaches to
> >>>>>> instrument allocators.
> >>>>>> I'm happy to arrange a separate meeting with MM folks if that woul=
d
> >>>>>> help to progress on the cost/benefit decision.
> >>>>> Note that I am only proposing ways forward.
> >>>>>
> >>>>> If you think you can easily achieve what Michal requested without a=
ll that,
> >>>>> good.
> >>>>
> >>>> He requested something?
> >>>
> >>> Yes, a cleaner instrumentation. Unfortunately the cleanest one is not
> >>> possible until the compiler feature is developed and deployed. And it
> >>> still would require changes to the headers, so don't think it's worth
> >>> delaying the feature for years.
> >>>
> >>
> >> I was talking about this: "I can live with all the downsides of the pr=
oposed
> >> implementationas long as there is a wider agreement from the MM commun=
ity as
> >> this is where the maintenance cost will be payed. So far I have not se=
en
> >> (m)any acks by MM developers".
> >>
> >> I certainly cannot be motivated at this point to review and ack this,
> >> unfortunately too much negative energy around here.
> >
> > David, this kind of reaction is exactly why I was telling Andrew I was
> > going to submit this as a direct pull request to Linus.
> >
> > This is an important feature; if we can't stay focused ot the technical
> > and get it done that's what I'll do.
>
> Kent, I started this with "Would it make sense" in an attempt to help
> Suren and you to finally make progress with this, one way or the other.
> I know that there were ways in the past to get the MM community to agree
> on such things.
>
> I tried to be helpful, finding ways *not having to* bypass the MM
> community to get MM stuff merged.
>
> The reply I got is mostly negative energy.
>
> So you don't need my help here, understood.
>
> But I will fight against any attempts to bypass the MM community.

Well, I'm definitely not trying to bypass the MM community, that's why
this patchset is posted. Not sure why people can't voice their opinion
on the benefit/cost balance of the patchset over the email... But if a
meeting would be more productive I'm happy to set it up.

>
> --
> Cheers,
>
> David / dhildenb
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFB-WimQoC1s-ZoiAx%2Bt31KRu1Hd9HgH3JTMssnskdvNw%40mail.gmai=
l.com.
