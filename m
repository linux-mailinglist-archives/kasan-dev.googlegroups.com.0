Return-Path: <kasan-dev+bncBC7OD3FKWUERBHWMV6XAMGQEIPHQNGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A204853DD3
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 22:58:55 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-42c685d0b1dsf609021cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 13:58:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707861534; cv=pass;
        d=google.com; s=arc-20160816;
        b=rMs9zmDqQakgkqb4Ho9nTJRcin9aDhiQRehW8+BZj0pbfB7JRsDInqmmp6VJu53qzM
         0y2KrGgubU7bfoNSkdnlsROnrTicbyJ9pcnXJjEUA+pT4yNFuK7eqm3ExgAVkwJ86Zef
         KxWYyxlzAspcNMltS3DQN1fe1ibq+7xdzVxFghqskefSkQmn+b126PAVov78Uvwh6Zkd
         SeynR9EcqsYYmolt4GTgK/GNPx6VyCabZ4R+HP85WdCMLQesNgWNN3OIqyJK+lRuQSmY
         MNdRng/E3QOFWECOOSewEf0kswfpsSJxHh0Ux4fzvsOau8sZAlYAI2ek7X3V1osdZDBi
         XmEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3pq+LXC1CgoroCEeHd0Qr5X2KTX7T96+TZgTSe7fj8s=;
        fh=HKmXkCJS33zTyxO96Qo8rU1tu0KEd7QbFrdfrxBAPAg=;
        b=N1Zc2HjjqwKy7QxLtvOSLqlsURDhgZkOj61Z95yqg0tf0AL3pEXntoPH/InM9gSpmU
         Y1qSoqm4qaaNzykHI4c48qByJquDGpQlxcT/Hek2Um2adpUPOMBIjVkAj/bV/erekexR
         NmFVoCfGqUQdfHVWEEPU3O5ivoat56F017JpIKYwlmSDhRhdFuVnLrJP0Pos5Jb8gJfE
         MC/lX4UbciQeub24EpcoArO1ixB0INyXHv3dL2xgrRDmTTsb7+wsA2j9zLlTqwJCjI4x
         EXIbrWeQqv6IN1010ADti/yZZ/eM4Mrz0SmXINI+R+agayRZiTQ6Lq2rgkCANT60tAvn
         gu0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qVyEDDZp;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707861534; x=1708466334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3pq+LXC1CgoroCEeHd0Qr5X2KTX7T96+TZgTSe7fj8s=;
        b=TLft1LdgydpRtJNsv3xfBAej624wtY5sDhMeOReEJmZE/+0xhgzHTDAWH9EV8svwhw
         6zaV4En+K1hroNGXBv199CuBu7og+23uN7REV/FNKecQklz7VHY0xcFJQHPt9TvviIct
         tAX8sWQOqfOqveyHR4DDif4aVWWjEEJU9OLRIeYN7x18K/uqpIdLsLJmHHDhifbIHk8m
         VnXcBoW0/lM0JwYD4erqO/QxV/+/Pg0m8e2VXzxDbnR/vG9lZhWoMR3wIgeZ+SjM9kvl
         3tsXEE/DrIBn+7jMR5RKgbLoD53xx+t+kAQ5K1mK1QtFChI2x7LTtN0/8Qp8mDKqecAt
         BWbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707861534; x=1708466334;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3pq+LXC1CgoroCEeHd0Qr5X2KTX7T96+TZgTSe7fj8s=;
        b=N0L4BkPx5Zdpf6lIraMA+mIbSVuRYXBBVprJIy6DUT0RjWooi1TVpw3DupGArTwO3Z
         66ZaxKdlRDpMTwEqB7Y6rWwPW+ENfMzZd2c530jLpMDzo4SVpTv1VLtBcNd6ACk4JNAa
         Wd/PAIFtMLcXjtL8FN/tUGGonvp691enyV6woYFYQ8cSr9Z0YtovffM0DPZ+LMhC1Gg1
         efUCtxPts9567oqvqMIbvuI8s0YtMX0k5RwRWFcRVAt1wfAxqgYmMI1oJGjCPXIOBUR8
         K3KBeMt9pvfngKFZeuAdn0VI5D8qXEr9hXYSxCj6yGWJl7kOq/nxGEcrYuHBpMSG2Dn9
         rmwA==
X-Forwarded-Encrypted: i=2; AJvYcCUDfKH9HtzeluQlQ0Yknk9Jo4ZlyWMYsz2N8KRrwop2FqSTdvrAD3im2S2u4+7pr2X3JjrRXMwjJO732AdHo5BiNj3r5+oX5g==
X-Gm-Message-State: AOJu0YxBnnTOJeWPRDm012HeUmEPdnT1maLJ5DHLEl35almnjOptJjYS
	e4LSC6B2y6uD89i52oBOob5LCEB3QDbuTWNrLPmVyh0bO29BPzhl
X-Google-Smtp-Source: AGHT+IHjjdA4urrDrfrZLxWRxYiJ57KXiIyU77q7ERw/t908Rvs/lmhfP6LLTgFM79QqlVqo0OoZ/w==
X-Received: by 2002:ac8:4e49:0:b0:42c:6b6f:51d2 with SMTP id e9-20020ac84e49000000b0042c6b6f51d2mr83339qtw.9.1707861534289;
        Tue, 13 Feb 2024 13:58:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:e66:b0:68e:e7cf:2abe with SMTP id
 jz6-20020a0562140e6600b0068ee7cf2abels1871543qvb.2.-pod-prod-00-us; Tue, 13
 Feb 2024 13:58:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU58eUX8WxnvkJGGmPg44s0gKdY4J2zmIYBAidki7cCNiBGTcLWsrWWvhxQ/mbvqMos7RI8CGPB1OqML7kr/Rz9qEXbqXEJRr1KaQ==
X-Received: by 2002:a1f:4f02:0:b0:4bf:fe7f:1c56 with SMTP id d2-20020a1f4f02000000b004bffe7f1c56mr107850vkb.7.1707861533668;
        Tue, 13 Feb 2024 13:58:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707861533; cv=none;
        d=google.com; s=arc-20160816;
        b=ptMODxXj5hjCDOIvthSRckhaOtjHOYivGR3hwlfbQJKLHyQGmFGRf48M66mbPU5Oo3
         OYtMoIOU1SxacUpWKQ8L2jwypArolYpNyJYZBbG3EDXZIWneDFFKNgZyA4BHQ2H8zWDA
         Y7QG4P4XQlNrCX398y0FR2xfu1qtBauw2F9Pvi4VX+NbA3lfzdIl5BDpcJg2j0cshzid
         oqjpiNQQFj5YXPiy5ARqrl3Rbw5kqwDrc2wr6M8tzjMkqEEAm0wux6TlLWBz9/h8Nex4
         /y45X4J8IbhL7BxVGhYkV6+vrsTv6sBgZVgUyueAaQCFedoPxyAPQOrcgNQV2fNMWrWk
         rMYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Sj6FkWt0IHINoPp252M2H78r73QaJ+UAYuAK2lRmHyc=;
        fh=sf2Gk9uoXCo7L7DBhQk1rmr5Apwu+LYqvBlxJymaRHg=;
        b=vZOaMRiDZT7yuP0O4z844QR0UXhWZ6qvXUWNB9jTW8StpK24kyPOrlBptElq1ET/86
         HHFedXs6Z9+fbvzXxF1wABpBGU/8E0Q/w65AXX1rE8YUnugvEh908Dpf7SGZ8fKurXx1
         YQBhu0A7uFFkcQ+CVsxOgGAiCyJ2mAUAHUALGmIYYEr1K0hlfksDcZ+3sH5tjnqinngZ
         xUPHN494MrFAPvIa1/d40dFelu7cxJB8tQZm035ICX26ZCneEU4a0AgttAPlLATW/i4B
         OeRpiCnOOLOffLKWagHuJzfMvTX0th+Imkh9UEy+QifXL2HkFLcxF+PjDBO/yJJkeXLc
         hWRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qVyEDDZp;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXUbKiw5j1dawwgbGCzt7qKF1lo9fISMOBh7k8Aq5Ey41JU8xrNFWmprnuh5ukWFX/3jWc+RvElu4Ozryu2BWO3C615UN3JQxBuTw==
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id 3-20020a0561220a0300b004b2e6e4330asi965845vkn.1.2024.02.13.13.58.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 13:58:53 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id 3f1490d57ef6-dcc6fc978ddso194401276.0
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 13:58:53 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXfF9KVYd+Ya6VO8Hg51W/RY8U4DykBHRnvRXtqZ8p4pMCOzA1pkTQmkXo8NwUFB52KtBncPsOeJF9x/02bwJDLjVZcgIav09CLeA==
X-Received: by 2002:a25:d815:0:b0:dc6:e7f6:254a with SMTP id
 p21-20020a25d815000000b00dc6e7f6254amr127954ybg.8.1707861532899; Tue, 13 Feb
 2024 13:58:52 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <Zctfa2DvmlTYSfe8@tiehlicka>
In-Reply-To: <Zctfa2DvmlTYSfe8@tiehlicka>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 13 Feb 2024 13:58:39 -0800
Message-ID: <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Michal Hocko <mhocko@suse.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz, 
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
 header.i=@google.com header.s=20230601 header.b=qVyEDDZp;       spf=pass
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

On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@suse.com> wrot=
e:
>
> On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
> [...]
> > We're aiming to get this in the next merge window, for 6.9. The feedbac=
k
> > we've gotten has been that even out of tree this patchset has already
> > been useful, and there's a significant amount of other work gated on th=
e
> > code tagging functionality included in this patchset [2].
>
> I suspect it will not come as a surprise that I really dislike the
> implementation proposed here. I will not repeat my arguments, I have
> done so on several occasions already.
>
> Anyway, I didn't go as far as to nak it even though I _strongly_ believe
> this debugging feature will add a maintenance overhead for a very long
> time. I can live with all the downsides of the proposed implementation
> _as long as_ there is a wider agreement from the MM community as this is
> where the maintenance cost will be payed. So far I have not seen (m)any
> acks by MM developers so aiming into the next merge window is more than
> little rushed.

We tried other previously proposed approaches and all have their
downsides without making maintenance much easier. Your position is
understandable and I think it's fair. Let's see if others see more
benefit than cost here.
Thanks,
Suren.

>
> >  81 files changed, 2126 insertions(+), 695 deletions(-)
> --
> Michal Hocko
> SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEsWfZnpL1vUB2C%3DcxRi_WxhxyvgGhUg7WdAxLEqy6oSw%40mail.gmai=
l.com.
