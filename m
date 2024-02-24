Return-Path: <kasan-dev+bncBC7OD3FKWUERBDE34WXAMGQE6UGZKDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C65F86221D
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 02:59:42 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-42e61ee16aasf11173701cf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 17:59:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708739981; cv=pass;
        d=google.com; s=arc-20160816;
        b=RkYgikJUtP49ZEraron4v8X9m/NN80J+WV8y5tE+rNpo5MDwl6G6RB2W9zo994LfD6
         1e4F2vzkI/7vCbNtrU5q0OtcENQN7rdkMZ9YhvP0vtZxYAXfKmliKy+uZLA+5WIcZ9wW
         VKct1mxvDoEg0PO+//cPePLg+xniEXXYVu+J2sXgXxBh+lQPWfSq/DzhkMd2pFLGrfBW
         nSPWqr8EzClq8DWTG60cgXqeXWSwjDEykgDNbjQ90QPbIkC4zfjimIf+ZJbXq6VV1cTU
         JBDwow+8W+3OEPh5iXtufNnHveDjlm8s7ZhIWWNQY5UkIRKLwhnb9M5LvkY4MsS9XEdx
         fJrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=D6TOirChoskLw8yp26w773Vkn4uzTD1F6eM6wZPyWL4=;
        fh=GaOXqKS7GxTX2u2Mmaic3j7pGDg+Fl8jM9Hn9Piogyw=;
        b=eTGGHQ+SC6RW5iP8+DMHDmpidTTQZEbyvO7MtZyDNCdvypGQ1a2vYAbUcOpDpWibND
         KAerRUaIQ+mREu+aysuCVMdrJPbeCnWI2Fq41nhu1ykl3vtv8QitWvgR0rfGNekrLNs7
         D1+ys5/PXJLkjdTxZScC7GujwGwnJ6aTDhnN8wzybH2kJ2Xhpuk6iSaf2/y++kFKHYEs
         EFGQrqsGYtC3uP2ZBiHdqAYic+QA03vTH8/kqoSnPv/7Rys1dH+jJHbRFt2nOyE/nogk
         /VaNvWomCv38rnXb/2yMl/xOlz2tLZyESGeJmcFq30oZAlNrpbKNj63jSLx5uvSrrIvT
         /24w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="RRSpi3/C";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708739981; x=1709344781; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=D6TOirChoskLw8yp26w773Vkn4uzTD1F6eM6wZPyWL4=;
        b=RqqFhXQqUI3lvxXtCmKZC9eaI7tPZIeI5nk1n5OvroC5kpY3e4gY2IsObPyOJa3ABy
         lx7+q+VIt3JhIDWb/JJRLRRiiyMtlQQTSfr77VU6PM/lk1pJ9Jtnp/T+kXeQkxK929Vl
         p9Ed9eBuRB/ZFElX394395lGp73V/0NtYPI0ksl6qgQWc/VbAoig9alqnBg6Tj9mmgAt
         6hgHjqCXRGSyfGZ3P5fHQJ4Zq0EuJzPIt4hNxkdyzwptHgXDoDm16G+JDu8df/q7ZOpv
         Th/FzFg5a6MsKmVMbYbww+duR85DsbB3rFgcCq1QMEHaHPjsGjwGHAX2rBrrGBMnEUZd
         vTdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708739981; x=1709344781;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=D6TOirChoskLw8yp26w773Vkn4uzTD1F6eM6wZPyWL4=;
        b=b56cUL6HcG4DESrBXQlFLzOQBrBDntNsNZ1If5c8QXoC5/fTzMSzhJUbFsFGyW+pVO
         R9y0EiihbcrxX+Ifoia6j/NO1J9Y+GVNj6YTDjwHA3vRS7iOz8i+rgxTHWRUw315Zy3t
         EeGRSCOeGuQIY5nWaXlq69uvUUCZLguPW6FVALK+Dy18MmjE87nSJCOXU4FRe8jsTYev
         ORXsqj3BI/thJVga8d15zGJ0GRCdAanYh3Eea5pIcCWU0mnxg8B3Jh7cxQAxD8wH/Oo0
         h8DwUwgzUTZ9+KQfBMmbqfs4ATgONvulBgI/KOw3dPDqCVvlzqNeprNfJAYqjR2sfzvX
         kknw==
X-Forwarded-Encrypted: i=2; AJvYcCWl9IFP+cG8qxamf12YQGtum9qP8NWhyXBLC3KlKHkt6/YOPO2Bth6im2muiPFgA59me/X40AQyXOj2iaTdxz0xIp9vQsNpHA==
X-Gm-Message-State: AOJu0YwelHSP49W+oh1IVzxPQd3MGcX/j0SHfRvHS6lyzHSI7W1UN7tY
	OLMpNEQTkjzGETeAmHfaXZZSGUTE7yibAw8KDftJvp3TZfWiqDEKVpo=
X-Google-Smtp-Source: AGHT+IGaOQiqDRGu0f4Gwl4KyGILmDpa0Jx3CHNu9B7kii/YXcRgHBkkjkDbJpcr8oCDZ2WVA6tNbg==
X-Received: by 2002:ac8:5f06:0:b0:42d:d026:f1b2 with SMTP id x6-20020ac85f06000000b0042dd026f1b2mr1051779qta.14.1708739980799;
        Fri, 23 Feb 2024 17:59:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:199e:b0:42e:5fdd:4f6c with SMTP id
 u30-20020a05622a199e00b0042e5fdd4f6cls808103qtc.1.-pod-prod-09-us; Fri, 23
 Feb 2024 17:59:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXJ6IMlgaEdTajnYe7Poesx23IKkG3Mqsp9GoeSW61puYAVPe292vumbW8leCE1DCFgOJfP3BwH1Uk18tR6p/6X03+VvjYgxxC9jg==
X-Received: by 2002:a05:622a:11ca:b0:42e:5eef:af2a with SMTP id n10-20020a05622a11ca00b0042e5eefaf2amr1099008qtk.28.1708739979935;
        Fri, 23 Feb 2024 17:59:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708739979; cv=none;
        d=google.com; s=arc-20160816;
        b=AKJUAB0Flftmqw+TEM7Lr06q//2A+X3b1NFreSMDS5hjWSwciXgN5muehEttjwHuXQ
         x/tsu8SZzqYDuWNnrGhQhgfvnPwyVwg8LArXM0CJHzMkfv96WnxRRwoOVetDY+e7mqFh
         fJRzEUBvfrOLWj5sgPs5ozlh51R5jzAIX33i7SK+It26Fk/uJuVvkwTmfGHbGIaNYYXM
         Gib+qghi1g8cPPOFs4U+OZYjI7rF6TyRUoGhBg+3y4hwiWweIdHzBIyr46DpCLzJ/ADo
         o8+FeZfkHt9SMZAuIAQk5IcB7CuXKjo/Vfu+0AuvDQz6kpHCx1WuH7kgqvtmRLLTIgGE
         cHwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=T+a2SRS9CYU21NdR/LXMyfpfOaFxGBggdHbbvAXJGNw=;
        fh=vcbEb62e3246zaCIoLakbyg4R0k+uwwCAHEF4xJLVc0=;
        b=vA3APYmKJkod+n6Pbidh5VZUqxOAVckFodz+iOTZSbY+C0+iWqEXyc2tTPsc/mI3AU
         ZVQvZwFomGsz+Sv7arIMqrrTTkeXw3lAc+MEvfjzIfDhZgTSD40Ga5jPC8dNeww7nGeN
         mjAfGRao6FRz2VpnsuKUxhFucOG94SGV4pkBndqynbQjAbQbTa6a2QB3D/4Z2DIHv/Ud
         DAIOrJBfMKbr+EyIkMW/UTtb/nkOSB7gbOn7BJBNZXFmvaXixmd8dQt+QpOcWS5R/8sl
         DpSjojACFSPsoAY3b3s95PkD7BCNcFEk/JRDM5FxeJnin/+V/H5Z4W3FTMUxDVwdJGjP
         Ozeg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="RRSpi3/C";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id e2-20020ac86702000000b0042e5ed57234si16868qtp.2.2024.02.23.17.59.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Feb 2024 17:59:39 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id 3f1490d57ef6-dc6d9a8815fso1072491276.3
        for <kasan-dev@googlegroups.com>; Fri, 23 Feb 2024 17:59:39 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXkKklINom3SPckKhETXtZyvAERnvTbtJ0RXSjO9Ny3E38RuPzKeK9L98SpDMki5yBj2q9x1QxGj6KafDFnEwJq3AMLnxCjArVWyw==
X-Received: by 2002:a25:aa67:0:b0:dcc:b69c:12e1 with SMTP id
 s94-20020a25aa67000000b00dccb69c12e1mr1515692ybi.59.1708739979162; Fri, 23
 Feb 2024 17:59:39 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-7-surenb@google.com>
 <Zdc6LUWnPOBRmtZH@tiehlicka> <20240222132410.6e1a2599@meshulam.tesarici.cz> <CAJuCfpGNoMa4G3o_us+Pn2wvAKxA2L=7WEif2xHT7tR76Mbw5g@mail.gmail.com>
In-Reply-To: <CAJuCfpGNoMa4G3o_us+Pn2wvAKxA2L=7WEif2xHT7tR76Mbw5g@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 23 Feb 2024 17:59:26 -0800
Message-ID: <CAJuCfpHY1T2jCCitt7cufKSeXP7zhh_f9gVN0UNZoOQz1cNBjw@mail.gmail.com>
Subject: Re: [PATCH v4 06/36] mm: enumerate all gfp flags
To: =?UTF-8?B?UGV0ciBUZXNhxZnDrWs=?= <petr@tesarici.cz>
Cc: Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, kent.overstreet@linux.dev, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
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
 header.i=@google.com header.s=20230601 header.b="RRSpi3/C";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as
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

On Fri, Feb 23, 2024 at 11:26=E2=80=AFAM Suren Baghdasaryan <surenb@google.=
com> wrote:
>
> On Thu, Feb 22, 2024 at 4:24=E2=80=AFAM 'Petr Tesa=C5=99=C3=ADk' via kern=
el-team
> <kernel-team@android.com> wrote:
> >
> > On Thu, 22 Feb 2024 13:12:29 +0100
> > Michal Hocko <mhocko@suse.com> wrote:
> >
> > > On Wed 21-02-24 11:40:19, Suren Baghdasaryan wrote:
> > > > Introduce GFP bits enumeration to let compiler track the number of =
used
> > > > bits (which depends on the config options) instead of hardcoding th=
em.
> > > > That simplifies __GFP_BITS_SHIFT calculation.
> > > >
> > > > Suggested-by: Petr Tesa=C5=99=C3=ADk <petr@tesarici.cz>
> > > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > > Reviewed-by: Kees Cook <keescook@chromium.org>
> > >
> > > I thought I have responded to this patch but obviously not the case.
> > > I like this change. Makes sense even without the rest of the series.
> > > Acked-by: Michal Hocko <mhocko@suse.com>
> >
> > Thank you, Michal. I also hope it can be merged without waiting for the
> > rest of the series.
>
> Thanks Michal! I can post it separately. With the Ack I don't think it
> will delay the rest of the series.

Stand-alone version is posted as v5 here:
https://lore.kernel.org/all/20240224015800.2569851-1-surenb@google.com/

> Thanks,
> Suren.
>
> >
> > Petr T
> >
> > --
> > To unsubscribe from this group and stop receiving emails from it, send =
an email to kernel-team+unsubscribe@android.com.
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHY1T2jCCitt7cufKSeXP7zhh_f9gVN0UNZoOQz1cNBjw%40mail.gmail.=
com.
