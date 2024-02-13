Return-Path: <kasan-dev+bncBC7OD3FKWUERB3HRVKXAMGQEGEW3YQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id E37808523C2
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 01:33:49 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-363da08fc19sf31890565ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 16:33:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707784428; cv=pass;
        d=google.com; s=arc-20160816;
        b=m9C1/eJwa01Pp/t7NF2u/yqH4xPA0raZIRFxuPBZPBFOOiNkQd5QvUW5yrrjqynrvN
         wGUImH3e6lkEa2TEt8JxOgKFAJhTPVcUuuRi4ECJFDjh6aLABkgyzDvZEzBom7zSTxQX
         z5JC1jax9kd+uEql91mLiEn/9GtNL7lg+0jx8vHCQ9cx+7aaXtOzJYWvLNE3Sa09A1N1
         sU6m8eEDkxlEtuJ3HAQhSiA4M+R9vRaaIsrOz98xAv3ZKUY5Z26+5N9wsyX1MpfNS4ra
         ww/ehlC+yHoHTxAMHDUJHGJDocX/t88PMEKg8v8FLmZIUN1dpYZJydh0lsiZbpBoVxVB
         80Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SJpKM+A2QWojbnwH0G+BUvQZudkoPNVWoeZyuH2gP1k=;
        fh=BgMhlJWY0FA91U5/iUp0nuZZ4xUjCeVRXXpMDHNwxEY=;
        b=SoDLoKhZRBiSziUa1wnN+tCKbFCT2oUItvq1ODQ9uJp3aX4+BJ/jCi4UsRxO6jUrfg
         lZjHblr9Kt6Tvi2LCF1b8Hv2ltxdG4d2cHQ7H+CIUDhBShIiWdaORHavdcD73TQkKaq2
         p+htWyc9u9ITa8eZbsOqfi3Fsi725aW1MZYhvlqy0VqHUpsqA3iGGwutf3SkYnf7Uqw6
         PtEZRTWs7HEDAAZoHf3vuuEg7RLEsSC6DwOiubwKZ6SF2xPe1LQh5DS5i8tohQ5eULKC
         BT4iPkcXq16d8nJn0G6JzDSJ3QOyOA0yRvzku8nia552aEag6dBixEJgpoiMQguzspG6
         FFeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=M70dimzf;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707784428; x=1708389228; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SJpKM+A2QWojbnwH0G+BUvQZudkoPNVWoeZyuH2gP1k=;
        b=UqkWWDQfdqiWgNFbPObmOe8FtCcCsKyrrdujtA4179JdnYEFLUmE8gxEfAqKrw4Ap8
         I9B16QUFxFt/uL6A9/3D5DSkMDZfaokqdNokvjzz1J8xOjQR5/G/2R9Qgp7VXxk54/br
         Obac2UK7AebsuaGSkM6UMteldGecsxiinP8fF8S4kHZu0dDunHhQUnWuofdBXYBeiokO
         ZWNrzlr66z+uECeGlvnrBjyibmd5xafU4jGTvIOgFT7kRlAveNdI3e4bfyezEmV7GahY
         lTS9ebCSPqn07Wd9Jpv64fhxMQeEXFAgpmVzLHkHtm/eNBFR1tGMZck6lv0kklvQTmAN
         yAow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707784428; x=1708389228;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SJpKM+A2QWojbnwH0G+BUvQZudkoPNVWoeZyuH2gP1k=;
        b=ki8n0Eo32n2J1lJqLVsEc6NVLWTCqg5S/ZKZcIum4e5ZxPdcs6ZXCEPza8MKki71Nx
         9urh6QW6UEE1zDNPoh0ie4S7pwMmtHpS67T4C7l7f7H7dx6xwjSXGevPu7+/rAaJdvAR
         a+KItYSn0sWB5jq+1FXMGs5As5dnybeXsRUi9wSz8ZiV8H0qxfQfK/TTLABvB3Gm+Bbz
         sjGjgV685GQdnytqDgme21rrxBaFw2EAQaUwakM7ZnIA2QpZMDS6/H7VEjl+NxikDyhY
         6igSqAFmLMxIw7othP+8LyJo4kagnBluH7x50EFf8l4K62qLAd40zScXGoAD8Jm1pVo2
         secg==
X-Forwarded-Encrypted: i=2; AJvYcCXmT18OuOVOOs3zo1NeHkXuRAPBJu0e7LcpxQMB8UDnuw1R2ieyS3TYy8kEuv8Q4mYWe0eRYs8+aJMPJZYqlw/w6V8t+MAAxw==
X-Gm-Message-State: AOJu0YzJn6lOL3kyLcp97OocTJlo56A0sVFp1wnw7XHcHXf1cipdiE4Q
	yeyDuPoad2cANdPolSMo6WqEmnzZqgg5iTfliE08PnVazzlScVgD
X-Google-Smtp-Source: AGHT+IG0IHtMHZ7M39Fv5FvtsdskT/Wq+bHdY8TvQbrRSaPXoFKHHqwoH293lfOHum4RxGOBZQ0A0Q==
X-Received: by 2002:a92:d4ca:0:b0:363:cac1:644 with SMTP id o10-20020a92d4ca000000b00363cac10644mr9364668ilm.31.1707784428715;
        Mon, 12 Feb 2024 16:33:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:32c2:b0:363:7733:5749 with SMTP id
 bl2-20020a056e0232c200b0036377335749ls2088298ilb.1.-pod-prod-07-us; Mon, 12
 Feb 2024 16:33:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXDDgXTpRnY37t/a4cSm4x19vljxnhBteGbfENuHSDYdASLSvAQC+gqtSnWpstXHcU9mrS0cFqejI89bq+lnklLSvPqpzDkW+c1XQ==
X-Received: by 2002:a05:6e02:1a2e:b0:363:b362:a2bb with SMTP id g14-20020a056e021a2e00b00363b362a2bbmr12850066ile.32.1707784427977;
        Mon, 12 Feb 2024 16:33:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707784427; cv=none;
        d=google.com; s=arc-20160816;
        b=GOTFzVdVr6sj6Nqd/g4buufcqEcX+7QW3Z6KUHCfLxP3RoN1l+mxKYFQQDZElMOymo
         jbMQBcl4fu8/SW4wkdLL7gOLpNDva3fMUt6E3vi5oRhPKERtx0XPcqbYd9UGHofR7WBm
         b0fGbcuPzkqtaQFSZKg9+ZXxvDKDS4C+Yw7ZYrCMtmMljRv+DXnWxq7TmmOV9d2a4649
         7Y+tifIXiHLFgm7XvF+Wi0/Pi8FPAvG8lg2urgFHQH4eGc/MLALFcj5TJFN3nHsGiEFl
         5+jpq2X6qeSo/u4/SS9lUCpRNDYImqPjOH6yDxa+Co5ewM+ZEterwkHUtxPcRK0afpWn
         Rrgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0zKsIvn4BR7Vnfqbap08Xbsf16NSeakKE4Kz9sErxMk=;
        fh=ok3e9TACUdS5S9gIWhsB1OQXYnFNjL3v7XmY6qZZtvM=;
        b=UoQnNi96B87gmTssSnCc8WRxcKEw/FFwpwtH0tRQFhRQBSMaPmHRM2okI7qgfOvyky
         iIQxiEP5Cor4YZtWC6rUGlh9dmNxGvWEUxAtYSlhazG2g/ayou6fOGrYLiZMs0Zm1mVB
         /Glx6HhW0T85jhkkqru8RVVdW2I6/VFHL7qMS/oerVZAAECmJeR9fORwwITF7yISOaWf
         sJyp81bgjJGb5Q7tWPC5sCKqGXtomRVxkHSDbC2US32VPzhGmEUZfht9qXNQaHd9NYNS
         +7wAMVHIIrlBG2msCHVp53N6ICoeHCsmkmYe5N/L6pQGwtnceD1vjoiagjjHjlWGj0c9
         W2fA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=M70dimzf;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXPFWbKp1q8fh7fYsN9QGVtXsodOmc+ZnV47kFgE5TORmVm39FWD4DK2mxUqZlTsbUIilPOGbvWW9HO4qmPvMYeV1MhA5PcX3jxog==
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id a16-20020a92ce50000000b00363a9324ffcsi699353ilr.0.2024.02.12.16.33.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 16:33:47 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 3f1490d57ef6-dcc660ce7a2so232087276.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 16:33:47 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUGc18iM+H+UVxASQdNsgo7x5X1pQ9yNxaheoxtJRR+IHhP886rXJJBW/wUt6w+cQceDw3pXns+qsn49HV+oWD76SXC3OAAT1bKFQ==
X-Received: by 2002:a25:6dc1:0:b0:dcc:693e:b396 with SMTP id
 i184-20020a256dc1000000b00dcc693eb396mr465601ybc.2.1707784427206; Mon, 12 Feb
 2024 16:33:47 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-36-surenb@google.com>
 <202402121443.C131BA80@keescook>
In-Reply-To: <202402121443.C131BA80@keescook>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Feb 2024 16:33:34 -0800
Message-ID: <CAJuCfpEkC9FXACy02PM6GTF_XHQ0XEN6UVpFzGxYNnPcFv8irw@mail.gmail.com>
Subject: Re: [PATCH v3 35/35] MAINTAINERS: Add entries for code tagging and
 memory allocation profiling
To: Kees Cook <keescook@chromium.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=M70dimzf;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as
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

On Mon, Feb 12, 2024 at 2:43=E2=80=AFPM Kees Cook <keescook@chromium.org> w=
rote:
>
> On Mon, Feb 12, 2024 at 01:39:21PM -0800, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > The new code & libraries added are being maintained - mark them as such=
.
> >
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  MAINTAINERS | 16 ++++++++++++++++
> >  1 file changed, 16 insertions(+)
> >
> > diff --git a/MAINTAINERS b/MAINTAINERS
> > index 73d898383e51..6da139418775 100644
> > --- a/MAINTAINERS
> > +++ b/MAINTAINERS
> > @@ -5210,6 +5210,13 @@ S:     Supported
> >  F:   Documentation/process/code-of-conduct-interpretation.rst
> >  F:   Documentation/process/code-of-conduct.rst
> >
> > +CODE TAGGING
> > +M:   Suren Baghdasaryan <surenb@google.com>
> > +M:   Kent Overstreet <kent.overstreet@linux.dev>
> > +S:   Maintained
> > +F:   include/linux/codetag.h
> > +F:   lib/codetag.c
> > +
> >  COMEDI DRIVERS
> >  M:   Ian Abbott <abbotti@mev.co.uk>
> >  M:   H Hartley Sweeten <hsweeten@visionengravers.com>
> > @@ -14056,6 +14063,15 @@ F:   mm/memblock.c
> >  F:   mm/mm_init.c
> >  F:   tools/testing/memblock/
> >
> > +MEMORY ALLOCATION PROFILING
> > +M:   Suren Baghdasaryan <surenb@google.com>
> > +M:   Kent Overstreet <kent.overstreet@linux.dev>
> > +S:   Maintained
> > +F:   include/linux/alloc_tag.h
> > +F:   include/linux/codetag_ctx.h
> > +F:   lib/alloc_tag.c
> > +F:   lib/pgalloc_tag.c
>
> Any mailing list to aim at? linux-mm maybe?

Good point. Will add. Thanks!

>
> Regardless:
>
> Reviewed-by: Kees Cook <keescook@chromium.org>
>
>
> > +
> >  MEMORY CONTROLLER DRIVERS
> >  M:   Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>
> >  L:   linux-kernel@vger.kernel.org
> > --
> > 2.43.0.687.g38aa6559b0-goog
> >
>
> --
> Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEkC9FXACy02PM6GTF_XHQ0XEN6UVpFzGxYNnPcFv8irw%40mail.gmail.=
com.
