Return-Path: <kasan-dev+bncBC7OD3FKWUERBYPL7WXAMGQED3HL6YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id EEBFA86B6B3
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 19:05:22 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-42e93a2d979sf32714241cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 10:05:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709143522; cv=pass;
        d=google.com; s=arc-20160816;
        b=XaxayLsGKC1bTUinykfS6N3VB09ngesyPO4fFmhwN7ymZ6csTGmqyM9I7pFaEBz0nu
         CCf9N3iHKfmuR13xtjPbgaRXKy2AJ+zXDiZtWlT07b/zIz9FDHY+kpwVZScnyXq5u43S
         xlGFkk0pQSMsIYXQki9oNdytLDKLWEU2BafP0bzU+NfMiWkET9+8Bmis1X57LF8FztWh
         8EQ/1aQ3wAK56ywLH98JnYmQpPl+lKFuSeTWooHLxufGgUbIfXGd7ThcweouBJFCJYg5
         dxQTxyIDM0X2s8mEi5eNA7JOA4ciaOF6XPd3IXq+LTnu5p+UYPVb5zvSFrP8u2h/KGPj
         M6kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=St7bEMJUjTpjFwxQdc6+XwHxHo3IudeT+/pJRSPC8G0=;
        fh=vJWET6dyU+nl8A5X0vM7Fg2UwmBCA1+LQKUQECHoYKA=;
        b=BRobwzQMbmd1+3qQPOX3sgYuq920GgsggZVFXdvVtcd+8BD15ctIUTvOUEr9ORa3ZD
         6pXmozbmo4akuplVPveNmu42TjmFsPn+69qSK5zrLTmSsy+TszUEI/vDOA2SWJgDPAfH
         zES74sMtHogARPStua4FT5WYK3NuLxzsxjpYLNU+tA6XS5Ij2ixoufkIp4esIR5cQU/b
         D4fqlD3P+1X6uPVzBfurri1/M1hdMejiwKLY3NRC8YpxW7yBsYr6oZiH3wNzxLXWCmmk
         4qQmzcR4f5KpNnyK6Fn8D5aVWt6OhNGRe3C989y5ib+liPX8cARk1wh5314xN+E0xGEC
         6rXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BDQCbXza;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709143521; x=1709748321; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=St7bEMJUjTpjFwxQdc6+XwHxHo3IudeT+/pJRSPC8G0=;
        b=S5u7K+L08HifD6wN1YkDcX0NpqR3waAF1vuPFlddBpC/uBhTdkOdUYvBWzC+0b9Gzv
         VJOVMdp+8Wx1dRMtyCvN6nqQoUQNy8Sy0BDfl2+Cr9KaVX1dBfcEY9EfcNYJl0lhL6mi
         nXVDC6JirHqSQ+TiWuBjuuqHROY+RR9zFrAbXUHSgYc+gcoLdjmwnqrM707FMcLruGM0
         W5ebhALeKwY5Gtz4ArG8gwHrfLZcqpbYXHa9kZBTQEFaOkNcJCwaJJ7HdQeDEH5xxFU8
         0vtxkgBaRkJ0SLdYWSVz7oCbAxagAZ5FGsU/lBvxrTK/HxCkLImkbv7gRGkm66ZQwAlM
         iJgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709143521; x=1709748321;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=St7bEMJUjTpjFwxQdc6+XwHxHo3IudeT+/pJRSPC8G0=;
        b=G402a1RDB7XcQk5PJD5x7OnxIq8zUyB0+rt4ob/a/e6jwKYs/6i2k5KYRv0WG6FcEA
         1gK8ensmSCbcSAYxmqN3MiXG8niGnRyzaA4EfdfNSpYZ4gRAF5nQ6JAM5SUOjzVQDPx9
         oeSgKnTTYHDXIVt0yXcsZh2FHhlGQ5JFZvtcyzsNLDhjEejHOjPKcpRTCe2BCMar73EX
         Eyrp/VJ8dP8xyOgTGHNAajh973I6yA20qE63vJnFFaAp/QRszzXgNCCuKWUvo2Gze/o3
         wtrSReRj8q8asUSGZDvxUxv0dAI7/SfLlroeuWi94RsZAPVGIUxuzVCJ87b3MUi0/Eac
         gXxQ==
X-Forwarded-Encrypted: i=2; AJvYcCVwrTk/xivc/mbZydqfr4tJIVs8gig+BZ+/Yvhv4rxYnIw+qrYilWlME5qMTfWBPNrDeb2hoPq74fjBNnedyxTCwOgEIdPWpw==
X-Gm-Message-State: AOJu0YxxnFykv/LY1X6mycDABgvnyajIAO9RZMqNLGBogQ3USKnUJ2F7
	WulFWMext9nTqYnTU2O6q2By6izJ0Q5BrDHDD7o6a5KescO87VD2
X-Google-Smtp-Source: AGHT+IGNPCtQIq5+IQlY/A1wwcZccLW5xKsGH4oCtpyhtJEfh/hB7AvcwgfdqEz4Zlqjh2IhX+tazA==
X-Received: by 2002:a05:622a:1b9f:b0:42e:6341:a830 with SMTP id bp31-20020a05622a1b9f00b0042e6341a830mr17477836qtb.4.1709143521622;
        Wed, 28 Feb 2024 10:05:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:20c:b0:42e:808c:fe9a with SMTP id
 b12-20020a05622a020c00b0042e808cfe9als81073qtx.1.-pod-prod-05-us; Wed, 28 Feb
 2024 10:05:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVBsF5pa4rWVz9JiSCdNbJgMT/RWkZQOAyJULqu4XGsaEDYGgFz8sIABUR21HUn60kZCzEvSDCmkaCLPUZzkvLe8upAq6xhLlfuLQ==
X-Received: by 2002:a67:e313:0:b0:471:c058:8a94 with SMTP id j19-20020a67e313000000b00471c0588a94mr290252vsf.16.1709143520853;
        Wed, 28 Feb 2024 10:05:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709143520; cv=none;
        d=google.com; s=arc-20160816;
        b=peo/5ALEXafpPuwHqOlSk/KjY1SjgN+muKs1BHFz/S7JvCHItwIKz/EZjeOp9PSn1y
         zHOh0JJtQJqwlT6wHlqgMRDL3mCLXA/VVMm2v69NC8EMMk2FCFwJkIiWc9dwfIwnT4XD
         WUXgBedzbA9MPf1SKeFqmAytYp6uVi9AD6fry5TN6vn3yuKCTkYgenAWj98zfy5liJto
         OaN0dIYLS2rS8+k0nKTt/Zc+NN8zkQPKDJKO34CAfTjhY54rTj7fFCmrNhdaVY/xISk9
         qRGbNooX52ZKFOajnegshaZloAnShUXpq6Db2a1G95YHp77xD0s42oxPos9+IRDkdolP
         CHMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=M5RWLefMMZcrjC6ohvg7ZMSlCbzmM6eu4zL9kM45cas=;
        fh=Qzerta+LKtapP4532EphI9abKDgYtcCFAIqQNqpeV8s=;
        b=F8oMSAIADAOZPUSRFeJYPl9cSqq5PWgTyc2kQhsEu3tUmMHY2GWU38tuDEsgM0UhDZ
         iiFN6Fh2B3ViVkiqj37z8cnHpeWpm+PhGxFXoMODOlrVepkuSb1XC0cl5g1UTtfMb6kF
         sx2XqMItbGYJM1ryL0KXtg71adyvO7Kd/Aef1AzoSiU9p1CTAWSJSEMTlKVqmzVgxDsv
         RXR/z5fJ0GypmPJYowOawGWD7FBgpMoajusVoaf7b+kpQdNKiY5MNPKXoZ/BsJHAD1nd
         +6Up4fsv5+9hepAZlkPSaBdFFQzQKId+NCZXfGWaiHs1jnd+aZMbrxrUBGhItuKxscuj
         mkXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BDQCbXza;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id e4-20020a67c504000000b0046d3986403esi7321vsk.0.2024.02.28.10.05.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Feb 2024 10:05:20 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-6087d1355fcso335457b3.0
        for <kasan-dev@googlegroups.com>; Wed, 28 Feb 2024 10:05:20 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVez0p0KEJVzP5zD42E3FasWJK8BAGP2a9pwoy6gBEEBMaIq15v76oHGenLxcRqqOoeNl2SJ0G8roNnru/1BiSNhNxqDzOzlOB/rA==
X-Received: by 2002:a25:4687:0:b0:dc2:398b:fa08 with SMTP id
 t129-20020a254687000000b00dc2398bfa08mr21101yba.31.1709143520037; Wed, 28 Feb
 2024 10:05:20 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-15-surenb@google.com>
 <1287d17e-9f9e-49a4-8db7-cf3bbbb15d02@suse.cz>
In-Reply-To: <1287d17e-9f9e-49a4-8db7-cf3bbbb15d02@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Feb 2024 18:05:08 +0000
Message-ID: <CAJuCfpGSNut2st7vKYJE7NXb6BPjd=DFW_VEUKfw=hGyzUpqJw@mail.gmail.com>
Subject: Re: [PATCH v4 14/36] lib: add allocation tagging support for memory
 allocation profiling
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
 header.i=@google.com header.s=20230601 header.b=BDQCbXza;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133
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

On Wed, Feb 28, 2024 at 8:29=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> >
> > +static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
> > +{
> > + __alloc_tag_sub(ref, bytes);
> > +}
> > +
> > +static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_=
t bytes)
> > +{
> > + __alloc_tag_sub(ref, bytes);
> > +}
> > +
>
> Nit: just notice these are now the same and maybe you could just drop bot=
h
> wrappers and rename __alloc_tag_sub to alloc_tag_sub?

Ack.

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
kasan-dev/CAJuCfpGSNut2st7vKYJE7NXb6BPjd%3DDFW_VEUKfw%3DhGyzUpqJw%40mail.gm=
ail.com.
