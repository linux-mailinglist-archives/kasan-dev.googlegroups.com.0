Return-Path: <kasan-dev+bncBC7OD3FKWUERBCUZXKXAMGQEMYZQYBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 3034E857033
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 23:13:32 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1db28bd4f77sf15438625ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 14:13:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708035210; cv=pass;
        d=google.com; s=arc-20160816;
        b=HvaOvaHRFQSyXUUk8FMSTIiz/LBpA1fc8ctjCMYYYOun/TtDVmJyNj01KPlCP/4vgQ
         Pbd6BwwCAyejp/LMSmoonUNZSNJFijQEYwIOLxMiy0D70elv0dcB/tIgULGxJVJtO0DA
         Bq+9lKlTwjL8/RLHXvK33pE1lVce4s4dRb/i5w02hiW5xHHQf3pKutd8eCDYkVoe3fhc
         SJnA0ZnvDV1x4z0b9jaP9hjx4tipEVsJyr6MPMNiNPkGgIjPDNAxJYI/v0kiAjFiKrS7
         J6m/uDs/0nO+kbgjMS+msDhblkmmNiRb0JAJIAy30HqGLOO1uy6+1+W3UcAUMAdRbUJw
         xoLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=t/k5ofkaTrPU1E4+09TXpaKGwkqE8/xennP7NX44+JM=;
        fh=Q736YP96F1qOnABw55Jm7yuaCQwZsDcbbjKaW2Z5uAM=;
        b=ft9IJc3EpHJ4yU1iRMS1aBXMAkDLxeB1D8NZgDnkCZ+2xusBF9mkYys5yg4Y8lXkbK
         R2w5Cm+8RC0Iktqq5SPrme3ghcQXBJeglpImjLK48PdklKO8UzTd3/8GsHgUn2Hv50pt
         H83Cf06nbfbXM55KjkldAkBblVSsol7l5h+aMSERaxHTO6UVqaNlG0otIxwSso/sagSC
         y+2pd45YrJTv8Gh6tYyqTqKZG1WvPVNLEmaUDNwZzMZq6G57Y+kYk3LGE/wcAJQlLInD
         sLioZ9DXGPYo4WqvaHwRnURcwBzrqdqIjKFCpSCD3Afek7s79q0Lanjc7VEUxuJtWvJO
         GM1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XONahskZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708035210; x=1708640010; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=t/k5ofkaTrPU1E4+09TXpaKGwkqE8/xennP7NX44+JM=;
        b=d24jxpcRTmNSpKWZJfm3WzodQp5NOiMUKbbWCzl1n+s/txl8dg6LksxvOwzflAj4UF
         NvvujK/wtdPsudhY2HGyCprCYsQr8OQyZx8cplS/KEaRvvT7JK7vpUmziAmHFN+9FkMg
         /v6tFgXT63HBgcQp/3zxpnfjbFzLB84Hxz6TGgww2W/Ts8BwJ6P1IYJXiyWF10YevywT
         yXK8V2CmA1dNraYPuU6H8QvasPhJRo5rZAdmcDVVrvTBdKJceYcQ1xIhZ+PUC3o1pUKz
         kmiRnAsGxTOXN6HK5MO+EEevHbXOBkhJnIfQ7vLVL55SnzHfyyrhT9N/a0O7Dld8Jegd
         b+aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708035210; x=1708640010;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=t/k5ofkaTrPU1E4+09TXpaKGwkqE8/xennP7NX44+JM=;
        b=EjwLcW48E/m+kbtm3Vzfcn1AJbYVxAfu0vSWDPcsMHqN+MBpQTlhNWlyp1sJ2TQDgH
         d0Add0axU033Yz+nSbxVibKRQ51zSBoGR1shrhgLep3H3ono6CFr+B81B3VC+hcFuqZM
         0uIMrpcMrRkHxVGg09EFFUG/T+pDFBUrwVQAkuWrHKEdwndwk1PPPJMOFEytzr5ohoN4
         3ydH+7c7L2UWEuI3bxoGMIBiNZvKy3DVb/adL4jzOJWZBrzf8SO+WJjbHtYgeZ6889+b
         myjL6UHB/CRSIUmitbNEQIf5U8B/BIoP9AT+y4j1sMRbAfhHQFjz9jgnOU6etdnsPS5n
         j8iA==
X-Forwarded-Encrypted: i=2; AJvYcCX2Q25iPJ1W+NEmMojHIPOWa4quV876vrvvD0OAijNNTsi+tJavmdv/hxx5QCvzbqya/txlJgoc+qtJQoDvg7OZvp3AojuG7Q==
X-Gm-Message-State: AOJu0YzJvi7e3To00guCJ/KwXx9GroaqzhNo0xH6NwTjOE/Eb65/wQhW
	5tPMwsXh5HhLnmoas85pCmj6DnoqgeMUaYVRxdRQvuCsQDc7iG47
X-Google-Smtp-Source: AGHT+IE+ABh83vhOAD4sMeUvTO3ZibkXGECsGAwMQkonVwSG2IhQbA3VPXaSdJ3AEqDD7re3oEN81A==
X-Received: by 2002:a17:903:40d2:b0:1db:916e:d77d with SMTP id t18-20020a17090340d200b001db916ed77dmr1240764pld.52.1708035210513;
        Thu, 15 Feb 2024 14:13:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:3295:b0:1db:2ca9:b5b8 with SMTP id
 jh21-20020a170903329500b001db2ca9b5b8ls153930plb.1.-pod-prod-07-us; Thu, 15
 Feb 2024 14:13:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX73GdyKtn5MwwGhBym1kZ9CTm8ESFHSVFBRNr2AxqTHF7M1eUynZasAo9RfhFuY40wMAzY0Vu+0NYtheW30A5K/okFP7FhElb4YQ==
X-Received: by 2002:a17:902:7898:b0:1d9:3b98:2709 with SMTP id q24-20020a170902789800b001d93b982709mr2171136pll.5.1708035209413;
        Thu, 15 Feb 2024 14:13:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708035209; cv=none;
        d=google.com; s=arc-20160816;
        b=fERGFyMHphp0pyCqDN8pjrVEteX1F7bEesKEedak8yVWoQf4kKiQ98zkdoPNfbjnV4
         DC+UFy0MDwWzaiYYm+HTL7m/DsNFIazHFNb5SfPRxmT4NlujMk+FKqC6G4gYUTGxmNVx
         ghcjIuCxdXqUS7nc5J37ZFe3GgZVptaBD4zzGI0XLl8N1nX2kxIsNgNQkdp86pCNhf7g
         JPfizVjKhmAw8/a2iBLo4HeTw8hVxGGHox4HZ0+T5IwSSVAhNdgMDnlsg0DL0/CC7KLx
         O5Z8fUMQfV3olQHO/32JnirZzPhSxh+/vs6BhCGXVTzStwuJt8als2hJYH9H+RyVNAbL
         y8Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vVXTqIldo+bBUN2qGPMpdu4xA8ur5OmocrNHlsGX//8=;
        fh=P89awllb10RXTT+KaGzqhcBrS5kOxl+1DWXaRtbQZAc=;
        b=v/wPHTvDtEDimS661xJXaD4uuh7eKw5CYc+aP239Ay2oE4VIMuD7NwfVjEVD0HY8ME
         6KGxFsvgDz27H8yxDQlvM0jhbkdRvsgSJhgJYw9duMSNZg0suJPO8E9hTGK0eg/RPoyu
         WvQjO2pVo03NAAoDbrcVNgcVP3WF+5P53c3St134ZiuLeJORd/C+ztS1ZUIcATjRQ86u
         ZTbgSYAKWYBG+cYJiUmbyouydCku8TyzjBVnB7Hzg0JtFoG8wOU+KZRQTDSKI6h+DQ7Q
         tbNIlXA8BsTp3cIZ+5JFWYHzMYEAmTEVoaQRaNTr0SYQc+GcpjsdgBSrDhAGOZk7lops
         b0UA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XONahskZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112e.google.com (mail-yw1-x112e.google.com. [2607:f8b0:4864:20::112e])
        by gmr-mx.google.com with ESMTPS id li15-20020a170903294f00b001db2d80f80asi140340plb.11.2024.02.15.14.13.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Feb 2024 14:13:29 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112e as permitted sender) client-ip=2607:f8b0:4864:20::112e;
Received: by mail-yw1-x112e.google.com with SMTP id 00721157ae682-607cb7c44a7so13009537b3.3
        for <kasan-dev@googlegroups.com>; Thu, 15 Feb 2024 14:13:29 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV6tWr6RBe0yu1s/vK2ctgKwdGZSK3OG0HPaKv+Fi+tY+YD9boARi2exh6GB7hkrfa8EzEG1b4/qaIvvD3q5LKcQmcrffIdc1pXXw==
X-Received: by 2002:a0d:cc4a:0:b0:607:cc6a:dcc5 with SMTP id
 o71-20020a0dcc4a000000b00607cc6adcc5mr3136666ywd.16.1708035208322; Thu, 15
 Feb 2024 14:13:28 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-9-surenb@google.com>
 <02cb04cd-0d8d-4948-b3ef-036160c52e64@suse.cz>
In-Reply-To: <02cb04cd-0d8d-4948-b3ef-036160c52e64@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Feb 2024 14:13:17 -0800
Message-ID: <CAJuCfpFj_vboiRZvpeuRpYK6ma-j-x2ry6dFbkaC=K51m8bQxA@mail.gmail.com>
Subject: Re: [PATCH v3 08/35] mm: prevent slabobj_ext allocations for
 slabobj_ext and kmem_cache objects
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
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
 header.i=@google.com header.s=20230601 header.b=XONahskZ;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112e
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

On Thu, Feb 15, 2024 at 1:44=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/12/24 22:38, Suren Baghdasaryan wrote:
> > Use __GFP_NO_OBJ_EXT to prevent recursions when allocating slabobj_ext
> > objects. Also prevent slabobj_ext allocations for kmem_cache objects.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  mm/slab.h        | 6 ++++++
> >  mm/slab_common.c | 2 ++
> >  2 files changed, 8 insertions(+)
> >
> > diff --git a/mm/slab.h b/mm/slab.h
> > index 436a126486b5..f4ff635091e4 100644
> > --- a/mm/slab.h
> > +++ b/mm/slab.h
> > @@ -589,6 +589,12 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s, g=
fp_t flags, void *p)
> >       if (!need_slab_obj_ext())
> >               return NULL;
> >
> > +     if (s->flags & SLAB_NO_OBJ_EXT)
> > +             return NULL;
> > +
> > +     if (flags & __GFP_NO_OBJ_EXT)
> > +             return NULL;
>
> Since we agreed to postpone this function, when it appears later it can h=
ave
> those in.

Yes, I think that works. Will have this in the same patch.

>
> >       slab =3D virt_to_slab(p);
> >       if (!slab_obj_exts(slab) &&
> >           WARN(alloc_slab_obj_exts(slab, s, flags, false),
> > diff --git a/mm/slab_common.c b/mm/slab_common.c
> > index 6bfa1810da5e..83fec2dd2e2d 100644
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -218,6 +218,8 @@ int alloc_slab_obj_exts(struct slab *slab, struct k=
mem_cache *s,
> >       void *vec;
> >
> >       gfp &=3D ~OBJCGS_CLEAR_MASK;
> > +     /* Prevent recursive extension vector allocation */
> > +     gfp |=3D __GFP_NO_OBJ_EXT;
>
> And this could become part of 6/35 mm: introduce __GFP_NO_OBJ_EXT ... ?

Yes, that will eliminate this patch. Thanks!

>
> >       vec =3D kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
> >                          slab_nid(slab));
> >       if (!vec)
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFj_vboiRZvpeuRpYK6ma-j-x2ry6dFbkaC%3DK51m8bQxA%40mail.gmai=
l.com.
