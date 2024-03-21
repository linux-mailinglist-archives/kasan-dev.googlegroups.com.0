Return-Path: <kasan-dev+bncBC7OD3FKWUERBLWY6GXQMGQERLGVOTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id A16C6885F85
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 18:19:43 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-366a7e3099bsf12486155ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 10:19:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711041582; cv=pass;
        d=google.com; s=arc-20160816;
        b=F0Nm77d6o1FQ1PK9hoy0F/0kJPeHT+9jX15ry54bEaTb4n++WLYKiSJEujqlkzRsFR
         /y+rLPa1qNOT6e00S7OagrYt/JzZ8EKmcLz8pjOhkKjDm3mbpy8/B2ACfLKtG7MhvF7N
         3iswemfA/t5Bp6/9TU72H80Ig8KZxeZZypVn36tYduGS5lYgpPJrL7g2dC9PRJbfHuQZ
         j4ONdkIMVA/VdEvdO51qqLwPwrVx8lBmbJ+kUy3K8SUCUoMiXkZHUUG1pvhgb9ou8Qhw
         V8OtJSnSKhiGFlKgrQldSwGb3nHTi71ajZSaA7N4WAjxVaoQ7q3j5dn85u6G3nk62nWW
         mRSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lnLcrco3bCaMBuuKT7/i3h5ZaTGV+qclhEsNwBztec0=;
        fh=2xHi2A5tQmCkYw+aIjqKW+LbS5GfwB4joiy4J/nyLQA=;
        b=OJGlxKo4mEOaqTU+S1hAWPKdj7z1J69l6MmV368Y87lytH6hrTyYVarOiKBjdQoqtZ
         EzmCcOaD+93nlMnfvoOskmU45CJx44kmZm1KyjJYcQDPAyMDakz4eLp6+t6NS2+f2yVE
         xMGqQTypzWD4v1eijiAhD2pXADxQVZlxuiOn/C3YIUtuiqjE3OC2ZINeXfeJTUceQQWe
         qyrIHlhIUs8T7miUgDJy/q8KMuLo6Ir5AmOgA28rWDXBqU7Rrkqz1NMrBtvnYudwevT8
         wzLc0BVxDY7pQ3BAkwX1CqZoiZKbZplP0l617i/MRFO/AAmZfH+2d78aDliq/Qn6Z1ue
         VTBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=We18dVod;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711041582; x=1711646382; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lnLcrco3bCaMBuuKT7/i3h5ZaTGV+qclhEsNwBztec0=;
        b=lOctL0hx/mK4nVvHsdV+IjB3u6QHsdPAaG0FfacdtsHxqh+T85cSUQFg1Xdvv4UcOy
         nCeZJY4m2EJDCjqTaHTCuftAJ16nSZ888wM1B5E9rRh8AYK9+GofCi4xSmfMG7MR/ia1
         cplaOlz6NAKeqlsQoesJvxzPihbhNOsiv6Ez+BgCPxv42PaNk/LJwxFx7uRjGrGJyU4P
         4MSeb6qTmLi0Yg9/bA/pNyBCmIi8TMiA/xedNc4CdT+mNn2nVQjrJ6dKB72gnPxje5/m
         B4RydIERPz6FORTk5Sis1AWSyjcptEmBfq8eFj3MTTG3f0FZxErlfkAB8MAL2qCd7Ls7
         2ziQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711041582; x=1711646382;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lnLcrco3bCaMBuuKT7/i3h5ZaTGV+qclhEsNwBztec0=;
        b=eS0LaKOtL5wQcutERZXDI4A5Ax2d8qa5lL95sq25Hcn57F/YeieT2tbBTfssfpXOsW
         oI2DqwgDiWa9hCnJCQnV7ehP4Fv/NjhljsDiliUv59IA2SZfvwirAyhYOi9O79+Tsmpq
         tF9spAeFf6ca/tQ1Y70PEfbZPuQueZ8l5aKSPdcYFYv92CWz1gsPNWsZqN3LXyGEX7rY
         keBn1P33UzwQJzB5xGUVdGwLsyff/Cc1KO45NPDfbRcbPknZFBHwSKpKlJ0HIygxIk5o
         08zJNTf2EbFgHp0jyLkPClLEUC9Jkz4aEViTLXNqNe1zLl71PTCfn/uinWLYSFeyg5xA
         VEFA==
X-Forwarded-Encrypted: i=2; AJvYcCWIVBZqzkkcIOoRi889M6c7QdimWlY/rnZ3BtwGzYrKMJ1TwkXUFN2x7t/L3Pl/gcGEys8sOLdUuwnuf2F9VEw1GXZlLFSaeQ==
X-Gm-Message-State: AOJu0YzvKhK+P876H76gwyomORuzOyXytdTc2RO9KhA2YlFWSSKDFdyY
	/l/hxWYVYL0V/x6PdqpV1cPtkAEq8iq9cp5STAQEW+PjfG51WOtV
X-Google-Smtp-Source: AGHT+IGT0Rbp+Vkoyn0kC9cFkb0QRsht1GS4nEW+T55uKv168Iw+dysi5GjgmnzEFntyG0wNWMPfWQ==
X-Received: by 2002:a92:de0c:0:b0:366:97e9:c9c1 with SMTP id x12-20020a92de0c000000b0036697e9c9c1mr178140ilm.8.1711041582462;
        Thu, 21 Mar 2024 10:19:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1526:b0:364:ed2b:1f69 with SMTP id
 i6-20020a056e02152600b00364ed2b1f69ls830004ilu.0.-pod-prod-02-us; Thu, 21 Mar
 2024 10:19:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrg1ZS2ijhZd2gnu0VxD8mIDb4ssOa8Y8R3JLuDzMm2yavRcb2F6xK2uLqxty+b84iICCicO7S9JmM2UC772Ec962vjZxDlk0voQ==
X-Received: by 2002:a92:4b11:0:b0:368:4f1e:a4fa with SMTP id m17-20020a924b11000000b003684f1ea4famr183416ilg.7.1711041581546;
        Thu, 21 Mar 2024 10:19:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711041581; cv=none;
        d=google.com; s=arc-20160816;
        b=nSXYsfLg2bwu/lPU1trbCnx6e2xGRfhu6DQvSkrofE4y0FvqdOwLZ5Y5riV62l/nUM
         h9Bu3Lh/SZvPac4ipTJO113zPSwxSQOwel+X3661wg3GTE4jH9FEKw5Nl6GSPj8YD79Y
         8mlNJzQbxQ4lqBsdYiaHQXKz27RTEJcSxFdWJ9RJ3C6FiWC3xKnhpVzuBkjw8f1wu2Ec
         eB3mH0hEPoYQmBZki+0BT+BpnNtWYKO//nMzRItoM6IMeUckcWNRDAbfLAyMgd/yagZz
         9J2R1EUfFyb1CPwfBrbidvfLyTFgv2NPDOZS17fvHVmWsW5eSqZWhvJKQlSBeYa2WRBp
         RDYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tqvfQSGh+Xzm8qjoxKwBWCT5Q1J0hViT+VZ+PA5jO/g=;
        fh=UV+VbZK+uBTDh8LUpqYhxr69Rn5BROS3SVtDEGyATVg=;
        b=SCe9bZMbesxeDiR80mwmf8IzlQ46perfXyl9UOKwJiK1GV4AU2vEQ08vPqZDM7wuxu
         7OQ1xj0PoU5vWmYIGN0kkzythSvjM3QlrQ+LuXDbKzn7a9WhqItl6JBWpbpx4krToxR8
         o5/Ea3ibCBYn9K312vTWSxSnpQvaZ1ggyibxPx9Q5OjIS7n2xjB2jIMc9MYVKMubhX1C
         TcPFOI/r1GjbcuHdP8PYE4zseWN1fls3ZKDhgUONn+GBfCM1cxMSDC6D8bd8Pvr5ShyL
         hwjsQSNDcNYxwAldIflRql8SO2IPU3gMcSQOFkjCWp0ZmyUMVhZopChc+Mk2Tx5KdG42
         O4Cw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=We18dVod;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id h12-20020a926c0c000000b003684959ab24si14275ilc.0.2024.03.21.10.19.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 10:19:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id 3f1490d57ef6-dcd9e34430cso1296984276.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 10:19:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVpRGwgGh5xxtPuNhRO23RoRMJvzhd2DA3uknkgPOrjkvvj26gAs5LyYUKzqz70wKFLBto34UCXjPb6EpZSmqRbCExr1i6m0pE6og==
X-Received: by 2002:a25:dc4a:0:b0:dcd:4e54:9420 with SMTP id
 y71-20020a25dc4a000000b00dcd4e549420mr19795790ybe.5.1711041580565; Thu, 21
 Mar 2024 10:19:40 -0700 (PDT)
MIME-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com> <20240321163705.3067592-21-surenb@google.com>
 <Zfxk9aFhF7O_-T3c@casper.infradead.org> <ZfxohXDDCx-_cJYa@casper.infradead.org>
In-Reply-To: <ZfxohXDDCx-_cJYa@casper.infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Mar 2024 10:19:28 -0700
Message-ID: <CAJuCfpHjfKYNyGeALZzwJ1k_AKOm_qcgKkx5zR+X6eyWmsZTLw@mail.gmail.com>
Subject: Re: [PATCH v6 20/37] mm: fix non-compound multi-order memory
 accounting in __free_pages
To: Matthew Wilcox <willy@infradead.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=We18dVod;       spf=pass
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

On Thu, Mar 21, 2024 at 10:04=E2=80=AFAM Matthew Wilcox <willy@infradead.or=
g> wrote:
>
> On Thu, Mar 21, 2024 at 04:48:53PM +0000, Matthew Wilcox wrote:
> > On Thu, Mar 21, 2024 at 09:36:42AM -0700, Suren Baghdasaryan wrote:
> > > +++ b/mm/page_alloc.c
> > > @@ -4700,12 +4700,15 @@ void __free_pages(struct page *page, unsigned=
 int order)
> > >  {
> > >     /* get PageHead before we drop reference */
> > >     int head =3D PageHead(page);
> > > +   struct alloc_tag *tag =3D pgalloc_tag_get(page);
> > >
> > >     if (put_page_testzero(page))
> > >             free_the_page(page, order);
> > > -   else if (!head)
> > > +   else if (!head) {
> > > +           pgalloc_tag_sub_pages(tag, (1 << order) - 1);
> > >             while (order-- > 0)
> > >                     free_the_page(page + (1 << order), order);
> > > +   }
> >
> > Why do you need these new functions instead of just:
> >
> > +     else if (!head) {
> > +             pgalloc_tag_sub(page, (1 << order) - 1);
> >               while (order-- > 0)
> >                       free_the_page(page + (1 << order), order);
> > +     }
>
> Actually, I'm not sure this is safe (I don't fully understand codetags,
> so it may be safe).  What can happen is that the put_page() can come in
> before the pgalloc_tag_sub(), and then that page can be allocated again.
> Will that cause confusion?

So, there are two reasons I unfortunately can't reuse pgalloc_tag_sub():

1. We need to subtract `bytes` counter from the codetag but not the
`calls` counter, otherwise the final accounting will be incorrect.
This is because we effectively allocated multiple pages with one call
but freeing them with separate calls here. pgalloc_tag_sub_pages()
subtracts bytes but keeps calls counter the same. I mentioned this in
here: https://lore.kernel.org/all/CAJuCfpEgh1OiYNE_uKG-BqW2x97sOL9+AaTX4Jct=
3=3DWHzAv+kg@mail.gmail.com/
2. The codetag object itself is stable, it's created at build time.
The exception is when we unload modules and the codetag section gets
freed but during module unloading we check that all module codetags
are not referenced anymore and we prevent unloading this section if
any of them are still referenced (should not normally happen). That
said, the reference to the codetag (in this case from the page_ext)
might change from under us and we have to make sure it's valid. We
ensure that here by getting the codetag itself with pgalloc_tag_get()
*before* calling put_page_testzero(), which ensures its stability.

>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHjfKYNyGeALZzwJ1k_AKOm_qcgKkx5zR%2BX6eyWmsZTLw%40mail.gmai=
l.com.
