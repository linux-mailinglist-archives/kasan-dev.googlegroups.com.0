Return-Path: <kasan-dev+bncBC7OD3FKWUERBVENY6XQMGQEP7RRT3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 2613E87AA6C
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 16:31:34 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3662c91feeasf189215ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 08:31:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710343893; cv=pass;
        d=google.com; s=arc-20160816;
        b=AAPCw7aZ0xjHr2WvvnqsPQzquIwofEFruteWZog2SeK5EccGi7zMVF14hUiUvSHtdg
         VqjFaPeoU8Wj1yzqC+WOzvUOlyH+i+WgpMH2+V67axLpN58891UV1KhUia2Epezdv5bc
         OExZ5323ig7vnbXEneaUwTowxOyBAkFH7LzAIfa21SiVWK4ppb6kh3uc1dif32Er5fsa
         QV7afmHeVKxeSk5qICMD4YDk3w9j/rxVvyxdhvjGZF3vtpymcXlQkAIupLU+SkA+pjIE
         wD/x2czDANTVHAAdKREmIf6LE0b7GBXE36Lk6fM0WOFaVmK/Sphh4lZdz4LwUr/0Xl/I
         Tb4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vn5mKC2L0tsn7p0q4z0yovmgc6Xfp2NIGKdj5nKfHsk=;
        fh=puI0sWqiKaK1QyhIYViekaRZv14+7L96yEFGxQJ5iyQ=;
        b=LzxoCPAIgUm4veDJyCOmZKmz6SwOdPaqMj7Lk5WRhnABOEkHs87ligr13uVZPCSy81
         OVFovvoRHnSpxdfYRmVoGOdSScr/hYHTTIt1sLaP4oIc3eIEqHJYMPJHob5QjCpUywS+
         XfdpVdmoAD1pDezT8m1vAh6P6Fm1u2ulnbMGjA+D//LhVHvMTgedGyEYY64nL7SHsw9F
         bgRESpmQD3YsqGBL0cG7WoC6lcr0Ej+Ja+UcGw8i/ruKQ6+FGfz8G6go1dmrYbu9sCKA
         oyNXebSsAFj+FU5TfFi9TpnUlxxDhVQzs9cDVHMI2Jnz7jxFm2fp7UhaddJHbqdrosDg
         jnkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="sysz/Lrc";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710343893; x=1710948693; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vn5mKC2L0tsn7p0q4z0yovmgc6Xfp2NIGKdj5nKfHsk=;
        b=GunhbVfFl8R+PMzKB62mTXGI5HPktH4g2poBCoDhckmbhccEISJkCOalya0Fbn0rCU
         GrmY/volj80oHXjnamnum9myPdyUl5nbJMrgoLiW+02dEtqSmE+qBD5J6P6GAISXj+d5
         2PSmCkLLcDAtRDQuAVIH4E/xmt6a4syJTLQ8/CfC850HiB9fgsbV5Oa4yiURIrJTexym
         g3zdyo/yyBYCR7hRE7c9jb1T7dgOwkPCrgK+I1gX8Axy5/xU8NlCPtpzVu3pjzjK5nlS
         2+3+AVGZKeaBipYiWtVziZjrXHQfMy2IRdFtA2HCk+aqnN1HBaTfbMQorhE+GLWwtawB
         jIdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710343893; x=1710948693;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vn5mKC2L0tsn7p0q4z0yovmgc6Xfp2NIGKdj5nKfHsk=;
        b=SSE7iopnOlafCkYybRc7Js8/tEEAG4DphBv+/OBaclXD6MzYE5YN4BIGLs9AF7aJof
         2tM4/fDhlvjwZk/CiBABds7eSY0kBc4gETuYN3dgeD/a4VFmE2TPEB/eCTwoDKTKeScP
         a3EM4w4cLDrzr5FWt41T74lgW1E4vi6RKhhZ+IQ5VnNRK3XDeyCFupz7Oa5nBDigw2hw
         RTJDUEjs/35MD3jWP7N33diqTO1nQ3fc6wsBY2Yo+zsEB0DGj21WvRE+HD9g5xJoIQYz
         ywBCtnXP+J76u3Snq7B8hVstOXPJ0WbjSPI3GGx1JF3e2KPpSQ/eYKUOd8Afk+WjejP0
         GTNQ==
X-Forwarded-Encrypted: i=2; AJvYcCUpUT2Nno8sirdBX1/mQ9sqLgoivtWtm5rC9a3HxnOqtVW4QHWN6BfvkXF6GnWLEii7H9yCSJ8GR7Yp1vwaaeoLPklTBkCPYQ==
X-Gm-Message-State: AOJu0Yw0GUZLw2tAvO8Qvb/mlSDuC7iHMME/8+TQPU6cj7d4HZ76ie8e
	FQ6TxcOg0K17BMvjbbV0UpSxDUijOQuEa2XFhDA+DgGPsDzM+OeS
X-Google-Smtp-Source: AGHT+IEAe+80zxpgvVuIDHGhgY7FAzHOZoAbzCNtD5Wq1UA2w+F9iw9bPLJywKVdECmUb5Ln9I4W6A==
X-Received: by 2002:a05:6e02:218f:b0:366:222d:6625 with SMTP id j15-20020a056e02218f00b00366222d6625mr245533ila.1.1710343892740;
        Wed, 13 Mar 2024 08:31:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1b8e:b0:21f:a0f8:8272 with SMTP id
 hm14-20020a0568701b8e00b0021fa0f88272ls5829664oab.2.-pod-prod-02-us; Wed, 13
 Mar 2024 08:31:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV70ZTG7364vwbL1DE1nC6VElcoLDMvyxQklHsp5jvxLK7C2M2SpFhKYgmCTTtcajvvAzpn+Z49Scd5m/E0SkfxfUApjklnFvrHjw==
X-Received: by 2002:a05:6870:204e:b0:220:8d07:1670 with SMTP id l14-20020a056870204e00b002208d071670mr3792566oad.29.1710343891964;
        Wed, 13 Mar 2024 08:31:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710343891; cv=none;
        d=google.com; s=arc-20160816;
        b=zT1QOIMs5UAP3Bfd9wn73zvbCNH0b1VsaCavOtO45KCI/6Pk3V8p3YqHTOiV/AYMvf
         cfUnYe+1ejr3FNol92n2xKMEvIj5r8LTRKDMLdiXl9x4m5Z6U7pNGnnXbG+sG2/aNKNc
         4jllpN0rSh/BN5hqk/lVbQ0WwzHcnSwySlC6F+iGZtJ0dNCsRIk4mBbKU35mgeOyFrP9
         9TxgzzndMnnjgBvi3u89FAULHxGS1yDhNAcwAYH1klfEXfaspAYjJSVjHbyeqcjjk/da
         iVIBTY+rHqmeYcKy5cKRS6NQE7yQ0qqbNHSaPuZGTTXeBid4EOfeceDr3XP4O8HgXqyO
         2Jfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JtMw74U66kmsHyXAV7bBZ7SbbkNSfFBApfqkzQBmCrI=;
        fh=Dg3ZGDxN3T7MFozeJAHhes+dfVeR5YFyUp03oendqKw=;
        b=Qtn21rxv9OKjFbeCn5l3qzmRquxCKItJnj45hKyR8sPMJdfDayAK+fFQ+b5KWNuWFT
         MDdKJWFKbmLi5AQByvgcVNANCRhAd6CR9g+jgadcJvPwPUC1vDTijskLr33NJtpNRVUl
         ly3pw9p5Zyj/0gQaJW5ZzqBlKwRqENTLTfZZGsnj6H9wwhaliDNYWLsW3mOf8wjYw3Q7
         vAFGh9wL08JGfmWbE4+1v6lPsIvFY841bYlQSwt2dfydlnuP/sHsJxNmylt0gXMt5x1D
         W/mu6BC3M15uzTK7KAap3pjFpoqLag8u7tbq48Xrca2iOYYC8v7n8Niv+joIAOjr4vf8
         KwRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="sysz/Lrc";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id pz10-20020a056871e48a00b00221d92ba892si1128484oac.4.2024.03.13.08.31.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Mar 2024 08:31:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 3f1490d57ef6-dcc73148611so1266550276.3
        for <kasan-dev@googlegroups.com>; Wed, 13 Mar 2024 08:31:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWfR2wzLVPTA2rYhys8YvrSmghFdMX1RY1S5erRVrJR+gTGfyI6hJKjAbgksd+0rgoSMAz+7gGuKI4JN+mehDuGyV0X2t+KfQScXg==
X-Received: by 2002:a5b:706:0:b0:dcb:abbc:f597 with SMTP id
 g6-20020a5b0706000000b00dcbabbcf597mr2798485ybq.54.1710343891190; Wed, 13 Mar
 2024 08:31:31 -0700 (PDT)
MIME-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com> <20240306182440.2003814-21-surenb@google.com>
 <ZfHAcVwJ6w9b1x0Z@casper.infradead.org>
In-Reply-To: <ZfHAcVwJ6w9b1x0Z@casper.infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Mar 2024 15:31:18 +0000
Message-ID: <CAJuCfpFf2xrCA_Rq_-e5HsDMqeS87p0b28PkK+wgWco17mxyDQ@mail.gmail.com>
Subject: Re: [PATCH v5 20/37] mm: fix non-compound multi-order memory
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
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
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
 header.i=@google.com header.s=20230601 header.b="sysz/Lrc";       spf=pass
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

On Wed, Mar 13, 2024 at 3:04=E2=80=AFPM Matthew Wilcox <willy@infradead.org=
> wrote:
>
> On Wed, Mar 06, 2024 at 10:24:18AM -0800, Suren Baghdasaryan wrote:
> > When a non-compound multi-order page is freed, it is possible that a
> > speculative reference keeps the page pinned. In this case we free all
> > pages except for the first page, which will be freed later by the last
> > put_page(). However put_page() ignores the order of the page being free=
d,
> > treating it as a 0-order page. This creates a memory accounting imbalan=
ce
> > because the pages freed in __free_pages() do not have their own alloc_t=
ag
> > and their memory was accounted to the first page. To fix this the first
> > page should adjust its allocation size counter when "tail" pages are fr=
eed.
>
> It's not "ignored".  It's not available!
>
> Better wording:
>
> However the page passed to put_page() is indisinguishable from an
> order-0 page, so it cannot do the accounting, just as it cannot free
> the subsequent pages.  Do the accounting here, where we free the pages.
>
> (I'm sure further improvements are possible)
>
> > +static inline void pgalloc_tag_sub_bytes(struct alloc_tag *tag, unsign=
ed int order)
> > +{
> > +     if (mem_alloc_profiling_enabled() && tag)
> > +             this_cpu_sub(tag->counters->bytes, PAGE_SIZE << order);
> > +}
>
> This is a terribly named function.  And it's not even good for what we
> want to use it for.
>
> static inline void pgalloc_tag_sub_pages(struct alloc_tag *tag, unsigned =
int nr)
> {
>         if (mem_alloc_profiling_enabled() && tag)
>                 this_cpu_sub(tag->counters->bytes, PAGE_SIZE * nr);
> }
>
> > +++ b/mm/page_alloc.c
> > @@ -4697,12 +4697,21 @@ void __free_pages(struct page *page, unsigned i=
nt order)
> >  {
> >       /* get PageHead before we drop reference */
> >       int head =3D PageHead(page);
> > +     struct alloc_tag *tag =3D pgalloc_tag_get(page);
> >
> >       if (put_page_testzero(page))
> >               free_the_page(page, order);
> >       else if (!head)
> > -             while (order-- > 0)
> > +             while (order-- > 0) {
> >                       free_the_page(page + (1 << order), order);
> > +                     /*
> > +                      * non-compound multi-order page accounts all all=
ocations
> > +                      * to the first page (just like compound one), th=
erefore
> > +                      * we need to adjust the allocation size of the f=
irst
> > +                      * page as its order is ignored when put_page() f=
rees it.
> > +                      */
> > +                     pgalloc_tag_sub_bytes(tag, order);
>
> -       else if (!head
> +       else if (!head) {
> +               pgalloc_tag_sub_pages(1 << order - 1);
>                 while (order-- > 0)
>                         free_the_page(page + (1 << order), order);
> +       }
>
> It doesn't need a comment, it's obvious what you're doing.

All suggestions seem fine to me. I'll adjust the next version accordingly.
Thanks for reviewing and the feedback!

>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFf2xrCA_Rq_-e5HsDMqeS87p0b28PkK%2BwgWco17mxyDQ%40mail.gmai=
l.com.
