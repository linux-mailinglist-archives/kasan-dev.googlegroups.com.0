Return-Path: <kasan-dev+bncBC7OD3FKWUERB2XAZGRAMGQE245NVKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B2466F5A12
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 16:32:12 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-51b51394f32sf2689135a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 07:32:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683124330; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tr9CEI8okEPajf7wigT0gbT40YQW+t/Hy3wiNSIpvixTNhZ0Sy7HW8FYQ78TJhg32d
         ZUwEzxLBNHBuXtz4p1zGP4+Yx6oGvLADmzbeLYCNPiVTNm25XOvCqnFCJtKQXm07kFMi
         ZLqHra/mH3NCeNUKJ4GdvgS/TbrSg2T7DcU+9n00CGBxD1qe0fm0ehNhS5bcmH8mEEHu
         s05uEaBKYrJzWyauDNNyJV69l12OQVFS+r1I1q4wl2naRWtz6WlexTJofrGR/+cuWjXp
         Jyeo9B82ISXM3YR+l3FRzr6hRA7dlpS/7Og1PBsoX1TIbPFAx0U0aBa60GzgkD3QUFOz
         DKDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xKysM3Dvh71N7g8VKpW87eVv/Rkmxi9lMdO8Q7IzAZE=;
        b=NWl52EeGkty7vnP/Y0ytSj2qcsSssLk6pEg1+0WpRa0jJ0lgQ6kkmU8ddvJ2cy+duD
         YCBYq1WTm1AtwTm6NfgRlUnW8PsGss7q9lSMHW7b3xNwH7ewBTTo3yRqvc1czjDXr7J5
         Q0DYXGtSMm7ibYOsIkV9sFD3DQzjBOUFbIq5DmjTj/3IcYzIyQgwCgK/2u88QNpYnCCf
         dDQE45kSzwEOgKBt70VX54dPHn01z7raVhSWu6wiKOFNc+8cebX9VkHK9SlSBknGjJ0V
         cloWUn/5iWtrQSuRHecLbrYnAMsGQuIDevuUZsYvIEF9+wr5EdZEPb+8bihAyedS+uc6
         JWPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="YYnwd/M3";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683124330; x=1685716330;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xKysM3Dvh71N7g8VKpW87eVv/Rkmxi9lMdO8Q7IzAZE=;
        b=kFc8DFaUIhOSZfQrn7LKK6UHmSwS1Q6DzyCGbGk30L/PyhzHDFC5xx630C4UH7qOqw
         WrmZH7PJ3nUMmVCoO1VluW7f/sE2Yao1RH14L8z4vkNqODoGJMnFD7aH7StrG7Oslws2
         GT3oZtvSse/zNHVZNiv1kgUa6W1sKh71NJ846vcD5CnBi9Z0/4nxEqcsLyAzE5PsekvC
         CqjnhtsQmNviEwS17p3Wo+Mh0pJeqybU9sfyNAUdSSBYj3n2ZN4iIocnUq3VB0ESGKBX
         UReMBrMy4duYSxpCfCrOfNzFfyRUWn+tyR5R2lhZJ0q08f/gbcWf3u5ClSHc6rUbKL5B
         2YWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683124330; x=1685716330;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xKysM3Dvh71N7g8VKpW87eVv/Rkmxi9lMdO8Q7IzAZE=;
        b=i7zFkSnGtffL6i9zO3WEwypSkmWPlKa78FDXKETwtq+7LqAV4lHcZ3ULwU/d7ZCUnS
         Vxd81sTBA44mqt1QROX368NEnyB2xoQcO8wGHRic7z6ET+mQJioYtkBKiS5wHX3LZZog
         iUTXbZs75/mNPw+lRIR0ctWdf4REi2cBjfKN0QQySIAFCP1Lb//b9dHuynynD3qqOaX9
         w+NLUdSI+I3Rr4sKkrfgk0REsJPhQtIXIuoGHcgB1Ti9WY/mChhVR19JgPYKYB5MXQ0n
         gZJZv9w8sXbINTq4PDT53KNe5w1Qhe9mpci6hTty1P4FivEhja46xGweglUuGwISjImX
         Qzcw==
X-Gm-Message-State: AC+VfDxTkEZZ9JRE6TLObMegGcvGsgAa43ljM9YLWmFGRDiIO5exc66E
	Eq3UU5xBhc6+vaFMShTyvSs=
X-Google-Smtp-Source: ACHHUZ5gtcp2hIwRZHNoKUi7uMxvxZZn74Qsr4SkA5pbr3PbjsUqx0ApnohARwOFxVd4hhj2b4IQ2A==
X-Received: by 2002:a63:8841:0:b0:513:9d12:f27e with SMTP id l62-20020a638841000000b005139d12f27emr598450pgd.3.1683124330543;
        Wed, 03 May 2023 07:32:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f646:b0:1a6:bf2b:cb14 with SMTP id
 m6-20020a170902f64600b001a6bf2bcb14ls365811plg.1.-pod-prod-03-us; Wed, 03 May
 2023 07:32:09 -0700 (PDT)
X-Received: by 2002:a17:902:bb92:b0:19e:665b:2514 with SMTP id m18-20020a170902bb9200b0019e665b2514mr236061pls.43.1683124329793;
        Wed, 03 May 2023 07:32:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683124329; cv=none;
        d=google.com; s=arc-20160816;
        b=0G7+U4tqC0j2l15uXKgnwWXNpEg190i+dw2tF/Oe7wp+zBojXY/qFX2T7urE5hC7Lm
         RJcYFWRUNiKOxcZ7ScStRkhNj6d9LsvAzg65AkhvTyvijQKlq0fLuJkSYH6zO1zphCkx
         jb48JIfRnMZU0BU3tCNxIAOgbU/2C6L2pKzVGMBIocNRlMcXM+CO4puaF81wvw8tirSD
         wlufZrO8/XX2uQkk5b1X+o7016++LsxaTFaOiN8mOd/56tKOzU9slZMFkh2SmucEpk2W
         2Nobuz+UBScd97MebRbMcZL6mAxhzMTsBq+yGIM592ir2sL/TlYzyJ78mXmkEjKjBOvE
         +dTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HEvcpQRFstUtOR1Eu0GIXU3Feju4Sch+HPMbK8t4eZw=;
        b=U/IvcFkHuHi3LTa7kFYrv5dbNtXJMQUXl2orUhPrN+i+OWiEVklxiQiFft7Zfml7iP
         ndgACbzWatIFXR2NqLzHmOZAHmVX2igO1cucr2KHi1T5hj8OEeXknx43gYIbYqBNJsaz
         Dgv2RvLkpKH7Y4/XF4eIyTm8xs57waZ2Ftj//d+r3EI1dhyJS1LIX0gp96VCIsZViOb8
         khD6JtwSIVvuToEz0GaLCks1fr3WkyTixi+WnwVKIUrbPk+eFxDDU6RGtAmSk2cGxgI4
         D2xOI1+ZrXhpqIfu8ZyzhrewJO9DavPTTUB9STImgm4hthaw74IWLT0xZgMAKRr2JKBL
         xbMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="YYnwd/M3";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id h7-20020a170902f70700b001a0767b58e8si1588905plo.7.2023.05.03.07.32.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 07:32:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-b9d8b458e10so7223654276.1
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 07:32:09 -0700 (PDT)
X-Received: by 2002:a25:7356:0:b0:b9d:de23:3c27 with SMTP id
 o83-20020a257356000000b00b9dde233c27mr12904071ybc.9.1683124329016; Wed, 03
 May 2023 07:32:09 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan> <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <20230503115051.30b8a97f@meshulam.tesarici.cz> <ZFIv+30UH7+ySCZr@moria.home.lan>
 <25a1ea786712df5111d7d1db42490624ac63651e.camel@HansenPartnership.com>
In-Reply-To: <25a1ea786712df5111d7d1db42490624ac63651e.camel@HansenPartnership.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 May 2023 07:31:57 -0700
Message-ID: <CAJuCfpFZHOLxhrimPbLg+MjyzLR7U=C2Nk+i5Jc+-ZaNvnVu8Q@mail.gmail.com>
Subject: Re: [PATCH 00/40] Memory allocation profiling
To: James Bottomley <James.Bottomley@hansenpartnership.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, =?UTF-8?B?UGV0ciBUZXNhxZnDrWs=?= <petr@tesarici.cz>, 
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
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
 header.i=@google.com header.s=20221208 header.b="YYnwd/M3";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as
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

On Wed, May 3, 2023 at 5:34=E2=80=AFAM James Bottomley
<James.Bottomley@hansenpartnership.com> wrote:
>
> On Wed, 2023-05-03 at 05:57 -0400, Kent Overstreet wrote:
> > On Wed, May 03, 2023 at 11:50:51AM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> > > If anyone ever wants to use this code tagging framework for
> > > something
> > > else, they will also have to convert relevant functions to macros,
> > > slowly changing the kernel to a minefield where local identifiers,
> > > struct, union and enum tags, field names and labels must avoid name
> > > conflict with a tagged function. For now, I have to remember that
> > > alloc_pages is forbidden, but the list may grow.
> >
> > Also, since you're not actually a kernel contributor yet...
>
> You have an amazing talent for being wrong.  But even if you were
> actually right about this, it would be an ad hominem personal attack on
> a new contributor which crosses the line into unacceptable behaviour on
> the list and runs counter to our code of conduct.

Kent, I asked you before and I'm asking you again. Please focus on the
technical discussion and stop personal attacks. That is extremely
counter-productive.

>
> James
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
kasan-dev/CAJuCfpFZHOLxhrimPbLg%2BMjyzLR7U%3DC2Nk%2Bi5Jc%2B-ZaNvnVu8Q%40mai=
l.gmail.com.
