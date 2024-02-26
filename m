Return-Path: <kasan-dev+bncBC7OD3FKWUERBYUM6OXAMGQEN5H2GQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id A453D867DAB
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 18:12:04 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-5d8bff2b792sf3074696a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 09:12:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708967523; cv=pass;
        d=google.com; s=arc-20160816;
        b=JTS4a6cWhpve3msTUiMvb5P693XF5AfM68QDPsUVdDeF5Ji+Uxwq9dS21VOztNAWHK
         L82ygqEL9CWI4ppBtI6rAcbT/ICm0rzNqeG/ZuNnJoEUosfroRj1ubBxDJTjyu8PEQgX
         Ca7mEwbReix1JDX4W82N0JM4vWXJacEyRn9Oa3MYZ3wGSgffOUhpr/pnITxc3LgWT3a6
         es6psqjv32Qzg/pZnF7aILpfaBqMp31Dy0/X3gH97MH13GImnR6sVUjElVdvDE3xlwar
         QEZIRC2esBtC1hDKig4QG3B3BzKf5b5yJHMhJsgpZ9p611RwmWlCYzr83L+rKl6/vOJ1
         XXxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X8gjaJa0HfK+ed9Xpx7+H4bCANG5v7OacYbXPrGepqM=;
        fh=fiYBnEF7o7oCuNZ+Q5kVCG7jmWqR0wI1DjaCeWcOK7w=;
        b=U5qzsdDX091nEH2iniV2uBpYZc050WahZ3sVmGmpuJhrx9p0HPZOUbEYDRhcUSmtc1
         0cleCSEFemSB88ZZ9P69KRafYQ8HH/MT2QV6DLyiaIOUv40C9UZiibfGmZyv+FcP/p6W
         Znqih40Q5drG3SFD3T7QqUJiis5em9D3X49AIuq/XOe1CPLCWO3z1QQpHwe9VugUM0QN
         kQaOfVlg57CvjLz9OvRk6TEwZEk1zE1vlOeyt4Ux9wnXnBMmrVEDGM+/zIwD1aJNfctC
         WAutAknbWLAmjqpflW29oKWkEfuQzWV/MX4lxlAt5y1GP1pZ5/09nq1VJD2osXyF4se0
         nA7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D6tD0Ht9;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708967523; x=1709572323; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=X8gjaJa0HfK+ed9Xpx7+H4bCANG5v7OacYbXPrGepqM=;
        b=REoCBPOph4rrCDkrukv/Litj7KtwAMVdYuMQCfbAI13ciZv2u4c9fYSHoVndk+QweN
         eJH/bX4Aeu4D/FO5xQrYFXg4Y35vJfFLwKEKwLNs/3DuLRQ9c6zV3B5719ejAajQohlH
         wzVYJF9KdM59KHIhfwax3dOcg3b4xPWnoJcET6CG4EAnQzRVki6CAiCMECO87ufnGYsl
         EjjGQG6F5tu6XcQ/u5M0zfMilDidk4jUtaHYMV5QBrId60+EFR0J5Uv7RFWwgVSiEiGJ
         eO9Nf/7Y5TaAwBst+MSQclGw52uVd8bpantXJWDk6KVc7VGJQEy2U5bzKtqwNKwAkLFx
         exSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708967523; x=1709572323;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=X8gjaJa0HfK+ed9Xpx7+H4bCANG5v7OacYbXPrGepqM=;
        b=ATTg7c6FpoPCadtEwhegHkZ1fm4w05wgrB8V5oKMbVM36WCA822ae7l7v+LQwE744y
         Lx/4H6aBdaU0XcqB4RI7MVlTFCezsULyP0rn653cW6l6vfh0N97gTLKwUQGt27RoQWFm
         tNQ+T8/1Z3ofrk5zXC9ey8z24dWpYA0qzxxI6EoSK8MMT2ZNKZka/TWzKxVHGh1rvk7l
         a39SzPZYUNYBrhXBzJPvsCUb2RtTtDJO3E5eq7JYyC9aYrzz4QTBxKyGS3fVJkSNqZRr
         w4qfNdEV7wq0q0Vep9K2pu2SivP8y9hB/UcKFLZXQWCFUvIzjVGiY6n0KrfIbFxQ5eYZ
         vQSQ==
X-Forwarded-Encrypted: i=2; AJvYcCXIDnaZSKedVb3c7pEFpXTSruA5xlZfBegdnfsRPo/grV5YqgN/C1OPbVSlcpRSz7WlGN9YFibSoElMf+Ncke8Vo+TaIDgnKQ==
X-Gm-Message-State: AOJu0YwvV7tlGbsNbf0tTYml0JXAFMalXJp3bV1jsA914eDa3YxeAoZJ
	KWvPbAvLO0BVEFyNHTKhYnGIEYAkiKW4YPIFllzHMMQ0oOstAhTc
X-Google-Smtp-Source: AGHT+IH9FEMEzpkc1/i+5dmeb5fqBM/ZY98JPMVQUPHyABZ38BRD6E+f/HGhWEMMkqV4AWqXzaWIBw==
X-Received: by 2002:a17:902:8c8a:b0:1db:ff7b:d202 with SMTP id t10-20020a1709028c8a00b001dbff7bd202mr9189820plo.11.1708967522749;
        Mon, 26 Feb 2024 09:12:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7614:b0:1d7:6a5d:5a9e with SMTP id
 k20-20020a170902761400b001d76a5d5a9els1989038pll.1.-pod-prod-06-us; Mon, 26
 Feb 2024 09:12:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXRM8wSHnv3f5x/LNNsf4ehuwf3NnAXuUD7qPpZ9II0v4Zd9jLg5FdB6DW9snCK28bD605jNRaGlggV/zblMNc2I4lSs20tooi7PA==
X-Received: by 2002:a17:902:da89:b0:1dc:b3df:a0a8 with SMTP id j9-20020a170902da8900b001dcb3dfa0a8mr847532plx.25.1708967520084;
        Mon, 26 Feb 2024 09:12:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708967520; cv=none;
        d=google.com; s=arc-20160816;
        b=soOIjF+T38E849dBnFM5/6L2X5zfpm1J+MFaqhLDsZNByH67phGp8MX+z5gsUV0yOq
         EbykXNaRERLnnODhDlqtdSsUCWFS+QHp+Dqrf2m2UhO6JdyDiEqmq446STfu4HSlTS/5
         vwk0fa1DsEDKBSzxII+xuGtcpu+02v/OPiMP1ZpY9JDkFWHL8Y/nSHezzFA3UMX681m7
         fVRdRyOsVbz61N/k4qK1SYI8HaDQO7QozMxey6krb96mvDcjV9uZuM3RbrtsMk7Bzxe+
         dIZviX1WCHgtcd3KF6eaj4XKBRRW86HVvYkP/jT2bjTl5xVWrt0Ee0AfnLm79zdajoRX
         +Z0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Chynr1L1b/d5TcYFCNc4RvKn+tu9v2QwhIq+NAH+cTo=;
        fh=tAL7o9XsfzO0zyxv6Q8xiGF0dGXmIJWl+Lt1G6OczJE=;
        b=T8EBkiTpt16Zljx41FrABRZsFRWak1wn6381NnaHsWlfibjBzoghwvye7REoXSwX/R
         Q1NExvpKupLxAnqQFxsnd7F3CeecDnceCTerADPskJ1HB6L/INYXrFb5Cn/q5EldFvgZ
         pNZZVlFcenBZjRdDqV7uAKd+/ZzAIT5CAzvCCh8TEHbOwCVrlN3ddjLT05dPc44Q3FCv
         UVL10HhgCtCKbXDSmSeThcJNezdR99sLJdIfYqRtqLdw1Q9cj6agkYdF5eYPQfygK+M9
         ouoi1Y91a1TZLJpTfWSl5X5GePH8ZayXsonyzyhR2KRH11TYRY16ADtrbNFrJR0Ytlyt
         xcZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D6tD0Ht9;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id h14-20020a170902f7ce00b001db9cb6daddsi422112plw.2.2024.02.26.09.12.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Feb 2024 09:12:00 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id 3f1490d57ef6-dc6d8bd612dso3249810276.1
        for <kasan-dev@googlegroups.com>; Mon, 26 Feb 2024 09:12:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX6lLBT0qmnOF+Xd7IYWb4vX8gochTqcNRPT5F2eHnLwGqLKp6rLw+P0Y49n/yL3cZe0ojZOVPXHupKD+IOm6f1XzG9erecdqefNw==
X-Received: by 2002:a25:acd2:0:b0:dcc:2caa:578b with SMTP id
 x18-20020a25acd2000000b00dcc2caa578bmr5024557ybd.40.1708967519035; Mon, 26
 Feb 2024 09:11:59 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-16-surenb@google.com>
 <d6141a99-3409-447b-88ac-16c24b0a892e@suse.cz>
In-Reply-To: <d6141a99-3409-447b-88ac-16c24b0a892e@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Feb 2024 09:11:45 -0800
Message-ID: <CAJuCfpGZ6W-vjby=hWd5F3BOCLjdeda2iQx_Tz-HcyjCAsmKVg@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=D6tD0Ht9;       spf=pass
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

On Mon, Feb 26, 2024 at 9:07=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> > Introduce helper functions to easily instrument page allocators by
> > storing a pointer to the allocation tag associated with the code that
> > allocated the page in a page_ext field.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
>
> The static key usage seems fine now. Even if the page_ext overhead is sti=
ll
> always paid when compiled in, you mention in the cover letter there's a p=
lan
> for boot-time toggle later, so

Yes, I already have a simple patch for that to be included in the next
revision: https://github.com/torvalds/linux/commit/7ca367e80232345f471b77b3=
ea71cf82faf50954

>
> Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

Thanks!

>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGZ6W-vjby%3DhWd5F3BOCLjdeda2iQx_Tz-HcyjCAsmKVg%40mail.gmai=
l.com.
