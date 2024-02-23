Return-Path: <kasan-dev+bncBC7OD3FKWUERBFVT4SXAMGQE77I36MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BBDC861F7A
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 23:18:00 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-598b795e5b4sf2008080eaf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 14:17:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708726678; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rh37IuaiYMjTOSWSJqyJkq2KdRA/ekn+MgXYUXU+oo5wlI1iQJcyybXleqeHIaY/+x
         7588Cgigwtps7yTTN1W7jog3EBLBr4NY72Ef89htQ9xWuMS8x9H/6vfxm+YFDp+IFE6E
         RJ8p5xiflTXXhHDw7ArvsxXI+hGjta7zGYvtZL6I1biRE1orUYD08DIGvK2Dh6BmIOp4
         Ta/3lUDy6d3F7YBpVxictxF5IkmyZYcufer0fj6kTIuLL/Vr/AOnnOhe9v0w+mRNqpUv
         PVkg3piFa/sbMaKgsRvCFpDh4ZOs1VjAUFgA09jlcX3W6TdZl3pXRqEjajQsyXubczM/
         8vyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=I4EOkf5KcZFk6sa5eDH1Lmh15/i2gdn0CoN1ZVMRdKY=;
        fh=N5FwDvfwnkHBEHiHe0oJBXXAxEKJ5HMqEEsRAJdtN5I=;
        b=cI0P8aqGV9kOpIN+ihiiKndOqQjqa1TnJZkpINNXfDIkPMBhguY0WcBDopQtw/jJ5Z
         oGKedsGUOo1L1c3IQg4jpjcZBiR/cO+LfXmy+7miw2vePKdSkAVr1k7hra/oyFm//3F+
         UwuU68E74equ6z3RyMUHAAbA6fvkfdhHfW4bPPI/8WHz2uyM9VU7Xbmk44sQeEimQN60
         iRkxBir7YfIfRXmY7BNjLyXfuHuUFMYlEg8SsnRb0wLQc2a+Xj7m9cVtw+tuIPmJBu+O
         OQ44NsZdd/eY1D2bHEMTMJLUG0+ZTJ8kym+EWtSYE+XasZgWxlfc5B6PX7kbwhAURFzf
         15GQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="uKEt/pL6";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708726678; x=1709331478; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I4EOkf5KcZFk6sa5eDH1Lmh15/i2gdn0CoN1ZVMRdKY=;
        b=xpxJYh6SCV+xZqvSXQD8THN8XZ9woO/kFkG8wOKmJAiBFFayaRGGpiT9LbgqNzz/X/
         Ywy7On3YOKZy3c2rWiS/dc0KxErhz+FuKp0PkoFOHrJP5EMzPcpHl1unfnWL/31y4CSL
         JkgIT6iJdl2HNZ9mBqQBWE4TYjRVFZ7mR/lTmGnxjlGunFnWxYM4SD7dECdKd6rfgwx8
         nLaTR36dm+uml9hH2Iw+g8HRIVrhXve7QYIXdWSTmRCQ2/P94yzT6INirgKNCVrMi8RN
         WM/6/Y3TsKT49CPwu8dfqoiiTFAYxNdIhz5FUYMcZTy9Eq3/UD3LlJ7nnyw7gczeJbo8
         W7nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708726678; x=1709331478;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=I4EOkf5KcZFk6sa5eDH1Lmh15/i2gdn0CoN1ZVMRdKY=;
        b=hmIxA65ifOdh+9kihbq+7eJ1/OKZr/hhWCJpldvM7RQjf9ExyNDmHivLSyu5T4bwbr
         qQj7cBffHOrgc6KCJeP+Je84n6/d5kTIhBoIw2cqCAJFLOKJdc2RU8JRXs+KZtSilCLI
         BDbG0pvTqqHpd+g94hHvlnSEHnp8+97K0ZltIIHUpDUVy1D+AOEpp03SicAfbPrOGafj
         FvC7igGT7s8r2v0wB2HW2082f0s0ZMMyTR5XXBVdIJQ1y7YfNqOTVFkyRiKgeLiHwsTT
         PW8BBNVDBhFeIhcIfEL4XDQtVuBsOF1maD1atpuH2NzoJuTfoN+nZWILy1lXw4FE9YIq
         n1Gw==
X-Forwarded-Encrypted: i=2; AJvYcCXBBGewRH6egiwaO4d7MaOh3OotW5crEZJDJ0N0IGJx5mO9dQelE3P7icMXX2sCTB8bohfrAkLwC1M1Z/x28zx5uV9IKr1eyw==
X-Gm-Message-State: AOJu0Yx74tq62t3GLQhlacwhgqccHY2GQfgoPYiQxYcUSi+g+QeSJP3c
	DyB8YUL9ifJGAZFq97CVJDGAnRS9GnmAn4DqbwRQQcoyMiJR8DR1
X-Google-Smtp-Source: AGHT+IFVXD11NbsWAmzLoL77N9VtikdZpyoO3un4ZwoectTo3i7xYID1tTLztt0eHECodiuEeo4kXw==
X-Received: by 2002:a4a:340d:0:b0:5a0:234:687 with SMTP id b13-20020a4a340d000000b005a002340687mr1287494ooa.4.1708726678598;
        Fri, 23 Feb 2024 14:17:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4bc7:0:b0:598:c9ef:f0fe with SMTP id q190-20020a4a4bc7000000b00598c9eff0fels1016365ooa.0.-pod-prod-06-us;
 Fri, 23 Feb 2024 14:17:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXH63X7awuqalbip90df1ueHXXxko23qzSotWzz9jfPo1PZUcTOZyQzaMCJUzSTM+c5IQUWtk6YwROSjl35xXtSVvvn6NJdtlo05g==
X-Received: by 2002:a05:6830:d8:b0:6e4:767d:a085 with SMTP id x24-20020a05683000d800b006e4767da085mr1310999oto.24.1708726677805;
        Fri, 23 Feb 2024 14:17:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708726677; cv=none;
        d=google.com; s=arc-20160816;
        b=E0oJ6wDsmQJL01ASp4oAwxQYCoJTENsV8y1KSN3VVOaT0Vnk7E/zxN1P44DOeoLZm2
         kcdGcOGlUoVHkPSLvhHFqMTEXQ4elK+aLJjL2ahEBa6P2e5c9/rULnsXPdaYU9lfLe/J
         syuXXh6V78hro9lcFbWJhClqUaldqGLdNIbkKGpJasi921rwQGtLNqA7iouyva3UVjv4
         O2ssUr47+PRbsbKJ1CPMdG8BTUJ2bzFJzpE72W8TIqPSt7+uWMCuILKYZIVM4Nca/lVW
         ATc2FzpctvtERDfMhnOjK1bagZ+clSEUmfHv36JbY+Sp8jFz8areVlJDhsZ3DQQzXf30
         J4GA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mr+d1THQdIOXLBHXtZjKUSDXbb7TH7vTqrSqao2j71w=;
        fh=R8x/wHRRzjr8jx8JMF3W5PK3+eKPDbSUfHZl6nzHqTU=;
        b=MU0NeHpg6K+F6e7bypQflQSVsSTKeT4XDoPa1+DvdiaaXsewKcoHDN4WN4jxOdRE3C
         NSG8VoVQAeQIz54buqLBVCFgggBYsCl3y5QPG0HxcqN+8aWe3DHiirr6PZLSC8FQZNv6
         5ozBsp5UkAmqq7Q9NM5gG0lAJ4dty0e7qYf+ttT8eOsyLp1HQ3musRDBeXJzDMZG7ohY
         mtYRPkKNHQDJaCtE2TUyxeIU2KIY7o9RAsFXs5xdznuIEz25TjMYR45v3P/StRLq/DIJ
         jTC9VZfq2xdTSaN1nfjAwm/oCjFxo0zyPWG0XkRdUMhMCgU8gn6gEy8tCgjIIUXcXBuj
         k/Rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="uKEt/pL6";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id z25-20020a0568301db900b006e4725c87dcsi408oti.3.2024.02.23.14.17.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Feb 2024 14:17:57 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-607c5679842so14113607b3.2
        for <kasan-dev@googlegroups.com>; Fri, 23 Feb 2024 14:17:57 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWnWuPBdFgKIDhG9U2fzsVpAyPRXEGFuGQD50wQX3EPolEr6r+hEsVeIeHqh/GSJ/hPQbE/JDhxeKJOt9LGFcRaOFEeLtabj9vLkA==
X-Received: by 2002:a25:a427:0:b0:dc7:47b7:9053 with SMTP id
 f36-20020a25a427000000b00dc747b79053mr1214318ybi.15.1708726677063; Fri, 23
 Feb 2024 14:17:57 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-25-surenb@google.com>
 <CAH5fLgiyouEuDGkbm3fB6WTOxAnTiDx=z6ADx7HN3BTMAO851g@mail.gmail.com>
In-Reply-To: <CAH5fLgiyouEuDGkbm3fB6WTOxAnTiDx=z6ADx7HN3BTMAO851g@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 23 Feb 2024 14:17:44 -0800
Message-ID: <CAJuCfpHBEX27ThkdMBag-rOwir0Aaie-EeAUgF6bem=3OX4EdA@mail.gmail.com>
Subject: Re: [PATCH v4 24/36] rust: Add a rust helper for krealloc()
To: Alice Ryhl <aliceryhl@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
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
	cgroups@vger.kernel.org, Miguel Ojeda <ojeda@kernel.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="uKEt/pL6";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1129
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

On Thu, Feb 22, 2024 at 2:00=E2=80=AFAM Alice Ryhl <aliceryhl@google.com> w=
rote:
>
> On Wed, Feb 21, 2024 at 8:41=E2=80=AFPM Suren Baghdasaryan <surenb@google=
.com> wrote:
> >
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > Memory allocation profiling is turning krealloc() into a nontrivial
> > macro - so for now, we need a helper for it.
> >
> > Until we have proper support on the rust side for memory allocation
> > profiling this does mean that all Rust allocations will be accounted to
> > the helper.
> >
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Cc: Miguel Ojeda <ojeda@kernel.org>
> > Cc: Alex Gaynor <alex.gaynor@gmail.com>
> > Cc: Wedson Almeida Filho <wedsonaf@gmail.com>
> > Cc: Boqun Feng <boqun.feng@gmail.com>
> > Cc: Gary Guo <gary@garyguo.net>
> > Cc: "Bj=C3=B6rn Roy Baron" <bjorn3_gh@protonmail.com>
> > Cc: Benno Lossin <benno.lossin@proton.me>
> > Cc: Andreas Hindborg <a.hindborg@samsung.com>
> > Cc: Alice Ryhl <aliceryhl@google.com>
> > Cc: rust-for-linux@vger.kernel.org
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>
> Currently, the Rust build doesn't work throughout the entire series
> since there are some commits where krealloc is missing before you
> introduce the helper. If you introduce the helper first before
> krealloc stops being an exported function, then the Rust build should
> work throughout the entire series. (Having both the helper and the
> exported function at the same time is not a problem.)

Ack. I'll move it up in the series.

>
> With the patch reordered:
>
> Reviewed-by: Alice Ryhl <aliceryhl@google.com>

Thanks Alice!

>
> Alice

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHBEX27ThkdMBag-rOwir0Aaie-EeAUgF6bem%3D3OX4EdA%40mail.gmai=
l.com.
