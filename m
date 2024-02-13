Return-Path: <kasan-dev+bncBC7OD3FKWUERBEGLVSXAMGQE5HRJUTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E5C99852AB5
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 09:17:21 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-dc64b659a9csf7140907276.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 00:17:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707812240; cv=pass;
        d=google.com; s=arc-20160816;
        b=yKzeEHO4i3pY6e7nybj/+BdfADKst0yibbwOl3K5elahgZzX3Kw65rBt9oxMp6UTJc
         UfBBuXL7LmSML9dd5mTxSpAtqRw2OBaRt4YmBiqr8DmiWq4BHonjsDwtJ9VPJkdWKC1g
         27KrVjArKiE4AWxB/jB+Up4tykSQdJ1NaadVyYyynDa+BJRfhws9vP7U4M5V5Xv8gIt6
         PlNLVbf+TO3Zi3I78hqILFhf2qmFZThJFLJlEjsGWnTD7VjgD6kdEI+kaKNfDlNLpmxC
         otj7wUSts/PD3lzpKgJIrW3yQg2kHQwkLQrtesI68jw0iaVc+GAzOuJ1Z4gBA0izP8iO
         3oCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6IpnOKGRL7cWSUVj+EKwmRSM8aY0/irTrRu5nsYv8Z4=;
        fh=Lmx6ASHG2Dl5b9nyIPWYeoISLnCeMgSpidENkCdWmI4=;
        b=BuoK6+rP+Afmrfn1NYxz/qYlF2z0h+PhR+V+KDLYxel6w0fSVcvNOtKkTZFBBGn6rV
         BE8D2Yh+JDHRPk/H4QqUXq+2QRO8Wu4jLSKTtHEioHFqHUChr7HQEjyN6GwRGsOTwWxy
         Z7KA0Pvfcne73z3y6AhEosykPqOylpyV61VNahR73dpLV7gi2oN2TuvCuw1wcpaK0F/Z
         yfxCB4F3i8zSZm4DQAqbyC1satIHAFHJFlDN1Ve9by6KLPwDFehJEh4WVMu57U+7eQQI
         W4UZ/zYyo59L0Sv9bDu8TPv41joTdEv3kF6ASBA0VuQbn12HjIj5qx5nsH7Vx7mxl38P
         NK4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=w+zm2aQW;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707812240; x=1708417040; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6IpnOKGRL7cWSUVj+EKwmRSM8aY0/irTrRu5nsYv8Z4=;
        b=CrI4mjYQmXnD/Gqu6CsLTAg0Wlyvz8wXyXurWlUDTTarjkZA14k13+Su2sG3T+Ynxz
         oW2vampjc1Y501uJXH6kS/GzRbh5VSalUhEiXHLXTPzw4/hh1YaVCOyVjeoYlgPjjq0I
         0lJZ70fzCF8nYvC7O36aSGwfawE0y5DKCdqMGPa2dsTS9GC6pBrQXT6YTbIjdF+zQoTy
         pqz4BrfoL9A/aLx3Z6rOqKVqZyF3Tbd0wPpXAL8Fax5DMZ/qloEKlv3UM7CzvV1p835P
         PmisMVEmi+a9MCa3FS5HDJ04sGu7iTlFRw+tyn490s2QpcZJIEa21hkF/h6mCjY/oBIX
         PiGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707812240; x=1708417040;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6IpnOKGRL7cWSUVj+EKwmRSM8aY0/irTrRu5nsYv8Z4=;
        b=TcHiKThkZAB4bBRLOgVs4+ERmga1U4YIPo62G75L5niMZiBU0oNfeyxEIDSvvLMxyq
         XnL4S86gXRh43Dbcx+WH6ORC7su95AYqFvO3H5xu0yGXxiB1SSoQYPkC6twQRC44Ngk5
         bMGDbtRR62weFHcJBldn7AO9L9HnTkgwPl0RpPXRPdON72IlJBcQbBeewaZlW+lTa49G
         NA8/FrIOpkQPOKspA9pWPkUjiqrN40reCwXi7rwDodjsncS1u1UsyPpJywSQT15nk8E9
         YNtD6krTOAXNhUxTrlI5zzRXURGHDn0ZwwFwsHWp5NH9AWr41Chkk12n1YvXJ6pItoHA
         FT7g==
X-Gm-Message-State: AOJu0YxdvQXshcoKk2lBP5Sa+3eUioFnc36JUb21QaXqfWtV6Z1usISG
	SV2NwGqOtGxlN88e8biNDL7x3g0b5HwMuqfScJgffpQm3oUk7yJXVA4=
X-Google-Smtp-Source: AGHT+IERM28bXpqzNp5OQj30CwC5n19jCbsYtOA1fTsdygvnnafQO5dguLFNobsaYg5FAa3PP2VCdQ==
X-Received: by 2002:a25:e807:0:b0:dc7:3166:ad25 with SMTP id k7-20020a25e807000000b00dc73166ad25mr6915678ybd.25.1707812240574;
        Tue, 13 Feb 2024 00:17:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:df14:0:b0:dcd:202d:6be8 with SMTP id w20-20020a25df14000000b00dcd202d6be8ls35882ybg.2.-pod-prod-08-us;
 Tue, 13 Feb 2024 00:17:20 -0800 (PST)
X-Received: by 2002:a25:e807:0:b0:dc7:3166:ad25 with SMTP id k7-20020a25e807000000b00dc73166ad25mr6915655ybd.25.1707812239571;
        Tue, 13 Feb 2024 00:17:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707812239; cv=none;
        d=google.com; s=arc-20160816;
        b=cnz7DrAVs1bO/eTaAP24OcuTLeB72Pf4VHdqFCowTZfcmLcafV890dhOITAP4yV/hC
         9SgtCTOcs7JFC9x4rnQfAOQbv+9EL/cDy0pLiOVRBTJ9sILZh14AFuv1MNSoJ0yI9rbq
         uo8vbaq6tXzMdGyan7CbrJyydcSTA2z5y2/xy/FJUhEwEtN9WfGojoUrsuXQNNE2j/1N
         7TfCGfTaY7m0VF/v/MU/LJd9WMsXJREUjCyjXIQnmT3iFxODS6DnD0ypToju+5ZvvEZG
         ylXrowax4uQKA0a3GbNh73GgpBTUzOAbBk5Ll2qeqJAMzuLwOUHxT7XNe5FE9uNqDYVE
         yviA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hC5Sp72DpOGszEFoskDK+zxBIS3uARFrNh6dT/DOYpw=;
        fh=Lmx6ASHG2Dl5b9nyIPWYeoISLnCeMgSpidENkCdWmI4=;
        b=Z+6ws2hh0dus05czbvTesMfiHk9IMsfaQAReOS3GimM/xW8UHOobHuxT5IKKDfvs0H
         h62FclsCv04r/EGQnCl4VM8QxDWE/OZZv/C+Z62547B9eYwZ4rWstUQnlXrQLNF9EF3f
         ESb6SSKMGvNU+19qW0okYz+KH71EVVeFlWX7VZn/qZrKEgGcuaIWTUY8EpEL001zuBuZ
         1kcIUA+8TkYWCjh3sO7JpIwBow1l8VrueuV/N2DiQ9d+8Q8gC94bFaP4yRYWgb5Zq3RC
         Uf2B8bVv7AUbqDyS7oCZVQ4W+CQiQcMbqpJ2ckmUl8duwfV2vtCop0+I/6487CoYxeAC
         xBHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=w+zm2aQW;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUUmnIo0z/M6Bz7sBCBfHSLDpiqpcGdod0GzgfKMldxM43QbMbpzMzlizHI0vpFAMV7U86Qv8/T1Q31SjSZgJxxiZtpOI7wS8GKuQ==
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id u1-20020a25ab01000000b00dcc3d9efcb7si148878ybi.3.2024.02.13.00.17.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 00:17:19 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id 3f1490d57ef6-dcbc6a6808fso1239713276.2
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 00:17:19 -0800 (PST)
X-Received: by 2002:a25:6841:0:b0:dcd:24b6:1aee with SMTP id
 d62-20020a256841000000b00dcd24b61aeemr45209ybc.47.1707812238953; Tue, 13 Feb
 2024 00:17:18 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-32-surenb@google.com>
 <202402121606.687E798B@keescook> <20240212192242.44493392@gandalf.local.home> <wvn5hh63omtqvs4e3jy7vfu7fvkikkzkhqbmcd7vdtmm7jta7s@qjagmjwle2z3>
In-Reply-To: <wvn5hh63omtqvs4e3jy7vfu7fvkikkzkhqbmcd7vdtmm7jta7s@qjagmjwle2z3>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 13 Feb 2024 00:17:04 -0800
Message-ID: <CAJuCfpE2hMx4rUSex3rX_wWiGOt=rX5FWms98Rd6WAaVqW6yvw@mail.gmail.com>
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Steven Rostedt <rostedt@goodmis.org>, Kees Cook <keescook@chromium.org>, 
	akpm@linux-foundation.org, mhocko@suse.com, vbabka@suse.cz, 
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
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=w+zm2aQW;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as
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

On Mon, Feb 12, 2024 at 8:33=E2=80=AFPM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Mon, Feb 12, 2024 at 07:22:42PM -0500, Steven Rostedt wrote:
> > On Mon, 12 Feb 2024 16:10:02 -0800
> > Kees Cook <keescook@chromium.org> wrote:
> >
> > > >  #endif
> > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > > + {
> > > > +         struct seq_buf s;
> > > > +         char *buf =3D kmalloc(4096, GFP_ATOMIC);
> > >
> > > Why 4096? Maybe use PAGE_SIZE instead?
> >
> > Will it make a difference for architectures that don't have 4096 PAGE_S=
IZE?
> > Like PowerPC which has PAGE_SIZE of anywhere between 4K to 256K!
>
> it's just a string buffer

We should document that __show_mem() prints only the top 10 largest
allocations, therefore as long as this buffer is large enough to hold
10 records we should be good. Technically we could simply print one
record at a time and then the buffer can be smaller.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpE2hMx4rUSex3rX_wWiGOt%3DrX5FWms98Rd6WAaVqW6yvw%40mail.gmai=
l.com.
