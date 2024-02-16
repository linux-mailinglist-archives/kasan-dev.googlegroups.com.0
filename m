Return-Path: <kasan-dev+bncBC7OD3FKWUERBKWGXSXAMGQEEUHVXGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9089C857821
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 09:56:12 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-297040c7cfasf1768655a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:56:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708073771; cv=pass;
        d=google.com; s=arc-20160816;
        b=zSWMoxn21O0bzpHB5T2t3BAO9nb6VdrRtrZ2xbzdSQE6jfBF0U21fYEVKRtws26YbR
         0hvK3OtGfRyYRJW/DH/idFVHkXfKqkbrygCOBsgXAqHu5VluahFe8eypdvNuTxvnmi+S
         s5k9NLwUQMCfidEP7dQAlwBsczlJmyuCEaz6+9sRnRb/aID1Ro6lsWe8tLp+eFw1UaLl
         vOwOoBVNVrcw0fDhaVt+6ABm2YtHgc7urqFyhSS2GYlDwl4XLdlkf5/vCrSfctYUC+TV
         4o+M3aBACUbQ/8EysW3diI1x8yREpZFgBCurly2tXEjormDQXTlSX4fWQpgGORDxYz2t
         9+yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hIhJHaY/gECacwluAVTCRNXBhFg5i7BRMI2COlXMCbw=;
        fh=a4c2LBj2OxqBkHhCNPpBwlIyCMayKuco2VvXnvmkj3Y=;
        b=Xd+q1bvi+XKJxvMSVIuJBcgaBfpTlZJhBXHEM3J+llP+x0obpsvEIF9sGgpQpyvkJp
         T4LtMHlT4cZQnyMPLX/H2Oh7UPVCCfCFwhlVzm1YxVilIpQVZ+3JIuXWSCWDYv7GeXYW
         EGnodk1ANxHbkeApEwANg3t2CxAlEfyYlTkAIm4aiyD1jb1Sc9dp85EZ8qWaBzS8ZZhV
         2+leih4CBEintiPd7J8y1Sv6jiEkxYzTmYuWLLGh2OZsyOy+H19dqHPxbAsOZ4D+7YCP
         +VhuWlorkUa0SiNj13lx1hiRWmcEwlGxTVyWAHNdvQ2NvHFAJ17gzqqFZu11WajhM6hZ
         pujQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="KzEMLh/C";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708073771; x=1708678571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hIhJHaY/gECacwluAVTCRNXBhFg5i7BRMI2COlXMCbw=;
        b=cUoPucc9PogWPbQncAEOwyE1Kcz4jYe6Z8aNhP03TPN6YAQuerLhLHMKD4Msioy20b
         L5/GPd9AYjW28Xq0ECs7U8YAGOp4Q7Xkefk3pZA7r8jFewqm9/4Qn8i7Tj4zs7f4kss0
         ltqnRISzNfNBcwS38t8AVpyZhQrLzCY3VoIbHlo2cEcj3SvNGu9MTVvriFEvj+8Ea6qR
         G1Fsv/p9YoGbbBzI+alfc1ZUNWya9l7fpQbhO9KGS4TgyTrmfWd4Prc8iyomRw81K5yY
         F/5li2RweW+tkRgOdkKjqHBkerOktGuEMz10Vnf88GpgX9U5i+Yi1M3OiwvSkUPehIuj
         +DYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708073771; x=1708678571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hIhJHaY/gECacwluAVTCRNXBhFg5i7BRMI2COlXMCbw=;
        b=lM8sGhjs+jmEpYrGd3PGe9RodlFBxFc3BECgxiZJh5scgOOChtihdLI3p/3+qqo0k7
         Io+vNJG9EujhGT7XtgmQm+iCkosKYZrvhEYbEKcBz8TqaSTouvGQLXJxqSBqNtJzFAKn
         s3VBz6AEPr0bd/avtGmSm4zWrB30lqq27qB7K6Z0XxdDSEj/LNJ26r7b4uZaX+1gtPcO
         5kVknubCxizgnEYenKsM+gMiHBDxo2Y+r/0ADfdkZXGz8BxUN4Wd9Y2RdV1DES2HYtBU
         vsSARiThVjzu2QlCbPLDgIMHsVn1y3CvT/ktnNmsvGLR7bgrjhDTgL5QtT+d5nUodYaj
         af3A==
X-Forwarded-Encrypted: i=2; AJvYcCX4wlFcexD9Bw2mKUtmMp0AsWkKefU+6PkcAlS+OxKxbCliEznKRUbyDmNlGaCAiRISGbQncN0M7gKS43XYb9Kk47M4Vel4uQ==
X-Gm-Message-State: AOJu0Yxi0wQVMZif7U8+edVsl82UQkxTLrZRmuR2KH6rwAN07fzmBkyD
	Msseky3hsH9aohJAiE4F4AlgCIvRrrLcQyf6aO9cjLyqkOEzYIyB
X-Google-Smtp-Source: AGHT+IGe4oLQ9qi1oCPvKCwr+30gxlbraO+wnlDFQaTSi4a1S6mPl7d4CvDW5WXA5OiRDantI+Vxeg==
X-Received: by 2002:a17:90b:1481:b0:299:35ea:74f9 with SMTP id js1-20020a17090b148100b0029935ea74f9mr765613pjb.44.1708073771154;
        Fri, 16 Feb 2024 00:56:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3c88:b0:297:700:3f2e with SMTP id
 pv8-20020a17090b3c8800b0029707003f2els520578pjb.2.-pod-prod-08-us; Fri, 16
 Feb 2024 00:56:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVpBCwekDSzWSadEzu/J6Fxq0mOgwgTPZDFuJzV0HlLZPwjL3YFzePVmfCnsXI3pP49EnIL4uJ9ap8rjt9rwT+BrpiIdT8T7NvPmQ==
X-Received: by 2002:a17:90a:6e44:b0:299:2c4b:5d20 with SMTP id s4-20020a17090a6e4400b002992c4b5d20mr2139608pjm.39.1708073770009;
        Fri, 16 Feb 2024 00:56:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708073769; cv=none;
        d=google.com; s=arc-20160816;
        b=kbURGJJGNUirg5POpLCfKhcZ+Z4NNCdmHUhvnAqUEPiT80r/pP9Ot5DJNSQwsfuwJm
         hXBMEzLu+Cmk7y3oZ6c5Xz2nKJYoFtZiNNc+9JCM0wfnwtCuGWznHtiv4UMcNKof/o7P
         PnUhWdAHZhQPueQn+qwQba8rq2Six6SllGirZHbsOWy6+VARNi621A6l0o+12Nnbp77X
         8MAt4C5CyMvJX6zvFmjG8yzlFKSYfUORzxOKz3EkANVGZ044ISTxSViF0cl0g4Jsovli
         QDdCxX0TjhCOmi1JgJDkJo/jQWdrpAAjICGXl3kj7rrRfx2LZqGRrRHHk/AmXmwMc7JU
         Xdkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=w/bNm1+I792YdZVlTWr+H7KQ1f6kurFtOITMvEEBO/k=;
        fh=XrDx7A/Ib35Y7chKxggZXOfkKbk+RaMzUUF+OuDzKoA=;
        b=K5Xmu55cOg0GrYOEM7O9++8krh4p6Acpm0jKmigTIBGJT5hMeeuM22Bgl54bLWMmTu
         ce+tG270e7DzedW0YZ3jGhzLiWntUdXVjyHg82J1Du722N3Nq+kTXtaIiTJjAPWxvwmo
         w7FWpba672n9dmOHTOnL7EJ2YgmcLC+W91nf6lVSBdtaELm3huRaUCXMO48l8JgQescY
         GMTMWvuyni/CERnBLXJPR+gyA+ZrHjDFwciTW8Mqwl/fCCPHj6APYEoeyrBDu6hCZulT
         0wSv8JVQZ6HpI8Mb7TMmdUgJrnnqPItTejGra0kCYDG4oOlXzrKu1Y/7w++ukEUGgL01
         XHLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="KzEMLh/C";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id o5-20020a17090ab88500b0029936d5e739si38145pjr.3.2024.02.16.00.56.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Feb 2024 00:56:09 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-607d9c4fa90so14633497b3.2
        for <kasan-dev@googlegroups.com>; Fri, 16 Feb 2024 00:56:09 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVPFA1N5J2XqJbSgQzVTULUFwV0lcUV/EmWfU6oagJwQMEzwl1u7lTl4PZGknA6IOWA+nMYoY1Gq/RzebBcFOHQPrYTLxIyfZoh/w==
X-Received: by 2002:a0d:e606:0:b0:607:9d64:d68d with SMTP id
 p6-20020a0de606000000b006079d64d68dmr3931990ywe.11.1708073768807; Fri, 16 Feb
 2024 00:56:08 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-14-surenb@google.com>
 <202402121433.5CC66F34B@keescook> <CAJuCfpGU+UhtcWxk7M3diSiz-b7H64_7NMBaKS5dxVdbYWvQqA@mail.gmail.com>
 <20240213222859.GE6184@frogsfrogsfrogs> <CAJuCfpGHrCXoK828KkmahJzsO7tJsz=7fKehhkWOT8rj-xsAmA@mail.gmail.com>
 <202402131436.2CA91AE@keescook> <af9eab14-367b-4832-8b78-66ca7e6ab328@suse.cz>
In-Reply-To: <af9eab14-367b-4832-8b78-66ca7e6ab328@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Feb 2024 00:55:55 -0800
Message-ID: <CAJuCfpF_RbdQhUpJfQNiYHXwheojF07R-L7Y53tmLZRgr7iR6g@mail.gmail.com>
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Kees Cook <keescook@chromium.org>, "Darrick J. Wong" <djwong@kernel.org>, akpm@linux-foundation.org, 
	kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
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
 header.i=@google.com header.s=20230601 header.b="KzEMLh/C";       spf=pass
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

On Fri, Feb 16, 2024 at 12:50=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>
> On 2/13/24 23:38, Kees Cook wrote:
> > On Tue, Feb 13, 2024 at 02:35:29PM -0800, Suren Baghdasaryan wrote:
> >> On Tue, Feb 13, 2024 at 2:29=E2=80=AFPM Darrick J. Wong <djwong@kernel=
.org> wrote:
> >> >
> >> > On Mon, Feb 12, 2024 at 05:01:19PM -0800, Suren Baghdasaryan wrote:
> >> > > On Mon, Feb 12, 2024 at 2:40=E2=80=AFPM Kees Cook <keescook@chromi=
um.org> wrote:
> >> > > >
> >> > > > On Mon, Feb 12, 2024 at 01:38:59PM -0800, Suren Baghdasaryan wro=
te:
> >> > > > > Introduce CONFIG_MEM_ALLOC_PROFILING which provides definition=
s to easily
> >> > > > > instrument memory allocators. It registers an "alloc_tags" cod=
etag type
> >> > > > > with /proc/allocinfo interface to output allocation tag inform=
ation when
> >> > > >
> >> > > > Please don't add anything new to the top-level /proc directory. =
This
> >> > > > should likely live in /sys.
> >> > >
> >> > > Ack. I'll find a more appropriate place for it then.
> >> > > It just seemed like such generic information which would belong ne=
xt
> >> > > to meminfo/zoneinfo and such...
> >> >
> >> > Save yourself a cycle of "rework the whole fs interface only to have
> >> > someone else tell you no" and put it in debugfs, not sysfs.  Wrangli=
ng
> >> > with debugfs is easier than all the macro-happy sysfs stuff; you don=
't
> >> > have to integrate with the "device" model; and there is no 'one valu=
e
> >> > per file' rule.
> >>
> >> Thanks for the input. This file used to be in debugfs but reviewers
> >> felt it belonged in /proc if it's to be used in production
> >> environments. Some distros (like Android) disable debugfs in
> >> production.
> >
> > FWIW, I agree debugfs is not right. If others feel it's right in /proc,
> > I certainly won't NAK -- it's just been that we've traditionally been
> > trying to avoid continuing to pollute the top-level /proc and instead
> > associate new things with something in /sys.
>
> Sysfs is really a "one value per file" thing though. /proc might be ok fo=
r a
> single overview file.

I'm preparing v4 and will keep the file it under /proc for now unless
there are strong objections.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpF_RbdQhUpJfQNiYHXwheojF07R-L7Y53tmLZRgr7iR6g%40mail.gmail.=
com.
