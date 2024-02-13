Return-Path: <kasan-dev+bncBC7OD3FKWUERBIG3V6XAMGQEIHJUJKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4735D853EAD
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:30:57 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-68c7947e07dsf53679006d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:30:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707863456; cv=pass;
        d=google.com; s=arc-20160816;
        b=kqttyqsoIzwk1+SwjzVpHkfvSxDsyXBukERItVTBKPDOlxeQLB3bTgSgQIrmxebn0b
         JaDGSbC/w3sIWivkNo2IGKC/4imtYJ9zX3wb4FIZMAP5IYshmsRvKp3Lvdp15OWL98au
         9e5TOvPny5kGMceRJx6mH1/SsclUn8uBlAuGUbekTubKeto63F4/1BQpXJOh3ynbgEZL
         xYy5Bgzpj3qqtlX4cxDvfBzK0rrMzinvTlHw4KXrYRBL+t+n/Ly3IQ0fuvQN1TqBG6Ti
         q9+qecfiga/EktzJH92G5uGxC4UDfQfyEaAZDtBnzXPc9ixwVi7lk3XZ8w0jHdysNZ+h
         gfnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4986psV7bqkH6dnmYMwB3tJmndDiyirMRm7LFMksoGQ=;
        fh=kJy96SyX7C3lFi6mKaoeBWqwf814SpmL8+5PPwkjSSU=;
        b=va18sH1rfMR7BMuBPal7ld3DLRA+ylJCT+ZBY4MuR1tlSxaseMcDLdJAjSgFOx3Rag
         V0ZNIu9Wf4gTcs9Clx2fYUQi14UDTUOFUhzQbGVCcOpkl2pJ9LS6/OXz2x3qMaVcpXOD
         PlMviG3DsM666cypdFIoNYZ1qgUHD2xkWkkLp8hogMJ7pgmGt6OK3pIROCZh5SqN4BYq
         fEZSbaD+hUP3HfeTe3ncuHfsfmdwN0jEwWhAxIsoiislQfr1DHqpeWJgZgl9m91NT1+5
         SnInMhRrP3rdMXQnstKhIUNE3MpVKzTpwI+tcfFixQQG1eFqQ8mCm6E6rv5vTKpswgmt
         pLdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="nDx/grTO";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707863456; x=1708468256; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4986psV7bqkH6dnmYMwB3tJmndDiyirMRm7LFMksoGQ=;
        b=enk8lVCJUOyNlou8yzcshzGD236Rm1a7F1UhEgjDvM1R5L/Lx7XvCmD+aSIYgo5RRS
         VTu6N3+eA6i1i45lMuTso/I0XX34Y9AKhUcJbIp/iF5GaOJSCxoLIS90BokLIIz3NBKW
         R8v9kSOgrBE2mUA/VmeN9kIuZuTIoZ9wIL5DezmPtw20cbvnsrt+vwXL3PTQxOUCNbyU
         iVjkxSgfjpNqXbEu8GH43Xy3wy8VrbwIkaafDvb9fNigXiZKMX+TmQuYSJ7QwkjkLQ1u
         nz4AED5tDLojJ6YAs8AxuhI5EK77SvgaMGl7MSwU0nfJCkvbGjh3Di5OFnTSnIpeYlXM
         YQXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707863456; x=1708468256;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4986psV7bqkH6dnmYMwB3tJmndDiyirMRm7LFMksoGQ=;
        b=vj3RrFKOk+wb9+4ZTXm1BKu+oaQLw1ET3o4rG4SM8loAJxrPC8PdRWGbsQWPoD/if3
         faL/Du+bwwatBBkZaY39fnMbWag7VhD08w8fP9HBWa65zJqpfaMgVvHkhO9DAcfezQ3d
         nnAp3Gn/tcaLVVV05zvkmEXAr7CGnUQQ6RSoeDxf0uNVhRykcgKAOqyYousCiwE7SlOu
         n5ib9N3S15xwbpWDEq3DJDwGLEMOOVJFdG6mOkB5zFjkzNbBCZZUwe16tkiI7ozoMeE0
         PydymiOVCXmKKDw2tNyEY05yx68rF83qAqs19U+B2Ja54SAV20aw4Ar0r/wk61kKTvLX
         HjZw==
X-Forwarded-Encrypted: i=2; AJvYcCVJhNy0OBriA7tVtxWNiLLtD9Sp6ZYctGbLhMJHLZj3MhlXj26DQIwuXf+b0UWQTjvB6EsFNdRJkFJAjso50MknhaXNTMk6jA==
X-Gm-Message-State: AOJu0YyafuYtYjIeIIJeJiGL6deqAljGUp8mxtnWe3sw6R8qXVYAyOzT
	RT6GHN3R8y182tq9PNmILxVgut3sDsvDrNYgGyuK+k3pPUQHKwPo
X-Google-Smtp-Source: AGHT+IEG2iN3JPK0qjYvYwZAmWUBkl8sAORb12LMNTd9mbz+lF0JsA5qqHr0APtw3MistsV7PXqX6Q==
X-Received: by 2002:a05:6214:130a:b0:68c:ba1b:e495 with SMTP id pn10-20020a056214130a00b0068cba1be495mr1187641qvb.43.1707863456300;
        Tue, 13 Feb 2024 14:30:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1c42:b0:68c:bf72:c903 with SMTP id
 if2-20020a0562141c4200b0068cbf72c903ls7042316qvb.1.-pod-prod-03-us; Tue, 13
 Feb 2024 14:30:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUixOsvZ2+H7R45nd80SmldCFnVhPcIl21pcUgpsbpTnfq6phu/VnUp5en+EpELqaWvYgtQAzFU8T7QLthdhBP5zU5iiq2pB1vldQ==
X-Received: by 2002:a1f:ea43:0:b0:4bd:7bf5:934c with SMTP id i64-20020a1fea43000000b004bd7bf5934cmr934431vkh.4.1707863455427;
        Tue, 13 Feb 2024 14:30:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707863455; cv=none;
        d=google.com; s=arc-20160816;
        b=nCNWpkDghguIHGeJ2uF1XvXUcWdq3bNC5XkIK+jivp0joJNJXhs2u1WhRiE6rJzZ29
         2M9lKDTQ16Mk0LpQYBN88wCl7bK4U2r7U9Xt9dg+5NDsL/dT37oTjsMsXEfUzcDU0VaD
         DhylDHW4X5J/bJWlVt7c68fwHyGV6wGywjipI5rgNa7UaEviztQvH3BV4KmTbrCSSash
         mhBe83CDSaJ0Jzm409pko1BSmRXmCL5axjz0i3xjXJPRWXxzlS9iZeoChUT1oq/uef83
         B7jaAxCdhzd8X/Dy1dWhQ2Sb0r9DrDZcZEzkem0a1TEkdJl7D3pq6gaYkc3IqBBW2FgT
         Qd/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=W3iVhRNI3SJOZTKFO/V2hJvAlU1SxV9FtnbmB6rZ05w=;
        fh=ZIm4Co4tSVO71wlWIE0n/IZaiG/CAa107/Kdy2H+oag=;
        b=fIT69o+esw4VX7tgFB4nYXI74oLtYk4tC3usPLrQBlmqJdQ6ffuHhS1lW5JumDzthU
         u4anpDgFTgeAN/XZSZM9DVUNvwjfH5i9R7YE4xYcCslPNrtkrphsQgOzqXgHs9jdkwfC
         tMldXyEwvMm3fp2dV9L75hNef+Sesj7J03CTNDOA641b8dG9yUiLsbpwJmTPsWi+TCYz
         FcWu59MFY7r3hPSQfFRxxSYngN8TTm6LP3CX3RxHnH80AmtuGNLf4EJmvo7aTxrTGIQR
         vaW1fhGipEn5Rj/uTS3auNngR+QWTsPxyhAmMnXR50CceEB3mNWpiGG+IYr8JcK4PYAX
         01LA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="nDx/grTO";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUQPcjA0+G9s41/eW9hilG91tpp37ObsJJMXpEvLqbeI/dATP/pbfsfrez9qsQxkFMK0dG1G2tR55PFN/54ROp5os6QLe9jMR/M6Q==
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id l34-20020a056122202200b004bd8843d8a7si960218vkd.2.2024.02.13.14.30.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 14:30:55 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id 3f1490d57ef6-dc742543119so4203105276.0
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 14:30:55 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUgQuzJyNmC40D8yAJsmmlfRSqnhbXJCWcbnHVPJaUikiYDFk7h5gJku/v08At7wDp/9QlDiMAo0U/NEidYo+Fq+v4bSuG+7evTkQ==
X-Received: by 2002:a25:e0d2:0:b0:dcd:df0:e672 with SMTP id
 x201-20020a25e0d2000000b00dcd0df0e672mr440832ybg.47.1707863454566; Tue, 13
 Feb 2024 14:30:54 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com> <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
In-Reply-To: <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 13 Feb 2024 14:30:41 -0800
Message-ID: <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: David Hildenbrand <david@redhat.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Michal Hocko <mhocko@suse.com>, 
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
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
 header.i=@google.com header.s=20230601 header.b="nDx/grTO";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as
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

On Tue, Feb 13, 2024 at 2:17=E2=80=AFPM David Hildenbrand <david@redhat.com=
> wrote:
>
> On 13.02.24 23:09, Kent Overstreet wrote:
> > On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrote:
> >> On 13.02.24 22:58, Suren Baghdasaryan wrote:
> >>> On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@suse.com=
> wrote:
> >>>>
> >>>> On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
> >>>> [...]
> >>>>> We're aiming to get this in the next merge window, for 6.9. The fee=
dback
> >>>>> we've gotten has been that even out of tree this patchset has alrea=
dy
> >>>>> been useful, and there's a significant amount of other work gated o=
n the
> >>>>> code tagging functionality included in this patchset [2].
> >>>>
> >>>> I suspect it will not come as a surprise that I really dislike the
> >>>> implementation proposed here. I will not repeat my arguments, I have
> >>>> done so on several occasions already.
> >>>>
> >>>> Anyway, I didn't go as far as to nak it even though I _strongly_ bel=
ieve
> >>>> this debugging feature will add a maintenance overhead for a very lo=
ng
> >>>> time. I can live with all the downsides of the proposed implementati=
on
> >>>> _as long as_ there is a wider agreement from the MM community as thi=
s is
> >>>> where the maintenance cost will be payed. So far I have not seen (m)=
any
> >>>> acks by MM developers so aiming into the next merge window is more t=
han
> >>>> little rushed.
> >>>
> >>> We tried other previously proposed approaches and all have their
> >>> downsides without making maintenance much easier. Your position is
> >>> understandable and I think it's fair. Let's see if others see more
> >>> benefit than cost here.
> >>
> >> Would it make sense to discuss that at LSF/MM once again, especially
> >> covering why proposed alternatives did not work out? LSF/MM is not "to=
o far"
> >> away (May).
> >>
> >> I recall that the last LSF/MM session on this topic was a bit unfortun=
ate
> >> (IMHO not as productive as it could have been). Maybe we can finally r=
each a
> >> consensus on this.
> >
> > I'd rather not delay for more bikeshedding. Before agreeing to LSF I'd
> > need to see a serious proposl - what we had at the last LSF was people
> > jumping in with half baked alternative proposals that very much hadn't
> > been thought through, and I see no need to repeat that.
> >
> > Like I mentioned, there's other work gated on this patchset; if people
> > want to hold this up for more discussion they better be putting forth
> > something to discuss.
>
> I'm thinking of ways on how to achieve Michal's request: "as long as
> there is a wider agreement from the MM community". If we can achieve
> that without LSF, great! (a bi-weekly MM meeting might also be an option)

There will be a maintenance burden even with the cleanest proposed
approach. We worked hard to make the patchset as clean as possible and
if benefits still don't outweigh the maintenance cost then we should
probably stop trying. At LSF/MM I would rather discuss functonal
issues/requirements/improvements than alternative approaches to
instrument allocators.
I'm happy to arrange a separate meeting with MM folks if that would
help to progress on the cost/benefit decision.

>
> --
> Cheers,
>
> David / dhildenb
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
kasan-dev/CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw%40mail.gmail.=
com.
