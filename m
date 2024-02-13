Return-Path: <kasan-dev+bncBC7OD3FKWUERBTHIV6XAMGQEYB37EAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 19276853F4C
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:59:26 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-42db934c1f8sf1714061cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:59:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707865165; cv=pass;
        d=google.com; s=arc-20160816;
        b=xHaq/ZiFQFMcH0PY1ky3okpIQ2G8q7IeQS3mTPm3PvTBtZ3sD5orhJM9qkbX7ZxTLJ
         1buiOPHYRgqjx4KOH5btOLqv9OHgZpa62CMHWZ5Gj0vue2msCO8ak2sCFRXt4KXU2ltA
         0y9Wj2aFK6LE4/DQA3O9diSUz8HHgT8B/eCe8qjruIzJzJhLb6m2zbea3b2eKoWu+a8d
         QLvohHxewQcW2HkM8MBL+DnjRut0o4u81YAMuFhr8bVgV9bKTezuQW467dNQ238JFeKF
         3jGTArK7MgDdyoLKT7BixlTWrhXi2r/ck4I9AGpbM5vXvgr9sgpD3m30MEst4p3kGOUn
         OH8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+cm7gY9xph4yrVhMk4iG2JLGq9M/lBi61DwMBO2dwqI=;
        fh=e4+8/Y0KIrzdm9EQZdi+VSK9xr9hdrkUp3OqO1gdBIE=;
        b=y92+C2NqyblP+HpY3HGAc0AxTJq5LS/9O6JIt7FRchzIsG3HP2KeLIxTZx/Hv3cGHR
         rVRAlNppbcXimTQQLuQAsNilh9nDpUIF20tsB/NAZHDyrOYsqS87enJa3fc7Gq1OcR1x
         PTWXGwJphEl/uoRDqQnnQ2SYCxAYWPTVx/eBh1WYe0eujG+qn0IeNi5BdHhIkkoNWcyR
         1zrZFa4hOJcWHboVYDf2fjyjCevCs8416zVykQr8j5J3hSqrzVtkejnvB1QlJ4YgqqBh
         ASkMR2uKKl5eKGun3BETuF5e3IEW8vJZnA3ySXHdEgQTlNCW6NrgCZxW+oaM5OndcrDE
         ZKmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ayUP4FqD;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707865165; x=1708469965; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+cm7gY9xph4yrVhMk4iG2JLGq9M/lBi61DwMBO2dwqI=;
        b=VlWkY8ZDYIHWLPlWD0a7c+aE9aFBFl3rXAjxWxpMhUMCSWo72vLay8dZMyRv3jIVy5
         a9E7e+7YACQ8I9Yhm7OkmmMCRNy1EVpslOrd4VwlvUtlxXVu18Y/dGSWS3FrFB1HO7pu
         /yZ7ZmLwW3vmNtoRxtRBNzXnY8l+0JwGxhaNAq8/rW9wjH8s2NIyN6s5dgbKukHpfKB+
         3DYfKP1fxhCf+YPGO6mgJAzEsolr0UvPrMo8EkieVk+5Mbt0PSYPxIGN49ydUZyXUKiH
         8IArhVvf7L2wTez98dad927Bnbot0uuGRHYpRj4g5WVFdx7XwQ1GKpipCbwf81zkzNgN
         ZKdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707865165; x=1708469965;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+cm7gY9xph4yrVhMk4iG2JLGq9M/lBi61DwMBO2dwqI=;
        b=UyaKMWJAPXzwZdY9Y76nal7xLH3f5PFU0poLUGf6B9wS/9NJf5OmxU3VyXBLyFjbUF
         RxBfaj8wC7zpapKEa3Yz1XUZqxDEy4uG5l3KsvGxSQugSInMb3sD9Ycb9RG+0g8iBxo0
         hdSylxJB+lLwjeq8KE5fETx2Co/ebZukjghovYjlR8CjbH5liNACNECEF/pdh1oT5roy
         eXPiwU6ZghJdTX04pIrZY49BLs9oOyPpvsVR2hhTv/8I8RfYqJlnd405cKGfZClPuvJr
         i/xnBivDmx5f2iyql5623fmwrBrDM7zTQrA5VNrfydOJPXjXyvQ9ObVcHOsB5TvlLaBy
         Jq5Q==
X-Forwarded-Encrypted: i=2; AJvYcCVpma1NPaJ1jSlzfKbzlHiAQC2+k0/k4u+8nmqQ0rFLY+lF4NfLrhSu9AcygqHx3d+N4Xy2Z6KGfx3cC2VI1Q1bDT99yortDw==
X-Gm-Message-State: AOJu0Yzi4fNTys97KJEaWT05jwN/Kv7JRPskhw7et/NwfSUKh/Hn506K
	sgct25I5dGJoL0YvACazZDcAs0HsaV9vufSMExO2dHGVCOytKGKp
X-Google-Smtp-Source: AGHT+IGQgDMD+tZD9aYppqUOAQg9ccUG6XLksReg6D5BNcMJ1WG3Lb2EEh7/vPrI7XE2/NH8DvPA/g==
X-Received: by 2002:ac8:7d8c:0:b0:42c:7da1:693a with SMTP id c12-20020ac87d8c000000b0042c7da1693amr793263qtd.36.1707865164969;
        Tue, 13 Feb 2024 14:59:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7dca:0:b0:42c:95fa:382f with SMTP id c10-20020ac87dca000000b0042c95fa382fls2518569qte.1.-pod-prod-05-us;
 Tue, 13 Feb 2024 14:59:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWXeejGtwzsTdFJqmfizFpN5E4PuOtKhrtPvLGZMe+cagoXKoJ7fgUWnIGu8aSHWdk/h0Nl/jDRWWW4w8synUSuLKraso3EHaN9Og==
X-Received: by 2002:ac8:59c8:0:b0:42c:dcd7:bbc9 with SMTP id f8-20020ac859c8000000b0042cdcd7bbc9mr904543qtf.38.1707865163543;
        Tue, 13 Feb 2024 14:59:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707865163; cv=none;
        d=google.com; s=arc-20160816;
        b=H2nu/GkH8FX1Z8X93RvPAZmf2MPA1uDbGGYlY+RDQ7lAEUboaBEFPxBIjNK31vg5OG
         lUHw5ZxvX1gjaEPxnPyKrAIcqSlc+HEwu2ZExKGLgw5V9cxoiODBQQsi7WDz+wPqj5NS
         +pFzOwYDVeDBj9Cib9M8b0kWbB6Rv6C2oPgHanWQMRlC3EOSNcYa6H/5iPyXf8WJeALN
         34LAtOr2Tm2uvxtOkLQ0TLdRvW6Q32qde4eU4j/Aqsm7iqoZXYcCpyX8NHUKf0tt2FzH
         YkLHe9cPlVS4adjUVbbmert8yPYvwDyRbH4RtPn0j093+ELVUxIo8LRW3nbSKCMVeaGO
         yvbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=844WXX5yd15NBvKyBWDdzovUDDmAUcOrqOuOYCpCKD8=;
        fh=1DExSe7I8HgxJhqb2CtSsybyr3WA84wraBd9PVklr7Q=;
        b=LvwcsYcBtd7gRBYwbuM35Bm0vcMeMrgoZVCWWQPav+cFe5PNuycEo8DECLmUz5/rB1
         2BIgvj8nWXbYWqQ8wGxpdaYklyEWKSX4/VkLrowLgymohoSHL6n6ceCZ0A4OqNpBQCNx
         nkj5e+Sp1sf52Bkt/hdwbrrAH+kx9fGfrUYutxHvBO/W4lKjrbrQ/L/E35ZzZNt7UXQ/
         WURTzo47ZXNVbpyOlDAY9U57x1FYJV5jQJN+pmElqCRWxz08uZmtg/jPObcZzIaIDJiJ
         1QUouEhyzq6sz3ydMfLBjj7SnCgzfQ+x0fKxCODbmIK60yUn26RKvGX6s3EimmojgMvZ
         5DfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ayUP4FqD;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXd94oilwICLMJpSUeouKsnQgHWsTxI9UpbfK7oBmaww/tbnRMj4AspXYg2ZFR67M3P1jBkRD+xWSsYbZi83LlJddFZXmOw6ofr7Q==
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id qg5-20020a05620a664500b00785d4bdc268si524786qkn.2.2024.02.13.14.59.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 14:59:23 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-dc238cb1b17so4683675276.0
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 14:59:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXGJPXCDjuV32fD/Txx9H4K7VHEJNrFiPCVq1lcU4LS48ziio0n2YNuRhvEgPPGK6rLqMGZdk5/AeAzihqu5Ph0JdVED/dIOO4BHw==
X-Received: by 2002:a25:8691:0:b0:dc6:1869:9919 with SMTP id
 z17-20020a258691000000b00dc618699919mr694753ybk.41.1707865162739; Tue, 13 Feb
 2024 14:59:22 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com> <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com> <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com> <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
In-Reply-To: <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 13 Feb 2024 14:59:11 -0800
Message-ID: <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: David Hildenbrand <david@redhat.com>, Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=ayUP4FqD;       spf=pass
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

On Tue, Feb 13, 2024 at 2:50=E2=80=AFPM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Tue, Feb 13, 2024 at 11:48:41PM +0100, David Hildenbrand wrote:
> > On 13.02.24 23:30, Suren Baghdasaryan wrote:
> > > On Tue, Feb 13, 2024 at 2:17=E2=80=AFPM David Hildenbrand <david@redh=
at.com> wrote:
> > > >
> > > > On 13.02.24 23:09, Kent Overstreet wrote:
> > > > > On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrote=
:
> > > > > > On 13.02.24 22:58, Suren Baghdasaryan wrote:
> > > > > > > On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@=
suse.com> wrote:
> > > > > > > >
> > > > > > > > On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
> > > > > > > > [...]
> > > > > > > > > We're aiming to get this in the next merge window, for 6.=
9. The feedback
> > > > > > > > > we've gotten has been that even out of tree this patchset=
 has already
> > > > > > > > > been useful, and there's a significant amount of other wo=
rk gated on the
> > > > > > > > > code tagging functionality included in this patchset [2].
> > > > > > > >
> > > > > > > > I suspect it will not come as a surprise that I really disl=
ike the
> > > > > > > > implementation proposed here. I will not repeat my argument=
s, I have
> > > > > > > > done so on several occasions already.
> > > > > > > >
> > > > > > > > Anyway, I didn't go as far as to nak it even though I _stro=
ngly_ believe
> > > > > > > > this debugging feature will add a maintenance overhead for =
a very long
> > > > > > > > time. I can live with all the downsides of the proposed imp=
lementation
> > > > > > > > _as long as_ there is a wider agreement from the MM communi=
ty as this is
> > > > > > > > where the maintenance cost will be payed. So far I have not=
 seen (m)any
> > > > > > > > acks by MM developers so aiming into the next merge window =
is more than
> > > > > > > > little rushed.
> > > > > > >
> > > > > > > We tried other previously proposed approaches and all have th=
eir
> > > > > > > downsides without making maintenance much easier. Your positi=
on is
> > > > > > > understandable and I think it's fair. Let's see if others see=
 more
> > > > > > > benefit than cost here.
> > > > > >
> > > > > > Would it make sense to discuss that at LSF/MM once again, espec=
ially
> > > > > > covering why proposed alternatives did not work out? LSF/MM is =
not "too far"
> > > > > > away (May).
> > > > > >
> > > > > > I recall that the last LSF/MM session on this topic was a bit u=
nfortunate
> > > > > > (IMHO not as productive as it could have been). Maybe we can fi=
nally reach a
> > > > > > consensus on this.
> > > > >
> > > > > I'd rather not delay for more bikeshedding. Before agreeing to LS=
F I'd
> > > > > need to see a serious proposl - what we had at the last LSF was p=
eople
> > > > > jumping in with half baked alternative proposals that very much h=
adn't
> > > > > been thought through, and I see no need to repeat that.
> > > > >
> > > > > Like I mentioned, there's other work gated on this patchset; if p=
eople
> > > > > want to hold this up for more discussion they better be putting f=
orth
> > > > > something to discuss.
> > > >
> > > > I'm thinking of ways on how to achieve Michal's request: "as long a=
s
> > > > there is a wider agreement from the MM community". If we can achiev=
e
> > > > that without LSF, great! (a bi-weekly MM meeting might also be an o=
ption)
> > >
> > > There will be a maintenance burden even with the cleanest proposed
> > > approach.
> >
> > Yes.
> >
> > > We worked hard to make the patchset as clean as possible and
> > > if benefits still don't outweigh the maintenance cost then we should
> > > probably stop trying.
> >
> > Indeed.
> >
> > > At LSF/MM I would rather discuss functonal
> > > issues/requirements/improvements than alternative approaches to
> > > instrument allocators.
> > > I'm happy to arrange a separate meeting with MM folks if that would
> > > help to progress on the cost/benefit decision.
> > Note that I am only proposing ways forward.
> >
> > If you think you can easily achieve what Michal requested without all t=
hat,
> > good.
>
> He requested something?

Yes, a cleaner instrumentation. Unfortunately the cleanest one is not
possible until the compiler feature is developed and deployed. And it
still would require changes to the headers, so don't think it's worth
delaying the feature for years.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q%40mail.gmail.=
com.
