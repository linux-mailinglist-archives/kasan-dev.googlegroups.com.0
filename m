Return-Path: <kasan-dev+bncBDH6XEHUZMDBBGHOV6XAMGQEE7FDIEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E3364853FBB
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 00:11:21 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-dbf618042dasf2430350276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 15:11:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707865881; cv=pass;
        d=google.com; s=arc-20160816;
        b=fwiCIiPKcpn4AfvW0Y8Yr1Epoh/CyWyq00esW5suLxja5vtUl4FouwxOOVMEe0mGwz
         VYKTedW0gf0pDtyYfnHdomq8CBc4mwebjuoKuQq8eutq0deuNkw8iNURTzNeiSnfcMmV
         zQmA/Dc41a98jWRbSUc5yb1UIHFSs0j1u/lp4bFgg8csBk5lTkPJnrDpfuV63VQnr/b5
         PBJvUINArdu+aOTD51TDhs2g7D/dWO1KhHW+vc3FyhPEcmqkkOTxymB+MtfOi19Qn1OF
         2ku9ypyWa9vgrnjYFfqJnsNf2+RXZWMc/3eluP7eWc5bcejpjR56llAYIe0IvolSA41n
         zXkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Js73TxFQ4MkpyMFAlTni5EgCJCsmySzHXA12XdSO/AI=;
        fh=bfWLmuypghd+DIt/20yxwGdL+xnmoNMFIhfbgTzSZlY=;
        b=W0ihx6k6yKdKv3mdj8FTIBRsBb9E/SrLv7VTACoCdkqgJm+HohPGFfiN8nQLl4Sh45
         tMYfcYIAu76FYSUcaIFWDQ93UuczkfoakePZ3jO2fuUEAbWNXSDKduuz2SVuC0xYJG4R
         GK2phOM8lTIweKtNCRp4TjDRV91KjkVi0gfllbD4E+jBmnrcdyVAEHaQ6H0xFpa8s8XE
         HsMlKaGZAXEBqAuGZxwns/VgHpiqHDw8rBE9GQewNahXFFK81B3TWsOVqc+c762H2PXA
         6aLkjW+Kz6tQoU4J6VPVF7UI1k2F6ZkZLYSA9DA2xgZmS2kfPXIi0vVS+dEwMhGTSFty
         fPDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ToFeO/6+";
       spf=pass (google.com: domain of djwong@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=djwong@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707865881; x=1708470681; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Js73TxFQ4MkpyMFAlTni5EgCJCsmySzHXA12XdSO/AI=;
        b=Pom8Odxo6PyNHf/AZfTO8VLOcovM/nmL8ZXfQ89BpNye6xFWb3WYes6VNPIxrwsOvG
         Y/QvOcVAtpZBHML4J0MazG7g0pxYUHK21MR6BYXYKfilyIraimynij7PV0OxF7shtgiA
         rVK96GqwfTqDJD0oqHchcQYngfcYCWg0aEXZ+AeMbwm3tLn/Jrl/5QG8nMk/Bw3hqEUQ
         lfYCM3/9U70woVY5oEUBS7rUhiEJeqRlgX9rbz/5AR6v0DqBDxiV7GspRDgOL5/n2Spv
         toP8QIPWBy0Vytqkelxn4LHDnTTprNZ1ye60TuRfBH3LyyIz/6qc0jv3qtMiPNfvsS8F
         o3Bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707865881; x=1708470681;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Js73TxFQ4MkpyMFAlTni5EgCJCsmySzHXA12XdSO/AI=;
        b=TyPswNKBHXv9WonYXutqhdIZ7sJuJzicrP12xgH3mwGsXwwxDFtAmvc1GmKB24a8e7
         8ArH0ThQQiPn5CZi1j70MF3fxRJ6yfv7uQ9sQGLY1PBPauTnXnScsHjyle5hJGf60nsT
         EBYG6sf3aA8voHTHRWRhHsR8uirYRK9JY9fXw9QTNBCZ4BtG6detI3/ptV9wcrML2EBO
         okDzILIXpTOQKnBkyrkS2kJMQF3mYAEDYUkPmU2NnDz+upJ46EftCQIWgMk1ttZm1yy2
         NpV/P8BRsAWhmZkVQHlnIq0aPUNmO6lF7GTX89CMzHxqOcO9dVg7vSFCxFUhu3icrK5z
         rX0g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbii/TkOVAx/D1tU2BTJDn6aTx7kCsw4s3wV/SJutuJdfFfqzFayJeIYI1krIl6WMPSZ/njz/YDuoytHWw/vZOL+Fo+/BhNg==
X-Gm-Message-State: AOJu0YytFHravMvVdMGermfkFqaN7C5M2BGLtBGmqC0ZX9XJi3d4+I38
	xurowB9JaNOLGNcYvR9kUTPU5z8vK9RlQMC58xKzwsDqxiyyLo+X
X-Google-Smtp-Source: AGHT+IHRQ1X1ZHqChA7iiRmdeAh2R6CHUzFOMKVjqSYLdPT17wdGYe12yLb5RwEutwmWNgyoEk7vaA==
X-Received: by 2002:a25:b14:0:b0:dc6:ad43:8cf4 with SMTP id 20-20020a250b14000000b00dc6ad438cf4mr782533ybl.20.1707865880773;
        Tue, 13 Feb 2024 15:11:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d050:0:b0:dcc:8ecd:49fe with SMTP id h77-20020a25d050000000b00dcc8ecd49fels493723ybg.0.-pod-prod-02-us;
 Tue, 13 Feb 2024 15:11:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUqsZUiFkwXo3C0A9+QC6rskc8KFZY2/MaNLKCySOym6Ry4Xxu1qi9bVihe/zU6fyX0ZiVbqfCDDuaMpHn7o9ukWmqbfCKHCgMNEw==
X-Received: by 2002:a05:6902:2506:b0:dcc:2bc:652 with SMTP id dt6-20020a056902250600b00dcc02bc0652mr766151ybb.60.1707865879866;
        Tue, 13 Feb 2024 15:11:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707865879; cv=none;
        d=google.com; s=arc-20160816;
        b=mU6u0MPHCqUo6EoUnAMWERC3ctlO9foPaJzI+e0xiXiL5DcLF4oxan0W1BlHxwBwZ3
         vb0Y1UeszIqjUf4/ZTTfUxYx3F71sA6PHhb8aefiAL1Z7OYM9RuRifVzh2XfN5HXt9L/
         moMqbiXipLLao1/7ODmsOI2GqPTz04GG4UnDGYoAEQDn64MZxujLh+6zIqsCxn25D5kA
         rOc6MEyxVktvmJozOApRId2bYapmxB97szYDCnnurKySZJVxVSC+4ClZBloxSC5tODDm
         tycF6YvAvWHxj/CXWcnfwj8vFbFvbDgFWzpx2EcoW14S3A1IFxqWp4Yhx1Po7LtuIa/2
         NVsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=uBlORA7oAiRZpmlLnSCkPETL6W80/9G4ERNL9yCsowY=;
        fh=l24VWGaTZwn+3A6SDi2NjGra6kpLYmz7oFFCZDX9x4s=;
        b=WGZLtASOHQKVs5ZTF3YakYWcBgPuDPD9k7LZAyTJfWo+b7r+1JWLXXzpyhc7Nskb62
         pfsR4j+BDjqTwKAk7y1Sc4ToANAoWnbgt/PJ9uDu8uyxuq5GdUc8vozxYZ9LoWTs6UQ3
         w+C/GotyS2LQ5htMLU7oQkXzqd1u44ekBMpv/yO0qBpt5QbV6PN3goMfOjr8XaCJHBUD
         X2O9dQBgwznUYgLghKkYKcJfN3qwXvTP/OtHuszzs4Cx0HXJjKHcU7EhGtsz94WkYJUl
         7WA0svI8KimFuI82Nc2yHdXOQ3wmtBvoKdtCfNCXanvX4qpk40ickDsTJ+VgckxCnjKj
         eeOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ToFeO/6+";
       spf=pass (google.com: domain of djwong@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=djwong@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Forwarded-Encrypted: i=1; AJvYcCVivo66BPMlZ6cp1EHI8RshIuEi3nbaGjm+e0CYl9jF5zMwblpB9PpxTlSQLUYSY1Xp1ey6XEmWteViHvQ2bczCCkPCuHSSI92Uwg==
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id p77-20020a25d850000000b00dc657e7de95si369501ybg.0.2024.02.13.15.11.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 15:11:19 -0800 (PST)
Received-SPF: pass (google.com: domain of djwong@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id EC2CDCE1F73;
	Tue, 13 Feb 2024 23:11:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1AB84C433F1;
	Tue, 13 Feb 2024 23:11:16 +0000 (UTC)
Date: Tue, 13 Feb 2024 15:11:15 -0800
From: "Darrick J. Wong" <djwong@kernel.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: David Hildenbrand <david@redhat.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, axboe@kernel.dk,
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <20240213231115.GF6184@frogsfrogsfrogs>
References: <20240212213922.783301-1-surenb@google.com>
 <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <huysjw5jiyd7m7ouf6g5n2yptg7slxk3am457x2x4ecz277k4o@gjfy2lu7ntos>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <huysjw5jiyd7m7ouf6g5n2yptg7slxk3am457x2x4ecz277k4o@gjfy2lu7ntos>
X-Original-Sender: djwong@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="ToFeO/6+";       spf=pass
 (google.com: domain of djwong@kernel.org designates 2604:1380:40e1:4800::1 as
 permitted sender) smtp.mailfrom=djwong@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Feb 13, 2024 at 05:29:03PM -0500, Kent Overstreet wrote:
> On Tue, Feb 13, 2024 at 11:17:32PM +0100, David Hildenbrand wrote:
> > On 13.02.24 23:09, Kent Overstreet wrote:
> > > On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrote:
> > > > On 13.02.24 22:58, Suren Baghdasaryan wrote:
> > > > > On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@suse=
.com> wrote:
> > > > > >=20
> > > > > > On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
> > > > > > [...]
> > > > > > > We're aiming to get this in the next merge window, for 6.9. T=
he feedback
> > > > > > > we've gotten has been that even out of tree this patchset has=
 already
> > > > > > > been useful, and there's a significant amount of other work g=
ated on the
> > > > > > > code tagging functionality included in this patchset [2].
> > > > > >=20
> > > > > > I suspect it will not come as a surprise that I really dislike =
the
> > > > > > implementation proposed here. I will not repeat my arguments, I=
 have
> > > > > > done so on several occasions already.
> > > > > >=20
> > > > > > Anyway, I didn't go as far as to nak it even though I _strongly=
_ believe
> > > > > > this debugging feature will add a maintenance overhead for a ve=
ry long
> > > > > > time. I can live with all the downsides of the proposed impleme=
ntation
> > > > > > _as long as_ there is a wider agreement from the MM community a=
s this is
> > > > > > where the maintenance cost will be payed. So far I have not see=
n (m)any
> > > > > > acks by MM developers so aiming into the next merge window is m=
ore than
> > > > > > little rushed.
> > > > >
> > > > > We tried other previously proposed approaches and all have their
> > > > > downsides without making maintenance much easier. Your position i=
s
> > > > > understandable and I think it's fair. Let's see if others see mor=
e
> > > > > benefit than cost here.
> > > >=20
> > > > Would it make sense to discuss that at LSF/MM once again, especiall=
y
> > > > covering why proposed alternatives did not work out? LSF/MM is not =
"too far"
> > > > away (May).

You want to stall this effort for *three months* to schedule a meeting?

I would love to have better profiling of memory allocations inside XFS
so that we can answer questions like "What's going on with these
allocation stalls?" or "What memory is getting used, and where?" more
quickly than we can now.

Right now I get to stare at tracepoints and printk crap until my eyes
bleed, and maybe dchinner comes to my rescue and figures out what's
going on sooner than I do.  More often we just never figure it out
because only the customer can reproduce the problem, the reams of data
produced by ftrace is unmanageable, and BPF isn't always available.

I'm not thrilled by the large increase in macro crap in the allocation
paths, but I don't know of a better way to instrument things.  Our
attempts to use _RET_IP in XFS to instrument its code paths have never
worked quite right w.r.t. inlined functions and whatnot.

> > > > I recall that the last LSF/MM session on this topic was a bit unfor=
tunate
> > > > (IMHO not as productive as it could have been). Maybe we can finall=
y reach a
> > > > consensus on this.

From my outsider's perspective, nine months have gone by since the last
LSF.  Who has come up with a cleaner/better/faster way to do what Suren
and Kent have done?  Were those code changes integrated into this
patchset?  Or why not?

Most of what I saw in 2023 involved compiler changes (great; now I have
to wait until RHEL 11/Debian 14 to use it) and/or still utilize fugly
macros.

Recalling all the way back to suggestions made in 2022, who wrote the
prototype for doing this via ftrace?  Or BPF?  How well did that go for
counting allocation events and the like?  I saw Tejun saying something
about how they use BPF aggressively inside Meta, but that was about it.

Were any of those solutions significantly better than what's in front of
us here?

I get it, a giant patch forcing everyone to know the difference between
alloc_foo and alloc_foo_noperf offends my (yours?) stylistic
sensibilities.  On the other side, making analysis easier during
customer escalations means we kernel people get data, answers, and
solutions sooner instead of watching all our time get eaten up on L4
support and backporting hell.

> > > I'd rather not delay for more bikeshedding. Before agreeing to LSF I'=
d
> > > need to see a serious proposl - what we had at the last LSF was peopl=
e
> > > jumping in with half baked alternative proposals that very much hadn'=
t
> > > been thought through, and I see no need to repeat that.
> > >=20
> > > Like I mentioned, there's other work gated on this patchset; if peopl=
e
> > > want to hold this up for more discussion they better be putting forth
> > > something to discuss.
> >=20
> > I'm thinking of ways on how to achieve Michal's request: "as long as th=
ere
> > is a wider agreement from the MM community". If we can achieve that wit=
hout
> > LSF, great! (a bi-weekly MM meeting might also be an option)
>=20
> A meeting wouldn't be out of the question, _if_ there is an agenda, but:
>=20
> What's that coffeee mug say? I just survived another meeting that
> could've been an email?

I congratulate you on your memory of my kitchen mug.  Yes, that's what
it says.

> What exactly is the outcome we're looking for?
>=20
> Is there info that people are looking for? I think we summed things up
> pretty well in the cover letter; if there are specifics that people
> want to discuss, that's why we emailed the series out.
>=20
> There's people in this thread who've used this patchset in production
> and diagnosed real issues (gigabytes of memory gone missing, I heard the
> other day); I'm personally looking for them to chime in on this thread
> (Johannes, Pasha).
>=20
> If it's just grumbling about "maintenance overhead" we need to get past
> - well, people are going to have to accept that we can't deliver
> features without writing code, and I'm confident that the hooking in
> particular is about as clean as it's going to get, _regardless_ of
> toolchain support; and moreover it addresses what's been historically a
> pretty gaping hole in our ability to profile and understand the code we
> write.

Are you and Suren willing to pay whatever maintenance overhead there is?

--D

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240213231115.GF6184%40frogsfrogsfrogs.
