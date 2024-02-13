Return-Path: <kasan-dev+bncBCS2NBWRUIFBB5HOV6XAMGQEDSDHGRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 56940853FC7
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 00:12:53 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2d0be4e5cf2sf52871321fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 15:12:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707865972; cv=pass;
        d=google.com; s=arc-20160816;
        b=QShz9BFpBE1Zr9giZxtFUy5+dc/ma7j3NDr/iWkwl7n0CyIAacU4qkH8H5b1ipbNMw
         PGwNRRp4Aa/FiZzlLHCiXZfZ+Xns4OJVJVp4z8tr59iK4vUsiJ0y0ArSSCWChRQLbvrP
         eYRy9s6qaWoRDB53vm8FpGjWCmkvCMyB/WXlFHp5c5YACWGmFYuIsBrT6KP7yCQDUnGk
         unZxUv4ytLwaJoG45HCdczDU9gWUedQUJRR/Tt+z7n9xYmxBclrb3SOV/Xnl8UP1LT2R
         1Jhzjo/X6IOKbSU9otzeyu6++GLld0eya8OIYsR2J52b2afOOnwuow0Xn1paMPR6QaUF
         8yvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=BRZR2CqKDVMBjci7IPjF+394re8nqLC/VfbO9yrTROQ=;
        fh=nO3kdRhaEeFE7FlHE0x7KcSTf2nswcHifzCIKDed9XQ=;
        b=jERd2BSd5McLX/2/qh4aHkQBuWNZkfout2EJN51snywbVZDhXpTGaZlnCHaMWQPEb8
         ItebDgCF1lYgDeI42Z+iVuJrsZ7JZTUPwuu3kvEM4WUWtAceI2REW//ReSzwA5HxvLK5
         nRKcWcly6W4Bkq8yErBsGpnMQ7MvtyRBqBvt0L91U72rwAudIlTFJWMDcERalV0sBnAn
         IKUlwrugmt7EI/kkW5e+nXix6FKL0Zf4C+vHgoml1ogiCfNBKYfMtCQhROPo+xQXaVbo
         ZVifq0aWe883ooB1eQGS45szJ8ctbmXjABb/ljqgDkCs01/USibYleiG82hlGFqi/t/4
         qWcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h9atok+b;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707865972; x=1708470772; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BRZR2CqKDVMBjci7IPjF+394re8nqLC/VfbO9yrTROQ=;
        b=cLG3e+k1kWHljGzD0mYN1Kk1oXZFlfMTlzKetq1ylovruGNvxPFwua+oi7kdhaROCS
         5LxcjKlTqc/ln5hA8gYJ1fP0G6gqo9Ht9alvcQ8lSmY6PfQvYBUg40IWOmUVq/7giBQE
         sHviM8/AqFrZpPlUl3tpkRKtLCQLT4zQXw7BWAU6U22QgFRM+dIu4uZAPK28JiT/f3Ns
         YdiBQxA+9rDebFph+CK04U77e3qhHAejvdj2OTzbDYlOOC6tx5le/G+/KAC6E/G4oPSa
         89Iw3fwpAAHtMFTvmzL+PiT8eIb0DOp54pfUGebPWlofaNX10ed0X7gCvXM37IkccKar
         YGjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707865972; x=1708470772;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BRZR2CqKDVMBjci7IPjF+394re8nqLC/VfbO9yrTROQ=;
        b=EgQohMCdwONyMXTRzFU+g5veEJ8vOtPzUqEXzRE3iZwQWl3XPDLV73xs6Q77rjT0yc
         WyMWAHrVG/QVPjpymlkidaM8TjnFwoCVKKt7sX+zJ3SucAQeepexHq+Co8dI9mBUkmrA
         gS0sZgtYVIbrkSuACDsevW+qp9DpKzM4cv6ENgtZdtZJh18JrUWwMupFWThsaxlyhTIM
         NdIk6l5uxYmhVWRq/YPQhwzQH/2VPNphetGCGaRovRIHOPN86KKlPr5zGq1z6iDVluuI
         DuKgdDYaUj+ILP2ZOuyar+a4WHrIilVQnUbBKiZEBCmXPRBJauxgpQ3Rrdy/ooskYO4Z
         UFIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUAIb2L1Q/CFbH46mMoabOPyfNtSK6HTzmidBMYVtuWcpEJOcbXMPd/efC/McQlk+N6jT7a7wiFjR579ASB+RNZVE7NoGea1w==
X-Gm-Message-State: AOJu0YynSCqh5DObQwFH/Ehs9Drp55Qhf5fFcZTAkKZb4y912cNX5nOG
	gKom7wkN0QAEtgdp5OLMi2/VQ2xHWP0PEl6AsYPZlKQlxuyzNgeI
X-Google-Smtp-Source: AGHT+IEc4JXKASPtt3KRzVnFk3oinR1TU0lNSetaH/qzGeWg/QqwAs1/epO2n4nZhdSEpAzqlKdXDw==
X-Received: by 2002:a2e:bc19:0:b0:2d1:1020:ab8b with SMTP id b25-20020a2ebc19000000b002d11020ab8bmr885743ljf.37.1707865972214;
        Tue, 13 Feb 2024 15:12:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5195:b0:411:969d:b0d8 with SMTP id
 fa21-20020a05600c519500b00411969db0d8ls862362wmb.0.-pod-prod-03-eu; Tue, 13
 Feb 2024 15:12:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVd2/pD/1gMGPpeUEOk3O8bGCK0+b9K4yAcEeLP12b1yp5Vzk7KzLebT1wAKxoGW9zKRgVatMnqtcwzQkfvmxWpG9jAHMIaDdlrRQ==
X-Received: by 2002:adf:f08d:0:b0:33c:df3e:a598 with SMTP id n13-20020adff08d000000b0033cdf3ea598mr521185wro.6.1707865970266;
        Tue, 13 Feb 2024 15:12:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707865970; cv=none;
        d=google.com; s=arc-20160816;
        b=edduhx/KrUopZD5IX0y4I+Uv89bnz+1I3H/lvlTF7KS7+wXHdQSCEafMD4eP1uDiDI
         Dtk2se6Nc/8lOsLrlwUMX8yWfOW5kWp+rvXQWLZM/ah6jBzL7Z5iEPcXXb4CLHK4l2F1
         gf5nLdXJSkPJuKWISZrP1H3MRxAmpM1vYlThCUlqdAuFjQW0gXhAVUeC4lRBQibz3vT2
         Z0ikkJSaJHPmONSMC23E6qnQI2wWWap/Cr7gfM8zR66heNtEOf07vJfHqP0vk4mO1U+V
         vBOPLwaLGtuYbYaH3Rb7hpwLqy+0xUF0JL4owQTyLHEju0ek0mC7H8NJwdqZ7i9rFRsZ
         /C6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=f0TdyX1LIEW+TxM6rJOce5L4g2KmC9LD2hQu+Hn6Qhs=;
        fh=QFlkgyyCQ5O38p+6S08QpUFaz8RHvuQLIIepbLH8S+4=;
        b=V7aYFn6m4ZTpM847tvVr7sjfrKbDpcuWPmjbKzuONlT0RvheQmycrr2xurb4WCMq1K
         diiufXWEg7Kw+VJQiSw2/UnVkOoOVwl7+ybm2GnuLFCEs2BF2zijOiffLJKrTnSkVhFu
         C03YD/yMa0IPjuri+uUvvmIIZPQRVBB1g+5jsqofgZLMvYHPeeer5Dh37lOcfJNWPQig
         i5ul0XeTrV34MV0gxeQFPxzj+6SVC4vNSNa8ycjkPhhSKnyEcN8U1G7pp75AJ961hvy/
         BOocr9+YxqNjrnHy89dZcu2T1i+mx3ahk7/3+SuD0bZclqkuJsE8cJbQioYbypes3X1I
         3H4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h9atok+b;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta1.migadu.com (out-175.mta1.migadu.com. [2001:41d0:203:375::af])
        by gmr-mx.google.com with ESMTPS id 18-20020a05600c22d200b00411e6461fa7si4791wmg.1.2024.02.13.15.12.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 15:12:50 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::af as permitted sender) client-ip=2001:41d0:203:375::af;
Date: Tue, 13 Feb 2024 18:12:38 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: David Hildenbrand <david@redhat.com>
Cc: Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, 
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <xbehqbtjp5wi4z2ppzrbmlj6vfazd2w5flz3tgjbo37tlisexa@caq633gciggt>
References: <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
 <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
 <a9b0440b-844e-4e45-a546-315d53322aad@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <a9b0440b-844e-4e45-a546-315d53322aad@redhat.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=h9atok+b;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Wed, Feb 14, 2024 at 12:02:30AM +0100, David Hildenbrand wrote:
> On 13.02.24 23:59, Suren Baghdasaryan wrote:
> > On Tue, Feb 13, 2024 at 2:50=E2=80=AFPM Kent Overstreet
> > <kent.overstreet@linux.dev> wrote:
> > >=20
> > > On Tue, Feb 13, 2024 at 11:48:41PM +0100, David Hildenbrand wrote:
> > > > On 13.02.24 23:30, Suren Baghdasaryan wrote:
> > > > > On Tue, Feb 13, 2024 at 2:17=E2=80=AFPM David Hildenbrand <david@=
redhat.com> wrote:
> > > > > >=20
> > > > > > On 13.02.24 23:09, Kent Overstreet wrote:
> > > > > > > On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand w=
rote:
> > > > > > > > On 13.02.24 22:58, Suren Baghdasaryan wrote:
> > > > > > > > > On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mho=
cko@suse.com> wrote:
> > > > > > > > > >=20
> > > > > > > > > > On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
> > > > > > > > > > [...]
> > > > > > > > > > > We're aiming to get this in the next merge window, fo=
r 6.9. The feedback
> > > > > > > > > > > we've gotten has been that even out of tree this patc=
hset has already
> > > > > > > > > > > been useful, and there's a significant amount of othe=
r work gated on the
> > > > > > > > > > > code tagging functionality included in this patchset =
[2].
> > > > > > > > > >=20
> > > > > > > > > > I suspect it will not come as a surprise that I really =
dislike the
> > > > > > > > > > implementation proposed here. I will not repeat my argu=
ments, I have
> > > > > > > > > > done so on several occasions already.
> > > > > > > > > >=20
> > > > > > > > > > Anyway, I didn't go as far as to nak it even though I _=
strongly_ believe
> > > > > > > > > > this debugging feature will add a maintenance overhead =
for a very long
> > > > > > > > > > time. I can live with all the downsides of the proposed=
 implementation
> > > > > > > > > > _as long as_ there is a wider agreement from the MM com=
munity as this is
> > > > > > > > > > where the maintenance cost will be payed. So far I have=
 not seen (m)any
> > > > > > > > > > acks by MM developers so aiming into the next merge win=
dow is more than
> > > > > > > > > > little rushed.
> > > > > > > > >=20
> > > > > > > > > We tried other previously proposed approaches and all hav=
e their
> > > > > > > > > downsides without making maintenance much easier. Your po=
sition is
> > > > > > > > > understandable and I think it's fair. Let's see if others=
 see more
> > > > > > > > > benefit than cost here.
> > > > > > > >=20
> > > > > > > > Would it make sense to discuss that at LSF/MM once again, e=
specially
> > > > > > > > covering why proposed alternatives did not work out? LSF/MM=
 is not "too far"
> > > > > > > > away (May).
> > > > > > > >=20
> > > > > > > > I recall that the last LSF/MM session on this topic was a b=
it unfortunate
> > > > > > > > (IMHO not as productive as it could have been). Maybe we ca=
n finally reach a
> > > > > > > > consensus on this.
> > > > > > >=20
> > > > > > > I'd rather not delay for more bikeshedding. Before agreeing t=
o LSF I'd
> > > > > > > need to see a serious proposl - what we had at the last LSF w=
as people
> > > > > > > jumping in with half baked alternative proposals that very mu=
ch hadn't
> > > > > > > been thought through, and I see no need to repeat that.
> > > > > > >=20
> > > > > > > Like I mentioned, there's other work gated on this patchset; =
if people
> > > > > > > want to hold this up for more discussion they better be putti=
ng forth
> > > > > > > something to discuss.
> > > > > >=20
> > > > > > I'm thinking of ways on how to achieve Michal's request: "as lo=
ng as
> > > > > > there is a wider agreement from the MM community". If we can ac=
hieve
> > > > > > that without LSF, great! (a bi-weekly MM meeting might also be =
an option)
> > > > >=20
> > > > > There will be a maintenance burden even with the cleanest propose=
d
> > > > > approach.
> > > >=20
> > > > Yes.
> > > >=20
> > > > > We worked hard to make the patchset as clean as possible and
> > > > > if benefits still don't outweigh the maintenance cost then we sho=
uld
> > > > > probably stop trying.
> > > >=20
> > > > Indeed.
> > > >=20
> > > > > At LSF/MM I would rather discuss functonal
> > > > > issues/requirements/improvements than alternative approaches to
> > > > > instrument allocators.
> > > > > I'm happy to arrange a separate meeting with MM folks if that wou=
ld
> > > > > help to progress on the cost/benefit decision.
> > > > Note that I am only proposing ways forward.
> > > >=20
> > > > If you think you can easily achieve what Michal requested without a=
ll that,
> > > > good.
> > >=20
> > > He requested something?
> >=20
> > Yes, a cleaner instrumentation. Unfortunately the cleanest one is not
> > possible until the compiler feature is developed and deployed. And it
> > still would require changes to the headers, so don't think it's worth
> > delaying the feature for years.
> >=20
>=20
> I was talking about this: "I can live with all the downsides of the propo=
sed
> implementationas long as there is a wider agreement from the MM community=
 as
> this is where the maintenance cost will be payed. So far I have not seen
> (m)any acks by MM developers".
>=20
> I certainly cannot be motivated at this point to review and ack this,
> unfortunately too much negative energy around here.

David, this kind of reaction is exactly why I was telling Andrew I was
going to submit this as a direct pull request to Linus.

This is an important feature; if we can't stay focused ot the technical
and get it done that's what I'll do.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/xbehqbtjp5wi4z2ppzrbmlj6vfazd2w5flz3tgjbo37tlisexa%40caq633gciggt=
.
