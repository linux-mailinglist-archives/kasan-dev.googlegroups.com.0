Return-Path: <kasan-dev+bncBCS2NBWRUIFBBLHEV6XAMGQEUIDJUZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id D4800853F20
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:50:21 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-559555e38b0sf4414772a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:50:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707864621; cv=pass;
        d=google.com; s=arc-20160816;
        b=sV4153GQr4luzewMPcWHYMMzKe5yy+/I6CpjNWW3jGU8wOfcvssVMO5pE+fZl//lQH
         edieG+wvbQ8HZ468DW58K2UsSeuZDxUPvk3LVa0/fs6uTWsS9+/nyibsWZxlon2ThFQA
         lNZvLJj+gvKNAzZ8kkdYBcqaAUNXuB+l3qG0IRwoSfHCZBePDWi1TjorLxWuQbBX437R
         VI5KqN+ClPyEy8bIkdZvxTAnZob9YnlNxcnF8PbXUacwLSI8CU62z9DF5u2bPMYTw575
         u2AzNJW+agJz3k1Y9QBf1oUWHukG3O//xJqnuxcjVE8xxvcWqoMfgPp1LVtRi5XjYXfb
         VDtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=SLeKhLkuXmC3Ns3dsn5/S5I40WsGsctrepScEcJ/3YY=;
        fh=Op/O2KGPizVaGOVIA8gs0X7y9bZhvTavNzhV+CTrFH0=;
        b=iITvgROykx6owZku5wWU3SMZZHX7p34m92cG0ZKGLa2DAJQCjk+37zbOSUzmMs9JbL
         2iZhmBe4cVICsiLR/fZKza16UQWM6ThcVpglYSCm5JfBj1GhUQUs4JtIAQ3MFjRVhOcz
         D0CXoUDGCLDReVYz5pDKjNBcdH4C4x/ENRGWNnm1d3nfuE4pCqCX3cEWsPUkBR61IRW4
         w8yZ1bOfr47i+v0J0cSO51/JB+HErfpkSSIqg5Ydb8fgSu4YDhgSfgDI93ExtZO8Lfs3
         qqnGDdfGiTHoEFbpD0zUY91pbFUA128XB+s1YjIsMOJwsx/eDYF2JLbYIkJWXsKD8KL4
         8AKg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=d6oZDfuz;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.188 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707864621; x=1708469421; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SLeKhLkuXmC3Ns3dsn5/S5I40WsGsctrepScEcJ/3YY=;
        b=LrcwPvG5Tnye2wWLN+EZHH5mqWuB0levG4WHC2UsDVflvNsNkKbYD6V7BOw73MBL/r
         nXPTd4+FBpQC3aHuOdmaSKwPBC8xWzUGaTDLFeqgOmOrse4a3h7S9y39YnRUsFmWRgbu
         MZhNH5bHaPfcKVhCUSon6l/sZpT7P/AXAivKr8EQkdAnyLr2N5SzJ+9Cbug5OEdT8Um4
         F289B0mbDnIxBQQjd6GNjp6IzewbvcZpX3D5kbK6U0Ew9OgySxIsKYRRRxe2YCZdDnoJ
         D7OElS1sD04XnvoL6SsRP0UmJNsZTWszYMsvxgWNeD5jgOBR0lfhLUU5Hpo/o7HT2WwZ
         /rnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707864621; x=1708469421;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SLeKhLkuXmC3Ns3dsn5/S5I40WsGsctrepScEcJ/3YY=;
        b=S+XE7fdoXyYWRVGkR8bkmUtSKoBoLpHLHRU5c/Msup8ckGvcPbRXt+jXzUfiZtMRGE
         9buHojj6gw5lzNltkuHzcSGuciXB34I6cab3/lnb4mHQ5GgrNUYF1tIGvOY1eL3Ifi3o
         Nx67hEpOIzpgFBwm2uOKT14kpahJB7dYvC7dYQQz1VKbxqKacp3b8yRTHutYbuBLQERA
         72CVjM5d4cTFsMjmnFNe7T9H+Pm2UytIOHA0DacVgldrjNJyuJ38/HiVP4juwfjtsTwS
         sDNQDT6ral/x456ND3vb2Yn9H34+FWPLy/yZ4JMUKLSLXcE43s9kKqmep8nJc1VzuxZM
         WxNA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzliGK4oFFm2hOQz2YKg8SXT89f7kTo0qgvZTBEVoLoqihL4dFnUWaga8Nvobowa9fhSlqFj7meupxb3egXbYJsUBbXrJf6Q==
X-Gm-Message-State: AOJu0Yx5zbjJpPizkM/UyZYyE1x7szapziO4CKLzXCMUaopRMvGpuLbX
	RlhAMrPSpjgmuZXrY4KMmcXN1OUAqK5+3hfThdDVmSger2jfSzpU
X-Google-Smtp-Source: AGHT+IGIeAPlR0nPc9NOuPSV6ttqoowCeeaP5Sxh37voT/63Y9XPfL1XHrM4R0TTTOPZK8WEfmcwFw==
X-Received: by 2002:a05:6402:68b:b0:55f:52c5:ab9d with SMTP id f11-20020a056402068b00b0055f52c5ab9dmr677699edy.28.1707864620962;
        Tue, 13 Feb 2024 14:50:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4010:b0:562:802:8da1 with SMTP id
 d16-20020a056402401000b0056208028da1ls456528eda.2.-pod-prod-05-eu; Tue, 13
 Feb 2024 14:50:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUtnjL7f+TY2E1q5VRX6h9b4habB9eATCeTiFpBbm/LgnV58j+OIkj9RqV/C70/J+njko0aK1+41WveOpg7EJhWRYijjgvWPkeehw==
X-Received: by 2002:a17:906:194a:b0:a3b:d4d8:98a1 with SMTP id b10-20020a170906194a00b00a3bd4d898a1mr454156eje.60.1707864619010;
        Tue, 13 Feb 2024 14:50:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707864618; cv=none;
        d=google.com; s=arc-20160816;
        b=fbeMfPn856745bfK9y5jC3SSpNRQIjIQdgl0yccu1PnfkPvvJkmkfYFmz+jK/kBf/w
         UiejljCLiZVjvzJfD+wqaFVeDIbyzN4J9zGGxdCGlPE8kxz25IbOU+LUSQCKY28nzwy9
         lqRe0aGkWqVTv5mMTl14pktOrURnNf01uQeiFGLHECWKZHNDRuTsJgy68C+gBAepEq+w
         ORVIv2Y+uSlZKc3hX06UAjCy3qBoeYSTTDXcFBXj4Ul/UGAQ2SRzoIVQI9pEvPAthtod
         ErjfKKPf6jw+mI9jq3N+eQjt9b0bwHBwz446Pa0VJD+wfaKPCYSvRCYiuQ3G5T5Y4P9F
         sLcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=jiv4lM5HdhNU9bAiRFQZPMt1GA0MoNC/u5JMEJbfz1E=;
        fh=ae7Ypi1+Is0EmSxE3wGlGWi0pmn+clHlqXNI5VRVxUk=;
        b=r2PWb18LsBiPeZsNcQ6t0TCxPR0CgqZrE/QNVKE2q1KVZbfi6lv9b+HihFz38q3G42
         +3jsrt9hNTGhSJc4X1Yq3SjqePJpzgPOntXmMQIkO137ST6tI/g+9md72qrZoaEjjcVx
         D0WHo0TIUWwuukOIQ/V8QW3+WPHGm1siS6kXeyu9hNEKd1nqUfAp8S4DzBiPxAWFjqKQ
         7/B3qvZ+oueHiZiCVYQl7fSC2a22Tf9Y2Yy9whnwIK+JdD2z1/W64uk20ARL85VfPBFA
         AstvyD5s9ZNZVlmZFzlMbvuC7Qg5KVa43DxhLk3KikpQIJGtTrvt8HbigkcxoVBz7jhG
         t9Yg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=d6oZDfuz;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.188 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCWlvbhX5DHb+/12UN5oJ9+IG4jy3Qqt73IQI86n591TQa0SQbSU7lUFC68mJzck48ytKXFg0s6d0T1WUwzvMYtPyahTsPl1FlllMA==
Received: from out-188.mta0.migadu.com (out-188.mta0.migadu.com. [91.218.175.188])
        by gmr-mx.google.com with ESMTPS id eq22-20020a170907291600b00a3cffbbb483si180759ejc.2.2024.02.13.14.50.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 14:50:18 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.188 as permitted sender) client-ip=91.218.175.188;
Date: Tue, 13 Feb 2024 17:50:02 -0500
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
Message-ID: <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
References: <20240212213922.783301-1-surenb@google.com>
 <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=d6oZDfuz;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.188 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Tue, Feb 13, 2024 at 11:48:41PM +0100, David Hildenbrand wrote:
> On 13.02.24 23:30, Suren Baghdasaryan wrote:
> > On Tue, Feb 13, 2024 at 2:17=E2=80=AFPM David Hildenbrand <david@redhat=
.com> wrote:
> > >=20
> > > On 13.02.24 23:09, Kent Overstreet wrote:
> > > > On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrote:
> > > > > On 13.02.24 22:58, Suren Baghdasaryan wrote:
> > > > > > On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@su=
se.com> wrote:
> > > > > > >=20
> > > > > > > On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
> > > > > > > [...]
> > > > > > > > We're aiming to get this in the next merge window, for 6.9.=
 The feedback
> > > > > > > > we've gotten has been that even out of tree this patchset h=
as already
> > > > > > > > been useful, and there's a significant amount of other work=
 gated on the
> > > > > > > > code tagging functionality included in this patchset [2].
> > > > > > >=20
> > > > > > > I suspect it will not come as a surprise that I really dislik=
e the
> > > > > > > implementation proposed here. I will not repeat my arguments,=
 I have
> > > > > > > done so on several occasions already.
> > > > > > >=20
> > > > > > > Anyway, I didn't go as far as to nak it even though I _strong=
ly_ believe
> > > > > > > this debugging feature will add a maintenance overhead for a =
very long
> > > > > > > time. I can live with all the downsides of the proposed imple=
mentation
> > > > > > > _as long as_ there is a wider agreement from the MM community=
 as this is
> > > > > > > where the maintenance cost will be payed. So far I have not s=
een (m)any
> > > > > > > acks by MM developers so aiming into the next merge window is=
 more than
> > > > > > > little rushed.
> > > > > >=20
> > > > > > We tried other previously proposed approaches and all have thei=
r
> > > > > > downsides without making maintenance much easier. Your position=
 is
> > > > > > understandable and I think it's fair. Let's see if others see m=
ore
> > > > > > benefit than cost here.
> > > > >=20
> > > > > Would it make sense to discuss that at LSF/MM once again, especia=
lly
> > > > > covering why proposed alternatives did not work out? LSF/MM is no=
t "too far"
> > > > > away (May).
> > > > >=20
> > > > > I recall that the last LSF/MM session on this topic was a bit unf=
ortunate
> > > > > (IMHO not as productive as it could have been). Maybe we can fina=
lly reach a
> > > > > consensus on this.
> > > >=20
> > > > I'd rather not delay for more bikeshedding. Before agreeing to LSF =
I'd
> > > > need to see a serious proposl - what we had at the last LSF was peo=
ple
> > > > jumping in with half baked alternative proposals that very much had=
n't
> > > > been thought through, and I see no need to repeat that.
> > > >=20
> > > > Like I mentioned, there's other work gated on this patchset; if peo=
ple
> > > > want to hold this up for more discussion they better be putting for=
th
> > > > something to discuss.
> > >=20
> > > I'm thinking of ways on how to achieve Michal's request: "as long as
> > > there is a wider agreement from the MM community". If we can achieve
> > > that without LSF, great! (a bi-weekly MM meeting might also be an opt=
ion)
> >=20
> > There will be a maintenance burden even with the cleanest proposed
> > approach.
>=20
> Yes.
>=20
> > We worked hard to make the patchset as clean as possible and
> > if benefits still don't outweigh the maintenance cost then we should
> > probably stop trying.
>=20
> Indeed.
>=20
> > At LSF/MM I would rather discuss functonal
> > issues/requirements/improvements than alternative approaches to
> > instrument allocators.
> > I'm happy to arrange a separate meeting with MM folks if that would
> > help to progress on the cost/benefit decision.
> Note that I am only proposing ways forward.
>=20
> If you think you can easily achieve what Michal requested without all tha=
t,
> good.

He requested something?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq%4045lbvxjavwb3=
.
