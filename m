Return-Path: <kasan-dev+bncBCS2NBWRUIFBBPW2V6XAMGQECHHLDTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 32138853E9D
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:29:19 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-51169a55bddsf4835244e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:29:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707863358; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ufha0ikWeFY5rN6a8bv3kY4hHED+UU/Op8Uyk0WlwG8+Y/s4EKWotaIN1B9qZeJSTZ
         ODhNnBT+ZJJT1mZPFHIgNvAvZggc9Dl8xdvkd6gEcc7y3XlLZWeX6roPGyusL9/UM4fa
         rzpy88YkuK0UAqSTTJzIYFirIasairFYKW9RqFOQrarxxMDDLflHaBX13brUULDSSL5B
         s/T76D2eJmtQydZ8NH4Kg6npvyHsE93IGt0MUBI1TffQ8ObKngO2dZrUc4MJiw9QgRWF
         eNY0aByTQTD5ydmHFDjmeI8qznVgu64ZagpRf5aT2tdLfF7yilkqWwqBxcQdRjt/w1mM
         94yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=y3n7G8FyggLDMazsPaYI/G6nFI5/HVdq/dSYZC/Uw10=;
        fh=NQ/KZCTeq3lBJHBAopGGrPSOqk7E22JeMwByWn36nRU=;
        b=X1j7fmNOTSVyXuFzMnZy7icdN8wOnbCbM3yMcdL80m6jiuAijaGX0chGTpoB8YsBL4
         m2MSuIEg5HfBpZMVqSCMcfaW91lZBn/gm3ngzhA+/1j2DbluEwOvbLitVEG8ck00ev+r
         hq0HWoeM10Kywlf05xd3sBUydbDB5YFbUB2kcUGs9HQ5mQu3fPJ2DgORz/geiForipwJ
         SIMgkXGtexnL0bibF0GTdv/h0VJROzdLkmIIciTjXq8jHwCJlJnkphCABSXRho3DIlFz
         Fq5t6JqFNJSHbCjLN671F+bdCKX7KVxzYpKLpyZVajkzi1xQ50cHODse6BDYARQKeN0G
         y7OA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NkR1gNLT;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.181 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707863358; x=1708468158; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=y3n7G8FyggLDMazsPaYI/G6nFI5/HVdq/dSYZC/Uw10=;
        b=wcTbozlTEUVEy2Y2kXbN7xstz7JkMfolRWgAbBndCA0M9Ze71rsrIa3s39cUzBZCfN
         irbfmWx+7OIrbCQ81t85xj7EFN+mBJ9NT2IaSiVoIWfwA8imMSnAo5GrtldVgD2HkIEn
         0xFt4eXlBOY2VCj5Nqm7d1Fkh0ItT/d4tpotK7AzZAMrWYkkrB9J7j/E5spnAT5JwukR
         /TA3RcvTZAdK9oEGQhsDAvpCjwGp4KJ0iAyoAzkkCqQrV0GGhrHQs4Cb3BgWL2GGSleN
         Wqh7LNsELfXtyHIeT7jOJFRRrw4LWqkS7EvODTgUwABoJU00Uma1NjuKPrKQThEKtcGZ
         oGSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707863358; x=1708468158;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=y3n7G8FyggLDMazsPaYI/G6nFI5/HVdq/dSYZC/Uw10=;
        b=sBLp3X57VkH6wfVmbs/kZsTkwoLIEqdTISLLD2Bvly0BprqtsHezGQxWiQN/FXhgyq
         KTs37LLUO+IyRM3NsWaIPJsv+FneYs47YJlP6aMElSTiaSPD9SRPcuNVqjAzN0Zx00J1
         pqV8a8GUcnJ7Nah654kobJ05/oKrIG/NnQeFHFQ+N6swEVgYar8ySxycUmkiZs90BXRP
         rUxJgRfwOh4foq4YVkA1U2ChVIxlfCKYq8WGvhMqxcWMYMOz3MupDstF62f6bS8z+NsO
         vACZzV1pfVynU0d/A4BRpLCn337x5XZxFfbfjleGSx7A+VJwwpInx5/9czhLedoYVMfW
         42ZQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVZ6aSPSzturBX2CR3NXLILjw0TSr6Mi/WdR3f6lijHkJzD3ddc4Mun2y3Sb5GzalfLamKIx341XmHfnuE8UlIvt0IG2BOAZA==
X-Gm-Message-State: AOJu0YzFpnGwqn3yvRRl0kk8zwcYgLPM2S3jEKbaclygBGhbw61Ug5SH
	cnRNC4SeTRgfC4whnRJvyEvOc9JaiaxjtI/PBlAuwQ8wbL7FXgxe
X-Google-Smtp-Source: AGHT+IFmGFCv4URclgZGrIpGTtK82DRC/VS/9Idh17dKXAj71npY+9UJiXez8xQttAyp54ctFReDzg==
X-Received: by 2002:ac2:44b9:0:b0:511:87c0:a327 with SMTP id c25-20020ac244b9000000b0051187c0a327mr629637lfm.68.1707863358341;
        Tue, 13 Feb 2024 14:29:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3da1:b0:511:5b43:6c1b with SMTP id
 k33-20020a0565123da100b005115b436c1bls565686lfv.2.-pod-prod-08-eu; Tue, 13
 Feb 2024 14:29:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU01qPSh4MRD1PO6CwxBp0tdeccihS3u5alY3TpRNel0rygPpOv0VHmcz2ZWTy+63W3NXRjn1itLOlE+14OX9WC8R104nla2tGqew==
X-Received: by 2002:a2e:808f:0:b0:2d0:a71f:5eab with SMTP id i15-20020a2e808f000000b002d0a71f5eabmr749703ljg.23.1707863356375;
        Tue, 13 Feb 2024 14:29:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707863356; cv=none;
        d=google.com; s=arc-20160816;
        b=mDn0nuPJc8syFxjtHM8q42+Rsjh0/pBF648+neuUlJhMwoIsptWgwh196gLmfY7atK
         spZlQCWA84674Mah6ozKvmlJ8WLMAiDZf5s/qt7JLyfT/NSCnzODZMIvfNt/b6cBhe44
         MryH4/S97o0GVcOtgktXeI5IGvN2cGNtqC4tANvb0YlU2VzV3JvL+K4wtV7B0eTonu/j
         /rp7SMz3bwqH406UZV0oqROb6INBMMzSj9WoFoOLLNdVRPJ+kxtRtX5uZiEbwaCGakOT
         fScKAodIZ16mUdm+er39kA+dXDmgHBFRXYTX9SDxucg8pUXINeN6sakzcsuX68c9Wybq
         qVZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=wx/MC+bC4jjIx0YLEQfGF9XmXIKmKElg0ARBnR+PN7U=;
        fh=pfDcVD1s3f04JEs+c/HUIBPDBIHCEggVKSbldKFNXjc=;
        b=tw1wt878BkwgfZIdBoqM/mbwk6m71O8wEfJ7DfVLm85nz2VpS2YwO6vj/XuUK2X9f5
         YTxj7BIVwLhvqP831Jo/rhrRuPaiyiJZ052Eqh7dkY10MkZGy8ac2K99GYro1Ck4A30d
         Db/MSXU534CzvVaWq+FnbZK8CEv62+l323VmcJT5sV5V3ZkNJafPpV3xBQyg1C9BSwRS
         w7tcERObApdRQtHl2nicU7RfuxUYe3WneX/yVyvjtg7tdBRBZVOItJvMacBLMqERAUBl
         g4MRh4ntjLW1Vz7V/Ig4da/jK21MDjU5imqLPTIo0uC6Jm8CqemEBFlSGbs048pzPjZ+
         tnwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NkR1gNLT;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.181 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCUp0TZyMrA4FVvsLO+aeHQCLXrIHDKbb32qXGP6NUJCp/nywZSdTLLGWvfsSReraiMFdY0fcDTuDQx050faC0x2YT24nUdBXebwaQ==
Received: from out-181.mta1.migadu.com (out-181.mta1.migadu.com. [95.215.58.181])
        by gmr-mx.google.com with ESMTPS id c61-20020a509fc3000000b00560ea64148csi981727edf.2.2024.02.13.14.29.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 14:29:16 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.181 as permitted sender) client-ip=95.215.58.181;
Date: Tue, 13 Feb 2024 17:29:03 -0500
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
Message-ID: <huysjw5jiyd7m7ouf6g5n2yptg7slxk3am457x2x4ecz277k4o@gjfy2lu7ntos>
References: <20240212213922.783301-1-surenb@google.com>
 <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=NkR1gNLT;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.181 as
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

On Tue, Feb 13, 2024 at 11:17:32PM +0100, David Hildenbrand wrote:
> On 13.02.24 23:09, Kent Overstreet wrote:
> > On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrote:
> > > On 13.02.24 22:58, Suren Baghdasaryan wrote:
> > > > On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@suse.c=
om> wrote:
> > > > >=20
> > > > > On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
> > > > > [...]
> > > > > > We're aiming to get this in the next merge window, for 6.9. The=
 feedback
> > > > > > we've gotten has been that even out of tree this patchset has a=
lready
> > > > > > been useful, and there's a significant amount of other work gat=
ed on the
> > > > > > code tagging functionality included in this patchset [2].
> > > > >=20
> > > > > I suspect it will not come as a surprise that I really dislike th=
e
> > > > > implementation proposed here. I will not repeat my arguments, I h=
ave
> > > > > done so on several occasions already.
> > > > >=20
> > > > > Anyway, I didn't go as far as to nak it even though I _strongly_ =
believe
> > > > > this debugging feature will add a maintenance overhead for a very=
 long
> > > > > time. I can live with all the downsides of the proposed implement=
ation
> > > > > _as long as_ there is a wider agreement from the MM community as =
this is
> > > > > where the maintenance cost will be payed. So far I have not seen =
(m)any
> > > > > acks by MM developers so aiming into the next merge window is mor=
e than
> > > > > little rushed.
> > > >=20
> > > > We tried other previously proposed approaches and all have their
> > > > downsides without making maintenance much easier. Your position is
> > > > understandable and I think it's fair. Let's see if others see more
> > > > benefit than cost here.
> > >=20
> > > Would it make sense to discuss that at LSF/MM once again, especially
> > > covering why proposed alternatives did not work out? LSF/MM is not "t=
oo far"
> > > away (May).
> > >=20
> > > I recall that the last LSF/MM session on this topic was a bit unfortu=
nate
> > > (IMHO not as productive as it could have been). Maybe we can finally =
reach a
> > > consensus on this.
> >=20
> > I'd rather not delay for more bikeshedding. Before agreeing to LSF I'd
> > need to see a serious proposl - what we had at the last LSF was people
> > jumping in with half baked alternative proposals that very much hadn't
> > been thought through, and I see no need to repeat that.
> >=20
> > Like I mentioned, there's other work gated on this patchset; if people
> > want to hold this up for more discussion they better be putting forth
> > something to discuss.
>=20
> I'm thinking of ways on how to achieve Michal's request: "as long as ther=
e
> is a wider agreement from the MM community". If we can achieve that witho=
ut
> LSF, great! (a bi-weekly MM meeting might also be an option)

A meeting wouldn't be out of the question, _if_ there is an agenda, but:

What's that coffeee mug say? I just survived another meeting that
could've been an email? What exactly is the outcome we're looking for?

Is there info that people are looking for? I think we summed things up
pretty well in the cover letter; if there are specifics that people
want to discuss, that's why we emailed the series out.

There's people in this thread who've used this patchset in production
and diagnosed real issues (gigabytes of memory gone missing, I heard the
other day); I'm personally looking for them to chime in on this thread
(Johannes, Pasha).

If it's just grumbling about "maintenance overhead" we need to get past
- well, people are going to have to accept that we can't deliver
features without writing code, and I'm confident that the hooking in
particular is about as clean as it's going to get, _regardless_ of
toolchain support; and moreover it addresses what's been historically a
pretty gaping hole in our ability to profile and understand the code we
write.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/huysjw5jiyd7m7ouf6g5n2yptg7slxk3am457x2x4ecz277k4o%40gjfy2lu7ntos=
.
