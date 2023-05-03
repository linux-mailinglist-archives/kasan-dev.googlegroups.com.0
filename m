Return-Path: <kasan-dev+bncBCS2NBWRUIFBBC4TZCRAMGQEXK5BEUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 667E56F50E5
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 09:13:16 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-4ef455ba61csf2940527e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 00:13:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683097995; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fc1/T6aDtBx/HEFLHFLoxLyH5gje8vf8RFsO7OyTGHqTEJ55nWHNtTkNjTsvXMoAds
         Wj8KzPgCVmEr27HZE2R8FAiBM4PYTfk7dnrna9JT3agu/QfFVOyNw5TqjxQX1qznXSR/
         gxmw4t68WZwRPE61MW+C7YKci9Dr+Gcdk+rMRqFIO2K+2luI//wGAbCb+VFqKrN4zJbR
         Hs58ZA3Xb7+xZv9Kbcz9vKTnt/7BT14wTY7wbVHcyy+kz5Z1FfygMg2vfWeLqHd1RGxU
         EZRrzy8w/u9os65tMhyY2YNQ0MOGJjISUzAyvUWK4iOynjU6OELjJ7r26iJmgSL7TP8z
         W2qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=7Pa+1d2YIa0WlyNI+7Q2ZpmabtGbx1ERVTPzFJa32KI=;
        b=Y/5xvAodNeeZaYJ4B1aWlltD6vJBJFq4m6sknC5AL+C3ZoSmF6LjRYrkJGEItO/QVa
         KONM8xOzrKBJh1QB5KCn1FkP6t7cuFMvUcprhAVSIV0OOlzefvukUt75KfZxUzP4Z25o
         qZPM/C0LCBCr2gPqrAKblJwstYOhongNFHQP7rMhYT5DUHOA5J6uPNpl02xuEzfNJLok
         WJBzvijmMw56Nj3Sit5Z+KlU7DDgp9L2DzpiRVU26Ro7X8PIcVO+i3P0DIkEI7NLVMgq
         9YnvBUmT76k2q6qB/G6IMCkMgrty++n1uzsbBugKvDwQ2gHlKBTxx8LZJhA8mQIsUz5/
         kUJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=houGGarh;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::16 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683097995; x=1685689995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7Pa+1d2YIa0WlyNI+7Q2ZpmabtGbx1ERVTPzFJa32KI=;
        b=P/xtgwmIr31zn2nntIB3a9pTuz+5Qw1otHr33W1LkJwxJOfIwZlRw4nOCP3sxXRYi+
         ftDcyD/4fuQRZtX54BhXNCMRudtjmIF8b9qfvdDDclS/sudB6SP02g7wTvidby6x9Ju3
         lLyPJnWXiPEqy2b0S4eYYWzw7HAtATi+ysNk8otjv1H2iMOBEEtwleZpFBr0WEw0Oj6X
         u5/6d3cTiGGB8aUroTABiHnz9tgagwie3Tg65edGl13Ylq6Se+gICfZwjqVV9As0VNBo
         k2GNQBLkDsX+pBiY/kfCXe0hcRElpJZgftiamihN3/cQ2fUm8f6P2AwWp3vYnp+oj81Z
         MtXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683097995; x=1685689995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7Pa+1d2YIa0WlyNI+7Q2ZpmabtGbx1ERVTPzFJa32KI=;
        b=EEu1ir96VeIFKzToTx42Cu9ouT/6yuKuyRwmtQTD9tbd/+oTMha3ChL1yr/HTx3qbr
         aWUlrZbZZ0UiXuLTVjoGcv5/KiS6sMC2vhRREV/O5QsHK0aeGf8wSRuvEd/iQz/yEW5S
         DJgO9jwzr1M/jJXiBi+yCX5PfkUDe5yjkxQ13L9dkaapfn2l1d5AQPyP3xT+NokRcEyc
         o56zh757bZVGWfZ/xj8jw3P4oTEdu/Q8TNhFcLbhLZHjGkomFgt6QuXSy2q65UAf/b+r
         EsQZR0N/mvuDhxfg7IUAQ8LM4uqGbFrg3+pHru1TZO0MsECC3wWPkJOm5L8vHJ9bGqxO
         7aMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzdpFucv3aK110ib8DMciXQjsTn6Fq9kRyIPHl5ZgmUKbImlSjx
	N+f0yoBufRcvIZY0VDHlzDE=
X-Google-Smtp-Source: ACHHUZ4fCo3ZJTXf74F645XN7SlerVmSTKsz76MFObM/+hbzrgZuLVTwJeYAEN2IrgEG2VFRdnk9XA==
X-Received: by 2002:ac2:43db:0:b0:4f0:121f:b4af with SMTP id u27-20020ac243db000000b004f0121fb4afmr564900lfl.5.1683097995523;
        Wed, 03 May 2023 00:13:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4017:b0:4ed:bafc:b947 with SMTP id
 br23-20020a056512401700b004edbafcb947ls2345416lfb.2.-pod-prod-gmail; Wed, 03
 May 2023 00:13:14 -0700 (PDT)
X-Received: by 2002:ac2:5102:0:b0:4ee:d8f3:1398 with SMTP id q2-20020ac25102000000b004eed8f31398mr755519lfb.68.1683097994074;
        Wed, 03 May 2023 00:13:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683097994; cv=none;
        d=google.com; s=arc-20160816;
        b=ZSXuSyMgWh8l6kF13MbnK6aETvOIvs/hRyMq9ep5EN4Wb6Uc+4HbJs24G/cQ+rESh9
         h3jkLV6wcXHELzzoGYbFuqziyVwtm1NHiiRW8Rg7BwjeyZ22D6LPVxVNmLgKLJ99c+7x
         r278wcDxqY29IEoigWntnDKBnPU7wLEdQATSBtv+Xo4fPCDFfASHri4MFjh5Fbro7xk/
         m28R6yt2cBDXV5XWCosjWxgAPlEDxJED772WegcIlH3Bjjt4Xs2V5sCzMTbueG9v2pVm
         n8K7gmw584wY3ujR7ouMKcyY+B9hGeyVleWmQf4EVEDzsLu5fXgjaO7g5Ocq+GUFOup+
         Z6IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=Sa4OTZB5b+skGudhSwhmk32TbWUPA01HpPa43R3XypE=;
        b=RUJjVzZKo1F1JPaX/pUeLStqzp6n4GRPOrrLQlprzOoVWcpbCnFgwaa9i/CN4/SKMG
         yMDHpy40sTBgYV/xvaZZqmqoR5plwGBAvXzHCZ6YYBf5f+Sc0MmJOhwDlUGa4r1uj2Fe
         ZNgfc+lLnKYnVcXJ4kQXkjx/6w8IvHKAFj2avbMzeDQ+ckc7Sox8oyGTphPhkD0CmVXP
         qQ/vNyUiZ3xcEKhNhvWHiov+zK2ynkm0HOcEii41Mj7dBdaq6avlzPWMFOMsXrvNcfMu
         Pf+JDNZC42Q7wXy6QFagGoMVeGo2oXArzIwdvO2aFoYBFARU9Yk8EzjiVcAH4Vjh1OfK
         ZVHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=houGGarh;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::16 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-22.mta1.migadu.com (out-22.mta1.migadu.com. [2001:41d0:203:375::16])
        by gmr-mx.google.com with ESMTPS id f43-20020a0565123b2b00b004ec6206f60esi2247823lfv.9.2023.05.03.00.13.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 00:13:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::16 as permitted sender) client-ip=2001:41d0:203:375::16;
Date: Wed, 3 May 2023 03:12:57 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Andy Shevchenko <andy.shevchenko@gmail.com>
Cc: James Bottomley <James.Bottomley@hansenpartnership.com>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
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
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Noralf =?utf-8?B?VHLDr8K/wr1ubmVz?= <noralf@tronnes.org>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in
 string_get_size's output
Message-ID: <ZFIJeSv9xn9qnMzg@moria.home.lan>
References: <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan>
 <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
 <ZFCA2FF+9MI8LI5i@moria.home.lan>
 <CAHp75VdK2bgU8P+-np7ScVWTEpLrz+muG-R15SXm=ETXnjaiZg@mail.gmail.com>
 <ZFCsAZFMhPWIQIpk@moria.home.lan>
 <CAHp75VdvRshCthpFOjtmajVgCS_8YoJBGbLVukPwU+t79Jgmww@mail.gmail.com>
 <ZFHB2ATrPIsjObm/@moria.home.lan>
 <CAHp75VdH07gTYCPvp2FRjnWn17BxpJCcFBbFPpjpGxBt1B158A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAHp75VdH07gTYCPvp2FRjnWn17BxpJCcFBbFPpjpGxBt1B158A@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=houGGarh;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::16 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, May 03, 2023 at 09:30:11AM +0300, Andy Shevchenko wrote:
> On Wed, May 3, 2023 at 5:07=E2=80=AFAM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> > On Tue, May 02, 2023 at 06:19:27PM +0300, Andy Shevchenko wrote:
> > > On Tue, May 2, 2023 at 9:22=E2=80=AFAM Kent Overstreet
> > > <kent.overstreet@linux.dev> wrote:
> > > > On Tue, May 02, 2023 at 08:33:57AM +0300, Andy Shevchenko wrote:
> > > > > Actually instead of producing zillions of variants, do a %p exten=
sion
> > > > > to the printf() and that's it. We have, for example, %pt with T a=
nd
> > > > > with space to follow users that want one or the other variant. Sa=
me
> > > > > can be done with string_get_size().
> > > >
> > > > God no.
> > >
> > > Any elaboration what's wrong with that?
> >
> > I'm really not a fan of %p extensions in general (they are what people
> > reach for because we can't standardize on a common string output API),
>=20
> The whole story behind, for example, %pt is to _standardize_ the
> output of the same stanza in the kernel.

Wtf does this have to do with the rest of the discussion? The %p thing
seems like a total non sequitar and a distraction.

I'm not getting involved with that. All I'm interested in is fixing the
memory allocation profiling output to make it more usable.

> > but when we'd be passing it bare integers the lack of type safety would
> > be a particularly big footgun.
>=20
> There is no difference to any other place in the kernel where we can
> shoot into our foot.

Yeah, no, absolutely not. Passing different size integers to
string_get_size() is fine; passing pointers to different size integers
to a %p extension will explode and the compiler won't be able to warn.

>=20
> > > God no for zillion APIs for almost the same. Today you want space,
> > > tomorrow some other (special) delimiter.
> >
> > No, I just want to delete the space and output numbers the same way
> > everyone else does. And if we are stuck with two string_get_size()
> > functions, %p extensions in no way improve the situation.
>=20
> I think it's exactly for the opposite, i.e. standardize that output
> once and for all.

So, are you dropping your NACK then, so we can standardize the kernel on
the way everything else does it?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFIJeSv9xn9qnMzg%40moria.home.lan.
