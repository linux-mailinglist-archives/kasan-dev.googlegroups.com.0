Return-Path: <kasan-dev+bncBCS2NBWRUIFBB2EDY6RAMGQEY6UVXVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 05B3A6F4EB8
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 04:07:38 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4f0176dcc4fsf2663331e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 19:07:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683079657; cv=pass;
        d=google.com; s=arc-20160816;
        b=PDw/AavysvbxVRubNvBufjOLx1BtWRDzrlN/k1+LggYqOEMZT0SiDsNakI1l5p2acz
         N90nm/f3HtojATP4xWElEsd9zXvSGA2lrDFVzp5LToATB2C2qIsjNvk4l5kbH57WHgbl
         st9oiZUG0Gt37dXowwP0mZhN/TB9DAz3nBae67p08+ewHD1Iww5sAMW4RolzBS4/R9F7
         nxbQXaEDDf8POTr6+oo87xc6s0uqOJ625Ak3GiT1MFf+W8vd/9KinO2Wog42HZoj4iag
         nccXGkbDS/FvwMBOKJf/jXraNxq2TPDCr4sSASlRyL5r6alkR+ZOdpdzmv9Bk/P/3Qei
         o4tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=kOnh4ehrRUCbrT92GSKirqic9ZPtgcEO/D505Udjf1Y=;
        b=ri398j6subMQ5aHWEh6lFg9Zdky7cd0pEvoQdc8dkkVNukwVIvaQNz0RW6YIIPDX4x
         y23jcZOEHk1evmC+tCyy84UFOYkUXbW8r/qmxXX82ewgXbjqj8Vs/QQq7Ja90Ww4iESA
         ZQTQBFtEfH0S4MV5inwRz/MpfixzSIfTiB/n4beK3uEiFyVZuPCcX1+P/PZI+/OFjtdw
         Cw9nD56JLPwaxGt5LKPjptQleQ74vIkR/apSXW53lxfRe3W/UX0fhLeWPVfj+FXwyIT+
         5I/bvtg2uS5w5MX8ttpPB8JmKcnhdm6LbvrEmV+mKZ6+4tMyQuCxMRWbqdjEQLCv6pFa
         4wAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=v2LisaB7;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::24 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683079657; x=1685671657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kOnh4ehrRUCbrT92GSKirqic9ZPtgcEO/D505Udjf1Y=;
        b=BvMXv+YopsMYn/mzEwMwZygYzU4mF0hN44bBmqlWJV/RyH7ms4Tbyph5fxMxgudEie
         5265HtGOb1yH/pM3TrC6rrWxuoWlhF23Dzj1taezRVukRyAKzKZWTAKcolcs4Impr9gJ
         WSuy9yCEyV46dn57/xt5kbubawGhcsthKpuBL+PhxejV2VU1g+YLBrZCP1a20P+/woEs
         MBEXEY/EFLTCIo3CBmaS5k7HxOpl+u7/ip1fFn1DjG/nMpz8uKq/0bwsCIi4S1FigUrN
         Tw/RGfI5P/NOci34Kb+iVpQfI0Cxt64pZEm559kaowPFaFET6l9LCPWrVdmP/NcH4HLj
         rOmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683079657; x=1685671657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kOnh4ehrRUCbrT92GSKirqic9ZPtgcEO/D505Udjf1Y=;
        b=HQGAU57Ne5yBey3s/NCxo0zrTqg+mchsk3vhG70OwIpIOp3pyNRTL5yhz5gH+N8748
         XcFtKHio4VSEmfBou6xqQYQ3gbhS1i4X1/j1SM86w6vxDEIbxQF2/pZMohtrmK6T+ZZL
         E4bEMHiIzgnmqfduC20ObansqmvfCVNZxfxjjSWOD4Qw4uBipBdmwo2S0if7OToTDEvJ
         3DkjumsWNA0kTXgxmZOXVLu3zVdtvn/yz6Tc4tcP+hcTvciexQ+sCSl0qKRnr9AAr2D/
         AIyD8lhiaEq6x7R+S3meMGzj5/EeeWuCuUO/oS1U7PG19vGEcwbrH6I56wnCR2eA5eeF
         cxBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxEnG5BcSh/EZjHUdTf0J5v6Iav99/imFbeggJyWT1Mirj37t4p
	SLZmNBZHIfjdY7CWcRHx170=
X-Google-Smtp-Source: ACHHUZ4MJYYJAp6O2KhPZI7Ha5WWxJ57EJyJTBOQ/Vu5s6zDnoLH08MZwOoSr0WBGfoOOMnUTBGomQ==
X-Received: by 2002:ac2:5448:0:b0:4ec:9350:e57f with SMTP id d8-20020ac25448000000b004ec9350e57fmr447024lfn.7.1683079657096;
        Tue, 02 May 2023 19:07:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158d:b0:4ec:6fe6:9f26 with SMTP id
 bp13-20020a056512158d00b004ec6fe69f26ls2014856lfb.0.-pod-prod-gmail; Tue, 02
 May 2023 19:07:35 -0700 (PDT)
X-Received: by 2002:a05:6512:1028:b0:4ef:f725:ae2f with SMTP id r8-20020a056512102800b004eff725ae2fmr463658lfr.37.1683079655695;
        Tue, 02 May 2023 19:07:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683079655; cv=none;
        d=google.com; s=arc-20160816;
        b=cJhWfGoAFvPSqVuYFVYlidCgULQr6kIJEycBXe3JnuD26MCp5zyie+h1gMAFog1byq
         +MUc6+YxHxFEYW+XYfJUeYQ4Jf3Z61xyJZKK5J4JsOIXYVlu496YNO88MSGLRlcFDzCM
         ArEZFJXRVo9tKLFvGp8TLtpQrIMetCb3Hl2DuWhV7jeRE6i2l90G6f9RUf1JtM0t8U2W
         1m9n/cCeCqCxzZpHmt2soGcjjLQ5CX5idwPsaWJTY1vwhlSHMZe0IjLWGVLJr+cHvEra
         VRh0s+TUXJieKZm8sxkvg0LvgqYVX57KSTjv6702b5uCc/fFI1rbddQP1CuFPY5U9ezx
         KkZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=cpRynykubcluzGzuthbmrNkuNIeg8BzMwNks1+1YuhA=;
        b=zMckCqpmBABu+s6UKGBVqIiGnTPFq4rL4Yy+lBPVpkW6onjdAhG+9AiUaRESjRzKGI
         BHzaVCqFED3uXmNIsIvTt94GdqDEndTUoPpBjfsxFQKhdfPIrX3aKfchpxM4ZaYbizc/
         7jxVH2DpNPBoR3WiMId4IoBwrQcSO3nxXSHQ0CssM9G0+u/lDZH+WAcYnDYmM+DEHm+y
         KLT2Y7ZYpmMazbbZBWUeTUQJKCm7jsqQltpcMH1mQCSbbbfiniKHIyj/KbPWxf/ItxaG
         epMVEflyHxjRDlcv/A7cRWooBRw9GjHTqzL44dvilbu/NPfzbiUqcuNRt9qVSwyY6epq
         5Fqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=v2LisaB7;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::24 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-36.mta1.migadu.com (out-36.mta1.migadu.com. [2001:41d0:203:375::24])
        by gmr-mx.google.com with ESMTPS id c35-20020a05651223a300b004efeb1773ebsi1772333lfv.11.2023.05.02.19.07.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 May 2023 19:07:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::24 as permitted sender) client-ip=2001:41d0:203:375::24;
Date: Tue, 2 May 2023 22:07:20 -0400
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
Message-ID: <ZFHB2ATrPIsjObm/@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan>
 <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
 <ZFCA2FF+9MI8LI5i@moria.home.lan>
 <CAHp75VdK2bgU8P+-np7ScVWTEpLrz+muG-R15SXm=ETXnjaiZg@mail.gmail.com>
 <ZFCsAZFMhPWIQIpk@moria.home.lan>
 <CAHp75VdvRshCthpFOjtmajVgCS_8YoJBGbLVukPwU+t79Jgmww@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAHp75VdvRshCthpFOjtmajVgCS_8YoJBGbLVukPwU+t79Jgmww@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=v2LisaB7;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::24 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Tue, May 02, 2023 at 06:19:27PM +0300, Andy Shevchenko wrote:
> On Tue, May 2, 2023 at 9:22=E2=80=AFAM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> > On Tue, May 02, 2023 at 08:33:57AM +0300, Andy Shevchenko wrote:
> > > Actually instead of producing zillions of variants, do a %p extension
> > > to the printf() and that's it. We have, for example, %pt with T and
> > > with space to follow users that want one or the other variant. Same
> > > can be done with string_get_size().
> >
> > God no.
>=20
> Any elaboration what's wrong with that?

I'm really not a fan of %p extensions in general (they are what people
reach for because we can't standardize on a common string output API),
but when we'd be passing it bare integers the lack of type safety would
be a particularly big footgun.

> God no for zillion APIs for almost the same. Today you want space,
> tomorrow some other (special) delimiter.

No, I just want to delete the space and output numbers the same way
everyone else does. And if we are stuck with two string_get_size()
functions, %p extensions in no way improve the situation.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFHB2ATrPIsjObm/%40moria.home.lan.
