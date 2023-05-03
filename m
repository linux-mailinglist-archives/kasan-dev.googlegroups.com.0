Return-Path: <kasan-dev+bncBCB5ZLWIQIBRBKXVZKRAMGQEEHPSBQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id CB9D76F5F65
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 21:48:59 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-6a7b0f4829fsf4264639a34.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 12:48:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683143338; cv=pass;
        d=google.com; s=arc-20160816;
        b=PQheA59YW+jKBmWvOZOrTVHUwMU6loVbV3gx9a2e/EwyZpTNFywnDUMIj0xLX4w8yH
         +To46j9jsNZdmWbQJ//z9wmTjpPWddEKInZbwfrPlPxt373rppIggI2UENGEnL+7Z9pN
         jjS7Z9z1NK0AegxDy/dx0oKf4LTDapHU35aI6hgm/kt0Yxe6ti3Y2EfsVAizVonrDD3v
         KMcpqr2hUx3Tnvp2B6CDzWt3FxHSNNHB16Xz4TMx4ADF1RdGTv31RHI5HopIMjF3tdZn
         bmH6P7eXbE55dj30uRHONJe5VXcsoO0HOTax7K4MgiuRkzgDVTsRUWxONzODa85SSeuq
         rifw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=kIwBu4bzsCnhYs8Ee99Nkm/mYxSuxl5RZMbOaMr/+20=;
        b=hokCiQTwBy8KKLTH9e9A+2IKLjHzILhF1F62/yQy/5lcNnmiZE40hy6PeofiI42cCC
         LyOMsfmReQsvnEyE0twBBo//Zf5WAcge9spLfF0uW6WfH5eiRvS5+5YORS7s0kVQOGi5
         yI6eY6e1b60BqTx+CJiLZqxrJsZaLgQFETLkLLxNo7k/r08MaCoU7oReT0ZwwRsXWmVI
         V5issRpcNzLGtdGUpMP7/28OCs9MJ8r821iVGcyNR1q33L1Z5LgShwSmoXkEfON98yKH
         5K68Y+jSob6lFyvMP0Kx6mzM8AkwhfAaLh2Fu+jYESuygJ1xffIjTo4bp1Uz+AvJZtoV
         enHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=WRBBKM6R;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683143338; x=1685735338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kIwBu4bzsCnhYs8Ee99Nkm/mYxSuxl5RZMbOaMr/+20=;
        b=ifR83QMXPUEPhZ0aPjhcoT4p2Jo4CVV8s6UEa1KTsmF/kS6B4SdXwwtsgtfMSnPPOj
         eZcNs4D9L22qKK6p8T8Y6SHwUPxr4rS5C9AqiVIulWmJn0NOYQViS8JvmlwFgenVxRfh
         L0EwTBbglc7jdA84GRHUqjUiHeQoD/3E8CLBLb5Re4NZBxcbK9aZJ8H72g0zoaAHBloJ
         qSxlYrpIIhBK9aD4f8aag5VafpKSKzwCwsjg4xZPFqbzj3Kgz84A1YpoMQUdoMqVNdHU
         9eWs1jU+o16v+htRuB+SgeL3TtJygmAvrpMimlHQ1HWsfBRdxd1xNyDVWm+VZpzWrYbC
         598Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683143338; x=1685735338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=kIwBu4bzsCnhYs8Ee99Nkm/mYxSuxl5RZMbOaMr/+20=;
        b=fn01ZR6gX3OC07Uz/hMTxEMczcv1rkFQ9EdzLzuC2WNMyMtvXVzGZdBrWseA0lBtOi
         mryUwp0qyZBlvAe52X35fgzippC3qOWlwxUq4+wNNKKpaW26EOA8JWckx1b/VeoZPGGi
         lzzbTOjCXE1zYsbTvzt5czaOPntUzasSZVUfGv7rRKbOIDahgPgG72YdMzk7wi+vh+ET
         f55APmC0+RaFyB4JY9VxrfVqMU1TqVqMcu4E33I7xVrIT1I3jkdgngSD1Q5Gv3CQwW/8
         105/S1BvVDSpU9prBmUv1DnY781rlWKlOOzv+th7fe9EEObCIxE1qWx13mu64DZLHkfK
         DiEw==
X-Gm-Message-State: AC+VfDxymRpuWS0rBKOa5AvfchybUWDIzZnXsK2iJKGM81dl8YwAa8vd
	KE1lJXHXZ4bGDkP2967e3qM=
X-Google-Smtp-Source: ACHHUZ6rDuvGK31wyV2+PEaXwk+nmwYh0dIhILCsY2kf9NATt1iE2W2PjPhoY4+tZ51LG8IRPWvLuQ==
X-Received: by 2002:a05:6830:10d0:b0:6a6:38a6:e1b1 with SMTP id z16-20020a05683010d000b006a638a6e1b1mr5652796oto.4.1683143338499;
        Wed, 03 May 2023 12:48:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:3b41:0:b0:38e:a160:8a3a with SMTP id i62-20020aca3b41000000b0038ea1608a3als4228048oia.11.-pod-prod-gmail;
 Wed, 03 May 2023 12:48:58 -0700 (PDT)
X-Received: by 2002:a05:6808:189c:b0:38d:eb0e:7b15 with SMTP id bi28-20020a056808189c00b0038deb0e7b15mr629313oib.17.1683143337972;
        Wed, 03 May 2023 12:48:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683143337; cv=none;
        d=google.com; s=arc-20160816;
        b=ejFm3TphcjDPBLLwzPOIxz1zzVqWA1AbHV5gCbUOkqU6UC3qRILkzeFRCMSEeyqIwh
         uJhuVJdrdAPonIAbLhDdAnzwnTVKM5snXiuTvWKQrKyXrdfKu7vG63DAQlkGKlzhf5gu
         QiCdoh3DMVk3dbNSEcCF7TS7yQRCZWPEn8VaRLrDSiYVHfG0EQRy+yQSYoehsLsIQgLQ
         PvkSu16OmIyoLtQ0k/fGhJpRJrGHTNQv9MT2NKD8qdHCOU/FXYmvm2mqXkUnGvxDnBAv
         70qHi7mCTWLDJwT6BxUnDmTjRBNiAwiq58mqAq0m+oDNAJ37iKCulvRMuTcgXdaa8bqV
         94NA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=X0rUD0Br2hVe3zymEpoVc3T4TI1iG6AHKLcBxAchx6c=;
        b=FUoDZh+9PczMvLgB6G+UjahQXphYyRbYvnEHT3n6fABb/JHgegP0RHDl95xpts691H
         rH/IYAKz8Bkg9ZboTz6GE6guOp6+55GES1UjSV43KEIR9tr19dZ2trGNSSSnTifyfQvZ
         siUnLQMm5aUyORxaQ91bYsC1WVXiljVwZlTF/ATwStTUWyDDXsXf/XLRqmFc1UdqIVyf
         /DTwhJH1Nocz44XwS0P9bDpwqEe9q1aG1s7YaooWXXjg2lZTmB16dBP/jQloU4NirGpW
         K7zXbJKV0GMsCBVNnzwaww1pqDC5pW71VyBFHzBUmHiLawExB7EpIzvdV1VmPOAQulHI
         Xm8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=WRBBKM6R;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id a15-20020a056808120f00b0038e9bae5289si97327oil.3.2023.05.03.12.48.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 12:48:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-6434e263962so708757b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 12:48:57 -0700 (PDT)
X-Received: by 2002:a05:6a00:16ca:b0:641:23df:e914 with SMTP id l10-20020a056a0016ca00b0064123dfe914mr31263008pfc.13.1683143337337;
        Wed, 03 May 2023 12:48:57 -0700 (PDT)
Received: from localhost ([2620:10d:c090:400::5:6454])
        by smtp.gmail.com with ESMTPSA id s12-20020a056a00178c00b0062e12f945adsm23909517pfg.135.2023.05.03.12.48.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 12:48:56 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Wed, 3 May 2023 09:48:55 -1000
From: Tejun Heo <tj@kernel.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
	Alexei Starovoitov <ast@kernel.org>,
	Andrii Nakryiko <andrii@kernel.org>
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFK6pwOelIlhV8Bm@slm.duckdns.org>
References: <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
 <20230503180726.GA196054@cmpxchg.org>
 <ZFKlrP7nLn93iIRf@slm.duckdns.org>
 <ZFKqh5Dh93UULdse@slm.duckdns.org>
 <ZFKubD/lq7oB4svV@moria.home.lan>
 <ZFKu6zWA00AzArMF@slm.duckdns.org>
 <ZFKxcfqkUQ60zBB_@slm.duckdns.org>
 <CAJuCfpEPkCJZO2svT-GfmpJ+V-jSLyFDKM_atnqPVRBKtzgtnQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpEPkCJZO2svT-GfmpJ+V-jSLyFDKM_atnqPVRBKtzgtnQ@mail.gmail.com>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=WRBBKM6R;       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::42b as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
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

Hello,

On Wed, May 03, 2023 at 12:41:08PM -0700, Suren Baghdasaryan wrote:
> On Wed, May 3, 2023 at 12:09=E2=80=AFPM Tejun Heo <tj@kernel.org> wrote:
> >
> > On Wed, May 03, 2023 at 08:58:51AM -1000, Tejun Heo wrote:
> > > On Wed, May 03, 2023 at 02:56:44PM -0400, Kent Overstreet wrote:
> > > > On Wed, May 03, 2023 at 08:40:07AM -1000, Tejun Heo wrote:
> > > > > > Yeah, easy / default visibility argument does make sense to me.
> > > > >
> > > > > So, a bit of addition here. If this is the thrust, the debugfs pa=
rt seems
> > > > > rather redundant, right? That's trivially obtainable with tracing=
 / bpf and
> > > > > in a more flexible and performant manner. Also, are we happy with=
 recording
> > > > > just single depth for persistent tracking?
>=20
> IIUC, by single depth you mean no call stack capturing?

Yes.

> If so, that's the idea behind the context capture feature so that we
> can enable it on specific allocations only after we determine there is
> something interesting there. So, with low-cost persistent tracking we
> can determine the suspects and then pay some more to investigate those
> suspects in more detail.

Yeah, I was wondering whether it'd be useful to have that configurable so
that it'd be possible for a user to say "I'm okay with the cost, please
track more context per allocation". Given that tracking the immediate calle=
r
is already a huge improvement and narrowing it down from there using
existing tools shouldn't be that difficult, I don't think this is a blocker
in any way. It just bothers me a bit that the code is structured so that
source line is the main abstraction.

> > > > Not sure what you're envisioning?
> > > >
> > > > I'd consider the debugfs interface pretty integral; it's much more
> > > > discoverable for users, and it's hardly any code out of the whole
> > > > patchset.
> > >
> > > You can do the same thing with a bpftrace one liner tho. That's rathe=
r
> > > difficult to beat.
>=20
> debugfs seemed like a natural choice for such information. If another
> interface is more appropriate I'm happy to explore that.
>=20
> >
> > Ah, shit, I'm an idiot. Sorry. I thought allocations was under /proc an=
d
> > allocations.ctx under debugfs. I meant allocations.ctx is redundant.
>=20
> Do you mean that we could display allocation context in
> debugfs/allocations file (for the allocations which we explicitly
> enabled context capturing)?

Sorry about the fumbled communication. Here's what I mean:

* Improving memory allocation visibility makes sense to me. To me, a more
  natural place for that feels like /proc/allocations next to other memory
  info files rather than under debugfs.

* The default visibility provided by "allocations" provides something which
  is more difficult or at least cumbersome to obtain using existing tracing
  tools. However, what's provided by "allocations.ctx" can be trivially
  obtained using kprobe and BPF and seems redundant.

Thanks.

--=20
tejun

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFK6pwOelIlhV8Bm%40slm.duckdns.org.
