Return-Path: <kasan-dev+bncBDV6LP4FXIHRBC4AZORAMGQEMD5ASBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id B80886F5FD8
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 22:11:56 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-51b7810ec2csf2786271a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 13:11:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683144715; cv=pass;
        d=google.com; s=arc-20160816;
        b=oND1KpdBwsPoNgcAjmcM1YkP4yJdKd2evpLhxsGYGB5dLuBP7NnW+L/HHiS/pA6qMD
         sH2jIh/BWblT41ANDmFrVTeeLNsRkMJu+aHoi9mVClPJ/OQZE3xnBMCkVce6jj14yVDi
         r9CsbghpCi9v6FoegbV/MuxFpQ5YZJumhNhg1TSWa9DV31lsCVkpwJgr4Vuo22gopkiD
         Zc3M/0L6kUePkxyCD5+izIw4e5V8LwHYijDBAUk0suA7nismCKkotPMoh49oOAKHSLdu
         8wZFcJ2jv950TXwntI6uWL42Hz/vEGiNjcDdOuckTTy1zM1YEpdgpKJ6NW80CSLOrTvO
         qysQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=oXGPkan+Jm0UP2xIpTm14aolYfP17/KxM11Do9hG+/c=;
        b=t5+zjGv5U617pAjglaNSnfmTWOHDnYF2Si68ccGY5D129tVLlMunB9HFMjwJ1Ny0b3
         ZZ8eWR5t1JK6IGqyXPGqkGIysz+yte2W6nX32XIuT64OmLPyFob7hERLFpQV613KIlzW
         BZGa9f/Y1YzZuiFdJ5n5Y0Jf7Rm3MZIYvt4255Yq5BQ+wddyjXqxTpWG5U+aTFx8s889
         rWFdpkJrII837kPoTfFz76uxQYG0YMyWfzB+x86+VPsMvDbeJukQjVMccmpua0nYM2br
         QV2/sIJRLjSUz2ZNjHlXoMgkZPvGVA6tAwoLFlMu7leiKThMmUB4ISgbkBr3OvyCY/J9
         lkjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cmpxchg-org.20221208.gappssmtp.com header.s=20221208 header.b=B77wj2ua;
       spf=pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683144715; x=1685736715;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oXGPkan+Jm0UP2xIpTm14aolYfP17/KxM11Do9hG+/c=;
        b=pUKuTmr7LHcIBfwIuPgTGOCCgJmgs1Og9sXEgj2n5pM9af9BTVtLf3C20KczskemjT
         yAZ9dU0rj13N25KBessQMrCx6YZxT/yvKsimmZD9TwUQVjc7xFnu1xfsuKMOkNhjkDQk
         49KZ7x8gvYvbxQFQGQHxK7KWrf7p9bu0bFtb3VD0/6JSiMyby0IrA6I7KyuwE5gcu2DN
         NWPWnQ/oJrW7lDXrGccwIEIR1UDvHaAM/Z5RNE1pX8T1C3/KiJuYQC5fE9W7j2awYqoX
         HzXAtrOEEhY+jxjgwseh0QemWLQUwKqmP2gbex7MM8BjOEyC8IrJRmSeU2dqcka7LhNR
         uvTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683144715; x=1685736715;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oXGPkan+Jm0UP2xIpTm14aolYfP17/KxM11Do9hG+/c=;
        b=BpO+jEiFvmvLYrrJDqRPGEfns/9tVsRgdrS1rKpJe7A75FmtM4TjJLcYb4PJYH/VF1
         ueMt4fuGyTUKxDPZLdwL2sty2BTVublMXAFrRho/PRFx1Kgbm5lBK74zNeUSqkj1GD3r
         N3HPzGWjPr5k0+0ZFInz3vDcYBKGFN/15LlQzfqV/1XP2jWOancm8U5/NPaXBfnL4C+P
         FTQjmNJH4QdQeLChk1IG/KRn+9vlXNL3DUNahsqxhrgzhoJQM82qqrRRIOtivYMYrcLa
         0Rci2Dss+GJaNhimxYANdmTCHo2MV8j3KrGizZ1BgFO0Fi6wrXkswAbaCalu+Br4CnzP
         BimQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDznnUnX64e++u4/tXPmF7QroLd1RieeR6ioerXmIUqUVFIXnAbe
	GNVrychaADshc1bbABWembE=
X-Google-Smtp-Source: ACHHUZ5lLjWPqpn8gkno08GcyVEsHfdwSgmn0i+K+HpsenaVhgiKU6dUMiOi/DbFkBW+ZaR5VFiOyA==
X-Received: by 2002:a63:6b04:0:b0:503:77c9:45aa with SMTP id g4-20020a636b04000000b0050377c945aamr827318pgc.9.1683144715218;
        Wed, 03 May 2023 13:11:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f612:b0:19a:9859:be2a with SMTP id
 n18-20020a170902f61200b0019a9859be2als403582plg.1.-pod-prod-05-us; Wed, 03
 May 2023 13:11:54 -0700 (PDT)
X-Received: by 2002:a17:902:7583:b0:19d:20a:a219 with SMTP id j3-20020a170902758300b0019d020aa219mr999241pll.66.1683144714328;
        Wed, 03 May 2023 13:11:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683144714; cv=none;
        d=google.com; s=arc-20160816;
        b=YbAmWPwL5hdH7YcqyiwDqFkKnu7G7r8w9h88R9eloUy6Ntbn+mCVfr+xmeBoN8aLWH
         McyN5KDDLiGVJyI+ceRnyXJz6WACtrFtJL4uv47u3T7sTZJNaex8Sq+X9I/y+LBuXGDy
         ceQAnuNv8n2KyiohMgqihKk9O4yDGIRR+t5qc8yhKlm6KXL4E1PsZO90bDSe8I8jGdw/
         RK+MxlYL1ZHjnaT/cOOQq0KfBIGwUcgwKktW4kLWO1CJo4XUCuwkpKLlZ/VUoysy9Ald
         MVrigT6+glzqmXhkPg6i5tJSLpcUuWxwxqEH28pv/jTWJTmtttAz0RRL/VjkqStN038X
         2iDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=6aQuySOZ5f1xPp5M/IH7FdCb3YCBcIXK77oTLJoa1To=;
        b=F9bIkmxiuL35TAQgwQx6WulcFMImBxxN8q+uHwF2OSHhZir3bs05zxc66ywN5EriwP
         UqPovBmqqdzgPmT+ZLBdHGeQzvAj+Mpv/HFHs6jcV//sMt2eousH6fCshzzHC8gBo/l+
         ICPwKBwMPDNmrtFeVZx7vRQamlI3goUYeBBYSIetuZDAJc/5Zf4/tNPiEdG414DR4DyN
         OnTFPSzrvmxuUegofVmE0FGvelhnkE4zrgOrnK3XNojuCd8M61X8MtRcOs8gRjaSHszi
         k6UvNOSboYpkM/ngHL+JYfOFFwnc391zR5hceZMo4jSdxE2eDCqsdd/mNAxzqlUkI7Hl
         EghQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cmpxchg-org.20221208.gappssmtp.com header.s=20221208 header.b=B77wj2ua;
       spf=pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
Received: from mail-qt1-x82f.google.com (mail-qt1-x82f.google.com. [2607:f8b0:4864:20::82f])
        by gmr-mx.google.com with ESMTPS id e3-20020a170902ef4300b0018712ccd6e0si1765700plx.2.2023.05.03.13.11.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 13:11:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::82f as permitted sender) client-ip=2607:f8b0:4864:20::82f;
Received: by mail-qt1-x82f.google.com with SMTP id d75a77b69052e-3f36523e104so3804151cf.2
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 13:11:53 -0700 (PDT)
X-Received: by 2002:ac8:5e0d:0:b0:3e6:9716:ba58 with SMTP id h13-20020ac85e0d000000b003e69716ba58mr2436956qtx.26.1683144712859;
        Wed, 03 May 2023 13:11:52 -0700 (PDT)
Received: from localhost (2603-7000-0c01-2716-8f57-5681-ccd3-4a2e.res6.spectrum.com. [2603:7000:c01:2716:8f57:5681:ccd3:4a2e])
        by smtp.gmail.com with ESMTPSA id ed27-20020a05620a491b00b0074e2da97de4sm10761665qkb.33.2023.05.03.13.11.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 13:11:52 -0700 (PDT)
Date: Wed, 3 May 2023 16:11:50 -0400
From: Johannes Weiner <hannes@cmpxchg.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Tejun Heo <tj@kernel.org>, Kent Overstreet <kent.overstreet@linux.dev>,
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
Message-ID: <20230503201150.GB197627@cmpxchg.org>
References: <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
 <20230503180726.GA196054@cmpxchg.org>
 <ZFKlrP7nLn93iIRf@slm.duckdns.org>
 <ZFKqh5Dh93UULdse@slm.duckdns.org>
 <ZFKubD/lq7oB4svV@moria.home.lan>
 <ZFKu6zWA00AzArMF@slm.duckdns.org>
 <ZFKxcfqkUQ60zBB_@slm.duckdns.org>
 <CAJuCfpEPkCJZO2svT-GfmpJ+V-jSLyFDKM_atnqPVRBKtzgtnQ@mail.gmail.com>
 <ZFK6pwOelIlhV8Bm@slm.duckdns.org>
 <CAJuCfpG4TmRpT5iU7bJmKcjW2Tghstdo1b=qEG=tDsmtJQYuWA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpG4TmRpT5iU7bJmKcjW2Tghstdo1b=qEG=tDsmtJQYuWA@mail.gmail.com>
X-Original-Sender: hannes@cmpxchg.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cmpxchg-org.20221208.gappssmtp.com header.s=20221208
 header.b=B77wj2ua;       spf=pass (google.com: domain of hannes@cmpxchg.org
 designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
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

On Wed, May 03, 2023 at 01:08:40PM -0700, Suren Baghdasaryan wrote:
> On Wed, May 3, 2023 at 12:49=E2=80=AFPM Tejun Heo <tj@kernel.org> wrote:
> > * Improving memory allocation visibility makes sense to me. To me, a mo=
re
> >   natural place for that feels like /proc/allocations next to other mem=
ory
> >   info files rather than under debugfs.
>=20
> TBH I would love that if this approach is acceptable.

Ack

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230503201150.GB197627%40cmpxchg.org.
