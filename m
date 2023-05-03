Return-Path: <kasan-dev+bncBC7OD3FKWUERBYXRZKRAMGQEGT7274I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B1D66F5F46
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 21:41:24 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-64115ef7234sf5010459b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 12:41:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683142882; cv=pass;
        d=google.com; s=arc-20160816;
        b=012JiJ/154/kDXzrzsejmsExbOXqVn7JRypZFVlAnZSAOzvLw2oi328H3k7Z1uK4Zi
         PdEh7S3n1yUU5cbvqiereI+6rT+ZyXT6LsZz9JulLPKQPlpKiE7PKebNEbbdwg0xoE6x
         FaCh4VH4oLsh/DumyFeLPLUPNbM4aeRZNPwENmKikW7R38fxsBqyfpnSxeQDVNQc18Zq
         2yjB+rGYQ/bNlo2wnl6HUWSNHZvbdoLDg4VuL9s/6BurvzDrYK6c797BGDZ3LEnyFr2B
         oBBsZDbR70cwzxtb+TtB6pMCon+bVmqogItsMBnOh1x9BAIdjDgUye36Tb5FZ85oiwos
         iLyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1CdPgNoEd8SgO1+5Pj8PM0+CFXPQulS2Xfp2iSGlaqQ=;
        b=TCWl5CUos6T/MTtrJdVSly2/Cr3RbPAjWnNZfLVmw1NdqDIYeqPDrJa3NfH/M5KrqV
         IgMLnQnEhr7ynnHa9Vvp/GqqU+B+d953impoN1BfLTqsSdXaUFhVC2LBCnFRdT1lRHg8
         20XZrXQB2RG4RpQK8E11i2K5J5qhaqsDHiIFZlwFAJOXafoYTdGdy9DXsz/tzGZSn+xX
         71AoIlVEqycsgHrBFBJKCVZH06hxPpobvffRnOJ1MZhZsZJXbKqyBcVkyPueBruBMk6s
         Zw+Bu2F4a2ddASg59+umZ/NlqKqOaiBM4tBsIJhyk9NZMpSw78QuqkBCbFC+8XZPMZ5N
         w3Qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="njnY9/ZT";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683142882; x=1685734882;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1CdPgNoEd8SgO1+5Pj8PM0+CFXPQulS2Xfp2iSGlaqQ=;
        b=Oao5U++nnO8TL93Q1HVfbQdMA6dl/xwyBbxAE244NnPqsYQUW0Hyq2+/L2bQIrn7/8
         oJQqEiJJanrN2lADBzCjYymQuFP2aYR/Ior03MDExDqDVBMxYngu7Kgy5MpzPmJjeoAg
         tlv/6vwSXZZe3Qw0WTZQn+4u7t93sOnI5Pu11ZX7erZ84PxrsHnDFay4gDB1or+x+XEt
         BqT//Z3t1SgOiN+cQ7fx0raSo8mrRBdQpxSduPna3bvkNHaUMevGI1TVcnYDhoXmr4Vc
         MlfFvPbsQR0GUqXtepklccYdo/gYE9kve4HfoLztLsKnW8CboNOGWCsZUG9A+SQxcr8n
         qRrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683142882; x=1685734882;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1CdPgNoEd8SgO1+5Pj8PM0+CFXPQulS2Xfp2iSGlaqQ=;
        b=RlD0c9jSmzRMWA4v7ejLG91PmFJL/s0n/IHhO1fm676QiBUi+vDthz4Yme3r1786bs
         tsGJu3HMDcqd6xFTc+ASLHFhVVA9NlRxDFPM7pmij+4uqKh55wRVC7ZAG2SaQfKSYDut
         ACze/Em2bvfyELR+xMzeBLu2Hqrh6aOk5WaLtOwNzU2PxSjjQp1cSclCJeGli/juJv1Q
         Wi/Z+BdbxMu1M7gF5HEhYbzZ/U/vn6lEpcgtOPuA+hHIsdhoRsbXRcgFicS8JKRSUCcw
         GR6vxhzIUTuciky9BiU47QLmqzeWngpD7zuqvkOBXSe1LCutbdjEbK5GLRRn8ra9W6Kh
         KOKw==
X-Gm-Message-State: AC+VfDzPzPTqwsuT04sE8l/QZXgmRH4u4a3mxYr7IW4/AdZQLZXPKoq4
	VU7KlzKaPP9JXl6FwRVOXVmRhQ==
X-Google-Smtp-Source: ACHHUZ7/mnLdTXd0nj1QfgcptVg7vCQgOGVo58yX2uU0eSp75Tt3JN96HVVfTtTaviRONOcvPa7fGA==
X-Received: by 2002:a63:113:0:b0:528:a60c:c06b with SMTP id 19-20020a630113000000b00528a60cc06bmr756967pgb.1.1683142882655;
        Wed, 03 May 2023 12:41:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d50c:b0:19f:3460:3f0 with SMTP id
 b12-20020a170902d50c00b0019f346003f0ls16507532plg.5.-pod-prod-gmail; Wed, 03
 May 2023 12:41:21 -0700 (PDT)
X-Received: by 2002:a05:6a20:42a8:b0:f3:a3b7:ae37 with SMTP id o40-20020a056a2042a800b000f3a3b7ae37mr29421231pzj.29.1683142881833;
        Wed, 03 May 2023 12:41:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683142881; cv=none;
        d=google.com; s=arc-20160816;
        b=W40BSVc33bHs1VHIz88mBITVILebRUdHrUbORN3orbLzptCxQaelQDwN0gakbw416t
         CkuWN/YQAs/ptkbTvhHruTu91B8wAWjUMQwq95BFJnYC/ItfnnMGURovmHp2MoQDt3Ya
         stxLG6+Jt+sQQhHOj9L/NZXR0295zlKbHyU7AgN7lXBBWdOj2zIp6z+TYAojAyroC8Q+
         xuBI6TtWDaO2l9zgVrfnfHyGP9JTqs21P98G7K1mWXVhImgSDyoeVPAdophEOv/FKXnG
         6xUFTZGliSQSSkexoBw4u9ypFAb7ak2BcQFRE8dv93vXRlXHSOYzoSJytaU5MmNEQlx9
         Synw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7eRiiP2JCtlxvX+BHzTjXxhFfE3xb3L5Tko5xVivHIc=;
        b=oLBizU4/9wHUrjUgJ3xcMsSVxgaPx6k+xfrAU9Fg/Y0oFM+bDwmaInEh/GeP1n2+x3
         w2VI1HUYM5rQ74bi3UzPbP2REZRg5dAcfix32MXqNmeLXuvsvPLIhC7VWA9A5+NaQmQK
         pK1mHXRMMMC6oEFHZdaeMdkynMygUxHSPHyW8+KBdcQ6uiuSqf+RTm2Ry69guWSqBpPE
         PbcfEMUDJxvTP+1Z8zieelCM9xk3cXjyzHYJLbtso1YHeTg80saQn6HK7+c6HnSZodYw
         DCbSOXezfecs6TohhNPK8rX9YKhgzl58q3uKCJh8GvXgv26uyKr/D+q+MkaqAzO/kt93
         9rSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="njnY9/ZT";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id d5-20020a056a0024c500b006430a9291fasi173096pfv.3.2023.05.03.12.41.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 12:41:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-b9e2f227640so4788067276.3
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 12:41:21 -0700 (PDT)
X-Received: by 2002:a25:308a:0:b0:b9a:38b2:8069 with SMTP id
 w132-20020a25308a000000b00b9a38b28069mr18330170ybw.6.1683142880244; Wed, 03
 May 2023 12:41:20 -0700 (PDT)
MIME-Version: 1.0
References: <ZFIMaflxeHS3uR/A@dhcp22.suse.cz> <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz> <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org> <20230503180726.GA196054@cmpxchg.org>
 <ZFKlrP7nLn93iIRf@slm.duckdns.org> <ZFKqh5Dh93UULdse@slm.duckdns.org>
 <ZFKubD/lq7oB4svV@moria.home.lan> <ZFKu6zWA00AzArMF@slm.duckdns.org> <ZFKxcfqkUQ60zBB_@slm.duckdns.org>
In-Reply-To: <ZFKxcfqkUQ60zBB_@slm.duckdns.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 May 2023 12:41:08 -0700
Message-ID: <CAJuCfpEPkCJZO2svT-GfmpJ+V-jSLyFDKM_atnqPVRBKtzgtnQ@mail.gmail.com>
Subject: Re: [PATCH 00/40] Memory allocation profiling
To: Tejun Heo <tj@kernel.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Johannes Weiner <hannes@cmpxchg.org>, 
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, vbabka@suse.cz, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Alexei Starovoitov <ast@kernel.org>, 
	Andrii Nakryiko <andrii@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="njnY9/ZT";       spf=pass
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

On Wed, May 3, 2023 at 12:09=E2=80=AFPM Tejun Heo <tj@kernel.org> wrote:
>
> On Wed, May 03, 2023 at 08:58:51AM -1000, Tejun Heo wrote:
> > On Wed, May 03, 2023 at 02:56:44PM -0400, Kent Overstreet wrote:
> > > On Wed, May 03, 2023 at 08:40:07AM -1000, Tejun Heo wrote:
> > > > > Yeah, easy / default visibility argument does make sense to me.
> > > >
> > > > So, a bit of addition here. If this is the thrust, the debugfs part=
 seems
> > > > rather redundant, right? That's trivially obtainable with tracing /=
 bpf and
> > > > in a more flexible and performant manner. Also, are we happy with r=
ecording
> > > > just single depth for persistent tracking?

IIUC, by single depth you mean no call stack capturing?
If so, that's the idea behind the context capture feature so that we
can enable it on specific allocations only after we determine there is
something interesting there. So, with low-cost persistent tracking we
can determine the suspects and then pay some more to investigate those
suspects in more detail.

> > >
> > > Not sure what you're envisioning?
> > >
> > > I'd consider the debugfs interface pretty integral; it's much more
> > > discoverable for users, and it's hardly any code out of the whole
> > > patchset.
> >
> > You can do the same thing with a bpftrace one liner tho. That's rather
> > difficult to beat.

debugfs seemed like a natural choice for such information. If another
interface is more appropriate I'm happy to explore that.

>
> Ah, shit, I'm an idiot. Sorry. I thought allocations was under /proc and
> allocations.ctx under debugfs. I meant allocations.ctx is redundant.

Do you mean that we could display allocation context in
debugfs/allocations file (for the allocations which we explicitly
enabled context capturing)?

>
> Thanks.
>
> --
> tejun

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEPkCJZO2svT-GfmpJ%2BV-jSLyFDKM_atnqPVRBKtzgtnQ%40mail.gmai=
l.com.
