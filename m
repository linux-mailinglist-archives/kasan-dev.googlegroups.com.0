Return-Path: <kasan-dev+bncBC7OD3FKWUERBPVXZ6RAMGQEN2XIEYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id BE7D86F6FD3
	for <lists+kasan-dev@lfdr.de>; Thu,  4 May 2023 18:22:23 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-4f139de8c55sf3304267e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 May 2023 09:22:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683217343; cv=pass;
        d=google.com; s=arc-20160816;
        b=bIQUwaSdinAphAB/dT05h9uSpRJ5qCXyrhsYBAWa6jl9mf1xzYUSW1zwcMJXgNJAZh
         5nRVqfyZeod5o7+fyR49DEu97ZVpwI3nqIhqlqEDo8yKQryheiYOcYe4zk1XNQAgQOHe
         5o0slOT/Rd5sJJr5Ag6sVVR/SiRIFULYbriJVLjicLDXkcI44d2UF2UDcCTRyRtB0fWy
         4sQa3c8T+eYH9/NFthmLIEpp0vM1/EWT7RcMCNNJsUwm9gqxkDpHZbaBt0YiHB+nmV4A
         7PaabhHiQE24bkdd/bvoY0H1EA5bQ2HeuX1KkN2MFJvwTFSJ+qcz//jPkBhzJr3twMMc
         G8+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KeEntI9ssgTtr2VvbR1rkjVrdPnERBQzfAFWqXda+Mk=;
        b=CE9gme6Ieagp397j+5NRfOt404XIQCQkLlnTaiIi3oxzBFn8velP9JR+90h+W5UVEb
         R0J3CjIZnk0uCpaOhTGI4ypz7SCelJkQJXkXvUOI0G42odKCe76XkJkhJ479gI+ibJin
         EnCadYLRMBymdj8tRdSl2TQxSDLWP2RC3JklALeRNDyswY5ZNAZ3uLQ234TZxgvazL5n
         5WZGp8NAWio2K8iiXpWOa7vYbD4+XxNZgSc1ZkW9V2EuJyF/EHR0oAFAzTT8ToJJhnEJ
         u6yJ0s+9/Q39VobxHhwftG10jZMFhVwDmR3xLP3315TzM5rTdmNeF5pG9s15eMB/EDpt
         5U5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=6NGLeWA3;
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683217343; x=1685809343;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KeEntI9ssgTtr2VvbR1rkjVrdPnERBQzfAFWqXda+Mk=;
        b=Bdb9HVrUfSygEkhQsmGwm4IpTzZ93vUPfo2cH865RuFR2yV56i6tKd4XIpFYw28lp0
         TrHQ6jjF5RpVQbJ43yd9gPYn+3sNypDsBifVWjGAezTLrl+qVw6SBkEenlWXyik1p32V
         pmJRG/nZZCfrMp1k9zLUoKCLiXc+v4y5UWzpOIjHXu6Ck63Z4YVzMlyTFW9qZfd1VQI0
         Fo1R4meSsaO3c9iqnw5DnfMYvQFKynjQBWyCOA6IQZwrut/tpv0TA19FvpXPU8WoHAaJ
         Dzs3TlIdxLP+tQOumzwa01w37095TgKz9X7NNwydWGJdNRk3J/S9GG94HA95fu79xYFi
         yaiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683217343; x=1685809343;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KeEntI9ssgTtr2VvbR1rkjVrdPnERBQzfAFWqXda+Mk=;
        b=EkgucKBHnadstWcBMniRTRnGClJHFE/roD9Za7hw9jVzX7hlQzagUrWnFTsF7P9ggy
         EBx0KC5EpIIujYSH6HlFzHrVpMYR4Loy8IW2ELUYKQ/KDr/FQeoA4Sc46gHBozCo8ydR
         qO1LjZlitYkZ/tIJPu5qn9GWVq92tuZz3gV1AEZcGjsaK6NKPukHfZC7iFfC/sMJJMsR
         4eMIG7iv0GDsMPWYt4T18eST5P4dgO5Cpep3Ep6zrFqfn9vGK+FFhSvn/CdG5MunmpKn
         t8Z2BzbRCSBDy0XTNAoop+PJ/Nw9eT8arStpb1Sqq8v4Mu99MNMIsXJZCSZrHvAGYbSM
         rE1A==
X-Gm-Message-State: AC+VfDzoVk/sa2Y6aILUQvJieRsk0VSUD1wKB4bdPecErTm3VgWXRWkz
	jq6SpHaJXuP8NuyTB6QXhx8=
X-Google-Smtp-Source: ACHHUZ7ypS2iZ8ZmA6PO1sd6BeGE1DSDuAmoEJLxDHPFDhZsISvWaPxN+ugW53apZpp5VI812kBCKg==
X-Received: by 2002:a05:651c:c8e:b0:2a7:6f6a:baf with SMTP id bz14-20020a05651c0c8e00b002a76f6a0bafmr1385374ljb.0.1683217342709;
        Thu, 04 May 2023 09:22:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158d:b0:4ec:6fe6:9f26 with SMTP id
 bp13-20020a056512158d00b004ec6fe69f26ls3765843lfb.0.-pod-prod-gmail; Thu, 04
 May 2023 09:22:21 -0700 (PDT)
X-Received: by 2002:a19:c217:0:b0:4cb:13d7:77e2 with SMTP id l23-20020a19c217000000b004cb13d777e2mr1661689lfc.26.1683217341317;
        Thu, 04 May 2023 09:22:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683217341; cv=none;
        d=google.com; s=arc-20160816;
        b=DekhDlliB6SXW+AMNZRlp9BulZ++lEh4PjDtodAlXIG41ZaTuOp0TG7cxr58rWexi5
         WYZ0iTyT/L17lCgrvYI1CasiTVSkEdM4zQBkTNJVx29DVO8mrOu6ofNkTsadyYNz75/u
         uG+LGV0S1BcxEBQL95GZFrEKlslsJ/3XjQDIa4JZHxgKvcxrXiyVtbSNC39Eg6zZrvJw
         M5u9i3GF225p5+pCzsSiDjmA+mlytCDWNtSDw930WDN6LQhEp8EKfhz+7p/2AEelVE3V
         PCCVEhzwHEqZftBHB72URSiIt4mzwpTQ6YJep0ME28NyyTbfVAG/z02i4kuh66y9K4S1
         PnMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Gsk62XwjD8JjQowiDifvFLPW2uokrx3QTotNr7V9c/A=;
        b=Tn+DSecAUWYe2GBqpnkYBUxAPhB1bGnKXZt0vWXDUub7IfJnAPCpnJbjxP5uPL/80X
         gH9DLNtpMQQs7wRojTXF4SVTAOYkHCpRvilMgBE5+VfLeiT1Ta+mgf2rhDFbZgLKKAtM
         LayASe6YDs6NcmKzYdaVdvlxyj2pUbu9sH8Tl+gq9yQbDRZjnH6emopzLolNDHHaKGcX
         NfpypACYXywIv+sFoaAGMS+wQ87D40QTyz0Onp3rKk/oNsxHwZa3N1rSufRq4wwSrHKU
         BDBDl4J0Ds0tej4V8OYSHMdQIRlmu6fMa6i35ZCxCSSOEYDHiMjE5H+J1t1o8eVTwPm0
         5NwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=6NGLeWA3;
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id be19-20020a056512251300b004edb55cd1e9si2730179lfb.1.2023.05.04.09.22.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 May 2023 09:22:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-30626f4d74aso508621f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 04 May 2023 09:22:21 -0700 (PDT)
X-Received: by 2002:a05:6000:120a:b0:2fc:7b62:f459 with SMTP id
 e10-20020a056000120a00b002fc7b62f459mr2840579wrx.32.1683217340407; Thu, 04
 May 2023 09:22:20 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-36-surenb@google.com>
 <ZFIPmnrSIdJ5yusM@dhcp22.suse.cz> <CAJuCfpGsvWupMbasqvwcMYsOOPxTQqi1ed5+=vyu-yoPQwwybg@mail.gmail.com>
 <ZFNoVfb+1W4NAh74@dhcp22.suse.cz>
In-Reply-To: <ZFNoVfb+1W4NAh74@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 May 2023 09:22:07 -0700
Message-ID: <CAJuCfpGUtw6cbjLsksGJKATZfTV0FEYRXwXT0pZV83XqQydBgg@mail.gmail.com>
Subject: Re: [PATCH 35/40] lib: implement context capture support for tagged allocations
To: Michal Hocko <mhocko@suse.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
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
 header.i=@google.com header.s=20221208 header.b=6NGLeWA3;       spf=pass
 (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::429 as
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

On Thu, May 4, 2023 at 1:09=E2=80=AFAM Michal Hocko <mhocko@suse.com> wrote=
:
>
> On Wed 03-05-23 08:24:19, Suren Baghdasaryan wrote:
> > On Wed, May 3, 2023 at 12:39=E2=80=AFAM Michal Hocko <mhocko@suse.com> =
wrote:
> > >
> > > On Mon 01-05-23 09:54:45, Suren Baghdasaryan wrote:
> > > [...]
> > > > +struct codetag_ctx *alloc_tag_create_ctx(struct alloc_tag *tag, si=
ze_t size)
> > > > +{
> > > > +     struct alloc_call_ctx *ac_ctx;
> > > > +
> > > > +     /* TODO: use a dedicated kmem_cache */
> > > > +     ac_ctx =3D kmalloc(sizeof(struct alloc_call_ctx), GFP_KERNEL)=
;
> > >
> > > You cannot really use GFP_KERNEL here. This is post_alloc_hook path a=
nd
> > > that has its own gfp context.
> >
> > I missed that. Would it be appropriate to use the gfp_flags parameter
> > of post_alloc_hook() here?
>
> No. the original allocation could have been GFP_USER based and you do
> not want these allocations to pullute other zones potentially. You want
> GFP_KERNEL compatible subset of that mask.

Ack.

>
> But even then I really detest an additional allocation from this context
> for every single allocation request. There GFP_NOWAIT allocation for
> steckdepot but that is at least cached and generally not allocating.
> This will allocate for every single allocation.

A small correction here. alloc_tag_create_ctx() is used only for
allocations which we requested to capture the context. So, this last
sentence is true for allocations we specifically marked to capture the
context, not in general.

> There must be a better way.

Yeah, agree, it would be good to avoid allocations in this path. Any
specific ideas on how to improve this? Pooling/caching perhaps? I
think kmem_cache does some of that already but maybe something else?
Thanks,
Suren.

> --
> Michal Hocko
> SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGUtw6cbjLsksGJKATZfTV0FEYRXwXT0pZV83XqQydBgg%40mail.gmail.=
com.
