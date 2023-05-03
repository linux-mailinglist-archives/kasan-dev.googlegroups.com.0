Return-Path: <kasan-dev+bncBCT4VV5O2QKBBGP7Y6RAMGQET5PENEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id DE9B16F501F
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 08:30:51 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-63b3bc3e431sf2782946b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 23:30:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683095450; cv=pass;
        d=google.com; s=arc-20160816;
        b=lkiQNkIlNhZ3Rb51t75zZRWC+9OMAE2JJSjvfoy1JzNKjm5d92VMyo5w+D3T0oHeew
         OY8kuyIzsEd2E9eOV87Rs1YwiQrN99ROeYaXGh3UL+LayyGDgTn5aYBXHexfbt5SUgoe
         Men3a/U4HhYVDJS2zNntWEGBuXKZu+EUGdXHH1vdVl7bl2Y/dbOtN/YiWcQMYM7vEGs9
         e0opZkjadUYy7uT0VBzwk0fzyx0bsAUFlpDwIwq2DMMPwd1Or2eTW7Q4tWD24kbsMOe4
         Remzz/75HZ3cwPsb9ecPsnwoVFAAjtx+4A7nDz84xBzNB8uVImSRvpCx2NBfl/EKqlAQ
         l/FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=+H/HVOfhglwBnde/TSUkxqzke3upKdrugOWchu+O/+8=;
        b=x+IrJp6IaNwfwaf9UBK7K4Ap4d0Z8Gs+JlfF13Qm5jIzum3wdxRCvemg3JP/bPX3tm
         /6ZLBsY681ttbifxv6stUitmvhUMNpBX/MVKm9h6FsHKNr1Cy1CcNEzjKyhC1sX1nk76
         gMU5PAq7WOWnrLbHYq9qvZWndBujBunW5L56r3ZGSypKSZ4BrmSdbx2Z12MxLp9PpgZy
         LXmOLXzs4oY8icfNIpRu1f27wfCR04i7EjApaVeKY9n9wYF+UPGpLl2lg+LWZAYSybpD
         A8N8muALM1F0EaM35w2Uk5EMbT/0LqqtWyW+ba4weUdjUnNUoO6SupPzOwTOMchPk0ap
         Ndsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=FwxsWECu;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683095450; x=1685687450;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+H/HVOfhglwBnde/TSUkxqzke3upKdrugOWchu+O/+8=;
        b=carnTp/3sxcEaS/hOxJztwLlfuVHgLQFjglu/iCAXt50TFK/NAepvRn+TsQRMsUvTm
         1gCxHeEI8Hh03pHwgmmnkTSjr0Ltf7Mb+4z/CbvhZ7MwW3bOzDtW2Z+3DAJzgLDQ3csE
         x0z67hK3lBtlWNLzPEO9oPQIJEVngxPAN3dKdtgHFR6rPLXjx7TawvamWzi0WlBKK5Ha
         Wfx7qTRzXHsZtmvy3ENUWn86p4jXhBBPd1DfZ3E1DRzQ0e1/vGlHwmWfjZWob4YzBNzp
         XZdN/KbnRiWcJ6WqaNpkoaYVXL8PXaopm1ceMeuEpz/5KXnY/kHz8057Yngcop23dQU8
         AiuQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683095450; x=1685687450;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+H/HVOfhglwBnde/TSUkxqzke3upKdrugOWchu+O/+8=;
        b=GY/xUdNwT9E2SHlaxN8htiTIJvv251OgzL2QQXyrbERDCoVACbnwX0IovemxXH2ynr
         mKj/q3VnpO7QmwSYG0ghWEmYoU1OFW1UkbMTPe2CSHlbp+O/6nylo2bwQG4+ur6QtBiH
         ZsFifNJFcser+m1o2ytON+OtzMnENr20MBPjk8i+E5FdfIKhoJDoEhPFSTrVwMApZZj7
         U8Z+YN9f6YGB2fI3LFePg8uWp+JMvQODXze5ES+OEYHXuryv34kUXPLMW4eZuI+nRTVN
         +acvQS7uQo6fyWvgDt28vkU/fVY/3eOuOOw+13aM4O+SoT/Zt6bHO+bMwrgRdoUIgmIy
         nizA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683095450; x=1685687450;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+H/HVOfhglwBnde/TSUkxqzke3upKdrugOWchu+O/+8=;
        b=b+wgP9ToL0gkDjemX55g6H7i0EOMZ97ojfkm4jEAMtvXBhG2mH20TnOstCc3F85Cq3
         hMSt+5qXG8L+vO9GV1Uv3Si5j+wHHvcOzpC00YFia4yCRblbBt7gDZbljDL2ouNpWZtN
         RU/H5aBL/PmpqxgsJixRWIo1xGRYciI31bNJ1yHWoMo3c/rBKllPh3gw47HBp7TBsPF0
         iO1zYR/2Yy2IjF7LLRV5hVHPWIhdisuHD/522ZjqdsfenZc+iLjS8zHQjgoSc56B5iHv
         Rjm8UI5yvtpyL7fLi/emnJlhHGJU0dh3l9Eh1o1kDWoNeYQIGoHDccVLv/nkpRgWCskd
         lUuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyxK2b0xyhUHOQw4BTlbuWJDF2dVQTpfHtgQntojpgJyAJU1X7S
	mlzS6GLdUAY7NnGAe/xAiKI=
X-Google-Smtp-Source: ACHHUZ5qErxSVqtW2q+8RE2Ekb6kkVvL1+ukdo7mWGaLo3v8U8g2ChCL52ArUnTpFbqkhBvTKyTfWw==
X-Received: by 2002:a05:6a00:1625:b0:63e:2229:60dc with SMTP id e5-20020a056a00162500b0063e222960dcmr4803112pfc.1.1683095450127;
        Tue, 02 May 2023 23:30:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:910:b0:246:6edd:bdde with SMTP id
 bo16-20020a17090b091000b002466eddbddels144825pjb.0.-pod-prod-07-us; Tue, 02
 May 2023 23:30:49 -0700 (PDT)
X-Received: by 2002:a17:902:b78b:b0:1a9:6b57:f400 with SMTP id e11-20020a170902b78b00b001a96b57f400mr1067416pls.16.1683095449154;
        Tue, 02 May 2023 23:30:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683095449; cv=none;
        d=google.com; s=arc-20160816;
        b=njdLG6pufdSNdQ9Re1B9q2O1S1nsLMmeMEr1HGFe5ePOrnNNg1sE0TzEuIbGJTFDIS
         /MzY97bKAlE0Rwv+uS6o71HREqLf3sdmDl3VWvOdepvJmDiiJLGHxH5WMbGD/07GHhxz
         sDc9GKABBTKhE/5Alw3D0zasuGkgK1hNQ9J3F8uEPTfeZL8yICzQra/q4GtUccxPKqsu
         KfHcL3X771g7j2JdmISOAZpdMU8m2PniTQmyyAN1w8MeIsNsP+ZkMTjnULWpl8PcprNS
         DcYRQm2rpsvmLxrXyjVXVV5LHRuQAN4P1sRrmMMml+X2Ii4lhoEHNk2vtPEVX9Muc58a
         GfwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NSWUOSuqVLpIOWgszk2VW3MzVdJnM+9N5Gz+a5oZIik=;
        b=AmjbmfV0MSjUGgWoYUFsUhAlsoo8RPpDqH/QRAIr932o2CoMvpBwryrQj6grS2Qbq1
         A3fCUkTaD/8ipjK9Cd3LOtLn0NRE0JbsGe2PbeEKbCThOGSD8j2g1upjWvWs0w8Eg0MR
         xV35uomIyznmsPNOE1WitNnt+GzSUY2CJnzakDHjqYVFGU3thwCBwcRSassrkHfOriJZ
         iSN8cbu4+epmgAuP11gBqag31t7b2uZ3IqJX+x2mFcXq0owiY31bAF+Fyo19zA1rBNcL
         CdytwEkMD4QcZmafzSQDIx/DRwExZNIYakVFPjqAbqyTyr1PHx4JeutHVHUGsw7dky2G
         cM/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=FwxsWECu;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id mu16-20020a17090b389000b0023f99147cfdsi37771pjb.3.2023.05.02.23.30.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 May 2023 23:30:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-5f3da4f91a0so21968686d6.2
        for <kasan-dev@googlegroups.com>; Tue, 02 May 2023 23:30:49 -0700 (PDT)
X-Received: by 2002:a05:6214:1941:b0:61b:5cba:5820 with SMTP id
 q1-20020a056214194100b0061b5cba5820mr9799913qvk.50.1683095448149; Tue, 02 May
 2023 23:30:48 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan> <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
 <ZFCA2FF+9MI8LI5i@moria.home.lan> <CAHp75VdK2bgU8P+-np7ScVWTEpLrz+muG-R15SXm=ETXnjaiZg@mail.gmail.com>
 <ZFCsAZFMhPWIQIpk@moria.home.lan> <CAHp75VdvRshCthpFOjtmajVgCS_8YoJBGbLVukPwU+t79Jgmww@mail.gmail.com>
 <ZFHB2ATrPIsjObm/@moria.home.lan>
In-Reply-To: <ZFHB2ATrPIsjObm/@moria.home.lan>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Wed, 3 May 2023 09:30:11 +0300
Message-ID: <CAHp75VdH07gTYCPvp2FRjnWn17BxpJCcFBbFPpjpGxBt1B158A@mail.gmail.com>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in string_get_size's output
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: James Bottomley <James.Bottomley@hansenpartnership.com>, 
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, 
	=?UTF-8?B?Tm9yYWxmIFRyw6/Cv8K9bm5lcw==?= <noralf@tronnes.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=FwxsWECu;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, May 3, 2023 at 5:07=E2=80=AFAM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
> On Tue, May 02, 2023 at 06:19:27PM +0300, Andy Shevchenko wrote:
> > On Tue, May 2, 2023 at 9:22=E2=80=AFAM Kent Overstreet
> > <kent.overstreet@linux.dev> wrote:
> > > On Tue, May 02, 2023 at 08:33:57AM +0300, Andy Shevchenko wrote:
> > > > Actually instead of producing zillions of variants, do a %p extensi=
on
> > > > to the printf() and that's it. We have, for example, %pt with T and
> > > > with space to follow users that want one or the other variant. Same
> > > > can be done with string_get_size().
> > >
> > > God no.
> >
> > Any elaboration what's wrong with that?
>
> I'm really not a fan of %p extensions in general (they are what people
> reach for because we can't standardize on a common string output API),

The whole story behind, for example, %pt is to _standardize_ the
output of the same stanza in the kernel.

> but when we'd be passing it bare integers the lack of type safety would
> be a particularly big footgun.

There is no difference to any other place in the kernel where we can
shoot into our foot.

> > God no for zillion APIs for almost the same. Today you want space,
> > tomorrow some other (special) delimiter.
>
> No, I just want to delete the space and output numbers the same way
> everyone else does. And if we are stuck with two string_get_size()
> functions, %p extensions in no way improve the situation.

I think it's exactly for the opposite, i.e. standardize that output
once and for all.

--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHp75VdH07gTYCPvp2FRjnWn17BxpJCcFBbFPpjpGxBt1B158A%40mail.gmail.=
com.
