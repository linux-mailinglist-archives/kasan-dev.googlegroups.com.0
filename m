Return-Path: <kasan-dev+bncBCT4VV5O2QKBBE6LZCRAMGQE5Y7FX3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 917AF6F5418
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 11:12:53 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-6435432f4ffsf49938b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 02:12:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683105172; cv=pass;
        d=google.com; s=arc-20160816;
        b=ids9KdIRP9t4OwuxLkm/ZNeHu+WvbUhOWOvRfSpccwiflTkW+L6m5Y5S236avaHIkO
         IdOPxVwMq/CvVXxcpF4uhYj/LyzBKzvQMfmJWEt6lNoydFz7EDUgV6M4fpE7TSew0DlY
         e4j3W2xLgULvgef0XvXE8CSnUuphJaLnlRjkSancx/tC1GfiYfgtxrXije75a2aUR+Sz
         DeBIQ3tqs8WAlmeAYnIr8dW8K1r+dJEDXLeTzi9sUw/1YiR9dIDJobV1RYWC5A6nkPhj
         PUrW4kiCKS4Kqxqu2wlkaeThIB4XmMAySyqP771O2p9gqko1vzhsopHC6YWEII19H1KU
         gFRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=YGc8jHRjbTwTf09XLicQCgnH+2v4ivbRiwEp4cl4OqU=;
        b=iGkOpbM4EvbPZQqjiA+p9kqUKEUDDG9kUaQ/8GL/oTFRYI6jJqW0CIgPas2nA3tHN/
         4C572hVqT8ZN+zm3niteReCJCbjYTMzsvUbBpFYwaVSNpgDMA6mmMxPIj4kwMVQxT5hf
         Lr785L9RJaxqf8HoQ/8EFJaxlNAqs7T8RovM4kVCkv9joGu2dTbHNANu9DfwWByxVhYt
         wSn3dQ+9Nq/ENKKv3DBbgGwduXtQJ/Ii5vh9S24VMzfmKw/uXl0tqS1EV7pWlZhWnayf
         DivwO2Oz61Clbh0UhPZH7QolcB+1DBbRNMC7uJUHnEpJ9jiBvTP0rtYhPS2lMzfNlF7s
         Z9ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=lkpnSWbI;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683105172; x=1685697172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YGc8jHRjbTwTf09XLicQCgnH+2v4ivbRiwEp4cl4OqU=;
        b=UZTm2Zkopy9LvVQ1MbfT8SjKigLUFHx3cxd6QVsDOIqYzJIQwjbbPZiUhCgpivHPV3
         PIetweE6lYUgc/L+co7X9RM+zJEKm+LZft2IIVQrkhih1YLf7KZFBeSQWC5lmS5wfT+8
         YnhjE1NurJ45tqOZHa+LRwmUEUbje1s9qqFFgxXCvHD72h0pjoR+OMUm+u9cd2j86Kf5
         mJE9tIh4vH8Vu9glyftWuCxySYz19c+zCpKyMX8Us82WFapB/gpaK9vmag2pbCLmj1Qs
         w/lcs5gfs2b/Haa8u6JclVUzj/kk1L5ZeFAfAD8zks6vfrrBFo9YWlS5sEiqWFHLTyPF
         FSsQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683105172; x=1685697172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YGc8jHRjbTwTf09XLicQCgnH+2v4ivbRiwEp4cl4OqU=;
        b=J478M9fbQz7SbC+WnMorwPKaFK/ebpByshOoAwqwoycQE1N3W5S0x34RdoYvk/tZfm
         hh1pBL1+rBFixmB6F4VBOwMjc41OUToEFDVqOYBWtEEC3WfX83oyjnm0GdSrtriTaUOo
         vl9z2gx4v2/NKOw7T13WiiJcS5gPIWNeeITzpSUs6TcgHxk3zpcULaniyPfN92bL3eCN
         iHtINuGJnOLQ2WpoE1L/Xyk6qsA3m3QArCiXpDBkVXMMBgJiVsNp8ABJFUxAcaIuycLD
         S7jEGSaSVqa6H8h9UGEm6YdwJ8Hv9TtK8SCpbL7jwO8Cxf1EPmfkY8jyzGkguXgM0u58
         VhhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683105172; x=1685697172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YGc8jHRjbTwTf09XLicQCgnH+2v4ivbRiwEp4cl4OqU=;
        b=bJx12EZLFt76SDbkSL6dUjB7FjPN5JmgQwJcjY6Ug/sAh0IB6CJgjZFtH4LHBX1M+e
         60zDjctw2+ghm7HgVDeQHwUxgv42/9h3RHPcLwLREcEJX9Y7JX8ZTu/7pVn5CWcQ6NnG
         SCmnYVaKGbV6vczrhqwgWCfzutMMO4Pbc39N3tgoRkNwupMSIMG7wNSMZKFxBDmx1T+E
         8bL1ONaRMB5gqca+liPQpDqEi4XViZ+8BT0m+EgJyNN/B0AwLyIok8Dfk2a1q2OXJJGv
         UEUht0LRcMIiyNDxx6qD4Q6tVWcPT2TQCY6NIMUCfOFslGN85fT+U2RIfR4uVz3FsK6M
         YOgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyCFS15eAWZ99mb9jYV90ba5vW2M+DzwXN8t2zGtQ+oB1G6BenF
	alE+LM+AnCq+7HLGQ2Mlb2A=
X-Google-Smtp-Source: ACHHUZ7+liPWMTV7dB7vqHCvcpqonUqzhWjIhLlba4LrVBy7iD+RK9Nsybg+Fb18u+OY9hyITQlfBw==
X-Received: by 2002:a05:6a00:80f2:b0:643:4b03:4932 with SMTP id ei50-20020a056a0080f200b006434b034932mr146309pfb.4.1683105171953;
        Wed, 03 May 2023 02:12:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:428e:b0:24d:f0d1:e44c with SMTP id
 p14-20020a17090a428e00b0024df0d1e44cls8022684pjg.3.-pod-canary-gmail; Wed, 03
 May 2023 02:12:51 -0700 (PDT)
X-Received: by 2002:a17:90a:c253:b0:24d:f8e6:9d4c with SMTP id d19-20020a17090ac25300b0024df8e69d4cmr10024776pjx.49.1683105170965;
        Wed, 03 May 2023 02:12:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683105170; cv=none;
        d=google.com; s=arc-20160816;
        b=F3ixs1xwOvHMoimLFLxiLg3RYEZETJHsdKi+s06hHzpv4op1qxXbKVmDgJBz3suumC
         k/OYPvzQBDEI4cadU031zT36mZP2QkGbYy0ZRkfM8vvgcTLM23JJhrecoXksJogVQDsa
         TelCu0m/O8uzbnYYevvYrDNuIB88AD+gg67RGTwmtBDBEeG5IgMULh6SJJhYnq0AT0fA
         Qbgt6n5VkFkFRhvTEFqdzEy/x8l/fxSpcreco8lLU3g43CTQZK6pw1C8e5FWV/Bfjnab
         0aOVsCzWjcYTMjHHsIOG/GMTHjR6QlqOrnLwjO5Av21OIy6y5Ae/vabhze5sa1o6vstJ
         Z1hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TEZd+b8sulXt8fKAN8kz+Gm51fXRGcBOvDO84eUPrqA=;
        b=DCqmAtlsR7//s6LJemgV9AjgNIVwT+X5QmwVBY36IKrAO7j2+MUkd7Kb5J1H1JDprK
         RMTnzI6U4C4Ie6VoqE7hrXJlMv+Rx9MFOK1JkMaECn7kkBaa4YBNvvPhft9BQu9eNUR7
         5Ge14uEPB758Uk7bMGjcq1+hwUVJauc2MiD5bxvtikkYIGreMF0FyxkQBJCVM5EEY37o
         EbljzNe2jBQURA2IL5PprFRuXTFbT5G6EyNYoP+cuS+WG/kPi9C7QpalwMbfNikfu1Ds
         OiYGtkNwrJBN2K+Kk9uh0BcRQDry0AJHM3sYHdMwekenPbMFB3tlmW9Y4remSv/sNEfu
         Qg8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=lkpnSWbI;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id pv15-20020a17090b3c8f00b00246fa2ea350si2258647pjb.1.2023.05.03.02.12.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 02:12:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id af79cd13be357-74e07c2ee30so214304685a.1
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 02:12:50 -0700 (PDT)
X-Received: by 2002:ad4:5947:0:b0:5ca:83ed:12be with SMTP id
 eo7-20020ad45947000000b005ca83ed12bemr11144076qvb.21.1683105169929; Wed, 03
 May 2023 02:12:49 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-2-surenb@google.com> <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan> <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
 <ZFCA2FF+9MI8LI5i@moria.home.lan> <CAHp75VdK2bgU8P+-np7ScVWTEpLrz+muG-R15SXm=ETXnjaiZg@mail.gmail.com>
 <ZFCsAZFMhPWIQIpk@moria.home.lan> <CAHp75VdvRshCthpFOjtmajVgCS_8YoJBGbLVukPwU+t79Jgmww@mail.gmail.com>
 <ZFHB2ATrPIsjObm/@moria.home.lan> <CAHp75VdH07gTYCPvp2FRjnWn17BxpJCcFBbFPpjpGxBt1B158A@mail.gmail.com>
 <ZFIJeSv9xn9qnMzg@moria.home.lan>
In-Reply-To: <ZFIJeSv9xn9qnMzg@moria.home.lan>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Wed, 3 May 2023 12:12:12 +0300
Message-ID: <CAHp75Vd_VMOh1zxJvr0KqhxYBXAU1X+Ax7YA1sJ0G_abEpn-Dg@mail.gmail.com>
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
 header.i=@gmail.com header.s=20221208 header.b=lkpnSWbI;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
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

On Wed, May 3, 2023 at 10:13=E2=80=AFAM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
> On Wed, May 03, 2023 at 09:30:11AM +0300, Andy Shevchenko wrote:
> > On Wed, May 3, 2023 at 5:07=E2=80=AFAM Kent Overstreet
> > <kent.overstreet@linux.dev> wrote:
> > > On Tue, May 02, 2023 at 06:19:27PM +0300, Andy Shevchenko wrote:
> > > > On Tue, May 2, 2023 at 9:22=E2=80=AFAM Kent Overstreet
> > > > <kent.overstreet@linux.dev> wrote:
> > > > > On Tue, May 02, 2023 at 08:33:57AM +0300, Andy Shevchenko wrote:
> > > > > > Actually instead of producing zillions of variants, do a %p ext=
ension
> > > > > > to the printf() and that's it. We have, for example, %pt with T=
 and
> > > > > > with space to follow users that want one or the other variant. =
Same
> > > > > > can be done with string_get_size().
> > > > >
> > > > > God no.
> > > >
> > > > Any elaboration what's wrong with that?
> > >
> > > I'm really not a fan of %p extensions in general (they are what peopl=
e
> > > reach for because we can't standardize on a common string output API)=
,
> >
> > The whole story behind, for example, %pt is to _standardize_ the
> > output of the same stanza in the kernel.
>
> Wtf does this have to do with the rest of the discussion? The %p thing
> seems like a total non sequitar and a distraction.
>
> I'm not getting involved with that. All I'm interested in is fixing the
> memory allocation profiling output to make it more usable.
>
> > > but when we'd be passing it bare integers the lack of type safety wou=
ld
> > > be a particularly big footgun.
> >
> > There is no difference to any other place in the kernel where we can
> > shoot into our foot.
>
> Yeah, no, absolutely not. Passing different size integers to
> string_get_size() is fine; passing pointers to different size integers
> to a %p extension will explode and the compiler won't be able to warn.

This is another topic. Yes, there is a discussion to have a compiler
plugin to check this.

> > > > God no for zillion APIs for almost the same. Today you want space,
> > > > tomorrow some other (special) delimiter.
> > >
> > > No, I just want to delete the space and output numbers the same way
> > > everyone else does. And if we are stuck with two string_get_size()
> > > functions, %p extensions in no way improve the situation.
> >
> > I think it's exactly for the opposite, i.e. standardize that output
> > once and for all.
>
> So, are you dropping your NACK then, so we can standardize the kernel on
> the way everything else does it?

No, you are breaking existing users. The NAK stays.
The whole discussion after that is to make the way on how users can
utilize your format and existing format without multiplying APIs.


--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHp75Vd_VMOh1zxJvr0KqhxYBXAU1X%2BAx7YA1sJ0G_abEpn-Dg%40mail.gmai=
l.com.
