Return-Path: <kasan-dev+bncBCT4VV5O2QKBBONTYCRAMGQEELRU2QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 57F476F38C6
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 21:57:46 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-763a89d850asf163404439f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 12:57:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682971065; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tj/wgWHhSFP1x0+52S9ntu6Ch3kdWcyFKnVUCpSZhDFBvbcJE5ICyahgXqvwqI8KZ5
         LMGYZQmEm2n0XQxgORV7q/yz/e2jtpUEvrY01LSrg40GvTIxQa3rSJC35cJgVRjXZ0XT
         ohoJBggn4YEFOclD/m8s/8lRbvqDrszvcf4t1vFJKpzkEITFcboTIicavt0wW64F9RkE
         GUGaorZ63UGKgKpV7I3KrCd85Rn7NG3gUE2zfOKHc6i03pSYUYD7Wm3cEsX+2dLNRvCa
         YvJ+elgHdw3u/KvihvQ98bcE97G8stfPwJzqDzTmZPDTQ1ZTmzhszjuMxRYIwOaA/1dw
         IC9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=B6U4y3Si9u7yflqgn4rz5f+IKtOBJJqpvrqSt5MBNDI=;
        b=Iu3XsdbqpRei3uFflU6iWe+UkTsJVB4lM8SPxSBzowXwqX/oXmU3C+OLwuyZB9lLNO
         sqH2omF3lRjw2YnYOkBXaqYrmWsucmzq7UZGxZae26qpaFpeTE3ijYWnOBs8sim9G/eN
         ABIASv5FY0mfF+9LtJlyuB3kRBozUQSn0XOdn3AW1LyUKDXOEPklkE2nkTbdnAdsvQ8k
         r3sHrtCZ7n5nzTL4FfW2g5gm2VaKReAJmP8CxqdnwnklbotKf3yyr6mYaoYp8X2D2Aah
         iWxeSQ01g48UGANPykiRRt9Zb3jOBY+sFkbiWpGckkzP638DPZF8khayOIfc06he0qdn
         p3rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=H8s0D2Pn;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682971065; x=1685563065;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=B6U4y3Si9u7yflqgn4rz5f+IKtOBJJqpvrqSt5MBNDI=;
        b=OhZlADO6IAV97Ni4x5EixRFkyMji6+aGDYegQudnog36Qm8rGsuIj+VLc1hfgb4lLl
         9So+blIBBy0IoWhTaqamLRit2uE2DYcFuLbridmcbtA4kW9RqyoIygisvZ3bpCoJiqpG
         3JtOuzJ4va8d3fQBA1q+3zxo0eWYlfB09RdMRUfo7X5JGLjY+3WbibFiNFcaLvMfQq8G
         1z2OCFc0b/g37CuONUMdj/jnaqvCKTXcMhZsQEJXsMncfIs6LcbGGI9OebRsnsWf3ZFf
         A0Y23v048XH9lYAUqo9hl/VafA4u9xShts7UJALTSTrgE7f9Gc/YUsqpntw53JMJ38oo
         w+Ng==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1682971065; x=1685563065;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=B6U4y3Si9u7yflqgn4rz5f+IKtOBJJqpvrqSt5MBNDI=;
        b=lNzavYqY4+zqMSuS9wfHiXm4BHyKMvlOdzC4hmwf6yeVZ+jQWRiYJJt9eCmM63NnnZ
         0SeQLZghU1Me9Admx1eADmvUdG3NVAFHbpVA6h7c/JnFRUseBbMuZWGx9M9XEZok9bkr
         iVlCevh0/73e9qfW2YNpJmo/h0GEmUvaS18inNfigpXNqMe65I9zJTn3M97DJUw9A/Lo
         rM5zDDSFsFI6d5ZAlr5bI+/KdIz3o1vE5M32hYTVY/UzYdY6dtIggWlAPEy3UiiaPRFG
         Ux6WIf9XiMGnC0sbT4z/EyWDRt1JUSfurvMvJJDzK2HANk/cepDgH1HZN2Vl309GlSpq
         Svgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682971065; x=1685563065;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=B6U4y3Si9u7yflqgn4rz5f+IKtOBJJqpvrqSt5MBNDI=;
        b=dYq5HaBOF/KHer7fsXb9NeC0DZUB5LNz2rXk4ZeIw3331/kHC2+lJIE3n/2fzFFo8U
         1llXBUtpidk863B42afX4GpuPyAmr11HcNzMKxYiqG6zW1nV3A/pvIO04McN3mFNQd3J
         mMIWQhaph56UHS+1fl1nx4FKvN76v8/b2qA1yAschU3GD0mp4m/JcuVBKvBQn9X3yH/R
         x2GMY6WUX27k5aPArqx42ee73TTAseEP1W8cWgD6/GlG76CW+0wvE2N6Dcp7YwBs+o9s
         xoSz2n4HFhu6g9CHdwMZ4KKrrMC1Sa/hqifId0CMhZoz4G+wynB1khK7Zx0Hp9UChYyc
         G3jA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwGwS/BXCDrMp/YisTtj7BL+Ae0DbKvrcdSan/HLRojki3h4zy8
	2rsAMzdUgqzOTY17McrMUq8=
X-Google-Smtp-Source: ACHHUZ40aPuTkxCsuGOt4B0zs4LmcHAY8fRyHRcppkksDarTJT1Qu225CEaydx6FkMP8GS2wFNb4Jw==
X-Received: by 2002:a92:d143:0:b0:330:a575:37e2 with SMTP id t3-20020a92d143000000b00330a57537e2mr3051810ilg.4.1682971065218;
        Mon, 01 May 2023 12:57:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1b86:b0:317:979d:93b3 with SMTP id
 h6-20020a056e021b8600b00317979d93b3ls3530234ili.9.-pod-prod-gmail; Mon, 01
 May 2023 12:57:44 -0700 (PDT)
X-Received: by 2002:a05:6e02:78e:b0:328:af6b:d030 with SMTP id q14-20020a056e02078e00b00328af6bd030mr10324809ils.19.1682971064612;
        Mon, 01 May 2023 12:57:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682971064; cv=none;
        d=google.com; s=arc-20160816;
        b=LkBdK4GQ6a2Wgr6iOO3pc3iS0fung5yTE6xTelSeHfJjNPeIJCoJQkMTZzm8qtous0
         eYzSIU7++LEwThmE83KLi8n/jLgOV3Xeph8c+RKRgjh++Kp+UyYLTlPE4UpK1x6f7bkS
         WG77cAuGAT3GLYIC1+7fxFNtTjxwzIFkF1Uk8VW8LVrFevNbt2L9jluNLbHIqwIDJQno
         uJx0Km4wUmymqniOY1em9u6EHS0an4kAbZFNOxjogswSJaKmo+DN0dCBj1pL8oHPP7pq
         PBLyagdniAaeFp3KGgaS2zxWt0wAqDfKMK7w7tvcoHN9lf/+q1VAVyZoRLkfn7xotVV8
         t4hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9KWtLWCFndJNZE972x4UIl3VMb5lgPnWy05QC+e9YHQ=;
        b=I4CBw26806Cmp9fb0hfI5xMVZSL88o/ujZLsNHj345P26jr4EbAauZ/E0WUag3hdTf
         oCXc5TUyo386d5ZaJ6DSnniBfrbr5HDqtZ7xI0PHC+azxOBC7PoI3ODqxZ17rJ3bBpec
         OrH7l2G/u89EgNamrIRYMk4ia5ZYjiAjMLa2EDj0JvzBZZmrDQ5I/Zf0HMmCzkbFkFjz
         ZWgVQRi/iUBpx7dRwcswYBsOECM/TrZ1lg5gWCWdrsoS0O+bg5GpDoeb5i8l7JKgLnoe
         OPzsLff2BZEluh7HCPihz9whfeBcvHKS3SOkgxbHEobjwi0wB88ykyc8Fc072L+aPTGt
         vDnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=H8s0D2Pn;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id y15-20020a056e02174f00b003296112f42asi1833750ill.0.2023.05.01.12.57.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 12:57:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id af79cd13be357-74e4f839ae4so130477585a.0
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 12:57:44 -0700 (PDT)
X-Received: by 2002:a05:6214:4008:b0:5ea:654e:4d3f with SMTP id
 kd8-20020a056214400800b005ea654e4d3fmr1607440qvb.5.1682971064004; Mon, 01 May
 2023 12:57:44 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti> <ZFAUj+Q+hP7cWs4w@moria.home.lan>
In-Reply-To: <ZFAUj+Q+hP7cWs4w@moria.home.lan>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Mon, 1 May 2023 22:57:07 +0300
Message-ID: <CAHp75VeJ_a6j3uweLN5-woSQUtN5u36c2gkoiXhnJa1HXJdoyQ@mail.gmail.com>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in string_get_size's output
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, mhocko@suse.com, 
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
 header.i=@gmail.com header.s=20221208 header.b=H8s0D2Pn;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
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

On Mon, May 1, 2023 at 10:36=E2=80=AFPM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Mon, May 01, 2023 at 11:13:15AM -0700, Davidlohr Bueso wrote:
> > On Mon, 01 May 2023, Suren Baghdasaryan wrote:
> >
> > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > >
> > > Previously, string_get_size() outputted a space between the number an=
d
> > > the units, i.e.
> > >  9.88 MiB
> > >
> > > This changes it to
> > >  9.88MiB
> > >
> > > which allows it to be parsed correctly by the 'sort -h' command.

But why do we need that? What's the use case?

> > Wouldn't this break users that already parse it the current way?
>
> It's not impossible - but it's not used in very many places and we
> wouldn't be printing in human-readable units if it was meant to be
> parsed - it's mainly used for debug output currently.
>
> If someone raises a specific objection we'll do something different,
> otherwise I think standardizing on what userspace tooling already parses
> is a good idea.

Yes, I NAK this on the basis of
https://english.stackexchange.com/a/2911/153144


--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHp75VeJ_a6j3uweLN5-woSQUtN5u36c2gkoiXhnJa1HXJdoyQ%40mail.gmail.=
com.
