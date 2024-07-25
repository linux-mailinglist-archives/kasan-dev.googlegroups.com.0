Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB6G5RC2QMGQEJR23JTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 75E0693C076
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 12:54:50 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-427ffa0c9c7sf8391365e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 03:54:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721904890; cv=pass;
        d=google.com; s=arc-20160816;
        b=SLDwC4xlbhsyRLwNWDbgAtmBcBXgu0RyaxOCskGTpuNLmOvxdAhiZmij5R0O2ZaGI6
         2lrJt2973z9lzpQf7Tey9nD8sO9DZo5yf6CJkRamZmoamox+/eeAuOI6UwyDq39FgWHN
         yivkFpZ88e5o/zCNwJgRHR1UDr+hPyUfepJ/ZW6mHyIdYbakuvivG/pFQxFm5MkTa5I4
         Wwkn7NkMAhrj4cjDqCZJHe/V8ppQPS9+tExDd5m+nsJSz3Lc2Wn87zTt4qaYoekoEl5k
         NK/tMZv5luwjr6Lc9k4HBQBDYFscCEvj2MdVbdd1lSN85nSviForpMBYAcyNZhW323nm
         pNng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CHDWFVWVGQkR/LE5yHiiiNd8G1WaNOINKdVgyJNV5Tc=;
        fh=gwvFIc3UYL48MtDCmAJiErxK1+mzXJf0QSStL3eaggQ=;
        b=fNypmYy7eQ4z4N4FgrD88gidfR3pd+KtwK8y4ze7NYHbYjFa754p5KNEBw6NhK/6g3
         m2iPqr9PhIr+GSD+ekAPfPUBlFzhuTA5C1BALSieW1h4P+ys3ASq/R/YNb94dEUVSZWG
         u11t1sk9vFLf2M0VaF/dnfqjzZYkuJB9W5w0Cz7DukOgodywkK+aZm5/IBE5anOzJOCs
         axtekSfMdd1PLxxnSmWf96Py2p5fM+KAdzWSIdhu6oPhmocGF/rRHCjnvdDeUpVGnzar
         SNfo8RSOuY0Rbats/f3l981abI6fVfTWXj39W2zjxEQ68HCg+7fz07Nc0TvQcA5OciIh
         LaGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tnO29sIg;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721904890; x=1722509690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CHDWFVWVGQkR/LE5yHiiiNd8G1WaNOINKdVgyJNV5Tc=;
        b=p7A/miOrjbVvMD4OyCCczjCU4e38b+TJdxcmfVBLpHnQ6kHtza8Y/LlTd/oqyP1kzw
         +bXoOBlu+8d+bQk5/X3BrmJAAt113KTGoHVsETtxDz7EtvOwpQ6ssLWY+lEWaKGMu109
         2o5o2PaBdmb3xPRkiaVABHNmaT4ySjnU4p8bUOqG7ie0ZHVgMJxzI/1baKmFAIuyCUjz
         sAW/aDjBzOpY+NKcAXkITGnVZUaZnruRC1/SgnW4wpvwczVzttt3XPn7fSiEQsC9ajJH
         91FnvK9U4u7p8pvepVkYXwv23n6DdJ2h2cQmBkorNAxykVqOyI9XRssV/+4+ag0vMici
         +wCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721904890; x=1722509690;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CHDWFVWVGQkR/LE5yHiiiNd8G1WaNOINKdVgyJNV5Tc=;
        b=ciRfBnJmDhdd1tydNU8xFPKXZ/j/h9CPCEpDb6MKzsT4xxWVqAOrXUexnBpasngm/T
         AiEcEEbOdsMi9DjPZy4JRVhBcyVDaJsWFVZjNARQGCFSj+fyxBByVGTR3ffhy0+CiQRr
         zEX9HBgPUNhyFuQ/O13/BYsdjH2Dn5Lb3ohZo+pZgtkpM7opl0jJcRmXrwtf6IVG+u0A
         U2PhnpET1n5qtvk1sUPgwF7iw2FC1jp0fNw9Rfrg4c5WpswloCIk7TRLoc7WUYAQqpxL
         g1f5vre+5x6JeV2CZAq8KF7Be2aE4YrD/gtXrNSkor1R0gR6qZwWfMN5/Fl0BrrEQOyf
         H+IA==
X-Forwarded-Encrypted: i=2; AJvYcCWsJqH934NH5RLjXT4uLlWiNqfdVIfJGWNcV+Vhkd+yjd7Du4uD3/IQr5cOJoVc9prYDSNLaIr+AlhIagiAIE15tSy6AlaOxw==
X-Gm-Message-State: AOJu0YwdRnIIVXiFIxqGgacpHLiE0VjYwIdIwlKODsABLiKrbcSrPdLI
	sYrJ4AE4kRjY8XpmLJXDg/1gl9/JGaanTZNEK91r2+leDtBW0L7S
X-Google-Smtp-Source: AGHT+IFZuJr8bMJGNWnFandO+1gb8dT4sjDZSysQz9xczkoaWs2APTBIdJdvU4U15slvzGgVV1hhlQ==
X-Received: by 2002:a05:600c:b47:b0:426:5b44:2be7 with SMTP id 5b1f17b1804b1-42806b86519mr16499085e9.10.1721904888645;
        Thu, 25 Jul 2024 03:54:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b8c:b0:426:7318:c5a0 with SMTP id
 5b1f17b1804b1-42803b872e7ls5025145e9.2.-pod-prod-05-eu; Thu, 25 Jul 2024
 03:54:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUytT7ebAN6tTond5gfJxaImqPTcvk0OkFP9mVLm4WMZW++2Zn7/1zSuVzxARu1SoCmuHiaF2w/2JPn7vFUDSLEWnJkR3/q8UCX6Q==
X-Received: by 2002:a05:6000:b83:b0:368:3ef7:3929 with SMTP id ffacd0b85a97d-36b363c61d5mr1463736f8f.22.1721904886770;
        Thu, 25 Jul 2024 03:54:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721904886; cv=none;
        d=google.com; s=arc-20160816;
        b=xaZyLG97lCAg4tNUSGRxG+5tUERmWIpwUD/PvJBWfL4PRwr/+KfdQROHwBiVdTKLj9
         zvnCDy07Ey8BSKwGtSsr7XO+dhe2cDnUz4LN2cfLnj0CFAVwENqu8W1a7BpJMDmDqp+l
         VdbkAX3QF5Lihx2PtWfPgj9kayJoi3xO57Hzag9au9yF0agq18xsROr6Fn9h+2/vW5oL
         HwQCzMx+hhKtuibsXInvjfrN1MIebMcChk5fBXgCXTPf5jT/5HTYe354RcIc4LtshDpK
         Z5vouvki0CrbsvUWLBrRIPrmBrkyTjvhKMsMfnn9F/lpmka7leeQslqf7DUvtqt/BVn+
         i5Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=iA+Dy2gymI5rMbPMbetsdAXWUSOVO1pHxP5QyvQLaJ4=;
        fh=zPLmYW4Ot8A3Bt9+C/4YgP/eamD7hF4P3spiLKFORj0=;
        b=Dp2JIKYJVEAu4PEjB/wFVue0ysJ1ywTuNLdcuO5dRUhY58vepa7OtCfSP4h1GzF2Tw
         AM7YtQYrrkOs3yhuLsvd+IOL8ivGT5QsVrT2o86/fNLVq1FtFVE2ZkPVGdsGRzETZRUf
         6TzHT4jXdC16OL7YF09uwoHSp5+2NjnNXzfHCmwO0LNn6p1J8DBCs2TKnRtXdooUjVwx
         cCK0iiRB3X5b1JnVJ+CW1TPMU0a89BBwAxjpV5yWk4+JT9MU214kLLjvVXfH5YdxIO93
         DBfelsOflcvUc6qn3Gm458KbkLLqfePUClXQ8Mg5Ztg3nSmJawNnOTZNvmABAVpTGqBn
         xSaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tnO29sIg;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36b36800e14si23580f8f.3.2024.07.25.03.54.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jul 2024 03:54:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id 4fb4d7f45d1cf-5a1b073d7cdso14625a12.0
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2024 03:54:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUR43ZJsW6FFyezGH+yv6JxzhEGzpfFS+AagQI8cLwG+7UVGAvNmYWDGsgNOQVxUUxmSo88BrMCwBkF9kyItHXsPsmPx0HksGuVPQ==
X-Received: by 2002:a05:6402:5250:b0:59f:9f59:9b07 with SMTP id
 4fb4d7f45d1cf-5ac2c3b3edemr213993a12.4.1721904885552; Thu, 25 Jul 2024
 03:54:45 -0700 (PDT)
MIME-Version: 1.0
References: <20240724-kasan-tsbrcu-v2-0-45f898064468@google.com>
 <20240724-kasan-tsbrcu-v2-1-45f898064468@google.com> <20240724141709.8350097a90d88f7d6d14c363@linux-foundation.org>
In-Reply-To: <20240724141709.8350097a90d88f7d6d14c363@linux-foundation.org>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Jul 2024 12:54:09 +0200
Message-ID: <CAG48ez1d-iiWmt55-1+H4z=Didw=NaKZ0-f+RP7tSRwRNsiSyQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] kasan: catch invalid free before SLUB
 reinitializes the object
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=tnO29sIg;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Jul 24, 2024 at 11:17=E2=80=AFPM Andrew Morton
<akpm@linux-foundation.org> wrote:
> On Wed, 24 Jul 2024 18:34:12 +0200 Jann Horn <jannh@google.com> wrote:
>
> > Currently, when KASAN is combined with init-on-free behavior, the
> > initialization happens before KASAN's "invalid free" checks.
> >
> > More importantly, a subsequent commit will want to use the object metad=
ata
> > region to store an rcu_head, and we should let KASAN check that the obj=
ect
> > pointer is valid before that. (Otherwise that change will make the exis=
ting
> > testcase kmem_cache_invalid_free fail.)
> >
> > So add a new KASAN hook that allows KASAN to pre-validate a
> > kmem_cache_free() operation before SLUB actually starts modifying the
> > object or its metadata.
>
> I added this, to fix the CONFIG_KASAN=3Dn build

Whoops, thanks for fixing that up.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez1d-iiWmt55-1%2BH4z%3DDidw%3DNaKZ0-f%2BRP7tSRwRNsiSyQ%40mai=
l.gmail.com.
