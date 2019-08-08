Return-Path: <kasan-dev+bncBC73DXES3YKRBPP6V7VAKGQE23JHNAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id A0EF686062
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2019 12:53:49 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id j22sf18625616ljb.16
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2019 03:53:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565261629; cv=pass;
        d=google.com; s=arc-20160816;
        b=CwrPPPGAdZnReyJmfuEWq+Mg6u9bPpzbi2wkfzYT9d7WqIrjoo8qvQ4l7MVmJsuEz8
         C292ch06bFzAI5BOhpla7g2gK19pwbPBDbzRiPuNOUf7cikwx0j5arHAa7HRk49vZ/8b
         Q7ZhploEfDuYgo7au4GGwef4Am6GrjaYp+8iZg0gc2LNGd+Kb2g7aO9ETltzum1XOaRY
         tCp3uIvEkcuKq2dfU8o5dSLF3SsRq60eELnHRIJICoxT7Z9KbgbIc9OKVOMH7Y4wwgV0
         iaYZYg0lmD2FSGZs62F52Qrh/Nj4HwZ8kkjeB49tILv/vq/ZSxpBWSUjABwfWy8OeUyq
         /C9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=JyjnWMHLGrqfT24DSxCcIb79poln7vbwfYLm1WoDgxU=;
        b=GAD5UmB9DhDy4O/iWxizftTA7aFaKhnnv94BcErGpr9z6ntyicdLjHOKuMIOz8sZmV
         8avJ9B+bz3XfoiGNeO4S34SFt6szNCHfq5S9926VHb6kOYoTphperxc5VDeeGq8EVSav
         ZTyVL6q6bE9pQMcfgzq7jvKNx67JWA34lddMEys+vTiENwYzlUZO3eCqokBVAJ/VOk+C
         ok5EF0hnPxsSDkXb/MoD2UPjqxDfwMWyLaepC/63wOSiNL1J9ZSi70hg5IYbWdBHTH59
         7UTZMGYZZZKeZsaKrU5rNujk8Id7xei+hore52KNj47cvpzuLTteI8/MOUD09rP/VIBq
         5LLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@fuzzit.dev header.s=google header.b=r9vZ4DTk;
       spf=pass (google.com: domain of yp@fuzzit.dev designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=yp@fuzzit.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JyjnWMHLGrqfT24DSxCcIb79poln7vbwfYLm1WoDgxU=;
        b=fsE4EfcuxSYjAPIcc4KZapc2TLLwDUd3OeA2MOuWadHSLLZ4hgy6tgmpi8HGhnb1fA
         8TpQRU1oZdt2FhpwV8zEo8Y2wOKyM5h+/Tffl6zMX+pzq22/J98FY3h77M5IcRuel+Vs
         qlNJWKeutk0y0oTzsOdq0aaTEfZvbXH02HwOxkgAKSEQ3fdS/e0YyWC1a1Hnkjf6upFc
         Uwlkb8H33+j4gqMpndpMe7Dn7AjeA60k8tdm9Tib0FcN5sMquDww/AT+8dtnPbmZl1ID
         lEGX3pXq6//g2EArL6u+r1VKGcx9QXPr9h3hNb5IGUuD9MN2ilEplLlaTWKtDUN6CNA4
         DZWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JyjnWMHLGrqfT24DSxCcIb79poln7vbwfYLm1WoDgxU=;
        b=jVxLIcn69X7W6bbgRjEEGo6bKJyPIvjgvZkGPQ/BSSc/lXleP7zQ5ynVnncD8hwgwE
         agGKZklW/frQw50ag4P+XurpJ8PCBvbRK9uJCe6x+x9bupD1kQiTBJK9OTcavEN0ebJ6
         3ldb8GYaonpdsbg0G5jSE68/3ABrQoLoNs6C7FKEd9zpDN/bYoFB5ZSAsLv4yjgp6oWD
         l8n2QT9/BGFwEBVVO21pDdQ4047uT5qvCpcwD9df8fwxem/UgEkrF5xlVGZdNjqmKmZZ
         KBeLxg6mMazRbKXTWnSFY2fZeCOO3DFGhyTE3QEmNoDLdzJrdbZill7NbIlc0Q3+LhrU
         e4kQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUidfO0XrEKZFlUyoxxSGxQAg0B5l/2ieiKa1sYcMh0zlyEu1Ln
	8a4tZr5cFbee0URbfD1c+ro=
X-Google-Smtp-Source: APXvYqx2ENdifg3eSOJFqNB9p4VyxKz6ZUlNa79WcJqA0OxvMIYpeit9iMMHJNSfKQn/DR7iGDq9xA==
X-Received: by 2002:a2e:9997:: with SMTP id w23mr7947610lji.45.1565261629240;
        Thu, 08 Aug 2019 03:53:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9714:: with SMTP id r20ls10619111lji.6.gmail; Thu, 08
 Aug 2019 03:53:48 -0700 (PDT)
X-Received: by 2002:a2e:9610:: with SMTP id v16mr7775559ljh.229.1565261628819;
        Thu, 08 Aug 2019 03:53:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565261628; cv=none;
        d=google.com; s=arc-20160816;
        b=t1Q+c1IQRSwHXHvzpjlGC4xqJsYFkXxOZq+kZW6/IQtq0g6jD1piwkmIZlhxqBxY7X
         IBzS3pADwpg8vDZDlLroF1v7Uojxc8C7SI4+FLTKKRPhzCfW/C+cbdkILsNDefBe+FXm
         5pxVnOmscOxlX84/clELIwch7EBvap82PlYD7HqLmH2a29QCOgvDYdW07hUEO8W1Q0iw
         UslfUUFpElhwUUxO7+R47egCjLJakB47E5O+iiFTu76l5UdUBVOg3WmsHBvxf6DngAaN
         47SdIiDNWj/tA1Q1uGF2KACez0Uq7FkH1Ot2Xme3ykfpo5hJ9NgZ+OCm8cffQKMmHcQu
         uiRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4Z3AZdjsKE/4xGVlVYMwMP2DzNqEQQEbbq/204rf2YU=;
        b=NAo95d1eTxrv7Fj/cPqgfvNRdb7Bn4e4Gn9P8z/q1ep4XiXuxlymFZWY+kxhfPvDDF
         ZovnqsBmgBH8Kb4QoZb5RK5nZi9OaMe9CqAa6D/xbijes3Zd72qQFddniHPEVeZH2kFE
         fbMHym2gh9fxHhT5gwehqMVGXOeWfHSGVnPAuVNBtryDnEyMTosvfdIcds8gkLxg4UP7
         oB1Zk/TmilIKPdqkV1vKKeYcEMwMdgQo/mVaZpusqEhnGAz9z7TRuTcSeNZWCLNTRl3F
         BtfsZTdxOEEpPkqfava/98zjSkanDZRBz+CsgG2LoW/oapzo/DPislqEyJKihePvvDr9
         ZKIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@fuzzit.dev header.s=google header.b=r9vZ4DTk;
       spf=pass (google.com: domain of yp@fuzzit.dev designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=yp@fuzzit.dev
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id m84si3870353lje.1.2019.08.08.03.53.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Aug 2019 03:53:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of yp@fuzzit.dev designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id b3so2056888wro.4
        for <kasan-dev@googlegroups.com>; Thu, 08 Aug 2019 03:53:48 -0700 (PDT)
X-Received: by 2002:a5d:460a:: with SMTP id t10mr15674392wrq.83.1565261628561;
 Thu, 08 Aug 2019 03:53:48 -0700 (PDT)
MIME-Version: 1.0
References: <CAMGGO8pWt=me-sYGfG5Szqx1b3doWRrbnamM_mc8SsMANBLg1w@mail.gmail.com>
 <CACT4Y+ZtkTqHcVSM=VaBF=GnrWZ_pKRoMSqz5xHyVWDcd=8LHA@mail.gmail.com>
In-Reply-To: <CACT4Y+ZtkTqHcVSM=VaBF=GnrWZ_pKRoMSqz5xHyVWDcd=8LHA@mail.gmail.com>
From: Yevgeny Pats <yp@fuzzit.dev>
Date: Thu, 8 Aug 2019 13:53:36 +0300
Message-ID: <CAMGGO8qBuo1y8Fy5_ZZZMmFB_Beye-pqOC88CUCxLfBu7eYj9w@mail.gmail.com>
Subject: Re: Kasan Syzkaller Comptability
To: Dmitry Vyukov <dvyukov@google.com>
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="00000000000059ed45058f98df35"
X-Original-Sender: yp@fuzzit.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fuzzit.dev header.s=google header.b=r9vZ4DTk;       spf=pass
 (google.com: domain of yp@fuzzit.dev designates 2a00:1450:4864:20::42e as
 permitted sender) smtp.mailfrom=yp@fuzzit.dev
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

--00000000000059ed45058f98df35
Content-Type: text/plain; charset="UTF-8"

Got it, will try. Thanks!

On Thu, Aug 8, 2019, 1:51 PM Dmitry Vyukov <dvyukov@google.com> wrote:

> On Thu, Aug 8, 2019 at 12:41 PM Yevgeny Pats <yp@fuzzit.dev> wrote:
> >
> > Hi Dmitry,
> >
> > I have a bit unrelated question. I was playing with Syzkaller on
> different old Android devices. I have a compilation problem related to
> Kasan that maybe you can direct me to the right solution:
> >
> > I'm compiling 4.14.85 kernel with KCOV/KASAN support, it seems the
> clangs I use are looking for symbols that do not exist in my kernel
> (__asan_alloca_poison, __asan_allocas_unpoison, __asan_set_shadow_00) yet
> they appear in later versions, so maybe my clang is too new, when I try to
> use an older one (3.6) it says it/gcc doesn't support CONFIG_GCC_PLUGINS so
> Im kinda stuck.
> >
> > Maybe you know which clang should I use or how do I tell my clang to use
> a newer gcc that will support CONFIG_GCC_PLUGINS? Or maybe I should
> recompile the clang from source?
> >
> > Much appreciated,
> > Yevgeny
>
> +syzkaller and kasan-dev mailing lists
>
> Hi Yevgeny,
>
> clang support for upstream kernel is very fresh, esp for x86. Only the
> most recent kernel versions can be compiled with clang on x86. Stick
> with gcc for older releases.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMGGO8qBuo1y8Fy5_ZZZMmFB_Beye-pqOC88CUCxLfBu7eYj9w%40mail.gmail.com.

--00000000000059ed45058f98df35
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto">Got it, will try. Thanks!</div><br><div class=3D"gmail_qu=
ote"><div dir=3D"ltr" class=3D"gmail_attr">On Thu, Aug 8, 2019, 1:51 PM Dmi=
try Vyukov &lt;<a href=3D"mailto:dvyukov@google.com">dvyukov@google.com</a>=
&gt; wrote:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0 0 =
0 .8ex;border-left:1px #ccc solid;padding-left:1ex">On Thu, Aug 8, 2019 at =
12:41 PM Yevgeny Pats &lt;<a href=3D"mailto:yp@fuzzit.dev" target=3D"_blank=
" rel=3D"noreferrer">yp@fuzzit.dev</a>&gt; wrote:<br>
&gt;<br>
&gt; Hi Dmitry,<br>
&gt;<br>
&gt; I have a bit unrelated question. I was playing with Syzkaller on diffe=
rent old Android devices. I have a compilation problem related to Kasan tha=
t maybe you can direct me to the right solution:<br>
&gt;<br>
&gt; I&#39;m compiling 4.14.85 kernel with KCOV/KASAN support, it seems the=
 clangs I use are looking for symbols that do not exist in my kernel (__asa=
n_alloca_poison, __asan_allocas_unpoison, __asan_set_shadow_00) yet they ap=
pear in later versions, so maybe my clang is too new, when I try to use an =
older one (3.6) it says it/gcc doesn&#39;t support CONFIG_GCC_PLUGINS so Im=
 kinda stuck.<br>
&gt;<br>
&gt; Maybe you know which clang should I use or how do I tell my clang to u=
se a newer gcc that will support CONFIG_GCC_PLUGINS? Or maybe I should reco=
mpile the clang from source?<br>
&gt;<br>
&gt; Much appreciated,<br>
&gt; Yevgeny<br>
<br>
+syzkaller and kasan-dev mailing lists<br>
<br>
Hi Yevgeny,<br>
<br>
clang support for upstream kernel is very fresh, esp for x86. Only the<br>
most recent kernel versions can be compiled with clang on x86. Stick<br>
with gcc for older releases.<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAMGGO8qBuo1y8Fy5_ZZZMmFB_Beye-pqOC88CUCxLfBu7eYj9w%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAMGGO8qBuo1y8Fy5_ZZZMmFB_Beye-pqOC88CUCxLfBu7eYj9w=
%40mail.gmail.com</a>.<br />

--00000000000059ed45058f98df35--
