Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK7XXKAAMGQERH3YEAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id E13A6302506
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 13:38:04 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id m15sf5383671oig.9
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 04:38:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611578284; cv=pass;
        d=google.com; s=arc-20160816;
        b=MpgS7Jm2LhYszUI5XvcvdWHzXx8Je/EPzIWnwZm5GCD24W3uccTZiNC3vLn5w37AAE
         jXF0eG1zmAY0iQKAO8EMfhwfz0d9KjU2Etcr2gurVfazM7UeA04COJo+XvcF+B7pF8af
         uKy8QyFzM1XImLtBwCcaExB4ZSpSC7UDn5aiUpaijP+ediBrQom/JbeQ5nXlbmdAis6L
         BIG0EpYdVPTzjm9aG/lYyQdeJXNn+ORSUzQYZprWl2C4Ob0lJK5Dtiw5o0bbkT0fc70n
         JbDWgxY1PBY+4BJz8arlpjIPBh59sTOTkhg4a4/jgTBHuCpkmvek0dN3kWe7SV3ZONmu
         e6qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=dpPKY3p3IueRdnXR/YJCYIjEJopuIC3O7abVamfS710=;
        b=sZe0P6RmW7M2NLO/pBYiAcSJk6X2tsDYQ0vEdSmgFz7Z74MEiyjxD85bFtNmjWmLhZ
         UgS903rmn61q+NeHnkcRVrE9oaXJ4Z4kUsVxZJ9pBcNRGz9RFmfAf8w/TbEFfTNLh+MZ
         pyuUL0s6VpDyMRc9x1gzrCUMGKXw0iRaatj6jBln7LLtpIN9Rb1HdS9JY3xpaLiX8tB4
         e7soORSQYjuzElxAO9rBYPy34gY3K+KGq1srxjz+14Bduc6iIWpYSAK4RrQpNJDy5XRB
         Z1+ge9tIdOxZh2k6+I0eEQgP1Oi4ar/kMDTJjBnaM3lbVHd2Encyhe5uEvO+A9J6+DNx
         Ao7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fhdQt9QE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=dpPKY3p3IueRdnXR/YJCYIjEJopuIC3O7abVamfS710=;
        b=cU4z6MnxswUtgQ1MqVnIzpxWl6GU6sl4h4oITCKyqCqkc1ry5GV+4FikTQHNOOXmof
         uZvYa1BdZeMaAOZONSMiA0of027JU2vh2HPO0svK8a6TAcI+RKnOc6ryU0d2/LqEwkGK
         QrzgArC3G3rCcUzjndN7I8Fl/nRC0K4vzibre0cPSlo6AQn80ugcGV76fdtj9y4437hH
         ll+k/G029zsdAcY5AZfyQ5wCziNAJYcCYeo+F+KgwE+fI3q7yrinAnIMVLpDHfZSn1do
         7YGSKaE95p1zcWfKdb1t+xGDfXr7sAAe95czQJbBk2KBFaxhMX5Ra3Iw2WBEaVRpslbb
         RUUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dpPKY3p3IueRdnXR/YJCYIjEJopuIC3O7abVamfS710=;
        b=RaIOtQEM/rNSVfTg9BS5qQjfXngjlUw+t6XSmXX0iUvRmB9WOhJKS+3ByCWjGGQg+L
         ofmJJaF/S/vzQpRFua5Zy24FGI1L5B+5+RoFK3DDAC3vbry312fccs3m6Fa54VxsLY/K
         Ixoh21lFpCi1rUtx9TKra/lQgGoTdbzEjuyO33cmtgysMv0PPe69OyAea6ugAlmLju5q
         9aveDPLp2tbXU/WGVdknnKDtJXQ3EMa724Cr3wGKzIt0V0VfyWpdUK/i/IGjprDq5V34
         0sXI2sN3xkGxxyxmizmyvZq/W/umZZxT5aFmU41/kBRKvilI9XQm83rFjdD3tPJ27vDX
         dd1A==
X-Gm-Message-State: AOAM53155pWv+grQZ83XURK3TyiY6k1Xu+ILaoJk0PCS1lbAsdsVK/WV
	dIhZCUShp4xqeIPlo4pDUYM=
X-Google-Smtp-Source: ABdhPJwp7fntcERKXE/8X6GmmNrtv+s2Ih9midJTxrkfOt5obwJ00DlE3STnbQ02EHwY+nMSy2yoFg==
X-Received: by 2002:aca:b5d6:: with SMTP id e205mr356993oif.15.1611578283882;
        Mon, 25 Jan 2021 04:38:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b489:: with SMTP id d131ls1966849oif.10.gmail; Mon, 25
 Jan 2021 04:38:03 -0800 (PST)
X-Received: by 2002:aca:ad12:: with SMTP id w18mr375272oie.80.1611578282969;
        Mon, 25 Jan 2021 04:38:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611578282; cv=none;
        d=google.com; s=arc-20160816;
        b=slJjlC/4aeA4i/B3euFaJlNnDtmDMrGbCCks4xsqr6l9LmUfi/852m//KEMS7tIMml
         kpMuJ409W4xEldm0tU6oxbsHmPrNQ/MUeQR5kmtpAFztgxviq6YpS1PHTz3UYaZPunHo
         s/igmaN6vwCIdEB7cecRCFcjaJQqNNeBcYiGyXhqQ1mN5U+DrsmL2udX3dewppQ/F7Mg
         rRj+Vp8RuicUpObc1UZsHKuM1Zth9uZadA7cw5aqJSsVxVPX4q4t2ibkajTOyrzMMWf9
         Q18J0c8QQjGujAcEhK2sSrEJnEqBQeJ9heln96b2xebKHPhU8TArC2mOgwgVhXAfemPJ
         LXTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vHKt0v45gq57gUZMBiQDVWBDmURZODRH6SULWwFGx00=;
        b=noPAxehnjJ/2hq7R2Zkek3HFyUrfGezfywyZdSSZmPFAoxCQrxeNwdJGCamH2tSmvS
         kU1zwdcE8JzshHqHLpuX5nLbccyt6b7hmD/ZCfuD247PwKJWT8ATSrJm2KGCY71ZxVHd
         Xt6L5ndG5Qy7fFRX6K6K5qR0fw01zPm1VT/PYu4MsHotqBBuwZxKRrRQo9LdXsxr4ZKJ
         yyL08rCY133n7ztoGuA2KSaKMZDyPPFp2AyxqlgZ+rdV184KlFDXg9V/GHEtnQv/S/5a
         AK0bNiHvnkTdlyW0VrByVPjreXHQkInQnV1ymh9JG3FLswlGILbif/VeDZchXV92wj/z
         6O1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fhdQt9QE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id b124si1008531oii.4.2021.01.25.04.38.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Jan 2021 04:38:02 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id r189so14576296oih.4
        for <kasan-dev@googlegroups.com>; Mon, 25 Jan 2021 04:38:02 -0800 (PST)
X-Received: by 2002:aca:cf50:: with SMTP id f77mr361028oig.172.1611578282607;
 Mon, 25 Jan 2021 04:38:02 -0800 (PST)
MIME-Version: 1.0
References: <CADYN=9L7q8hZKsfmj2m2k2HoPSTqm=Y1SjG654e-uK1gutg4fw@mail.gmail.com>
In-Reply-To: <CADYN=9L7q8hZKsfmj2m2k2HoPSTqm=Y1SjG654e-uK1gutg4fw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 25 Jan 2021 13:37:51 +0100
Message-ID: <CANpmjNMzwa8kEY0GRP1MwYZJsLA8wL031W1cO4CvxQL4Ltvrkg@mail.gmail.com>
Subject: Re: kfence: implicit declaration of function
To: Anders Roxell <anders.roxell@linaro.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fhdQt9QE;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

[+Cc kasan-dev, akpm]

On Mon, 25 Jan 2021 at 11:19, Anders Roxell <anders.roxell@linaro.org> wrot=
e:
> Hi Marco,
>
> I hope you had a good weekend.
>
> Sorry for the direct email.
>
> I can see this error showing up again [1] on todays next-20210125:
>
> n file included from mm/kfence/report.c:13:
> arch/arm64/include/asm/kfence.h: In function =E2=80=98kfence_protect_page=
=E2=80=99:
> arch/arm64/include/asm/kfence.h:12:2: error: implicit declaration of
> function =E2=80=98set_memory_valid=E2=80=99 [-Werror=3Dimplicit-function-=
declaration]
>    12 |  set_memory_valid(addr, 1, !protect);
>       |  ^~~~~~~~~~~~~~~~
>
> Have you seen it to or do you know what happened?

Looks like "kfence: fix implicit function declaration" was dropped
from -next?  Andrew, do you know what happened? Is the fix still in
-mm?

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMzwa8kEY0GRP1MwYZJsLA8wL031W1cO4CvxQL4Ltvrkg%40mail.gmail.=
com.
