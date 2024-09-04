Return-Path: <kasan-dev+bncBCH2XPOBSAERB7PA323AMGQEUXDZ45A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2188E96AD86
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 02:57:35 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e0b3d35ccfbsf9079578276.3
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2024 17:57:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725411454; cv=pass;
        d=google.com; s=arc-20240605;
        b=A4V7a/dWkEGxFl46uELBjascDGdIKpusZLFdtcu4rDdXfZX9+8Q/FnMbEEV01HBtO6
         Tv8Zh7U06g0txh/st+PBmIyQmX8jn12Z+K93lVN/wVZGvDomJhezo3cPAeID8lklHXfx
         f/ij7zVhhdvClFZvRA7hRir7aSxP1yptpBIvgMm/1DGtMBCuy8YyXaNcq1DAIEX6w+YF
         7m3q4GrK5QmbUE2p6pwyjPMyKNw7V8p3j0VFnPKFe0u66G1FoMNDZiFSsfWcri8mSNAx
         XO0S2FMocaWcXW+rzHcQ2S4N4fcTPQFoe3YdSS7IRwl8DytFej/pJDsv6nm/m1W8ma0g
         cIdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=DBUv4J9KK//CgWxv6sMgsGKKWn+sk5yGRhM+k4J+bAU=;
        fh=s2Jp70Jiot54AUg9FtwBfbWr8OQtNFBsxAVLMmDdZ68=;
        b=TNy0CJSU7LSd2muzJpweMbxveQ7yLV0+MzdjByD0NbGRA153tZ1/sEZuMpYtsVlUp2
         vfcXZCfQQVaZvqmDUsSNbija/XrqiUX8nv/5N4wmQTd1QV2Ps1R31Fzeq8CzwmQIOcXR
         PR2Jh1/lTIdNdavnw4GdYFN+ya2yh0Ty/vKtqY/M1+d/xQg/lCixaBUKXxYzbDk2EraG
         /PMC3eXEVzkoyEdEpxNXwxTS2KQ19Cd/DzyuJtAQ2FFBWKUVGE3m4CslJ4TlvT9ehW3x
         DIVu5S3TnmVfVlyqSxDQsiSXHrOIff3yfF3rZeJAPYJPNekLwN+FBBAp/NffwphPeKpy
         OUXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fq8W0l2s;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::c36 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725411454; x=1726016254; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DBUv4J9KK//CgWxv6sMgsGKKWn+sk5yGRhM+k4J+bAU=;
        b=WjsYNXHYcKuBn5Z2w9DRvjPtiK2kYG86ozlOVYKQw0lexOQGf4PMbsF0gizLBgE3kB
         6d5vHCQdCdtyUuexoPv+jYgtzcNyMRo/2M54ECL7YsXEpN6tpZZFqHHQFZq1F9Y49Nuo
         bf59JyRNOeCav60tALjToJzhyMes/XnLCxDalE5UPfr+2c2P5I/P0hP74EFvUTyiogCt
         xpeNxVWLfTgvZwMa3dQnl7Tf35mm+gaoljxb6ZhFtFB+iTfp2bsmvRqtjTNCttaz0O5Q
         eYTF9Rs3e+g1rXeODBh7t+UMK2rOW3/ACHmrstYYtPoMsssnNnknvVDCVoIp1uB+R53/
         +6GQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1725411454; x=1726016254; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DBUv4J9KK//CgWxv6sMgsGKKWn+sk5yGRhM+k4J+bAU=;
        b=F0bZyOOYx1Aa2xINFrt4dCOyb04+Pz6AQNZmJhRsQtb4pq+m9nUnl4pYoWpZ+koYEt
         R0XRPx5kxIPmeAu4FuwGuev5vXxS8iLTeGp5dZQ3q4vUCzn9VuEjqhpRwTIRfwiiJrny
         OHBr/95HAYrVsujxj8da18TyugmHIaTR0IgjmNV3aYFSYSZpe+4UidqEFgZ5cr3GPeYD
         QObvnKgKrSpTb2OZiDDijQltITd0MWVO84QTQdQy6WqFjc49FkBpa2MGtHduka5A2TQ4
         Y0pJW7mW4bKTCNX/LZOmhuO5a7OEPnshUzxiRQ2by9SdSJZS/qqRRHhKhcGvCwJLPtpl
         jMag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725411454; x=1726016254;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DBUv4J9KK//CgWxv6sMgsGKKWn+sk5yGRhM+k4J+bAU=;
        b=qGFj90DDuu1xvJQRoWWUXsGdRy1baS/mgddQVHEEiKQelSVFel+61AO8iLnezCV3id
         kwjNya78ojQz92u+3btY23nO4rr/jmCsaQZzLQJd9q93FxhyK+008Ov29JcHBlC7HUnC
         ht2OYxe3UsRqFzZ2zsbvoPGsdknfrsMJlVxsI60KpmN3GcxbNxagCWBgBOiE4MAQT6FK
         25XyeuLZiiReS5GkDFQdZd5iCaJW/rlH/JJOuOwy2PLnkOcdXMLJno2ASgIO2tU7frjn
         h3e+4fNMohnnyeeZInbZVVvtA8Gkgb2DS+6HHoJ40rID+xyN1cxlAYOshHfyRg0WaDlX
         erTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWyqAE1ZsPDhwt0fhcyxFmT3o/cE2pHg/3CEXwa58Ds3WqcfKmPa3COX4MsDO7f5AgCS5UqnA==@lfdr.de
X-Gm-Message-State: AOJu0YyAvZa1dZ0AAJDG4Lq3eSHsFGeerYNphQcb50YBpumjtNG7FJqS
	FFlHqcNxMErX5ocycxgFIrQ8zMPISv5Zrxz/DTAoa4Tfev7gANyA
X-Google-Smtp-Source: AGHT+IHPpq0w/c0vmvtZoZX+wbr41RYfXcnJcIzyRIzpcyQwmYiLNTp1P0Wljue3RIUcMAr2t/gzcA==
X-Received: by 2002:a05:6902:2584:b0:e1a:7872:8b6d with SMTP id 3f1490d57ef6-e1a7a018af6mr15943561276.20.1725411453577;
        Tue, 03 Sep 2024 17:57:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1c88:b0:6bd:735f:a702 with SMTP id
 6a1803df08f44-6c33df3a5f3ls71710556d6.0.-pod-prod-03-us; Tue, 03 Sep 2024
 17:57:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpY1/pm7j9LUpN8ZGHhVSgmDLXo/YqpymAo9g4FQKe24t/qZ+ON3X9c4ciRNKHLbT1C1SjrQ3O91Y=@googlegroups.com
X-Received: by 2002:a05:6102:dd1:b0:492:ab05:8d62 with SMTP id ada2fe7eead31-49a5b13a563mr18917890137.21.1725411452762;
        Tue, 03 Sep 2024 17:57:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725411452; cv=none;
        d=google.com; s=arc-20160816;
        b=noJGvLIfiittHt8VGvyjNjvQMQQ/CSt14sQtqRIDaGSxi47P1uo+sfm9WVXFOoPXGx
         Qi5vhfnX8Ym4gOh+CzWcd2QBkAhNKwcCHnQL5G4I8US6+FVh0h+EeqyK2TxqjoMp03H9
         y66vfWvzr8BfzMai3dDNJJQuqrsoBaaODELvaF2F6PPxvhWq5YLBO4b02mqxPqbgDWrT
         DtArssU9G7xzGiXHHqlWfhk8MNQI38WVAapfE2B0R25Ujh0F9vdozbGds1PeMWAo8OzO
         41Qhoh6nXf2GExF195QQeQJp67arsHlhKuS/BvyvGSJISFBZOAVAzkn31JROfTpWhtv5
         bo4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7gdWZihFLmXnMT6aCYKGEU34zWd8T6tn0I3DQDEBdks=;
        fh=g9hRdcfqEvEEaDW6denl9blEdrdU7IW0Z1bvueBgGC0=;
        b=I0zbsu1na/CRfWKbxoOqWij46eUu9FEPW1wD2cAbel9llHH0sLrkhkVD0IUOqTjvFf
         0Gdpd/xQpA2CiqeX9qhhW59fHlqxjdSdsFUDVCrg8RBGSCelxNvkOUqE0rqjL0THkD3R
         ZoYCMOd8Qmp7Hrhw0bIB6mF8pLBMxqTEm4DDTK3H2zLo2CdojVx1k0h0ZZbErYb0Jvno
         iLyapYmS58g5RobYGF9cVhLjhpEt7LTuvXszmBm9XvneBspx2xb0Erctmrtkb8DZvK+I
         iCmD0Z8tLDBvAns9QHUAXs6H6iPRlfPbosCMrc/60LOfWeNbTh9a4XgUuk1b11JAu50T
         xUKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fq8W0l2s;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::c36 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oo1-xc36.google.com (mail-oo1-xc36.google.com. [2607:f8b0:4864:20::c36])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-846bffd2686si389384241.2.2024.09.03.17.57.32
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2024 17:57:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::c36 as permitted sender) client-ip=2607:f8b0:4864:20::c36;
Received: by mail-oo1-xc36.google.com with SMTP id 006d021491bc7-5dcd8403656so4269493eaf.1;
        Tue, 03 Sep 2024 17:57:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCURGXyskw2FpMV6b3HY87f+BWMv9o07qaPVSu2eY2it/Rcfq9qkelUxCRU8Sy5muLytZxr0wISu1VND@googlegroups.com, AJvYcCVsxNsyhn722NFK8aG8cUn6uPTPRW2RtAUkHNWRP3wSwhvGnlfW74ivZjcdENGXlEEafqzHGNRxjAliU5b6b5IFy479IFph@googlegroups.com
X-Received: by 2002:a05:6871:8ab:b0:270:1f1e:e3ea with SMTP id
 586e51a60fabf-2779013e567mr23407349fac.28.1725411452015; Tue, 03 Sep 2024
 17:57:32 -0700 (PDT)
MIME-Version: 1.0
References: <20240725174632.23803-1-tttturtleruss@hust.edu.cn>
 <a6285062-4e36-431e-b902-48f4bee620e0@hust.edu.cn> <CANpmjNOiMFUM8KxV8Gj_LTSbC_qLYSh+34Ma8gC1LFCgjtPRsA@mail.gmail.com>
 <bd647428-f74d-4f89-acd2-0a96c7f0478a@hust.edu.cn> <CANpmjNMHsbr=1+obzwGHcHT86fqpdPXOs-VayPmB8f2t=AmBbA@mail.gmail.com>
 <241be3d1-2630-471f-9c04-3b4004b5d832@hust.edu.cn>
In-Reply-To: <241be3d1-2630-471f-9c04-3b4004b5d832@hust.edu.cn>
From: Dongliang Mu <mudongliangabcd@gmail.com>
Date: Wed, 4 Sep 2024 08:57:05 +0800
Message-ID: <CAD-N9QXVY8iKd6uMakpvfvRNSiKec+GtjJ9k3sic8GyqEMXe-w@mail.gmail.com>
Subject: Re: [PATCH] docs: update dev-tools/kcsan.rst url about KTSAN
To: Jonathan Corbet <corbet@lwn.net>
Cc: Marco Elver <elver@google.com>, Dongliang Mu <dzm91@hust.edu.cn>, 
	Dmitry Vyukov <dvyukov@google.com>, Haoyang Liu <tttturtleruss@hust.edu.cn>, 
	hust-os-kernel-patches@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mudongliangabcd@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fq8W0l2s;       spf=pass
 (google.com: domain of mudongliangabcd@gmail.com designates
 2607:f8b0:4864:20::c36 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Sep 4, 2024 at 2:05=E2=80=AFAM Haoyang Liu <tttturtleruss@hust.edu.=
cn> wrote:
>
>
> =E5=9C=A8 2024/9/4 2:01, Marco Elver =E5=86=99=E9=81=93:
> > On Tue, 3 Sept 2024 at 19:58, Haoyang Liu <tttturtleruss@hust.edu.cn> w=
rote:
> >>
> >> =E5=9C=A8 2024/7/26 16:38, Marco Elver =E5=86=99=E9=81=93:
> >>> On Fri, 26 Jul 2024 at 03:36, Dongliang Mu <dzm91@hust.edu.cn> wrote:
> >>>> On 2024/7/26 01:46, Haoyang Liu wrote:
> >>>>> The KTSAN doc has moved to
> >>>>> https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md.
> >>>>> Update the url in kcsan.rst accordingly.
> >>>>>
> >>>>> Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
> >>>> Although the old link is still accessible, I agree to use the newer =
one.
> >>>>
> >>>> If this patch is merged, you need to change your Chinese version to
> >>>> catch up.
> >>>>
> >>>> Reviewed-by: Dongliang Mu <dzm91@hust.edu.cn>
> >>>>
> >>>>> ---
> >>>>>     Documentation/dev-tools/kcsan.rst | 3 ++-
> >>>>>     1 file changed, 2 insertions(+), 1 deletion(-)
> >>>>>
> >>>>> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-=
tools/kcsan.rst
> >>>>> index 02143f060b22..d81c42d1063e 100644
> >>>>> --- a/Documentation/dev-tools/kcsan.rst
> >>>>> +++ b/Documentation/dev-tools/kcsan.rst
> >>>>> @@ -361,7 +361,8 @@ Alternatives Considered
> >>>>>     -----------------------
> >>>>>
> >>>>>     An alternative data race detection approach for the kernel can =
be found in the
> >>>>> -`Kernel Thread Sanitizer (KTSAN) <https://github.com/google/ktsan/=
wiki>`_.
> >>>>> +`Kernel Thread Sanitizer (KTSAN)
> >>>>> +<https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md>=
`_.
> >>>>>     KTSAN is a happens-before data race detector, which explicitly =
establishes the
> >>>>>     happens-before order between memory operations, which can then =
be used to
> >>>>>     determine data races as defined in `Data Races`_.
> >>> Acked-by: Marco Elver <elver@google.com>
> >>>
> >>> Do you have a tree to take your other patch ("docs/zh_CN: Add
> >>> dev-tools/kcsan Chinese translation") through? If so, I would suggest
> >>> that you ask that maintainer to take both patches, this and the
> >>> Chinese translation patch. (Otherwise, I will queue this patch to be
> >>> remembered but it'll be a while until it reaches mainline.)
> >> Hi, Marco.
> >>
> >>
> >> The patch "docs/zh_CN: Add dev-tools/kcsan Chinese translation" has be=
en
> >> applied, but they didn't take this one. How about you take it into you=
r
> >> tree?
> > I don't have a tree.
> >
> > Since this is purely documentation changes, could Jon take it into the
> > Documentation tree?
> > Otherwise we have to ask Paul to take it into -rcu.
> >
> > Thanks,
> > -- Marco
>
> Ok, I will send this patch to Jon and see if he can take it.

Hi Jon,

Could you please take this patch to lwn tree maintained by you?

P.S., it seems Jon is in the cc list previously.

>
>
> Thanks,
>
> Haoyang
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAD-N9QXVY8iKd6uMakpvfvRNSiKec%2BGtjJ9k3sic8GyqEMXe-w%40mail.gmai=
l.com.
