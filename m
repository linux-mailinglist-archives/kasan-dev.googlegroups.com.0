Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBRGKVC2QMGQEKMC2M5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D7ED942D7D
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 13:51:34 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-428072db8fbsf696175e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 04:51:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722426693; cv=pass;
        d=google.com; s=arc-20160816;
        b=saW9rBHn1YyIp0FKLQ0TdLT78NrroC4k+CEfNwRtXiLjKeuj7kyogdd5oP6IEdMLDG
         P9oBA1xhTh2NoxMUKIf4Mh1FXR+cu3Yxq3xFWHp9w/DWcQq0ErWBjA8JycIdpqfhRTqO
         /EuQkyL2f85/XdiwiZ3TvBA/kMUYzD5bq54cw/SOlGV+qBUO/9gP3BImyhEIH3S18Vy3
         d5mzQrk25zOajoI+vy96XVK0gApbFUzvmmeOMAUpfQbA0E+601eLSMKN0sroyH0UEPqN
         iNLh9NrFp4SdRVqsZ6zItx6sXiuLCckuilii+3cLxHpYEDyHjqfYteaXlfGt9d13lr3H
         x5zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OQO15TMEvbV7L12GJFlP2zVVFxpHR39+gLr6WQNOPCY=;
        fh=1GFuamt2nOWhm0YnKIWSuOVP0S2l/zd3KrFoIaC0jxo=;
        b=EYZ5RI7pMQUvgciM+G4cYGyOsWNm4LM+yLDT7j6Hzx0or8i9WYDxJhfDOlhdpJRhsf
         Dw3Uev8HMnwIh1tCLzahobdDN6TIXy6IatUgTgkBd5/WJ30hHEbbdk1FpsWsh7eevWyi
         EUe5vLgBHGdfwpe0gDjw+Cl4LDSGrQT36n1RpmeZjeKojxusS4Yxmcv/CBUlNmPSTlZb
         uvHLoBy9vEO7BLnqmkLAk2wNxPQiVYgvIZ4NDFky6Psr2vU3Y24H9HGPQH0j6XipSlyw
         BxlZlv2R8ti4TqQ00V2NCywc+1sY9Dqnt3etb3LPqTPFaBAb5cWqEooW3GatqmhKiqFo
         KSmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=m4HLHvO4;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722426693; x=1723031493; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OQO15TMEvbV7L12GJFlP2zVVFxpHR39+gLr6WQNOPCY=;
        b=TCd2XVAoaPupSSRGDsiorxrF1KvmwLzIG9zHqR/FGGk3Nl0kezr5tNiOr7cnOmSeo7
         8yqTwtbm1rlwxr1tn2hhkTtv8wTBgiuQt3xE+tZCpJGehOhw9RXRy4yzcO6ehca/0d6a
         IBpOIXVfIqb4oH19L+YfoveR7Oi5/tRjmmtFB7qYgeebesN5A9f0z/14V3N7onP2Ofx9
         5EEffIl14AwdBjbIYXnDpHsizKs/k1q2K+58nH0JY4AiFwcL5WHEKOIGj9UyHAf3cL3P
         nJtk9+/iLndxU702bJXgjV1iEuUAPEbONiYynjHzUXD9rV+5GmFIxl9mrXHle27Ixaoy
         Z6ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722426693; x=1723031493;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OQO15TMEvbV7L12GJFlP2zVVFxpHR39+gLr6WQNOPCY=;
        b=lG6fJC7Bm1dvdiblvhK6sEsXLbVIK6MjK8tSnicYyi53/0eakg53409VnUdmwe78oY
         o37MaQulOZlgZBjCVIi4n+brrqIvN9RijHa1OmscLGgDx4BIM9tSBHJkjiVLc+LPD7Sh
         +ZdmAbTEp6fRtQk2yEo5AX45xsd0eMwZTO6SNEd/At1JJZhD4SVgoAcvIHTQpOm81U21
         cuPfSwjSYv5mCMtegKL5BfUwYyIk9GL5vdowP0dFknnkbwC1LX0JiherhX/vspQOeMt8
         ABEZLcKt91DH92pCp3bPMT8W0OM19R6UsDy8hY4a3nYTU/AZulWILFRHvDVBrvzBRTZh
         /c3Q==
X-Forwarded-Encrypted: i=2; AJvYcCXoeX0X9GGyzqge/tES+QQiWLxVz3sGhJw6aSKzI/ifjA0iS7PHbOQfdVwUt8kD0QCn5TIM6A==@lfdr.de
X-Gm-Message-State: AOJu0Yymv+mzcWOgenhvKIhAHqrKnAmUKLJ4hpffYJAPtwpGv73Uhf90
	KyGMtRNI/MVdRFvtvR6GFMRT7TM8SXdpNykGMX2GSFRn3okbcA12
X-Google-Smtp-Source: AGHT+IEmO6xSdY2UJdxf7/Z3Gw9f3VVp5B2exZtCrhq1ORCMbIt1To9pbMb8AQPp705aJVRHGQIMAw==
X-Received: by 2002:a05:600c:3b16:b0:426:68ce:c97a with SMTP id 5b1f17b1804b1-42829f4fa8bmr906695e9.7.1722426692876;
        Wed, 31 Jul 2024 04:51:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5114:b0:426:6c3e:18fc with SMTP id
 5b1f17b1804b1-42803b79e84ls32369085e9.2.-pod-prod-04-eu; Wed, 31 Jul 2024
 04:51:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVXoYxS8obL5iawVnkHoSwqHaWbPYLaYDA8OoZaqJCcB4Lr1JfVVc9Clbh3gYXn6kdGK5bBtburI2A=@googlegroups.com
X-Received: by 2002:a05:600c:1d03:b0:426:5cdf:2674 with SMTP id 5b1f17b1804b1-42811d735c9mr90000385e9.4.1722426690985;
        Wed, 31 Jul 2024 04:51:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722426690; cv=none;
        d=google.com; s=arc-20160816;
        b=uXckri2+z+aISjjYQvguRijzaGBmlZmCaCHrsQhoSaU2yRsWAdvp8rxlLr8bDfStEx
         ySzesYGFD5BtCW3kgDFokYGbl3dJ054/fFkFjLuvJkIXgxdODxIJsNt7p68PCLj47mJA
         byMhBrC6F/VX6OSDh+7T9nP/Uxft72dVw0Kk0wiznYoTzOfi19ypWy0WVWtVDtrLYSCn
         E5tia+VdXK5q0qHbiMPjCT7jOvghB1YkQ2kD7u4XVDs5fCY4TfHqNkXX3OvLb8shdTbp
         RfSz0rGZ9Ot9xJDtEtgUgY6XezRqYYpDRR2755EK02j29IdcJJkgmz1beYEByd+46k7/
         RNGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Z3tgfa0TBZZlAPRPnyhZzHIHwaJAdGwVAItxUYwICbU=;
        fh=rQWpN6EANKm3LUqffD69lRdIxaCZ/qlRBI3Nq+yfMOg=;
        b=FSKRv/Op2YbT6Y68SOhkpy4G1kRiIoWUeaus2nN1ca5O2vwFzmY88EFMqgKKH14Zon
         6l6N+ksyULCYz3ftNT/Dp/Ql/pvumUnZf6sntXB6sYd1NLdRVpLbxWfgLtxlxJCDJUzB
         Y+ocqBjKltpPF6waw1dNG7pi0J5v1ORHKXYcO+e5lfWf2d0nvDgbYxxd5UhGCeR/I0TB
         2GwG9C8c/KxmZk4FmFS9oqNioXdk4R7wq/ib7XfP1kJmPHrrl7HN+fItceSYv046g9ss
         SpZPkf3aFtrqYDRwS6/iygCzH6hAywlZ2A+bFGq9Hjd0w46lFHwdmhVr9mT2DYKbH5Cb
         oEzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=m4HLHvO4;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4282b8a9084si237065e9.1.2024.07.31.04.51.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Jul 2024 04:51:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id 4fb4d7f45d1cf-5a18a5dbb23so14607a12.1
        for <kasan-dev@googlegroups.com>; Wed, 31 Jul 2024 04:51:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVHxt4sxhEe2LK14c6y/EYqSkfdyCiFY24m2zTaK++tyHiqt4W08nuyT0T8JVvvk2oBXELcpdhS9OI=@googlegroups.com
X-Received: by 2002:a05:6402:35cf:b0:5a0:d4ce:59a6 with SMTP id
 4fb4d7f45d1cf-5b58cb9c7e7mr255375a12.2.1722426689865; Wed, 31 Jul 2024
 04:51:29 -0700 (PDT)
MIME-Version: 1.0
References: <202407311019.5ea52390-lkp@intel.com>
In-Reply-To: <202407311019.5ea52390-lkp@intel.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Jul 2024 13:50:50 +0200
Message-ID: <CAG48ez08Qzvqw+QA_kqm62+yqHeS0G+26C9jLeA7eYUqZMRkig@mail.gmail.com>
Subject: Re: [linux-next:master] [slub] d543c8fb9c: BUG_filp(Not_tainted):Bulk_free_expected#objects_but_found
To: kernel test robot <oliver.sang@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, 
	Linux Memory Management List <linux-mm@kvack.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Pekka Enberg <penberg@kernel.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=m4HLHvO4;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as
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

Hi!

On Wed, Jul 31, 2024 at 7:27=E2=80=AFAM kernel test robot <oliver.sang@inte=
l.com> wrote:
> hi, Jann Horn,
>
> we reported "WARNING:possible_circular_locking_dependency_detected"
> issue upon v3 of this patch in
> https://lore.kernel.org/all/202407291014.2ead1e72-oliver.sang@intel.com/
> several days ago.
>
> at that time, you said that real issue should be something like
> "BUG filp (Not tainted): Bulk free expected 1 objects but found 2"
> and you will send a fix.
>
> now we noticed this patch in in linux-next/master, but not sure the versi=
on.
>
> we found there are still similar issues so just send report to you FYI.

Right, that's still v2 of the patch - you can tell from the "Link:
https://lkml.kernel.org/r/20240724-kasan-tsbrcu-v2-2-45f898064468@google.co=
m"
line in the commit message, which contains "v2" and links to an email
with subject "[PATCH v2 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG".

And yeah, that seems like the same issue that I fixed in v4 of the
patch (https://lore.kernel.org/all/20240729-kasan-tsbrcu-v4-2-57ec85ef80c6@=
google.com/).
v5 is now in the mm tree, so I think once the next version of
linux-next is built, the issue should go away.

Have a nice day,
Jann

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez08Qzvqw%2BQA_kqm62%2ByqHeS0G%2B26C9jLeA7eYUqZMRkig%40mail.=
gmail.com.
