Return-Path: <kasan-dev+bncBD63B2HX4EPBBRVP4P7AKGQEHWHM76Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 054C82DB02B
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 16:35:36 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id e68sf16846905yba.7
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 07:35:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608046535; cv=pass;
        d=google.com; s=arc-20160816;
        b=k0QYDMInvXycJQGAp5Vuj8qIt/HyEUAh98EtohqBf4Q3qowcquNYgZ3dCTsbPT2JWb
         U5gLsDxa9Tjr1f2K74eEHMXpn66gx4J24qqMhQR+wbqga12JJ+/+ei7eFrZpaNiVH7m9
         DH2gyEsNGLInV9uMq753UyEnWwsU44t5k9b2+AzITQfUK6xHFYRP/XJJk11cXTaEsYwj
         i6PUAZRn6OFRSeb/eSqEb+cGFcHAFciTl95ayK/2Sz6xTn1v3RpqgNyD4pv01xyq/NJO
         /b6hCbtRHWB5Cv1VCX1YJ8oZBSiPuf43fw2/m5DynCFbtIcgVMI3WgH6COA7DTq4jCO6
         dNSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Vmgc1IwfhVVvY+hEh5j154F8tZBXKqbHUf1IgUSgSQA=;
        b=vwTR2jlY3TwEGJ1XtmR/j4N7fV2fpdnh89X1KJNqGjPxDZjihCJZwTpC+h8yd0UprI
         anx8ou9M5YzHWFdCCy8I/xao+5GgprszgOwCjbCvfjUqJlNisZABYLdv87auPSBhRTWy
         q1AH0yuJFSULf9cPHKdX9pQC6LYjUk3HnZUMS/KdqmCp2U27l2vRoC6pgbP+LGaJmsOx
         BOvZ0+Ro1EP0t0QXpBJ0YF7xE+5a0rDjIP9wkwwb1RxlAq1kFwXBh9PK0zMXB1dnTEMR
         GS5XNnsHQwiJDFXnen8BAAeQtNJb2SK4ojV5pPFjfOs3sDzHW8PIPlZCHeI05zmHvpz3
         MKSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b="jtRuo/AL";
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vmgc1IwfhVVvY+hEh5j154F8tZBXKqbHUf1IgUSgSQA=;
        b=BdKcHJVeAvolDEgE+O8+nFqndp/p/Vrynl7vB3NCFpoqhCFK9KX+eXKF4QVXbeB4qg
         p/myVa5mMoX6c3tAinRUHklL6PpUYdCWzYz6BrjHpPAVTAruHwg5aU1Npq5BwLLyKXOs
         t/7HkO+mzf1Mby6glsKFMV3SYJChVa9heJOALzeFcLC/4xIY/Kl+ulsXo2Abzq8z0RtS
         GubkFE61OwDESnSEumJyUgnqwgOZF7LIdCyr8Eb9DIdWpKxJiDPitu2lHkprbtbk7txZ
         EPa2mxv+EJZcj36cC8l8B+x3088NSWiq6gCg0tCRVCmbGrKLqVBlLMSJt+XIViEdz/6j
         tmrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Vmgc1IwfhVVvY+hEh5j154F8tZBXKqbHUf1IgUSgSQA=;
        b=uXfcURt6LcKVBJ56bS3KdZHe4vjk82GKeU8RtIR9C237Nlu6+zRA8Eqq0otz5fTfXg
         z6HQFCwA8rhP+2aK3eZsP/iZpGrl9XenQHmJu9zGa8n+J+9JaGX+wQgp2OhibmS4qXk6
         EE37KH7bJZQlZYxvwDH7jA2/5WWLSjVUxwhEU/Hx51KNgwvW1YoEf58kcLYHWswtJofH
         y1xCweOam2HUDfXSWzAelchaqQYzpHKrgTQ3F554ZelQt5Q/WUPYd6P/4nYbRoxFZozJ
         BGazADdx0eOrCaSzmb+2HyKHME75kTZvhi+/kRKuUW7mhwpGssLo9Vodc6/p1R9rRIiY
         r6rA==
X-Gm-Message-State: AOAM530HIzK83TRoeqcAFMXW+43zB3nrYuiM0foSrZ/CyMRHOkd+fW+f
	9K3XyqqWLesskAyLm0zjAhU=
X-Google-Smtp-Source: ABdhPJywIKuYIYWZXp/CLTL0vfOJGJZoOevbkCK1+xLOCO7pbGeDhaAfttf3b8cLCEblCgM8JLGtsw==
X-Received: by 2002:a25:6648:: with SMTP id z8mr41719911ybm.190.1608046535118;
        Tue, 15 Dec 2020 07:35:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:20e:: with SMTP id 14ls10190947ybc.0.gmail; Tue, 15 Dec
 2020 07:35:34 -0800 (PST)
X-Received: by 2002:a25:22d5:: with SMTP id i204mr47980507ybi.0.1608046534599;
        Tue, 15 Dec 2020 07:35:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608046534; cv=none;
        d=google.com; s=arc-20160816;
        b=sCWiVIDwFou2Ir9ZqT2HnfxgAqPhJtmp5Fmi0X9ad2jZLX24hVJeJVw/9OfAvbifVK
         xM5/jaB7YFqdqtWVscS0ntSWumdPGc1q8RtQCotlMOgHHNqTFE3m5jeubyGocNWNVc9y
         pOrmHsOPzVcaQwrcQHBKkCJe8IHDsgSsYSDqrpOGJVPzq1OGYqM31WnSs6yK4Rt5vPp7
         wjd8H9SI7UFZfPQPTIlNsYpPOEo5VNnlcq5dJiJW8beYZQU5UBf9w2yucyXRRG8IKd1W
         kjl4hN6fMojinlYzTc07HSJlR/EWOzJZpxfoyN17zlOp4z1bQaV/PZ+7prWA626QqaOe
         5uSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Usvmqd/x1Ffqb5wEoHPmzCDAXAUpgjKq/EtgmvAF75w=;
        b=yB05nBXwqy/k/7L3XGxTyZGN5k1iLBBFUIBZT+5trKSSytLEpLUH6UBEppUENKkLEE
         /c/D6xVXg51rMZKcI9VIq22CarrakbXooGvyIxlfcblEUq8FLqP1MOT/mnl7Z2XKDTbM
         wG/J/U6Qq5yVajBPJbvub4fAK/BPuD3m+ghAopW3NTK9CEFHeA9tfRMdr69GR5UIq80g
         EfmRrGOn/qVbw04VLaLsrkG40XA7I0wceVvWM5FF0/vS5y/12T7nGOfq7ZS3ukLSTQpy
         vNWSju7Gwq/N2dYAeYLGhY8/PS1RgeIh9CWJ/ZlBOkC1L/EEEG20bRAtmw5wCMyElo9H
         3rdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b="jtRuo/AL";
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id e10si301432ybp.4.2020.12.15.07.35.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Dec 2020 07:35:34 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id v3so11207799plz.13
        for <kasan-dev@googlegroups.com>; Tue, 15 Dec 2020 07:35:34 -0800 (PST)
X-Received: by 2002:a17:902:8b8c:b029:d8:de6f:ed35 with SMTP id ay12-20020a1709028b8cb02900d8de6fed35mr27954098plb.36.1608046533848;
        Tue, 15 Dec 2020 07:35:33 -0800 (PST)
Received: from cork (c-73-93-175-39.hsd1.ca.comcast.net. [73.93.175.39])
        by smtp.gmail.com with ESMTPSA id u1sm4276911pjr.51.2020.12.15.07.35.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Dec 2020 07:35:32 -0800 (PST)
Date: Tue, 15 Dec 2020 07:35:31 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: stack_trace_save skip
Message-ID: <20201215153531.GB3865940@cork>
References: <20201215151401.GA3865940@cork>
 <CANpmjNOH0fS6Ce--sPk2MPntssdzm6a4BmW21d1b7NHbW=bgTA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNOH0fS6Ce--sPk2MPntssdzm6a4BmW21d1b7NHbW=bgTA@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b="jtRuo/AL";       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::62c
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Tue, Dec 15, 2020 at 04:21:22PM +0100, Marco Elver wrote:
> On Tue, 15 Dec 2020 at 16:14, J=C3=B6rn Engel <joern@purestorage.com> wro=
te:
> >
> > We're getting kfence reports, which is good.
>=20
> Very good! :-)

Indeed.  We also caught a use-after-free that might explain a few memory
corruptions.

> It is supposed to remove them. Do you have this patch:
> https://lkml.kernel.org/r/20201105092133.2075331-1-elver@google.com

I do not.

> Yes, get_stack_skipnr() (in report.c) is supposed to solve this, but
> it was fragile because the page fault handler name changed between
> kernel versions. Hopefully the above patch that uses pt_regs solves
> this for all cases (it uses stack_trace_save_regs()).

pt_regs is a good solution.  Thank you!

J=C3=B6rn

--
No single rain drop thinks it is responsible for the flood.
-- unknown

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201215153531.GB3865940%40cork.
