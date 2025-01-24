Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7VCZW6AMGQE3LVJ7QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 25051A1B1CC
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 09:38:24 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3a7e0d5899bsf32808435ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 00:38:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737707902; cv=pass;
        d=google.com; s=arc-20240605;
        b=BPfqRBcX0DQsOR15b/TT1MVQUKxfWXnvFwg6zSZlBaNvcuiVSRwYopyverccIvNuBf
         iVjgYE//rkFslq/Y7V6ZSArDohlyHhVzIwbCNaT0Y2sQG73lBsPbw6wPqFxE9chuJE5r
         5bUxBXCdcz2SxVIZ2wpLKB6/gIDZR3Ome0AEbZLcdFC8WeUyhGZKFluf1ykI9Ol2ULIu
         g5CcR/WZade/hiSmhSiQ3vCzF6SM55RqwPMuSQ+uj1B50wB00GJeUp05bhGwtFggmD03
         32z2bXNIuMyXvLhAHGPUI4vYFMA+g47AGDnUlZbzTmTctIlHUyWRgrkSoz23Y3UOLNE1
         Yyig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ia3Mqogpj2ngf9msDkFwNrKo/kUWRQSio+otc7FpBsI=;
        fh=JclNg97JWJs02FZVAAMwitn65KHMRntR/OHfgYoipSI=;
        b=HRNm9RSv9WjRomu5Gw2tKCr/L16szobp3+IqSPA+F6XFLI2QHyLpLpCUvT0iz304Ne
         p1Rwwa8ZtSqZ6uxwqjpahWMMyUaeyNNU6XgQCHnuGBWpsQRm47HSEtr61UwQCDqG6wmO
         lefG9TYFHBvK3EDeMYwPjyPaYGNZmfRnua6b0VdBeDq3vLCLr1VJYewXdllBw87atotv
         +Jp33lrP8bZjtzzer4JtCLijq8PXkV5MyGHAG4ctNbOjd46T9tDpJ0/Vco72iqI8Lic8
         doVgJzg3P5nxeqWsAp5cXyPjrF4iGvDFXAEoyivFu106w7kioa8igIJcCRKg6JU+UEJx
         RIDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vE9KHGQg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737707902; x=1738312702; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ia3Mqogpj2ngf9msDkFwNrKo/kUWRQSio+otc7FpBsI=;
        b=iZN+NOeoJb5QBo4856pGyYmCeYn8QJ7miDVqCjhHoFGgk92o3oGBbRGjU7NEsDdBZo
         1bjnFjdzz6iRxBNKe2pDsyXYVBX8d9sHRX1Xv+LpqwSsCPT4oY82j7Wob4bLkQM5hyXZ
         8A0i0tDFvvUpV/sbI8v6ZRURGHGtzEVH2HJqLaSeCrDzzgzkjVqRK8OyOE3jdtLN8t1I
         xV/fWLAQ9On/3oqX7gzkC2jVwOBw3+d1JD5DtV7YoF+tdCLBlCn++wVnlGsegJMSDme7
         F2/tcfps+jPUYva3KYIF8WTGfCKjZzIl5AhLmzargKDKYQcXZvdyZMmpOfcC2r4oIDrx
         y2vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737707902; x=1738312702;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ia3Mqogpj2ngf9msDkFwNrKo/kUWRQSio+otc7FpBsI=;
        b=NNzM07qrXLC7RpFV0J2/z4iNTvoMsXHHJHPfakqIiEZIJIM2a5MqWUAmjRD6o5N45b
         1otN+rE1pUdJ7FkOA5gz4jGX0zoZGymsKCZFBfPeZhiW3UEoPUzqDQHF17HpBV6QTutL
         NhxRQPsCT/I+kibWn7UwKmu1FKykr99b/G0ZoEjT0f5VALzwsdcwDnOSD8TZ/m5fL8Qe
         AfWlPGGEhsVfBd/EU/dc/EFkLuMkbLebDrellSZEaLOVYF9OskdrNHSV+t1MJ5rkgyQp
         ci+uiZzXPT6esnFV92o8GFGCvTZ70+QHVQ0NdZ0ud8hBy+ooGAc2bvAgc3GQuRCXzdeU
         ab+Q==
X-Forwarded-Encrypted: i=2; AJvYcCW4aAd+kFOI4pcPD+eS+PsUG0sX/LRV0F43KNHNHnQDfHV17CSZ/2qKHNlkScSdHBxJV6P1pA==@lfdr.de
X-Gm-Message-State: AOJu0YxPXIV5jjUTIK/776yHSSfXDlQHMIZ13Q+BsZKPOU8TiKyzdy2a
	7m9GPR4DELK+8V/2sihvERva0ILvo/qIz3KM8asr7REvwUV2+B/X
X-Google-Smtp-Source: AGHT+IFbO4MoPM4uQELX1hp6C5DU7Qmi585MBYziJZTQoV6imaA7zhHr8CLaIG6GhL/suv8fCZzROA==
X-Received: by 2002:a05:6e02:16cb:b0:3cf:cdb8:78fb with SMTP id e9e14a558f8ab-3cfcdb87ac6mr984645ab.16.1737707902615;
        Fri, 24 Jan 2025 00:38:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:dc92:0:b0:3cf:6e43:61dc with SMTP id e9e14a558f8ab-3cfbbdfa149ls8537105ab.1.-pod-prod-01-us;
 Fri, 24 Jan 2025 00:38:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXPzZxLmiFVZ615Z0PtEHA6QgF1RLeNBI4Qhk5fak2CB0ty/i9YaQxOqQMBfIJ1sWLJrX1PZjcQ3i0=@googlegroups.com
X-Received: by 2002:a05:6e02:16cb:b0:3cf:cdb8:78fb with SMTP id e9e14a558f8ab-3cfcdb87ac6mr984115ab.16.1737707900708;
        Fri, 24 Jan 2025 00:38:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737707900; cv=none;
        d=google.com; s=arc-20240605;
        b=G0HHCCCdt7EFgdDeRDmHwTFqYQaKe0HksJTPQIIaWatFfy3SeR5kM9GWuL00AKB4TO
         24BAwdV2Gq4BFIiJT12zD2esD7DO1DEZ/VD+69YVDSR82e1o2yoKZc7yRbfvMLrbDuus
         8oFXIr8wkmZbv/DZxZ7lwfGhiI57CnxG1HWJDr7+apMYuv5pYkSYjb7DUo/dgd6yDFft
         9lxFPHbbVcXw2CpvwOv/5KDme1WhOImtuYUwjJw7x/OG9vGs73ZoE4keA5feGxOo2vfr
         JwTCC96y1AYil1JimQzCZjIMnPsXLc6u/wymkwIPoeNdE49Ro+Re/wS8PnpMCwm4xY4y
         /pOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9tddCrPwZq+AKGA6FysyP+fBCq0+ub/7HsVtiuOI4UI=;
        fh=Ret2eX8KQavqU4FfBXXLC7wxJZtcJSwJGuW0JUFacTU=;
        b=cVkLeqKHbLrl89gBCeFY8Xhi6cDdbxNOB2WDk5Auwvk1iwPRQfezscLRz90p2A95uD
         dsro4awhiwXOJiUGcicJemanrpAma9QeWt9h7bvHTuZ+IsQwO7ep/22j9cUKj93oZViE
         9S9oSRl+XCxvhFVWOWciDzZJG2WzFZhQqiIcHuMSlwzLtAPasG45RItDP4pI1sd9ygHX
         zUwS6WWFAn/50rwV5GuevHAkKcI1uV0Pa3KljXXq37Zxo5zLF/+JED0WHJhVOjmpPIPY
         F+nzdx/WmMKojQGy7XG3gDIYmRpODovevfaIBGiHr6Uu0vWtVaDDv0DXKCQG1xzrr/2l
         GRkg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vE9KHGQg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3cfc7504fccsi954365ab.5.2025.01.24.00.38.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jan 2025 00:38:20 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id 98e67ed59e1d1-2ee46851b5eso2614668a91.1
        for <kasan-dev@googlegroups.com>; Fri, 24 Jan 2025 00:38:20 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU3epZlakTiqbss1Dr4bRDxqlNpMccIBKYnIWFx+c2NnQQzF7Y7QxLW6dqoejTUwxvCOlQItlmZ8UM=@googlegroups.com
X-Gm-Gg: ASbGncv87p04OyqIB9rcc9NJ4vFRSvkcHgPKSwwWhHWdvGQXxP6Lhh8vxkUSmj3618x
	u1LPP9EqcQ/UqXaTXpZUiadexO2GrECIsxybSYpfPvalGdp0P9vb7gtb3zeyub4ID3rPYBUsDLr
	vNUQBDmjZssLqSYQnL8g==
X-Received: by 2002:a17:90b:3503:b0:2ee:9d65:65a7 with SMTP id
 98e67ed59e1d1-2f782d7ff77mr40198898a91.29.1737707899764; Fri, 24 Jan 2025
 00:38:19 -0800 (PST)
MIME-Version: 1.0
References: <20250123-kfence_doc_update-v1-1-9aa8e94b3d0b@gentwo.org> <b788d591-4c5f-4c1d-be07-651db699fb7a@suse.cz>
In-Reply-To: <b788d591-4c5f-4c1d-be07-651db699fb7a@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Jan 2025 09:37:43 +0100
X-Gm-Features: AWEUYZnsNQFUSJsERPtNV2HXTL_4mZGDJWzPTu4wScV_GdE309XO7yGCB5BQmXM
Message-ID: <CANpmjNM_2EB-sTBjPDADNh_cAEJS8euY_71pw0WNu2h_eisAYA@mail.gmail.com>
Subject: Re: [PATCH] KFENCE: Clarify that sample allocations are not following
 NUMA or memory policies
To: Vlastimil Babka <vbabka@suse.cz>
Cc: cl@gentwo.org, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>, 
	Yang Shi <shy828301@gmail.com>, Huang Shijie <shijie@os.amperecomputing.com>, 
	kasan-dev@googlegroups.com, workflows@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Christoph Lameter <cl@linux.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vE9KHGQg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, 24 Jan 2025 at 09:13, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 1/23/25 23:44, Christoph Lameter via B4 Relay wrote:
> > From: Christoph Lameter <cl@linux.com>
> >
> > KFENCE manages its own pools and redirects regular memory allocations
> > to those pools in a sporadic way. The usual memory allocator features
> > like NUMA, memory policies and pfmemalloc are not supported.
>
> Can it also violate __GFP_THISNODE constraint? That could be a problem, I
> recall a problem in the past where it could have been not honoured by the
> page allocator, leading to corruption of slab lists.

KFENCE does not sample page allocator allocations. Is kmalloc()
allowed to take __GFP_THISNODE?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM_2EB-sTBjPDADNh_cAEJS8euY_71pw0WNu2h_eisAYA%40mail.gmail.com.
