Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMWZ7GZQMGQETEWZEMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id EB79291B91C
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 09:56:35 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-5c41265a2a2sf430395eaf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 00:56:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719561394; cv=pass;
        d=google.com; s=arc-20160816;
        b=UmCbJDGq45WM3zTt9jlYH4Lwajc230smgtT17Iyxi0NbBv1hT05h+0PDcgHWpwVwhW
         DjlT5wDqyiXWjdQI+JPUGV+dGCJjL/HBiADEOnPWd9qkOY+Y2k4Yfatk1nLeIM6+CBUi
         ZJRpQf2sn9s4CyAd2H3fKMx5f4wHt37kJH1SqDomLzRAfAZqcp6aWUn86T+z4/KWFwSb
         GR+318KDQGn2PRfRJMiV4DHPVm5lhK+R+vflusUwgzG17y6fCCNi0Rg89KlyZPU9VzTi
         rqSUmk+RhEtJSJ6Vk6V8G4AXOpQi2aO0DUEfDefB1BzFnfHlgtsSQikfp0GucfubVZAK
         iMng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GFhqXetd70OxjLs9My2m814ipTmmxBu+ctNGrlcDqgU=;
        fh=ZBoQ7sFstQy9hJGVhU66lDBtKKMEbOB6s1pGtI6r5lA=;
        b=V2iDwo3mQY/DhwWfaFkr+oRVSkumACd9U7H6rLEzELiDeymfylzFcyOAuYElAvqzLC
         uUbiQRTRVK2EEb7+dSCRjqeLXacf/6j0UWSg8XZzQc5MKb/FNN+Wus15zl9wHOOxXSw3
         7d9LKSUDF8J4oAHm1nmUZik4uJCFzwUdBKW/qYbFylPnjZ0rHTTirtob8o1APhMIjnzC
         GjRI1LPP8Vgjr4Qdwv5yuQ7nFvYd/eNa8LRWg2DkBrZ79dRVF2ddGQMbPEXR+l/Gdyiy
         vPbHR1hBkeaMdTnVW4KZhlAfqBrNxdiFL/L4vWi3qhsNMrdA6gRp/a4kfGSHsU5KVGMb
         KMSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UEZcusbl;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719561394; x=1720166194; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GFhqXetd70OxjLs9My2m814ipTmmxBu+ctNGrlcDqgU=;
        b=ApDPdC+J6WU0+Ta2MxTVrDYWPbS4PzlBpA/HscTwSWt/rE+KzsULPeFaNAhZHiLHaX
         WBLqVFVUJUcMHDNXZNo63KDPxX9sqO2J2yX0P0cZ2lKQ3tUBvBJTOg9hSwOLrc5xc2wQ
         OJuCDxHnMa6sJul8GXXmEI9ziR2WpkgQVNzCwf/axuaxX5OBmqtvhlr1Y66YHzsy+QMh
         dhISsP6sYl0ImjOcVj2EqX5/pGJRlnRVFAi8ThZHH0HgHCxlPRr4tiIVV6x3HfHGUru4
         jfeLQ4xGGN1v+U19FfQ9RILDt0ytWgitwvGhu9s6tVEOJzQd/MJBPu3gFo85slc5alFV
         2BXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719561394; x=1720166194;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GFhqXetd70OxjLs9My2m814ipTmmxBu+ctNGrlcDqgU=;
        b=ERcBPtVXULtCAl2IYscfS5u6CyyFS/KTF1IRlpMBF6rlwNZCzeN7ssBYYuqXTdxMNl
         bzpddtmcSYSIUnX9PmTu1PF4WTf6atDXDoW28ogcn6BSo5bu8eEJVxTVv58jpYRPeLp1
         YL0QINTArTHwNaq8u3EtwbSqjPV7YW0daWgo7Qqo3CkcUZ3aahzqm7TBSzoyKLXXwxeq
         mPbAOa3z9HK/E6IIbVL2aOQ3cxMtm1N/MxtvzlVGnynm/LKkLpUhqax18cKjCfqfnPEr
         EVE4WYa1Rf2YhB56FPuhBxJab7iuzjKZXnRQ8b1nSverqDd3PsI+skzcfKXRa0z1ZXYd
         dOlw==
X-Forwarded-Encrypted: i=2; AJvYcCWGqCMHS6wyvujnD1E1ezdetjENnyusAQv3Vx6xwGvLgbD5E3wdhyZfVIA2NZmcHWAANCOWzSJ/Y//AhcTCqO4jAA4Agwgadg==
X-Gm-Message-State: AOJu0Yx/5nU3xijpFGcdczm2QuQmSsFnXLfca9FeSVkbw9v1DJ41JMAL
	DU6jR1fz0pCjsldh+VtjQkYCl+lZosNmjRUMZ33BiygiuBPdLnMu
X-Google-Smtp-Source: AGHT+IHZY6PrBYJpCQVGCnhBfveB/ffAnQOBVDJV5+HSp7t618Bd1S+otnpL+mhT96fW5xgA1KQdKg==
X-Received: by 2002:a4a:ae46:0:b0:5c4:27f0:ae with SMTP id 006d021491bc7-5c427f000femr687747eaf.1.1719561394278;
        Fri, 28 Jun 2024 00:56:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:58cd:0:b0:5c1:ddcb:9923 with SMTP id 006d021491bc7-5c417fdafc0ls424350eaf.2.-pod-prod-05-us;
 Fri, 28 Jun 2024 00:56:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWp6Z4mvozdZOo7TfMfDlIj3gF31gL21zeTpYDtVZhUxhKM+IsPydpshRkbje6yuPP85mSnimuNER2i/v6ZpIxOsm5ztdg/AwA7+w==
X-Received: by 2002:a05:6830:22da:b0:700:d37f:3517 with SMTP id 46e09a7af769-700d37f57c5mr7158627a34.8.1719561393585;
        Fri, 28 Jun 2024 00:56:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719561393; cv=none;
        d=google.com; s=arc-20160816;
        b=zzukLG6+lLrnkfkf+Y9oxqAhvmiyZMx4Trc0dAdvqvrZLBB/Hq4KDXP8YmE7+qqQzb
         joZOESlYpp0jNu/s4MZDdN01YeQIxSEKv4I92/dj+cOj6d9Zkz3Q3MGsKtgj9zpFJxq5
         m6FwtbnJ3vV0xeDS+rV551Fv8ICzn2fmBidmJcnMhvoEXhqrIDD+qyEPTr2DOTQNbVFB
         5ggYBCKPgw58AOSL3+CBuAoLx/nW4ZuJrKXY+45DsJ6WoCykRsloxnDpvSI+lA3NqbUZ
         p4I/hzPUZ68V5jOygj9TTf1IhG08WLXLj/M1BgiyhMDPtj9MSGEuxqxlbek2rAwhOlGs
         5Qog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3eq4WAeAv7a05RSJOZ/FC8KCB2QrYL2z/HLtuN/Zoho=;
        fh=00hDxwkiFGTsopqccr69w307J710syyQBPeacq2kaOw=;
        b=H9B0P//Jx3MELGKBUVFVykIzwRKH3Nxx9gWFAuuRxL1kPCn/XxzDfSavjKOHr8nC5m
         r47VOpCaCBDPxWt3zZteYDCC4P8kytQVu2FOjohaqlye2yMb4ioAIBJn3eiI24cWdCb0
         uPZR7SH5ICXX8kYsPbnE7iNrWxahri5ghBxXydHt+BTbMH5HM52ahnL4Joyz3v0XSvJe
         QhrZkPdfBSAIS4oyOa0TiPLm/NERxHLbIOppcO+idDof6DIhFpoeglSv/KnM9MXBwKt5
         WG5DW8byMtf+oIyDlY6jszqAr5EBjoHJs8xpooryYj+g6uzQp5jHm01se5fPCAYpFSt/
         qoWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UEZcusbl;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-72c6a8df9f9si65699a12.2.2024.06.28.00.56.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Jun 2024 00:56:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id d75a77b69052e-446428931a0so1426661cf.1
        for <kasan-dev@googlegroups.com>; Fri, 28 Jun 2024 00:56:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWUzprJcQO3L02GaujG0O4a1Iu/KaZSAUoXrLZDbE8N+VyQiYx+ynxpAwmXWoE4oiU1LWjc3/uAYVxpCzHVAwJAmmoSs9o8CmXIYw==
X-Received: by 2002:a05:6214:509d:b0:6b0:7485:719c with SMTP id
 6a1803df08f44-6b59a04ea34mr34155586d6.2.1719561392494; Fri, 28 Jun 2024
 00:56:32 -0700 (PDT)
MIME-Version: 1.0
References: <20240627145754.27333-1-iii@linux.ibm.com> <20240627145754.27333-2-iii@linux.ibm.com>
In-Reply-To: <20240627145754.27333-2-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Jun 2024 09:55:52 +0200
Message-ID: <CAG_fn=Ucr+=Wq=h=qnK7iq+DqBom7eQEjQ06+YUabvO8jXq6xA@mail.gmail.com>
Subject: Re: [PATCH 1/2] kmsan: add missing __user tags
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=UEZcusbl;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jun 27, 2024 at 5:14=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> sparse complains that __user pointers are being passed to functions
> that expect non-__user ones.  In all cases, these functions are in fact
> working with user pointers, only the tag is missing. Add it.

Thanks!

>
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202406272033.KejtfLkw-lkp@i=
ntel.com/
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUcr%2B%3DWq%3Dh%3DqnK7iq%2BDqBom7eQEjQ06%2BYUabvO8jXq6xA=
%40mail.gmail.com.
