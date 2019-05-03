Return-Path: <kasan-dev+bncBAABBU6NV7TAKGQEMZXWMII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 815311283C
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2019 08:59:32 +0200 (CEST)
Received: by mail-yw1-xc3f.google.com with SMTP id l192sf7858398ywc.10
        for <lists+kasan-dev@lfdr.de>; Thu, 02 May 2019 23:59:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556866771; cv=pass;
        d=google.com; s=arc-20160816;
        b=YfBHWXUAvuWJnM7Jw00Vdy3b9JGIM2MNolr8Jho1ztvexy2DfMGbzTd+WFizFSb6eL
         oieI+aELyng9evRs4qjbPc+zFRRH6lb47mRytXGpHjAR9ctC5JJLr5ITVkv02vT6uQw4
         RELE0bVhTSvLXwnjW1F3nQTNj+RuuLFw9019Odkb7aCgcgYUWtuGzvZlfy6pYgapKRg3
         dg77vVlEznTNYdD0PHXKA107FVGnkrVGxpFE7PoRKgx3CDEmIwTwWLjMGH+D9UM9Wmwa
         52vGUh31vJiOFiprQw7rz+coVArFbaz+hp2fCei25E3RBrEDJbYAQDdEL9GzGg25QzZf
         PM7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:date:message-id:subject:cc:from:to
         :in-reply-to:mime-version:sender:dkim-signature;
        bh=AwV1fcOv/TMQsF7Q/WHFn2n+4qMlnUGTHcymmPU4oww=;
        b=uKsfdhMlgewGckUcg1LV412SxGnGLLxyRwG4nx6MQKE+QriCF1SXTPzdz3oW/wj1+M
         SvgWupDOhXeYpQ+meW9PUtOH+8QagdI3Mx2jF+XQ0X5WQMobewmMqpmVWlUQ7OXJqyNC
         W9FQ8AklUu5stzJrikbKsww4e8GoCs8yL8CH4MrQxoXB221GZerW5qlYWHqHUVfBxXSU
         qyAoq6kP7wZy5lGbcfQBstuU6cf3+YTt8HNWweVjaBBofk+gJpy4CvPhlWqaE1+RXRh3
         xcCSVdrDQswGdu4ZIrRLF1x0wzFCRarnCHEjNuf3uRihRU98Qt4e4d69z9TiNeGmSMsc
         bUuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of michael@ozlabs.org designates 203.11.71.1 as permitted sender) smtp.mailfrom=michael@ozlabs.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:in-reply-to:to:from:cc:subject:message-id:date
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AwV1fcOv/TMQsF7Q/WHFn2n+4qMlnUGTHcymmPU4oww=;
        b=mTi2iiLAKMqG8STf5uDznGgpZWTXROuOtSg5A5Ja9ER/NfXAXBFAOSqPig1NhCCk4a
         g+mcFl2E5ncAkIVyvYBDNrz8XvdOOi92zDptOEIX2qKbBZy+FJrbIE/RhYHR9CDSh/j2
         ewqWdqOfbXhe4wJstHf7Hj1xFY43IoB3VAOkod2Ldq0GaRvo++OWDPa5jULCXdchqmur
         tdHqlDB8XdPs1lQ0rbGC8WwhfCV0atvXWkIDAQMl0Oy07GuOway6ibrPa9BYgPdsk7N0
         Fxl+qveNYTfdJfhYWm3QbXBO7/2zJVj/jOy0YSqV1cra4zxBJzD/GpNAeq7eP2WlU054
         mdLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:in-reply-to:to:from:cc
         :subject:message-id:date:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AwV1fcOv/TMQsF7Q/WHFn2n+4qMlnUGTHcymmPU4oww=;
        b=eWNOquJ04yArAb4eLng9OLKLKNJH9c72nufVqkAAsUi3SB9eOJ/C02NlDW1UXz+lGj
         3D6DLOUbUlj5Yqx56ddt5jTOUBhS+RybpP4fU+vKCNwwr6CncFZjabco8hCTz5FS6FTC
         7qrrkW5QjHuavRk45qKWeh2aveSTtja5bqsKDVtumu/9sRQttSxz4WIbxNAAj2/XzxQm
         sM6cKkH2gjJ1tl3qS0zOxIfyiqJKiRmag2TV2xPUyCCrGQRJVt7/9dWnJjq014DWaxfJ
         YHBz1oqMM5r1FvGpmOQphz+4sRxkaJ1PTbdVthJVZzTIsu352goekU58zpzaQPv/n+BY
         YMTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUSjcERvVKDIeyg/ki7g6nw/egJTw+KDsGX3GsMtilVWyV10iUg
	ENVBYCCKIT+cE+SvGMQF5Z0=
X-Google-Smtp-Source: APXvYqzo25uDt5zL9mCecLd7zqXRWrpUD7vZEksdnEBEOq1nQZy5UAqRKtpxnMIi1vtm5Z9f7C6enw==
X-Received: by 2002:a25:cf92:: with SMTP id f140mr444198ybg.229.1556866771202;
        Thu, 02 May 2019 23:59:31 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:a458:: with SMTP id b85ls185925ywh.7.gmail; Thu, 02 May
 2019 23:59:30 -0700 (PDT)
X-Received: by 2002:a81:e11:: with SMTP id 17mr6703973ywo.57.1556866770964;
        Thu, 02 May 2019 23:59:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556866770; cv=none;
        d=google.com; s=arc-20160816;
        b=Vd18qAeNIErV31kkTcfomCt4duzYRm0ZkQYyp0lSZmVMr9EDb2N3OGjpXOhbTzylTy
         N7nAgntDkAhD9MKhb6U38vOjlVX9rwTxdrNfiKBKoBMYIv3elLAPuhEdAQbVBletZ3CT
         ye7ZiVT0VQPoeeqatqgk1zYlnnD5ZOnMCmAWRRTRRrdO+ushuuaBilQSDwqPdaRv4v7J
         QKA7B435C9rZVvUEd7DAYHuymXPlOqPhLnACxXFOdSMP4VqYR8hy+xX4cC5DEZ0+eN2H
         VGQbDRWttUXyKO8VGQ82pF8nnakuJ259Xw/QtYKFM01u/3RpED0erYYHM+wXhFskMonR
         Syrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=date:message-id:subject:cc:from:to:in-reply-to;
        bh=VliTphK8d2uY++B+00kx4b2yo/8La2sjNa+6+heMhZQ=;
        b=O0s5Oc14IfOhwUrGfr0o1tPaEwUEOdvlFYhI3bZIuspT9yJOAcsUptVnwF0RjkGNA4
         caiBs2h365GKLMkruSFYvQx72/DoeCwrNiiHswMW8SXci9uS9iTlF4F+4AlPlqwjmpjT
         TJyLNuzPBTSizB8mM5V3pnF1/nc8Y9NbhmGH4NHlgzo+GiCp4Oz130LJ52z5MPm4Fa1G
         47aOnM/NhFtSfVS+2hlO41d0rVc/Ve1hf259sTsUaUaTf7jdwIEeAWGJwsXvHFE+NBP1
         QCvBavBYu1T6uq8EUMUriPIGl5aJCgDNHQ0yXFBb/fHhsoU1VmMs9wpuM/zMnY+0F1zg
         599g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of michael@ozlabs.org designates 203.11.71.1 as permitted sender) smtp.mailfrom=michael@ozlabs.org
Received: from ozlabs.org (bilbo.ozlabs.org. [203.11.71.1])
        by gmr-mx.google.com with ESMTPS id 189si122070ybf.1.2019.05.02.23.59.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 02 May 2019 23:59:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of michael@ozlabs.org designates 203.11.71.1 as permitted sender) client-ip=203.11.71.1;
Received: by ozlabs.org (Postfix, from userid 1034)
	id 44wNKS6JSsz9sPW; Fri,  3 May 2019 16:59:24 +1000 (AEST)
X-powerpc-patch-notification: thanks
X-powerpc-patch-commit: d69ca6bab39e84a84781535b977c7e62c8f84d37
X-Patchwork-Hint: ignore
In-Reply-To: <08b3159b2094581c71e002dec1865e99e08e2320.1556295459.git.christophe.leroy@c-s.fr>
To: Christophe Leroy <christophe.leroy@c-s.fr>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Nicholas Piggin <npiggin@gmail.com>, Aneesh Kumar K.V <aneesh.kumar@linux.ibm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Daniel Axtens <dja@axtens.net>
From: Michael Ellerman <patch-notifications@ellerman.id.au>
Cc: linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v11 01/13] powerpc/32: Move early_init() in a separate file
Message-Id: <44wNKS6JSsz9sPW@ozlabs.org>
Date: Fri,  3 May 2019 16:59:24 +1000 (AEST)
X-Original-Sender: patch-notifications@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of michael@ozlabs.org designates 203.11.71.1 as permitted
 sender) smtp.mailfrom=michael@ozlabs.org
Content-Type: text/plain; charset="UTF-8"
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

On Fri, 2019-04-26 at 16:23:25 UTC, Christophe Leroy wrote:
> In preparation of KASAN, move early_init() into a separate
> file in order to allow deactivation of KASAN for that function.
> 
> Signed-off-by: Christophe Leroy <christophe.leroy@c-s.fr>

Series applied to powerpc next, thanks.

https://git.kernel.org/powerpc/c/d69ca6bab39e84a84781535b977c7e62

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/44wNKS6JSsz9sPW%40ozlabs.org.
For more options, visit https://groups.google.com/d/optout.
