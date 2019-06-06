Return-Path: <kasan-dev+bncBCMIZB7QWENRB5ED4PTQKGQE33HB6JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 716FF36D64
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Jun 2019 09:34:14 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id f8sf1038757pgp.9
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Jun 2019 00:34:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559806452; cv=pass;
        d=google.com; s=arc-20160816;
        b=qCc7CUWFE6m01kaQe2igS5RN2GapQCtzBXTFaWQ7QPLxpt1ubHg5y8CZcVn3LASYMp
         jA+pDyMlngs9/dELU1+VFwhDkQXGB0RY3P9JC0nNqQflhXjA0PV8AyFHeaeCQw3joYzg
         o0hUpcZeljS1EcTxrUv/PqCHVBYgUMWlmoGWpAZIP0DWq0+tUuaww4hMZTVe7f77WTzt
         YZJP0HAT9g3lsBYtp2tGkVP22vandswVahD7IFJFfrD+gJJzqDmPxOOwWxj+m0eFgTH3
         0FMPhbKDDZciCf1/VGFtOhLPlOqJhz7t3JFs+S3FNRNIE9iyJvZmOcAKh+qgf2ZzDdCM
         LUng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wXLMEB04BWFM2kZUCOEaJ3JjE/AvFE/nRqvVAX+fEcQ=;
        b=ryKKzWxNaMx9ZStanyGHtjgF5PLu18yvXT/1wwoTwE41GFAG5aXPnf+1Qfd9K+a4XM
         T/edi4Ib1vn50yANTvV5qs9fggWxwae+kUMFlJ1Cb4D6lBVt+WXztaLIjh0jrGSt5AaP
         3b04TGsGT+ZFGkOsohtfrm4F6l1trU+ZIkikxy1dbM+UR/3i3xR6MGHtbtRkB07RwPBV
         8IDvnLAdiirkiy0jYRGjLtrHDENoGVkcQumQj7At/wi2exohnWcG94DLcAUDGO4oYiaT
         bk+0rMBvmvg35UBIczxFVisSsQCZN3D3RGJUxhqn8oZ9FPD8L2ImvNmtVZEtgHWSP2Yv
         HewA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LGRI9LDp;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wXLMEB04BWFM2kZUCOEaJ3JjE/AvFE/nRqvVAX+fEcQ=;
        b=QIUBJAsQYQvneOC5QXE4wqgWCiOEDEUsWRH62Wmxm0UV70HA2bdhXtmxkfpXKxTEVY
         SYiu3xJ0MvuWRFPkKuSzJg5T0xu8LXBdk3Gl3FOHG7w0SayajB0+OWQ1MRGNakk7Z16b
         VcrGLgXYjuitiiwJO0+R9pkoBke8pvK8ZABRRBpzOQGl8fagWmI4z9HXqDNZoijKvESy
         ubErj6E9eHHj6uOkAKQlxHuBa2vnDg0IJex1AnUH9GsXXKO16iyEGiH6RpbBhrM5kkAA
         7jUABrIc1Pt3MLzkTDI3xnWDrgYtQ+/HBSk69YiNDeAUab+6xKYv3cDUzMbp7fYALbOw
         AFUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wXLMEB04BWFM2kZUCOEaJ3JjE/AvFE/nRqvVAX+fEcQ=;
        b=sZ7d+403DDisWURlj4WkhoH9+/RcmykGkpNfZ8HerZ9frBR4KeTAwcXOuyrBih5Vwh
         QFXYivhI4x3UsJRcJN6TzzsHYDMnOX152bOfM0S26FmGOnydZdKS7II5yuDZKUzDEIKC
         9ZKWw5zcUBuR2tCEhbFbnBMUI/JiG48MwDMvDtKsijHmnmcdPlKoBgPST6mOf6bMw1Hp
         47yzjtj3A9ES0BD//0Rl6QvKJkeiq/LUcXIgqMaEzp7kH9+TY1Cim7XIRM84BrRmgO85
         x8vl6VTkdpqFZNDdpYOYoDfRr11rSVva/M+4qH8PqueWa0+2RFE2YYtJI1h4crkl1tHW
         Lz1g==
X-Gm-Message-State: APjAAAWBz2Vzhefi3EO1pI8D8XaB6pvLyeohw+xRRyMEDSn3u5cwYgMi
	KHmdR0bVkMLDcdROF9tZgKg=
X-Google-Smtp-Source: APXvYqy/tSUj2ll5AP8j2BSrEDBZv+KB++KhUmGz0wYNoCtwO0Flf+0YKmzjB4UKDGyWJTFKFUkqnA==
X-Received: by 2002:a17:90a:5d0a:: with SMTP id s10mr49321632pji.94.1559806452762;
        Thu, 06 Jun 2019 00:34:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bf0b:: with SMTP id c11ls1164292pjs.1.gmail; Thu, 06
 Jun 2019 00:34:12 -0700 (PDT)
X-Received: by 2002:a17:90a:cd04:: with SMTP id d4mr51054505pju.128.1559806452487;
        Thu, 06 Jun 2019 00:34:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559806452; cv=none;
        d=google.com; s=arc-20160816;
        b=axiMPcmxmUqjXplmykp4bUjee+rok0zT55Nmd4vzQp4LCzDpXldlgyu3ZaIqEFYbqx
         cr/6nKX8o3WEwiQKcrdN0mvV0weXlAeizrNCZ7siyI+pNzQV8+HJg6NV8hatS/4cSfn9
         3rdM9nq3tSCH/JBvFYQXnnZEWy+EqCYy1mFPrb0uzUanUjcwMeZhYhHOvaFStd/AECYR
         TdA/ZeTRRlt9I2ldTAlbceFeWfzFLkdoTpnU72B2SQ6u/QtgnDKEPqsIoA7EFD8C3T3w
         eKTmDq7pqswMz9uC98uiwGby7g+tK4pNFQJJvPENqBk8Z1NzGpRoINdPA+F4GVjTyGfI
         Iv9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Jvdb9Zfp5M1Bx4VLz416uaElh0ColBgYizp4FJ9+Aqg=;
        b=zOdjeOUCLejvvynDUdiRValUqzQs5RodxNqL1vYDe2RYUZdec29GCsEdPlyiZK8uns
         j6q53iNqjzhM6Owt5VKUouTmeTFg4Fe7iFHQH5yIFzh9oSDZImCi+Q9MSgBz5mVr1zkB
         +WUtlvtmpQmYr2GostWWbqHRiXW7oh3jxUC5FHHRTUKK1mZRfTwNDzkLqnOl8IXPwvU7
         bgQ7P9lgnPJQCKPW0Fj8ialeLxynpB/bXyAR/9SpBJ5LTeVJT+cSUrKzE8CIyFxti8/n
         d+NZNS9yCk4DrkZdJjerB9gmPu5SkJ1hihd/X0h1cs7UxWiN7Dy8I37njncibFnBj3Gc
         M56A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LGRI9LDp;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id y15si28567plr.5.2019.06.06.00.34.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Jun 2019 00:34:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id e5so1062110iok.4
        for <kasan-dev@googlegroups.com>; Thu, 06 Jun 2019 00:34:12 -0700 (PDT)
X-Received: by 2002:a5d:9c91:: with SMTP id p17mr13380478iop.231.1559806451592;
 Thu, 06 Jun 2019 00:34:11 -0700 (PDT)
MIME-Version: 1.0
References: <448e89ff-d0ab-a3b8-59bd-1ec9e8aea515@suse.com>
In-Reply-To: <448e89ff-d0ab-a3b8-59bd-1ec9e8aea515@suse.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Jun 2019 09:34:00 +0200
Message-ID: <CACT4Y+a2GvxQrPWk7ShdvtZ0m3cEZdaM8tQ0wxVpW6uJpg+9gw@mail.gmail.com>
Subject: Re: kasan coverage of strncmp/memcmp
To: Nikolay Borisov <nborisov@suse.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LGRI9LDp;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d31
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Jun 5, 2019 at 4:23 PM Nikolay Borisov <nborisov@suse.com> wrote:
>
> Hello Dmitry,
>
> I observed something strange on latest -next kernel. Kasan rightuflly
> detected an out of bound access on the following call:
>
> strncmp("lzo", value, 3), in this case 'value' is set to 'lz' but not
> null terminated hence the out of bound access. If I change the strncmp
> to memcmp though and everything else remains the same I don't get a
> kasan complaint on rerunning the test. Is this expected? That's on a
> x86_64 vm in qemu and the compiler used to compile the kernel is gcc
> 7.4.0-1ubuntu1~18.04.

+kasan-dev

Hi Nikolay,

memcmp is supposed to catch buffer overflows. I don't see any relevant
open bugs at:
https://bugzilla.kernel.org/buglist.cgi?bug_status=__open__&component=Sanitizers&list_id=1025947&product=Memory%20Management

Perhaps the buffer has 3 bytes allocated (even if not 0-terminated)?
If it has just 2, please provide a stand-alone test for addition to
lib/test_kasan.c.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba2GvxQrPWk7ShdvtZ0m3cEZdaM8tQ0wxVpW6uJpg%2B9gw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
